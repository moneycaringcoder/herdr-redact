//! The findings store: what has been seen, what has been acknowledged, and what
//! has already been shouted about.
//!
//! # Contract
//!
//! * Nothing written to disk may contain a secret. The store persists the
//!   pattern name, the pane, the masked preview, the length and the **keyed**
//!   digest — never the value.
//! * A finding stays until acknowledged. A secret that scrolled out of view is
//!   still in scrollback and still exposed.
//! * Acknowledgements persist across restarts. Re-warning about something the
//!   user already dismissed is the crying-wolf failure mode.
//! * A finding whose pane no longer exists is pruned: its scrollback died with
//!   the pane, so there is nothing left to warn about.
//! * Notifications are rate limited to one per pattern per pane per daemon run.
//!
//! # Why the on-disk types live here and not in `model`
//!
//! [`Finding`] deliberately has no `Serialize` implementation. Persistence goes
//! through [`StoredFinding`] in this file, which names every field it writes out
//! by hand. Adding a field to `Finding` therefore cannot silently start writing
//! it to disk — someone has to come here and type its name, which is the moment
//! to ask whether it is safe to store.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::config::{self, Config};
use crate::model::{Confidence, DigestKey, Finding, Match, PaneRef, Report};
use crate::Result;

/// Bumped only when the on-disk shape changes incompatibly. Suppressions are an
/// additive, defaulted field and unknown fields are already ignored on read, so
/// adding them does not require a version bump.
const FILE_VERSION: u32 = 1;

/// Key for the change stamp, which is not a security boundary: it only answers
/// "did another process rewrite the findings file since we last touched it".
const STAMP_KEY: DigestKey = [0u8; 16];

/// Permissions for everything this module writes. The findings file carries
/// masked previews and the pane layout of a developer's machine, and the key
/// file is the only thing standing between a stored digest and a dictionary
/// attack on a low-entropy secret.
const PRIVATE: u32 = 0o600;
/// A human-readable report note doubles as the suppression count's transport to
/// [`Report`], whose stable public shape predates suppressions.
pub(crate) const SUPPRESSIONS_NOTE_SUFFIX: &str = " permanent value suppression(s) active.";

/// One exact value the user has permanently suppressed for one detection rule.
///
/// There is deliberately no preview or other string field that could carry the
/// value. FNV-1a is not a cryptographic MAC; pairing its keyed digest with the
/// rule name makes a collision as specific as it can cheaply be now that a
/// collision could silence a real credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suppression {
    rule: String,
    digest: u64,
}

impl Suppression {
    pub fn rule(&self) -> &str {
        &self.rule
    }

    pub fn short_digest(&self) -> String {
        format!("{:06x}", self.digest >> 40)
    }
}

#[derive(Debug)]
pub struct Store {
    key: DigestKey,
    findings: Vec<Finding>,
    suppressions: Vec<Suppression>,
    path: PathBuf,
    max_findings: usize,
    /// Problems raised while loading, or by the cap. Folded into every report,
    /// because "no findings" and "I could not read my own state" must not look
    /// the same.
    notes: Vec<String>,
    /// `(pattern, pane_id)` pairs already toasted. Deliberately **not**
    /// persisted: the limit is one toast per pattern per pane per daemon *run*,
    /// and a restart is a new run.
    notified: HashSet<(String, String)>,
    /// Hash of the text last scanned per pane, so an unchanged pane costs
    /// nothing. `PaneReadResult.revision` cannot be used for this — it is always
    /// zero on the wire (trap 3 in docs/herdr-protocol.md).
    ///
    /// It lives here rather than in the daemon because the store is the one
    /// per-run object threaded through every cycle, and `scan_cycle`'s signature
    /// has nowhere else to keep state that must outlive a single cycle.
    seen_text: HashMap<String, u64>,
    /// Pane ids whose one-time startup scrollback read has been requested.
    ///
    /// Deliberately not persisted: backfilling once more in a fresh process is
    /// harmless, while persisting this would keep a restarted watcher from
    /// re-reading history that may now be available.
    backfilled_panes: HashSet<String>,
    /// Findings first seen since the last drain, awaiting a notification
    /// decision. [`Store::observe`] returns the same list, but `scan_cycle`
    /// returns a [`Report`] and has no channel to hand them back through, so
    /// they are queued here and drained by [`Store::take_new_findings`].
    pending: Vec<Finding>,

    /// Digest of the findings file as we last read or wrote it, so an
    /// acknowledgement or suppression made by another process (`redact --ack`
    /// or `redact --suppress` from a shell) can be noticed rather than clobbered
    /// by the daemon's next save.
    ///
    /// A content digest rather than an mtime: filesystem timestamp granularity
    /// is a whole second on some filesystems, which is shorter than a scan
    /// interval and would lose writes.
    stamp: Cell<Option<u64>>,
    /// Where the next cycle starts reading.
    ///
    /// A cycle has a time budget, and a session with thirty panes on a loaded
    /// server can exhaust it partway through the list. Always starting at the
    /// front would mean the same first handful of panes were read every cycle
    /// and the tail was never read at all — a scanner with a permanent blind
    /// spot, reporting a clean session for panes it has never looked at.
    ///
    /// Not persisted: a fresh process starting at the front is fine, and the
    /// only thing the cursor buys is fairness within a long run.
    scan_cursor: usize,
}

impl Store {
    /// Loads the persisted store, or an empty one. Best effort and never fails:
    /// an unreadable state file must not stop the scanner from running, though
    /// it must say so.
    pub fn load(config: &Config) -> Self {
        let mut notes = Vec::new();
        let dir = config::state_dir();
        if let Err(err) = fs::create_dir_all(&dir) {
            notes.push(format!(
                "could not create the state directory {} ({err}) — findings, acknowledgements and \
                 suppressions will not be remembered",
                dir.display()
            ));
        }
        let key = load_or_create_key(&config::key_file(), &mut notes);
        let path = config::findings_file();
        let (findings, suppressions, stamp) = read_state(&path, &mut notes);

        let mut store = Self {
            key,
            findings,
            suppressions,
            path,
            max_findings: config.max_findings.max(1),
            notes,
            notified: HashSet::new(),
            seen_text: HashMap::new(),
            backfilled_panes: HashSet::new(),
            pending: Vec::new(),
            stamp: Cell::new(stamp),
            scan_cursor: 0,
        };
        store.apply_suppressions_to_findings();
        // A file written by a build with a larger cap must not stay over it.
        store.enforce_cap();
        store
    }

    /// The per-installation digest key, drawn on first use and persisted.
    pub fn key(&self) -> &DigestKey {
        &self.key
    }

    /// Folds one pane's matches into the store. Returns the findings that are
    /// new — the ones a notification would be about.
    ///
    /// Re-observing an existing finding updates `last_seen` and nothing else. It
    /// must not un-acknowledge it and must not be reported as new, or a
    /// dismissed warning would come straight back on the next cycle.
    pub fn observe(&mut self, pane: &PaneRef, matches: &[Match], now: u64) -> Vec<Finding> {
        let mut fresh = Vec::new();
        for candidate in matches {
            // Suppression is global across panes on purpose: the digest is
            // pane-independent, and the same exact false positive printed in a
            // second pane should stay quiet. The rule remains part of the key so
            // the same value can still be caught by a different detector.
            if self
                .suppressions
                .iter()
                .any(|entry| entry.rule == candidate.pattern && entry.digest == candidate.digest)
            {
                continue;
            }
            let id = Finding::fingerprint(&candidate.pattern, &pane.pane_id, candidate.digest);
            // The same secret twice in one pane is one finding: the fingerprint
            // does not carry the line number, so the second sighting lands here.
            if let Some(existing) = self.findings.iter_mut().find(|f| f.id == id) {
                existing.last_seen = now;
                continue;
            }
            let finding = Finding {
                id,
                pattern: candidate.pattern.clone(),
                label: candidate.label.clone(),
                confidence: candidate.confidence,
                preview: candidate.preview.clone(),
                value_len: candidate.value_len,
                pane_id: pane.pane_id.clone(),
                workspace_id: pane.workspace_id.clone(),
                pane_label: pane.label().to_string(),
                agent: pane.agent.clone(),
                cwd: pane.cwd.clone(),
                foreground_process_name_when_first_seen: None,
                foreground_process_pid_when_first_seen: None,
                line: candidate.line,
                digest: candidate.digest,
                first_seen: now,
                last_seen: now,
                acknowledged: false,
            };
            self.findings.push(finding.clone());
            fresh.push(finding);
        }
        self.pending.extend(fresh.iter().cloned());
        self.enforce_cap();
        fresh
    }

    /// Adds the foreground process observed immediately after these findings
    /// were first seen. Both the store and notification queue own copies.
    pub fn record_foreground_process_when_first_seen(
        &mut self,
        fresh: &[Finding],
        name: Option<&str>,
        pid: Option<u32>,
    ) {
        if name.is_none() && pid.is_none() {
            return;
        }
        for finding in self.findings.iter_mut().chain(self.pending.iter_mut()) {
            if fresh.iter().any(|candidate| candidate.id == finding.id) {
                finding.foreground_process_name_when_first_seen = name.map(str::to_string);
                finding.foreground_process_pid_when_first_seen = pid;
            }
        }
    }

    /// Drops findings whose pane is no longer in the session.
    ///
    /// The pane's scrollback died with the pane, so there is nothing left to
    /// warn about. The per-pane caches go with them, so a long-lived daemon in a
    /// churning session does not grow without bound.
    pub fn prune_to(&mut self, live_pane_ids: &[String]) -> usize {
        let before = self.findings.len();
        self.findings
            .retain(|finding| live_pane_ids.iter().any(|id| id == &finding.pane_id));
        self.seen_text
            .retain(|pane_id, _| live_pane_ids.iter().any(|id| id == pane_id));
        self.notified
            .retain(|(_, pane_id)| live_pane_ids.iter().any(|id| id == pane_id));
        self.backfilled_panes
            .retain(|pane_id| live_pane_ids.iter().any(|id| id == pane_id));
        before - self.findings.len()
    }

    /// Acknowledges by id or unambiguous id prefix. Returns how many were
    /// acknowledged; zero is an error at the call site, not here.
    ///
    /// An ambiguous prefix acknowledges nothing: silently picking one of two
    /// findings would leave the user believing they had dismissed the other.
    pub fn acknowledge(&mut self, id: &str) -> usize {
        let Some(index) = self.finding_index(id) else {
            return 0;
        };
        self.findings[index].acknowledged = true;
        1
    }

    /// Acknowledges a finding and permanently suppresses this exact value for
    /// this rule. The pane is deliberately absent from the suppression key.
    pub fn suppress(&mut self, id: &str) -> usize {
        let Some(index) = self.finding_index(id) else {
            return 0;
        };
        self.findings[index].acknowledged = true;
        let finding = &self.findings[index];
        if !self
            .suppressions
            .iter()
            .any(|entry| entry.rule == finding.pattern && entry.digest == finding.digest)
        {
            self.suppressions.push(Suppression {
                rule: finding.pattern.clone(),
                digest: finding.digest,
            });
        }
        1
    }

    pub fn suppression_count(&self) -> usize {
        self.suppressions.len()
    }

    pub fn suppressions(&self) -> &[Suppression] {
        &self.suppressions
    }

    /// Acknowledges everything outstanding. Returns how many findings changed,
    /// so acknowledging an already-quiet store reports zero rather than lying.
    pub fn acknowledge_all(&mut self) -> usize {
        let mut count = 0;
        for finding in &mut self.findings {
            if !finding.acknowledged {
                finding.acknowledged = true;
                count += 1;
            }
        }
        count
    }

    /// Forgets every finding and permanent suppression. The state file is
    /// rewritten empty rather than deleted, so the digest key survives.
    ///
    /// The notification limiter is *not* reset: this is still the same daemon
    /// run, and a user who cleared the list did not ask to be toasted again.
    pub fn forget_all(&mut self) -> usize {
        let count = self.findings.len();
        self.findings.clear();
        self.suppressions.clear();
        self.pending.clear();
        count
    }

    /// Whether a toast should be posted for this finding, and marks it shouted
    /// about. One per pattern per pane per daemon run.
    pub fn claim_notification(&mut self, finding: &Finding) -> bool {
        self.notified
            .insert((finding.pattern.clone(), finding.pane_id.clone()))
    }

    /// Findings first seen since the last drain. The daemon notifies from this;
    /// the one-shot verbs drop it on the floor, which is why `--once` is silent.
    pub fn take_new_findings(&mut self) -> Vec<Finding> {
        std::mem::take(&mut self.pending)
    }

    /// Whether this pane's text differs from the last text scanned for it, and
    /// records the new text as scanned.
    ///
    /// A cache hit means "do not scan again", never "this pane has no findings":
    /// the existing findings are untouched and stay in the report.
    pub fn pane_text_changed(&mut self, pane_id: &str, text: &str) -> bool {
        let hash = crate::model::digest(&self.key, text);
        if self.seen_text.get(pane_id) == Some(&hash) {
            return false;
        }
        self.seen_text.insert(pane_id.to_string(), hash);
        true
    }

    /// Whether this pane is still owed the deep scrollback read for this
    /// watcher run. Read-only: the pane is only marked once a read has actually
    /// come back, by [`Store::mark_backfilled`].
    pub fn needs_backfill(&self, pane_id: &str) -> bool {
        !self.backfilled_panes.contains(pane_id)
    }

    /// Records that this pane's deep read has happened, so later cycles use the
    /// ordinary window.
    pub fn mark_backfilled(&mut self, pane_id: &str) {
        self.backfilled_panes.insert(pane_id.to_string());
    }

    /// Re-reads the findings file if another process has rewritten it, keeping
    /// this run's in-memory state (the key, the notification limiter).
    ///
    /// Without this a daemon would hold a stale copy of the findings and its
    /// Index into this cycle's pane list at which reading should start. See
    /// [`Store::scan_cursor`].
    pub fn scan_cursor(&self, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            self.scan_cursor % len
        }
    }

    /// Records where the next cycle should pick up.
    pub fn set_scan_cursor(&mut self, at: usize) {
        self.scan_cursor = at;
    }

    /// Re-reads the state file if another process has rewritten it since we last
    /// touched it, so this run's next save cannot silently undo an
    /// acknowledgement or suppression made from a shell. Returns whether
    /// anything was reloaded.
    pub fn reload_if_changed(&mut self, config: &Config) -> bool {
        let stamp = fs::read(&self.path)
            .ok()
            .map(|bytes| crate::model::digest(&STAMP_KEY, &String::from_utf8_lossy(&bytes)));
        if stamp == self.stamp.get() {
            return false;
        }
        let mut notes = Vec::new();
        let (findings, suppressions, stamp) = read_state(&self.path, &mut notes);
        self.findings = findings;
        self.suppressions = suppressions;
        self.apply_suppressions_to_findings();
        self.stamp.set(stamp);
        self.max_findings = config.max_findings.max(1);
        for note in notes {
            self.push_note(note);
        }
        // Someone may have forgotten everything; the panes' text has not changed
        // so the cache would keep us from ever looking at them again.
        self.seen_text.clear();
        self.enforce_cap();
        true
    }

    /// Every finding, unacknowledged first, then most recently seen first.
    pub fn findings(&self) -> Vec<Finding> {
        let mut findings = self.findings.clone();
        // Ties broken by id so two findings seen in the same second do not swap
        // places between cycles and make the pane flicker.
        findings.sort_by(|a, b| {
            a.acknowledged
                .cmp(&b.acknowledged)
                .then(b.last_seen.cmp(&a.last_seen))
                .then(a.id.cmp(&b.id))
        });
        findings
    }

    /// Builds the report the renderers consume. The store's own notes come
    /// first: a state file it could not read explains everything below it.
    pub fn report(&self, notes: Vec<String>) -> Report {
        let mut all = self.notes.clone();
        for note in notes {
            if !all.contains(&note) {
                all.push(note);
            }
        }
        if !self.suppressions.is_empty() {
            all.push(format!(
                "{}{SUPPRESSIONS_NOTE_SUFFIX}",
                self.suppressions.len()
            ));
        }
        Report {
            findings: self.findings(),
            notes: all,
            generated_at: crate::model::now(),
            ..Report::default()
        }
    }

    /// Folds in monotonic state another process has written since our last read.
    ///
    /// [`Store::reload_if_changed`] runs at the *top* of a cycle, and a cycle on
    /// a large session takes tens of seconds. An acknowledgement or suppression
    /// typed into a shell during that window must not be overwritten by this
    /// run's save the moment the cycle finishes.
    ///
    /// Acknowledgements and suppressions are monotonic within a run, so merging
    /// is a union. `--forget` is deliberately *not* merged: it empties the file,
    /// and a watcher looking at the same screen will report what is still there.
    fn adopt_external_monotonic_state(&mut self) {
        let stamp = fs::read(&self.path)
            .ok()
            .map(|bytes| crate::model::digest(&STAMP_KEY, &String::from_utf8_lossy(&bytes)));
        if stamp == self.stamp.get() {
            return;
        }
        let mut notes = Vec::new();
        let (theirs, their_suppressions, _) = read_state(&self.path, &mut notes);
        for other in theirs {
            if !other.acknowledged {
                continue;
            }
            if let Some(ours) = self.findings.iter_mut().find(|f| f.id == other.id) {
                ours.acknowledged = true;
            }
        }
        for suppression in their_suppressions {
            if !self.suppressions.contains(&suppression) {
                self.suppressions.push(suppression);
            }
        }
        self.apply_suppressions_to_findings();
        // Deliberately silent about read problems here: `reload_if_changed` at
        // the top of the next cycle reports them, and a save is not the place to
        // start narrating.
    }

    /// Writes the store out atomically: a temp file in the same directory, then
    /// a rename. A daemon killed mid-write cannot leave a half-written file that
    /// loses every acknowledgement.
    pub fn save(&mut self) -> Result<()> {
        self.adopt_external_monotonic_state();
        let dir = self
            .path
            .parent()
            .ok_or_else(|| format!("{} has no parent directory", self.path.display()))?;
        fs::create_dir_all(dir)?;

        let file = StoredFile {
            version: FILE_VERSION,
            findings: self.findings.iter().map(StoredFinding::from).collect(),
            suppressions: self
                .suppressions
                .iter()
                .map(StoredSuppression::from)
                .collect(),
        };
        let mut body = serde_json::to_string_pretty(&file)?;
        body.push('\n');

        // Same directory, so the rename is atomic; pid in the name so two
        // processes saving at once cannot corrupt each other's temp file.
        let name = self
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "findings.json".to_string());
        let temp = dir.join(format!("{name}.tmp.{}", std::process::id()));

        // Created 0600 from the start: a chmod after the write leaves a window
        // in which the file is world-readable.
        let mut handle = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(PRIVATE)
            .open(&temp)?;
        handle.write_all(body.as_bytes())?;
        handle.sync_all()?;
        drop(handle);

        if let Err(err) = fs::rename(&temp, &self.path) {
            let _ = fs::remove_file(&temp);
            return Err(Box::new(err));
        }
        self.stamp
            .set(Some(crate::model::digest(&STAMP_KEY, &body)));
        Ok(())
    }

    fn push_note(&mut self, note: String) {
        if !self.notes.contains(&note) {
            self.notes.push(note);
        }
    }

    fn finding_index(&self, id: &str) -> Option<usize> {
        let needle = id.trim().to_ascii_lowercase();
        if needle.is_empty() {
            return None;
        }
        if let Some(index) = self
            .findings
            .iter()
            .position(|finding| finding.id == needle)
        {
            return Some(index);
        }
        let mut hits = self
            .findings
            .iter()
            .enumerate()
            .filter(|(_, finding)| finding.id.starts_with(&needle));
        match (hits.next(), hits.next()) {
            (Some((index, _)), None) => Some(index),
            _ => None,
        }
    }

    fn apply_suppressions_to_findings(&mut self) {
        for finding in &mut self.findings {
            if self
                .suppressions
                .iter()
                .any(|entry| entry.rule == finding.pattern && entry.digest == finding.digest)
            {
                finding.acknowledged = true;
            }
        }
    }

    /// Keeps the store under `max_findings`.
    ///
    /// Acknowledged findings go first, least recently seen first: the user has
    /// already looked at them. An unacknowledged finding is only ever dropped
    /// when there is nothing acknowledged left to drop, and that is loud —
    /// silently forgetting a warning is the one thing this store must not do.
    /// Trims the store back to `max_findings`.
    ///
    /// Acknowledged findings go first, oldest by `last_seen`; only when there
    /// are none left does an unacknowledged one get dropped, and that is loud.
    ///
    /// Ties are broken by **insertion order**, not by id. Every finding from one
    /// cycle shares the same `now`, so a tie is the normal case rather than the
    /// exotic one, and an id tie-break made the choice effectively random: the
    /// finding discovered *this* cycle could be the one dropped, while the note
    /// said the oldest had been. `min_by` returns the first of several equal
    /// minima, and `self.findings` is push-ordered, so leaving the id out of the
    /// key is what makes "oldest" mean oldest.
    fn enforce_cap(&mut self) {
        while self.findings.len() > self.max_findings {
            let acknowledged = self
                .findings
                .iter()
                .enumerate()
                .filter(|(_, f)| f.acknowledged)
                .min_by_key(|(_, f)| (f.last_seen, f.first_seen))
                .map(|(index, _)| index);
            let (index, unacknowledged) = match acknowledged {
                Some(index) => (index, false),
                None => (
                    self.findings
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, f)| (f.first_seen, f.last_seen))
                        .map(|(index, _)| index)
                        .unwrap_or(0),
                    true,
                ),
            };
            let dropped = self.findings.remove(index);
            // A finding that no longer exists must not be toasted about. It was
            // queued for notification the moment it was observed, and a toast
            // naming an id that `--ack` cannot find is worse than no toast.
            self.pending.retain(|f| f.id != dropped.id);

            if unacknowledged {
                let cap = self.max_findings;
                self.push_note(format!(
                    "the findings cap of {cap} was reached with nothing acknowledged; the oldest \
                     unacknowledged findings were dropped and will not be reported again until \
                     their pane's output changes"
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// On-disk shape
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct StoredFile {
    version: u32,
    #[serde(default)]
    findings: Vec<StoredFinding>,
    #[serde(default)]
    suppressions: Vec<StoredSuppression>,
}

/// One persisted finding.
///
/// Every field here was chosen deliberately. `preview` is masked at the source
/// by `scan::mask` and `digest` is keyed by the per-installation key, so the
/// file identifies a credential without containing one.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct StoredFinding {
    id: String,
    pattern: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    confidence: String,
    #[serde(default)]
    preview: String,
    #[serde(default)]
    value_len: usize,
    pane_id: String,
    #[serde(default)]
    workspace_id: String,
    #[serde(default)]
    pane_label: String,
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    cwd: Option<PathBuf>,
    #[serde(default)]
    foreground_process_name_when_first_seen: Option<String>,
    #[serde(default)]
    foreground_process_pid_when_first_seen: Option<u32>,
    #[serde(default)]
    line: usize,
    digest: u64,
    #[serde(default)]
    first_seen: u64,
    #[serde(default)]
    last_seen: u64,
    #[serde(default)]
    acknowledged: bool,
}

/// One persisted suppression, with every field named by hand so a future model
/// change cannot silently put a value on disk.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct StoredSuppression {
    rule: String,
    digest: u64,
}

impl From<&Suppression> for StoredSuppression {
    fn from(suppression: &Suppression) -> Self {
        Self {
            rule: suppression.rule.clone(),
            digest: suppression.digest,
        }
    }
}

impl StoredSuppression {
    fn into_suppression(self) -> Suppression {
        Suppression {
            rule: self.rule,
            digest: self.digest,
        }
    }
}

impl From<&Finding> for StoredFinding {
    fn from(finding: &Finding) -> Self {
        Self {
            id: finding.id.clone(),
            pattern: finding.pattern.clone(),
            label: finding.label.clone(),
            confidence: finding.confidence.as_str().to_string(),
            preview: finding.preview.clone(),
            value_len: finding.value_len,
            pane_id: finding.pane_id.clone(),
            workspace_id: finding.workspace_id.clone(),
            pane_label: finding.pane_label.clone(),
            agent: finding.agent.clone(),
            cwd: finding.cwd.clone(),
            foreground_process_name_when_first_seen: finding
                .foreground_process_name_when_first_seen
                .clone(),
            foreground_process_pid_when_first_seen: finding.foreground_process_pid_when_first_seen,
            line: finding.line,
            digest: finding.digest,
            first_seen: finding.first_seen,
            last_seen: finding.last_seen,
            acknowledged: finding.acknowledged,
        }
    }
}

impl StoredFinding {
    fn into_finding(self) -> Finding {
        Finding {
            id: self.id,
            pattern: self.pattern,
            label: self.label,
            // An unrecognised level came from a newer build. Reading it as the
            // louder one keeps a real credential loud; the other way round a
            // downgrade would quietly demote it to a hint.
            confidence: match self.confidence.as_str() {
                "weak" => Confidence::Weak,
                _ => Confidence::Strong,
            },
            preview: self.preview,
            value_len: self.value_len,
            pane_id: self.pane_id,
            workspace_id: self.workspace_id,
            pane_label: self.pane_label,
            agent: self.agent,
            cwd: self.cwd,
            foreground_process_name_when_first_seen: self.foreground_process_name_when_first_seen,
            foreground_process_pid_when_first_seen: self.foreground_process_pid_when_first_seen,
            line: self.line,
            digest: self.digest,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            acknowledged: self.acknowledged,
        }
    }
}

/// Reads the findings file. Returns findings, suppressions, and the change stamp.
///
/// Every failure below is a note rather than an error: the scanner has to keep
/// running. But none of them is silent, because an empty report from a store
/// that could not be read looks exactly like a clean session.
fn read_state(
    path: &Path,
    notes: &mut Vec<String>,
) -> (Vec<Finding>, Vec<Suppression>, Option<u64>) {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return (Vec::new(), Vec::new(), None);
        }
        Err(err) => {
            notes.push(format!(
                "could not read the findings file {} ({err}) — this report shows no history, \
                 which is not the same as a clean session",
                path.display()
            ));
            return (Vec::new(), Vec::new(), None);
        }
    };
    let stamp = Some(crate::model::digest(&STAMP_KEY, &raw));
    if raw.trim().is_empty() {
        return (Vec::new(), Vec::new(), stamp);
    }
    match serde_json::from_str::<StoredFile>(&raw) {
        Ok(file) => (
            file.findings
                .into_iter()
                .map(StoredFinding::into_finding)
                .collect(),
            file.suppressions
                .into_iter()
                .map(StoredSuppression::into_suppression)
                .collect(),
            stamp,
        ),
        Err(err) => {
            // Kept rather than overwritten: the next save would destroy it, and
            // a state file this plugin could not parse is worth a bug report.
            let backup = path.with_extension("json.corrupt");
            let kept = fs::rename(path, &backup).is_ok();
            notes.push(format!(
                "the findings file {} is malformed ({err}) — earlier acknowledgements are lost \
                 and this report shows no history, which is not the same as a clean session{}",
                path.display(),
                if kept {
                    format!("; the unreadable file was kept as {}", backup.display())
                } else {
                    String::new()
                }
            ));
            (Vec::new(), Vec::new(), None)
        }
    }
}

/// The per-installation digest key: read it, or draw a new one and persist it.
///
/// It never changes once written. A new key would re-fingerprint every stored
/// finding, so every acknowledgement the user had made would come back as a
/// fresh warning.
fn load_or_create_key(path: &Path, notes: &mut Vec<String>) -> DigestKey {
    if let Ok(raw) = fs::read_to_string(path) {
        if let Some(key) = parse_key(raw.trim()) {
            return key;
        }
        notes.push(format!(
            "the digest key in {} is unreadable; a new one was drawn, so findings acknowledged \
             before now will be reported again once",
            path.display()
        ));
    }

    let key = draw_key(notes);
    let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    if let Err(err) = write_private(path, &hex) {
        notes.push(format!(
            "could not store the digest key in {} ({err}); acknowledgements will not survive a \
             restart",
            path.display()
        ));
    }
    key
}

fn parse_key(raw: &str) -> Option<DigestKey> {
    if raw.len() != 32 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut key = [0u8; 16];
    for (index, slot) in key.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&raw[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(key)
}

/// 16 bytes from `/dev/urandom`.
///
/// The fallback is deliberately weak and deliberately loud. A predictable key
/// makes the stored digests guessable for a low-entropy secret, which is the one
/// thing keying them was for, so it must not pass unremarked.
fn draw_key(notes: &mut Vec<String>) -> DigestKey {
    let mut key = [0u8; 16];
    // `read_exact` rather than `fs::read`: /dev/urandom is an endless stream and
    // never reaches EOF, so reading it to the end would never return.
    let drawn = fs::File::open("/dev/urandom").and_then(|mut file| file.read_exact(&mut key));
    match drawn {
        Ok(()) => return key,
        Err(err) => notes.push(format!(
            "could not read /dev/urandom ({err}); the digest key for this installation is derived \
             from the clock and is not unpredictable"
        )),
    }
    let seed = crate::model::now() ^ (u64::from(std::process::id()) << 32);
    key[..8].copy_from_slice(&seed.to_le_bytes());
    key[8..].copy_from_slice(&seed.rotate_left(17).to_be_bytes());
    key
}

fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut handle = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(PRIVATE)
        .open(path)?;
    handle.write_all(contents.as_bytes())?;
    handle.write_all(b"\n")
}
