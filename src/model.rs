//! Shared types. This module is the contract between the scanner, the socket
//! client, the findings store, the daemon and the renderers, so that each can be
//! developed and tested independently.
//!
//! # The rule this module exists to enforce
//!
//! **A secret value never leaves `scan.rs`.** The scanner is the only code that
//! ever holds a matched credential, and the only things it is allowed to hand
//! back are in this file: a masked [`preview`](Match::preview), a length, a
//! [`digest`](Match::digest), and metadata. There is deliberately no field
//! anywhere below that can carry a raw value, so "did we leak it?" is a question
//! about one module rather than about the whole program.

use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

/// Keying material for [`digest`], drawn once per installation and stored in the
/// plugin state directory.
///
/// It exists so the persisted acknowledgement file can say "this exact finding
/// again" without storing anything derived from the secret in an unkeyed way. A
/// bare hash of a low-entropy value (`PASSWORD=hunter2`) is a guessing oracle;
/// a keyed one is only as useful as the key, which never leaves the machine and
/// lives beside the file it protects.
pub type DigestKey = [u8; 16];

/// FNV-1a over `key ++ value`.
///
/// Not a cryptographic MAC and not claimed to be one. Its job is collision
/// resistance good enough that two different credentials in one pane are not
/// mistaken for each other, plus enough keying that the stored value is not a
/// dictionary lookup away from the original. It is deliberately dependency-free
/// and deterministic, so the same finding fingerprints identically across runs.
pub fn digest(key: &DigestKey, value: &str) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for byte in key.iter().copied().chain(value.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

// ---------------------------------------------------------------------------
// Panes
// ---------------------------------------------------------------------------

/// One herdr pane, reduced to what the scanner and the renderers need.
///
/// Built from `session.snapshot`. `agent` is `None` for a plain shell pane —
/// that absence is the default scan filter, not an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaneRef {
    pub pane_id: String,
    pub workspace_id: String,
    pub tab_id: String,
    /// The workspace's own label, for the report's location column.
    pub workspace_label: String,
    /// Agent program or the user's name for it, when herdr reports one.
    pub agent: Option<String>,
    /// `terminal_title_stripped`, which is the most human thing a pane carries.
    pub title: Option<String>,
    pub cwd: Option<PathBuf>,
}

impl PaneRef {
    /// Short human label for a pane: the agent name when there is one, the pane
    /// id otherwise. Never the title — titles are long and change constantly.
    pub fn label(&self) -> &str {
        self.agent.as_deref().unwrap_or(&self.pane_id)
    }
}

/// One pane's terminal text as `pane.read` returned it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaneText {
    pub pane_id: String,
    pub text: String,
    /// herdr had more output than `lines` allowed, so this is not the whole
    /// story. Surfaced in the UI rather than swallowed.
    pub truncated: bool,
}

// ---------------------------------------------------------------------------
// Matches
// ---------------------------------------------------------------------------

/// How much a match is trusted. Ordering is severity order.
///
/// `Weak` exists so the `.env`-style assignment heuristic (`FOO_TOKEN=…`) can be
/// reported without being given the same weight as a structurally verified
/// provider key. It gets its own badge token, and so its own colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    Weak,
    Strong,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Weak => "weak",
            Confidence::Strong => "strong",
        }
    }
}

/// One credential-shaped thing found in one blob of text.
///
/// Produced by [`crate::scan::scan`], which is a pure function. Nothing here can
/// carry the matched value: `preview` is masked at source and `digest` is keyed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// Stable machine name of the rule that fired, e.g. `aws_access_key_id`.
    /// This is what notification rate limiting and the config allowlist key on,
    /// so it must never change between releases without a note.
    pub pattern: String,
    /// Human name of the rule, e.g. `AWS access key ID`.
    pub label: String,
    pub confidence: Confidence,
    /// Masked rendering of the value — see [`crate::scan::mask`]. At most the
    /// first four and last four characters, and never more than a third of the
    /// value.
    pub preview: String,
    /// Length in characters of the value that matched. Safe to print: it is
    /// already implied by the pattern for every fixed-width provider key.
    pub value_len: usize,
    /// 1-based line number within the scanned text.
    pub line: usize,
    /// Keyed digest of the matched value. Identity only — never rendered.
    pub digest: u64,
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/// A [`Match`] pinned to the pane it was seen in, with the lifecycle state the
/// store keeps for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Short stable handle for `--ack <id>`, derived from the fingerprint.
    pub id: String,
    pub pattern: String,
    pub label: String,
    pub confidence: Confidence,
    pub preview: String,
    pub value_len: usize,
    pub pane_id: String,
    pub workspace_id: String,
    /// Pane label at the time of the sighting, for display.
    pub pane_label: String,
    pub line: usize,
    pub digest: u64,
    /// Unix seconds. A finding stays until acknowledged, so `first_seen` is what
    /// the report sorts and ages by.
    pub first_seen: u64,
    pub last_seen: u64,
    pub acknowledged: bool,
}

/// Characters of the fingerprint a user has to type for `--ack`. Six hex
/// characters is 24 bits, which is ample for the handful of findings a session
/// produces and short enough to read off a sidebar and retype.
pub const SHORT_ID_CHARS: usize = 6;

impl Finding {
    /// Identity of a finding: the same credential, in the same pane, from the
    /// same rule. Deliberately *not* keyed on the line number — output scrolls,
    /// and the same secret moving up the pane is not a new exposure.
    pub fn fingerprint(pattern: &str, pane_id: &str, digest: u64) -> String {
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&digest.to_le_bytes());
        let combined = crate::model::digest(&key, &format!("{pattern}\u{0}{pane_id}"));
        format!("{combined:016x}")
    }

    /// The short handle a user types. Long enough that collisions are not a
    /// practical concern for the handful of findings a session produces.
    ///
    /// Sliced on a character boundary rather than a byte one. Our own ids are
    /// hex and so can never need it, but a hand-edited state file is not our
    /// own, and this is a display path — it must not be able to panic.
    pub fn short_id(&self) -> &str {
        match self.id.char_indices().nth(SHORT_ID_CHARS) {
            Some((end, _)) => &self.id[..end],
            None => &self.id,
        }
    }
}

// ---------------------------------------------------------------------------
// Alert level and badge tokens
// ---------------------------------------------------------------------------

/// Worst unacknowledged finding for one badge target, which is what the badge
/// shows. Severity is carried by the token *name* because herdr renders a token
/// value as flat text and cannot colour by content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Alert {
    #[default]
    Clear,
    Weak,
    Secret,
}

impl Alert {
    pub fn token_name(self) -> &'static str {
        match self {
            // Never actually set: a clear target clears its tokens instead of
            // writing an empty one. Named so the disable sweep has something
            // total to clear.
            Alert::Clear => "redact_clear",
            Alert::Weak => "redact_weak",
            Alert::Secret => "redact_secret",
        }
    }

    /// Every token name this plugin may ever have written, for the disable
    /// sweep. Clearing a name that was never set costs one round trip and
    /// cannot go stale.
    pub const ALL_TOKENS: [&'static str; 3] = ["redact_clear", "redact_weak", "redact_secret"];

    /// The two names a user has to colour in `config.toml`.
    pub const CONFIGURED_TOKENS: [&'static str; 2] = ["redact_weak", "redact_secret"];

    pub fn from_confidence(confidence: Confidence) -> Self {
        match confidence {
            Confidence::Weak => Alert::Weak,
            Confidence::Strong => Alert::Secret,
        }
    }
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

/// Everything one scan cycle produced, shared by the badge daemon, the findings
/// pane, and the JSON action.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Unacknowledged first, then most recent first. The renderer does not sort.
    pub findings: Vec<Finding>,
    pub panes_scanned: usize,
    /// Panes herdr reported but that we chose not to read (not an agent pane,
    /// with `scan_all_panes` off).
    pub panes_skipped: usize,
    /// Panes whose output was cut short by the `lines` budget.
    pub panes_truncated: usize,
    /// Human-readable problems from this cycle: a pane that vanished, a rule
    /// that would not compile, a read that failed. Never silently dropped —
    /// "nothing found" and "I could not look" must not render the same.
    pub notes: Vec<String>,
    /// Unix seconds.
    pub generated_at: u64,
}

impl Report {
    pub fn unacknowledged(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| !f.acknowledged)
    }

    /// Worst unacknowledged alert across every finding, which is what a
    /// session-wide summary shows.
    pub fn alert(&self) -> Alert {
        self.unacknowledged()
            .map(|f| Alert::from_confidence(f.confidence))
            .max()
            .unwrap_or(Alert::Clear)
    }

    /// Worst unacknowledged alert for one pane, plus how many findings carry it.
    pub fn alert_for_pane(&self, pane_id: &str) -> (Alert, usize) {
        alert_of(self.unacknowledged().filter(|f| f.pane_id == pane_id))
    }

    /// Worst unacknowledged alert for one workspace, plus how many findings
    /// carry it.
    pub fn alert_for_workspace(&self, workspace_id: &str) -> (Alert, usize) {
        alert_of(
            self.unacknowledged()
                .filter(|f| f.workspace_id == workspace_id),
        )
    }
}

/// Worst alert in a set of findings and the count *at that level*.
///
/// The count is level-scoped on purpose: a badge reading `⚠ 3` next to one real
/// key and two weak assignments would overstate what was actually found.
fn alert_of<'a>(findings: impl Iterator<Item = &'a Finding>) -> (Alert, usize) {
    let mut alert = Alert::Clear;
    let mut count = 0usize;
    for finding in findings {
        let level = Alert::from_confidence(finding.confidence);
        match level.cmp(&alert) {
            std::cmp::Ordering::Greater => {
                alert = level;
                count = 1;
            }
            std::cmp::Ordering::Equal => count += 1,
            std::cmp::Ordering::Less => {}
        }
    }
    (alert, count)
}

/// Seconds since the Unix epoch, or 0 if the clock is before it.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
