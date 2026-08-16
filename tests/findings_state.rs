//! The findings store, against a temp state directory.
//!
//! The load-bearing test in this file is the last one: a credential must not
//! appear in the bytes the store writes. Everything else protects the
//! acknowledgement lifecycle, which is what stops the plugin from crying wolf.
//!
//! No running herdr is required, and nothing here writes outside a temp
//! directory.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use redact::config::{self, Config};
use redact::findings::Store;
use redact::model::{Confidence, Finding, Match, PaneRef};

/// A structurally valid but obviously fake AWS access key ID. It exists so the
/// "nothing on disk is a secret" test has a concrete string to hunt for.
const FAKE_CREDENTIAL: &str = "AKIAIOSFODNN7EXAMPLE";

/// `HERDR_PLUGIN_STATE_DIR` is process-global, so these tests run one at a time
/// even though cargo runs them on separate threads.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A temp state directory, pointed at by `HERDR_PLUGIN_STATE_DIR` for as long
/// as it is alive.
struct StateDir {
    path: PathBuf,
    _guard: MutexGuard<'static, ()>,
}

impl StateDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let guard = env_lock();
        let path = std::env::temp_dir().join(format!(
            "redact-state-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("temp state dir");
        std::env::set_var("HERDR_PLUGIN_STATE_DIR", &path);
        Self {
            path,
            _guard: guard,
        }
    }

    fn findings_file(&self) -> PathBuf {
        self.path.join("findings.json")
    }

    fn read_findings_file(&self) -> String {
        fs::read_to_string(self.findings_file()).expect("findings file")
    }
}

impl Drop for StateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn config(max_findings: usize) -> Config {
    Config {
        max_findings,
        ..Config::default()
    }
}

fn pane(pane_id: &str) -> PaneRef {
    PaneRef {
        pane_id: pane_id.to_string(),
        workspace_id: pane_id.split(':').next().unwrap_or(pane_id).to_string(),
        tab_id: format!("{}:t1", pane_id.split(':').next().unwrap_or(pane_id)),
        workspace_label: "media-throughput".to_string(),
        agent: Some("rev-media".to_string()),
        title: None,
        cwd: None,
    }
}

/// A match with the shape `scan` produces: a masked preview, a length, and a
/// keyed digest. There is no field that could carry the value.
fn a_match(pattern: &str, digest: u64) -> Match {
    Match {
        pattern: pattern.to_string(),
        label: "AWS access key ID".to_string(),
        confidence: Confidence::Strong,
        preview: "AKIA\u{2026}MPLE".to_string(),
        value_len: FAKE_CREDENTIAL.len(),
        line: 12,
        digest,
    }
}

fn only(findings: &[Finding]) -> &Finding {
    assert_eq!(findings.len(), 1, "expected one finding, got {findings:?}");
    &findings[0]
}

#[test]
fn a_finding_survives_re_observation_without_becoming_new_again() {
    let state = StateDir::new();
    let config = config(500);
    let mut store = Store::load(&config);

    let fresh = store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 7)], 100);
    assert_eq!(fresh.len(), 1, "the first sighting is new");

    let again = store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 7)], 250);
    assert!(
        again.is_empty(),
        "the same credential in the same pane is not a new exposure"
    );

    let findings = store.findings();
    let finding = only(&findings);
    assert_eq!(finding.first_seen, 100);
    assert_eq!(finding.last_seen, 250, "re-observing refreshes last_seen");
    assert_eq!(finding.pane_label, "rev-media");
    drop(state);
}

/// Output scrolls, and the same secret moving up the pane is not a new
/// exposure. The fingerprint is deliberately not keyed on the line number.
#[test]
fn the_same_secret_on_a_different_line_is_the_same_finding() {
    let state = StateDir::new();
    let config = config(500);
    let mut store = Store::load(&config);

    store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 7)], 100);
    let mut moved = a_match("aws_access_key_id", 7);
    moved.line = 940;
    let fresh = store.observe(&pane("wE:p2"), &[moved], 200);

    assert!(fresh.is_empty());
    assert_eq!(store.findings().len(), 1);
    drop(state);
}

#[test]
fn re_observing_an_acknowledged_finding_does_not_un_acknowledge_it() {
    let state = StateDir::new();
    let config = config(500);
    let mut store = Store::load(&config);

    let fresh = store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 7)], 100);
    assert_eq!(store.acknowledge(&fresh[0].id), 1);

    store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 7)], 200);

    let findings = store.findings();
    assert!(
        only(&findings).acknowledged,
        "a dismissed warning must not come straight back"
    );
    drop(state);
}

#[test]
fn an_acknowledgement_survives_a_save_and_a_reload() {
    let state = StateDir::new();
    let config = config(500);

    let id = {
        let mut store = Store::load(&config);
        let fresh = store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 7)], 100);
        store.acknowledge_all();
        store.save().expect("save");
        fresh[0].id.clone()
    };

    let store = Store::load(&config);
    let findings = store.findings();
    let finding = only(&findings);
    assert_eq!(finding.id, id, "the fingerprint must be stable across runs");
    assert!(finding.acknowledged);
    assert_eq!(finding.pattern, "aws_access_key_id");
    assert_eq!(finding.confidence, Confidence::Strong);
    assert_eq!(finding.value_len, FAKE_CREDENTIAL.len());
    assert_eq!(finding.first_seen, 100);
    drop(state);
}

#[test]
fn acknowledging_by_an_unambiguous_prefix_works_and_an_ambiguous_one_does_not() {
    let state = StateDir::new();
    let config = config(500);
    let mut store = Store::load(&config);

    let fresh = store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 7)], 100);
    let id = fresh[0].id.clone();

    assert_eq!(
        store.acknowledge("nope"),
        0,
        "an unknown id matches nothing"
    );
    assert_eq!(store.acknowledge(&id[..6]), 1, "a short prefix is enough");

    // Every id shares the empty prefix, so it must never resolve to one.
    assert_eq!(store.acknowledge(""), 0);
    drop(state);
}

/// Silently picking one of two findings would leave the user believing they had
/// dismissed the other.
#[test]
fn an_ambiguous_prefix_acknowledges_nothing() {
    let state = StateDir::new();
    let config = config(500);
    let mut store = Store::load(&config);

    // Ids are 16 hex characters, so a hundred of them are certain to share a
    // first character with something.
    for digest in 1..=100u64 {
        store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", digest)], 100);
    }
    let ids: Vec<String> = store.findings().iter().map(|f| f.id.clone()).collect();
    let shared = ids
        .iter()
        .map(|id| id[..1].to_string())
        .find(|prefix| ids.iter().filter(|id| id.starts_with(prefix)).count() > 1)
        .expect("a shared first character among a hundred ids");

    assert_eq!(
        store.acknowledge(&shared),
        0,
        "prefix {shared} is ambiguous"
    );
    assert!(
        store.findings().iter().all(|f| !f.acknowledged),
        "an ambiguous prefix must acknowledge nothing at all"
    );
    drop(state);
}

#[test]
fn prune_to_drops_a_closed_panes_findings() {
    let state = StateDir::new();
    let config = config(500);
    let mut store = Store::load(&config);

    store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 7)], 100);
    store.observe(&pane("wM:p1"), &[a_match("aws_access_key_id", 9)], 100);

    let dropped = store.prune_to(&["wM:p1".to_string()]);

    assert_eq!(dropped, 1);
    let findings = store.findings();
    assert_eq!(only(&findings).pane_id, "wM:p1");
    drop(state);
}

#[test]
fn the_cap_drops_acknowledged_findings_before_unacknowledged_ones() {
    let state = StateDir::new();
    let config = config(2);
    let mut store = Store::load(&config);

    let first = store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 1)], 100);
    store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 2)], 200);
    store.acknowledge(&first[0].id);

    store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 3)], 300);

    let findings = store.findings();
    assert_eq!(findings.len(), 2);
    assert!(
        !findings.iter().any(|f| f.id == first[0].id),
        "the acknowledged finding is the one the user has already looked at"
    );
    assert!(
        findings.iter().all(|f| !f.acknowledged),
        "no unacknowledged finding may be dropped while an acknowledged one remains"
    );
    // Dropping something the user had already dismissed is routine, not a note.
    assert!(store.report(Vec::new()).notes.is_empty());
    drop(state);
}

#[test]
fn the_cap_with_nothing_acknowledged_keeps_the_newest_and_says_so() {
    let state = StateDir::new();
    let config = config(2);
    let mut store = Store::load(&config);

    let oldest = store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 1)], 100);
    store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 2)], 200);
    store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 3)], 300);

    let report = store.report(Vec::new());
    assert_eq!(report.findings.len(), 2);
    assert!(!report.findings.iter().any(|f| f.id == oldest[0].id));
    assert!(
        report.notes.iter().any(|note| note.contains("cap")),
        "silently forgetting a warning is the one thing the store must not do: {:?}",
        report.notes
    );
    drop(state);
}

#[test]
fn a_notification_is_claimed_once_per_pattern_per_pane() {
    let state = StateDir::new();
    let config = config(500);
    let mut store = Store::load(&config);

    let here = store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 1)], 100);
    let also_here = store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 2)], 100);
    let elsewhere = store.observe(&pane("wM:p1"), &[a_match("aws_access_key_id", 3)], 100);
    let other_rule = store.observe(&pane("wE:p2"), &[a_match("github_pat", 4)], 100);

    assert!(store.claim_notification(&here[0]));
    assert!(
        !store.claim_notification(&here[0]),
        "the same finding must not toast twice"
    );
    assert!(
        !store.claim_notification(&also_here[0]),
        "a second credential from the same rule in the same pane is one toast, not two"
    );
    assert!(
        store.claim_notification(&elsewhere[0]),
        "a different pane is a different exposure"
    );
    assert!(
        store.claim_notification(&other_rule[0]),
        "a different rule is a different exposure"
    );
    drop(state);
}

#[test]
fn a_corrupt_state_file_is_a_note_and_an_empty_store_rather_than_a_panic() {
    let state = StateDir::new();
    fs::write(state.findings_file(), "{ this is not json").expect("write");

    let store = Store::load(&config(500));

    assert!(store.findings().is_empty());
    let notes = store.report(Vec::new()).notes;
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].contains("malformed") && notes[0].contains("not the same as a clean session"),
        "\"no findings\" and \"I could not read my own state\" must not look the same: {notes:?}"
    );
    // The unreadable file is kept rather than overwritten by the next save.
    assert!(state.path.join("findings.json.corrupt").exists());
    drop(state);
}

#[test]
fn a_missing_state_file_is_the_normal_case_and_raises_nothing() {
    let state = StateDir::new();

    let store = Store::load(&config(500));

    assert!(store.findings().is_empty());
    assert!(
        store.report(Vec::new()).notes.is_empty(),
        "a first run is not a problem to report"
    );
    drop(state);
}

#[test]
fn the_digest_key_is_drawn_once_and_reused_for_ever() {
    let state = StateDir::new();
    let config = config(500);

    let first = *Store::load(&config).key();
    let second = *Store::load(&config).key();

    assert_eq!(
        first, second,
        "a new key would re-fingerprint every finding and undo every acknowledgement"
    );
    assert_ne!(first, [0u8; 16], "the key must actually be drawn");

    let key_file = state.path.join("digest.key");
    let mode = fs::metadata(&key_file)
        .expect("key file")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o600,
        "the key file must not be readable by others"
    );
    drop(state);
}

#[test]
fn the_report_puts_unacknowledged_first_then_the_most_recent() {
    let state = StateDir::new();
    let config = config(500);
    let mut store = Store::load(&config);

    let acknowledged = store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 1)], 900);
    store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 2)], 100);
    store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 3)], 500);
    store.acknowledge(&acknowledged[0].id);

    let report = store.report(Vec::new());
    let order: Vec<u64> = report.findings.iter().map(|f| f.last_seen).collect();

    assert_eq!(
        order,
        vec![500, 100, 900],
        "unacknowledged first, then most recently seen first"
    );
    drop(state);
}

#[test]
fn an_unchanged_pane_is_not_rescanned_but_keeps_its_findings() {
    let state = StateDir::new();
    let config = config(500);
    let mut store = Store::load(&config);

    store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 7)], 100);

    assert!(store.pane_text_changed("wE:p2", "$ cargo build\n"));
    assert!(
        !store.pane_text_changed("wE:p2", "$ cargo build\n"),
        "byte-identical output does not need scanning again"
    );
    assert!(store.pane_text_changed("wE:p2", "$ cargo build\n$ ls\n"));
    assert_eq!(
        store.findings().len(),
        1,
        "a cache hit means \"do not scan\", never \"this pane is clean\""
    );
    drop(state);
}

/// A user acknowledging from a shell while the daemon is running must not have
/// their acknowledgement clobbered by the daemon's next save.
#[test]
fn an_acknowledgement_made_by_another_process_is_picked_up() {
    let state = StateDir::new();
    let config = config(500);

    let mut daemon = Store::load(&config);
    daemon.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 7)], 100);
    daemon.save().expect("save");

    let mut shell = Store::load(&config);
    assert_eq!(shell.acknowledge_all(), 1);
    shell.save().expect("save");

    assert!(daemon.reload_if_changed(&config));
    let findings = daemon.findings();
    assert!(only(&findings).acknowledged);

    daemon.save().expect("save");
    let reread = Store::load(&config);
    let findings = reread.findings();
    assert!(
        only(&findings).acknowledged,
        "the daemon's save must not undo what the user dismissed"
    );
    drop(state);
}

#[test]
fn reloading_an_unchanged_file_is_a_no_op() {
    let state = StateDir::new();
    let config = config(500);
    let mut store = Store::load(&config);

    store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 7)], 100);
    store.save().expect("save");

    assert!(!store.reload_if_changed(&config));
    assert_eq!(store.findings().len(), 1);
    drop(state);
}

#[test]
fn forget_all_empties_the_store_and_keeps_the_key() {
    let state = StateDir::new();
    let config = config(500);
    let mut store = Store::load(&config);
    let key = *store.key();

    store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 7)], 100);
    assert_eq!(store.forget_all(), 1);
    store.save().expect("save");

    let reloaded = Store::load(&config);
    assert!(reloaded.findings().is_empty());
    assert_eq!(
        *reloaded.key(),
        key,
        "the state file is emptied, not deleted"
    );
    drop(state);
}

/// The whole safety argument, checked against the bytes on disk.
#[test]
fn the_persisted_file_contains_no_secret() {
    let state = StateDir::new();
    let config = config(500);
    let mut store = Store::load(&config);

    // The digest is keyed with the store's own key, exactly as `scan` would
    // have produced it for this credential in this installation.
    let digest = redact::model::digest(store.key(), FAKE_CREDENTIAL);
    store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", digest)], 100);
    store.save().expect("save");

    let raw = state.read_findings_file();
    assert!(
        !raw.contains(FAKE_CREDENTIAL),
        "the credential must appear nowhere in the state file"
    );
    // And the file really does describe that finding, so the assertion above is
    // not passing because there was nothing in it.
    assert!(raw.contains("aws_access_key_id"));
    assert!(
        raw.contains("AKIA\u{2026}MPLE"),
        "the masked preview is stored"
    );
    assert!(raw.contains("wE:p2"));

    let mode = fs::metadata(state.findings_file())
        .expect("findings file")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "the findings file must be private");

    // Nothing else the store writes carries it either.
    for entry in fs::read_dir(&state.path).expect("state dir") {
        let path = entry.expect("entry").path();
        let bytes = fs::read(&path).expect("read");
        assert!(
            !String::from_utf8_lossy(&bytes).contains(FAKE_CREDENTIAL),
            "{} contains the credential",
            path.display()
        );
    }
    drop(state);
}

/// The store writes through a temp file in the same directory and renames, so a
/// process killed mid-save cannot leave a half-written file behind.
#[test]
fn saving_leaves_no_temp_file_behind() {
    let state = StateDir::new();
    let config = config(500);
    let mut store = Store::load(&config);

    store.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 7)], 100);
    store.save().expect("save");

    let leftovers: Vec<PathBuf> = fs::read_dir(&state.path)
        .expect("state dir")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.to_string_lossy().contains(".tmp."))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    drop(state);
}

/// The state directory the store writes to is the one the rest of the plugin
/// reads from. A split between them would give `--enable` and `--ack` two
/// different stores.
#[test]
fn the_store_writes_where_the_config_module_says_it_should() {
    let state = StateDir::new();
    assert_eq!(config::findings_file(), state.findings_file());
    assert_eq!(config::key_file(), state.path.join("digest.key"));
    drop(state);
}

/// The regression test for a bug the live run found and no unit test could:
/// an acknowledgement typed into a shell was silently undone by the watcher.
///
/// `reload_if_changed` runs at the *top* of a cycle, and a cycle on a large
/// session takes tens of seconds. An acknowledgement made inside that window was
/// written to the file and then overwritten when the cycle's own save landed.
/// The badge came straight back, and the user's dismissal looked like it had
/// simply not worked.
#[test]
fn an_acknowledgement_made_by_another_process_mid_cycle_is_not_clobbered() {
    let state = StateDir::new();
    let config = config(500);

    // The watcher: loads, sees a finding, and is now part-way through a long
    // cycle with the store held in memory.
    let mut watcher = Store::load(&config);
    watcher.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 7)], 100);
    watcher.save().expect("save");
    let id = only(&watcher.findings()).id.clone();

    // The user, in a shell, part-way through that cycle.
    let mut shell = Store::load(&config);
    assert_eq!(shell.acknowledge(&id), 1);
    shell.save().expect("save");

    // The watcher's cycle finishes and it saves its own, older, view.
    watcher.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 7)], 160);
    watcher.save().expect("save");

    let after = Store::load(&config);
    assert!(
        only(&after.findings()).acknowledged,
        "the watcher's save undid an acknowledgement made from a shell"
    );
    // And the watcher's own copy agrees, so the next badge push clears rather
    // than re-lighting it.
    assert!(only(&watcher.findings()).acknowledged);
    drop(state);
}

/// The other half: a save must not resurrect an acknowledgement that was never
/// made, nor invent findings from a file it half-read.
#[test]
fn adopting_external_state_only_ever_adds_acknowledgement() {
    let state = StateDir::new();
    let config = config(500);

    let mut watcher = Store::load(&config);
    watcher.observe(&pane("wE:p2"), &[a_match("aws_access_key_id", 7)], 100);
    watcher.save().expect("save");

    // Another process writes a file with a *different* finding in it,
    // unacknowledged. Nothing about that should change what we hold.
    let mut other = Store::load(&config);
    other.observe(&pane("wE:p3"), &[a_match("github_token", 9)], 120);
    other.save().expect("save");

    watcher.save().expect("save");
    let after = Store::load(&config);
    assert!(
        after.findings().iter().all(|f| !f.acknowledged),
        "an acknowledgement appeared from nowhere"
    );
    drop(state);
}

/// The review found this: every finding from one cycle shares the same `now`, so
/// the cap's tie-break decided by id — effectively at random. The finding
/// discovered *this* cycle could be the one dropped, while the note claimed the
/// oldest had been, and it was dropped after being queued for a toast, so a
/// notification fired naming an id `--ack` could not find.
#[test]
fn the_cap_drops_the_oldest_when_every_finding_shares_a_timestamp() {
    let state = StateDir::new();
    let config = config(2);
    let mut store = Store::load(&config);

    // Three findings, one cycle, one clock reading.
    let first = store.observe(&pane("wE:p1"), &[a_match("aws_access_key_id", 1)], 100);
    let second = store.observe(&pane("wE:p1"), &[a_match("github_token", 2)], 100);
    let third = store.observe(&pane("wE:p1"), &[a_match("slack_token", 3)], 100);
    assert_eq!((first.len(), second.len(), third.len()), (1, 1, 1));

    let kept: Vec<String> = store.findings().iter().map(|f| f.id.clone()).collect();
    assert_eq!(kept.len(), 2, "the cap did not bite");
    assert!(
        !kept.contains(&first[0].id),
        "the oldest finding should have gone first"
    );
    assert!(
        kept.contains(&third[0].id),
        "the newest finding was dropped instead of the oldest: {kept:?}"
    );

    // And the one that was dropped must not still be queued for a toast, or the
    // user gets a notification carrying an id that `--ack` cannot resolve.
    let pending: Vec<String> = store
        .take_new_findings()
        .iter()
        .map(|f| f.id.clone())
        .collect();
    assert!(
        !pending.contains(&first[0].id),
        "a dropped finding was still queued for a notification: {pending:?}"
    );
    for id in &pending {
        assert!(
            store.findings().iter().any(|f| &f.id == id),
            "queued a toast for a finding that is not in the store: {id}"
        );
    }
    drop(state);
}
