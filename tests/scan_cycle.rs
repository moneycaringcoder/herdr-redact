//! The scan cycle against a stand-in herdr, with an emphasis on what happens
//! when the session is bigger than one cycle's reading budget.
//!
//! This is the failure the live run found and the unit tests could not: reading
//! is one round trip per pane, a loaded server can take a second or more per
//! read, and a session with thirty panes then blows through any sane interval.
//! The plugin has to degrade into "reads as many as it can, says so, and starts
//! the next cycle where it stopped" rather than into "cycle never returns and
//! the badge is never pushed".
//!
//! The server here answers from the captured fixtures but with a synthetic pane
//! list, because the shape being tested is a large session and the captured one
//! has four panes.

use std::collections::{BTreeSet, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use redact::config::Config;
use redact::daemon;
use redact::findings::Store;
use redact::herdr::Herdr;
use serde_json::{json, Value};

/// Panes in the synthetic session. Larger than any budget below can read in one
/// go, which is the whole point.
const PANES: usize = 8;

/// How long the stand-in server takes to answer a `pane.read`. Slow enough that
/// a budget can be expressed in whole multiples of it without being flaky.
const READ_DELAY: Duration = Duration::from_millis(40);

/// `HERDR_SOCKET_PATH` and the state directory are process-global.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct TestServer {
    path: PathBuf,
    dir: PathBuf,
    reads: Arc<Mutex<Vec<(String, u32)>>>,
    methods: Arc<Mutex<Vec<(String, String)>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    fn start(delay: Duration) -> Self {
        Self::start_failing(delay, Vec::new())
    }

    /// `fail` names panes the server answers with an error envelope, the way it
    /// answers for a pane that closed under us.
    fn start_failing(delay: Duration, fail: Vec<String>) -> Self {
        Self::start_with(delay, fail, false, Vec::new())
    }

    /// [`TestServer::start_failing`], except each named pane fails only its
    /// first read and answers normally afterwards — a transport hiccup rather
    /// than a pane that is gone for good.
    fn start_failing_once(delay: Duration, fail: Vec<String>) -> Self {
        Self::start_with(delay, fail, true, Vec::new())
    }

    fn start_truncated(delay: Duration, truncated: Vec<String>) -> Self {
        Self::start_with(delay, Vec::new(), false, truncated)
    }

    /// `fail` names panes the server answers with an error envelope, `fail_once`
    /// limits that to their first read, and `truncated` names successful reads
    /// whose response carries that flag.
    fn start_with(
        delay: Duration,
        fail: Vec<String>,
        fail_once: bool,
        truncated: Vec<String>,
    ) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "redact-cycle-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("s.sock");

        let listener = UnixListener::bind(&path).expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let reads = Arc::new(Mutex::new(Vec::new()));
        let methods = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let thread = {
            let reads = Arc::clone(&reads);
            let methods = Arc::clone(&methods);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut failed_once: HashSet<String> = HashSet::new();
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).expect("blocking");
                            let mut line = String::new();
                            if BufReader::new(&stream).read_line(&mut line).unwrap_or(0) == 0 {
                                continue;
                            }
                            let request: Value =
                                serde_json::from_str(line.trim_end()).expect("JSON");
                            let method = request["method"].as_str().unwrap_or_default();
                            if method.starts_with("pane.") {
                                let pane_id = request["params"]["pane_id"]
                                    .as_str()
                                    .unwrap_or_default()
                                    .to_string();
                                methods
                                    .lock()
                                    .expect("methods")
                                    .push((pane_id, method.to_string()));
                            }
                            if method == "pane.read" {
                                let pane_id = request["params"]["pane_id"]
                                    .as_str()
                                    .unwrap_or_default()
                                    .to_string();
                                let lines = request["params"]["lines"].as_u64().unwrap_or_default();
                                reads.lock().expect("reads").push((pane_id, lines as u32));
                                std::thread::sleep(delay);
                            }
                            let refuse = method == "pane.read" && {
                                let id = request["params"]["pane_id"].as_str().unwrap_or_default();
                                fail.iter().any(|f| f.as_str() == id)
                                    && (!fail_once || failed_once.insert(id.to_string()))
                            };
                            let body = if refuse {
                                json!({
                                    "id": "redact:1",
                                    "error": {
                                        "code": "pane_not_found",
                                        "message": "pane closed"
                                    }
                                })
                                .to_string()
                            } else {
                                let is_truncated = truncated.iter().any(|id| {
                                    request["params"]["pane_id"].as_str() == Some(id.as_str())
                                });
                                reply_to(&request, is_truncated)
                            };
                            let mut stream = &stream;
                            let _ = stream.write_all(body.as_bytes());
                            let _ = stream.write_all(b"\n");
                            let _ = stream.flush();
                            // One request per connection, then EOF.
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
            })
        };

        Self {
            path,
            dir,
            reads,
            methods,
            stop,
            thread: Some(thread),
        }
    }

    fn reads(&self) -> Vec<(String, u32)> {
        self.reads.lock().expect("reads").clone()
    }

    fn take_reads(&self) -> Vec<(String, u32)> {
        std::mem::take(&mut *self.reads.lock().expect("reads"))
    }

    fn take_methods(&self) -> Vec<(String, String)> {
        std::mem::take(&mut *self.methods.lock().expect("methods"))
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A session of [`PANES`] agent panes across two workspaces, in the shape the
/// captured fixture uses.
fn snapshot() -> Value {
    let panes: Vec<Value> = (0..PANES)
        .map(|n| {
            json!({
                "pane_id": format!("w1:p{n}"),
                "terminal_id": format!("term_{n}"),
                "workspace_id": if n % 2 == 0 { "w1" } else { "w2" },
                "tab_id": "w1:t1",
                "focused": false,
                "agent": "claude",
                "agent_status": "working",
                "revision": 100 + n,
            })
        })
        .collect();
    json!({
        "version": "0.8.0",
        "protocol": 19,
        "workspaces": [
            {"workspace_id": "w1", "label": "one", "number": 1, "agent_status": "working"},
            {"workspace_id": "w2", "label": "two", "number": 2, "agent_status": "working"}
        ],
        "tabs": [],
        "layouts": [],
        "agents": [],
        "panes": panes,
    })
}

/// Each pane returns text unique to it, so a scan produces a distinct finding
/// per pane and coverage is observable in the findings as well as in the reads.
fn pane_body(pane_id: &str) -> String {
    let tag: String = pane_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    format!("$ cat .env\nGITHUB_TOKEN=ghp_EXAMPLEEXAMPLEEXAMPLE{tag:E<18}\n$ echo done\ndone\n")
}

fn reply_to(request: &Value, truncated: bool) -> String {
    let method = request["method"].as_str().unwrap_or_default();
    let result = match method {
        "session.snapshot" => json!({"type": "session_snapshot", "snapshot": snapshot()}),
        "pane.read" => {
            let pane_id = request["params"]["pane_id"].as_str().unwrap_or_default();
            let mut read: Value =
                serde_json::from_str(include_str!("fixtures/pane_read.json")).expect("fixture");
            read["read"]["pane_id"] = json!(pane_id);
            read["read"]["text"] = json!(pane_body(pane_id));
            read["read"]["truncated"] = json!(truncated);
            read
        }
        "pane.process_info" => {
            let pane_id = request["params"]["pane_id"].as_str().unwrap_or_default();
            json!({
                "type": "pane_process_info",
                "process_info": {
                    "pane_id": pane_id,
                    "foreground_processes": [{"pid": 4310, "name": "cargo"}]
                }
            })
        }
        _ => json!({"type": "ok"}),
    };
    json!({"id": "redact:1", "result": result}).to_string()
}

fn sandbox(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("redact-cycle-state-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("sandbox");
    dir
}

fn connect(server: &TestServer, state: &PathBuf) -> Herdr {
    std::env::set_var("HERDR_SOCKET_PATH", &server.path);
    std::env::set_var("HERDR_PLUGIN_STATE_DIR", state);
    std::env::set_var("HERDR_PLUGIN_ID", "test.redact");
    std::env::remove_var("HERDR_PANE_ID");
    Herdr::connect().expect("connect")
}

// ---------------------------------------------------------------------------

#[test]
fn a_cycle_with_room_to_spare_reads_every_pane() {
    let _guard = env_lock();
    let server = TestServer::start(Duration::from_millis(0));
    let state = sandbox("whole");
    let mut client = connect(&server, &state);
    let mut store = Store::load(&Config::default());

    let (report, panes) = daemon::scan_cycle_within(
        &mut client,
        &Config::default(),
        &mut store,
        Duration::from_secs(30),
    )
    .expect("cycle");

    assert_eq!(panes.len(), PANES);
    assert_eq!(report.panes_scanned, PANES);
    assert_eq!(report.panes_unread, 0);
    assert_eq!(report.findings.len(), PANES, "one finding per pane");

    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn process_info_is_requested_only_for_panes_with_new_findings() {
    let _guard = env_lock();
    let server = TestServer::start(Duration::from_millis(0));
    let state = sandbox("process-info");
    let config = Config::default();
    let mut client = connect(&server, &state);
    let mut store = Store::load(&config);

    let (first, _) =
        daemon::scan_cycle_within(&mut client, &config, &mut store, Duration::from_secs(30))
            .expect("first cycle");
    assert_eq!(first.findings.len(), PANES);
    let methods = server.take_methods();
    let reads: BTreeSet<&str> = methods
        .iter()
        .filter(|(_, method)| method == "pane.read")
        .map(|(pane_id, _)| pane_id.as_str())
        .collect();
    let process_info: BTreeSet<&str> = methods
        .iter()
        .filter(|(_, method)| method == "pane.process_info")
        .map(|(pane_id, _)| pane_id.as_str())
        .collect();
    assert_eq!(
        process_info, reads,
        "only panes that produced new findings should get process context"
    );

    let (second, _) =
        daemon::scan_cycle_within(&mut client, &config, &mut store, Duration::from_secs(30))
            .expect("unchanged cycle");
    assert_eq!(second.findings.len(), PANES);
    let methods = server.take_methods();
    assert!(
        methods
            .iter()
            .all(|(_, method)| method != "pane.process_info"),
        "a cycle with no new findings requested process context: {methods:?}"
    );

    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn each_pane_uses_backfill_then_the_ordinary_window() {
    let _guard = env_lock();
    let server = TestServer::start(Duration::from_millis(0));
    let state = sandbox("backfill-then-window");
    let config = Config::default();
    let mut client = connect(&server, &state);
    let mut store = Store::load(&config);

    daemon::scan_cycle_within(&mut client, &config, &mut store, Duration::from_secs(30))
        .expect("first cycle");
    assert!(
        server
            .take_reads()
            .iter()
            .all(|(_, lines)| *lines == config.backfill_lines),
        "the first read of every pane must use backfill_lines"
    );

    daemon::scan_cycle_within(&mut client, &config, &mut store, Duration::from_secs(30))
        .expect("second cycle");
    assert!(
        server
            .take_reads()
            .iter()
            .all(|(_, lines)| *lines == config.lines),
        "later reads must use lines"
    );

    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn zero_backfill_uses_the_ordinary_window_for_every_read() {
    let _guard = env_lock();
    let server = TestServer::start(Duration::from_millis(0));
    let state = sandbox("backfill-disabled");
    let config = Config {
        backfill_lines: 0,
        ..Config::default()
    };
    let mut client = connect(&server, &state);
    let mut store = Store::load(&config);

    for _ in 0..2 {
        daemon::scan_cycle_within(&mut client, &config, &mut store, Duration::from_secs(30))
            .expect("cycle");
    }
    let reads = server.take_reads();
    assert_eq!(reads.len(), PANES * 2);
    for (pane_id, lines) in &reads {
        assert_eq!(
            *lines, config.lines,
            "backfill_lines: 0 must preserve the old pane.read value for {pane_id}: {reads:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn backfill_and_ordinary_truncation_have_distinct_notes() {
    let _guard = env_lock();
    let pane_id = "w1:p0";
    let server = TestServer::start_truncated(Duration::from_millis(0), vec![pane_id.to_string()]);
    let state = sandbox("backfill-truncated");
    let config = Config::default();
    let mut client = connect(&server, &state);
    let mut store = Store::load(&config);

    let (backfill, _) =
        daemon::scan_cycle_within(&mut client, &config, &mut store, Duration::from_secs(30))
            .expect("backfill cycle");
    assert!(
        backfill
            .notes
            .iter()
            .any(|note| note.contains(pane_id) && note.contains("startup backfill")),
        "no backfill-specific truncation note: {:?}",
        backfill.notes
    );
    assert_eq!(
        backfill.panes_truncated, 0,
        "a backfill truncation must not trigger the ordinary-window summary"
    );

    let (ordinary, _) =
        daemon::scan_cycle_within(&mut client, &config, &mut store, Duration::from_secs(30))
            .expect("ordinary cycle");
    assert!(
        ordinary
            .notes
            .iter()
            .any(|note| note.contains(pane_id) && note.contains("had more output")),
        "no ordinary truncation note: {:?}",
        ordinary.notes
    );
    assert_eq!(ordinary.panes_truncated, 1);
    let rendered = redact::render::report_text(&ordinary, 80);
    assert!(
        rendered.contains("raise `lines`"),
        "ordinary truncation summary disappeared:\n{rendered}"
    );

    let _ = std::fs::remove_dir_all(&state);
}

/// The heart of it: a session too large for one budget is still fully covered,
/// because each cycle resumes where the last one stopped.
#[test]
fn a_session_too_large_for_one_budget_is_covered_across_cycles() {
    let _guard = env_lock();
    let server = TestServer::start(READ_DELAY);
    let state = sandbox("rotation");
    let config = Config::default();
    let mut client = connect(&server, &state);
    let mut store = Store::load(&config);

    // Room for roughly three reads per cycle, so no single cycle can see the
    // whole session and the rotation has to do the work.
    let budget = READ_DELAY * 3;

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut cycles = 0usize;
    // Generous: three reads a cycle over eight panes needs three, and a loaded
    // CI runner may manage fewer.
    while seen.len() < PANES && cycles < 12 {
        let (report, _) =
            daemon::scan_cycle_within(&mut client, &config, &mut store, budget).expect("cycle");
        let read = server.take_reads();
        assert!(
            !read.is_empty(),
            "a cycle that read nothing at all cannot make progress"
        );
        assert!(
            report.panes_scanned <= PANES,
            "more reads than there are panes"
        );
        for (pane_id, lines) in read {
            if seen.insert(pane_id) {
                assert_eq!(
                    lines,
                    config.backfill_lines,
                    "a pane first reached on cycle {} did not get its deep read",
                    cycles + 1
                );
            }
        }
        cycles += 1;
    }

    assert_eq!(
        seen.len(),
        PANES,
        "after {cycles} cycles these panes had never been read: {:?}",
        (0..PANES)
            .map(|n| format!("w1:p{n}"))
            .filter(|id| !seen.contains(id))
            .collect::<Vec<_>>()
    );
    assert!(
        cycles > 1,
        "the budget did not actually bite, so nothing was proved"
    );

    let _ = std::fs::remove_dir_all(&state);
}

#[test]
fn panes_left_unread_are_counted_and_named_in_a_note() {
    let _guard = env_lock();
    let server = TestServer::start(READ_DELAY);
    let state = sandbox("unread");
    let config = Config::default();
    let mut client = connect(&server, &state);
    let mut store = Store::load(&config);

    let (report, _) =
        daemon::scan_cycle_within(&mut client, &config, &mut store, READ_DELAY * 2).expect("cycle");

    assert!(
        report.panes_unread > 0,
        "the budget did not bite: {report:?}"
    );
    assert_eq!(
        report.panes_scanned + report.panes_unread,
        PANES,
        "every pane is either read or accounted for as unread"
    );
    // Silence here is the failure mode: an unread pane is one nobody has looked
    // at, and a report that does not say so is a report claiming a clean session
    // it never established.
    assert!(
        report.notes.iter().any(|note| note.contains("budget")),
        "no note explains the unread panes: {:?}",
        report.notes
    );
    let rendered = redact::render::report_text(&report, 80);
    assert!(
        rendered.contains("could not be read"),
        "the unread panes are invisible in the rendered report:\n{rendered}"
    );

    let _ = std::fs::remove_dir_all(&state);
}

/// A pane the server refuses is data, not a reason to abandon the cycle. Before
/// this was true, one unreadable pane cost every other pane its badge, because
/// the failure propagated out before anything was pushed.
#[test]
fn a_failing_pane_read_does_not_abandon_the_cycle() {
    let _guard = env_lock();
    let broken = vec!["w1:p2".to_string(), "w1:p5".to_string()];
    let server = TestServer::start_failing(Duration::from_millis(0), broken.clone());
    let state = sandbox("failing");
    let config = Config::default();
    let mut client = connect(&server, &state);
    let mut store = Store::load(&config);

    let (report, _) =
        daemon::scan_cycle_within(&mut client, &config, &mut store, Duration::from_secs(30))
            .expect("a failing pane read must not fail the cycle");

    assert_eq!(server.reads().len(), PANES, "every pane was attempted");
    assert_eq!(report.panes_scanned, PANES - broken.len());
    assert_eq!(report.panes_unread, broken.len());
    assert_eq!(
        report.findings.len(),
        PANES - broken.len(),
        "the readable panes still produced their findings"
    );
    for pane_id in &broken {
        assert!(
            report.notes.iter().any(|note| note.contains(pane_id)),
            "no note names the pane that could not be read: {:?}",
            report.notes
        );
    }

    let _ = std::fs::remove_dir_all(&state);
}

/// A read that failed never looked at anything, so it cannot have spent the
/// pane's one deep read. Before this was true a single transport hiccup left
/// that pane on the ordinary window for the life of the process: its scrollback
/// was never scanned, and the report said nothing at all about the hole.
#[test]
fn a_pane_whose_first_read_fails_is_still_owed_its_deep_read() {
    let _guard = env_lock();
    let broken = "w1:p3";
    let server = TestServer::start_failing_once(Duration::from_millis(0), vec![broken.to_string()]);
    let state = sandbox("backfill-after-failure");
    let config = Config::default();
    let mut client = connect(&server, &state);
    let mut store = Store::load(&config);

    daemon::scan_cycle_within(&mut client, &config, &mut store, Duration::from_secs(30))
        .expect("first cycle");
    let first: Vec<u32> = server
        .take_reads()
        .iter()
        .filter(|(pane_id, _)| pane_id == broken)
        .map(|(_, lines)| *lines)
        .collect();
    assert_eq!(
        first,
        vec![config.backfill_lines],
        "the failing pane was not offered its deep read on the first cycle"
    );

    daemon::scan_cycle_within(&mut client, &config, &mut store, Duration::from_secs(30))
        .expect("second cycle");
    let reads = server.take_reads();
    let retry: Vec<u32> = reads
        .iter()
        .filter(|(pane_id, _)| pane_id == broken)
        .map(|(_, lines)| *lines)
        .collect();
    assert_eq!(
        retry,
        vec![config.backfill_lines],
        "a failed read must leave the pane still owed its deep read: {reads:?}"
    );
    for (pane_id, lines) in &reads {
        if pane_id != broken {
            assert_eq!(
                *lines, config.lines,
                "a pane already read successfully must not backfill twice: {reads:?}"
            );
        }
    }

    let _ = std::fs::remove_dir_all(&state);
}
