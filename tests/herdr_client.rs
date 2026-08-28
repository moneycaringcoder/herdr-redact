//! Wire-level tests for the socket client.
//!
//! Every test stands up a real Unix socket server in a temp directory and
//! asserts the bytes the client puts on the wire, because the parts of this
//! protocol that bite (mandatory `{}` params, one request per connection, the
//! snake_case source spelling, the payload nested one level below `result`, the
//! merge-patch clear with no TTL) are invisible from the Rust API alone.
//!
//! The replies are built from `tests/fixtures/`, which were captured from a live
//! herdr 0.8.0 server rather than written to match this client's expectations. A
//! fake that encodes an assumption cannot catch the assumption being wrong.
//!
//! No running herdr is required, and nothing here touches the user's state.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use redact::herdr::{error_code, Herdr};
use redact::model::PaneRef;
use serde_json::{json, Value};

const SOURCE: &str = "test.redact";

/// Captured from a live 10-pane session, trimmed to four representative panes.
const SNAPSHOT_FIXTURE: &str = include_str!("fixtures/session_snapshot.json");
/// Captured from a live pane, body replaced with synthetic build output.
const READ_FIXTURE: &str = include_str!("fixtures/pane_read.json");
/// Captured from a live pane running `curl`; the full response envelope is kept.
const PROCESS_FIXTURE: &str = include_str!("fixtures/pane_process_info.json");
const PROCESS_CREDENTIAL: &str = "ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXA4c75gp";

/// `HERDR_SOCKET_PATH` and `HERDR_PLUGIN_ID` are process-global, so the tests
/// that set them have to run one at a time even though cargo runs them on
/// separate threads.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// What the server does with one connection.
#[derive(Clone)]
enum Reply {
    /// Answer, then close — the real server's behaviour.
    Line(String),
    /// Read the request and close without answering, which is what a client
    /// sees when it lands on a socket the server is tearing down.
    Eof,
}

struct TestServer {
    path: PathBuf,
    dir: PathBuf,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    fn start(replies: Vec<Reply>) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "redact-wire-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        // Kept short: a Unix socket path is capped at ~108 bytes.
        let path = dir.join("s.sock");

        let listener = UnixListener::bind(&path).expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let thread = {
            let requests = Arc::clone(&requests);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut replies = replies.into_iter();
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).expect("blocking");
                            let mut line = String::new();
                            let mut reader = BufReader::new(&stream);
                            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                                continue;
                            }
                            requests.lock().expect("requests").push(line.clone());
                            match replies.next() {
                                Some(Reply::Line(reply)) => {
                                    let reply = match serde_json::from_str::<Value>(&reply) {
                                        Ok(mut response) => {
                                            let request: Value = serde_json::from_str(&line)
                                                .expect("fake request is JSON");
                                            response["id"] = request["id"].clone();
                                            response.to_string()
                                        }
                                        Err(_) => reply,
                                    };
                                    let mut stream = &stream;
                                    let _ = stream.write_all(reply.as_bytes());
                                    let _ = stream.write_all(b"\n");
                                    let _ = stream.flush();
                                }
                                // Exhausted or an explicit EOF: just close, the
                                // way herdr closes after answering.
                                Some(Reply::Eof) | None => {}
                            }
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
            requests,
            stop,
            thread: Some(thread),
        }
    }

    fn client(&self) -> Herdr {
        std::env::set_var("HERDR_SOCKET_PATH", &self.path);
        std::env::set_var("HERDR_PLUGIN_ID", SOURCE);
        Herdr::connect().expect("connect")
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("requests").clone()
    }

    /// The single request, parsed, with its raw framing already asserted.
    fn only_request(&self) -> Value {
        let requests = self.requests();
        assert_eq!(requests.len(), 1, "expected one request, got {requests:?}");
        parse_framed(&requests[0])
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

/// One line, newline-terminated, with no trailing framing of its own.
fn parse_framed(raw: &str) -> Value {
    assert!(raw.ends_with('\n'), "request must be newline-terminated");
    assert_eq!(
        raw.matches('\n').count(),
        1,
        "one request per line, got {raw:?}"
    );
    serde_json::from_str(raw.trim_end()).expect("request is JSON")
}

/// Every mutation answers with this, verified live against herdr 0.8.0 for both
/// a set and a clear of `pane.report_metadata`.
fn ok_reply() -> Reply {
    Reply::Line(json!({"id": "redact:1", "result": {"type": "ok"}}).to_string())
}

/// `notification.show` does **not** answer `ok`: it reports whether the toast
/// was actually shown, and why not when it was not.
fn notification_reply() -> Reply {
    Reply::Line(
        json!({
            "id": "redact:1",
            "result": {"type": "notification_show", "shown": true, "reason": "shown"}
        })
        .to_string(),
    )
}

/// The captured `session.snapshot` result, verbatim. It is already the whole
/// `result` object, `type` discriminator and nested `snapshot` included.
fn snapshot_result() -> Value {
    serde_json::from_str(SNAPSHOT_FIXTURE).expect("snapshot fixture is JSON")
}

fn read_result() -> Value {
    serde_json::from_str(READ_FIXTURE).expect("pane read fixture is JSON")
}

fn reply_with(result: Value) -> Reply {
    Reply::Line(json!({"id": "redact:1", "result": result}).to_string())
}

fn pane<'a>(panes: &'a [PaneRef], pane_id: &str) -> &'a PaneRef {
    panes
        .iter()
        .find(|pane| pane.pane_id == pane_id)
        .unwrap_or_else(|| panic!("no pane {pane_id} in {panes:?}"))
}

#[test]
fn request_framing_is_a_single_json_line_with_object_params() {
    let _guard = env_lock();
    let server = TestServer::start(vec![reply_with(snapshot_result())]);
    let mut client = server.client();

    client.panes().expect("snapshot");

    let request = server.only_request();
    assert_eq!(request["method"], "session.snapshot");
    assert!(request["id"].is_string(), "id must be a string");
    // Mandatory and an object even when empty — never null, never absent.
    assert_eq!(request["params"], json!({}));
    assert!(request["params"].is_object());
    assert!(
        request.get("jsonrpc").is_none(),
        "this protocol has no jsonrpc field"
    );
}

#[test]
fn one_request_per_connection_is_survived_by_reconnecting() {
    let _guard = env_lock();
    // The first connection is read and closed without an answer, exactly as a
    // server that has just handed off behaves. The retry must land the call.
    let server = TestServer::start(vec![Reply::Eof, reply_with(snapshot_result())]);
    let mut client = server.client();

    let panes = client.panes().expect("retry should succeed");

    assert_eq!(panes.len(), 4);
    assert_eq!(
        server.requests().len(),
        2,
        "the dropped connection must be retried on a fresh one"
    );
}

#[test]
fn pane_read_sends_the_snake_case_source_and_the_line_budget() {
    let _guard = env_lock();
    let server = TestServer::start(vec![reply_with(read_result())]);
    let mut client = server.client();

    client.read_pane("wE:p2", 400).expect("read");

    let params = server.only_request()["params"].clone();
    assert_eq!(params["pane_id"], "wE:p2");
    // The CLI spells this `recent-unwrapped`; the socket rejects the hyphen
    // outright with `unknown variant`.
    assert_eq!(
        params["source"], "recent_unwrapped",
        "the wire spelling is snake_case, got {params}"
    );
    assert_eq!(params["lines"], 400);
}

#[test]
fn pane_read_reads_its_payload_from_the_nested_read_object() {
    let _guard = env_lock();
    let server = TestServer::start(vec![reply_with(read_result())]);
    let mut client = server.client();

    let text = client.read_pane("wE:p2", 400).expect("read");

    assert_eq!(text.pane_id, "wE:p2");
    assert!(
        text.text.contains("cargo build --release"),
        "a live pane must not read as silent: {text:?}"
    );
    assert!(!text.truncated);
}

/// The other half of the nesting trap: a reply that stops carrying `read` must
/// be loud. Empty text is indistinguishable from an idle pane, so degrading
/// quietly would report a clean session for ever.
#[test]
fn a_reply_without_the_read_object_is_an_error_not_an_empty_pane() {
    let _guard = env_lock();
    // The fields are present, but at the level a client reading `result.text`
    // would find them.
    let flattened = {
        let result = read_result();
        let mut flat = result["read"].clone();
        flat["type"] = json!("pane_read");
        flat
    };
    let server = TestServer::start(vec![reply_with(flattened)]);
    let mut client = server.client();

    let err = client
        .read_pane("wE:p2", 400)
        .expect_err("a missing `read` object must not read as an empty pane");

    assert!(
        err.to_string().contains("read"),
        "the message must name what is missing: {err}"
    );
}

#[test]
fn pane_process_info_is_reduced_to_the_first_process_name_and_pid() {
    let _guard = env_lock();
    let server = TestServer::start(vec![Reply::Line(PROCESS_FIXTURE.trim().to_string())]);
    let mut client = server.client();

    let process = client.process_info("w16:p5").expect("process info");

    assert_eq!(process.pane_id, "w16:p5");
    assert_eq!(process.foreground_process_name.as_deref(), Some("curl"));
    assert_eq!(process.foreground_process_pid, Some(4310));
    assert!(
        !format!("{process:?}").contains(PROCESS_CREDENTIAL),
        "the reduced value must not retain command-line credentials: {process:?}"
    );
    let request = server.only_request();
    assert_eq!(request["method"], "pane.process_info");
    assert_eq!(request["params"], json!({"pane_id": "w16:p5"}));
}

#[test]
fn a_reply_without_the_process_info_object_is_a_hard_error() {
    let _guard = env_lock();
    let server = TestServer::start(vec![reply_with(json!({
        "type": "pane_process_info"
    }))]);
    let mut client = server.client();

    let err = client
        .process_info("w16:p5")
        .expect_err("a missing `process_info` object must not read as empty context");

    assert!(
        err.to_string().contains("process_info"),
        "the message must name what is missing: {err}"
    );
}

#[test]
fn truncated_is_carried_through_rather_than_swallowed() {
    let _guard = env_lock();
    let mut result = read_result();
    result["read"]["truncated"] = json!(true);
    let server = TestServer::start(vec![reply_with(result)]);
    let mut client = server.client();

    let text = client.read_pane("wE:p2", 10).expect("read");

    assert!(
        text.truncated,
        "the user is not seeing everything and the UI has to be able to say so"
    );
}

#[test]
fn panes_are_read_from_the_nested_snapshot_object() {
    let _guard = env_lock();
    let server = TestServer::start(vec![reply_with(snapshot_result())]);
    let mut client = server.client();

    let panes = client.panes().expect("snapshot");

    assert_eq!(panes.len(), 4, "a live session must not read as idle");
    let claude = pane(&panes, "wM:p1");
    assert_eq!(claude.workspace_id, "wM");
    assert_eq!(claude.tab_id, "wM:t1");
    assert_eq!(claude.workspace_label, "herdr takeover");
    assert_eq!(claude.cwd, Some(PathBuf::from("/home/dev/repos")));
    assert_eq!(claude.title.as_deref(), Some("a task title"));
}

/// The same shape trap as `pane.read`. An empty pane list looks exactly like an
/// idle session, so silently returning one would hide the breakage.
#[test]
fn a_reply_without_the_snapshot_object_is_an_error_not_an_idle_session() {
    let _guard = env_lock();
    let flattened = {
        let result = snapshot_result();
        let mut flat = result["snapshot"].clone();
        flat["type"] = json!("session_snapshot");
        flat
    };
    let server = TestServer::start(vec![reply_with(flattened)]);
    let mut client = server.client();

    let err = client
        .panes()
        .expect_err("a missing `snapshot` object must not read as an idle session");

    assert!(
        err.to_string().contains("snapshot"),
        "the message must name what is missing: {err}"
    );
}

/// A plain shell pane has no `agent` key at all. That absence is the default
/// scan filter, so the pane has to survive the parse in order to be filtered —
/// dropping it would also drop it from the live-pane list the store prunes to.
#[test]
fn a_pane_with_no_agent_key_parses_as_none_rather_than_being_dropped() {
    let _guard = env_lock();
    let server = TestServer::start(vec![reply_with(snapshot_result())]);
    let mut client = server.client();

    let panes = client.panes().expect("snapshot");

    let shell = pane(&panes, "w0:p1");
    assert_eq!(shell.agent, None);
    // With no agent to name it, the pane's own id is its label.
    assert_eq!(shell.label(), "w0:p1");
    assert_eq!(shell.workspace_label, "herdr-collide");
}

#[test]
fn the_agents_array_name_wins_over_the_pane_agent() {
    let _guard = env_lock();
    let server = TestServer::start(vec![reply_with(snapshot_result())]);
    let mut client = server.client();

    let panes = client.panes().expect("snapshot");

    // `panes[].agent` says "opencode"; the user called it "media-throughput".
    assert_eq!(
        pane(&panes, "wE:p1").agent.as_deref(),
        Some("media-throughput")
    );
    assert_eq!(pane(&panes, "wE:p2").agent.as_deref(), Some("rev-media"));
    // The agents row for this pane carries no `name`, so the program name is
    // the best label there is.
    assert_eq!(pane(&panes, "wM:p1").agent.as_deref(), Some("claude"));
}

#[test]
fn set_pane_badge_sends_pane_id_source_tokens_and_ttl() {
    let _guard = env_lock();
    let server = TestServer::start(vec![ok_reply()]);
    let mut client = server.client();

    client
        .set_pane_badge("wE:p2", "redact_secret", "! 1", 15_000)
        .expect("set");

    let request = server.only_request();
    assert_eq!(request["method"], "pane.report_metadata");
    let params = request["params"].clone();
    assert_eq!(
        params,
        json!({
            "pane_id": "wE:p2",
            "source": SOURCE,
            "tokens": {"redact_secret": "! 1"},
            "ttl_ms": 15_000
        })
    );
    // No `$` prefix on the wire: that syntax belongs to herdr's config.toml.
    assert!(!params["tokens"]
        .as_object()
        .unwrap()
        .keys()
        .any(|key| key.starts_with('$')));
}

#[test]
fn clear_pane_badge_sends_a_null_token_and_no_ttl() {
    let _guard = env_lock();
    let server = TestServer::start(vec![ok_reply()]);
    let mut client = server.client();

    client
        .clear_pane_badge("wE:p2", "redact_weak")
        .expect("clear");

    let params = server.only_request()["params"].clone();
    // Tokens are a merge patch: null deletes the name. 0.8.0 tolerates a TTL
    // alongside a delete, but the documented contract does not, and a stricter
    // server must not break us.
    assert!(params["tokens"]["redact_weak"].is_null());
    assert!(
        params.get("ttl_ms").is_none(),
        "a clear must omit ttl_ms entirely, got {params}"
    );
    assert_eq!(params["pane_id"], "wE:p2");
    assert_eq!(params["source"], SOURCE);
}

#[test]
fn set_workspace_badge_sends_workspace_id_source_tokens_and_ttl() {
    let _guard = env_lock();
    let server = TestServer::start(vec![ok_reply()]);
    let mut client = server.client();

    client
        .set_workspace_badge("wE", "redact_weak", "? 2", 15_000)
        .expect("set");

    let request = server.only_request();
    assert_eq!(request["method"], "workspace.report_metadata");
    assert_eq!(
        request["params"],
        json!({
            "workspace_id": "wE",
            "source": SOURCE,
            "tokens": {"redact_weak": "? 2"},
            "ttl_ms": 15_000
        })
    );
}

#[test]
fn clear_workspace_badge_sends_a_null_token_and_no_ttl() {
    let _guard = env_lock();
    let server = TestServer::start(vec![ok_reply()]);
    let mut client = server.client();

    client
        .clear_workspace_badge("wE", "redact_secret")
        .expect("clear");

    let params = server.only_request()["params"].clone();
    assert!(params["tokens"]["redact_secret"].is_null());
    assert!(
        params.get("ttl_ms").is_none(),
        "a clear must omit ttl_ms entirely, got {params}"
    );
    assert_eq!(params["workspace_id"], "wE");
}

#[test]
fn ttl_is_clamped_into_the_protocol_range() {
    let _guard = env_lock();
    let server = TestServer::start(vec![ok_reply(), ok_reply()]);
    let mut client = server.client();

    client
        .set_pane_badge("wE:p2", "redact_weak", "?", 0)
        .expect("low");
    client
        .set_workspace_badge("wE", "redact_weak", "?", u64::MAX)
        .expect("high");

    let requests = server.requests();
    // herdr rejects anything outside 1..=86_400_000 with `invalid_metadata_ttl`.
    assert_eq!(parse_framed(&requests[0])["params"]["ttl_ms"], 1);
    assert_eq!(
        parse_framed(&requests[1])["params"]["ttl_ms"],
        86_400_000u64
    );
}

#[test]
fn error_envelopes_surface_as_a_typed_error_and_are_not_retried() {
    let _guard = env_lock();
    let server = TestServer::start(vec![Reply::Line(
        json!({
            "id": "redact:1",
            "error": {"code": "pane_not_found", "message": "pane nosuch:p9 not found"}
        })
        .to_string(),
    )]);
    let mut client = server.client();

    let err = client
        .read_pane("nosuch:p9", 400)
        .expect_err("an error envelope is a failure");

    // The daemon turns exactly this code into a note and carries on, so it has
    // to be able to see it.
    assert_eq!(error_code(&*err), Some("pane_not_found"));
    assert!(err.to_string().contains("nosuch:p9"));
    // A rejected request is not a transport failure, so it must not be retried.
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn transport_failure_after_the_retry_is_not_a_herdr_error_code() {
    let _guard = env_lock();
    let server = TestServer::start(vec![Reply::Eof, Reply::Eof]);
    let mut client = server.client();

    let err = client.panes().expect_err("both attempts fail");

    assert_eq!(
        error_code(&*err),
        None,
        "callers must be able to tell blindness from rejection"
    );
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn notify_sends_title_and_body() {
    let _guard = env_lock();
    // Not an `ok` envelope: this method reports whether the toast was shown.
    let server = TestServer::start(vec![notification_reply()]);
    let mut client = server.client();

    client
        .notify("redact: AWS access key ID in rev-media", "aws… (20 chars)")
        .expect("notify");

    let request = server.only_request();
    assert_eq!(request["method"], "notification.show");
    assert_eq!(
        request["params"]["title"],
        "redact: AWS access key ID in rev-media"
    );
    assert_eq!(request["params"]["body"], "aws… (20 chars)");
}

#[test]
fn connect_reports_the_socket_path_when_there_is_no_server() {
    let _guard = env_lock();
    std::env::set_var("HERDR_SOCKET_PATH", "/nonexistent/redact-test.sock");

    let err = Herdr::connect().expect_err("no server listening");

    assert!(
        err.to_string().contains("/nonexistent/redact-test.sock"),
        "the message must name the path: {err}"
    );
}
