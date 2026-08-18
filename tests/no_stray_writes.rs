//! Proof of the plugin's filesystem claim: a full scan writes nothing outside
//! its own state directory.
//!
//! The sibling plugin this one is modelled on had to prove it never wrote to a
//! git repository. redact never touches git at all, so the equivalent claim is
//! broader and simpler: the **only** paths it may create or modify are the ones
//! under `HERDR_PLUGIN_STATE_DIR`. Not the working directory — which for an
//! installed plugin is its own root and for a hand run is somebody's repository
//! — not the config directory it reads, not `$HOME`.
//!
//! The fingerprint covers more than the assertions strictly need: every file
//! under a sandboxed `$HOME`, by content hash and length, plus the working
//! directory. Anything the plugin writes shows up.
//!
//! The stand-in server behaves the way the real one does — one request per
//! connection, then EOF — and answers from the fixtures captured off a live
//! herdr 0.8.0 server.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

/// Structurally valid, obviously fake.
const PANE_OUTPUT: &str = "\
$ cat .env
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
GITHUB_TOKEN=ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE01
$ cargo build --release
    Finished `release` profile [optimized] target(s) in 9.42s
";

// ---------------------------------------------------------------------------
// A stand-in herdr
// ---------------------------------------------------------------------------

struct TestServer {
    path: PathBuf,
    dir: PathBuf,
    stop: Arc<AtomicBool>,
    methods: Arc<Mutex<Vec<String>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    /// Answers `session.snapshot` and `pane.read` from the fixtures and records
    /// every request method. Mutations receive `ok` so an unexpected write is
    /// observable without derailing the caller before the assertion.
    fn start() -> Self {
        let dir = std::env::temp_dir().join(format!("redact-writes-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        // Kept short: a Unix socket path is capped at ~108 bytes.
        let path = dir.join("s.sock");

        let listener = UnixListener::bind(&path).expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let methods = Arc::new(Mutex::new(Vec::new()));

        let thread = {
            let stop = Arc::clone(&stop);
            let methods = Arc::clone(&methods);
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).expect("blocking");
                            let mut line = String::new();
                            if BufReader::new(&stream).read_line(&mut line).unwrap_or(0) == 0 {
                                continue;
                            }
                            let request: Value =
                                serde_json::from_str(line.trim_end()).expect("request is JSON");
                            let method = request["method"].as_str().unwrap_or_default().to_string();
                            methods.lock().expect("methods lock").push(method.clone());
                            let body = reply_to(&method);
                            let mut stream = &stream;
                            let _ = stream.write_all(body.as_bytes());
                            let _ = stream.write_all(b"\n");
                            let _ = stream.flush();
                            // One request per connection, then EOF — the real
                            // server's behaviour, and what forces the client to
                            // reconnect for every call.
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
            stop,
            thread: Some(thread),
            methods,
        }
    }

    fn methods(&self) -> Vec<String> {
        self.methods.lock().expect("methods lock").clone()
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

fn reply_to(method: &str) -> String {
    let result = match method {
        "session.snapshot" => {
            serde_json::from_str::<Value>(include_str!("fixtures/session_snapshot.json"))
                .expect("fixture")
        }
        "pane.read" => {
            let mut read: Value =
                serde_json::from_str(include_str!("fixtures/pane_read.json")).expect("fixture");
            read["read"]["text"] = json!(PANE_OUTPUT);
            read
        }
        _ => json!({"type": "ok"}),
    };
    json!({"id": "redact:1", "result": result}).to_string()
}

// ---------------------------------------------------------------------------
// Fingerprinting
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp {
    hash: u64,
    len: u64,
    is_dir: bool,
}

fn hash_of(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

fn walk(root: &Path, out: &mut BTreeMap<PathBuf, Stamp>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(t) if t.is_dir() => {
                out.insert(
                    path.clone(),
                    Stamp {
                        hash: 0,
                        len: 0,
                        is_dir: true,
                    },
                );
                walk(&path, out);
            }
            Ok(_) => {
                let bytes = std::fs::read(&path).unwrap_or_default();
                out.insert(
                    path,
                    Stamp {
                        hash: hash_of(&bytes),
                        len: bytes.len() as u64,
                        is_dir: false,
                    },
                );
            }
            Err(_) => {}
        }
    }
}

fn fingerprint(root: &Path) -> BTreeMap<PathBuf, Stamp> {
    let mut out = BTreeMap::new();
    walk(root, &mut out);
    out
}

/// Every path created, modified or removed between two fingerprints.
fn changed(before: &BTreeMap<PathBuf, Stamp>, after: &BTreeMap<PathBuf, Stamp>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = before
        .iter()
        .filter(|(path, was)| after.get(*path) != Some(was))
        .map(|(path, _)| path.clone())
        .chain(
            after
                .keys()
                .filter(|path| !before.contains_key(*path))
                .cloned(),
        )
        .collect();
    out.sort();
    out.dedup();
    out
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn a_full_scan_writes_nothing_outside_the_state_directory() {
    let _guard = TEST_LOCK.lock().expect("test lock");
    let home = std::env::temp_dir().join(format!("redact-writes-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let state = home.join("state");
    let config_dir = home.join("config");
    let workdir = home.join("work");
    for dir in [&state, &config_dir, &workdir] {
        std::fs::create_dir_all(dir).expect("sandbox");
    }
    // Files that look like a user's repository, in the directory a plugin runs
    // in. Nothing the plugin does may touch them.
    std::fs::write(workdir.join("Cargo.toml"), b"[package]\n").expect("work file");
    std::fs::write(workdir.join(".env"), b"AWS_SECRET_ACCESS_KEY=nope\n").expect("work file");
    // A config file the plugin reads. Reading must not rewrite it.
    std::fs::write(config_dir.join("config.json"), b"{\"lines\": 200}\n").expect("config");

    let server = TestServer::start();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_STATE_HOME", home.join("xdg-state"));
    std::env::set_var("XDG_CONFIG_HOME", home.join("xdg-config"));
    std::env::set_var("HERDR_PLUGIN_STATE_DIR", &state);
    std::env::set_var("HERDR_PLUGIN_CONFIG_DIR", &config_dir);
    std::env::set_var("HERDR_SOCKET_PATH", &server.path);
    std::env::set_var("HERDR_PLUGIN_ID", "test.redact");
    // The plugin refuses to read its own pane; make sure that is not what keeps
    // this run quiet.
    std::env::remove_var("HERDR_PANE_ID");

    let before = fingerprint(&home);
    assert!(
        before.len() >= 3,
        "the sandbox has nothing to protect: {before:?}"
    );

    let config = redact::config::load().expect("config");
    assert_eq!(config.lines, 200, "the config file was not read");
    let report = redact::daemon::scan_once(&config).expect("scan");

    // The scan really did run. A test that scanned nothing would satisfy the
    // assertion below trivially.
    assert!(
        !report.findings.is_empty(),
        "the scan found nothing, so this proves nothing. notes: {:?}",
        report.notes
    );
    assert!(
        report.panes_scanned > 0,
        "no pane was read: {:?}",
        report.notes
    );

    let after = fingerprint(&home);
    let written = changed(&before, &after);

    let strays: Vec<&PathBuf> = written
        .iter()
        .filter(|path| !path.starts_with(&state))
        .collect();
    assert!(
        strays.is_empty(),
        "the plugin wrote outside its own state directory: {strays:?}"
    );

    // And it did write inside it, so the fingerprint is measuring something.
    assert!(
        written.iter().any(|path| path.starts_with(&state)),
        "the store persisted nothing at all: {written:?}"
    );

    drop(server);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_sarif_run_writes_nothing_outside_the_state_directory() {
    let _guard = TEST_LOCK.lock().expect("test lock");
    let home = std::env::temp_dir().join(format!("redact-sarif-writes-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let state = home.join("state");
    let config_dir = home.join("config");
    let workdir = home.join("work");
    for dir in [&state, &config_dir, &workdir] {
        std::fs::create_dir_all(dir).expect("sandbox");
    }
    std::fs::write(workdir.join("Cargo.toml"), b"[package]\n").expect("work file");
    std::fs::write(workdir.join(".env"), b"AWS_SECRET_ACCESS_KEY=nope\n").expect("work file");
    std::fs::write(config_dir.join("config.json"), b"{\"lines\": 200}\n").expect("config");

    let server = TestServer::start();
    let before = fingerprint(&home);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_redact"))
        .current_dir(&workdir)
        .arg("--sarif")
        .env("HOME", &home)
        .env("XDG_STATE_HOME", home.join("xdg-state"))
        .env("XDG_CONFIG_HOME", home.join("xdg-config"))
        .env("HERDR_PLUGIN_STATE_DIR", &state)
        .env("HERDR_PLUGIN_CONFIG_DIR", &config_dir)
        .env("HERDR_SOCKET_PATH", &server.path)
        .env("HERDR_PLUGIN_ID", "test.redact")
        .env_remove("HERDR_PANE_ID")
        .output()
        .expect("run --sarif");
    assert!(
        output.status.success(),
        "--sarif failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let sarif: Value = serde_json::from_slice(&output.stdout).expect("--sarif did not print JSON");
    assert_eq!(sarif["version"], "2.1.0");
    assert!(
        !sarif["runs"][0]["results"]
            .as_array()
            .expect("SARIF results")
            .is_empty(),
        "the SARIF scan found nothing, so this proves nothing"
    );

    let after = fingerprint(&home);
    let written = changed(&before, &after);
    let strays: Vec<&PathBuf> = written
        .iter()
        .filter(|path| !path.starts_with(&state))
        .collect();
    assert!(
        strays.is_empty(),
        "--sarif wrote outside its own state directory: {strays:?}"
    );

    drop(server);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn calibrating_writes_nothing_at_all() {
    let _guard = TEST_LOCK.lock().expect("test lock");
    let home = std::env::temp_dir().join(format!("redact-calibrate-writes-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let state = home.join("state");
    let config_dir = home.join("config");
    let workdir = home.join("work");
    for dir in [&config_dir, &workdir] {
        std::fs::create_dir_all(dir).expect("sandbox");
    }
    std::fs::write(workdir.join("Cargo.toml"), b"[package]\n").expect("work file");
    std::fs::write(workdir.join(".env"), b"AWS_SECRET_ACCESS_KEY=nope\n").expect("work file");
    std::fs::write(config_dir.join("config.json"), b"{\"lines\": 200}\n").expect("config");

    let server = TestServer::start();
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_STATE_HOME", home.join("xdg-state"));
    std::env::set_var("XDG_CONFIG_HOME", home.join("xdg-config"));
    std::env::set_var("HERDR_PLUGIN_STATE_DIR", &state);
    std::env::set_var("HERDR_PLUGIN_CONFIG_DIR", &config_dir);
    std::env::set_var("HERDR_SOCKET_PATH", &server.path);
    std::env::set_var("HERDR_PLUGIN_ID", "test.redact");
    std::env::remove_var("HERDR_PANE_ID");

    let before = fingerprint(&home);
    assert!(
        !state.exists(),
        "the state directory existed before calibration"
    );

    let config = redact::config::load().expect("config");
    let calibration = redact::daemon::calibrate(&config).expect("calibration");
    assert!(
        !calibration.hits.is_empty(),
        "calibration found nothing, so this proves nothing. notes: {:?}",
        calibration.notes
    );
    assert!(
        calibration.panes_scanned > 0,
        "no pane was read: {:?}",
        calibration.notes
    );

    let after = fingerprint(&home);
    let written = changed(&before, &after);
    assert!(
        written.is_empty(),
        "calibration changed the sandboxed HOME, including plugin state: {written:?}"
    );
    assert!(
        !state.exists(),
        "calibration created the plugin state directory"
    );

    let methods = server.methods();
    assert!(methods.iter().any(|method| method == "session.snapshot"));
    assert!(methods.iter().any(|method| method == "pane.read"));
    for forbidden in [
        "pane.report_metadata",
        "workspace.report_metadata",
        "notification.show",
    ] {
        assert!(
            !methods.iter().any(|method| method == forbidden),
            "calibration sent {forbidden}: {methods:?}"
        );
    }

    drop(server);
    let _ = std::fs::remove_dir_all(&home);
}
