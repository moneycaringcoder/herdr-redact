//! Proof of the claim the whole plugin rests on: **a secret value never leaves
//! the scanner.**
//!
//! Every other test here checks that redact finds the right things. This one
//! checks that finding them costs the user nothing — that the value which
//! triggered a finding cannot be recovered from anything the plugin produces:
//! not a `Match`, not a `Finding`, not the persisted state file, not the badge,
//! not the toast body, not the rendered table, not the JSON, and not a `Debug`
//! rendering of any of them.
//!
//! The vectors below are deliberately **not** imported from
//! `tests/scan_corpus.rs`. That file belongs to the scanner and can legitimately
//! change; this one is an independent statement of the safety property, and a
//! test that asks the code under test what to test proves nothing. Two of these
//! also appear in the corpus, which is fine — the point is that this list is
//! maintained separately.
//!
//! Every value here is structurally valid and obviously fake.

use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard, OnceLock};

use redact::config::Config;
use redact::findings::Store;
use redact::model::{now, Alert, Finding, PaneRef, Report};
use redact::scan::{self, Rules};

/// Structurally valid, obviously fake. Nothing here is or ever was a real
/// credential.
const VECTORS: &[&str] = &[
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXA4c75gp",
    "sk-ant-api03-EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPL-EXAMPLEAA",
    "xoxb-000000000000-000000000000-EXAMPLEEXAMPLEEXAMPLEEX",
    "AIzaSyEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXA",
    "glpat-EXAMPLEEXAMPLEEXAMPLE",
    "hunter2correcthorsebattery",
];

const TERMINAL_TITLE_VECTOR: &str = "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";
const SHELL_PROMPT_VECTOR: &str = "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";

/// The pane text the vectors are found in, and the assignments that carry the
/// ones with no prefix of their own.
fn pane_text() -> String {
    format!(
        "$ printf '%s' {}\n\
         $ cat .env\n\
         AWS_ACCESS_KEY_ID={}\n\
         GITHUB_TOKEN={}\n\
         ANTHROPIC_API_KEY={}\n\
         SLACK_BOT_TOKEN={}\n\
         GOOGLE_API_KEY={}\n\
         GITLAB_TOKEN={}\n\
         DATABASE_PASSWORD={}\n\
         $ cargo build --release\n\
             Finished `release` profile [optimized] target(s) in 9.42s\n",
        SHELL_PROMPT_VECTOR,
        VECTORS[0],
        VECTORS[1],
        VECTORS[2],
        VECTORS[3],
        VECTORS[4],
        VECTORS[5],
        VECTORS[6],
    )
}

/// `HERDR_PLUGIN_STATE_DIR` is process-global, so every test that sets it has to
/// run on its own even though cargo runs them on separate threads. Without this
/// one test's sandbox teardown deletes another's state directory, and the
/// failure reads as "the store wrote nothing at all".
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn sandbox(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("redact-leaks-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("sandbox");
    dir
}

fn pane() -> PaneRef {
    PaneRef {
        pane_id: "w9:p1".into(),
        workspace_id: "w9".into(),
        tab_id: "w9:t1".into(),
        workspace_label: "app".into(),
        agent: Some("claude".into()),
        title: Some(TERMINAL_TITLE_VECTOR.into()),
        cwd: Some("/home/dev/repos/app".into()),
    }
}

/// Every vector that must not appear, plus the substrings that would betray a
/// partial leak: a preview is allowed four characters at each end, so a longer
/// run than that is a leak even if the whole value is absent.
fn forbidden() -> Vec<String> {
    let mut out: Vec<String> = VECTORS.iter().map(|v| v.to_string()).collect();
    out.push(TERMINAL_TITLE_VECTOR.to_string());
    out.push(SHELL_PROMPT_VECTOR.to_string());
    for value in VECTORS {
        let chars: Vec<char> = value.chars().collect();
        // Five characters from the head and from the tail: one more than the
        // mask is ever allowed to show.
        if chars.len() > 12 {
            out.push(chars[..5].iter().collect());
            out.push(chars[chars.len() - 5..].iter().collect());
        }
    }
    out
}

fn assert_clean(what: &str, text: &str) {
    for needle in forbidden() {
        assert!(
            !text.contains(&needle),
            "{what} leaked {needle:?}\n--- offending output ---\n{text}"
        );
    }
}

// ---------------------------------------------------------------------------
// The scanner
// ---------------------------------------------------------------------------

#[test]
fn a_match_carries_no_value_in_any_field() {
    let rules = Rules::builtin();
    let text = pane_text();
    let matches = scan::scan(&text, &rules, &[7u8; 16]);
    assert!(
        matches.len() >= 5,
        "the vectors are not being detected, so this proves nothing: {matches:?}"
    );

    for found in &matches {
        assert_clean("Match::pattern", &found.pattern);
        assert_clean("Match::label", &found.label);
        assert_clean("Match::preview", &found.preview);
        assert_clean("Match::Debug", &format!("{found:?}"));
    }
    // And the whole vector at once, which catches a value split across fields.
    assert_clean("the match list", &format!("{matches:?}"));
}

#[test]
fn a_preview_never_shows_more_than_four_characters_at_either_end() {
    for value in VECTORS {
        let preview = scan::mask(value);
        let chars: Vec<char> = value.chars().collect();
        let shown: usize = preview.chars().filter(|c| *c != '\u{2026}').count();

        assert!(
            shown <= 8,
            "mask({value:?}) shows {shown} characters: {preview:?}"
        );
        // The documented policy is a third, and the test used to assert two
        // thirds — a regression that doubled the number of characters kept would
        // have passed it. One extra character of slack, because `k = min(4,
        // len/6)` doubled is at most 8 and a 12-character value is allowed 4.
        assert!(
            shown * 3 <= chars.len().max(1) + 3,
            "mask({value:?}) shows {shown} of {} characters, which is over a third: {preview:?}",
            chars.len()
        );
        assert_ne!(&preview, value, "mask({value:?}) is the value itself");
        assert_clean("mask", &preview);
    }
}

// ---------------------------------------------------------------------------
// The store, on disk
// ---------------------------------------------------------------------------

#[test]
fn the_persisted_state_file_contains_no_value() {
    let _guard = env_lock();
    let dir = sandbox("state");
    std::env::set_var("HERDR_PLUGIN_STATE_DIR", &dir);
    std::env::set_var("HERDR_PLUGIN_ID", "test.redact");

    let config = Config::default();
    let rules = Rules::builtin();
    let mut store = Store::load(&config);
    let matches = scan::scan(&pane_text(), &rules, store.key());
    assert!(
        !matches.is_empty(),
        "nothing detected, so nothing is proved"
    );
    let fresh = store.observe(&pane(), &matches, now());
    store.record_foreground_process_when_first_seen(&fresh, Some("curl"), Some(4310));
    let ids: Vec<String> = fresh.iter().map(|finding| finding.id.clone()).collect();
    for id in &ids {
        assert_eq!(store.suppress(id), 1);
    }
    assert_eq!(
        store.suppression_count(),
        ids.len(),
        "every detected vector must exercise the persisted suppression shape"
    );
    assert!(
        store.observe(&pane(), &matches, now()).is_empty(),
        "the suppressed vectors must pass through observe's suppression path"
    );
    store.save().expect("save");
    let state = std::fs::read_to_string(dir.join("findings.json")).expect("findings state");
    assert!(
        state.contains("\"suppressions\""),
        "the leak check must include the suppression section"
    );

    // Every file the store wrote, not just the one we expect it to have.
    let mut checked = 0usize;
    for entry in std::fs::read_dir(&dir).expect("state dir").flatten() {
        let bytes = std::fs::read(entry.path()).unwrap_or_default();
        let text = String::from_utf8_lossy(&bytes);
        assert_clean(&format!("state file {:?}", entry.file_name()), &text);
        checked += 1;
    }
    assert!(checked >= 1, "the store wrote nothing at all");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Everything that renders
// ---------------------------------------------------------------------------

/// A report built the way the daemon builds one, so the renderers are fed real
/// findings rather than hand-written ones.
fn report_from_vectors(dir: &std::path::Path) -> Report {
    std::env::set_var("HERDR_PLUGIN_STATE_DIR", dir);
    std::env::set_var("HERDR_PLUGIN_ID", "test.redact");
    let config = Config::default();
    let rules = Rules::builtin();
    let mut store = Store::load(&config);
    let matches = scan::scan(&pane_text(), &rules, store.key());
    assert!(!matches.is_empty(), "nothing detected");
    let fresh = store.observe(&pane(), &matches, now());
    store.record_foreground_process_when_first_seen(&fresh, Some("curl"), Some(4310));
    store.report(vec!["a note about something going wrong".into()])
}

#[test]
fn nothing_the_renderers_produce_contains_a_value() {
    let _guard = env_lock();
    let dir = sandbox("render");
    let report = report_from_vectors(&dir);
    assert!(!report.findings.is_empty());

    // Every width the table is ever asked for, including the degenerate ones,
    // because a narrow layout takes a different branch.
    for columns in [10usize, 20, 40, 80, 120, 400] {
        assert_clean(
            &format!("report_text at {columns} columns"),
            &redact::render::report_text(&report, columns),
        );
    }
    assert_clean("report_json", &redact::render::report_json(&report));
    assert_clean("report_sarif", &redact::render::report_sarif(&report));
    assert_clean("Report::Debug", &format!("{report:?}"));

    for alert in [Alert::Clear, Alert::Weak, Alert::Secret] {
        for count in [0usize, 1, 7, 9_999] {
            assert_clean("badge", &redact::render::badge(alert, count));
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_json_snapshot_is_machine_readable_and_still_masked() {
    let _guard = env_lock();
    let dir = sandbox("json");
    let report = report_from_vectors(&dir);

    let parsed: serde_json::Value =
        serde_json::from_str(&redact::render::report_json(&report)).expect("valid JSON");
    // Walk every string in the document rather than trusting the top level.
    let mut strings = Vec::new();
    collect_strings(&parsed, &mut strings);
    assert!(!strings.is_empty());
    for text in strings {
        assert_clean("a JSON string", &text);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

fn collect_strings(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => out.push(text.clone()),
        serde_json::Value::Array(items) => items.iter().for_each(|v| collect_strings(v, out)),
        serde_json::Value::Object(map) => {
            for (key, v) in map {
                out.push(key.clone());
                collect_strings(v, out);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// The badge and the toast
// ---------------------------------------------------------------------------

#[test]
fn a_badge_carries_only_a_mark_and_a_count() {
    // A badge is written into herdr's session state, where it outlives the
    // process and is visible to anyone looking at the screen. It must be
    // incapable of carrying anything but a shape and a number.
    for count in [0usize, 1, 2, 42, usize::MAX] {
        for alert in [Alert::Weak, Alert::Secret] {
            let text = redact::render::badge(alert, count);
            assert!(
                text.chars()
                    .all(|c| !c.is_ascii_alphanumeric() || c.is_ascii_digit() || "kMG".contains(c)),
                "a badge contains letters that are not a magnitude suffix: {text:?}"
            );
        }
    }
}

/// The token names the plugin writes are a fixed, closed set. A badge that could
/// carry a per-finding name would put attacker-influenced text into herdr's
/// session state.
#[test]
fn the_token_names_are_a_closed_set() {
    let names: BTreeSet<&str> = Alert::ALL_TOKENS.into_iter().collect();
    assert_eq!(names.len(), Alert::ALL_TOKENS.len(), "duplicate token name");
    for alert in [Alert::Clear, Alert::Weak, Alert::Secret] {
        assert!(names.contains(alert.token_name()));
    }
}

// ---------------------------------------------------------------------------
// The model itself
// ---------------------------------------------------------------------------

#[test]
fn a_finding_has_no_field_that_could_hold_a_value() {
    let _guard = env_lock();
    let dir = sandbox("model");
    let report = report_from_vectors(&dir);

    for finding in &report.findings {
        assert_clean("Finding::Debug", &format!("{finding:?}"));
        // The fields that are rendered anywhere, named one by one so that adding
        // a new one to `Finding` makes this test look incomplete on review.
        let Finding {
            id,
            pattern,
            label,
            confidence: _,
            preview,
            value_len: _,
            pane_id,
            workspace_id,
            pane_label,
            agent,
            cwd,
            foreground_process_name_when_first_seen,
            foreground_process_pid_when_first_seen: _,
            line: _,
            digest: _,
            first_seen: _,
            last_seen: _,
            acknowledged: _,
        } = finding;
        for (what, text) in [
            ("id", id),
            ("pattern", pattern),
            ("label", label),
            ("preview", preview),
            ("pane_id", pane_id),
            ("workspace_id", workspace_id),
            ("pane_label", pane_label),
            ("agent", agent.as_ref().expect("agent provenance")),
            (
                "foreground process when first seen",
                foreground_process_name_when_first_seen
                    .as_ref()
                    .expect("process provenance"),
            ),
        ] {
            assert_clean(what, text);
        }
        assert_clean(
            "cwd",
            &cwd.as_ref()
                .expect("working-directory provenance")
                .display()
                .to_string(),
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// The digest is an identity, not a store. It must not be reversible by the
/// trivial route of being the value, and it must depend on the key — an unkeyed
/// hash of `PASSWORD=hunter2` is a dictionary lookup away from the original.
#[test]
fn the_digest_is_keyed_and_is_not_the_value() {
    for value in VECTORS {
        let a = redact::model::digest(&[0u8; 16], value);
        let b = redact::model::digest(&[1u8; 16], value);
        assert_ne!(a, b, "the digest ignores its key for {value:?}");
        assert_clean("digest", &format!("{a:x}{b:x}"));
    }
}

/// The toast body, asserted directly.
///
/// The review pointed out that this file's module doc claimed to cover it while
/// nothing in the file exercised it. A toast is the one output the user sees and
/// the suite does not: it is a hand-built string, it goes to herdr's
/// notification surface, and nobody re-reads it afterwards.
#[test]
fn a_toast_body_carries_no_value() {
    let dir = sandbox("toast");
    let _guard = env_lock();
    let report = report_from_vectors(&dir);
    assert!(!report.findings.is_empty());

    for finding in &report.findings {
        let (title, body) = redact::daemon::toast(finding);
        assert_clean("a toast title", &title);
        assert_clean("a toast body", &body);
        // And it has to be useful: the id in it is the one `--ack` takes.
        assert!(
            body.contains(finding.short_id()),
            "the toast does not say how to dismiss it: {body}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// A user-supplied rule reports the whole match rather than a capture group, so
/// it is a different code path through `mask` than any built-in with groups.
/// Nothing in this file went through it before.
#[test]
fn a_user_supplied_rule_masks_its_value_like_any_other() {
    let _guard = env_lock();
    let config = Config {
        patterns: vec![
            redact::config::CustomPattern {
                name: "internal_token".into(),
                former_names: Vec::new(),
                // Matches the whole thing, no capture group.
                regex: r"INT-[A-Za-z0-9]{24}".into(),
                label: Some("Internal service token".into()),
                strong: true,
            },
            redact::config::CustomPattern {
                name: "internal_weak".into(),
                former_names: Vec::new(),
                regex: r"WEAK-[A-Za-z0-9]{10}".into(),
                label: None,
                strong: false,
            },
        ],
        ..Config::default()
    };
    let rules = Rules::compile(&config).expect("the patterns compile");

    let value = "INT-EXAMPLEEXAMPLEEXAMPLEEXA";
    let weak = "WEAK-EXAMPLE123";
    let text = format!("$ deploy\nusing {value}\nfallback {weak}\n");
    let matches = scan::scan(&text, &rules, &[3u8; 16]);

    let found: Vec<&str> = matches.iter().map(|m| m.pattern.as_str()).collect();
    assert!(
        found.contains(&"internal_token") && found.contains(&"internal_weak"),
        "the user's own rules did not fire: {found:?}"
    );

    for found in &matches {
        assert_ne!(found.preview, value, "a user rule echoed its whole match");
        assert!(
            !found.preview.contains(value) && !found.preview.contains(weak),
            "a user rule's preview carries the value: {:?}",
            found.preview
        );
        assert!(
            !format!("{found:?}").contains(value),
            "a user rule's Debug carries the value"
        );
    }
}
