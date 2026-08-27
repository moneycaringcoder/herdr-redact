//! Formatting tests for the badge string, the findings table, and the JSON
//! snapshot.
//!
//! These exercise only local state and formatting: nothing here talks to herdr,
//! and every assertion is about the text that comes out.
//!
//! Two things are load-bearing about how they are written.
//!
//! **Widths are checked in display columns, never in bytes.** The badge marks
//! are multi-byte, so `str::len` reports 5 for a badge that occupies 3 columns.
//! The `columns` helper below is a deliberately independent second
//! implementation of the width rule, so a bug in the renderer's own width code
//! cannot hide behind a matching bug in the test.
//!
//! **The credential in these fixtures is fake but complete.** It is a
//! structurally valid, published-as-an-example AWS key, present in full so that
//! `no_rendering_contains_the_secret` can assert its absence from every string
//! this module can produce. Nothing here may ever hold a real one.

use redact::config::Config;
use redact::findings::Store;
use redact::model::{
    Alert, Calibration, CalibrationHit, Confidence, Finding, Match, PaneRef, Report,
};
use redact::render::{
    abbreviate, badge, calibration_text, report_json, report_json_with_quiet,
    report_sarif_with_quiet, report_text, report_text_with_quiet, BADGE_COLUMNS, MIN_COLUMNS,
};

// ---------------------------------------------------------------------------
// Test-local display width
// ---------------------------------------------------------------------------

/// Width of `text` in terminal columns, for the test's own assertions.
///
/// It delegates to `unicode-width`, the same crate the renderer uses, which
/// looks like the mistake the module docs warn against — a test measuring with
/// the code's own ruler. It is not quite: the renderer's job on top of the crate
/// is stripping ANSI and control characters and measuring whole strings rather
/// than characters, and that is the part this re-implements independently.
///
/// The ruler itself is pinned by [`the_width_table_is_right_about_hard_cases`]
/// below, which asserts hard-coded expected widths for the characters a
/// hand-rolled range table got wrong. Those numbers came from a reviewer
/// checking them against a terminal, not from either implementation.
fn columns(text: &str) -> usize {
    use unicode_width::UnicodeWidthStr;
    let mut visible = String::with_capacity(text.len());
    let mut in_escape = false;
    for ch in text.chars() {
        if in_escape {
            // A CSI sequence ends at its final byte, which is always in @-~.
            if ('\u{40}'..='\u{7e}').contains(&ch) {
                in_escape = false;
            }
            continue;
        }
        if ch == '\u{1b}' {
            in_escape = true;
            continue;
        }
        if ch.is_control() {
            continue;
        }
        visible.push(ch);
    }
    UnicodeWidthStr::width(visible.as_str())
}

/// Hard-coded widths for the cases a hand-rolled range table got wrong, so the
/// ruler both sides of these tests use is itself pinned to something outside
/// this crate.
///
/// Under-counting is the dangerous direction: every layout promise in the
/// renderer is "no line exceeds the width it was given".
#[test]
fn the_width_table_is_right_about_hard_cases() {
    let cases: [(&str, usize); 10] = [
        ("plain", 5),
        ("\u{1f680}", 2),          // 🚀, above the 1F300–1F64F block
        ("\u{2705}", 2),           // ✅, an emoji well below it
        ("\u{1f44d}\u{1f3fd}", 2), // 👍🏽, base plus skin-tone modifier
        // 👨‍👩‍👧 — a ZWJ family sequence, three people and two joiners.
        ("\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}", 2),
        ("\u{5e2d}\u{4f4d}", 4), // 席位, East Asian wide
        ("\u{05d0}\u{05b0}", 1), // Hebrew alef with a vowel point
        ("\u{0e01}\u{0e31}", 1), // Thai ko kai with a vowel sign
        ("\u{26a0}", 1),         // ⚠, the badge mark, text presentation
        ("\u{2691}", 1),         // ⚑, the weak mark
    ];
    for (text, expected) in cases {
        assert_eq!(
            columns(text),
            expected,
            "the test's own ruler is wrong about {text:?}"
        );
        assert_eq!(
            redact::render::display_width(text),
            expected,
            "the renderer's ruler is wrong about {text:?}"
        );
    }
}

fn widest(text: &str) -> usize {
    text.lines().map(columns).max().unwrap_or(0)
}

/// The whole view as one whitespace-normalised line, for asserting on prose
/// that word-wraps differently at different widths.
fn flatten(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Every width worth rendering at: a very narrow pane, the stacked/table
/// boundary, the default, and a wide one.
const WIDTHS: [usize; 6] = [MIN_COLUMNS, 24, 40, 47, 80, 200];

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A structurally valid AWS access key ID that has never been a credential:
/// it is the example key from AWS's own documentation. The scanner would mask
/// it to `AKIA…MPLE`; the full value is here only so the tests can prove it
/// never appears in any output.
const FAKE_SECRET: &str = "AKIAIOSFODNN7EXAMPLE";
const FAKE_SECRET_PREVIEW: &str = "AKIA\u{2026}MPLE";
const AWS_ROTATION_URL: &str =
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html";

/// The report's own clock. Fixed, so ages are deterministic.
const NOW: u64 = 1_700_000_000;

fn finding(id: &str, label: &str, pane_label: &str) -> Finding {
    Finding {
        id: format!("{id}0000000000"),
        pattern: "aws_access_key_id".to_string(),
        label: label.to_string(),
        confidence: Confidence::Strong,
        preview: FAKE_SECRET_PREVIEW.to_string(),
        value_len: FAKE_SECRET.chars().count(),
        pane_id: "w0:p1".to_string(),
        workspace_id: "w0".to_string(),
        pane_label: pane_label.to_string(),
        agent: None,
        cwd: None,
        foreground_process_name_when_first_seen: None,
        foreground_process_pid_when_first_seen: None,
        line: 42,
        digest: 0xdead_beef,
        first_seen: NOW - 90,
        last_seen: NOW,
        acknowledged: false,
    }
}

/// The ordinary case: one strong finding and one weak one, in the order the
/// store hands them over.
fn populated() -> Report {
    let mut weak = finding("b2c3d4", "API key assignment", "w0:p3");
    weak.pattern = "env_assignment".to_string();
    weak.confidence = Confidence::Weak;
    weak.preview = "sk-l\u{2026}9ab2".to_string();
    weak.first_seen = NOW - 7_200;

    Report {
        findings: vec![finding("a1b2c3", "AWS access key ID", "claude"), weak],
        suppression_count: 0,
        panes_scanned: 4,
        panes_skipped: 2,
        panes_unread: 0,
        panes_truncated: 0,
        notes: Vec::new(),
        generated_at: NOW,
    }
}

/// Nothing found, and nothing went wrong.
fn empty_but_fine() -> Report {
    Report {
        panes_scanned: 6,
        generated_at: NOW,
        ..Report::default()
    }
}

/// Nothing found, because the scan could not be completed.
fn empty_but_broken() -> Report {
    Report {
        panes_scanned: 0,
        notes: vec![
            "pane w0:p2 vanished between the snapshot and the read".to_string(),
            "the rule `internal_token` would not compile, so the built-in rules were used alone"
                .to_string(),
        ],
        generated_at: NOW,
        ..Report::default()
    }
}

// ---------------------------------------------------------------------------
// Badge
// ---------------------------------------------------------------------------

#[test]
fn a_clear_target_renders_nothing_at_all() {
    // Not a tick, not a dash, not a space: the empty string, which the daemon
    // reads as "clear this token" rather than "write an empty badge".
    assert_eq!(badge(Alert::Clear, 0), "");
    assert_eq!(badge(Alert::Clear, 1), "");
    assert_eq!(badge(Alert::Clear, usize::MAX), "");
}

#[test]
fn the_two_levels_are_distinguishable_without_colour() {
    let weak = badge(Alert::Weak, 1);
    let secret = badge(Alert::Secret, 1);
    assert_ne!(weak, secret);
    assert!(weak.ends_with('1') && secret.ends_with('1'));
}

#[test]
fn a_badge_never_exceeds_its_column_budget() {
    let interesting = [
        0usize,
        1,
        9,
        99,
        999,
        1_000,
        1_234,
        9_999,
        10_000,
        999_999,
        1_000_000,
        9_999_999,
        10_000_000,
        999_999_999,
        1_000_000_000,
        usize::MAX,
    ];
    for count in interesting {
        for alert in [Alert::Weak, Alert::Secret] {
            let text = badge(alert, count);
            assert!(
                columns(&text) <= BADGE_COLUMNS,
                "badge({alert:?}, {count}) = {text:?} is {} columns",
                columns(&text)
            );
        }
    }
}

#[test]
fn a_badge_with_no_count_is_the_mark_alone() {
    assert_eq!(columns(&badge(Alert::Secret, 0)), 1);
}

#[test]
fn abbreviated_counts_never_overstate_and_never_widen() {
    assert_eq!(abbreviate(999), "999");
    assert_eq!(abbreviate(1_999), "1.9k"); // truncated, not rounded to 2.0k
    assert_eq!(abbreviate(12_345), "12k");
    assert_eq!(abbreviate(1_999_999), "1.9M");
    assert_eq!(abbreviate(u64::MAX), "1G+");
    for n in [0, 1, 999, 1_000, 999_999, 1_000_000, u64::MAX] {
        assert!(columns(&abbreviate(n)) <= 4, "{n} abbreviated too wide");
    }
}

// ---------------------------------------------------------------------------
// Table width
// ---------------------------------------------------------------------------

#[test]
fn no_line_ever_exceeds_the_requested_width() {
    // Every hard case at once: a rule label longer than any real one, a wide
    // CJK pane label, an emoji in an agent name, and a long agent name.
    let mut long = finding(
        "c3d4e5",
        "Google Cloud service account private key (PEM block)",
        "\u{7d71}\u{8a08}\u{30d1}\u{30cd}\u{30eb}\u{30fb}\u{672c}\u{756a}",
    );
    long.first_seen = NOW - 400_000;

    let mut emoji = finding(
        "d4e5f6",
        "GitHub personal access token",
        "\u{1f680} deploy-agent",
    );
    emoji.acknowledged = true;

    let mut named = finding(
        "e5f6a7",
        "Slack bot token",
        "a-very-long-agent-name-somebody-actually-typed",
    );
    named.confidence = Confidence::Weak;

    let report = Report {
        findings: vec![long, emoji, named],
        suppression_count: 0,
        panes_scanned: 9,
        panes_skipped: 3,
        panes_unread: 1,
        panes_truncated: 2,
        notes: vec!["pane w1:p4 could not be read: permission denied".to_string()],
        generated_at: NOW,
    };

    for width in WIDTHS {
        let text = report_text(&report, width);
        assert!(
            widest(&text) <= width.max(MIN_COLUMNS),
            "at width {width} the widest line was {}:\n{text}",
            widest(&text)
        );
    }
}

#[test]
fn even_below_the_floor_nothing_overflows() {
    let report = populated();
    for width in [0, 1, 5, 12, 19] {
        let text = report_text(&report, width);
        assert!(
            widest(&text) <= MIN_COLUMNS,
            "at width {width} the widest line was {}",
            widest(&text)
        );
    }
}

#[test]
fn every_finding_survives_every_width() {
    let report = populated();
    for width in WIDTHS {
        let text = report_text(&report, width);
        for finding in &report.findings {
            assert!(
                text.contains(finding.short_id()),
                "{} vanished at width {width}:\n{text}",
                finding.short_id()
            );
        }
    }
}

#[test]
fn stacked_strong_finding_shows_rotation_link_without_changing_the_table() {
    let report = Report {
        findings: vec![finding("a1b2c3", "AWS access key ID", "claude")],
        panes_scanned: 1,
        generated_at: NOW,
        ..Report::default()
    };

    let stacked = report_text(&report, 40);
    let compact: String = stacked.chars().filter(|ch| !ch.is_whitespace()).collect();
    assert!(
        compact.contains(AWS_ROTATION_URL),
        "rotation URL was lost while wrapping:\n{stacked}"
    );
    assert!(
        flatten(&stacked).contains("rotation guidance:"),
        "{stacked}"
    );

    let table = report_text(&report, 80);
    assert!(!table.contains("rotation guidance:"), "{table}");
    assert!(!table.contains(AWS_ROTATION_URL), "{table}");
}

#[test]
fn stacked_strong_finding_without_provider_guidance_omits_it_cleanly() {
    let mut found = finding("a1b2c3", "JSON Web Token", "claude");
    found.pattern = "jwt".to_string();
    let report = Report {
        findings: vec![found],
        panes_scanned: 1,
        generated_at: NOW,
        ..Report::default()
    };

    let stacked = report_text(&report, 40);
    assert!(!stacked.contains("rotation guidance:"), "{stacked}");
    assert!(!stacked.contains("https://"), "{stacked}");
}

#[test]
fn stacked_findings_and_json_carry_provenance_when_present() {
    let mut found = finding("a1b2c3", "AWS access key ID", "claude");
    found.agent = Some("claude".to_string());
    found.cwd = Some("/home/dev/repos/app".into());
    found.foreground_process_name_when_first_seen = Some("curl".to_string());
    found.foreground_process_pid_when_first_seen = Some(4310);
    let report = Report {
        findings: vec![found],
        panes_scanned: 1,
        generated_at: NOW,
        ..Report::default()
    };

    let stacked = flatten(&report_text(&report, 40));
    assert!(
        stacked.contains("agent when first seen: claude"),
        "{stacked}"
    );
    assert!(
        stacked.contains("working directory when first seen: /home/dev/repos/app"),
        "{stacked}"
    );
    assert!(
        stacked.contains("foreground process when first seen: curl (pid 4310)"),
        "{stacked}"
    );

    let value: serde_json::Value =
        serde_json::from_str(&report_json(&report)).expect("report JSON");
    let finding = &value["findings"][0];
    assert_eq!(finding["agent"], "claude");
    assert_eq!(finding["cwd"], "/home/dev/repos/app");
    assert_eq!(finding["foreground_process_name_when_first_seen"], "curl");
    assert_eq!(finding["foreground_process_pid_when_first_seen"], 4310);
}

#[test]
fn absent_provenance_is_omitted_cleanly() {
    let report = populated();
    let stacked = flatten(&report_text(&report, 40));
    for label in [
        "agent when first seen",
        "working directory when first seen",
        "foreground process when first seen",
    ] {
        assert!(!stacked.contains(label), "{label:?} appeared in {stacked}");
    }

    let value: serde_json::Value =
        serde_json::from_str(&report_json(&report)).expect("report JSON");
    for finding in value["findings"].as_array().expect("findings") {
        for key in [
            "agent",
            "cwd",
            "foreground_process_name_when_first_seen",
            "foreground_process_pid_when_first_seen",
        ] {
            assert!(
                finding.get(key).is_none(),
                "{key} was not omitted: {finding}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Empty, and why
// ---------------------------------------------------------------------------

#[test]
fn nothing_found_says_how_many_panes_were_looked_at() {
    let text = report_text(&empty_but_fine(), 80);
    assert!(
        flatten(&text).contains("6 panes scanned, nothing found"),
        "{text}"
    );
}

#[test]
fn active_suppressions_are_visible_even_when_there_are_no_findings() {
    let dir =
        std::env::temp_dir().join(format!("redact-render-suppressions-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("state dir");
    std::env::set_var("HERDR_PLUGIN_STATE_DIR", &dir);

    let mut store = Store::load(&Config::default());
    let pane = PaneRef {
        pane_id: "w0:p1".to_string(),
        workspace_id: "w0".to_string(),
        tab_id: "w0:t1".to_string(),
        workspace_label: "app".to_string(),
        agent: Some("claude".to_string()),
        title: None,
        cwd: None,
    };
    for digest in 1..=12 {
        let candidate = Match {
            pattern: "fixture_rule".to_string(),
            label: "Fixture".to_string(),
            confidence: Confidence::Strong,
            preview: "ABCD…WXYZ".to_string(),
            value_len: 20,
            line: digest as usize,
            digest,
        };
        let fresh = store.observe(&pane, &[candidate], NOW);
        assert_eq!(store.suppress(&fresh[0].id), 1);
    }
    store.prune_to(&[]);
    let report = store.report(Vec::new());
    assert!(report.findings.is_empty());
    assert_eq!(report.suppression_count, 12);
    assert!(report.notes.is_empty());

    let text = flatten(&report_text(&report, 80));
    assert!(
        text.contains("12 permanent value suppression(s) active"),
        "{text}"
    );

    let json: serde_json::Value = serde_json::from_str(&report_json(&report)).expect("report JSON");
    assert_eq!(json["counts"]["findings"], 0);
    assert_eq!(json["counts"]["suppressions"], 12);
    assert_eq!(
        json["counts"]["notes"], 0,
        "the suppression count is visibility, not a scan failure"
    );

    drop(store);
    std::env::remove_var("HERDR_PLUGIN_STATE_DIR");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn zero_suppressions_render_as_zero_without_a_note() {
    let report = empty_but_fine();
    let text = flatten(&report_text(&report, 80));
    assert!(
        !text.contains("permanent value suppression"),
        "an inactive suppression should not add prose: {text}"
    );

    let json: serde_json::Value = serde_json::from_str(&report_json(&report)).expect("report JSON");
    assert_eq!(json["counts"]["suppressions"], 0);
}

#[test]
fn nothing_found_and_could_not_look_do_not_render_the_same() {
    // The single most important property in this file. A user who cannot tell
    // these apart is a user who trusts a clean report that never happened.
    let fine = report_text(&empty_but_fine(), 80);
    let broken = report_text(&empty_but_broken(), 80);
    assert_ne!(fine, broken);

    assert!(!flatten(&broken).contains("nothing found"), "{broken}");
    assert!(
        flatten(&broken).contains("did not complete cleanly"),
        "{broken}"
    );
    assert!(
        !flatten(&fine).contains("did not complete cleanly"),
        "{fine}"
    );
}

#[test]
fn a_scan_that_looked_at_nothing_says_which_kind_of_nothing() {
    // Every pane skipped is a different fact from no panes at all, and the
    // remedy for one is not the remedy for the other.
    let skipped = Report {
        panes_skipped: 5,
        generated_at: NOW,
        ..Report::default()
    };
    let none = Report {
        generated_at: NOW,
        ..Report::default()
    };

    let skipped = flatten(&report_text(&skipped, 80));
    let none = flatten(&report_text(&none, 80));

    assert_ne!(skipped, none);
    assert!(skipped.contains("5 panes skipped"), "{skipped}");
    assert!(skipped.contains("--all-panes"), "{skipped}");
    assert!(none.contains("no panes to read"), "{none}");
}

#[test]
fn notes_always_appear() {
    let broken = empty_but_broken();
    // With findings and without, at every width: a note is never dropped for
    // want of room, because it is the only thing that says the result is
    // incomplete.
    let with_findings = Report {
        notes: broken.notes.clone(),
        ..populated()
    };

    for report in [&broken, &with_findings] {
        for width in WIDTHS {
            let text = flatten(&report_text(report, width));
            for note in &report.notes {
                for word in note.split_whitespace() {
                    assert!(
                        text.contains(word),
                        "note word {word:?} missing at width {width}"
                    );
                }
            }
        }
    }
}

#[test]
fn a_truncated_pane_is_reported_because_the_user_is_not_seeing_everything() {
    let report = Report {
        panes_truncated: 3,
        ..populated()
    };
    let text = flatten(&report_text(&report, 80));
    assert!(text.contains("3 panes had more output"), "{text}");
}

// ---------------------------------------------------------------------------
// Acknowledgement
// ---------------------------------------------------------------------------

#[test]
fn acknowledged_findings_are_marked_and_stay_below_the_live_ones() {
    // The store sorts; the renderer must not. This fixture arrives in store
    // order, and the assertion is that the order survives.
    let mut acknowledged = finding("f6a7b8", "Stripe live secret key", "codex");
    acknowledged.acknowledged = true;

    let report = Report {
        findings: vec![
            finding("a1b2c3", "AWS access key ID", "claude"),
            acknowledged,
        ],
        panes_scanned: 2,
        generated_at: NOW,
        ..Report::default()
    };

    let text = report_text(&report, 80);
    let live = text.find("a1b2c").expect("live finding is missing");
    let done = text.find("f6a7b").expect("acknowledged finding is missing");
    assert!(live < done, "acknowledged finding sorted above a live one");

    // Marked, in a way that is legible without colour, and explained.
    let ack_line = text
        .lines()
        .find(|line| line.contains("f6a7b"))
        .expect("acknowledged row is missing");
    assert!(
        ack_line.contains('\u{2713}'),
        "{ack_line:?} carries no mark"
    );
    assert!(flatten(&text).contains("\u{2713} acknowledged"), "{text}");

    // The counts say it in words as well as in marks.
    assert!(
        flatten(&text).contains("1 unacknowledged and 1 acknowledged"),
        "{text}"
    );
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

#[test]
fn the_json_snapshot_round_trips_and_carries_the_counts_and_the_notes() {
    let report = Report {
        notes: vec!["pane w0:p2 vanished between the snapshot and the read".to_string()],
        panes_truncated: 1,
        ..populated()
    };

    let raw = report_json(&report);
    let value: serde_json::Value = serde_json::from_str(&raw).expect("report_json is not JSON");

    assert_eq!(value["version"], 1);
    assert_eq!(value["alert"], "secret");
    assert_eq!(value["counts"]["findings"], 2);
    assert_eq!(value["counts"]["unacknowledged"], 2);
    assert_eq!(value["counts"]["acknowledged"], 0);
    assert_eq!(value["counts"]["panes_scanned"], 4);
    assert_eq!(value["counts"]["panes_skipped"], 2);
    assert_eq!(value["counts"]["panes_truncated"], 1);
    assert_eq!(value["notes"][0], report.notes[0].as_str());

    let first = &value["findings"][0];
    assert_eq!(first["pattern"], "aws_access_key_id");
    assert_eq!(first["confidence"], "strong");
    assert_eq!(first["preview"], FAKE_SECRET_PREVIEW);
    assert_eq!(first["value_len"], 20);
    assert_eq!(first["age_seconds"], 90);
    assert_eq!(first["acknowledged"], false);

    // Identity material is not for publication, keyed or not.
    assert!(first.get("digest").is_none(), "the digest is in the JSON");
}

#[test]
fn an_empty_result_and_a_failed_one_are_distinguishable_by_a_script() {
    let fine: serde_json::Value = serde_json::from_str(&report_json(&empty_but_fine())).unwrap();
    let broken: serde_json::Value =
        serde_json::from_str(&report_json(&empty_but_broken())).unwrap();

    assert_eq!(fine["counts"]["findings"], 0);
    assert_eq!(broken["counts"]["findings"], 0);

    // The discriminator, without parsing any prose.
    assert_eq!(fine["counts"]["notes"], 0);
    assert_eq!(broken["counts"]["notes"], 2);
    assert_eq!(fine["counts"]["panes_scanned"], 6);
    assert_eq!(broken["counts"]["panes_scanned"], 0);
    assert_eq!(fine["alert"], "clear");
}

#[test]
fn the_alert_level_follows_the_worst_unacknowledged_finding() {
    let mut report = populated();
    let value: serde_json::Value = serde_json::from_str(&report_json(&report)).unwrap();
    assert_eq!(value["alert"], "secret");

    // Acknowledging the strong one leaves only the weak one lit.
    report.findings[0].acknowledged = true;
    let value: serde_json::Value = serde_json::from_str(&report_json(&report)).unwrap();
    assert_eq!(value["alert"], "weak");

    // Acknowledging everything clears it, which is what makes the badge go away.
    report.findings[1].acknowledged = true;
    let value: serde_json::Value = serde_json::from_str(&report_json(&report)).unwrap();
    assert_eq!(value["alert"], "clear");
}

// ---------------------------------------------------------------------------
// SARIF
// ---------------------------------------------------------------------------

#[test]
fn the_sarif_snapshot_carries_findings_disposition_provenance_and_scan_quality() {
    let mut strong = finding("a1b2c3", "AWS access key ID", "claude");
    strong.agent = Some("claude".to_string());
    strong.cwd = Some(std::path::PathBuf::from("/workspace/example"));
    strong.foreground_process_name_when_first_seen = Some("cargo".to_string());
    strong.foreground_process_pid_when_first_seen = Some(4310);

    let mut weak = finding("b2c3d4", "API key assignment", "shell");
    weak.pattern = "env_assignment".to_string();
    weak.confidence = Confidence::Weak;
    weak.preview = "sk-l\u{2026}9ab2".to_string();
    weak.pane_id = "w0:p2".to_string();
    weak.line = 7;

    let mut acknowledged = finding("c3d4e5", "Stripe live secret key", "codex");
    acknowledged.pattern = "stripe_secret_key".to_string();
    acknowledged.preview = "sk_l\u{2026}7890".to_string();
    acknowledged.pane_id = "w0:p3".to_string();
    acknowledged.line = 91;
    acknowledged.acknowledged = true;

    let report = Report {
        findings: vec![strong, weak, acknowledged],
        suppression_count: 2,
        panes_scanned: 5,
        panes_skipped: 2,
        panes_unread: 1,
        panes_truncated: 3,
        notes: vec!["pane w0:p4 could not be read".to_string()],
        generated_at: NOW,
    };
    let raw = report_sarif_with_quiet(&report, Some(2_000), 1_000);
    let value: serde_json::Value = serde_json::from_str(&raw).expect("report_sarif is not JSON");

    assert_eq!(
        value["$schema"],
        "https://json.schemastore.org/sarif-2.1.0.json"
    );
    assert_eq!(value["version"], "2.1.0");
    assert_eq!(value["runs"].as_array().map(Vec::len), Some(1));

    let run = &value["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "redact");
    let rule_ids: Vec<&str> = run["tool"]["driver"]["rules"]
        .as_array()
        .expect("driver rules")
        .iter()
        .filter_map(|rule| rule["id"].as_str())
        .collect();
    assert_eq!(
        rule_ids,
        ["aws_access_key_id", "env_assignment", "stripe_secret_key"]
    );

    // `aws_access_key_id` and `stripe_secret_key` name a provider revocation
    // page; `env_assignment` is exempt, so it has no page to carry.
    let rules = run["tool"]["driver"]["rules"]
        .as_array()
        .expect("driver rules");
    assert_eq!(
        rules[0]["helpUri"],
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
    );
    assert_eq!(rules[2]["helpUri"], "https://dashboard.stripe.com/apikeys");
    assert!(
        rules[1].get("helpUri").is_none(),
        "an exempt rule carries a helpUri: {}",
        rules[1]
    );

    let results = run["results"].as_array().expect("SARIF results");
    assert_eq!(results.len(), 3);
    assert_eq!(results[0]["ruleId"], "aws_access_key_id");
    assert_eq!(results[0]["level"], "error");
    assert_eq!(
        results[0]["message"]["text"],
        format!("aws_access_key_id in pane w0:p1: {FAKE_SECRET_PREVIEW}")
    );
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "herdr://pane/w0:p1"
    );
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["region"]["startLine"],
        42
    );
    assert_eq!(
        results[0]["partialFingerprints"]["redactFindingId"],
        report.findings[0].id
    );
    assert_eq!(results[0]["properties"]["agent"], "claude");
    assert_eq!(
        results[0]["properties"]["workingDirectory"],
        "/workspace/example"
    );
    assert_eq!(
        results[0]["properties"]["foregroundProcessNameWhenFirstSeen"],
        "cargo"
    );
    assert_eq!(
        results[0]["properties"]["foregroundProcessPidWhenFirstSeen"],
        4310
    );

    assert_eq!(results[1]["level"], "warning");
    assert_eq!(
        results[1]["message"]["text"],
        "env_assignment in pane w0:p2: sk-l\u{2026}9ab2"
    );
    assert!(results[1].get("suppressions").is_none());
    assert_eq!(
        results[2]["message"]["text"],
        "stripe_secret_key in pane w0:p3: sk_l\u{2026}7890"
    );
    assert_eq!(results[2]["suppressions"][0]["kind"], "external");
    assert_eq!(results[2]["suppressions"][0]["status"], "accepted");

    let counts = &run["properties"]["counts"];
    assert_eq!(counts["findings"], 3);
    assert_eq!(counts["acknowledged"], 1);
    assert_eq!(counts["suppressions"], 2);
    assert_eq!(counts["panesScanned"], 5);
    assert_eq!(counts["panesSkipped"], 2);
    assert_eq!(counts["panesUnread"], 1);
    assert_eq!(counts["panesTruncated"], 3);
    assert_eq!(counts["notes"], 1);
    assert_eq!(run["properties"]["notes"][0], report.notes[0]);
    assert_eq!(run["properties"]["quiet"]["active"], true);
    assert_eq!(run["properties"]["quiet"]["remainingSeconds"], 1_000);

    fn has_key(value: &serde_json::Value, wanted: &str) -> bool {
        match value {
            serde_json::Value::Array(items) => items.iter().any(|item| has_key(item, wanted)),
            serde_json::Value::Object(object) => object
                .iter()
                .any(|(key, child)| key == wanted || has_key(child, wanted)),
            _ => false,
        }
    }
    assert!(!has_key(&value, "digest"), "the digest is in the SARIF");
    assert!(
        !raw.contains(FAKE_SECRET),
        "the unmasked value is in the SARIF"
    );
}

#[test]
fn quiet_banner_names_its_expiry_and_says_collection_continues() {
    let text = report_text_with_quiet(&populated(), 80, Some(2_000), 1_000);
    let flat = flatten(&text);

    assert!(flat.contains("QUIET until Unix time 2000"), "{text}");
    assert!(
        flat.contains("findings are still being collected"),
        "{text}"
    );
}

#[test]
fn json_carries_quiet_state_and_expiry() {
    let value: serde_json::Value =
        serde_json::from_str(&report_json_with_quiet(&populated(), Some(2_000), 1_000)).unwrap();

    assert_eq!(value["quiet"]["active"], true);
    assert_eq!(value["quiet"]["until"], 2_000);
    assert_eq!(value["quiet"]["remaining_seconds"], 1_000);
    assert_eq!(value["quiet"]["findings_still_collected"], true);
}

#[test]
fn a_clean_quiet_report_does_not_read_as_a_failed_scan() {
    let report = empty_but_fine();
    let text = flatten(&report_text_with_quiet(&report, 80, Some(2_000), 1_000));
    let value: serde_json::Value =
        serde_json::from_str(&report_json_with_quiet(&report, Some(2_000), 1_000)).unwrap();

    assert!(text.contains("6 panes scanned, nothing found"), "{text}");
    assert!(!text.contains("did not complete cleanly"), "{text}");
    assert!(!text.contains("failed"), "{text}");
    assert_eq!(value["alert"], "clear");
    assert_eq!(value["counts"]["notes"], 0);
    assert_eq!(value["quiet"]["active"], true);
}

// ---------------------------------------------------------------------------
// The whole point
// ---------------------------------------------------------------------------

#[test]
fn no_rendering_contains_the_secret() {
    // `preview` is masked at source, so this test is not about the mask. It is
    // about everything this module writes *around* the mask: that nothing here
    // re-derives, concatenates, or pads its way back to the value.
    let mut report = populated();
    report.notes.push("scanned 4 panes".to_string());
    report.panes_truncated = 1;

    let mut rendered: Vec<String> = Vec::new();
    for width in WIDTHS {
        rendered.push(report_text(&report, width));
    }
    rendered.push(report_json(&report));
    for count in [0usize, 1, 2, 4_000, usize::MAX] {
        for alert in [Alert::Clear, Alert::Weak, Alert::Secret] {
            rendered.push(badge(alert, count));
        }
    }

    for text in &rendered {
        assert!(
            !text.contains(FAKE_SECRET),
            "a rendering contained the credential:\n{text}"
        );
        // The masked preview keeps four characters at each end, so the halves
        // are expected; anything longer than that is not.
        assert!(
            !text.contains("IOSFODNN7"),
            "a rendering contained the middle of the credential:\n{text}"
        );
    }
}

/// The review found this: with every pane read failing, the empty-table branch
/// said "herdr reported no panes to read" — false, and contradicted two lines
/// later by "3 panes could not be read at all".
#[test]
fn every_read_failing_is_not_reported_as_an_empty_session() {
    let all_failed = Report {
        panes_scanned: 0,
        panes_unread: 3,
        notes: vec!["pane w1:p1 could not be read: timed out".to_string()],
        generated_at: NOW,
        ..Report::default()
    };
    let no_panes = Report {
        generated_at: NOW,
        ..Report::default()
    };

    let failed = flatten(&report_text(&all_failed, 80));
    let empty = flatten(&report_text(&no_panes, 80));

    assert!(
        !failed.contains("no panes to read"),
        "a session whose reads all failed is not a session with no panes:\n{failed}"
    );
    assert!(
        failed.contains("nobody looked at") || failed.contains("failed"),
        "the failure is not stated:\n{failed}"
    );
    assert!(
        empty.contains("no panes to read"),
        "the genuinely empty session lost its own message:\n{empty}"
    );
    assert_ne!(failed, empty);
}

// ---------------------------------------------------------------------------
// Calibration
// ---------------------------------------------------------------------------

fn calibration_hit(
    pattern: &str,
    confidence: Confidence,
    preview: &str,
    pane_id: &str,
) -> CalibrationHit {
    CalibrationHit {
        pane_id: pane_id.to_string(),
        pane_label: pane_id.to_string(),
        workspace_id: "w0".to_string(),
        matched: Match {
            pattern: pattern.to_string(),
            label: pattern.replace('_', " "),
            confidence,
            preview: preview.to_string(),
            value_len: 20,
            line: 12,
            digest: 3_735_928_559,
        },
    }
}

#[test]
fn a_clean_calibration_says_nothing_would_have_fired() {
    let calibration = Calibration {
        panes_scanned: 4,
        generated_at: NOW,
        ..Calibration::default()
    };

    let text = calibration_text(&calibration, 80);
    assert_eq!(
        text,
        "redact \u{b7} calibration\n\n0 matches would have fired across 4 panes scanned.\n"
    );
}

#[test]
fn a_calibration_with_several_rules_groups_and_sorts_its_hits() {
    let calibration = Calibration {
        hits: vec![
            calibration_hit(
                "aws_access_key_id",
                Confidence::Strong,
                FAKE_SECRET_PREVIEW,
                "w0:p1",
            ),
            calibration_hit(
                "github_token",
                Confidence::Strong,
                "ghp_\u{2026}LE01",
                "w0:p3",
            ),
            calibration_hit(
                "aws_access_key_id",
                Confidence::Strong,
                FAKE_SECRET_PREVIEW,
                "w0:p1",
            ),
            calibration_hit(
                "aws_access_key_id",
                Confidence::Strong,
                "ASIA\u{2026}MPLE",
                "w0:p2",
            ),
        ],
        panes_scanned: 3,
        generated_at: NOW,
        ..Calibration::default()
    };

    let text = calibration_text(&calibration, 80);
    let flat = flatten(&text);
    assert!(
        flat.contains("4 matches would have fired across 3 panes scanned"),
        "{text}"
    );
    assert!(text.contains("rule"), "{text}");
    assert!(text.contains("confidence"), "{text}");
    assert!(text.contains("masked sample"), "{text}");
    let aws = text.find("aws_access_key_id").expect("AWS rule missing");
    let github = text.find("github_token").expect("GitHub rule missing");
    assert!(aws < github, "the higher-count rule was not first:\n{text}");
    let aws_line = text
        .lines()
        .find(|line| line.contains("aws_access_key_id"))
        .unwrap();
    assert!(aws_line.contains('3'), "{aws_line}");
    assert!(aws_line.contains('2'), "{aws_line}");
    assert!(aws_line.contains(FAKE_SECRET_PREVIEW), "{aws_line}");
    assert!(
        !text.contains("3735928559"),
        "a digest was rendered:\n{text}"
    );
    assert!(
        !text.contains(FAKE_SECRET),
        "a raw value was rendered:\n{text}"
    );

    for width in WIDTHS {
        let text = calibration_text(&calibration, width);
        assert!(
            widest(&text) <= width.max(MIN_COLUMNS),
            "calibration overflowed at width {width}:\n{text}"
        );
    }
}

#[test]
fn a_calibration_that_ran_out_of_budget_is_incomplete_not_clean() {
    let note = "2 pane(s) were not read before this calibration's 30s budget ran out; calibration \
                has no later cycle, so this result is incomplete";
    let calibration = Calibration {
        panes_scanned: 1,
        panes_unread: 2,
        notes: vec![note.to_string()],
        generated_at: NOW,
        ..Calibration::default()
    };

    let text = calibration_text(&calibration, 80);
    let flat = flatten(&text);
    assert!(flat.contains("0 matches were observed"), "{text}");
    assert!(flat.contains("did not complete cleanly"), "{text}");
    assert!(flat.contains("This is not a clean result"), "{text}");
    assert!(flat.contains("2 panes could not be read at all"), "{text}");
    assert!(!flat.contains("0 matches would have fired"), "{text}");
    assert!(flat.contains(note), "{text}");
}
