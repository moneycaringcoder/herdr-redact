//! Formatting tests for the badge string, the findings table, and the JSON
//! snapshot.
//!
//! These are pure: nothing here talks to herdr. Every fixture is a hand-built
//! `Report`, and every assertion is about the text that comes out.
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

use redact::model::{Alert, Confidence, Finding, Report};
use redact::render::{abbreviate, badge, report_json, report_text, BADGE_COLUMNS, MIN_COLUMNS};

// ---------------------------------------------------------------------------
// Test-local display width
// ---------------------------------------------------------------------------

/// Width of `text` in terminal columns. Written from scratch rather than
/// reusing `render::display_width`, and rather than pulling in `unicode-width`,
/// which is not a dependency of this crate.
fn columns(text: &str) -> usize {
    let mut total = 0;
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
        total += match ch as u32 {
            // Combining marks and variation selectors take no space.
            0x0300..=0x036f | 0x200b..=0x200f | 0xfe00..=0xfe0f | 0xfeff => 0,
            // The common East Asian wide and fullwidth blocks take two.
            0x1100..=0x115f
            | 0x2e80..=0xa4cf
            | 0xac00..=0xd7a3
            | 0xf900..=0xfaff
            | 0xfe30..=0xfe6f
            | 0xff00..=0xff60
            | 0xffe0..=0xffe6
            | 0x1f300..=0x1f64f
            | 0x1f900..=0x1f9ff => 2,
            _ => 1,
        };
    }
    total
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
