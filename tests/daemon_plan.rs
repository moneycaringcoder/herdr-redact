//! The daemon's pure decisions: which panes may be read at all, which badge
//! calls a cycle produces, and which arguments survive being handed to a
//! detached child.
//!
//! `badge_plan` is a pure function so these rules can be checked without a
//! socket. They are ordering rules, and getting them wrong renders as two
//! badges at once or a badge that never goes away — both of which are
//! invisible from a unit test of anything smaller.

use std::collections::HashMap;

use redact::config::Config;
use redact::daemon::{
    badge_plan, badge_plan_with, forwarded_args, should_scan, ActiveBadges, BadgeOp,
};
use redact::model::{Alert, Confidence, Finding, PaneRef, Report};

/// Badge text as `render::badge` is contracted to produce it: the empty string
/// for a clear target, and something short otherwise.
///
/// The tests supply it rather than calling `render::badge` so they check the
/// planner's rules against the contract rather than against whatever the
/// renderer happens to produce today.
fn badge_text(alert: Alert, count: usize) -> String {
    match alert {
        Alert::Clear => String::new(),
        Alert::Weak => format!("? {count}"),
        Alert::Secret => format!("! {count}"),
    }
}

fn pane(pane_id: &str, workspace_id: &str) -> PaneRef {
    PaneRef {
        pane_id: pane_id.to_string(),
        workspace_id: workspace_id.to_string(),
        tab_id: format!("{workspace_id}:t1"),
        workspace_label: workspace_id.to_string(),
        agent: Some("claude".to_string()),
        title: None,
        cwd: None,
    }
}

fn finding(pane_id: &str, workspace_id: &str, confidence: Confidence) -> Finding {
    Finding {
        id: format!("{pane_id}-{}", confidence.as_str()),
        pattern: "aws_access_key_id".to_string(),
        label: "AWS access key ID".to_string(),
        confidence,
        preview: "AKIA\u{2026}MPLE".to_string(),
        value_len: 20,
        pane_id: pane_id.to_string(),
        workspace_id: workspace_id.to_string(),
        pane_label: "rev-media".to_string(),
        agent: None,
        cwd: None,
        foreground_process_name_when_first_seen: None,
        foreground_process_pid_when_first_seen: None,
        line: 12,
        digest: 7,
        first_seen: 100,
        last_seen: 100,
        acknowledged: false,
    }
}

fn report(findings: Vec<Finding>) -> Report {
    Report {
        findings,
        ..Report::default()
    }
}

fn active(panes: &[(&str, &str)], workspaces: &[(&str, &str)]) -> ActiveBadges {
    ActiveBadges {
        panes: to_map(panes),
        workspaces: to_map(workspaces),
    }
}

fn to_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn plan(active: &ActiveBadges, report: &Report, panes: &[PaneRef]) -> Vec<BadgeOp> {
    badge_plan_with(active, report, panes, badge_text)
}

#[test]
fn a_finding_lights_both_the_pane_and_its_workspace() {
    // An agent panel can be collapsed, and a badge nobody can see protects
    // nobody, so the space row carries one too.
    let panes = [pane("wE:p2", "wE")];
    let report = report(vec![finding("wE:p2", "wE", Confidence::Strong)]);

    let ops = plan(&ActiveBadges::default(), &report, &panes);

    assert_eq!(
        ops,
        vec![
            BadgeOp::SetPane {
                pane_id: "wE:p2".to_string(),
                token: "redact_secret",
                text: "! 1".to_string(),
            },
            BadgeOp::SetWorkspace {
                workspace_id: "wE".to_string(),
                token: "redact_secret",
                text: "! 1".to_string(),
            },
        ]
    );
}

/// Tokens are a merge patch: a name we do not mention stays lit. Setting the
/// new name without clearing the old one renders two badges on one row.
#[test]
fn a_severity_flip_clears_the_old_token_before_setting_the_new_one() {
    let panes = [pane("wE:p2", "wE")];
    let report = report(vec![finding("wE:p2", "wE", Confidence::Strong)]);
    let active = active(&[("wE:p2", "redact_weak")], &[("wE", "redact_weak")]);

    let ops = plan(&active, &report, &panes);

    assert_eq!(
        ops,
        vec![
            BadgeOp::ClearPane {
                pane_id: "wE:p2".to_string(),
                token: "redact_weak".to_string(),
            },
            BadgeOp::SetPane {
                pane_id: "wE:p2".to_string(),
                token: "redact_secret",
                text: "! 1".to_string(),
            },
            BadgeOp::ClearWorkspace {
                workspace_id: "wE".to_string(),
                token: "redact_weak".to_string(),
            },
            BadgeOp::SetWorkspace {
                workspace_id: "wE".to_string(),
                token: "redact_secret",
                text: "! 1".to_string(),
            },
        ]
    );
}

#[test]
fn an_unchanged_severity_is_re_sent_without_a_clear() {
    // The TTL is what makes a badge self-heal after a killed daemon, and it
    // only refreshes on a write, so an unchanged badge is still written.
    let panes = [pane("wE:p2", "wE")];
    let report = report(vec![finding("wE:p2", "wE", Confidence::Strong)]);
    let active = active(&[("wE:p2", "redact_secret")], &[("wE", "redact_secret")]);

    let ops = plan(&active, &report, &panes);

    assert!(
        !ops.iter().any(|op| matches!(
            op,
            BadgeOp::ClearPane { .. } | BadgeOp::ClearWorkspace { .. }
        )),
        "{ops:?}"
    );
    assert_eq!(ops.len(), 2);
}

#[test]
fn acknowledging_the_last_finding_clears_the_badge() {
    let panes = [pane("wE:p2", "wE")];
    let mut acknowledged = finding("wE:p2", "wE", Confidence::Strong);
    acknowledged.acknowledged = true;
    let report = report(vec![acknowledged]);
    let active = active(&[("wE:p2", "redact_secret")], &[("wE", "redact_secret")]);

    let ops = plan(&active, &report, &panes);

    assert_eq!(
        ops,
        vec![
            BadgeOp::ClearPane {
                pane_id: "wE:p2".to_string(),
                token: "redact_secret".to_string(),
            },
            BadgeOp::ClearWorkspace {
                workspace_id: "wE".to_string(),
                token: "redact_secret".to_string(),
            },
        ]
    );
}

/// A pane that closed is not in the snapshot at all, so nothing in the report
/// mentions it. It still has to be cleared rather than left to expire.
#[test]
fn a_target_that_dropped_out_of_the_report_is_cleared() {
    let panes = [pane("wE:p2", "wE")];
    let report = report(vec![finding("wE:p2", "wE", Confidence::Strong)]);
    let active = active(
        &[("wE:p2", "redact_secret"), ("gone:p1", "redact_weak")],
        &[("wE", "redact_secret"), ("gone", "redact_weak")],
    );

    let ops = plan(&active, &report, &panes);

    assert!(ops.contains(&BadgeOp::ClearPane {
        pane_id: "gone:p1".to_string(),
        token: "redact_weak".to_string(),
    }));
    assert!(ops.contains(&BadgeOp::ClearWorkspace {
        workspace_id: "gone".to_string(),
        token: "redact_weak".to_string(),
    }));
}

/// An empty badge string is the renderer saying "nothing to show". Writing it
/// would occupy the row with nothing at all.
#[test]
fn an_empty_badge_string_is_a_clear_and_never_a_set() {
    let panes = [pane("wE:p2", "wE")];
    let report = report(Vec::new());
    let active = active(&[("wE:p2", "redact_secret")], &[("wE", "redact_secret")]);

    let ops = plan(&active, &report, &panes);

    assert!(
        !ops.iter()
            .any(|op| matches!(op, BadgeOp::SetPane { .. } | BadgeOp::SetWorkspace { .. })),
        "{ops:?}"
    );
    assert_eq!(ops.len(), 2, "both targets are cleared: {ops:?}");
}

/// Whatever the renderer returns, a target with nothing to say and nothing lit
/// produces no calls at all — an idle session must not generate traffic.
#[test]
fn a_clean_session_with_nothing_lit_produces_no_calls() {
    let panes = [pane("wE:p2", "wE"), pane("wM:p1", "wM")];

    assert!(plan(&ActiveBadges::default(), &report(Vec::new()), &panes).is_empty());
    assert!(badge_plan(&ActiveBadges::default(), &report(Vec::new()), &panes).is_empty());
}

/// Two panes in one workspace: the pane badges are per pane, and the workspace
/// badge aggregates to the worst of them.
#[test]
fn a_workspace_badge_takes_the_worst_of_its_panes() {
    let panes = [pane("wE:p1", "wE"), pane("wE:p2", "wE")];
    let report = report(vec![
        finding("wE:p1", "wE", Confidence::Weak),
        finding("wE:p2", "wE", Confidence::Strong),
    ]);

    let ops = plan(&ActiveBadges::default(), &report, &panes);

    assert_eq!(
        ops,
        vec![
            BadgeOp::SetPane {
                pane_id: "wE:p1".to_string(),
                token: "redact_weak",
                text: "? 1".to_string(),
            },
            BadgeOp::SetPane {
                pane_id: "wE:p2".to_string(),
                token: "redact_secret",
                text: "! 1".to_string(),
            },
            BadgeOp::SetWorkspace {
                workspace_id: "wE".to_string(),
                token: "redact_secret",
                text: "! 1".to_string(),
            },
        ]
    );
}

/// A HashMap iterates arbitrarily. Without a sort the plan would shuffle
/// between cycles, and both the tests and the daemon's log would be noise.
#[test]
fn the_plan_is_deterministic() {
    let panes = [
        pane("wM:p1", "wM"),
        pane("wE:p2", "wE"),
        pane("wE:p1", "wE"),
    ];
    let report = report(vec![
        finding("wE:p1", "wE", Confidence::Weak),
        finding("wM:p1", "wM", Confidence::Strong),
    ]);
    let active = active(
        &[("zz:p9", "redact_weak"), ("aa:p1", "redact_secret")],
        &[("zz", "redact_weak"), ("aa", "redact_secret")],
    );

    let first = plan(&active, &report, &panes);
    for _ in 0..16 {
        assert_eq!(plan(&active, &report, &panes), first);
    }

    // Sorted, so a reader can find a target in the log.
    let stale_panes: Vec<&String> = first
        .iter()
        .filter_map(|op| match op {
            BadgeOp::ClearPane { pane_id, .. } => Some(pane_id),
            _ => None,
        })
        .collect();
    assert_eq!(stale_panes, vec!["aa:p1", "zz:p9"]);
}

// ---------------------------------------------------------------------------
// The pane filter
// ---------------------------------------------------------------------------

#[test]
fn only_agent_panes_are_read_by_default() {
    let config = Config::default();
    let mut shell = pane("w0:p1", "w0");
    shell.agent = None;

    assert!(should_scan(&pane("wE:p2", "wE"), &config, None));
    assert!(!should_scan(&shell, &config, None));
}

#[test]
fn all_panes_widens_the_filter() {
    let config = Config {
        scan_all_panes: true,
        ..Config::default()
    };
    let mut shell = pane("w0:p1", "w0");
    shell.agent = None;

    assert!(
        should_scan(&shell, &config, None),
        "the shell where someone ran `cat .env` is often not an agent pane"
    );
}

/// A pane that scans itself reports its own masked previews for ever, and every
/// one of them looks like a real finding.
#[test]
fn this_processes_own_pane_is_never_read() {
    let config = Config {
        scan_all_panes: true,
        ..Config::default()
    };

    assert!(!should_scan(&pane("wE:p2", "wE"), &config, Some("wE:p2")));
    assert!(should_scan(&pane("wE:p1", "wE"), &config, Some("wE:p2")));
}

#[test]
fn ignored_panes_are_never_read_even_with_all_panes() {
    let config = Config {
        scan_all_panes: true,
        ignore_panes: vec!["wE:p2".to_string()],
        ..Config::default()
    };

    assert!(!should_scan(&pane("wE:p2", "wE"), &config, None));
}

// ---------------------------------------------------------------------------
// Detached child arguments
// ---------------------------------------------------------------------------

/// The child re-reads the config file but never sees the user's command line,
/// so anything it needs has to be handed over explicitly.
#[test]
fn the_child_is_given_the_options_the_user_typed() {
    let args: Vec<String> = ["--enable", "--interval", "30", "--lines=800", "--all-panes"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    assert_eq!(
        forwarded_args(&args).expect("parse"),
        vec!["--interval", "30", "--lines", "800", "--all-panes"],
        "both spellings normalise to `--name value`"
    );
}

#[test]
fn nothing_else_on_the_command_line_reaches_the_child() {
    let args: Vec<String> = ["--toggle", "--json"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    assert!(forwarded_args(&args).expect("parse").is_empty());
}

/// A typo'd value has to fail where the user can see it, not inside a detached
/// child whose stderr is /dev/null.
#[test]
fn a_missing_value_is_an_error_rather_than_a_silent_drop() {
    let args: Vec<String> = ["--enable", "--interval"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    let err = forwarded_args(&args).expect_err("no value");
    assert!(err.to_string().contains("--interval"), "{err}");
}
