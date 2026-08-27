use std::path::PathBuf;

use redact::config::Config;
use redact::model::PaneRef;

fn pane(workspace_id: &str, workspace_label: &str, cwd: &str) -> PaneRef {
    PaneRef {
        pane_id: "w1:p1".to_string(),
        workspace_id: workspace_id.to_string(),
        tab_id: "w1:t1".to_string(),
        workspace_label: workspace_label.to_string(),
        agent: Some("claude".to_string()),
        title: None,
        cwd: Some(PathBuf::from(cwd)),
    }
}

fn names(config: &Config) -> Vec<&str> {
    config
        .patterns
        .iter()
        .map(|pattern| pattern.name.as_str())
        .collect()
}

#[test]
fn matches_workspace_id() {
    let config = Config::from_json(
        r#"{
            "lines": 400,
            "overlays": [{
                "match": {"workspace_id": "company-id"},
                "lines": 900
            }]
        }"#,
    )
    .expect("config");

    assert_eq!(
        config
            .effective_for(&pane("company-id", "Company", "/work/company"))
            .lines,
        900
    );
}

#[test]
fn matches_workspace_label() {
    let config = Config::from_json(
        r#"{
            "notify": true,
            "overlays": [{
                "match": {"workspace_label": "Company"},
                "notify": false
            }]
        }"#,
    )
    .expect("config");

    assert!(
        !config
            .effective_for(&pane("w7", "Company", "/work/company"))
            .notify
    );
}

#[test]
fn matches_working_directory_path_prefix_by_component() {
    let config = Config::from_json(
        r#"{
            "lines": 400,
            "overlays": [{
                "match": {"path_prefix": "/work/company"},
                "lines": 700
            }]
        }"#,
    )
    .expect("config");

    assert_eq!(
        config
            .effective_for(&pane("w7", "Company", "/work/company/service"))
            .lines,
        700
    );
    assert_eq!(
        config
            .effective_for(&pane("w8", "Personal", "/work/company-name-collision"))
            .lines,
        400,
        "path matching must not confuse a textual prefix with a path component"
    );
}

#[test]
fn first_matching_value_wins_for_each_scalar() {
    let config = Config::from_json(
        r#"{
            "lines": 400,
            "notify": true,
            "overlays": [
                {
                    "match": {"workspace_id": "w1"},
                    "lines": 600
                },
                {
                    "match": {"workspace_label": "Company"},
                    "lines": 800,
                    "notify": false
                }
            ]
        }"#,
    )
    .expect("config");
    let effective = config.effective_for(&pane("w1", "Company", "/work/company"));

    assert_eq!(effective.lines, 600);
    assert!(
        !effective.notify,
        "a later overlay may supply a scalar the first did not name"
    );
}

#[test]
fn scoped_backfill_and_rule_packs_follow_scalar_and_list_precedence() {
    let config = Config::from_json(
        r#"{
            "backfill_lines": 5000,
            "rule_packs": ["default"],
            "overlays": [
                {
                    "match": {"workspace_id": "w1"},
                    "backfill_lines": 50000,
                    "rule_packs": ["narrow"]
                },
                {
                    "match": {"workspace_label": "Company"},
                    "backfill_lines": 0,
                    "rule_packs": ["default"]
                }
            ]
        }"#,
    )
    .expect("config");

    let effective = config.effective_for(&pane("w1", "Company", "/work/company"));
    assert_eq!(effective.backfill_lines, 20_000);
    assert_eq!(effective.rule_packs, ["default", "narrow", "default"]);

    let zero_backfill = config.effective_for(&pane("w2", "Company", "/work/company"));
    assert_eq!(
        zero_backfill.backfill_lines, 0,
        "zero must keep disabling startup backfill in an overlay"
    );
    assert_eq!(zero_backfill.rule_packs, ["default", "default"]);
}

#[test]
fn invalid_scoped_keys_are_rejected_like_top_level_keys() {
    assert!(Config::from_json(r#"{"backfill_lines": -1}"#).is_err());
    assert!(Config::from_json(r#"{"rule_packs": ["narrow", 7]}"#).is_err());

    let config = Config::from_json(
        r#"{
            "backfill_lines": 900,
            "rule_packs": ["default"],
            "overlays": [
                {
                    "match": {"workspace_id": "w1"},
                    "backfill_lines": -1
                },
                {
                    "match": {"workspace_id": "w1"},
                    "rule_packs": ["narrow", 7]
                },
                {
                    "match": {"workspace_id": "w1"},
                    "backfill_line": 100
                }
            ]
        }"#,
    )
    .expect("malformed overlays do not invalidate the base configuration");

    assert!(config.overlays.is_empty());
    assert_eq!(config.notes.len(), 3);
    assert!(config.notes[0].contains("malformed overlay 1"));
    assert!(config.notes[1].contains("malformed overlay 2"));
    assert!(config.notes[2].contains("malformed overlay 3"));
    assert!(config.notes[2].contains("unknown field `backfill_line`"));
    let effective = config.effective_for(&pane("w1", "Company", "/work/company"));
    assert_eq!(effective.backfill_lines, 900);
    assert_eq!(effective.rule_packs, ["default"]);
}

#[test]
fn every_matching_overlay_appends_lists_in_file_order() {
    let config = Config::from_json(
        r#"{
            "allowlist": ["base"],
            "ignore_panes": ["base:pane"],
            "patterns": [{"name":"base", "regex":"base"}],
            "overlays": [
                {
                    "match": {"workspace_id": "w1"},
                    "allowlist": ["first"],
                    "ignore_panes": ["first:pane"],
                    "patterns": [{"name":"first", "regex":"first"}]
                },
                {
                    "match": {"workspace_label": "Company"},
                    "allowlist": ["second"],
                    "ignore_panes": ["second:pane"],
                    "patterns": [{"name":"second", "regex":"second"}]
                }
            ]
        }"#,
    )
    .expect("config");
    let effective = config.effective_for(&pane("w1", "Company", "/work/company"));

    assert_eq!(effective.allowlist, ["base", "first", "second"]);
    assert_eq!(
        effective.ignore_panes,
        ["base:pane", "first:pane", "second:pane"]
    );
    assert_eq!(names(&effective), ["base", "first", "second"]);
}

#[test]
fn pane_matching_no_overlay_gets_the_base_configuration() {
    let config = Config::from_json(
        r#"{
            "lines": 777,
            "allowlist": ["base"],
            "overlays": [{
                "match": {"workspace_id": "other"},
                "lines": 12,
                "allowlist": ["overlay"]
            }]
        }"#,
    )
    .expect("config");

    assert_eq!(
        config.effective_for(&pane("w1", "Personal", "/home/me/personal")),
        config.base()
    );
}

#[test]
fn shorter_and_longer_prefixes_both_append_in_declared_order() {
    let config = Config::from_json(
        r#"{
            "overlays": [
                {
                    "match": {"path_prefix": "/work"},
                    "patterns": [{"name":"short", "regex":"short"}]
                },
                {
                    "match": {"path_prefix": "/work/company/project"},
                    "patterns": [{"name":"long", "regex":"long"}]
                }
            ]
        }"#,
    )
    .expect("config");

    let effective =
        config.effective_for(&pane("w1", "Company", "/work/company/project/subdirectory"));
    assert_eq!(names(&effective), ["short", "long"]);
}

#[test]
fn malformed_overlay_is_a_note_and_does_not_discard_base_config() {
    let config = Config::from_json(
        r#"{
            "lines": 733,
            "allowlist": ["base-only"],
            "overlays": [{
                "match": {
                    "workspace_id": "w1",
                    "path_prefix": "/work/company"
                },
                "lines": 1,
                "allowlist": ["must-not-apply"]
            }]
        }"#,
    )
    .expect("a malformed overlay is not a malformed base configuration");

    assert!(config.overlays.is_empty());
    assert_eq!(config.notes.len(), 1);
    assert!(config.notes[0].contains("malformed overlay 1"));
    let effective = config.effective_for(&pane("w1", "Company", "/work/company"));
    assert_eq!(effective.lines, 733);
    assert_eq!(effective.allowlist, ["base-only"]);
}

#[test]
fn malformed_overlay_list_is_a_note_and_preserves_base_config() {
    let config = Config::from_json(
        r#"{
            "lines": 812,
            "overlays": {"match": {"workspace_id": "w1"}, "lines": 1}
        }"#,
    )
    .expect("base config");

    assert_eq!(config.lines, 812);
    assert!(config.overlays.is_empty());
    assert!(config
        .notes
        .iter()
        .any(|note| note.contains("expected a list")));
}

#[test]
fn an_empty_path_prefix_is_a_note_and_matches_nothing() {
    // `Path::new("/anywhere").starts_with("")` is true, so honouring this
    // matcher would apply the overlay to every pane in the session with
    // nothing on screen to say so.
    let config = Config::from_json(
        r#"{
            "lines": 640,
            "notify": true,
            "allowlist": ["base-only"],
            "overlays": [{
                "match": {"path_prefix": "   "},
                "lines": 1,
                "notify": false,
                "allowlist": ["must-not-apply"]
            }]
        }"#,
    )
    .expect("an empty prefix is not a malformed base configuration");

    assert!(config.overlays.is_empty());
    assert_eq!(config.notes.len(), 1);
    assert!(config.notes[0].contains("malformed overlay 1"));
    assert!(
        config.notes[0].contains("path_prefix"),
        "the note has to name the reason: {}",
        config.notes[0]
    );

    for pane in [
        pane("w1", "Company", "/work/company"),
        pane("w2", "Personal", "/home/me"),
        pane("w3", "Empty", ""),
    ] {
        let effective = config.effective_for(&pane);
        assert_eq!(
            effective,
            config.base(),
            "workspace {} was overlaid",
            pane.workspace_id
        );
        assert_eq!(effective.lines, 640);
        assert!(effective.notify);
        assert_eq!(effective.allowlist, ["base-only"]);
    }
}
