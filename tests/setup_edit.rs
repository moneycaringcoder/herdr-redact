//! The `config.toml` splice.
//!
//! This is the one place the plugin writes to a file it does not own, so the
//! tests are about damage rather than about features: the edit is additive, it
//! lands *inside* a row rather than beside one, it is idempotent, and it leaves
//! a file herdr can still parse.
//!
//! The "beside a row" case is the one that matters. `rows` is an array of
//! arrays, and each inner array is one rendered line. A bare table dropped
//! between two rows is still valid TOML, so herdr accepts the file and then
//! renders nothing at all — an invisible failure that shipped past a passing
//! suite once already in the sibling plugin this one is modelled on.
//!
//! Nothing here touches the user's real `config.toml`: `plan_edit` is pure, and
//! the fixtures below are strings.

use redact::model::Alert;
use redact::setup::plan_edit;

/// A config with both sidebars laid out the way herdr's own examples do, plus a
/// third-party plugin's tokens already present — which is the realistic case,
/// and the one where an insert can most easily land in the wrong array.
const REALISTIC: &str = r##"[theme]
name = "vesper"
auto_switch = false

[ui.toast]
delivery = "herdr"

[ui.sidebar.agents]
row_gap = 0
rows = [
  ["state_icon", "agent", "$title"],
  ["$provider", "$limit"],
  ["$context"],
]

[ui.sidebar.spaces]
rows = [
  ["state_icon", "workspace"],
  ["branch", "git_status",
    { token = "$git_clean", fg = "#99FFE4" },
    { token = "$git_dirty", fg = "#FFC799" },
    { token = "$git_conflict", fg = "#FF8080" }],
]

[[keys.command]]
key = "prefix+f"
type = "plugin_action"
command = "someone.else.toggle"
"##;

/// Every row on one line, which takes the single-line splice branch.
const SINGLE_LINE_ROWS: &str = r##"[ui.sidebar.spaces]
rows = [["state_icon", "workspace"], ["branch", "git_status"]]

[ui.sidebar.agents]
rows = [["state_icon", "agent"]]
"##;

const NO_SIDEBAR: &str = r##"[theme]
name = "vesper"
"##;

fn tokens_in(text: &str) -> Vec<&'static str> {
    Alert::CONFIGURED_TOKENS
        .into_iter()
        .filter(|token| text.contains(&format!("\"${token}\"")))
        .collect()
}

/// Byte ranges of every **row** in every `rows = [...]` array in the file,
/// tagged with the table header they sit under.
///
/// Deliberately an independent re-implementation rather than a call into
/// `setup.rs`: a test that asks the code under test where it put something can
/// only ever agree with it.
fn rows_of(text: &str) -> Vec<(String, std::ops::Range<usize>)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut header = String::new();
    let mut offset = 0usize;

    for line in text.split_inclusive('\n') {
        let here = offset;
        offset += line.len();
        let trimmed = line.trim_start();

        // A table header, as opposed to a row line, which also starts with `[`.
        let after = trimmed.trim_start_matches('[');
        if trimmed.starts_with('[')
            && after
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        {
            header = trimmed.trim_end().to_string();
            continue;
        }
        if !(trimmed.starts_with("rows") && line.contains('[')) {
            continue;
        }

        // Walk the array from its opening bracket, recording each row.
        let open = here + line.find('[').expect("checked above");
        let mut depth = 1usize;
        let mut in_string = false;
        let mut row_open = None;
        let mut cursor = open + 1;
        while cursor < bytes.len() {
            let ch = bytes[cursor] as char;
            if in_string {
                if ch == '"' {
                    in_string = false;
                }
            } else {
                match ch {
                    '"' => in_string = true,
                    '[' => {
                        depth += 1;
                        if depth == 2 {
                            row_open = Some(cursor);
                        }
                    }
                    ']' => {
                        if depth == 2 {
                            if let Some(start) = row_open.take() {
                                out.push((header.clone(), start..cursor + 1));
                            }
                        }
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            cursor += 1;
        }
    }
    out
}

/// Every byte offset at which a redact token entry appears.
fn token_positions(text: &str) -> Vec<usize> {
    text.match_indices("$redact_").map(|(at, _)| at).collect()
}

/// The table header of the row containing `offset`, or `None` if it is not
/// inside a row at all — which is the failure that renders nothing.
fn row_containing(text: &str, offset: usize) -> Option<String> {
    rows_of(text)
        .into_iter()
        .find(|(_, range)| range.contains(&offset))
        .map(|(header, _)| header)
}

#[test]
fn both_sidebars_gain_the_tokens() {
    let updated = plan_edit(REALISTIC).expect("a config with both sidebars must be edited");

    for token in Alert::CONFIGURED_TOKENS {
        let needle = format!("\"${token}\"");
        assert_eq!(
            updated.matches(&needle).count(),
            2,
            "{token} should appear once in each sidebar:\n{updated}"
        );
    }
}

#[test]
fn every_entry_lands_inside_a_row_not_beside_one() {
    for source in [REALISTIC, SINGLE_LINE_ROWS] {
        let updated = plan_edit(source).expect("edited");
        let positions = token_positions(&updated);
        assert!(!positions.is_empty(), "nothing was inserted:\n{updated}");
        for at in positions {
            assert!(
                row_containing(&updated, at).is_some(),
                "an entry at byte {at} landed outside every row — herdr would \
                 accept this file and render nothing:\n{updated}"
            );
        }
    }
}

#[test]
fn the_tokens_land_in_both_sidebar_sections() {
    let updated = plan_edit(REALISTIC).expect("edited");

    let headers: Vec<String> = token_positions(&updated)
        .into_iter()
        .filter_map(|at| row_containing(&updated, at))
        .collect();

    assert!(
        headers.iter().any(|h| h == "[ui.sidebar.spaces]"),
        "no entry in the spaces sidebar: {headers:?}"
    );
    assert!(
        headers.iter().any(|h| h == "[ui.sidebar.agents]"),
        "no entry in the agents sidebar: {headers:?}"
    );
}

#[test]
fn nothing_is_ever_removed() {
    let updated = plan_edit(REALISTIC).expect("edited");

    // Every non-blank line of the original survives, either verbatim or as the
    // head of a line that was extended in place.
    for line in REALISTIC.lines().filter(|l| !l.trim().is_empty()) {
        let head = line.trim_end_matches([']', ',', ' ']);
        let survived = updated
            .lines()
            .any(|candidate| candidate == line || candidate.starts_with(head));
        assert!(survived, "the edit lost a line: {line:?}");
    }
    // The third-party plugin's rows in particular.
    assert!(updated.contains("$git_clean"));
    assert!(updated.contains("$git_dirty"));
    assert!(updated.contains("$git_conflict"));
    assert!(updated.contains("someone.else.toggle"));
    // And the agent sidebar's own tokens.
    assert!(updated.contains("$provider"));
    assert!(updated.contains("$context"));
}

#[test]
fn running_it_twice_is_a_no_op() {
    let once = plan_edit(REALISTIC).expect("edited");
    assert!(
        plan_edit(&once).is_none(),
        "a second run must not insert a duplicate"
    );
}

#[test]
fn a_single_line_rows_array_is_spliced_in_place() {
    // `rows = [["a"], ["b"]]` all on one line. The trap here is splicing at the
    // last `]` on the line, which closes the rows array rather than the last row.
    let updated = plan_edit(SINGLE_LINE_ROWS).expect("edited");

    assert_eq!(tokens_in(&updated).len(), 2);
    for at in token_positions(&updated) {
        assert!(
            row_containing(&updated, at).is_some(),
            "single-line splice escaped the row it was aimed at:\n{updated}"
        );
    }
    assert!(
        plan_edit(&updated).is_none(),
        "the single-line form must also be idempotent"
    );
}

#[test]
fn a_config_with_no_sidebar_gains_a_spaces_section() {
    let updated = plan_edit(NO_SIDEBAR).expect("edited");

    assert!(updated.contains("[ui.sidebar.spaces]"));
    assert!(updated.contains("$redact_secret"));
    assert!(updated.contains("$redact_weak"));
    assert!(
        updated.starts_with("[theme]"),
        "the original content must stay at the top:\n{updated}"
    );
    // An absent agents sidebar is left alone on purpose: the user is on herdr's
    // defaults, and inventing a whole section would be a much bigger change than
    // they asked for.
    assert!(!updated.contains("[ui.sidebar.agents]"));
}

#[test]
fn a_trailing_newline_is_preserved_either_way() {
    let with = plan_edit(REALISTIC).expect("edited");
    assert!(with.ends_with('\n'), "a trailing newline was dropped");

    let without_source = REALISTIC.trim_end();
    let without = plan_edit(without_source).expect("edited");
    assert!(
        !without.ends_with('\n'),
        "a trailing newline was invented where the original had none"
    );
}

#[test]
fn an_empty_or_broken_config_never_panics() {
    // Not valid TOML, but the splice is line-oriented and must simply decline.
    for input in ["", "\n\n\n", "rows = [[[[", "[ui.sidebar.spaces]", "]]]]"] {
        let _ = plan_edit(input);
    }
}

#[test]
fn a_section_with_no_rows_array_is_left_alone() {
    let text = "[ui.sidebar.spaces]\nrow_gap = 1\n\n[ui.sidebar.agents]\nrow_gap = 0\n";
    // Neither section has a rows array to splice into, and the spaces section is
    // present, so nothing sensible can be added. Declining is correct; the
    // failure to avoid is inserting an orphan table between two rows.
    if let Some(updated) = plan_edit(text) {
        for at in token_positions(&updated) {
            assert!(
                row_containing(&updated, at).is_some(),
                "orphan entry outside any row:\n{updated}"
            );
        }
    }
}

/// The tokens the setup action writes have to be the tokens the daemon sets,
/// and both have to satisfy herdr's `^[A-Za-z0-9_-]{1,32}$` with **no `$`** on
/// the wire — the `$` belongs only to the config.toml row syntax.
#[test]
fn the_configured_tokens_are_wire_legal_and_match_the_alert_names() {
    for token in Alert::ALL_TOKENS {
        assert!(!token.starts_with('$'), "{token} carries a config-only `$`");
        assert!(
            !token.is_empty() && token.len() <= 32,
            "{token} is too long"
        );
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "{token} is not wire-legal"
        );
    }
    for token in Alert::CONFIGURED_TOKENS {
        assert!(
            Alert::ALL_TOKENS.contains(&token),
            "{token} is configured but never swept"
        );
    }
}

/// The review found this one: a config with no `[ui.sidebar.agents]` section got
/// the workspace tokens, a success message, and no pane badge — and the pane
/// badge is the primary surface, because a finding belongs to a pane.
///
/// The splice still declines to invent that section, because writing agent rows
/// would change how every agent row looks and we do not know what herdr's
/// defaults are. What it must not do is stay quiet about it.
#[test]
fn a_config_with_no_agents_sidebar_reports_the_section_it_could_not_configure() {
    let text = "[ui.sidebar.spaces]\nrows = [\n  [\"state_icon\", \"workspace\"],\n]\n";
    let edit = redact::setup::plan(text).expect("edited");

    assert_eq!(edit.configured, vec!["[ui.sidebar.spaces]"]);
    assert_eq!(
        edit.missing,
        vec!["[ui.sidebar.agents]"],
        "the section that could not be configured has to be reported, not swallowed"
    );
    assert!(!edit.text.contains("[ui.sidebar.agents]"));

    // And the snippet handed to the user has to be something they can paste:
    // both tokens, inside a row, in that section.
    let snippet = redact::setup::manual_snippet("[ui.sidebar.agents]");
    assert!(snippet.contains("[ui.sidebar.agents]"));
    for token in Alert::CONFIGURED_TOKENS {
        assert!(
            snippet.contains(&format!("\"${token}\"")),
            "{token} missing"
        );
    }
    for at in token_positions(&snippet) {
        assert!(
            row_containing(&snippet, at).is_some(),
            "the snippet puts an entry outside every row:\n{snippet}"
        );
    }
}

#[test]
fn a_config_with_both_sidebars_reports_nothing_missing() {
    let edit = redact::setup::plan(REALISTIC).expect("edited");
    assert_eq!(edit.configured.len(), 2);
    assert!(
        edit.missing.is_empty(),
        "nothing should be missing: {:?}",
        edit.missing
    );
}
