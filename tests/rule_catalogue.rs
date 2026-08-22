//! The public rule catalogue is generated from the compiled rule set because a
//! hand-written catalogue that goes stale would make a false claim about what
//! redact detects. Regenerate it with
//! `REDACT_WRITE_RULE_CATALOGUE=1 cargo test --test rule_catalogue`.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::{env, fs};

use redact::config::Config;
use redact::model::Confidence;
use redact::scan::{self, rule_packs, RotationGuidance, Rules};

const REGENERATION_COMMAND: &str = "REDACT_WRITE_RULE_CATALOGUE=1 cargo test --test rule_catalogue";
const WRITE_ENV: &str = "REDACT_WRITE_RULE_CATALOGUE";

fn catalogue_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/rules.md")
}

fn all_compiled_rules() -> Rules {
    let config = Config {
        // Enumerating the public pack registry makes a newly shipped pack enter
        // the catalogue automatically instead of silently disappearing from it.
        rule_packs: rule_packs()
            .iter()
            .map(|pack| pack.name.to_string())
            .collect(),
        ..Config::default()
    };
    Rules::compile(&config).expect("all compiled-in rule packs should compile")
}

fn render_catalogue(rules: &Rules) -> String {
    assert_eq!(
        rules.names.len(),
        rules.packs.len(),
        "rule names and pack metadata must stay aligned"
    );

    let explanations = rules.explanations();
    let mut output = String::new();
    writeln!(
        output,
        "> **Generated file — detection rule catalogue.** This file is generated from the compiled rule set by `tests/rule_catalogue.rs`.\n> Regenerate it with `{REGENERATION_COMMAND}`. Editing it by hand is pointless because that test compares the committed file byte-for-byte with a fresh rendering.\n"
    )
    .expect("writing Markdown into a String should succeed");
    output.push_str("# Detection rule catalogue\n\n");
    output.push_str(
        "Strong confidence means the format is structurally identifiable; weak confidence means the match is a hint. Every rule is listed with what it rejects as well as what it matches.\n\n",
    );
    output.push_str("## Summary\n\n");
    output.push_str("| Rule | Label | Confidence | Pack | Version |\n");
    output.push_str("| --- | --- | --- | --- | ---: |\n");

    for ((name, confidence), pack) in rules.names.iter().zip(&rules.packs) {
        let pack = pack.expect("catalogue rules must all belong to a compiled-in pack");
        let explanation = explanations
            .iter()
            .find(|explanation| explanation.name == *name)
            .expect("every compiled-in rule should carry an explanation");
        writeln!(
            output,
            "| `{name}` | {} | {} | `{}` | {} |",
            explanation.label,
            confidence.as_str(),
            pack.name,
            pack.version
        )
        .expect("writing Markdown into a String should succeed");
    }

    output.push_str(
        "\nCustom patterns are not listed because this catalogue is generated from compiled-in rules only.\n\n",
    );

    for ((name, confidence), pack) in rules.names.iter().zip(&rules.packs) {
        let pack = pack.expect("catalogue rules must all belong to a compiled-in pack");
        let explanation = explanations
            .iter()
            .find(|explanation| explanation.name == *name)
            .expect("every compiled-in rule should carry an explanation");
        writeln!(output, "## `{name}`\n").expect("writing Markdown into a String should succeed");
        writeln!(output, "- **Label:** {}", explanation.label)
            .expect("writing Markdown into a String should succeed");
        writeln!(output, "- **Confidence:** {}", confidence.as_str())
            .expect("writing Markdown into a String should succeed");
        writeln!(
            output,
            "- **Pack:** `{}` version {}",
            pack.name, pack.version
        )
        .expect("writing Markdown into a String should succeed");
        match explanation.rotation {
            RotationGuidance::Url(url) => writeln!(output, "- **Rotation guidance:** {url}"),
            RotationGuidance::Exempt(reason) => writeln!(
                output,
                "- **Rotation guidance:** no provider page — {reason}"
            ),
        }
        .expect("writing Markdown into a String should succeed");

        let former_names: Vec<_> = rules
            .aliases
            .iter()
            .filter(|(_, current)| current == name)
            .map(|(former, _)| format!("`{former}`"))
            .collect();
        if !former_names.is_empty() {
            writeln!(output, "- **Former names:** {}", former_names.join(", "))
                .expect("writing Markdown into a String should succeed");
        }
        writeln!(output, "\n{}\n", explanation.text)
            .expect("writing Markdown into a String should succeed");
    }

    output
}

fn committed_catalogue() -> String {
    fs::read_to_string(catalogue_path()).expect("the committed rule catalogue should be readable")
}

fn matching_line(catalogue: &str, line: usize) -> &str {
    catalogue
        .lines()
        .nth(line.saturating_sub(1))
        .unwrap_or("<line unavailable>")
}

#[test]
fn the_committed_catalogue_matches_the_compiled_rules() {
    let rendered = render_catalogue(&all_compiled_rules());
    let path = catalogue_path();

    if env::var(WRITE_ENV).as_deref() == Ok("1") {
        fs::write(&path, rendered).expect("the generated rule catalogue should be writable");
        return;
    }

    let committed =
        fs::read_to_string(path).expect("the committed rule catalogue should be readable");
    assert_eq!(
        committed, rendered,
        "docs/rules.md does not match the compiled rules; regenerate it with `{REGENERATION_COMMAND}`"
    );
}

#[test]
fn every_compiled_rule_appears_in_the_catalogue() {
    let rules = all_compiled_rules();
    let catalogue = committed_catalogue();
    let active: BTreeSet<_> = rules.names.iter().map(|(name, _)| name.as_str()).collect();
    let headings: Vec<_> = catalogue
        .lines()
        .filter_map(|line| {
            let heading = line.strip_prefix("## ")?;
            if heading == "Summary" {
                return None;
            }
            Some(
                heading
                    .strip_prefix('`')
                    .and_then(|name| name.strip_suffix('`'))
                    .unwrap_or(heading),
            )
        })
        .collect();

    for name in &active {
        assert!(
            headings.contains(name),
            "active rule `{name}` has no catalogue section"
        );
    }
    for heading in &headings {
        assert!(
            active.contains(heading),
            "catalogue section `{heading}` is not an active compiled rule"
        );
    }
    assert_eq!(
        headings.len(),
        active.len(),
        "each active rule should have exactly one catalogue section"
    );
}

#[test]
fn the_catalogue_carries_no_credential_shaped_value() {
    let catalogue = committed_catalogue();
    let matches = scan::scan(&catalogue, &Rules::builtin(), &[0_u8; 16]);
    let strong: Vec<_> = matches
        .iter()
        .filter(|found| found.confidence == Confidence::Strong)
        .collect();

    // Weak matches are allowed hints in explanatory prose, but surfacing the
    // exact rule and source line keeps that trade-off visible rather than
    // quietly redefining what this safety check promises.
    for found in matches
        .iter()
        .filter(|found| found.confidence == Confidence::Weak)
    {
        eprintln!(
            "weak rule `{}` fired on line {}: {:?}",
            found.pattern,
            found.line,
            matching_line(&catalogue, found.line)
        );
    }

    let mut details = String::new();
    for found in &strong {
        writeln!(
            details,
            "strong rule `{}` fired on line {}: {:?}",
            found.pattern,
            found.line,
            matching_line(&catalogue, found.line)
        )
        .expect("writing diagnostic text into a String should succeed");
    }
    assert!(
        strong.is_empty(),
        "the catalogue contains a strong credential-shaped value:\n{details}"
    );
}

#[test]
fn the_render_is_stable() {
    let rules = all_compiled_rules();
    assert_eq!(render_catalogue(&rules), render_catalogue(&rules));
}
