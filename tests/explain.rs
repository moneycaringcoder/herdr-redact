use std::collections::{BTreeMap, BTreeSet};

use redact::model::Confidence;
use redact::scan::Rules;

#[test]
fn every_builtin_rule_has_an_explanation() {
    let explanations = Rules::builtin().explanations();
    let mut seen = BTreeMap::new();

    for explanation in explanations {
        assert!(
            !explanation.text.trim().is_empty(),
            "rule `{}` has an empty explanation",
            explanation.name
        );
        assert!(
            !explanation.text.contains("http://") && !explanation.text.contains("https://"),
            "rule `{}` has a URL in its explanation",
            explanation.name
        );
        if let Some(other) = seen.insert(explanation.text.clone(), explanation.name.clone()) {
            panic!(
                "rules `{other}` and `{}` have duplicate explanations",
                explanation.name
            );
        }
    }
}

#[test]
fn explain_and_rules_agree_on_the_name_set() {
    let rules = Rules::builtin();
    let explained: BTreeSet<_> = rules
        .explanations()
        .into_iter()
        .map(|explanation| explanation.name)
        .collect();
    let listed: BTreeSet<_> = rules.names.iter().map(|(name, _)| name.clone()).collect();

    assert_eq!(explained, listed);
}

#[test]
fn the_readme_rule_table_matches_the_code() {
    let readme = readme_rules();
    let code: BTreeMap<String, Confidence> = Rules::builtin()
        .explanations()
        .into_iter()
        .map(|explanation| (explanation.name, explanation.confidence))
        .collect();

    for name in code.keys() {
        assert!(
            readme.contains_key(name),
            "rule `{name}` is present in code but missing from the README rule table"
        );
    }
    for name in readme.keys() {
        assert!(
            code.contains_key(name),
            "rule `{name}` is present in the README rule table but missing from code"
        );
    }
    for (name, confidence) in &code {
        let readme_confidence = &readme[name];
        assert_eq!(
            readme_confidence,
            confidence.as_str(),
            "rule `{name}` has confidence `{readme_confidence}` in the README but `{}` in code",
            confidence.as_str()
        );
    }
}

fn readme_rules() -> BTreeMap<String, String> {
    let mut lines = include_str!("../README.md").lines();
    let header = "| Rule | Catches | Confidence |";
    lines
        .find(|line| line.trim() == header)
        .unwrap_or_else(|| panic!("README rule table header `{header}` is missing"));
    let separator = lines
        .next()
        .unwrap_or_else(|| panic!("README rule table has no separator row"));
    assert_eq!(separator.trim(), "| --- | --- | --- |");

    let mut rules = BTreeMap::new();
    for line in lines {
        let line = line.trim();
        if !line.starts_with("| `") {
            break;
        }
        let columns: Vec<_> = line.trim_matches('|').split('|').map(str::trim).collect();
        assert_eq!(columns.len(), 3, "malformed README rule row: {line}");
        let name = columns[0]
            .strip_prefix('`')
            .and_then(|name| name.strip_suffix('`'))
            .unwrap_or_else(|| panic!("README rule name is not wrapped in backticks: {line}"));
        assert!(
            rules
                .insert(name.to_string(), columns[2].to_string())
                .is_none(),
            "README rule table contains `{name}` more than once"
        );
    }
    rules
}
