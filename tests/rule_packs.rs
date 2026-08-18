use redact::config::Config;
use redact::model::Confidence;
use redact::scan::{rule_packs, Rules, DEFAULT_RULE_PACK, NARROW_RULE_PACK};

const DEFAULT_RULES: &[(&str, Confidence)] = &[
    ("aws_access_key_id", Confidence::Strong),
    ("aws_principal_id", Confidence::Weak),
    ("aws_secret_access_key", Confidence::Strong),
    ("github_token", Confidence::Strong),
    ("github_pat", Confidence::Strong),
    ("anthropic_api_key", Confidence::Strong),
    ("openai_api_key", Confidence::Strong),
    ("stripe_secret_key", Confidence::Strong),
    ("slack_token", Confidence::Strong),
    ("google_api_key", Confidence::Strong),
    ("google_oauth_client_secret", Confidence::Strong),
    ("jwt", Confidence::Strong),
    ("private_key_block", Confidence::Strong),
    ("slack_webhook_url", Confidence::Strong),
    ("npm_token", Confidence::Strong),
    ("pypi_token", Confidence::Strong),
    ("sendgrid_api_key", Confidence::Strong),
    ("gitlab_pat", Confidence::Strong),
    ("huggingface_token", Confidence::Strong),
    ("age_secret_key", Confidence::Strong),
    ("jdbc_url_password", Confidence::Strong),
    ("docker_registry_auth", Confidence::Strong),
    ("vault_token", Confidence::Strong),
    ("url_credentials", Confidence::Weak),
    ("http_bearer_token", Confidence::Weak),
    ("env_assignment", Confidence::Weak),
    ("multiline_credential", Confidence::Weak),
];

fn compiled_names(rules: &Rules) -> Vec<(&str, Confidence)> {
    rules
        .names
        .iter()
        .map(|(name, confidence)| (name.as_str(), *confidence))
        .collect()
}

#[test]
fn default_rule_set_is_golden() {
    let config = Config::default();
    assert_eq!(config.rule_packs, ["default"]);
    let rules = Rules::compile(&config).expect("default rules compile");

    assert_eq!(compiled_names(&rules), DEFAULT_RULES);
    assert!(rules
        .packs
        .iter()
        .all(|pack| *pack == Some(DEFAULT_RULE_PACK)));
}

#[test]
fn enabling_a_pack_adds_exactly_that_packs_rules() {
    assert_eq!(rule_packs(), &[DEFAULT_RULE_PACK, NARROW_RULE_PACK]);

    let baseline = Rules::compile(&Config::default()).expect("default rules compile");
    let config = Config {
        // Packs are additive, so omitting `default` here cannot turn it off.
        rule_packs: vec![NARROW_RULE_PACK.name.to_string()],
        ..Config::default()
    };
    let extended = Rules::compile(&config).expect("narrow rules compile");
    let added: Vec<_> = extended
        .names
        .iter()
        .filter(|(name, _)| !baseline.names.iter().any(|(base, _)| base == name))
        .map(|(name, _)| name.as_str())
        .collect();
    let narrow_rules: Vec<_> = extended
        .names
        .iter()
        .zip(&extended.packs)
        .filter(|(_, pack)| **pack == Some(NARROW_RULE_PACK))
        .map(|((name, _), _)| name.as_str())
        .collect();

    // `narrow` v1 is deliberately empty: no existing default rule was demoted
    // merely to populate the new mechanism.
    assert_eq!(added, narrow_rules);
    assert!(added.is_empty());
    assert_eq!(extended.names, baseline.names);
}

#[test]
fn unknown_pack_is_noted_without_disabling_default_rules() {
    let baseline = Rules::compile(&Config::default()).expect("default rules compile");
    let config = Config {
        rule_packs: vec!["not-a-pack".to_string()],
        ..Config::default()
    };
    let rules = Rules::compile(&config).expect("unknown packs are not fatal");

    assert_eq!(rules.names, baseline.names);
    assert_eq!(rules.notes.len(), 1);
    assert!(rules.notes[0].contains("not-a-pack"));
    assert!(rules.notes[0].contains("default"));
}

#[test]
fn empty_pack_list_means_default_only() {
    let baseline = Rules::compile(&Config::default()).expect("default rules compile");
    let config = Config {
        // An empty additive list is the safe identity: it adds no optional
        // packs, while the invariant default pack remains active.
        rule_packs: Vec::new(),
        ..Config::default()
    };
    let rules = Rules::compile(&config).expect("empty pack list compiles");

    assert_eq!(rules.names, baseline.names);
    assert!(!rules.names.is_empty());
    assert!(rules.notes.is_empty());
}
