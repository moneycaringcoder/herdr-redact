use redact::config::{Config, CustomPattern};
use redact::model::Confidence;
use redact::scan::{
    rule_aliases, rule_packs, Resolved, Rules, DEFAULT_RULE_PACK, NARROW_RULE_PACK,
};

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
    ("grafana_service_account_token", Confidence::Strong),
    ("huggingface_token", Confidence::Strong),
    ("supabase_access_token", Confidence::Strong),
    ("sentry_auth_token", Confidence::Strong),
    ("age_secret_key", Confidence::Strong),
    ("jdbc_url_password", Confidence::Strong),
    ("docker_registry_auth", Confidence::Strong),
    ("vault_token", Confidence::Strong),
    ("url_credentials", Confidence::Weak),
    ("http_bearer_token", Confidence::Weak),
    ("env_assignment", Confidence::Weak),
    ("multiline_credential", Confidence::Weak),
];

const RULE_RENAMES: &[(&str, &str)] = &[];

fn custom_pattern(name: &str, former_names: &[&str]) -> CustomPattern {
    CustomPattern {
        name: name.to_string(),
        former_names: former_names
            .iter()
            .map(|former| former.to_string())
            .collect(),
        regex: r"ALIAS-[0-9]+".to_string(),
        label: None,
        strong: true,
    }
}

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

#[test]
fn rule_rename_ledger_is_golden_and_unambiguous() {
    let aliases: Vec<_> = rule_aliases()
        .iter()
        .map(|alias| (alias.former, alias.current))
        .collect();
    assert_eq!(aliases, RULE_RENAMES);

    let rules = Rules::builtin();
    for alias in rule_aliases() {
        assert!(
            rules.names.iter().any(|(name, _)| name == alias.current),
            "retired rule `{}` resolves to inactive rule `{}`",
            alias.former,
            alias.current
        );
        assert!(
            rules.names.iter().all(|(name, _)| name != alias.former),
            "retired rule `{}` collides with an active rule",
            alias.former
        );
    }
}

#[test]
fn default_rule_sets_have_no_aliases_today() {
    assert!(Rules::builtin().aliases.is_empty());
    assert!(Rules::compile(&Config::default())
        .expect("default rules compile")
        .aliases
        .is_empty());
}

#[test]
fn a_custom_patterns_former_name_resolves_to_its_active_name() {
    let current = "acme_token";
    let config = Config {
        patterns: vec![custom_pattern(current, &["old"])],
        ..Config::default()
    };
    let rules = Rules::compile(&config).expect("custom alias compiles");

    assert_eq!(
        rules.resolve("old"),
        Some(Resolved {
            name: current.to_string(),
            former: Some("old".to_string()),
        })
    );
    assert_eq!(
        rules.resolve(current),
        Some(Resolved {
            name: current.to_string(),
            former: None,
        })
    );
    assert_eq!(rules.resolve("never-a-rule"), None);
    let resolved = rules.resolve("old").expect("former name resolves");
    assert!(rules.explanation(&resolved.name).is_some());
    assert_eq!(
        rules.rotation_guidance("old"),
        rules.rotation_guidance(current)
    );
}

#[test]
fn a_custom_pattern_can_declare_two_former_names() {
    let config = Config {
        patterns: vec![custom_pattern("acme_token", &["old", "older"])],
        ..Config::default()
    };
    let rules = Rules::compile(&config).expect("both former names compile");

    assert_eq!(
        rules
            .resolve("old")
            .expect("first former name resolves")
            .name,
        "acme_token"
    );
    assert_eq!(
        rules
            .resolve("older")
            .expect("second former name resolves")
            .name,
        "acme_token"
    );
}

#[test]
fn an_empty_former_name_is_rejected() {
    let config = Config {
        patterns: vec![custom_pattern("acme_token", &["  "])],
        ..Config::default()
    };
    let error = Rules::compile(&config)
        .expect_err("blank former name must fail")
        .to_string();

    assert!(error.contains("pattern `acme_token` has an empty former name"));
}

#[test]
fn a_former_name_that_is_active_is_rejected() {
    let config = Config {
        patterns: vec![
            custom_pattern("acme_token", &["later_rule"]),
            custom_pattern("later_rule", &[]),
        ],
        ..Config::default()
    };
    let error = Rules::compile(&config)
        .expect_err("active former name must fail")
        .to_string();

    assert!(error.contains("pattern `acme_token`"));
    assert!(error.contains("former name `later_rule`"));
    assert!(error.contains("active rule name"));
}

#[test]
fn a_former_name_claimed_twice_is_rejected() {
    let config = Config {
        patterns: vec![
            custom_pattern("first_rule", &["shared_old_name"]),
            custom_pattern("second_rule", &["shared_old_name"]),
        ],
        ..Config::default()
    };
    let error = Rules::compile(&config)
        .expect_err("duplicate former name must fail")
        .to_string();

    assert!(error.contains("former name `shared_old_name`"));
    assert!(error.contains("`first_rule`"));
    assert!(error.contains("`second_rule`"));
}
