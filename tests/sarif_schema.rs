//! Snapshot tests can pin the shape of SARIF output, but they cannot prove that
//! a conforming SARIF consumer can read it. The oracle here is the vendored
//! SARIF 2.1.0 schema, read entirely offline. It is hand-written because the
//! smallest schema crate would add 45 packages, including the ICU stack, for a
//! test-only oracle. Before validating anything, it audits every schema node:
//! an unknown keyword or unsupported keyword shape panics with its schema JSON
//! pointer, so this deliberately small draft-07 subset can never under-validate
//! silently.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::LazyLock;

use redact::model::{Confidence, Finding, Report};
use redact::render::{report_sarif, report_sarif_with_quiet};
use regex::Regex;
use serde_json::{json, Map, Value};

const SARIF_SCHEMA_URL: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const NOW: u64 = 1_700_000_000;

const IMPLEMENTED_KEYWORDS: &[&str] = &[
    "$ref",
    "additionalProperties",
    "anyOf",
    "enum",
    "items",
    "maximum",
    "minimum",
    "minItems",
    "oneOf",
    "pattern",
    "properties",
    "required",
    "type",
    "uniqueItems",
];

// These annotations cannot change whether an instance is valid. `description`
// and `title` are prose, `default` is only a consumer hint, `$schema` and `$id`
// identify schema documents, and `definitions` only stores schemas (which the
// audit still visits). Draft-07 also defines `format` as an annotation unless a
// validator opts into assertion; hand-asserting URI and date-time syntax would
// merely create a second, weaker oracle.
const ANNOTATION_KEYWORDS: &[&str] = &[
    "$id",
    "$schema",
    "default",
    "definitions",
    "description",
    "format",
    "title",
];

struct SarifValidator {
    schema: Value,
    patterns: BTreeMap<String, Regex>,
}

impl SarifValidator {
    fn new(schema: Value) -> Self {
        let mut patterns = BTreeMap::new();
        let mut audited = BTreeSet::new();
        audit_schema(&schema, &schema, "", &mut patterns, &mut audited);
        Self { schema, patterns }
    }

    fn validate(&self, instance: &Value) -> Result<(), String> {
        let mut errors = Vec::new();
        self.validate_schema(&self.schema, instance, "", "", &mut errors);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("\n"))
        }
    }

    fn validate_schema(
        &self,
        schema: &Value,
        instance: &Value,
        schema_pointer: &str,
        instance_pointer: &str,
        errors: &mut Vec<String>,
    ) {
        let object = schema
            .as_object()
            .expect("the schema audit should have rejected a non-object schema");

        // Draft-07 says a `$ref` object is replaced by its target; siblings do
        // not add constraints. The audit still inspects those siblings so an
        // unsupported keyword cannot hide beside a reference.
        if let Some(reference) = object.get("$ref") {
            let reference = reference
                .as_str()
                .expect("the schema audit should have rejected a non-string `$ref`");
            let target = resolve_reference(&self.schema, reference, schema_pointer);
            self.validate_schema(
                target,
                instance,
                reference
                    .strip_prefix('#')
                    .expect("the schema audit should have rejected an external `$ref`"),
                instance_pointer,
                errors,
            );
            return;
        }

        if let Some(expected_type) = object.get("type") {
            let expected_type = expected_type
                .as_str()
                .expect("the schema audit should have rejected a non-string `type`");
            if !matches_type(instance, expected_type) {
                errors.push(instance_error(
                    instance_pointer,
                    format!("expected type `{expected_type}`"),
                ));
                return;
            }
        }

        if let Some(instance_object) = instance.as_object() {
            self.validate_object_keywords(
                object,
                instance_object,
                schema_pointer,
                instance_pointer,
                errors,
            );
        }

        if let Some(instance_array) = instance.as_array() {
            self.validate_array_keywords(
                object,
                instance_array,
                schema_pointer,
                instance_pointer,
                errors,
            );
        }

        if let Some(instance_number) = instance.as_number().and_then(serde_json::Number::as_f64) {
            if let Some(minimum) = object.get("minimum").and_then(Value::as_f64) {
                if instance_number < minimum {
                    errors.push(instance_error(
                        instance_pointer,
                        format!("expected a number greater than or equal to {minimum}"),
                    ));
                }
            }
            if let Some(maximum) = object.get("maximum").and_then(Value::as_f64) {
                if instance_number > maximum {
                    errors.push(instance_error(
                        instance_pointer,
                        format!("expected a number less than or equal to {maximum}"),
                    ));
                }
            }
        }

        if let Some(instance_string) = instance.as_str() {
            if object.contains_key("pattern") {
                let pattern_pointer = child_pointer(schema_pointer, "pattern");
                let pattern = self
                    .patterns
                    .get(&pattern_pointer)
                    .expect("the schema audit should have compiled every `pattern`");
                if !pattern.is_match(instance_string) {
                    errors.push(instance_error(
                        instance_pointer,
                        "expected a string matching the schema pattern",
                    ));
                }
            }
        }

        if let Some(choices) = object.get("enum").and_then(Value::as_array) {
            if !choices.iter().any(|choice| choice == instance) {
                errors.push(instance_error(
                    instance_pointer,
                    "expected one of the schema enumeration values",
                ));
            }
        }

        self.validate_combinators(object, instance, schema_pointer, instance_pointer, errors);
    }

    fn validate_object_keywords(
        &self,
        schema: &Map<String, Value>,
        instance: &Map<String, Value>,
        schema_pointer: &str,
        instance_pointer: &str,
        errors: &mut Vec<String>,
    ) {
        let properties = schema.get("properties").and_then(Value::as_object);
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for name in required {
                let name = name
                    .as_str()
                    .expect("the schema audit should have rejected a non-string `required` entry");
                if !instance.contains_key(name) {
                    errors.push(instance_error(
                        &child_pointer(instance_pointer, name),
                        "expected a required property",
                    ));
                }
            }
        }

        if let Some(properties) = properties {
            for (name, property_schema) in properties {
                if let Some(value) = instance.get(name) {
                    self.validate_schema(
                        property_schema,
                        value,
                        &child_pointer(&child_pointer(schema_pointer, "properties"), name),
                        &child_pointer(instance_pointer, name),
                        errors,
                    );
                }
            }
        }

        if let Some(additional) = schema.get("additionalProperties") {
            for (name, value) in instance {
                if properties.is_some_and(|known| known.contains_key(name)) {
                    continue;
                }
                let pointer = child_pointer(instance_pointer, name);
                match additional {
                    Value::Bool(true) => {}
                    Value::Bool(false) => {
                        errors.push(instance_error(&pointer, "expected no additional property"))
                    }
                    additional_schema => self.validate_schema(
                        additional_schema,
                        value,
                        &child_pointer(schema_pointer, "additionalProperties"),
                        &pointer,
                        errors,
                    ),
                }
            }
        }
    }

    fn validate_array_keywords(
        &self,
        schema: &Map<String, Value>,
        instance: &[Value],
        schema_pointer: &str,
        instance_pointer: &str,
        errors: &mut Vec<String>,
    ) {
        if let Some(items) = schema.get("items") {
            for (index, value) in instance.iter().enumerate() {
                self.validate_schema(
                    items,
                    value,
                    &child_pointer(schema_pointer, "items"),
                    &child_pointer(instance_pointer, &index.to_string()),
                    errors,
                );
            }
        }
        if let Some(minimum) = schema.get("minItems").and_then(Value::as_u64) {
            if instance.len() < minimum as usize {
                errors.push(instance_error(
                    instance_pointer,
                    format!("expected at least {minimum} array items"),
                ));
            }
        }
        if schema
            .get("uniqueItems")
            .and_then(Value::as_bool)
            .is_some_and(|unique| unique)
        {
            for (index, value) in instance.iter().enumerate() {
                if instance[..index].iter().any(|seen| seen == value) {
                    errors.push(instance_error(
                        &child_pointer(instance_pointer, &index.to_string()),
                        "expected every array item to be a unique JSON value",
                    ));
                }
            }
        }
    }

    fn validate_combinators(
        &self,
        schema: &Map<String, Value>,
        instance: &Value,
        schema_pointer: &str,
        instance_pointer: &str,
        errors: &mut Vec<String>,
    ) {
        if let Some(branches) = schema.get("anyOf").and_then(Value::as_array) {
            let matches = self.matching_branches(
                branches,
                instance,
                &child_pointer(schema_pointer, "anyOf"),
                instance_pointer,
            );
            if matches == 0 {
                errors.push(instance_error(
                    instance_pointer,
                    "expected at least one `anyOf` branch to match",
                ));
            }
        }
        if let Some(branches) = schema.get("oneOf").and_then(Value::as_array) {
            let matches = self.matching_branches(
                branches,
                instance,
                &child_pointer(schema_pointer, "oneOf"),
                instance_pointer,
            );
            if matches != 1 {
                errors.push(instance_error(
                    instance_pointer,
                    format!("expected exactly one `oneOf` branch to match; matched {matches}"),
                ));
            }
        }
    }

    fn matching_branches(
        &self,
        branches: &[Value],
        instance: &Value,
        branches_pointer: &str,
        instance_pointer: &str,
    ) -> usize {
        branches
            .iter()
            .enumerate()
            .filter(|(index, branch)| {
                let mut branch_errors = Vec::new();
                self.validate_schema(
                    branch,
                    instance,
                    &child_pointer(branches_pointer, &index.to_string()),
                    instance_pointer,
                    &mut branch_errors,
                );
                branch_errors.is_empty()
            })
            .count()
    }
}

static VALIDATOR: LazyLock<SarifValidator> = LazyLock::new(|| {
    let document = serde_json::from_str(include_str!("fixtures/sarif-2.1.0.json"))
        .expect("the vendored SARIF schema should be a JSON document");
    SarifValidator::new(document)
});

fn validator() -> &'static SarifValidator {
    &VALIDATOR
}

fn validate(value: &Value) -> Result<(), String> {
    validator().validate(value)
}

fn audit_schema(
    root: &Value,
    schema: &Value,
    schema_pointer: &str,
    patterns: &mut BTreeMap<String, Regex>,
    audited: &mut BTreeSet<String>,
) {
    if !audited.insert(schema_pointer.to_owned()) {
        return;
    }
    let object = schema.as_object().unwrap_or_else(|| {
        schema_failure(
            "<schema>",
            schema_pointer,
            "expected a schema object rather than a boolean or another JSON value",
        )
    });

    for keyword in object.keys() {
        if !IMPLEMENTED_KEYWORDS.contains(&keyword.as_str())
            && !ANNOTATION_KEYWORDS.contains(&keyword.as_str())
        {
            schema_failure(
                keyword,
                &child_pointer(schema_pointer, keyword),
                "the validator does not implement this keyword",
            );
        }
    }

    for (keyword, value) in object {
        let keyword_pointer = child_pointer(schema_pointer, keyword);
        match keyword.as_str() {
            "type" => {
                let expected = value.as_str().unwrap_or_else(|| {
                    schema_failure(
                        keyword,
                        &keyword_pointer,
                        "expected one type name; type arrays are unsupported",
                    )
                });
                if !["array", "boolean", "integer", "number", "object", "string"]
                    .contains(&expected)
                {
                    schema_failure(keyword, &keyword_pointer, "unknown type name");
                }
            }
            "$ref" => {
                let reference = value.as_str().unwrap_or_else(|| {
                    schema_failure(keyword, &keyword_pointer, "expected a string reference")
                });
                let target = resolve_reference(root, reference, schema_pointer);
                if !target.is_object() {
                    schema_failure(
                        keyword,
                        &keyword_pointer,
                        "the reference did not resolve to a schema object",
                    );
                }
                let target_pointer = reference
                    .strip_prefix('#')
                    .expect("resolve_reference should have rejected an external reference");
                audit_schema(root, target, target_pointer, patterns, audited);
            }
            "properties" | "definitions" => {
                let children = value.as_object().unwrap_or_else(|| {
                    schema_failure(keyword, &keyword_pointer, "expected an object of schemas")
                });
                for (name, child) in children {
                    if !child.is_object() {
                        schema_failure(
                            keyword,
                            &child_pointer(&keyword_pointer, name),
                            "expected a schema object",
                        );
                    }
                    audit_schema(
                        root,
                        child,
                        &child_pointer(&keyword_pointer, name),
                        patterns,
                        audited,
                    );
                }
            }
            "required" => {
                let names = value.as_array().unwrap_or_else(|| {
                    schema_failure(keyword, &keyword_pointer, "expected an array of strings")
                });
                if names.iter().any(|name| !name.is_string()) {
                    schema_failure(keyword, &keyword_pointer, "expected an array of strings");
                }
            }
            "additionalProperties" => match value {
                Value::Bool(_) => {}
                Value::Object(_) => {
                    audit_schema(root, value, &keyword_pointer, patterns, audited);
                }
                _ => schema_failure(
                    keyword,
                    &keyword_pointer,
                    "expected a boolean or schema object",
                ),
            },
            "items" => {
                if !value.is_object() {
                    schema_failure(
                        keyword,
                        &keyword_pointer,
                        "expected one schema object; tuple-schema arrays are unsupported",
                    );
                }
                audit_schema(root, value, &keyword_pointer, patterns, audited);
            }
            "minItems" => {
                if value.as_u64().is_none() {
                    schema_failure(keyword, &keyword_pointer, "expected a non-negative integer");
                }
            }
            "uniqueItems" => {
                if !value.is_boolean() {
                    schema_failure(keyword, &keyword_pointer, "expected a boolean");
                }
            }
            "minimum" | "maximum" => {
                if !value.is_number() {
                    schema_failure(keyword, &keyword_pointer, "expected a number");
                }
            }
            "pattern" => {
                let source = value.as_str().unwrap_or_else(|| {
                    schema_failure(keyword, &keyword_pointer, "expected a regular expression")
                });
                let compiled = Regex::new(source).unwrap_or_else(|error| {
                    schema_failure(
                        keyword,
                        &keyword_pointer,
                        format!("the regular expression did not compile: {error}"),
                    )
                });
                patterns.insert(keyword_pointer, compiled);
            }
            "enum" => {
                if !value.is_array() {
                    schema_failure(keyword, &keyword_pointer, "expected an array");
                }
            }
            "anyOf" | "oneOf" => {
                let branches = value.as_array().unwrap_or_else(|| {
                    schema_failure(keyword, &keyword_pointer, "expected an array of schemas")
                });
                for (index, branch) in branches.iter().enumerate() {
                    if !branch.is_object() {
                        schema_failure(
                            keyword,
                            &child_pointer(&keyword_pointer, &index.to_string()),
                            "expected a schema object",
                        );
                    }
                    audit_schema(
                        root,
                        branch,
                        &child_pointer(&keyword_pointer, &index.to_string()),
                        patterns,
                        audited,
                    );
                }
            }
            "description" | "title" | "$schema" | "$id" | "format" => {
                if !value.is_string() {
                    schema_failure(keyword, &keyword_pointer, "expected a string annotation");
                }
            }
            "default" => {}
            _ => unreachable!("the keyword allowlists and audit match must stay exhaustive"),
        }
    }
}

fn resolve_reference<'a>(root: &'a Value, reference: &str, schema_pointer: &str) -> &'a Value {
    let Some(pointer) = reference.strip_prefix('#') else {
        schema_failure(
            "$ref",
            &child_pointer(schema_pointer, "$ref"),
            format!("external reference `{reference}` is forbidden"),
        );
    };
    if !pointer.is_empty() && !pointer.starts_with('/') {
        schema_failure(
            "$ref",
            &child_pointer(schema_pointer, "$ref"),
            format!("local reference `{reference}` is not a JSON pointer"),
        );
    }
    root.pointer(pointer).unwrap_or_else(|| {
        schema_failure(
            "$ref",
            &child_pointer(schema_pointer, "$ref"),
            format!("local reference `{reference}` could not be resolved"),
        )
    })
}

fn matches_type(instance: &Value, expected: &str) -> bool {
    match expected {
        "array" => instance.is_array(),
        "boolean" => instance.is_boolean(),
        "integer" => {
            instance.as_i64().is_some()
                || instance.as_u64().is_some()
                || instance
                    .as_f64()
                    .is_some_and(|number| number.fract() == 0.0)
        }
        "number" => instance.is_number(),
        "object" => instance.is_object(),
        "string" => instance.is_string(),
        _ => unreachable!("the schema audit should reject unknown type names"),
    }
}

fn child_pointer(parent: &str, token: &str) -> String {
    let escaped = token.replace('~', "~0").replace('/', "~1");
    format!("{parent}/{escaped}")
}

fn instance_error(pointer: &str, expectation: impl std::fmt::Display) -> String {
    format!("instance JSON pointer `{pointer}`: {expectation}")
}

fn schema_failure(keyword: &str, pointer: &str, reason: impl std::fmt::Display) -> ! {
    panic!("schema keyword `{keyword}` at schema JSON pointer `{pointer}`: {reason}")
}

fn finding(
    id: &str,
    pattern: &str,
    label: &str,
    confidence: Confidence,
    preview: &str,
    pane_id: &str,
    line: usize,
) -> Finding {
    Finding {
        id: id.to_string(),
        pattern: pattern.to_string(),
        label: label.to_string(),
        confidence,
        preview: preview.to_string(),
        value_len: preview.chars().count(),
        pane_id: pane_id.to_string(),
        workspace_id: "w0".to_string(),
        pane_label: "agent".to_string(),
        agent: None,
        cwd: None,
        foreground_process_name_when_first_seen: None,
        foreground_process_pid_when_first_seen: None,
        line,
        digest: u64::default(),
        first_seen: NOW - 90,
        last_seen: NOW,
        acknowledged: false,
    }
}

fn populated_report() -> Report {
    let mut strong = finding(
        "a1b2c30000000000",
        "aws_access_key_id",
        "AWS access key ID",
        Confidence::Strong,
        "AKIA\u{2026}MPLE",
        "w0:p1",
        42,
    );
    strong.agent = Some("claude".to_string());
    strong.cwd = Some(PathBuf::from("/workspace/example"));
    strong.foreground_process_name_when_first_seen = Some("cargo".to_string());
    strong.foreground_process_pid_when_first_seen = Some(4310);

    let weak = finding(
        "b2c3d40000000000",
        "env_assignment",
        "API key assignment",
        Confidence::Weak,
        "sk-l\u{2026}9ab2",
        "w0:p2",
        7,
    );

    let mut acknowledged = finding(
        "c3d4e50000000000",
        "stripe_secret_key",
        "Stripe live secret key",
        Confidence::Strong,
        "sk_l\u{2026}7890",
        "w0:p3",
        91,
    );
    acknowledged.acknowledged = true;

    Report {
        findings: vec![strong, weak, acknowledged],
        panes_scanned: 5,
        panes_skipped: 2,
        panes_unread: 1,
        panes_truncated: 3,
        notes: vec![
            "pane w0:p4 could not be read".to_string(),
            "2 permanent value suppression(s) active.".to_string(),
        ],
        generated_at: NOW,
    }
}

fn emitted_value(report: &Report) -> Value {
    serde_json::from_str(&report_sarif(report)).expect("report_sarif should emit a JSON document")
}

#[test]
fn the_emitted_schema_identifier_matches_the_vendored_oracle() {
    let value = emitted_value(&Report::default());
    assert_eq!(
        value.get("$schema").and_then(Value::as_str),
        Some(SARIF_SCHEMA_URL),
        "the emitted schema identifier drifted from the URL recorded for the vendored document"
    );
}

#[test]
fn a_populated_report_is_valid_sarif() {
    let report = populated_report();
    let quiet_value = serde_json::from_str(&report_sarif_with_quiet(&report, Some(NOW + 600), NOW))
        .expect("report_sarif_with_quiet should emit a JSON document");
    validate(&quiet_value).unwrap_or_else(|error| {
        panic!("the populated report with quiet active is not valid SARIF:\n{error}")
    });

    let value = emitted_value(&report);
    validate(&value)
        .unwrap_or_else(|error| panic!("the populated report is not valid SARIF:\n{error}"));
}

#[test]
fn an_empty_report_is_valid_sarif() {
    let value = emitted_value(&Report::default());
    validate(&value)
        .unwrap_or_else(|error| panic!("the empty report is not valid SARIF:\n{error}"));
}

#[test]
fn a_finding_with_no_line_number_is_still_valid_sarif() {
    let report = Report {
        findings: vec![finding(
            "d4e5f60000000000",
            "env_assignment",
            "API key assignment",
            Confidence::Weak,
            "sk-l\u{2026}9ab2",
            "w0:p4",
            0,
        )],
        panes_scanned: 1,
        generated_at: NOW,
        ..Report::default()
    };
    let value = emitted_value(&report);
    validate(&value).unwrap_or_else(|error| {
        panic!("the report carrying a legacy finding without a line number is not valid SARIF:\n{error}")
    });

    let physical_location = &value["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
    assert_eq!(
        physical_location["artifactLocation"]["uri"], "herdr://pane/w0:p4",
        "omitting an unknown region must not discard the pane artifact location"
    );
    assert!(
        physical_location.get("region").is_none(),
        "an unknown line number must be absent rather than invented"
    );
}

#[test]
fn the_schema_rejects_output_it_should_reject() {
    let valid = emitted_value(&populated_report());
    validate(&valid).unwrap_or_else(|error| {
        panic!("the negative controls must start from valid SARIF:\n{error}")
    });

    let mut missing_version = valid.clone();
    missing_version
        .as_object_mut()
        .expect("the SARIF log should be a JSON object")
        .remove("version");
    assert!(
        validate(&missing_version).is_err(),
        "the schema accepted a SARIF log without its required version"
    );

    let mut unknown_level = valid.clone();
    unknown_level["runs"][0]["results"][0]["level"] = json!("notice");
    assert!(
        validate(&unknown_level).is_err(),
        "the schema accepted a result level outside the SARIF enumeration"
    );

    let mut zero_start_line = valid;
    zero_start_line["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        ["startLine"] = json!(0);
    assert!(
        validate(&zero_start_line).is_err(),
        "the schema accepted a region whose startLine is below one"
    );
}

#[test]
fn every_implemented_constraint_rejects_an_invalid_instance_at_its_json_pointer() {
    struct RejectionCase {
        keyword: &'static str,
        schema: Option<Value>,
        instance: Value,
        pointer: &'static str,
    }

    let valid = emitted_value(&populated_report());

    let mut missing_version = valid.clone();
    missing_version
        .as_object_mut()
        .expect("the SARIF log should be a JSON object")
        .remove("version");

    let mut additional_run_property = valid.clone();
    additional_run_property["runs"][0]["unexpected"] = json!(true);

    let mut unknown_version = valid.clone();
    unknown_version["version"] = json!("unexpected");

    let mut zero_start_line = valid;
    zero_start_line["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        ["startLine"] = json!(0);

    let cases = vec![
        RejectionCase {
            keyword: "type",
            schema: Some(json!({
                "type": "object",
                "properties": {"target": {"type": "integer"}}
            })),
            instance: json!({"target": 1.5}),
            pointer: "/target",
        },
        RejectionCase {
            keyword: "properties",
            schema: Some(json!({
                "type": "object",
                "properties": {"target": {"type": "boolean"}}
            })),
            instance: json!({"target": "unexpected"}),
            pointer: "/target",
        },
        RejectionCase {
            keyword: "required",
            schema: None,
            instance: missing_version,
            pointer: "/version",
        },
        RejectionCase {
            keyword: "additionalProperties",
            schema: None,
            instance: additional_run_property,
            pointer: "/runs/0/unexpected",
        },
        RejectionCase {
            keyword: "enum",
            schema: None,
            instance: unknown_version,
            pointer: "/version",
        },
        RejectionCase {
            keyword: "minimum",
            schema: None,
            instance: zero_start_line,
            pointer: "/runs/0/results/0/locations/0/physicalLocation/region/startLine",
        },
        RejectionCase {
            keyword: "maximum",
            schema: Some(json!({
                "type": "object",
                "properties": {"target": {"type": "number", "maximum": 3}}
            })),
            instance: json!({"target": 4}),
            pointer: "/target",
        },
        RejectionCase {
            keyword: "minItems",
            schema: Some(json!({
                "type": "object",
                "properties": {"target": {"type": "array", "minItems": 2}}
            })),
            instance: json!({"target": []}),
            pointer: "/target",
        },
        RejectionCase {
            keyword: "uniqueItems",
            schema: Some(json!({
                "type": "object",
                "properties": {"target": {"type": "array", "uniqueItems": true}}
            })),
            instance: json!({"target": [{"nested": [1]}, {"nested": [1]}]}),
            pointer: "/target/1",
        },
        RejectionCase {
            keyword: "pattern",
            schema: Some(json!({
                "type": "object",
                "properties": {"target": {"type": "string", "pattern": "^[a-z]+$"}}
            })),
            instance: json!({"target": "123"}),
            pointer: "/target",
        },
        RejectionCase {
            keyword: "items",
            schema: Some(json!({
                "type": "object",
                "properties": {
                    "target": {"type": "array", "items": {"type": "integer"}}
                }
            })),
            instance: json!({"target": [1, "unexpected"]}),
            pointer: "/target/1",
        },
        RejectionCase {
            keyword: "anyOf",
            schema: Some(json!({
                "type": "object",
                "properties": {
                    "target": {"anyOf": [{"type": "integer"}, {"type": "string"}]}
                }
            })),
            instance: json!({"target": false}),
            pointer: "/target",
        },
        RejectionCase {
            keyword: "oneOf",
            schema: Some(json!({
                "type": "object",
                "properties": {
                    "target": {"oneOf": [{"type": "integer"}, {"type": "number"}]}
                }
            })),
            instance: json!({"target": 2}),
            pointer: "/target",
        },
        RejectionCase {
            keyword: "$ref",
            schema: Some(json!({
                "type": "object",
                "properties": {"target": {"$ref": "#/definitions/target"}},
                "definitions": {"target": {"type": "integer"}}
            })),
            instance: json!({"target": "unexpected"}),
            pointer: "/target",
        },
    ];

    for case in cases {
        let result = if let Some(schema) = case.schema {
            SarifValidator::new(schema).validate(&case.instance)
        } else {
            validate(&case.instance)
        };
        let error = match result {
            Ok(()) => panic!(
                "the `{}` constraint unexpectedly accepted its invalid instance",
                case.keyword
            ),
            Err(error) => error,
        };
        assert!(
            error.contains(case.pointer),
            "the `{}` rejection did not name instance JSON pointer `{}`:\n{}",
            case.keyword,
            case.pointer,
            error
        );
    }

    let number_validator = SarifValidator::new(json!({"type": "number"}));
    number_validator
        .validate(&json!(2))
        .expect("the `number` type should accept an integer");
    number_validator
        .validate(&json!(2.5))
        .expect("the `number` type should accept a non-integral number");
}

#[test]
fn the_validator_hard_fails_on_unknown_keywords_and_unsupported_shapes() {
    let cases = [
        (
            "const",
            "/properties/target/const",
            json!({
                "properties": {"target": {"const": true}}
            }),
        ),
        ("type", "/type", json!({"type": ["string", "null"]})),
        ("items", "/items", json!({"items": [{"type": "string"}]})),
        (
            "properties",
            "/properties/target",
            json!({"properties": {"target": true}}),
        ),
        (
            "$ref",
            "/$ref",
            json!({"$ref": "https://example.invalid/schema.json"}),
        ),
        (
            "$ref",
            "/$ref",
            json!({"$ref": "#/definitions/missing", "definitions": {}}),
        ),
    ];

    for (keyword, pointer, schema) in cases {
        let panic = std::panic::catch_unwind(|| SarifValidator::new(schema));
        let payload = match panic {
            Ok(_) => panic!("schema keyword `{keyword}` passed without an implementation"),
            Err(payload) => payload,
        };
        let message = panic_message(payload);
        assert!(
            message.contains(keyword) && message.contains(pointer),
            "the hard failure must name schema keyword `{keyword}` and JSON pointer `{pointer}`"
        );
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else {
        panic!("the schema audit panic should carry a string message")
    }
}
