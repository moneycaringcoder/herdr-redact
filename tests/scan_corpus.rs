//! The scanner corpus.
//!
//! Two bodies of text carry most of the weight here.
//!
//! The **positive corpus** holds one structurally valid vector per rule. Every
//! value in it is obviously fake — a documented example value, or a synthetic
//! string that no provider ever issued — because a test suite is a place a real
//! credential must never be.
//!
//! The **negative corpus** is ordinary developer output: git SHAs, UUIDs, base64
//! images, build logs, source code, `.env` files full of placeholders. It is
//! asserted at 100% precision. Any false positive fails the suite, because a
//! scanner that cries wolf gets uninstalled and then protects nothing.

use std::time::Instant;

use redact::config::{Config, CustomPattern};
use redact::model::{digest, Confidence, DigestKey};
use redact::scan::{mask, scan, scan_reporting, Rules};

const KEY: DigestKey = [
    0x5a, 0x11, 0x9c, 0x03, 0x7e, 0xd2, 0x48, 0x6b, 0x91, 0x0f, 0xa4, 0x33, 0xc8, 0x27, 0x5e, 0xe1,
];

/// One positive vector: the text as it would appear in a pane, the value the
/// rule is expected to report, and the preview the user is expected to see.
struct Vector {
    rule: &'static str,
    confidence: Confidence,
    text: &'static str,
    value: &'static str,
    preview: &'static str,
}

/// Every value below is fake. The AWS pair and the JWT are the values published
/// in those vendors' own documentation; the rest are runs of `0123456789abc…`
/// or synthetic strings, padded to the length each provider's format demands.
const POSITIVE: &[Vector] = &[
    Vector {
        rule: "aws_access_key_id",
        confidence: Confidence::Strong,
        text: "AKIAIOSFODNN7EXAMPLE",
        value: "AKIAIOSFODNN7EXAMPLE",
        preview: "AKI\u{2026}PLE",
    },
    // A principal ID is 21 characters — four for the prefix, seventeen of
    // base32 — where an access key ID is twenty. It identifies a role, user,
    // group or policy; it authenticates nothing.
    Vector {
        rule: "aws_principal_id",
        confidence: Confidence::Weak,
        text: "\"UserId\": \"AROAEXAMPLEEXAMPLEEXA\"",
        value: "AROAEXAMPLEEXAMPLEEXA",
        preview: "ARO\u{2026}EXA",
    },
    Vector {
        rule: "aws_secret_access_key",
        confidence: Confidence::Strong,
        text: "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        preview: "wJal\u{2026}EKEY",
    },
    Vector {
        rule: "github_token",
        confidence: Confidence::Strong,
        text: "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
        value: "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
        preview: "ghp_\u{2026}wxyz",
    },
    Vector {
        rule: "github_pat",
        confidence: Confidence::Strong,
        text: "github_pat_0123456789abcdefghijkl_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklm",
        value: "github_pat_0123456789abcdefghijkl_0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklm",
        preview: "gith\u{2026}jklm",
    },
    Vector {
        rule: "anthropic_api_key",
        confidence: Confidence::Strong,
        text: "sk-ant-api03-0123456789abcdefghijklmnopqrstuvwxyz0123",
        value: "sk-ant-api03-0123456789abcdefghijklmnopqrstuvwxyz0123",
        preview: "sk-a\u{2026}0123",
    },
    Vector {
        rule: "openai_api_key",
        confidence: Confidence::Strong,
        text: "sk-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
        value: "sk-0123456789abcdefghijklmnopqrstuvwxyz0123456789ab",
        preview: "sk-0\u{2026}89ab",
    },
    Vector {
        rule: "openai_api_key",
        confidence: Confidence::Strong,
        text: "sk-proj-0123456789abcdefghijklmnopqrstuvwxyz0123",
        value: "sk-proj-0123456789abcdefghijklmnopqrstuvwxyz0123",
        preview: "sk-p\u{2026}0123",
    },
    Vector {
        rule: "stripe_secret_key",
        confidence: Confidence::Strong,
        text: "sk_live_0123456789abcdefghijklmn",
        value: "sk_live_0123456789abcdefghijklmn",
        preview: "sk_l\u{2026}klmn",
    },
    Vector {
        rule: "slack_token",
        confidence: Confidence::Strong,
        text: "xoxb-1111111111-2222222222-0123456789abcdefghijkl",
        value: "xoxb-1111111111-2222222222-0123456789abcdefghijkl",
        preview: "xoxb\u{2026}ijkl",
    },
    Vector {
        rule: "google_api_key",
        confidence: Confidence::Strong,
        text: "AIza0123456789abcdefghijklmnopqrstuvwxy",
        value: "AIza0123456789abcdefghijklmnopqrstuvwxy",
        preview: "AIza\u{2026}vwxy",
    },
    Vector {
        rule: "google_oauth_client_secret",
        confidence: Confidence::Strong,
        text: "GOCSPX-0123456789abcdefghijklmnopqr",
        value: "GOCSPX-0123456789abcdefghijklmnopqr",
        preview: "GOCS\u{2026}opqr",
    },
    Vector {
        rule: "jwt",
        confidence: Confidence::Strong,
        text: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        preview: "eyJh\u{2026}sw5c",
    },
    Vector {
        rule: "private_key_block",
        confidence: Confidence::Strong,
        text: "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\nKUpRKfFLfRYC9AIVPv3RUnnnJ4Gh1uNMNzGTuJXFcQIDAQAB0000000000000000\n-----END RSA PRIVATE KEY-----",
        value: "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\nKUpRKfFLfRYC9AIVPv3RUnnnJ4Gh1uNMNzGTuJXFcQIDAQAB0000000000000000\n-----END RSA PRIVATE KEY-----",
        preview: "----\u{2026}----",
    },
    Vector {
        rule: "slack_webhook_url",
        confidence: Confidence::Strong,
        text: "https://hooks.slack.com/services/T00000000/B00000000/0123456789abcdefghijkl",
        value: "https://hooks.slack.com/services/T00000000/B00000000/0123456789abcdefghijkl",
        preview: "http\u{2026}ijkl",
    },
    Vector {
        rule: "npm_token",
        confidence: Confidence::Strong,
        text: "npm_0123456789abcdefghijklmnopqrstuvwxyz",
        value: "npm_0123456789abcdefghijklmnopqrstuvwxyz",
        preview: "npm_\u{2026}wxyz",
    },
    Vector {
        rule: "pypi_token",
        confidence: Confidence::Strong,
        text: "pypi-AgEIcHlwaS5vcmc0123456789abcdefghijklmnopqrstuvwxyz0123",
        value: "pypi-AgEIcHlwaS5vcmc0123456789abcdefghijklmnopqrstuvwxyz0123",
        preview: "pypi\u{2026}0123",
    },
    Vector {
        rule: "sendgrid_api_key",
        confidence: Confidence::Strong,
        text: "SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyz0123456",
        value: "SG.0123456789abcdefghijkl.0123456789abcdefghijklmnopqrstuvwxyz0123456",
        preview: "SG.0\u{2026}3456",
    },
    Vector {
        rule: "gitlab_pat",
        confidence: Confidence::Strong,
        text: "glpat-0123456789abcdefghij",
        value: "glpat-0123456789abcdefghij",
        preview: "glpa\u{2026}ghij",
    },
    Vector {
        rule: "huggingface_token",
        confidence: Confidence::Strong,
        text: "hf_0123456789abcdefghijklmnopqrstuvwx",
        value: "hf_0123456789abcdefghijklmnopqrstuvwx",
        preview: "hf_0\u{2026}uvwx",
    },
    // The private half of an age keypair. Fake: the body is the bech32 charset
    // written out twice, which no `age-keygen` ever produced.
    Vector {
        rule: "age_secret_key",
        confidence: Confidence::Strong,
        text: "AGE-SECRET-KEY-1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE",
        value: "AGE-SECRET-KEY-1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE",
        preview: "AGE-\u{2026}KHCE",
    },
    Vector {
        rule: "url_credentials",
        confidence: Confidence::Weak,
        text: "psql postgres://svc:Zx9Qw7Lm2Kd8@db.internal:5432/app",
        value: "Zx9Qw7Lm2Kd8",
        preview: "Zx\u{2026}d8",
    },
    Vector {
        rule: "http_bearer_token",
        confidence: Confidence::Weak,
        text: "curl -H \"Authorization: Bearer Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6\" https://api.internal/v1/ping",
        value: "Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6",
        preview: "Zx9Q\u{2026}1Vf6",
    },
    Vector {
        rule: "env_assignment",
        confidence: Confidence::Weak,
        text: "MY_SERVICE_TOKEN=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6",
        value: "Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6",
        preview: "Zx9Q\u{2026}1Vf6",
    },
    Vector {
        rule: "env_assignment",
        confidence: Confidence::Weak,
        text: "  api_key: Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6",
        value: "Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6",
        preview: "Zx9Q\u{2026}1Vf6",
    },
    Vector {
        rule: "env_assignment",
        confidence: Confidence::Weak,
        text: "  \"database_password\": \"Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6\",",
        value: "Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6",
        preview: "Zx9Q\u{2026}1Vf6",
    },
    // Short and low entropy, but a password all the same — the keyed digest in
    // `model` exists precisely so this one can be tracked without storing a
    // guessable hash of it.
    Vector {
        rule: "env_assignment",
        confidence: Confidence::Weak,
        text: "PASSWORD=hunter2",
        value: "hunter2",
        preview: "h\u{2026}2",
    },
];

/// Ordinary developer output. Nothing here is a credential, and the suite fails
/// if the scanner thinks otherwise.
const NEGATIVE: &str = r#"
$ git log --oneline -3
9c1f0d7 Tighten the pane read budget
4b2e8a1 Adapt the socket client
e70dd41 Initial commit
commit 9c1f0d7a3b5e2f4c8d6a0b1e3f5a7c9d1b3e5f70
tree   4b2e8a15c9d7e3f1a6b8c0d2e4f6a8b0c2d4e6f8
parent e70dd419aa3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d

Run id: 3f2504e0-4f89-11d3-9a0c-0305e82c3301
Run id: 3F2504E0-4F89-11D3-9A0C-0305E82C3301
sha256 of the tarball: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Digest: sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809

data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==
logo.png (base64, wrapped):
iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAYAAAD0eNT6AAAACXBIWXMAAAsTAAALEwEAmpwY
AAAgAElEQVR4nOy9d3xUVfr48ffMZDLpvSekEEJCSSCE3nvvXar0ItJEUFFRQFF0RVFRQVBB
QaSDdOm9d0IJIYT0nkkyk8lkZn5/DFmyu35d9/vd39dd7/v14vFi5t57zj3n3ufc85znPEen
0WhAIBAIBAKBQCAQCAQCgUAgEAgEAoFAIBAIBAKBQCAQCAQCgUAgEAgEAoFAIBAIBAKBQCAQ
LEAgEAgEAoFAIBAIBAKBQCAQCAQCgUAgEAgEAoFAIBAIBAKBQCAQCAQCwf9nBAKBQCAQCAQC

Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod
tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,
quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo.

$ pip install sk-learn
Collecting sk-learn
$ curl -H "sk-ms-version: 2024-01-01" https://api.internal/v1/health
See the sk-learn docs, and the sk-ms-version header, for the migration notes.

Not a token: eyJZZZZZZZZZZZZ.aaaaaaaaaaaaaa.bbbbbbbbbbbbbb
Also not a token: eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.ZmFrZXNpZ25hdHVyZQ

// src/auth.rs
pub struct AuthorizationHeaderBuilder {
    default_timeout_in_milliseconds: u64,
}
const MAX_RETRIES: usize = 5;
const DEFAULT_TIMEOUT: u64 = 30;
let authorization_header_value = format!("Bearer {}", credentials.access_token());
api_key = os.environ["API_KEY"]
token = get_token_from_keyring(service_name)
const ACCESS_TOKEN_STORAGE_KEY = "acme.access-token.v2";
password_field.set_placeholder("enter your password");

$ cargo build --release
   Compiling regex-automata v0.4.18
   Compiling redact v0.1.0 (/home/dev/repos/herdr-redact)
    Finished `release` profile [optimized] target(s) in 12.03s
checksum = "d626bb9dae77e28219937af045c257c28830df2e6e0d70a4dfeb1b3b8b3b3b3b"
$ npm ci
added 412 packages, and audited 413 packages in 6s
  "integrity": "sha512-Kx3fZ0ZQ1kQ9m6xkzYQ4b7VvV0m0m5cQ2p1sT3nQ0nZ5xkO9vX2mQ8n1kZ9f2p3=="
$ docker pull ubuntu:24.04
24.04: Pulling from library/ubuntu
Digest: sha256:2e863c44b718727c860746568e1d54afd13b2fa71b160f5cd9058fc436217b30
Status: Downloaded newer image for ubuntu:24.04

LOG_LEVEL=debug
API_KEY=
TOKEN=$MY_TOKEN
SECRET_KEY=changeme
PASSWORD=***
GITHUB_TOKEN=<redacted>
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
STRIPE_SECRET_KEY=%STRIPE_SECRET%
API_KEY_FILE=/run/secrets/api_key
CREDENTIALS_PATH=./config/credentials.json
SESSION_SECRET=""
DATABASE_URL=postgres://localhost:5432/app
PUBLIC_KEY=ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ
TEST_TOKEN=0123456789abcdef
token: refreshed successfully
secret: null
password: not set
hash=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3

# "key" is the most overloaded word in a terminal. Every line in this block is
# ordinary output, and every one of them used to be reported as a credential.
# printed by `env` in every official python:3.x image — a *public* fingerprint
GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305
# GitHub Actions and CircleCI, on every cache hit
CACHE_KEY=Linux-node-8f14e45fceea167a5a36dedd4bea2543
# any CI config echoed back
  cache_key: posts/index-20260115
# RabbitMQ, Celery
routing_key: orders.created.v2
# Kafka, DynamoDB
partition_key: orders-2026-01-15
# every payments SDK log line
idempotency_key: 7f3a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8
# Pusher, and half the Laravel apps in the world
  app_key: frontend-v2
# S3
bucket_key: prod/state/v1
# the PUBLIC half of an age keypair; the private half is AGE-SECRET-KEY-1…
age_key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
# a service logging its own request headers
X-Request-Key: 5f2b8c1d9e4a7061
# also a key id or a public verification key as often as it is a secret
signing_key: rotated-2026-01

Authorization: Bearer $TOKEN
Authorization: Bearer <token>
Authorization: Bearer YOUR_API_KEY_HERE
Connection string in the docs: https://user:password@host:5432/db

$ aws sts get-caller-identity
{
    "UserId": "AIDAEXAMPLEEXAMPLE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/Example"
}
Region: us-east-1
Bucket: arn:aws:s3:::example-bucket/reports/2026/
Instance: i-0abcd1234ef567890 in us-west-2

Test keys, which are public by design:
sk_test_0123456789abcdefghijklmn
rk_test_0123456789abcdefghijklmn
Twilio account SID: AC0123456789abcdef0123456789abcdef

┌────────────────┬─────────┬──────────┐
│ package        │ version │ status   │
├────────────────┼─────────┼──────────┤
│ redact         │ 0.1.0   │ ok       │
│ regex          │ 1.13.1  │ ok       │
└────────────────┴─────────┴──────────┘
Building [========================>             ] 42/100 eta 00:03
✔ 128 passed   ✖ 0 failed   ⚠ 2 skipped
"#;

fn builtin() -> Rules {
    Rules::builtin()
}

/// The vector for one rule, by name. Looked up rather than indexed so that
/// adding a vector cannot silently repoint a test at a different rule.
fn vector(rule: &str) -> &'static Vector {
    POSITIVE
        .iter()
        .find(|vector| vector.rule == rule)
        .expect("every rule named in a test has a vector")
}

/// Wraps a vector so every value sits on line 3, after a blank line.
fn framed(text: &str) -> String {
    format!("starting build\n\n{text}\n\nbuild finished\n")
}

// ---------------------------------------------------------------------------
// The positive corpus
// ---------------------------------------------------------------------------

#[test]
fn positive_corpus_reports_every_rule_exactly_once() {
    let rules = builtin();
    for vector in POSITIVE {
        let text = framed(vector.text);
        let matches = scan(&text, &rules, &KEY);
        assert_eq!(
            matches.len(),
            1,
            "expected exactly one match for {}, got {matches:?}",
            vector.rule
        );
        let found = &matches[0];
        assert_eq!(found.pattern, vector.rule, "rule name for {}", vector.rule);
        assert_eq!(
            found.confidence, vector.confidence,
            "confidence for {}",
            vector.rule
        );
        assert_eq!(found.preview, vector.preview, "preview for {}", vector.rule);
        assert_eq!(
            found.preview,
            mask(vector.value),
            "preview disagrees with mask() for {}",
            vector.rule
        );
        assert_eq!(
            found.value_len,
            vector.value.chars().count(),
            "value_len for {}",
            vector.rule
        );
        assert_eq!(found.line, 3, "line number for {}", vector.rule);
        assert_eq!(
            found.digest,
            digest(&KEY, vector.value),
            "digest for {}",
            vector.rule
        );
        assert!(
            !found.label.is_empty(),
            "human label for {} is empty",
            vector.rule
        );
    }
}

#[test]
fn every_builtin_rule_has_a_vector() {
    let rules = builtin();
    for (name, _) in &rules.names {
        assert!(
            POSITIVE.iter().any(|vector| vector.rule == name),
            "rule `{name}` has no positive vector"
        );
    }
}

// ---------------------------------------------------------------------------
// The negative corpus — 100% precision or the suite fails
// ---------------------------------------------------------------------------

#[test]
fn negative_corpus_produces_no_findings() {
    let matches = scan(NEGATIVE, &builtin(), &KEY);
    assert!(
        matches.is_empty(),
        "false positives on ordinary developer output: {matches:?}"
    );
}

#[test]
fn negative_corpus_stays_clean_line_by_line() {
    // Scanned whole, a false positive could hide behind an overlapping true one.
    // Line by line, every line has to be clean on its own.
    let rules = builtin();
    for (index, line) in NEGATIVE.lines().enumerate() {
        let matches = scan(line, &rules, &KEY);
        assert!(
            matches.is_empty(),
            "false positive on line {}: {matches:?}",
            index + 1
        );
    }
}

#[test]
fn jwt_needs_a_header_that_decodes_to_json_with_alg() {
    let rules = builtin();
    // Decodes to bytes that are not JSON.
    assert!(scan(
        "eyJZZZZZZZZZZZZ.aaaaaaaaaaaaaa.bbbbbbbbbbbbbb",
        &rules,
        &KEY
    )
    .is_empty());
    // Decodes to JSON, but the object carries no `alg`.
    assert!(scan(
        "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.ZmFrZXNpZ25hdHVyZQ",
        &rules,
        &KEY
    )
    .is_empty());
    // The documented example, whose header is `{"alg":"HS256","typ":"JWT"}`.
    let matches = scan(vector("jwt").text, &rules, &KEY);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].pattern, "jwt");
}

#[test]
fn provider_prefixes_inside_a_longer_token_are_ignored() {
    let rules = builtin();
    // Each of these is a real prefix embedded in a longer base64 run, which is
    // what a pasted image or an encoded payload looks like.
    for text in [
        "Qm2ghp_0123456789abcdefghijklmnopqrstuvwxyz",
        "ghp_0123456789abcdefghijklmnopqrstuvwxyz+more",
        "xxAKIAIOSFODNN7EXAMPLE",
        "AKIAIOSFODNN7EXAMPLE0",
        "AIza0123456789abcdefghijklmnopqrstuvwxy=",
    ] {
        assert!(
            scan(text, &rules, &KEY).is_empty(),
            "matched inside a longer token: {text}"
        );
    }
}

/// The one piece of ordinary AWS output that is *not* in the negative corpus
/// above, and why.
///
/// `aws sts get-caller-identity` prints this, verbatim, several times a day in
/// any pane doing AWS work:
///
/// ```text
/// $ aws sts get-caller-identity
/// {
///     "UserId": "AROAZ3MXVX7QJH2WPKNSU:deploy-session",
///     "Account": "123456789012",
///     "Arn": "arn:aws:sts::123456789012:assumed-role/deploy/deploy-session"
/// }
/// ```
///
/// The `AROA…` value is a principal ID: it names a role, it authenticates
/// nothing, and nobody can do anything with it but recognise the account. Under
/// this plugin's own standard, reporting it as a credential is a false positive,
/// which is why `aws_access_key_id` no longer covers those prefixes. Dropping it
/// entirely would be wrong too — an account identifier in a screenshot is worth
/// knowing about — so it reports at `Weak`, with a label that says what it is.
/// A weak finding earns its own badge token and its own colour, so a user can
/// tell this apart from a live key at a glance without reading the table.
#[test]
fn aws_principal_ids_report_as_weak_identifiers_not_as_keys() {
    let rules = builtin();
    let output = "$ aws sts get-caller-identity\n{\n    \"UserId\": \"AROAZ3MXVX7QJH2WPKNSU:deploy-session\",\n    \"Account\": \"123456789012\",\n    \"Arn\": \"arn:aws:sts::123456789012:assumed-role/deploy/deploy-session\"\n}\n";
    let matches = scan(output, &rules, &KEY);
    assert_eq!(matches.len(), 1, "{matches:?}");
    assert_eq!(matches[0].pattern, "aws_principal_id");
    assert_eq!(matches[0].confidence, Confidence::Weak);
    assert_eq!(matches[0].line, 3);
    assert_eq!(matches[0].value_len, 21);
    assert!(matches[0].label.contains("identifier"));

    // Every prefix in the family lands on the same rule, at the same level.
    for prefix in ["AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "APKA"] {
        let text = format!("{prefix}Z3MXVX7QJH2WPKNSU");
        let matches = scan(&text, &rules, &KEY);
        assert_eq!(matches.len(), 1, "{prefix}: {matches:?}");
        assert_eq!(matches[0].pattern, "aws_principal_id", "{prefix}");
        assert_eq!(matches[0].confidence, Confidence::Weak, "{prefix}");
    }

    // The two prefixes that do introduce a credential stay Strong.
    for prefix in ["AKIA", "ASIA"] {
        let text = format!("{prefix}Z3MXVX7QJH2WPKNS");
        let matches = scan(&text, &rules, &KEY);
        assert_eq!(matches.len(), 1, "{prefix}: {matches:?}");
        assert_eq!(matches[0].pattern, "aws_access_key_id", "{prefix}");
        assert_eq!(matches[0].confidence, Confidence::Strong, "{prefix}");
    }
}

/// The `*_key` names that are not credentials, kept here as well as in the
/// negative corpus because the reason each one matters is worth reading.
///
/// A bare `*_KEY` is not enough to report on. "Key" is what a terminal calls a
/// cache key, a routing key, a partition key, an idempotency key and a public
/// fingerprint, and every one of these lines is output somebody sees daily.
#[test]
fn an_ordinary_key_named_assignment_is_not_a_credential() {
    let rules = builtin();
    for text in [
        // `env` in every official python:3.x image. The value is a *public* GPG
        // fingerprint, published so signatures can be verified.
        "GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305",
        // GitHub Actions, CircleCI.
        "CACHE_KEY=Linux-node-8f14e45fceea167a5a36dedd4bea2543",
        "  cache_key: posts/index-20260115",
        // RabbitMQ, Celery.
        "routing_key: orders.created.v2",
        // Kafka, DynamoDB.
        "partition_key: orders-2026-01-15",
        // Every payments SDK log line.
        "idempotency_key: 7f3a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8",
        // Pusher, Laravel.
        "  app_key: frontend-v2",
        // S3.
        "bucket_key: prod/state/v1",
        // Deliberately lost: as often a key id or a public verification key as
        // it is a secret. See `KEY_QUALIFIERS`.
        "signing_key: rotated-2026-01",
        "ENCRYPTION_KEY=8f14e45fceea167a5a36dedd4bea2543",
        // The *public* half of an age keypair — the recipient. Warning about
        // this one while missing the private half is the worst of both.
        "age_key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
    ] {
        assert!(
            scan(text, &rules, &KEY).is_empty(),
            "ordinary output reported as a credential: {text}"
        );
    }
}

/// The other half of the same decision: tightening the name test must not have
/// cost a name that really does carry a secret.
#[test]
fn a_name_that_carries_a_secret_still_reports() {
    let rules = builtin();
    for text in [
        "API_KEY=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6",
        "SECRET_KEY=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6",
        "MY_PRIVATE_KEY=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6",
        "ACCESS_KEY=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6",
        "AUTH_KEY=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6",
        "MEILI_MASTER_KEY=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6",
        "  apikey: Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6",
        "SERVICE_TOKEN=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6",
        "CLIENT_SECRET=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6",
        "DB_PASSWORD=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6",
        "PASSWORD=hunter2",
        "GPG_PASSPHRASE=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6",
        "REGISTRY_CREDENTIALS=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6",
    ] {
        let matches = scan(text, &rules, &KEY);
        assert_eq!(matches.len(), 1, "stopped reporting: {text} ({matches:?})");
        assert_eq!(matches[0].pattern, "env_assignment", "{text}");
    }
}

/// `age-keygen` prints both halves next to each other. Only one of them is a
/// secret, and until now the scanner had it backwards.
#[test]
fn only_the_private_half_of_an_age_keypair_reports() {
    let rules = builtin();
    let output = format!(
        "$ age-keygen\n# created: 2026-01-15T09:12:44Z\n# public key: \
         age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n{}\n",
        vector("age_secret_key").value
    );
    let matches = scan(&output, &rules, &KEY);
    assert_eq!(matches.len(), 1, "{matches:?}");
    assert_eq!(matches[0].pattern, "age_secret_key");
    assert_eq!(matches[0].confidence, Confidence::Strong);
    assert_eq!(matches[0].line, 4);

    // The prefix inside a longer token, and a body that is too short, are not
    // keys. `1`, `B`, `I` and `O` are outside the bech32 charset.
    for text in [
        "AGE-SECRET-KEY-1QPZRY9X8GF2TVDW0S3JN54KHCE",
        "AGE-SECRET-KEY-1BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "age-secret-key-1qpzry9x8gf2tvdw0s3jn54khce6mua7lqpzry9x8gf2tvdw0s3jn54khce",
    ] {
        assert!(scan(text, &rules, &KEY).is_empty(), "unexpected: {text}");
    }
}

#[test]
fn deliberately_unshipped_rules_stay_quiet() {
    let rules = builtin();
    // Stripe test keys are published in documentation and sample apps, and a
    // leaked one costs nothing. Twilio's SIDs are identifiers, and its auth
    // token is bare hex, indistinguishable from a blob id.
    for text in [
        "sk_test_0123456789abcdefghijklmn",
        "rk_test_0123456789abcdefghijklmn",
        "AC0123456789abcdef0123456789abcdef",
        "SK0123456789abcdef0123456789abcdef",
    ] {
        assert!(scan(text, &rules, &KEY).is_empty(), "unexpected: {text}");
    }
}

// ---------------------------------------------------------------------------
// Masking
// ---------------------------------------------------------------------------

#[test]
fn mask_never_shows_more_than_a_third_of_a_value() {
    for vector in POSITIVE {
        let preview = mask(vector.value);
        let shown = preview.chars().filter(|&c| c != '\u{2026}').count();
        let len = vector.value.chars().count();
        assert!(shown <= 8, "{} shows {shown} characters", vector.rule);
        assert!(
            shown * 3 <= len,
            "{} shows {shown} of {len} characters",
            vector.rule
        );
        assert_ne!(preview, vector.value, "{} rendered as itself", vector.rule);
        assert!(
            preview.contains('\u{2026}'),
            "{} has no ellipsis",
            vector.rule
        );
    }
}

#[test]
fn mask_edge_cases() {
    assert_eq!(mask(""), "\u{2026}");
    assert_eq!(mask("a"), "\u{2026}");
    // A four-character value must never render as itself.
    assert_eq!(mask("abcd"), "\u{2026}");
    assert_eq!(mask("abcde"), "\u{2026}");
    assert_eq!(mask("abcdef"), "a\u{2026}f");
    assert_eq!(mask("abcdefghijkl"), "ab\u{2026}kl");
    assert_eq!(mask("0123456789abcdefghijklmn"), "0123\u{2026}klmn");
    // Long values are still capped at four either side.
    assert_eq!(mask(&"x".repeat(1_000)), "xxxx\u{2026}xxxx");
    // Character-oriented, not byte-oriented.
    assert_eq!(mask("héllo wörld"), "h\u{2026}d");
}

// ---------------------------------------------------------------------------
// The rule that matters more than any detection rule
// ---------------------------------------------------------------------------

#[test]
fn no_matched_value_ever_leaves_the_scanner() {
    let rules = builtin();
    for vector in POSITIVE {
        let text = framed(vector.text);
        let matches = scan(&text, &rules, &KEY);
        let rendered = format!("{matches:?}");

        assert!(
            !rendered.contains(vector.value),
            "the value leaked into the Debug rendering for {}",
            vector.rule
        );
        // A multi-line value cannot appear verbatim in a Debug rendering, so
        // check its longest line too — that is the part worth stealing.
        let core = vector
            .value
            .lines()
            .max_by_key(|line| line.len())
            .unwrap_or(vector.value);
        assert!(
            !rendered.contains(core),
            "part of the value leaked into the Debug rendering for {}",
            vector.rule
        );

        for found in &matches {
            for field in [&found.pattern, &found.label, &found.preview] {
                assert!(
                    !field.contains(vector.value) && !field.contains(core),
                    "the value leaked into a field for {}",
                    vector.rule
                );
            }
        }
    }
}

#[test]
fn a_masked_preview_is_never_the_whole_value() {
    let rules = builtin();
    for vector in POSITIVE {
        let matches = scan(&framed(vector.text), &rules, &KEY);
        assert!(matches[0].preview.chars().count() <= 9);
        assert!(matches[0].preview.chars().count() < vector.value.chars().count());
    }
}

// ---------------------------------------------------------------------------
// Line numbers
// ---------------------------------------------------------------------------

#[test]
fn line_numbers_are_one_based_and_survive_blank_lines() {
    let rules = builtin();
    let token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

    let first = scan(&format!("{token}\nsecond line\nthird line"), &rules, &KEY);
    assert_eq!(first[0].line, 1);

    let last = scan(&format!("first line\nsecond line\n{token}"), &rules, &KEY);
    assert_eq!(last[0].line, 3);

    let trailing = scan(&format!("first line\n{token}\n"), &rules, &KEY);
    assert_eq!(trailing[0].line, 2);

    let after_blanks = scan(&format!("first\n\n\n\n\n{token}"), &rules, &KEY);
    assert_eq!(after_blanks[0].line, 6);
}

#[test]
fn crlf_line_endings_do_not_shift_the_line_or_the_value() {
    let rules = builtin();
    let text = "first line\r\nMY_SERVICE_TOKEN=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6\r\nthird line\r\n";
    let matches = scan(text, &rules, &KEY);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].line, 2);
    assert_eq!(matches[0].value_len, 24);
    assert_eq!(matches[0].digest, digest(&KEY, "Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6"));
}

/// The span the scanner reports is the span it validated.
///
/// The assignment rules capture to end of line, so the raw capture carries
/// trailing whitespace and a trailing comma while the plausibility check runs
/// on the trimmed value. Reporting the raw capture put spaces where the four
/// identifying tail characters belong, overstated `value_len`, and — because
/// the digest is the identity of a finding — turned one secret into two
/// findings, so acknowledging one left the other lit.
#[test]
fn trailing_whitespace_and_separators_do_not_change_the_finding() {
    let rules = builtin();
    let secret = "Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6";
    let expected = digest(&KEY, secret);

    for text in [
        "MY_SERVICE_TOKEN=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6".to_string(),
        "MY_SERVICE_TOKEN=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6     ".to_string(),
        "MY_SERVICE_TOKEN=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6\t".to_string(),
        "MY_SERVICE_TOKEN=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6,".to_string(),
        "MY_SERVICE_TOKEN=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6;  ".to_string(),
        "  api_key: Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6   ".to_string(),
        "  api_key: Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6,".to_string(),
        "  \"api_key\": \"Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6\",".to_string(),
        "  - api_key: 'Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6'  ".to_string(),
    ] {
        let matches = scan(&text, &rules, &KEY);
        assert_eq!(matches.len(), 1, "{text:?}: {matches:?}");
        let found = &matches[0];
        assert_eq!(found.value_len, 24, "value_len for {text:?}");
        assert_eq!(found.preview, mask(secret), "preview for {text:?}");
        assert_eq!(found.digest, expected, "digest for {text:?}");
        // Whatever the padding was, none of it reached the preview.
        assert!(
            !found.preview.contains([' ', '\t', ',', ';', '"', '\'']),
            "padding reached the preview for {text:?}: {:?}",
            found.preview
        );
    }
}

#[test]
fn matches_come_back_in_the_order_they_appear() {
    let rules = builtin();
    let text = format!(
        "{}\n{}\n{}\n",
        vector("github_token").text,
        vector("aws_access_key_id").text,
        vector("gitlab_pat").text
    );
    let matches = scan(&text, &rules, &KEY);
    let lines: Vec<usize> = matches.iter().map(|m| m.line).collect();
    assert_eq!(lines, vec![1, 2, 3]);
    assert_eq!(matches[0].pattern, "github_token");
    assert_eq!(matches[1].pattern, "aws_access_key_id");
    assert_eq!(matches[2].pattern, "gitlab_pat");
}

// ---------------------------------------------------------------------------
// Overlap
// ---------------------------------------------------------------------------

#[test]
fn overlapping_matches_keep_the_stronger_rule() {
    let rules = builtin();
    // The assignment heuristic and the GitHub rule both cover the value.
    let matches = scan(
        "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz",
        &rules,
        &KEY,
    );
    assert_eq!(matches.len(), 1, "{matches:?}");
    assert_eq!(matches[0].pattern, "github_token");
    assert_eq!(matches[0].confidence, Confidence::Strong);
}

#[test]
fn a_bearer_header_carrying_a_jwt_is_one_finding() {
    let rules = builtin();
    let text = format!("Authorization: Bearer {}", vector("jwt").value);
    let matches = scan(&text, &rules, &KEY);
    assert_eq!(matches.len(), 1, "{matches:?}");
    assert_eq!(matches[0].pattern, "jwt");
}

#[test]
fn the_aws_pair_on_one_line_is_two_findings() {
    let rules = builtin();
    let text =
        "AKIAIOSFODNN7EXAMPLE aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let matches = scan(text, &rules, &KEY);
    assert_eq!(matches.len(), 2, "{matches:?}");
    assert_eq!(matches[0].pattern, "aws_access_key_id");
    assert_eq!(matches[1].pattern, "aws_secret_access_key");
}

// ---------------------------------------------------------------------------
// Configuration: patterns, allowlist, flags
// ---------------------------------------------------------------------------

fn config_with(patterns: Vec<CustomPattern>, allowlist: Vec<String>) -> Config {
    Config {
        patterns,
        allowlist,
        ..Config::default()
    }
}

fn custom(name: &str, regex: &str, strong: bool) -> CustomPattern {
    CustomPattern {
        name: name.to_string(),
        regex: regex.to_string(),
        label: None,
        strong,
    }
}

#[test]
fn a_custom_pattern_scans_and_appears_in_the_rule_list() {
    let config = config_with(
        vec![
            custom("acme_internal", r"ACME-[0-9]{8}-[A-Z]{4}", true),
            custom("acme_hint", r"internal-hint-[0-9]{4}", false),
        ],
        Vec::new(),
    );
    let rules = Rules::compile(&config).expect("compiles");
    assert!(rules
        .names
        .contains(&("acme_internal".to_string(), Confidence::Strong)));
    assert!(rules
        .names
        .contains(&("acme_hint".to_string(), Confidence::Weak)));

    let matches = scan("token ACME-01234567-ABCD here", &rules, &KEY);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].pattern, "acme_internal");
    assert_eq!(matches[0].label, "acme_internal");
    assert_eq!(matches[0].confidence, Confidence::Strong);
    assert_eq!(matches[0].value_len, 18);

    let weak = scan("internal-hint-4242", &rules, &KEY);
    assert_eq!(weak.len(), 1);
    assert_eq!(weak[0].confidence, Confidence::Weak);
}

#[test]
fn a_custom_pattern_can_carry_a_human_label() {
    let config = config_with(
        vec![CustomPattern {
            name: "acme_internal".to_string(),
            regex: r"ACME-[0-9]{8}".to_string(),
            label: Some("ACME internal token".to_string()),
            strong: true,
        }],
        Vec::new(),
    );
    let rules = Rules::compile(&config).expect("compiles");
    let matches = scan("ACME-01234567", &rules, &KEY);
    assert_eq!(matches[0].label, "ACME internal token");
}

#[test]
fn a_malformed_user_regex_is_a_hard_error_that_names_the_pattern() {
    let config = config_with(
        vec![custom("acme_broken", r"ACME-([0-9]{8}", true)],
        Vec::new(),
    );
    let error = Rules::compile(&config)
        .expect_err("must not compile")
        .to_string();
    assert!(error.contains("acme_broken"), "error was: {error}");
}

#[test]
fn a_user_regex_that_matches_the_empty_string_is_rejected() {
    for pattern in [r"[0-9]*", r"(?:ACME-[0-9]+)?", r"^"] {
        let config = config_with(vec![custom("acme_empty", pattern, true)], Vec::new());
        let error = Rules::compile(&config)
            .expect_err("must not compile")
            .to_string();
        assert!(error.contains("acme_empty"), "error was: {error}");
        assert!(error.contains("empty string"), "error was: {error}");
    }
}

#[test]
fn a_malformed_allowlist_entry_is_a_hard_error_that_names_it() {
    let config = config_with(Vec::new(), vec![r"noisy-([a-z".to_string()]);
    let error = Rules::compile(&config)
        .expect_err("must not compile")
        .to_string();
    assert!(error.contains("noisy-(["), "error was: {error}");
}

#[test]
fn the_allowlist_suppresses_a_finding_by_its_value() {
    let config = config_with(
        Vec::new(),
        vec!["0123456789abcdefghijklmnopqrstuvwxyz".to_string()],
    );
    let rules = Rules::compile(&config).expect("compiles");
    assert!(scan(vector("github_token").text, &rules, &KEY).is_empty());
    // A different value from the same rule still reports.
    assert_eq!(
        scan("ghp_zzzz456789abcdefghijklmnopqrstuvwxyz", &rules, &KEY).len(),
        1
    );
}

#[test]
fn the_allowlist_suppresses_a_finding_by_its_line() {
    let config = config_with(Vec::new(), vec!["fixtures/credentials".to_string()]);
    let rules = Rules::compile(&config).expect("compiles");
    let noisy = format!("fixtures/credentials.env: {}", vector("github_token").text);
    assert!(scan(&noisy, &rules, &KEY).is_empty());
    // The same value on a line the allowlist does not cover still reports.
    assert_eq!(scan(vector("github_token").text, &rules, &KEY).len(), 1);
}

#[test]
fn the_assignment_heuristic_can_be_turned_off() {
    let config = Config {
        env_assignments: false,
        ..Config::default()
    };
    let rules = Rules::compile(&config).expect("compiles");
    assert!(!rules.names.iter().any(|(name, _)| name == "env_assignment"));
    assert!(scan("MY_SERVICE_TOKEN=Zx9Qw7Lm2Kd8Rt5Yb3Nc1Vf6", &rules, &KEY).is_empty());
    // Strong rules are unaffected.
    assert_eq!(scan(vector("github_token").text, &rules, &KEY).len(), 1);
}

#[test]
fn the_entropy_flag_changes_nothing_and_says_so() {
    let quiet = Rules::compile(&Config::default()).expect("compiles");
    assert!(quiet.notes.is_empty());

    let config = Config {
        entropy: true,
        ..Config::default()
    };
    let rules = Rules::compile(&config).expect("compiles");
    assert_eq!(rules.notes.len(), 1);
    assert!(rules.notes[0].contains("entropy"));
    assert!(scan(NEGATIVE, &rules, &KEY).is_empty());
}

#[test]
fn the_rule_list_is_stable_and_deduplicated() {
    let first = Rules::builtin().names;
    let second = Rules::compile(&Config::default()).expect("compiles").names;
    assert_eq!(first, second);
    assert!(!first.is_empty());
    for (index, (name, _)) in first.iter().enumerate() {
        assert!(
            !first[index + 1..].iter().any(|(other, _)| other == name),
            "`{name}` is listed twice"
        );
    }
    // Custom patterns are appended after the built-ins, in config order.
    let config = config_with(
        vec![custom("acme_internal", r"ACME-[0-9]{8}", true)],
        Vec::new(),
    );
    let extended = Rules::compile(&config).expect("compiles").names;
    assert_eq!(extended[..first.len()], first[..]);
    assert_eq!(extended.last().unwrap().0, "acme_internal");
}

// ---------------------------------------------------------------------------
// Degenerate input
// ---------------------------------------------------------------------------

#[test]
fn degenerate_input_neither_panics_nor_reports() {
    let rules = builtin();
    let ansi = "\u{1b}[2J\u{1b}[H\u{1b}[38;5;196m\u{1b}[0m".repeat(500);
    for text in [
        String::new(),
        "\n".to_string(),
        "\n\n\n\n\n".to_string(),
        "\0\0\0".to_string(),
        "a\0b=\0\0\0\0\0\0".to_string(),
        ansi,
        "\r\n\r\n".to_string(),
        "\u{2026}\u{1f512}\u{fe0f}".repeat(100),
        "=".repeat(10_000),
        "\\ud83d\\ude00 lone surrogate escapes are just text".to_string(),
    ] {
        let matches = scan(&text, &rules, &KEY);
        assert!(matches.is_empty(), "unexpected findings in {matches:?}");
    }
}

#[test]
fn a_one_megabyte_line_scans_quickly_and_still_finds_the_token() {
    let rules = builtin();
    let mut text = String::with_capacity(1_100_000);
    text.push_str("| ");
    while text.len() < 1_000_000 {
        text.push_str("0f8a2c4e6b1d3f5a7c9e0b2d4f6a8c1e3b5d7f9a0c2e4b6d8f1a3c5e7b9d0f2a");
    }
    text.push(' ');
    text.push_str("ghp_0123456789abcdefghijklmnopqrstuvwxyz");

    let started = Instant::now();
    let matches = scan(&text, &rules, &KEY);
    let elapsed = started.elapsed();

    assert_eq!(matches.len(), 1, "{matches:?}");
    assert_eq!(matches[0].pattern, "github_token");
    assert_eq!(matches[0].line, 1);
    // A real scan of this takes single-digit milliseconds; the bound is loose
    // only so a loaded CI runner cannot make the suite flaky.
    assert!(elapsed.as_secs() < 5, "1 MB scan took {elapsed:?}");
}

#[test]
fn many_lines_scan_quickly() {
    let rules = builtin();
    let text = NEGATIVE.repeat(80);
    let started = Instant::now();
    assert!(scan(&text, &rules, &KEY).is_empty());
    assert!(
        started.elapsed().as_secs() < 5,
        "{} bytes took too long",
        text.len()
    );
}

/// A flood of weak matches must not be able to hide a strong one, and a scan
/// that stopped looking has to be able to say so.
///
/// The cap used to be one budget shared by every rule, checked in a loop over
/// the rules in declaration order, so 2 000 `AROA…` lines from an early rule
/// meant `github_token` — declared later — never ran at all. The pane looked
/// clean of tokens because nothing had looked.
#[test]
fn a_flood_of_weak_matches_neither_starves_a_strong_rule_nor_passes_in_silence() {
    let rules = builtin();
    let mut text = String::new();
    for index in 0..2_100 {
        text.push_str(&format!("AROAZ3MXVX7QJH2W{index:04}\n"));
    }
    text.push_str("ghp_0123456789abcdefghijklmnopqrstuvwxyz\n");

    let scanned = scan_reporting(&text, &rules, &KEY);
    assert!(
        scanned
            .matches
            .iter()
            .any(|found| found.pattern == "github_token"),
        "the token was hidden by the flood"
    );

    // The prolific rule is capped, and only that rule.
    let principals = scanned
        .matches
        .iter()
        .filter(|found| found.pattern == "aws_principal_id")
        .count();
    assert!(principals > 0 && principals < 2_100, "{principals} kept");

    // And the truncation is said out loud, naming the rule that stopped.
    assert_eq!(scanned.notes.len(), 1, "{:?}", scanned.notes);
    assert!(
        scanned.notes[0].contains("aws_principal_id"),
        "{:?}",
        scanned.notes
    );

    // A scan that ran to completion says nothing.
    assert!(scan_reporting(NEGATIVE, &rules, &KEY).notes.is_empty());
    assert!(scan_reporting(vector("github_token").text, &rules, &KEY)
        .notes
        .is_empty());
    // `scan` is `scan_reporting` with the notes dropped.
    assert_eq!(scan(&text, &rules, &KEY), scanned.matches);
}

#[test]
fn scanning_is_deterministic() {
    let rules = builtin();
    let text = POSITIVE
        .iter()
        .map(|vector| vector.text)
        .collect::<Vec<_>>()
        .join("\n");
    let first = scan(&text, &rules, &KEY);
    let second = scan(&text, &rules, &KEY);
    assert_eq!(first, second);
    assert!(first.len() >= POSITIVE.len() - 1);
}

#[test]
fn the_digest_is_keyed() {
    let rules = builtin();
    let other: DigestKey = [9u8; 16];
    let mine = scan(vector("github_token").text, &rules, &KEY);
    let theirs = scan(vector("github_token").text, &rules, &other);
    assert_ne!(mine[0].digest, theirs[0].digest);
    assert_eq!(mine[0].preview, theirs[0].preview);
}

#[test]
fn the_same_value_twice_is_two_findings_on_two_lines() {
    let rules = builtin();
    let matches = scan(
        &format!(
            "{}\n{}",
            vector("github_token").text,
            vector("github_token").text
        ),
        &rules,
        &KEY,
    );
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].line, 1);
    assert_eq!(matches[1].line, 2);
    assert_eq!(matches[0].digest, matches[1].digest);
}

/// The matches a `Match` is built from all agree with each other: a caller can
/// trust `value_len` without ever seeing the value.
#[test]
fn value_len_counts_characters_not_bytes() {
    let config = config_with(
        vec![custom("acme_unicode", r"ACME-[\p{L}]{6}", true)],
        Vec::new(),
    );
    let rules = Rules::compile(&config).expect("compiles");
    let matches = scan("ACME-héllos", &rules, &KEY);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].value_len, 11);
}
