//! The scanner: a pure function over a string.
//!
//! # Contract
//!
//! * [`scan`] is pure. Same text, same rules, same key ⇒ same matches. It does
//!   no I/O, reads no clock, and touches no global state.
//! * A matched value **never leaves this module**. [`Match`] carries a masked
//!   preview, a length and a keyed digest. There is no field it could leave in.
//! * Precision over recall, always. A rule that fires on ordinary developer
//!   output is worse than no rule, because a scanner that cries wolf gets
//!   uninstalled and then protects nothing.
//!
//! # How precision is bought
//!
//! Three mechanisms, applied to every rule that wants them:
//!
//! * **Token boundaries.** `\b` treats `-`, `/`, `+` and `=` as boundaries, so a
//!   provider prefix sitting inside a base64 blob would match on its own. The
//!   `standalone` check additionally rejects a match whose neighbouring
//!   character is one of those, which is what keeps a pasted PNG quiet.
//! * **Structural validation.** A JWT is only a JWT when its header segment
//!   base64url-decodes to a JSON object containing `alg`; an AWS access key ID
//!   has to look like base32 output rather than a run of one letter. These are
//!   checks the regex engine cannot express, so they run afterwards.
//! * **Placeholder rejection.** The `.env`-style heuristic reports a value only
//!   when the value could plausibly *be* a credential — see
//!   `plausible_secret_value`, which is most of the work of that rule.
//!
//! # The reported span is the validated span
//!
//! A rule whose value has to be trimmed before it can be validated — the
//! assignment heuristic captures to end of line, so it picks up trailing
//! whitespace and a trailing comma — reports the *trimmed* span, not the raw
//! capture. Validating one string and reporting another would mean the preview,
//! the length and the digest all describe text the check never looked at, and
//! the digest is the identity of a finding: `TOKEN=abc` and `TOKEN=abc,` would
//! be two findings for one secret, so acknowledging one would leave the other
//! lit. See `narrow_span`.
//!
//! # Masking policy
//!
//! [`mask`] shows at most the first four and the last four characters, and never
//! more than a third of the value: `k = min(4, len / 6)`, and `k == 0` renders as
//! a bare ellipsis. A four-character value therefore never renders as itself.
//! The preview is the only rendering of a value that ever leaves this module, so
//! it is deliberately conservative.
//!
//! # Entropy
//!
//! `config.entropy` is **not implemented**. A Shannon-entropy heuristic over
//! terminal output is the false-positive machine this plugin exists to avoid
//! being, and there is no version of it that survives a page of base64 or a
//! minified bundle. Setting the flag is not an error, but it changes nothing:
//! [`Rules::compile`] records a note saying so.

use regex::{Captures, Regex, RegexBuilder};

use crate::config::Config;
use crate::model::{digest, Confidence, DigestKey, Match};
use crate::Result;

/// Ceiling on matches from one *rule* in one scan. A pane that produces more
/// than this from a single pattern is already a catastrophe rather than a
/// finding, and the cap keeps the candidate list bounded on adversarial input.
///
/// Per-rule rather than per-scan on purpose. A single ceiling across all rules
/// meant a flood of weak matches from an early rule could stop every later rule
/// from running at all, so 2 000 lines of `AROA…` could hide a GitHub token
/// completely. Every rule now gets its own budget, and a rule that exhausts one
/// says so in [`Scan::notes`] instead of truncating in silence.
const MAX_MATCHES_PER_RULE: usize = 500;

/// Compiled size ceiling for a user-supplied regex, so a pathological pattern
/// cannot eat memory at compile time.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/// Extra check on a match that the regex engine cannot express.
type Check = fn(&Captures<'_>) -> bool;

/// One compiled rule.
#[derive(Debug)]
struct Rule {
    name: String,
    label: String,
    confidence: Confidence,
    regex: Regex,
    /// Capture groups holding the value, most specific first; the first one that
    /// participated in the match wins. `[0]` means "the whole match".
    ///
    /// Rules with alternative quoting (`FOO=bar`, `FOO="bar"`, `FOO='bar'`) use
    /// this so that the reported span is the value itself and never the quotes.
    groups: Vec<usize>,
    /// Reject a match whose neighbouring character could make it part of a
    /// longer token — the base64-blob defence.
    standalone: bool,
    /// Report the trimmed value rather than the raw capture, for rules whose
    /// value is validated by `plausible_secret_value` — which trims before it
    /// looks. See `narrow_span`.
    narrow_value: bool,
    check: Option<Check>,
}

impl Rule {
    fn new(name: &str, label: &str, confidence: Confidence, pattern: &str) -> Self {
        Self {
            name: name.to_string(),
            label: label.to_string(),
            confidence,
            regex: Regex::new(pattern).expect("built-in pattern is valid"),
            groups: vec![0],
            standalone: false,
            narrow_value: false,
            check: None,
        }
    }

    fn groups(mut self, groups: &[usize]) -> Self {
        self.groups = groups.to_vec();
        self
    }

    fn standalone(mut self) -> Self {
        self.standalone = true;
        self
    }

    fn narrowed(mut self) -> Self {
        self.narrow_value = true;
        self
    }

    fn check(mut self, check: Check) -> Self {
        self.check = Some(check);
        self
    }

    /// Span of the value this rule reports, or `None` when no candidate group
    /// participated in the match.
    fn value<'t>(&self, caps: &Captures<'t>) -> Option<regex::Match<'t>> {
        self.groups.iter().find_map(|&group| caps.get(group))
    }
}

/// The compiled rule set: built-in provider patterns, the user's extra patterns,
/// and the allowlist that suppresses both.
#[derive(Debug, Default)]
pub struct Rules {
    /// Reported by `--rules` so a user can see what is actually active.
    pub names: Vec<(String, Confidence)>,
    /// Things the caller should tell the user about the rule set itself, such as
    /// a configuration flag that does nothing. Never contains a value.
    pub notes: Vec<String>,
    rules: Vec<Rule>,
    allowlist: Vec<Regex>,
}

impl Rules {
    /// Compiles the built-ins plus the user's `patterns` and `allowlist`.
    ///
    /// A malformed user regex is a hard error: the user typed it, they are
    /// looking right at it, and a silently dropped rule is a rule they think is
    /// protecting them. Callers that must keep running (the daemon) fall back to
    /// [`Rules::builtin`] and say so.
    pub fn compile(config: &Config) -> Result<Self> {
        let mut rules = builtin_rules(config.env_assignments);

        for pattern in &config.patterns {
            let name = pattern.name.trim();
            if name.is_empty() {
                return Err(format!("pattern `{}` has an empty name", pattern.regex).into());
            }
            let regex =
                user_regex(&pattern.regex).map_err(|err| format!("pattern `{name}`: {err}"))?;
            // A pattern that can match nothing at all would report a finding at
            // every position in the pane, which is worse than no rule.
            if regex.is_match("") {
                return Err(format!(
                    "pattern `{name}` matches the empty string, which would report a finding at every position"
                )
                .into());
            }
            rules.push(Rule {
                name: name.to_string(),
                label: pattern.label.clone().unwrap_or_else(|| name.to_string()),
                confidence: if pattern.strong {
                    Confidence::Strong
                } else {
                    Confidence::Weak
                },
                regex,
                groups: vec![0],
                standalone: false,
                narrow_value: false,
                check: None,
            });
        }

        let mut allowlist = Vec::with_capacity(config.allowlist.len());
        for entry in &config.allowlist {
            allowlist.push(
                user_regex(entry).map_err(|err| format!("allowlist entry `{entry}`: {err}"))?,
            );
        }

        let mut notes = Vec::new();
        if config.entropy {
            notes.push(
                "the entropy heuristic is not implemented; `entropy = true` has no effect"
                    .to_string(),
            );
        }

        Ok(Self {
            names: names_of(&rules),
            notes,
            rules,
            allowlist,
        })
    }

    /// The built-in rules alone, with no user configuration. Cannot fail.
    pub fn builtin() -> Self {
        let rules = builtin_rules(true);
        Self {
            names: names_of(&rules),
            notes: Vec::new(),
            rules,
            allowlist: Vec::new(),
        }
    }

    /// A finding is dropped when the allowlist matches either the matched value
    /// or the whole line it was found on.
    fn allowed(&self, value: &str, line: &str) -> bool {
        self.allowlist
            .iter()
            .any(|entry| entry.is_match(value) || entry.is_match(line))
    }
}

fn user_regex(pattern: &str) -> std::result::Result<Regex, regex::Error> {
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
}

/// Rule names in declaration order, built-ins first, one entry per machine name.
fn names_of(rules: &[Rule]) -> Vec<(String, Confidence)> {
    let mut names: Vec<(String, Confidence)> = Vec::with_capacity(rules.len());
    for rule in rules {
        if !names.iter().any(|(name, _)| name == &rule.name) {
            names.push((rule.name.clone(), rule.confidence));
        }
    }
    names
}

// ---------------------------------------------------------------------------
// The built-in rule set
// ---------------------------------------------------------------------------

/// Every built-in rule, in the order `--rules` prints them.
///
/// Deliberately **not** shipped, because none of them can be matched precisely
/// enough to be worth the false positives:
///
/// * Stripe `sk_test_`/`rk_test_` — test keys live in public documentation, CI
///   fixtures and sample apps, and leaking one costs nothing. Firing on them is
///   pure cry-wolf.
/// * Twilio — the `AC…`/`SK…` SIDs are identifiers rather than secrets, and the
///   auth token is 32 bare hex characters, indistinguishable from a git blob id.
/// * Cloudflare API tokens — 40 characters of `[A-Za-z0-9_-]` with no prefix.
/// * Generic 32/40-character hex or base64 "keys" with no context.
fn builtin_rules(env_assignments: bool) -> Vec<Rule> {
    let mut rules = vec![
        // AWS access key IDs are base32, so the tail is uppercase alphanumeric.
        // `check` rejects a run of a single character, which is what a redacted
        // key or an ASCII banner looks like.
        //
        // `AKIA` (long-term) and `ASIA` (temporary) are the only two prefixes
        // that introduce something a caller can authenticate with. The rest of
        // the `A…A` family is split out below.
        Rule::new(
            "aws_access_key_id",
            "AWS access key ID",
            Confidence::Strong,
            r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        )
        .standalone()
        .check(has_varied_body),
        // `AIDA`, `AROA` and friends are unique *identifiers* for a user, role,
        // group or managed policy. They are not credentials: `aws sts
        // get-caller-identity` and most IAM output print them in the clear, all
        // day, and treating them as a secret is the cry-wolf failure this plugin
        // exists to avoid. They are still worth a quiet word, because an
        // identifier in a screenshot tells a reader which account they are
        // looking at — so `Weak`, and labelled as an identifier.
        Rule::new(
            "aws_principal_id",
            "AWS principal ID (identifier, not a credential)",
            Confidence::Weak,
            r"\b(?:AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16,17}",
        )
        .standalone()
        .check(has_varied_body),
        // Forty base64 characters on their own is a false-positive machine, so
        // this one only fires next to the key name that AWS itself uses.
        Rule::new(
            "aws_secret_access_key",
            "AWS secret access key",
            Confidence::Strong,
            r#"(?i)aws[_-]?secret[_-]?access[_-]?key["']?[ \t]*[:=][ \t]*["']?([A-Za-z0-9/+=]{40})"#,
        )
        .groups(&[1]),
        Rule::new(
            "github_token",
            "GitHub token",
            Confidence::Strong,
            r"\bgh[pousr]_[A-Za-z0-9]{36,}",
        )
        .standalone(),
        Rule::new(
            "github_pat",
            "GitHub fine-grained token",
            Confidence::Strong,
            r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
        )
        .standalone(),
        Rule::new(
            "anthropic_api_key",
            "Anthropic API key",
            Confidence::Strong,
            r"\bsk-ant-[A-Za-z0-9_-]{32,}",
        )
        .standalone(),
        // The rule most likely to fire on prose, so both forms demand the full
        // charset: `sk-learn` and `sk-ms-version` fall out immediately.
        Rule::new(
            "openai_api_key",
            "OpenAI API key",
            Confidence::Strong,
            r"\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{48})",
        )
        .standalone(),
        Rule::new(
            "stripe_secret_key",
            "Stripe live secret key",
            Confidence::Strong,
            r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}",
        )
        .standalone(),
        Rule::new(
            "slack_token",
            "Slack token",
            Confidence::Strong,
            r"\bxox[baprs]-[A-Za-z0-9-]{12,}",
        )
        .standalone(),
        Rule::new(
            "google_api_key",
            "Google API key",
            Confidence::Strong,
            r"\bAIza[A-Za-z0-9_-]{35}",
        )
        .standalone(),
        // Google's OAuth client secrets have carried this prefix since 2021,
        // which is the only reason this rule is precise enough to ship.
        Rule::new(
            "google_oauth_client_secret",
            "Google OAuth client secret",
            Confidence::Strong,
            r"\bGOCSPX-[A-Za-z0-9_-]{28}",
        )
        .standalone(),
        // `eyJ` is base64url for `{"`, so every real JWT header starts with it.
        // `check` then insists the header actually decodes to JSON with `alg`.
        Rule::new(
            "jwt",
            "JSON Web Token",
            Confidence::Strong,
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        )
        .standalone()
        .check(is_jwt),
        // The trailing block is optional so a key truncated by the pane's line
        // budget still reports, which is exactly when it matters most.
        Rule::new(
            "private_key_block",
            "Private key block",
            Confidence::Strong,
            r"-----BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY(?: BLOCK)?-----(?s:.*?-----END [A-Z0-9 ]{0,32}PRIVATE KEY(?: BLOCK)?-----)?",
        ),
        Rule::new(
            "slack_webhook_url",
            "Slack webhook URL",
            Confidence::Strong,
            r"https://hooks\.slack\.com/services/[A-Za-z0-9]{8,}/[A-Za-z0-9]{8,}/[A-Za-z0-9]{20,}",
        ),
        Rule::new(
            "npm_token",
            "npm access token",
            Confidence::Strong,
            r"\bnpm_[A-Za-z0-9]{36}",
        )
        .standalone(),
        Rule::new(
            "pypi_token",
            "PyPI API token",
            Confidence::Strong,
            r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,}",
        )
        .standalone(),
        Rule::new(
            "sendgrid_api_key",
            "SendGrid API key",
            Confidence::Strong,
            r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        )
        .standalone(),
        Rule::new(
            "gitlab_pat",
            "GitLab personal access token",
            Confidence::Strong,
            r"\bglpat-[A-Za-z0-9_-]{20,}",
        )
        .standalone(),
        Rule::new(
            "huggingface_token",
            "Hugging Face token",
            Confidence::Strong,
            r"\bhf_[A-Za-z0-9]{34,}",
        )
        .standalone(),
        // The private half of an age keypair. The public half — `age1…`, the
        // recipient — is printed by `age-keygen` next to this one, appears in
        // every `.sops.yaml` and in every README that explains age, and is not
        // a secret; only this prefix is. Bech32, so the body excludes `1`, `B`,
        // `I` and `O`, and 58 characters is exactly what a 32-byte key encodes
        // to: the shape is rigid enough for `Strong`.
        Rule::new(
            "age_secret_key",
            "age secret key",
            Confidence::Strong,
            r"\bAGE-SECRET-KEY-1[02-9A-HJ-NP-Z]{58}\b",
        )
        .standalone(),
        // JDBC permits credentials in both URL query parameters and its
        // semicolon-delimited property form. The `jdbc:` anchor is what makes a
        // strong claim possible; a generic `password=` matcher would not be.
        Rule::new(
            "jdbc_url_password",
            "JDBC URL password",
            Confidence::Strong,
            r#"(?i)\bjdbc:[^\s]*[?&;]password=([^\s&#;"']+)"#,
        )
        .groups(&[1])
        .narrowed()
        .check(is_secret_capture),
        // Docker stores registry credentials as base64(username:password).
        // Checking the decoded shape keeps unrelated base64 fields and image
        // layers from becoming findings merely because they sit next to `auth`.
        Rule::new(
            "docker_registry_auth",
            "Docker registry auth",
            Confidence::Strong,
            r#""auth"[ \t]*:[ \t]*"([A-Za-z0-9+/]{8,}={0,2})""#,
        )
        .groups(&[1])
        .check(is_docker_registry_auth),
        // Modern Vault service, batch and recovery tokens carry provider-owned
        // prefixes. The legacy `s.` prefix is too short to support Strong.
        Rule::new(
            "vault_token",
            "Vault token",
            Confidence::Strong,
            r"\b(?:hvs|hvb|hvr)\.[A-Za-z0-9_-]{24,}",
        )
        .standalone(),
        // Weak, not Strong: `postgres://user:pass@host/db` is what every README
        // and every connection-string example in the world looks like. The
        // password still has to survive the placeholder filter, which is what
        // keeps `https://user:password@host` quiet.
        Rule::new(
            "url_credentials",
            "URL with embedded credentials",
            Confidence::Weak,
            r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,15}://[^\s/:@]{1,64}:([^\s/:@]{1,128})@",
        )
        .groups(&[1])
        .narrowed()
        .check(is_secret_capture),
        // Agents print `curl -H "Authorization: Bearer …"` constantly, which is
        // the motivating example in the crate docs.
        Rule::new(
            "http_bearer_token",
            "HTTP bearer token",
            Confidence::Weak,
            r"(?i)authorization[ \t]*:[ \t]*bearer[ \t]+([A-Za-z0-9._~+/=-]{16,})",
        )
        .groups(&[1])
        .narrowed()
        .check(is_secret_capture),
    ];

    if env_assignments {
        // `NAME=value`, anchored to the start of a line. The anchor is a large
        // part of the precision: `let api_key = compute()` inside a source file
        // never starts a line with the name.
        rules.push(
            Rule::new(
                "env_assignment",
                "Secret-looking assignment",
                Confidence::Weak,
                r#"(?m)^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\r\n]*))"#,
            )
            .groups(&[2, 3, 4])
            .narrowed()
            .check(is_secret_assignment),
        );
        // `name: value` (YAML) and `"name": "value"` (JSON). The mandatory space
        // after the colon is what keeps `arn:aws:iam::…` and `https://…` out.
        rules.push(
            Rule::new(
                "env_assignment",
                "Secret-looking assignment",
                Confidence::Weak,
                r#"(?m)^[ \t-]*"?([A-Za-z_][A-Za-z0-9_.-]*)"?[ \t]*:[ \t]+(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\r\n]*))"#,
            )
            .groups(&[2, 3, 4])
            .narrowed()
            .check(is_secret_assignment),
        );
    }

    rules
}

// ---------------------------------------------------------------------------
// Structural checks
// ---------------------------------------------------------------------------

/// AWS key IDs and principal IDs are base32 output, so a run of one character
/// after the prefix is a redaction, a banner, or somebody's placeholder — never
/// a real identifier.
fn has_varied_body(caps: &Captures<'_>) -> bool {
    let value = &caps[0];
    let tail = &value[4..];
    !tail.bytes().all(|byte| byte == tail.as_bytes()[0])
}

/// A JWT is only a JWT when its header segment base64url-decodes to a JSON
/// object carrying `alg`. Everything else that happens to have two dots in it —
/// version strings, file names, base64 blobs — fails here.
fn is_jwt(caps: &Captures<'_>) -> bool {
    let value = &caps[0];
    let Some((header, _)) = value.split_once('.') else {
        return false;
    };
    let Some(bytes) = base64url_decode(header) else {
        return false;
    };
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    json.get("alg").is_some_and(|alg| alg.is_string())
}

/// Group 1 has to look like a credential rather than a placeholder.
fn is_secret_capture(caps: &Captures<'_>) -> bool {
    caps.get(1)
        .is_some_and(|value| plausible_secret_value(value.as_str()))
}

/// Docker's `auth` value is standard base64 for `username:password`. Requiring
/// exactly one separator and applying the ordinary placeholder filter to the
/// password half distinguishes a credential from arbitrary encoded payloads.
fn is_docker_registry_auth(caps: &Captures<'_>) -> bool {
    let Some(value) = caps.get(1) else {
        return false;
    };
    let Some(bytes) = base64_decode(value.as_str()) else {
        return false;
    };
    let Ok(decoded) = std::str::from_utf8(&bytes) else {
        return false;
    };
    let Some((_, password)) = decoded.split_once(':') else {
        return false;
    };
    !password.contains(':') && plausible_secret_value(password)
}

/// Standard base64 with optional padding. Reject non-canonical trailing bits so
/// malformed payloads cannot accidentally decode into credential-shaped text.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let padding = bytes.iter().rev().take_while(|&&byte| byte == b'=').count();
    if padding > 2 || bytes.len() % 4 == 1 || (padding > 0 && !bytes.len().is_multiple_of(4)) {
        return None;
    }
    let encoded_len = bytes.len() - padding;
    if (padding == 1 && encoded_len % 4 != 3) || (padding == 2 && encoded_len % 4 != 2) {
        return None;
    }

    let mut out = Vec::with_capacity(encoded_len * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &byte in &bytes[..encoded_len] {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    if bits > 0 && buffer & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

/// Group 1 is the name, groups 2–4 are the quoting alternatives for the value.
/// Both halves have to look secret-ish, which is what makes this heuristic
/// survivable at all.
fn is_secret_assignment(caps: &Captures<'_>) -> bool {
    let Some(name) = caps.get(1) else {
        return false;
    };
    if !secretish_name(name.as_str()) {
        return false;
    }
    (2..=4)
        .filter_map(|group| caps.get(group))
        .next()
        .is_some_and(|value| plausible_secret_value(value.as_str()))
}

/// Base64url, no padding required. `None` for anything outside the alphabet,
/// which is most of what a naive JWT regex picks up.
fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => break,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// The `.env`-style heuristic
// ---------------------------------------------------------------------------

/// Underscore-delimited segments that make a name secret-ish.
const SECRET_SEGMENTS: &[&str] = &[
    "TOKEN",
    "TOKENS",
    "SECRET",
    "SECRETS",
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "CREDENTIAL",
    "CREDENTIALS",
    "APIKEY",
    "APIKEYS",
    "PRIVATEKEY",
    "SECRETKEY",
    "ACCESSKEY",
    "PAT",
];

/// Segments that make a trailing `KEY` a credential: `API_KEY`, `SECRET_KEY`,
/// `PRIVATE_KEY`, `ACCESS_KEY`, `AUTH_KEY`, `MASTER_KEY`.
///
/// A bare `*_KEY` is deliberately **not** enough. "Key" is the most overloaded
/// word in a terminal, and every one of these is ordinary output that used to
/// be reported as a credential: `GPG_KEY=…` (a *public* fingerprint, printed by
/// `env` in every official `python:3.x` image), `CACHE_KEY=…` (GitHub Actions,
/// CircleCI), `cache_key:`, `routing_key:` (RabbitMQ, Celery),
/// `partition_key:` (Kafka, DynamoDB), `idempotency_key:` (every payments SDK),
/// `app_key:`, `bucket_key:`, and `age_key: age1…` — which is the *public* half
/// of an age keypair, the one case where warning about the wrong half is worse
/// than saying nothing.
///
/// The price is that `SIGNING_KEY=…` and `ENCRYPTION_KEY=…` no longer report
/// from their name alone. That is deliberate: this is a weak heuristic, both of
/// those names are also used for public verification keys and for key *ids*,
/// and a scanner that cries wolf gets uninstalled and then protects nothing.
/// Please do not "fix" it back — add the name to your own `patterns` instead.
const KEY_QUALIFIERS: &[&str] = &["API", "SECRET", "PRIVATE", "ACCESS", "AUTH", "MASTER"];

/// Segments that disqualify a name outright. `PUBLIC_KEY` is not a secret,
/// `TOKEN_FILE` is a path to one, and `TEST_TOKEN` is somebody's fixture.
const INNOCENT_SEGMENTS: &[&str] = &[
    "PUBLIC",
    "PUB",
    "PATH",
    "FILE",
    "FILENAME",
    "DIR",
    "URL",
    "URI",
    "ID",
    "IDS",
    "NAME",
    "HINT",
    "EXAMPLE",
    "SAMPLE",
    "TEST",
    "FAKE",
    "LENGTH",
    "TYPE",
    "ALGORITHM",
    "ALG",
    "TTL",
    "EXPIRY",
];

/// Values that are obviously not credentials no matter what the name says.
const STOP_VALUES: &[&str] = &[
    "true",
    "false",
    "yes",
    "no",
    "on",
    "off",
    "none",
    "null",
    "nil",
    "undefined",
    "empty",
    "unset",
    "default",
    "local",
    "localhost",
    "debug",
    "info",
    "warn",
    "warning",
    "error",
    "trace",
    "latest",
    "stable",
    "main",
    "master",
    "auto",
    "disabled",
    "enabled",
];

/// Substrings that mark a value as a placeholder rather than a credential.
const PLACEHOLDER_FRAGMENTS: &[&str] = &[
    "change",
    "redact",
    "placeholder",
    "example",
    "your",
    "dummy",
    "sample",
    "insert",
    "here",
    "todo",
    "tbd",
    "xxxx",
    "secret",
    "password",
    "passwd",
    "token",
    "apikey",
];

/// Shorter than this and it cannot be a credential worth warning about.
const MIN_VALUE_LEN: usize = 6;

/// Longer than this and it is a payload, not a value.
const MAX_VALUE_LEN: usize = 4_096;

/// Does the *name* of an assignment suggest a credential?
///
/// Whole segments are compared rather than substrings, so `AUTHOR` is not
/// `AUTH` and `KEYBOARD_LAYOUT` is not `KEY`.
fn secretish_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let segments: Vec<&str> = upper
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.iter().any(|s| INNOCENT_SEGMENTS.contains(s)) {
        return false;
    }
    if segments.iter().any(|s| SECRET_SEGMENTS.contains(s)) {
        return true;
    }
    // `API_KEY`, `ACCESS_KEY` — but never a bare `*_KEY`, which is most of
    // what a terminal calls a key. See `KEY_QUALIFIERS`.
    let [.., qualifier, "KEY" | "KEYS"] = segments.as_slice() else {
        return false;
    };
    KEY_QUALIFIERS.contains(qualifier)
}

/// Could this *value* plausibly be a credential?
///
/// Ruling out placeholders is most of the work of the assignment heuristic, so
/// this errs hard towards "no". Every rejection below corresponds to something
/// that shows up in real terminal output all day.
fn plausible_secret_value(value: &str) -> bool {
    let value = narrow(value);

    if value.len() < MIN_VALUE_LEN || value.len() > MAX_VALUE_LEN {
        return false;
    }
    // Credential alphabets are narrow. `$VAR`, `${VAR}`, `%VAR%`, `***`,
    // `<redacted>`, `os.environ["API_KEY"]` and prose all leave it.
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"_-./+=:~@".contains(&b))
    {
        return false;
    }
    // Paths, relative paths, flags.
    if value.starts_with(['/', '.', '~', '-', '=', ':']) {
        return false;
    }
    // A URL with no userinfo is not a credential; one with userinfo is reported
    // by `url_credentials` instead.
    if value.contains("://") {
        return false;
    }
    // Integers, versions, decimals.
    if value.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return false;
    }
    // A single repeated character: `xxxxxx`, `------`, `000000`.
    if value.bytes().all(|b| b == value.as_bytes()[0]) {
        return false;
    }
    // A file name: `service.json`, `key.pem`.
    if let Some((_, extension)) = value.rsplit_once('.') {
        if (2..=5).contains(&extension.len()) && extension.bytes().all(|b| b.is_ascii_alphabetic())
        {
            return false;
        }
    }
    let lower = value.to_ascii_lowercase();
    if STOP_VALUES.contains(&lower.as_str()) {
        return false;
    }
    if PLACEHOLDER_FRAGMENTS
        .iter()
        .any(|fragment| lower.contains(fragment))
    {
        return false;
    }
    // Real credentials are either mixed alphanumeric or long. A short run of
    // letters is a word.
    value.bytes().any(|b| b.is_ascii_digit()) || value.len() >= 16
}

/// The part of a captured value that is actually the value: surrounding
/// whitespace, one trailing `,` or `;`, and one matching pair of surrounding
/// quotes removed.
///
/// Returned as byte offsets into `raw` so that the *span* the scanner reports
/// can be narrowed to exactly the text the plausibility check validated —
/// see the module docs. Only ASCII bytes are stepped over, so both offsets are
/// always on a character boundary.
fn narrow_span(raw: &str) -> (usize, usize) {
    let bytes = raw.as_bytes();
    let mut start = 0;
    let mut end = raw.len();

    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    // A trailing separator goes too: the same value in a JSON or YAML list and
    // on its own has to be one finding, not two.
    while end > start
        && (bytes[end - 1].is_ascii_whitespace() || matches!(bytes[end - 1], b',' | b';'))
    {
        end -= 1;
    }

    if end - start >= 2 {
        let quote = bytes[start];
        if matches!(quote, b'"' | b'\'') && bytes[end - 1] == quote {
            start += 1;
            end -= 1;
        }
    }
    (start, end)
}

/// `raw` narrowed to the value itself. See [`narrow_span`].
fn narrow(raw: &str) -> &str {
    let (start, end) = narrow_span(raw);
    &raw[start..end]
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/// Characters that would make a match the tail of a longer token. Wider than
/// `\w` on purpose: base64 and base64url are exactly what a provider prefix
/// hides inside.
fn continues_token_before(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '/')
}

/// As above, for the character after a match. `=` counts here and not before it,
/// because base64 padding only ever trails — treating it as a token character on
/// the left would reject every `NAME=ghp_…` assignment, which is one of the
/// places a token is most likely to appear.
fn continues_token_after(c: char) -> bool {
    continues_token_before(c) || c == '='
}

/// Is `text[start..end]` a whole token rather than a slice of a longer one?
fn standalone(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(continues_token_before) && !after.is_some_and(continues_token_after)
}

/// Byte offset of the start of each line, so a match can be turned into a line
/// number with a binary search rather than a rescan.
struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    fn new(text: &str) -> Self {
        let mut starts = Vec::with_capacity(text.len() / 40 + 1);
        starts.push(0);
        starts.extend(text.match_indices('\n').map(|(index, _)| index + 1));
        Self { starts }
    }

    /// 1-based line number containing `byte`.
    fn line_of(&self, byte: usize) -> usize {
        self.starts.partition_point(|&start| start <= byte)
    }

    /// The whole line containing `byte`, without its line ending.
    fn line_text<'t>(&self, text: &'t str, byte: usize) -> &'t str {
        let index = self.line_of(byte) - 1;
        let start = self.starts[index];
        let end = self
            .starts
            .get(index + 1)
            .map_or(text.len(), |&next| next - 1);
        text[start..end].trim_end_matches('\r')
    }
}

/// One surviving match before overlap resolution.
struct Candidate {
    rule: usize,
    start: usize,
    end: usize,
    confidence: Confidence,
}

/// Every credential-shaped thing in `text`, in the order they appear.
///
/// `key` keys the digest that identifies a match across cycles; tests pass a
/// fixed key, the daemon passes the per-installation one.
///
/// When two rules match overlapping spans the stronger one wins, and on a tie
/// the longer one does — a bearer header holding a JWT is one finding, not two.
///
/// This is [`scan_reporting`] with the notes dropped. A caller that shows the
/// user a report should call that instead, so a scan that stopped early can say
/// so rather than looking like a quiet one.
pub fn scan(text: &str, rules: &Rules, key: &DigestKey) -> Vec<Match> {
    scan_reporting(text, rules, key).matches
}

/// What one scan found, and anything the user should know about the scan
/// itself.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Scan {
    /// The findings, in the order they appear in the text.
    pub matches: Vec<Match>,
    /// Things that happened to the *scan*, in the same voice as
    /// [`Rules::notes`]: today, the rules that hit their per-rule ceiling and
    /// therefore stopped looking. Never contains a value. Empty on a scan that
    /// ran to completion, which is nearly all of them.
    pub notes: Vec<String>,
}

/// [`scan`], plus what the scan could not finish. See [`Scan`].
pub fn scan_reporting(text: &str, rules: &Rules, key: &DigestKey) -> Scan {
    if text.is_empty() || rules.rules.is_empty() {
        return Scan::default();
    }

    let mut candidates: Vec<Candidate> = Vec::new();
    let mut truncated: Vec<&str> = Vec::new();
    for (index, rule) in rules.rules.iter().enumerate() {
        let mut found_here = 0usize;
        for caps in rule.regex.captures_iter(text) {
            let Some(found) = rule.value(&caps) else {
                continue;
            };
            // A user pattern can match the empty string at a position even when
            // it does not match the empty *input*; reporting that would put a
            // finding on every byte.
            if found.is_empty() {
                continue;
            }
            // The span the check validated is the span that gets reported.
            let (mut start, mut end) = (found.start(), found.end());
            if rule.narrow_value {
                let (inner_start, inner_end) = narrow_span(found.as_str());
                end = start + inner_end;
                start += inner_start;
                if start == end {
                    continue;
                }
            }
            if rule.standalone && !standalone(text, start, end) {
                continue;
            }
            if let Some(check) = rule.check {
                if !check(&caps) {
                    continue;
                }
            }
            candidates.push(Candidate {
                rule: index,
                start,
                end,
                confidence: rule.confidence,
            });
            found_here += 1;
            // Only this rule stops. A flood of weak matches must not be able to
            // starve a strong rule that has not run yet.
            if found_here >= MAX_MATCHES_PER_RULE {
                if !truncated.contains(&rule.name.as_str()) {
                    truncated.push(&rule.name);
                }
                break;
            }
        }
    }

    let lines = LineIndex::new(text);

    // Allowlisting happens before overlap resolution: suppressing a strong match
    // must not also suppress a weak one that merely overlapped it.
    if !rules.allowlist.is_empty() {
        candidates.retain(|candidate| {
            !rules.allowed(
                &text[candidate.start..candidate.end],
                lines.line_text(text, candidate.start),
            )
        });
    }

    // Strongest first, then longest, then leftmost, then declaration order, so
    // the greedy sweep below keeps the match a human would have picked.
    candidates.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then((b.end - b.start).cmp(&(a.end - a.start)))
            .then(a.start.cmp(&b.start))
            .then(a.rule.cmp(&b.rule))
    });
    // `kept` is disjoint and stays sorted by start, so only the two neighbours
    // of the insertion point can overlap a new candidate. That keeps the sweep
    // near-linear however many candidates the rules produced.
    let mut kept: Vec<Candidate> = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let at = kept.partition_point(|other| other.start <= candidate.start);
        let overlaps_before = at > 0 && kept[at - 1].end > candidate.start;
        let overlaps_after = at < kept.len() && kept[at].start < candidate.end;
        if !overlaps_before && !overlaps_after {
            kept.insert(at, candidate);
        }
    }

    let matches = kept
        .into_iter()
        .map(|candidate| {
            let value = &text[candidate.start..candidate.end];
            let rule = &rules.rules[candidate.rule];
            Match {
                pattern: rule.name.clone(),
                label: rule.label.clone(),
                confidence: rule.confidence,
                preview: mask(value),
                value_len: value.chars().count(),
                line: lines.line_of(candidate.start),
                digest: digest(key, value),
            }
        })
        .collect();

    let notes = truncated
        .into_iter()
        .map(|name| {
            format!(
                "the `{name}` rule stopped after {MAX_MATCHES_PER_RULE} matches in one pane, so \
                 anything it would have found beyond that is missing; every other rule still ran"
            )
        })
        .collect();

    Scan { matches, notes }
}

/// Masked rendering of a value: at most the first four and the last four
/// characters, and never more than about a third of it.
///
/// `k = min(4, len / 6)`, and `k == 0` renders as a bare ellipsis, so a short
/// value — four characters, say — can never render as itself. This is the only
/// rendering of a value that ever leaves this module.
pub fn mask(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let keep = 4.min(chars.len() / 6);
    if keep == 0 {
        return String::from("\u{2026}");
    }
    let mut out = String::with_capacity(keep * 2 + 3);
    out.extend(&chars[..keep]);
    out.push('\u{2026}');
    out.extend(&chars[chars.len() - keep..]);
    out
}
