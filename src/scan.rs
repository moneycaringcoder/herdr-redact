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
//! There is no entropy heuristic. A Shannon-entropy heuristic over terminal
//! output is the false-positive machine this plugin exists to avoid being, and
//! there is no version of it that survives a page of base64 or a minified
//! bundle.

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

/// A structured value may use no more than this many physical lines after its
/// key. This is deliberately small: terminal output is usually a document
/// fragment, and an unterminated quote must not consume the rest of a pane.
const MAX_CONTINUATION_LINES: usize = 8;

const MULTILINE_CREDENTIAL_RULE: &str = "multiline_credential";

/// Compiled size ceiling for a user-supplied regex, so a pathological pattern
/// cannot eat memory at compile time.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/// Extra check on a match that the regex engine cannot express.
type Check = fn(&Captures<'_>) -> bool;
/// A compiled-in group of detection rules. Names and versions are public
/// interface: a pack may gain rules in a later version, but existing rule names
/// never change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RulePack {
    pub name: &'static str,
    pub version: u32,
}

pub const DEFAULT_RULE_PACK: RulePack = RulePack {
    name: "default",
    version: 1,
};

/// Reserved for precise formats whose relevance is too narrow for every user.
///
/// It is intentionally empty today: no shipped rule was demoted from the
/// default pack, so enabling packs cannot weaken existing protection.
pub const NARROW_RULE_PACK: RulePack = RulePack {
    name: "narrow",
    version: 1,
};

const RULE_PACKS: [RulePack; 2] = [DEFAULT_RULE_PACK, NARROW_RULE_PACK];

pub fn rule_packs() -> &'static [RulePack] {
    &RULE_PACKS
}

/// A credential format considered and deliberately not shipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RejectedFormat {
    /// Provider and token kind, e.g. "DigitalOcean personal access token".
    pub format: &'static str,
    /// The prefix or marker it is known by, or "" when it has none.
    pub marker: &'static str,
    /// Why it cannot be matched precisely enough to ship.
    pub reason: &'static str,
}

const REJECTED_FORMATS: [RejectedFormat; 69] = [
    RejectedFormat {
        format: "GitLab pipeline trigger token",
        marker: "glptt-",
        reason: "The prefix is documented but no provider-controlled source establishes the body's length or charset.",
    },
    RejectedFormat {
        format: "GitLab runner authentication token",
        marker: "glrt-",
        reason: "The prefix is documented but no provider-controlled source establishes the body's length or charset.",
    },
    RejectedFormat {
        format: "GitLab runner authentication token created via registration token",
        marker: "glrtr-",
        reason: "The prefix is documented but no provider-controlled source establishes the body's length or charset.",
    },
    RejectedFormat {
        format: "GitLab deploy token",
        marker: "gldt-",
        reason: "The prefix is documented but no provider-controlled source establishes the body's length or charset.",
    },
    RejectedFormat {
        format: "GitLab SCIM token",
        marker: "glsoat-",
        reason: "The prefix is documented but no provider-controlled source establishes the body's length or charset.",
    },
    RejectedFormat {
        format: "GitLab incoming mail token",
        marker: "glimt-",
        reason: "The prefix is documented but no provider-controlled source establishes the body's length or charset.",
    },
    RejectedFormat {
        format: "GitLab OAuth application secret",
        marker: "gloas-",
        reason: "The prefix is documented but no provider-controlled source establishes the body's length or charset.",
    },
    RejectedFormat {
        format: "DigitalOcean personal access token",
        marker: "dop_v1_",
        reason: "The prefix is documented but no provider-controlled source establishes the body's length or charset.",
    },
    RejectedFormat {
        format: "DigitalOcean OAuth access token",
        marker: "doo_v1_",
        reason: "The prefix is documented but no provider-controlled source establishes the body's length or charset.",
    },
    RejectedFormat {
        format: "DigitalOcean OAuth refresh token",
        marker: "dor_v1_",
        reason: "The prefix is documented but no provider-controlled source establishes the body's length or charset.",
    },
    RejectedFormat {
        format: "Slack app-level token",
        marker: "xapp-",
        reason: "The prefix is documented but no provider-controlled source establishes the body's length or charset.",
    },
    RejectedFormat {
        format: "Shopify Admin API access token",
        marker: "shpat_",
        reason: "The provider documents the value as opaque, and no provider-controlled source establishes the body's length or charset.",
    },
    RejectedFormat {
        format: "Shopify delegate access token",
        marker: "shppa_",
        reason: "The provider documents the value as opaque, and no provider-controlled source establishes the body's length or charset.",
    },
    RejectedFormat {
        format: "Shopify custom app access token",
        marker: "shpca_",
        reason: "The provider documents the value as opaque, and no provider-controlled source establishes the body's length or charset.",
    },
    RejectedFormat {
        format: "Shopify app secret",
        marker: "shpss_",
        reason: "The provider documents the value as opaque, and no provider-controlled source establishes the body's length or charset.",
    },
    RejectedFormat {
        format: "Atlassian API token",
        marker: "ATATT",
        reason: "The body length and charset appear only in third-party scanner rules, not a provider-controlled source.",
    },
    RejectedFormat {
        format: "Postman API key",
        marker: "PMAK-",
        reason: "The body length and charset appear only in third-party scanner rules, not a provider-controlled source.",
    },
    RejectedFormat {
        format: "SonarQube project analysis token",
        marker: "sqp_",
        reason: "The body length and charset appear only in third-party scanner rules, not a provider-controlled source.",
    },
    RejectedFormat {
        format: "SonarQube user token",
        marker: "squ_",
        reason: "The body length and charset appear only in third-party scanner rules, not a provider-controlled source.",
    },
    RejectedFormat {
        format: "SonarQube global analysis token",
        marker: "sqa_",
        reason: "The body length and charset appear only in third-party scanner rules, not a provider-controlled source.",
    },
    RejectedFormat {
        format: "Databricks personal access token",
        marker: "dapi",
        reason: "The body length and charset appear only in third-party scanner rules, not a provider-controlled source.",
    },
    RejectedFormat {
        format: "Docker Hub personal access token",
        marker: "dckr_pat_",
        reason: "The body length and charset appear only in third-party scanner rules, not a provider-controlled source.",
    },
    RejectedFormat {
        format: "New Relic user API key",
        marker: "NRAK-",
        reason: "The prefix mapping, body length, and charset appear only in third-party scanner rules, not a provider-controlled source.",
    },
    RejectedFormat {
        format: "New Relic browser key",
        marker: "NRJS-",
        reason: "The prefix mapping, body length, and charset appear only in third-party scanner rules, not a provider-controlled source.",
    },
    RejectedFormat {
        format: "New Relic ingest license key",
        marker: "NRII-",
        reason: "The prefix mapping, body length, and charset appear only in third-party scanner rules, not a provider-controlled source.",
    },
    RejectedFormat {
        format: "Linear API key",
        marker: "lin_api_",
        reason: "The body length and charset appear only in third-party scanner rules, not a provider-controlled source.",
    },
    RejectedFormat {
        format: "Figma personal access token",
        marker: "figd_",
        reason: "The body length and charset appear only in third-party scanner rules, not a provider-controlled source.",
    },
    RejectedFormat {
        format: "Groq API key",
        marker: "gsk_",
        reason: "The body length and charset appear only in third-party scanner rules, not a provider-controlled source.",
    },
    RejectedFormat {
        format: "Replicate API token",
        marker: "r8_",
        reason: "The body length and charset appear only in third-party scanner rules, not a provider-controlled source.",
    },
    RejectedFormat {
        format: "Perplexity API key",
        marker: "pplx-",
        reason: "The body length and charset appear only in third-party scanner rules, not a provider-controlled source.",
    },
    RejectedFormat {
        format: "OpenRouter API key",
        marker: "sk-or-v1-",
        reason: "The body length and charset appear only in third-party scanner rules, not a provider-controlled source.",
    },
    RejectedFormat {
        format: "Doppler personal token",
        marker: "dp.pt.",
        reason: "The provider documents the prefix and scope segment, but the body length appears only in third-party scanner rules.",
    },
    RejectedFormat {
        format: "Doppler service token",
        marker: "dp.st.",
        reason: "The provider documents the prefix and scope segment, but the body length appears only in third-party scanner rules.",
    },
    RejectedFormat {
        format: "Doppler service account token",
        marker: "dp.sa.",
        reason: "The provider documents the prefix and scope segment, but the body length appears only in third-party scanner rules.",
    },
    RejectedFormat {
        format: "Doppler CLI token",
        marker: "dp.ct.",
        reason: "The provider documents the prefix and scope segment, but the body length appears only in third-party scanner rules.",
    },
    RejectedFormat {
        format: "Doppler SCIM token",
        marker: "dp.scim.",
        reason: "The provider documents the prefix and scope segment, but the body length appears only in third-party scanner rules.",
    },
    RejectedFormat {
        format: "Terraform Cloud API token",
        marker: ".atlasv1.",
        reason: "The fixed marker is an infix, not a prefix.",
    },
    RejectedFormat {
        format: "Fly.io authorization token",
        marker: "FlyV1",
        reason: "The marker is ordinary text and the body has no invariant length.",
    },
    RejectedFormat {
        format: "Fly.io deploy token with fm1r marker",
        marker: "fm1r_",
        reason: "The marker is ordinary text and the body has no invariant length.",
    },
    RejectedFormat {
        format: "Fly.io deploy token with fm2 marker",
        marker: "fm2_",
        reason: "The marker is ordinary text and the body has no invariant length.",
    },
    RejectedFormat {
        format: "JFrog reference token",
        marker: "",
        reason: "The 64-character value has no provider-assigned prefix or provider-controlled charset.",
    },
    RejectedFormat {
        format: "Azure Storage account key",
        marker: "AccountKey=",
        reason: "The provider documents the key value as opaque.",
    },
    RejectedFormat {
        format: "Telegram bot token",
        marker: "",
        reason: "There is no invariant tail length because the bot identifier width changes.",
    },
    RejectedFormat {
        format: "Discord bot token",
        marker: "",
        reason: "The documented segment lengths are examples, not provider-guaranteed invariants.",
    },
    RejectedFormat {
        format: "Square access token",
        marker: "EAAA",
        reason: "The body varies from 22 to 60 characters, so the prefix does not establish a precise shape.",
    },
    RejectedFormat {
        format: "Mailgun API key",
        marker: "key-",
        reason: "The marker is a short English word and no provider-controlled source establishes the body grammar.",
    },
    RejectedFormat {
        format: "Airtable personal access token",
        marker: "",
        reason: "The provider documents the value as opaque and advises against pattern matching.",
    },
    RejectedFormat {
        format: "Notion integration token",
        marker: "ntn_",
        reason: "The provider documents the value as opaque and advises against pattern matching.",
    },
    RejectedFormat {
        format: "Grafana Cloud access policy token",
        marker: "glc_",
        reason: "The marker names a token and is not part of the secret value.",
    },
    RejectedFormat {
        format: "OpenAI organization identifier",
        marker: "org-",
        reason: "This value is an identifier rather than a credential.",
    },
    RejectedFormat {
        format: "Datadog API key",
        marker: "",
        reason: "There is no provider-assigned prefix at all.",
    },
    RejectedFormat {
        format: "Segment write key",
        marker: "",
        reason: "There is no provider-assigned prefix at all.",
    },
    RejectedFormat {
        format: "Vercel access token",
        marker: "",
        reason: "There is no provider-assigned prefix at all.",
    },
    RejectedFormat {
        format: "Netlify personal access token",
        marker: "",
        reason: "There is no provider-assigned prefix at all.",
    },
    RejectedFormat {
        format: "Render API key",
        marker: "",
        reason: "There is no provider-assigned prefix at all.",
    },
    RejectedFormat {
        format: "Railway API token",
        marker: "",
        reason: "There is no provider-assigned prefix at all.",
    },
    RejectedFormat {
        format: "Heroku API key",
        marker: "",
        reason: "There is no provider-assigned prefix at all.",
    },
    RejectedFormat {
        format: "Postmark server token",
        marker: "",
        reason: "There is no provider-assigned prefix at all.",
    },
    RejectedFormat {
        format: "Twitch client secret",
        marker: "",
        reason: "There is no provider-assigned prefix at all.",
    },
    RejectedFormat {
        format: "Asana personal access token",
        marker: "",
        reason: "There is no provider-assigned prefix at all.",
    },
    RejectedFormat {
        format: "Mistral API key",
        marker: "",
        reason: "There is no provider-assigned prefix at all.",
    },
    RejectedFormat {
        format: "Together AI API key",
        marker: "",
        reason: "There is no provider-assigned prefix at all.",
    },
    RejectedFormat {
        format: "Cohere API key",
        marker: "",
        reason: "There is no provider-assigned prefix at all.",
    },
    RejectedFormat {
        format: "DeepSeek API key",
        marker: "",
        reason: "There is no provider-assigned prefix at all.",
    },
    RejectedFormat {
        format: "Stripe test secret key",
        marker: "sk_test_",
        reason: "Test keys live in public documentation, CI fixtures, and sample apps, and leaking one costs nothing, so firing on them is pure cry-wolf.",
    },
    RejectedFormat {
        format: "Stripe test restricted key",
        marker: "rk_test_",
        reason: "Test keys live in public documentation, CI fixtures, and sample apps, and leaking one costs nothing, so firing on them is pure cry-wolf.",
    },
    RejectedFormat {
        format: "Twilio auth token",
        marker: "",
        reason: "The AC and SK SIDs are identifiers rather than secrets, while the auth token is 32 bare hex characters indistinguishable from a git blob identifier.",
    },
    RejectedFormat {
        format: "Cloudflare API token",
        marker: "",
        reason: "The value is 40 characters of alphanumeric, underscore, and hyphen characters with no prefix.",
    },
    RejectedFormat {
        format: "Generic high-entropy key",
        marker: "",
        reason: "Generic 32- or 40-character hex or base64 keys have no provider-specific context.",
    },
];

/// Returns credential formats that were researched and deliberately not shipped.
///
/// Rejections are as valuable as additions: without this ledger, the next
/// person re-derives the same conclusions. Adding an imprecise rule merely to
/// look thorough would break the scanner's only promise.
pub fn rejected_formats() -> &'static [RejectedFormat] {
    &REJECTED_FORMATS
}

/// A rule name this build has retired, and the active rule that answers for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleAlias {
    /// The retired machine name retained for compatibility.
    pub former: &'static str,
    /// The active machine name that now owns the rule.
    pub current: &'static str,
}

/// Empty: no shipped rule has ever been renamed.
const RULE_ALIASES: [RuleAlias; 0] = [];

/// Returns the compatibility ledger that makes rule renames observable.
///
/// Renaming a rule is a breaking change, so its former name keeps resolving for
/// at least one minor cycle. An entry is added in the same commit as the rename
/// and removed no earlier than the next major release.
pub fn rule_aliases() -> &'static [RuleAlias] {
    &RULE_ALIASES
}

/// Advisory remediation attached to a rule. This is rule metadata only: the
/// scanner never follows a URL or acts on a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationGuidance {
    Url(&'static str),
    Exempt(&'static str),
}

/// One compiled rule.
#[derive(Debug)]
struct Rule {
    name: String,
    label: String,
    confidence: Confidence,
    explain: &'static str,
    rotation: RotationGuidance,
    pack: Option<RulePack>,
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
    fn new(
        name: &str,
        label: &str,
        confidence: Confidence,
        explain: &'static str,
        rotation: RotationGuidance,
        pattern: &str,
    ) -> Self {
        Self {
            name: name.to_string(),
            label: label.to_string(),
            confidence,
            explain,
            rotation,
            pack: Some(DEFAULT_RULE_PACK),
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

/// A rule's public metadata and rationale. It cannot carry a matched value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    pub name: String,
    pub label: String,
    pub confidence: Confidence,
    pub text: String,
    pub rotation: RotationGuidance,
}

/// A rule name the user supplied, resolved against the active rule set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The active name that can be used for metadata and matching.
    pub name: String,
    /// The supplied retired name, when the caller needs to warn about it.
    pub former: Option<String>,
}

/// The compiled rule set: built-in provider patterns, the user's extra patterns,
/// and the allowlist that suppresses both.
#[derive(Debug, Default)]
pub struct Rules {
    /// Reported by `--rules` so a user can see what is actually active.
    pub names: Vec<(String, Confidence)>,
    /// Pack metadata aligned one-for-one with [`Self::names`]. Custom patterns
    /// have no compiled-in pack.
    pub packs: Vec<Option<RulePack>>,
    /// Things the caller should tell the user about the rule set itself, such as
    /// a configuration flag that does nothing. Never contains a value.
    pub notes: Vec<String>,
    /// Retired rule names and the active rules they resolve to: `(former, current)`.
    pub aliases: Vec<(String, String)>,
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
        // `notes` starts life here because pack selection is the first thing
        // that can have something to say: an unknown pack name is reported and
        // ignored rather than failing, so a typo narrows the rule set in the
        // open rather than in silence.
        let (enabled_packs, mut notes) = selected_rule_packs(&config.rule_packs);
        let mut rules = builtin_rules(config.env_assignments, &enabled_packs);
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
                explain: "This rule comes from the user's `patterns` configuration and has no built-in reasoning.",
                rotation: RotationGuidance::Exempt(
                    "Custom rules have no built-in provider; remediation depends on whoever issued the credential.",
                ),
                pack: None,
                regex,
                groups: vec![0],
                standalone: false,
                narrow_value: false,
                check: None,
            });
        }
        let mut aliases: Vec<(String, String)> = rule_aliases()
            .iter()
            .map(|alias| (alias.former.to_string(), alias.current.to_string()))
            .collect();
        // Alias validation waits until every custom rule exists because a former
        // name must never make an exact active-name lookup ambiguous.
        for pattern in &config.patterns {
            let name = pattern.name.trim();
            for former_name in &pattern.former_names {
                let former = former_name.trim();
                if former.is_empty() {
                    return Err(format!("pattern `{name}` has an empty former name").into());
                }
                if rules.iter().any(|rule| rule.name == former) {
                    return Err(format!(
                        "pattern `{name}`: former name `{former}` is also an active rule name"
                    )
                    .into());
                }
                if let Some((_, first)) = aliases.iter().find(|(claimed, _)| claimed == former) {
                    return Err(format!(
                        "former name `{former}` is claimed by both `{first}` and `{name}`"
                    )
                    .into());
                }
                aliases.push((former.to_string(), name.to_string()));
            }
        }

        let mut allowlist = Vec::with_capacity(config.allowlist.len());
        for entry in &config.allowlist {
            allowlist.push(
                user_regex(entry).map_err(|err| format!("allowlist entry `{entry}`: {err}"))?,
            );
        }

        let (names, packs) = names_and_packs_of(&rules);
        // Overlay parsing is deliberately lenient, so its diagnostics ride along
        // with anything pack selection had to say. An overlay that was ignored
        // has to be visible in every effective rule set it did not reach.
        notes.extend(config.notes.iter().cloned());

        Ok(Self {
            names,
            packs,
            notes,
            aliases,
            rules,
            allowlist,
        })
    }

    /// The default built-in pack alone, with no user configuration. Cannot fail.
    pub fn builtin() -> Self {
        let rules = builtin_rules(true, &[DEFAULT_RULE_PACK]);
        let (names, packs) = names_and_packs_of(&rules);
        Self {
            names,
            packs,
            notes: Vec::new(),
            aliases: rule_aliases()
                .iter()
                .map(|alias| (alias.former.to_string(), alias.current.to_string()))
                .collect(),
            rules,
            allowlist: Vec::new(),
        }
    }

    /// Resolves a supplied rule name, following one rename. `None` when no
    /// active rule answers for it.
    pub fn resolve(&self, name: &str) -> Option<Resolved> {
        if self.rules.iter().any(|rule| rule.name == name) {
            return Some(Resolved {
                name: name.to_string(),
                former: None,
            });
        }
        self.aliases
            .iter()
            .find(|(former, current)| {
                former == name && self.rules.iter().any(|rule| rule.name == *current)
            })
            .map(|(_, current)| Resolved {
                name: current.clone(),
                former: Some(name.to_string()),
            })
    }

    /// Returns the metadata and rationale for one exact machine name.
    pub fn explanation(&self, name: &str) -> Option<Explanation> {
        self.rules
            .iter()
            .find(|rule| rule.name == name)
            .map(explanation_of)
    }

    /// Returns advisory rotation metadata after resolving a retired machine name,
    /// so stored findings keep their remediation advice across a rule rename.
    pub fn rotation_guidance(&self, name: &str) -> Option<RotationGuidance> {
        let resolved = self.resolve(name)?;
        self.rules
            .iter()
            .find(|rule| rule.name == resolved.name)
            .map(|rule| rule.rotation)
    }

    /// Returns active rule explanations in declaration order, one per machine name.
    pub fn explanations(&self) -> Vec<Explanation> {
        let mut explanations = Vec::with_capacity(self.names.len());
        for rule in &self.rules {
            if !explanations
                .iter()
                .any(|explanation: &Explanation| explanation.name == rule.name)
            {
                explanations.push(explanation_of(rule));
            }
        }
        explanations
    }

    /// A finding is dropped when the allowlist matches either the matched value
    /// or the whole line it was found on.
    fn allowed(&self, value: &str, line: &str) -> bool {
        self.allowlist
            .iter()
            .any(|entry| entry.is_match(value) || entry.is_match(line))
    }
}

fn explanation_of(rule: &Rule) -> Explanation {
    Explanation {
        name: rule.name.clone(),
        label: rule.label.clone(),
        confidence: rule.confidence,
        text: rule.explain.to_string(),
        rotation: rule.rotation,
    }
}

fn user_regex(pattern: &str) -> std::result::Result<Regex, regex::Error> {
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
}

/// Rule names and pack metadata in declaration order, built-ins first, one
/// entry per machine name.
fn names_and_packs_of(rules: &[Rule]) -> (Vec<(String, Confidence)>, Vec<Option<RulePack>>) {
    let mut names = Vec::with_capacity(rules.len());
    let mut packs = Vec::with_capacity(rules.len());
    for rule in rules {
        if !names
            .iter()
            .any(|(name, _): &(String, Confidence)| name == &rule.name)
        {
            names.push((rule.name.clone(), rule.confidence));
            packs.push(rule.pack);
        }
    }
    (names, packs)
}

fn selected_rule_packs(requested: &[String]) -> (Vec<RulePack>, Vec<String>) {
    // The default pack is an invariant, not an opt-in. An empty list therefore
    // means "default only", never "scan nothing".
    let mut enabled = vec![DEFAULT_RULE_PACK];
    let mut notes = Vec::new();
    for requested_name in requested {
        let requested_name = requested_name.trim();
        match RULE_PACKS.iter().find(|pack| pack.name == requested_name) {
            Some(pack) if !enabled.contains(pack) => enabled.push(*pack),
            Some(_) => {}
            None => notes.push(format!(
                "unknown rule pack `{requested_name}` ignored; the default pack remains active"
            )),
        }
    }
    (enabled, notes)
}

// ---------------------------------------------------------------------------
// The built-in rule set
// ---------------------------------------------------------------------------

/// Every built-in rule, in the order `--rules` prints them.
///
/// Formats considered but deliberately not shipped are recorded by
/// [`rejected_formats`].
fn builtin_rules(env_assignments: bool, enabled_packs: &[RulePack]) -> Vec<Rule> {
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
            "Matches `AKIA` or `ASIA` followed by 16 uppercase base32-style characters. Those are the access-key prefixes, and a structural check rejects a tail made from one repeated character so redactions, banners, and placeholders do not fire.",
            RotationGuidance::Url(
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
            ),
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
            "Matches the `AGPA`, `AIDA`, `AROA`, `AIPA`, `ANPA`, `ANVA`, and `APKA` identifier prefixes followed by 16 or 17 uppercase base32-style characters, rejecting a tail made from one repeated character. It is weak and separate because these are identifiers rather than credentials and full-length values appear in ordinary `aws sts get-caller-identity` and IAM output.",
            RotationGuidance::Exempt(
                "AWS principal IDs are identifiers, not credentials, so there is nothing to rotate.",
            ),
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
            "Matches exactly 40 base64 characters only beside the AWS secret access key name, because a bare 40-character base64 run would cause false positives.",
            RotationGuidance::Url(
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
            ),
            r#"(?i)aws[_-]?secret[_-]?access[_-]?key["']?[ \t]*[:=][ \t]*["']?([A-Za-z0-9/+=]{40})"#,
        )
        .groups(&[1]),
        Rule::new(
            "github_token",
            "GitHub token",
            Confidence::Strong,
            "Matches a `ghp_`, `gho_`, `ghu_`, `ghs_`, or `ghr_` prefix followed by at least 36 alphanumeric characters.",
            RotationGuidance::Url(
                "https://docs.github.com/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation",
            ),
            r"\bgh[pousr]_[A-Za-z0-9]{36,}",
        )
        .standalone(),
        // GitHub's own token-format changelog says tokens "will likely increase
        // in length in future updates, so integrators should plan to support
        // tokens up to 255 characters". Both components are therefore floors:
        // pinned to 22 and 59, a longer token would match up to the pinned
        // width and the standalone check would then discard it as a fragment.
        Rule::new(
            "github_pat",
            "GitHub fine-grained token",
            Confidence::Strong,
            "Matches `github_pat_`, an alphanumeric component of at least 22 characters, an underscore, and an alphanumeric component of at least 59 characters. GitHub states that its tokens will grow in length, so both components are minimums and a longer token is reported whole rather than truncated and discarded.",
            RotationGuidance::Url(
                "https://docs.github.com/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
            ),
            r"\bgithub_pat_[A-Za-z0-9]{22,}_[A-Za-z0-9]{59,}",
        )
        .standalone(),
        Rule::new(
            "anthropic_api_key",
            "Anthropic API key",
            Confidence::Strong,
            "Matches `sk-ant-` followed by at least 32 characters from the alphanumeric, underscore, and hyphen alphabet.",
            RotationGuidance::Url("https://console.anthropic.com/settings/keys"),
            r"\bsk-ant-[A-Za-z0-9_-]{32,}",
        )
        .standalone(),
        // The rule most likely to fire on prose, so both forms demand the full
        // charset: `sk-learn` and `sk-ms-version` fall out immediately.
        Rule::new(
            "openai_api_key",
            "OpenAI API key",
            Confidence::Strong,
            "Matches `sk-proj-`, `sk-svcacct-`, or `sk-admin-` followed by at least 20 full-alphabet characters, or `sk-` followed by exactly 48 alphanumeric characters. Requiring the complete token alphabet keeps prose such as `sk-learn` and `sk-ms-version` out.",
            RotationGuidance::Url("https://platform.openai.com/api-keys"),
            r"\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{48})",
        )
        .standalone(),
        Rule::new(
            "stripe_secret_key",
            "Stripe live secret key",
            Confidence::Strong,
            "Matches only live `sk_live_` and `rk_live_` keys followed by at least 20 alphanumeric characters. Test keys are deliberately excluded because they live in public documentation, CI fixtures, and sample apps, and firing on them would be cry-wolf noise.",
            RotationGuidance::Url("https://dashboard.stripe.com/apikeys"),
            r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}",
        )
        .standalone(),
        Rule::new(
            "slack_token",
            "Slack token",
            Confidence::Strong,
            "Matches `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, or `xoxs-` followed by at least 12 alphanumeric or hyphen characters.",
            RotationGuidance::Url("https://api.slack.com/authentication/rotation"),
            r"\bxox[baprs]-[A-Za-z0-9-]{12,}",
        )
        .standalone(),
        Rule::new(
            "google_api_key",
            "Google API key",
            Confidence::Strong,
            "Matches `AIza` followed by exactly 35 characters from the alphanumeric, underscore, and hyphen alphabet.",
            RotationGuidance::Url("https://console.cloud.google.com/apis/credentials"),
            r"\bAIza[A-Za-z0-9_-]{35}",
        )
        .standalone(),
        // Google's OAuth client secrets have carried this prefix since 2021,
        // which is the only reason this rule is precise enough to ship.
        Rule::new(
            "google_oauth_client_secret",
            "Google OAuth client secret",
            Confidence::Strong,
            "Matches `GOCSPX-` followed by exactly 28 characters from the alphanumeric, underscore, and hyphen alphabet; the prefix is what makes the rule precise enough to ship.",
            RotationGuidance::Url("https://console.cloud.google.com/apis/credentials"),
            r"\bGOCSPX-[A-Za-z0-9_-]{28}",
        )
        .standalone(),
        // `eyJ` is base64url for `{"`, so every real JWT header starts with it.
        // `check` then insists the header actually decodes to JSON with `alg`.
        Rule::new(
            "jwt",
            "JSON Web Token",
            Confidence::Strong,
            "Matches three sufficiently long base64url segments beginning with `eyJ`, then fires only when the header segment base64url-decodes to a JSON object carrying a string `alg`. Version strings, file names, and base64 blobs that merely contain two dots are rejected.",
            RotationGuidance::Exempt(
                "JWT issuers control revocation, so the correct action depends on whoever issued the token.",
            ),
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
            "Matches a private-key opening marker and, when present, its body and closing marker. The closing block is optional so a key cut off by the pane's line budget still reports.",
            RotationGuidance::Exempt(
                "Private keys have no single provider; replace or revoke trust wherever the corresponding public key is authorized.",
            ),
            r"-----BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY(?: BLOCK)?-----(?s:.*?-----END [A-Z0-9 ]{0,32}PRIVATE KEY(?: BLOCK)?-----)?",
        ),
        Rule::new(
            "slack_webhook_url",
            "Slack webhook URL",
            Confidence::Strong,
            "Matches the Slack webhook host and services path followed by three alphanumeric path components of at least 8, 8, and 20 characters.",
            RotationGuidance::Url("https://api.slack.com/apps"),
            r"https://hooks\.slack\.com/services/[A-Za-z0-9]{8,}/[A-Za-z0-9]{8,}/[A-Za-z0-9]{20,}",
        ),
        // npm ships its own redactor, and `lib/matchers.js` matches
        // `/\b(npms?_)[a-zA-Z0-9]{36,48}\b/gi`: two prefixes, and a body wider
        // than the 36 characters npm's examples show. The length is therefore a
        // floor, not a width. Pinned to exactly 36, a 40-character body matched
        // its first 36 characters and the standalone check below then discarded
        // the finding as a fragment — the credential was found and thrown away.
        Rule::new(
            "npm_token",
            "npm access token",
            Confidence::Strong,
            "Matches `npm_` or `npms_` followed by at least 36 alphanumeric characters. npm's own redactor covers both prefixes and a body of 36 to 48 characters, so the rule treats the length as a minimum and reports a longer body whole rather than matching its first 36 characters and then discarding the finding as part of a longer token.",
            RotationGuidance::Url("https://www.npmjs.com/settings/~/tokens"),
            r"\bnpms?_[A-Za-z0-9]{36,}",
        )
        .standalone(),
        Rule::new(
            "pypi_token",
            "PyPI API token",
            Confidence::Strong,
            "Matches `pypi-AgEIcHlwaS5vcmc` followed by at least 40 characters from the alphanumeric, underscore, and hyphen alphabet.",
            RotationGuidance::Url("https://pypi.org/manage/account/token/"),
            r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,}",
        )
        .standalone(),
        Rule::new(
            "sendgrid_api_key",
            "SendGrid API key",
            Confidence::Strong,
            "Matches `SG.`, a 22-character component, a dot, and a 43-character component, with both components restricted to the alphanumeric, underscore, and hyphen alphabet.",
            RotationGuidance::Url("https://app.sendgrid.com/settings/api_keys"),
            r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        )
        .standalone(),
        Rule::new(
            "gitlab_pat",
            "GitLab personal access token",
            Confidence::Strong,
            "Matches `glpat-` followed by at least 20 characters from the alphanumeric, underscore, and hyphen alphabet.",
            RotationGuidance::Url(
                "https://docs.gitlab.com/user/profile/personal_access_tokens/",
            ),
            r"\bglpat-[A-Za-z0-9_-]{20,}",
        )
        .standalone(),
        Rule::new(
            "grafana_service_account_token",
            "Grafana service account token",
            Confidence::Strong,
            "Matches the `glsa_` prefix, a 32-character alphanumeric body, and an eight-character lowercase hexadecimal checksum separated by an underscore. Grafana's own generator is the source of the checksum algorithm; the rule recomputes its IEEE CRC-32 and little-endian encoding, so a string of the right shape with the wrong checksum does not fire.",
            RotationGuidance::Url(
                "https://grafana.com/docs/grafana/latest/administration/service-accounts/",
            ),
            r"\bglsa_[0-9A-Za-z]{32}_[0-9a-f]{8}\b",
        )
        .standalone()
        .check(is_grafana_service_account_token),
        Rule::new(
            "huggingface_token",
            "Hugging Face token",
            Confidence::Strong,
            "Matches `hf_` followed by at least 34 alphanumeric characters.",
            RotationGuidance::Url("https://huggingface.co/settings/tokens"),
            r"\bhf_[A-Za-z0-9]{34,}",
        )
        .standalone(),
        // Supabase's CLI validates every token it loads — `access_token.go`
        // holds `AccessTokenPattern = regexp.MustCompile("^sbp_(oauth_)?[a-f0-9]{40}$")`
        // — so this is a provider-enforced grammar rather than a description of
        // one, and the length and charset are exact rather than a floor.
        Rule::new(
            "supabase_access_token",
            "Supabase personal access token",
            Confidence::Strong,
            "Matches `sbp_` or `sbp_oauth_` followed by exactly 40 lowercase hexadecimal characters. Supabase's own CLI refuses to load a token outside that shape, so the length and charset are enforced by the provider rather than inferred, and an uppercase or shorter body does not fire.",
            RotationGuidance::Url("https://supabase.com/dashboard/account/tokens"),
            r"\bsbp_(?:oauth_)?[0-9a-f]{40}",
        )
        .standalone(),
        // Sentry generates auth tokens as a type marker plus
        // `secrets.token_hex(nbytes=32)` in `models/apitoken.py`, and the column
        // is `max_length=71`, which is 7 + 64. The markers come from
        // `types/token.py`: `sntryu_` for a user token, `sntrya_` for a user
        // application token, and `sntryi_` for an integration token. The fourth,
        // `sntrys_`, is base64 of a JSON document and is a different rule's
        // problem, so it is left alone rather than half-matched.
        Rule::new(
            "sentry_auth_token",
            "Sentry auth token",
            Confidence::Strong,
            "Matches the `sntryu_`, `sntrya_`, and `sntryi_` markers followed by exactly 64 lowercase hexadecimal characters. Sentry's own generator produces the body from a 32-byte hexadecimal token, and its column width of 71 characters corroborates the seven-character marker plus that body. The organisation-token marker `sntrys_` carries a base64 JSON document instead and is deliberately not matched.",
            RotationGuidance::Url("https://docs.sentry.io/api/auth/"),
            r"\bsntry[aiu]_[0-9a-f]{64}",
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
            "Matches the private half of an age keypair: `AGE-SECRET-KEY-1` followed by exactly 58 Bech32 characters. The public `age1` recipient is deliberately excluded because it is not a secret, and the body omits `1`, `B`, `I`, and `O` as required by that alphabet.",
            RotationGuidance::Exempt(
                "age keys have no provider or revocation service; replace the recipient wherever the public key is trusted.",
            ),
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
            "Matches a password carried in a JDBC connection string, either as a `?password=` or `&password=` query parameter or as a `;password=` property. The literal `jdbc:` scheme is the anchor: without it this would be a generic `password=` matcher, which would fire on ordinary query strings and log lines. The value still has to survive the placeholder filter, so `password=${DB_PASS}` and `password=changeme` stay quiet.",
            RotationGuidance::Exempt(
                "The database provider is not encoded in a JDBC password, so rotation depends on the database that issued it.",
            ),
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
            "Matches the `\"auth\"` field of a Docker registry credential, which holds base64 of `username:password`. The base64 is decoded and has to contain exactly one `:` with a password half that looks like a credential; without that check the rule would fire on pasted image layers and on any base64 that happens to sit next to the word `auth`.",
            RotationGuidance::Exempt(
                "The registry is not encoded in Docker auth metadata, so rotation depends on the registry that issued the credential.",
            ),
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
            "Matches the `hvs.`, `hvb.` and `hvr.` token prefixes followed by at least 24 characters. The legacy `s.` form is deliberately excluded: two characters of prefix, one of them a full stop, cannot carry a strong claim, and prose beginning `s.` is ordinary output.",
            RotationGuidance::Url(
                "https://developer.hashicorp.com/vault/docs/commands/token/revoke",
            ),
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
            "Matches only the password portion of a scheme-based URL containing user information. It is weak because connection-string examples commonly have this shape, and the password must pass the placeholder filter.",
            RotationGuidance::Exempt(
                "The URL can refer to any issuer, so rotation depends on the service that issued the password.",
            ),
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
            "Matches at least 16 credential-alphabet characters following an `Authorization: Bearer` header. It is weak because agents commonly print that header in curl commands, and the captured token must pass the placeholder filter.",
            RotationGuidance::Exempt(
                "Bearer tokens have no provider-specific shape, so revocation depends on whoever issued the token.",
            ),
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
                "Matches secret-looking shell assignments and YAML or JSON-style mappings anchored at the start of a line. It requires a secret-ish name segment, rejects a bare `*_KEY` because names such as `GPG_KEY` and `CACHE_KEY` are ordinary output, and drops placeholder values. The mapping form requires whitespace after the colon so ARN and URL text does not fire.",
                RotationGuidance::Exempt(
                    "Generic assignments do not identify an issuer, so rotation depends on whoever issued the credential.",
                ),
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
                "Matches secret-looking shell assignments and YAML or JSON-style mappings anchored at the start of a line. It requires a secret-ish name segment, rejects a bare `*_KEY` because names such as `GPG_KEY` and `CACHE_KEY` are ordinary output, and drops placeholder values. The mapping form requires whitespace after the colon so ARN and URL text does not fire.",
                RotationGuidance::Exempt(
                    "Generic assignments do not identify an issuer, so rotation depends on whoever issued the credential.",
                ),
                r#"(?m)^[ \t-]*"?([A-Za-z_][A-Za-z0-9_.-]*)"?[ \t]*:[ \t]+(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\r\n]*))"#,
            )
            .groups(&[2, 3, 4])
            .narrowed()
            .check(is_secret_assignment),
        );
        // A bounded pre-pass joins only an explicitly quoted JSON/YAML value or
        // a YAML block scalar. The regex finds a possible key line; the scanner
        // below owns the structural and length checks.
        rules.push(Rule::new(
            MULTILINE_CREDENTIAL_RULE,
            "Multi-line structured credential",
            Confidence::Weak,
            "Matches a credential-shaped key whose value continues onto following lines, as a GCP service-account key, a Kubernetes secret manifest or a YAML block scalar prints one. The key must pass the same secret-ish name test the single-line assignment rule uses, the join is bounded to eight continuation lines and 4096 characters, and the joined value still has to survive the placeholder filter. It is weak because a key-and-value line is the shape of almost all structured output; where the joined value turns out to be something a strong rule validates on its own merits, that rule reports it instead. A bare `auth` key deliberately cannot start a join, because `AUTH` is a key qualifier rather than a secret-ish name and the single-line Docker rule already covers that shape.",
            RotationGuidance::Exempt(
                "Multi-line credential shapes do not identify an issuer, so rotation depends on whoever issued the credential.",
            ),
            r#"(?m)^[ \t-]*"?([A-Za-z_][A-Za-z0-9_.-]*)"?[ \t]*:[ \t]*([^\r\n]*)$"#,
        ));
    }

    rules.retain(|rule| rule.pack.is_some_and(|pack| enabled_packs.contains(&pack)));
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

/// A Grafana service-account token carries the checksum of its prefix and body
/// after the last underscore.
fn is_grafana_service_account_token(caps: &Captures<'_>) -> bool {
    let value = &caps[0];
    let Some((payload, checksum)) = value.rsplit_once('_') else {
        return false;
    };
    let checksum_bytes = crc32_ieee(payload.as_bytes()).to_le_bytes();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0u8; 8];
    for (index, byte) in checksum_bytes.iter().enumerate() {
        encoded[index * 2] = HEX[usize::from(byte >> 4)];
        encoded[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    checksum.as_bytes() == encoded.as_slice()
}

/// IEEE CRC-32 used by Grafana's service-account token generator. It lives here
/// as a small bitwise implementation so structural validation adds no dependency.
fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
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

/// A normalized credential assembled from a bounded structured value. The
/// source range exists only for ordering and overlap resolution; the owned value
/// is the exact string that validation, masking and digesting use.
struct JoinedValue {
    value: String,
    source_start: usize,
    source_end: usize,
    line_start: usize,
}

/// The next physical line after `after`, returned as content byte offsets plus
/// the byte at which another call should continue.
fn following_line(text: &str, after: usize) -> Option<(usize, usize, usize)> {
    let bytes = text.as_bytes();
    let mut start = after;
    if bytes.get(start) == Some(&b'\r') {
        start += 1;
    }
    if bytes.get(start) != Some(&b'\n') {
        return None;
    }
    start += 1;
    let raw_end = text[start..]
        .find('\n')
        .map_or(text.len(), |relative| start + relative);
    let end = if raw_end > start && bytes[raw_end - 1] == b'\r' {
        raw_end - 1
    } else {
        raw_end
    };
    Some((start, end, raw_end))
}

fn trimmed_span(text: &str, mut start: usize, mut end: usize) -> (usize, usize) {
    let bytes = text.as_bytes();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    (start, end)
}

fn closing_quote(value: &str, quote: u8) -> Option<usize> {
    let mut escaped = false;
    for (index, byte) in value.bytes().enumerate() {
        if byte == quote && !escaped {
            return Some(index);
        }
        if byte == b'\\' {
            escaped = !escaped;
        } else {
            escaped = false;
        }
    }
    None
}

fn push_joined(joined: &mut String, joined_chars: &mut usize, fragment: &str) -> bool {
    let fragment_chars = fragment.chars().count();
    if *joined_chars + fragment_chars > MAX_VALUE_LEN {
        return false;
    }
    joined.push_str(fragment);
    *joined_chars += fragment_chars;
    true
}

fn quote_tail_is_structural(tail: &str) -> bool {
    matches!(tail.trim(), "" | ",")
}

/// Join one JSON/YAML quoted continuation or YAML block scalar. This is not a
/// parser: it recognizes only the two credential shapes cloud tools print and
/// never examines more than [`MAX_CONTINUATION_LINES`] lines.
fn join_multiline_value(text: &str, caps: &Captures<'_>) -> Option<JoinedValue> {
    let whole = caps.get(0)?;
    let rest = caps.get(2)?;
    let key_indent = whole
        .as_str()
        .bytes()
        .take_while(|byte| matches!(byte, b' ' | b'\t'))
        .count();
    let rest_text = rest.as_str().trim();

    if matches!(rest_text, "|" | "|-" | "|+" | ">" | ">-" | ">+") {
        let mut joined = String::new();
        let mut joined_chars = 0usize;
        let mut cursor = whole.end();
        let mut source_end = whole.end();
        let mut has_content = false;
        for _ in 0..MAX_CONTINUATION_LINES {
            let Some((line_start, line_end, next)) = following_line(text, cursor) else {
                break;
            };
            let line = &text[line_start..line_end];
            let indent = line
                .bytes()
                .take_while(|byte| matches!(byte, b' ' | b'\t'))
                .count();
            let (value_start, value_end) = trimmed_span(text, line_start, line_end);
            if value_start != value_end && indent <= key_indent {
                break;
            }
            if !push_joined(
                &mut joined,
                &mut joined_chars,
                &text[value_start..value_end],
            ) {
                return None;
            }
            has_content |= value_start != value_end;
            source_end = line_end;
            cursor = next;
        }
        return has_content.then_some(JoinedValue {
            value: joined,
            source_start: whole.start(),
            source_end,
            line_start: whole.start(),
        });
    }

    let mut joined = String::new();
    let mut joined_chars = 0usize;
    let mut cursor = whole.end();
    let mut continuation_lines = 0usize;
    let (quote, first_start, first_end) =
        if let Some(quote @ (b'"' | b'\'')) = rest_text.as_bytes().first().copied() {
            let offset = rest.as_str().find(rest_text)?;
            let start = rest.start() + offset + 1;
            (quote, start, rest.end())
        } else if rest_text.is_empty() {
            let (line_start, line_end, next) = following_line(text, cursor)?;
            let (trimmed_start, trimmed_end) = trimmed_span(text, line_start, line_end);
            let quote @ (b'"' | b'\'') = text.as_bytes().get(trimmed_start).copied()? else {
                return None;
            };
            continuation_lines = 1;
            cursor = next;
            (quote, trimmed_start + 1, trimmed_end)
        } else {
            return None;
        };

    let first = &text[first_start..first_end];
    if let Some(close) = closing_quote(first, quote) {
        if continuation_lines == 0 || !quote_tail_is_structural(&first[close + 1..]) {
            return None;
        }
        let fragment = first[..close].trim();
        if !push_joined(&mut joined, &mut joined_chars, fragment) {
            return None;
        }
        return Some(JoinedValue {
            value: joined,
            source_start: whole.start(),
            source_end: first_start + close,
            line_start: whole.start(),
        });
    }
    if !push_joined(&mut joined, &mut joined_chars, first.trim()) {
        return None;
    }
    let mut source_end = first_end;

    while continuation_lines < MAX_CONTINUATION_LINES {
        let Some((line_start, line_end, next)) = following_line(text, cursor) else {
            break;
        };
        continuation_lines += 1;
        cursor = next;
        let (value_start, value_end) = trimmed_span(text, line_start, line_end);
        let fragment = &text[value_start..value_end];
        if let Some(close) = closing_quote(fragment, quote) {
            if !quote_tail_is_structural(&fragment[close + 1..])
                || !push_joined(&mut joined, &mut joined_chars, &fragment[..close])
            {
                return None;
            }
            source_end = value_start + close;
            break;
        }
        if !push_joined(&mut joined, &mut joined_chars, fragment) {
            return None;
        }
        source_end = line_end;
    }

    (continuation_lines > 0 && !joined.is_empty()).then_some(JoinedValue {
        value: joined,
        source_start: whole.start(),
        source_end,
        line_start: whole.start(),
    })
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

/// One surviving match before overlap resolution. Joined values stay private to
/// this module just like slices of the input; only their mask, length and digest
/// are exported.
struct Candidate {
    rule: usize,
    start: usize,
    end: usize,
    line_start: usize,
    confidence: Confidence,
    joined_value: Option<String>,
}

impl Candidate {
    fn value<'a>(&'a self, text: &'a str) -> &'a str {
        self.joined_value
            .as_deref()
            .unwrap_or(&text[self.start..self.end])
    }
}

/// Apply every existing strong rule to a normalized joined value. The longest
/// validated span wins, preserving declaration order on a tie.
fn joined_strong_match(
    joined: &str,
    rules: &Rules,
    multiline_rule: usize,
) -> Option<(usize, usize, usize)> {
    let mut best: Option<(usize, usize, usize)> = None;
    for (index, rule) in rules.rules.iter().enumerate() {
        if index == multiline_rule || rule.confidence != Confidence::Strong {
            continue;
        }
        for caps in rule.regex.captures_iter(joined) {
            let Some(found) = rule.value(&caps) else {
                continue;
            };
            let (mut start, mut end) = (found.start(), found.end());
            if rule.narrow_value {
                let (inner_start, inner_end) = narrow_span(found.as_str());
                end = start + inner_end;
                start += inner_start;
            }
            if start == end
                || (rule.standalone && !standalone(joined, start, end))
                || rule.check.is_some_and(|check| !check(&caps))
            {
                continue;
            }
            if best.is_none_or(|(_, current_start, current_end)| {
                end - start > current_end - current_start
            }) {
                best = Some((index, start, end));
            }
        }
    }
    best
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
    let multiline_rule = rules
        .rules
        .iter()
        .position(|rule| rule.name == MULTILINE_CREDENTIAL_RULE);
    if let Some(multiline_index) = multiline_rule {
        let rule = &rules.rules[multiline_index];
        let mut found_here = 0usize;
        for caps in rule.regex.captures_iter(text) {
            let Some(name) = caps.get(1) else {
                continue;
            };
            if !secretish_name(name.as_str()) {
                continue;
            }
            let Some(mut joined) = join_multiline_value(text, &caps) else {
                continue;
            };
            let candidate_rule = if let Some((strong_rule, start, end)) =
                joined_strong_match(&joined.value, rules, multiline_index)
            {
                joined.value.truncate(end);
                joined.value.drain(..start);
                strong_rule
            } else {
                if !plausible_secret_value(&joined.value) {
                    continue;
                }
                multiline_index
            };
            candidates.push(Candidate {
                rule: candidate_rule,
                start: joined.source_start,
                end: joined.source_end,
                line_start: joined.line_start,
                confidence: rules.rules[candidate_rule].confidence,
                joined_value: Some(joined.value),
            });
            found_here += 1;
            if found_here >= MAX_MATCHES_PER_RULE {
                truncated.push(&rule.name);
                break;
            }
        }
    }
    for (index, rule) in rules.rules.iter().enumerate() {
        if Some(index) == multiline_rule {
            continue;
        }
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
                line_start: start,
                confidence: rule.confidence,
                joined_value: None,
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
                candidate.value(text),
                lines.line_text(text, candidate.line_start),
            )
        });
    }

    // Strongest first, then joined spans, longest, leftmost, and declaration
    // order. Preferring a joined span only affects the new path and ensures an
    // overlapping strong rule reports the normalized value on the key's line.
    candidates.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then(b.joined_value.is_some().cmp(&a.joined_value.is_some()))
            .then(b.value(text).len().cmp(&a.value(text).len()))
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
            let value = candidate.value(text);
            let rule = &rules.rules[candidate.rule];
            Match {
                pattern: rule.name.clone(),
                label: rule.label.clone(),
                confidence: rule.confidence,
                preview: mask(value),
                value_len: value.chars().count(),
                line: lines.line_of(candidate.line_start),
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
