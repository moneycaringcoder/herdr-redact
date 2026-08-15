//! The scanner: a pure function over a string.
//!
//! STUB — owned by the `scanner` builder. The signatures below are the contract
//! the rest of the crate compiles against; the bodies are placeholders.
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

use crate::config::Config;
use crate::model::{Confidence, DigestKey, Match};
use crate::Result;

/// The compiled rule set: built-in provider patterns, the user's extra patterns,
/// and the allowlist that suppresses both.
#[derive(Debug, Default)]
pub struct Rules {
    /// Reported by `--rules` so a user can see what is actually active.
    pub names: Vec<(String, Confidence)>,
}

impl Rules {
    /// Compiles the built-ins plus the user's `patterns` and `allowlist`.
    ///
    /// A malformed user regex is a hard error: the user typed it, they are
    /// looking right at it, and a silently dropped rule is a rule they think is
    /// protecting them. Callers that must keep running (the daemon) fall back to
    /// [`Rules::builtin`] and say so.
    pub fn compile(_config: &Config) -> Result<Self> {
        Ok(Self::builtin())
    }

    /// The built-in rules alone, with no user configuration. Cannot fail.
    pub fn builtin() -> Self {
        Self::default()
    }
}

/// Every credential-shaped thing in `text`, in the order they appear.
///
/// `key` keys the digest that identifies a match across cycles; tests pass a
/// fixed key, the daemon passes the per-installation one.
pub fn scan(_text: &str, _rules: &Rules, _key: &DigestKey) -> Vec<Match> {
    Vec::new()
}

/// Masked rendering of a value: at most the first four and the last four
/// characters, and never more than about a third of it.
pub fn mask(_value: &str) -> String {
    String::from("\u{2026}")
}
