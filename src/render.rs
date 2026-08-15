//! Rendering: the badge string that rides a token, the findings pane, and the
//! machine-readable snapshot.
//!
//! STUB — owned by the `interface` builder. The signatures below are the
//! contract the rest of the crate compiles against; the bodies are placeholders.
//!
//! # Contract
//!
//! * Nothing here emits colour. herdr renders a token value as flat text and
//!   cannot colour by content, so severity travels in the token *name*
//!   (`Alert::token_name`).
//! * [`badge`] is the single author of badge text, and renders a clear target as
//!   the empty string, which the daemon treats as "clear the token" rather than
//!   "write an empty one".
//! * The formatting half of the module is pure, and is what `tests/render.rs`
//!   exercises. Only `run_watch` talks to herdr.
//! * No renderer may print a value. It only ever has a masked preview to print,
//!   which is the point.

use crate::config::Config;
use crate::model::{Alert, Report};
use crate::Result;

/// A badge sits beside a branch or an agent name. Six display columns is the
/// budget; anything longer starts pushing its neighbour out of view.
pub const BADGE_COLUMNS: usize = 6;
pub const DEFAULT_COLUMNS: usize = 80;
pub const MIN_COLUMNS: usize = 20;

/// Badge text for one target, e.g. `⚠ 2`. Severity itself is carried by the
/// token *name*, not this string. A clear target renders the empty string.
pub fn badge(_alert: Alert, _count: usize) -> String {
    String::new()
}

/// Full findings view of one report, laid out for an 80-column pane.
pub fn report_text(_report: &Report, _columns: usize) -> String {
    String::new()
}

/// Machine-readable snapshot. Same masking rules as everything else.
pub fn report_json(_report: &Report) -> String {
    String::from("{}")
}

pub fn run_once(_config: &Config) -> Result<()> {
    Ok(())
}

pub fn run_json(_config: &Config) -> Result<()> {
    Ok(())
}

/// Live findings pane: `a` acknowledges the selected finding, `A` acknowledges
/// them all, `q` quits.
pub fn run_watch(_config: &Config) -> Result<()> {
    Ok(())
}
