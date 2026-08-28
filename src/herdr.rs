//! Thin herdr client wrappers over Crook's bounded Unix-socket transport.
//!
//! Crook owns connection preflight, newline-delimited envelopes, response
//! bounds, and transport retries. This module owns Redact's request parameters,
//! retry-safety choices, result validation, and domain reduction.
//!
//! Three response shapes in this file nest their payload one level below
//! `result` (`snapshot`, `read`, and `process_info`). They are read explicitly
//! and treat an absent object as a hard error, because the quiet fallback — no
//! panes, no text, or no process context — is indistinguishable from a
//! legitimately idle session.

use std::fmt;
use std::path::PathBuf;

use crook::client::{Client, Error as CrookError, RetrySafety};
use crook::env::PluginEnv;
use serde_json::{json, Value};

use crate::config;
use crate::model::{PaneRef, PaneText};
use crate::Result;

/// herdr rejects a `ttl_ms` outside this range with `invalid_metadata_ttl`.
const MIN_TTL_MS: u64 = 1;
const MAX_TTL_MS: u64 = 86_400_000;

/// The wire spelling is snake_case even though the CLI flag is hyphenated.
/// `recent-unwrapped` is rejected outright — see docs/herdr-protocol.md.
///
/// Unwrapped is the right source for a scanner: it joins soft-wrapped lines, and
/// a credential split across a wrap boundary is invisible to a line-oriented
/// matcher.
const READ_SOURCE: &str = "recent_unwrapped";

/// A herdr error envelope, carried as a real error type so callers can tell
/// `pane_not_found` (a pane closed under us — benign) from a transport failure
/// (we are blind and should say so).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HerdrError {
    pub code: String,
    pub message: String,
}

impl fmt::Display for HerdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "herdr {}: {}", self.code, self.message)
    }
}

impl std::error::Error for HerdrError {}

/// Current process context for one pane, reduced before it leaves the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaneProcessInfo {
    pub pane_id: String,
    pub foreground_process_name: Option<String>,
    pub foreground_process_pid: Option<u32>,
}

/// Error code from a herdr error envelope, or `None` for a transport failure.
pub fn error_code<'a>(err: &'a (dyn std::error::Error + 'static)) -> Option<&'a str> {
    err.downcast_ref::<HerdrError>().map(|e| e.code.as_str())
}

#[derive(Debug)]
pub struct Herdr {
    client: Client,
}

impl Herdr {
    pub fn connect() -> Result<Self> {
        let plugin_env = PluginEnv::resolve(config::PLUGIN_ID);
        let client =
            Client::connect(plugin_env.socket_path(), "redact").map_err(map_crook_error)?;
        Ok(Self { client })
    }

    /// One `session.snapshot` call, reduced to the panes.
    ///
    /// Every pane is returned, agent or not; filtering to agent panes is the
    /// caller's decision because `--all-panes` exists.
    pub fn panes(&mut self) -> Result<Vec<PaneRef>> {
        let result = self.call("session.snapshot", json!({}), RetrySafety::Idempotent)?;
        // The payload is `{"type":"session_snapshot","snapshot":{…}}`; the arrays
        // live one level down. Reading them off the result object silently
        // yields no panes at all, which looks exactly like an idle session — so
        // an absent `snapshot` is an error, not a fallback.
        let snapshot = result.get("snapshot").ok_or_else(|| {
            format!(
                "session.snapshot returned no `snapshot` object (result type `{}`)",
                text(&result, "type").unwrap_or("missing")
            )
        })?;
        Ok(reduce_snapshot(snapshot))
    }

    /// One `pane.read`. Returns the pane's recent output with soft wraps joined.
    ///
    /// `lines` is a budget, not a guarantee: herdr sets `truncated` when it had
    /// more to give, and that flag is carried through to the UI rather than
    /// swallowed.
    pub fn read_pane(&mut self, pane_id: &str, lines: u32) -> Result<PaneText> {
        let result = self.call(
            "pane.read",
            json!({
                "pane_id": pane_id,
                "source": READ_SOURCE,
                "lines": lines,
            }),
            RetrySafety::Idempotent,
        )?;
        // Same nesting trap as `session.snapshot`: the payload is under `read`.
        // A client reading `result.text` finds nothing and reports a silent pane.
        let read = result.get("read").ok_or_else(|| {
            format!(
                "pane.read on {pane_id} returned no `read` object (result type `{}`)",
                text(&result, "type").unwrap_or("missing")
            )
        })?;
        // An empty pane is legitimate, so an empty string is fine — but an
        // absent or non-string `text` is a protocol change, and reporting it as
        // "this pane is clean" would be exactly the invisible failure this
        // plugin cannot afford.
        let body = read
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("pane.read on {pane_id} carried no `text` string"))?;
        Ok(PaneText {
            pane_id: text(read, "pane_id").unwrap_or(pane_id).to_string(),
            text: body.to_string(),
            truncated: read
                .get("truncated")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }

    /// One `pane.process_info` call, reduced to safe process context.
    pub fn process_info(&mut self, pane_id: &str) -> Result<PaneProcessInfo> {
        let result = self.call(
            "pane.process_info",
            json!({ "pane_id": pane_id }),
            RetrySafety::Idempotent,
        )?;
        // Same nesting trap as `session.snapshot` and `pane.read`: silently
        // accepting an absent payload makes a protocol break look like normal
        // missing context.
        let process_info = result
            .get("process_info")
            .filter(|value| value.is_object())
            .ok_or_else(|| {
                format!(
                    "pane.process_info on {pane_id} returned no `process_info` object (result type `{}`)",
                    text(&result, "type").unwrap_or("missing")
                )
            })?;
        let foreground_process = process_info
            .get("foreground_processes")
            .and_then(Value::as_array)
            .and_then(|processes| processes.first());
        // `argv` and `cmdline` are deliberately not read: either may contain the credential itself.
        Ok(PaneProcessInfo {
            pane_id: text(process_info, "pane_id").unwrap_or(pane_id).to_string(),
            foreground_process_name: foreground_process
                .and_then(|process| text(process, "name"))
                .map(str::to_string),
            foreground_process_pid: foreground_process
                .and_then(|process| process.get("pid"))
                .and_then(Value::as_u64)
                .and_then(|pid| u32::try_from(pid).ok()),
        })
    }

    /// Sets one badge token on a workspace, with a TTL so it self-clears if this
    /// process dies.
    pub fn set_workspace_badge(
        &mut self,
        workspace_id: &str,
        token: &str,
        value: &str,
        ttl_ms: u64,
    ) -> Result<()> {
        self.call(
            "workspace.report_metadata",
            json!({
                "workspace_id": workspace_id,
                "source": config::plugin_id(),
                "tokens": { token: value },
                "ttl_ms": ttl_ms.clamp(MIN_TTL_MS, MAX_TTL_MS),
            }),
            RetrySafety::Never,
        )?;
        Ok(())
    }

    /// Clears one workspace badge token. Null value, no TTL.
    pub fn clear_workspace_badge(&mut self, workspace_id: &str, token: &str) -> Result<()> {
        self.call(
            "workspace.report_metadata",
            json!({
                "workspace_id": workspace_id,
                "source": config::plugin_id(),
                "tokens": { token: Value::Null },
            }),
            RetrySafety::Never,
        )?;
        Ok(())
    }

    /// Sets one badge token on a pane — the agent sidebar row, which is where
    /// the finding actually is.
    ///
    /// Tokens only. This is `pane.report_metadata`, not `pane.report_agent`: it
    /// does not claim the pane as an agent, so a spare pane never starts
    /// rendering as a live idle one.
    pub fn set_pane_badge(
        &mut self,
        pane_id: &str,
        token: &str,
        value: &str,
        ttl_ms: u64,
    ) -> Result<()> {
        self.call(
            "pane.report_metadata",
            json!({
                "pane_id": pane_id,
                "source": config::plugin_id(),
                "tokens": { token: value },
                "ttl_ms": ttl_ms.clamp(MIN_TTL_MS, MAX_TTL_MS),
            }),
            RetrySafety::Never,
        )?;
        Ok(())
    }

    pub fn clear_pane_badge(&mut self, pane_id: &str, token: &str) -> Result<()> {
        self.call(
            "pane.report_metadata",
            json!({
                "pane_id": pane_id,
                "source": config::plugin_id(),
                "tokens": { token: Value::Null },
            }),
            RetrySafety::Never,
        )?;
        Ok(())
    }

    pub fn notify(&mut self, title: &str, body: &str) -> Result<()> {
        self.call(
            "notification.show",
            json!({ "title": title, "body": body }),
            RetrySafety::Never,
        )?;
        Ok(())
    }

    fn call(&mut self, method: &str, params: Value, retry_safety: RetrySafety) -> Result<Value> {
        self.client
            .request(method, params, retry_safety)
            .map_err(map_crook_error)
    }
}

fn map_crook_error(error: CrookError) -> Box<dyn std::error::Error> {
    match error {
        CrookError::Protocol { code, message } => Box::new(HerdrError { code, message }),
        error => Box::new(error),
    }
}

/// Non-empty string field, since herdr reports absent context as an empty string
/// rather than as a missing key.
fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value.get(key).and_then(Value::as_array).map_or(&[], |a| a)
}

/// Reduces a `session.snapshot` result to its panes. The flat sibling arrays are
/// joined on `pane_id` and `workspace_id`.
fn reduce_snapshot(snapshot: &Value) -> Vec<PaneRef> {
    // `agents[].name` is the user's own label for the agent ("gitsmith"),
    // `agents[].agent` is the program ("claude"). `agent_session` is an object on
    // the wire, not a string, so it is no use as a display name.
    let mut agent_names: Vec<(&str, &str)> = Vec::new();
    for agent in array(snapshot, "agents") {
        if let (Some(pane_id), Some(name)) = (
            text(agent, "pane_id"),
            text(agent, "name").or_else(|| text(agent, "agent")),
        ) {
            agent_names.push((pane_id, name));
        }
    }

    let mut labels: Vec<(&str, &str)> = Vec::new();
    for workspace in array(snapshot, "workspaces") {
        if let Some(id) = text(workspace, "workspace_id") {
            labels.push((id, text(workspace, "label").unwrap_or(id)));
        }
    }

    let mut panes = Vec::new();
    for pane in array(snapshot, "panes") {
        // A pane with no id cannot be read or badged, so there is nothing to do
        // with it. A pane with no *workspace* id is a different matter: it can
        // still be read and it can still carry a pane badge, only its workspace
        // badge has nowhere to go.
        //
        // Dropping it here was a silent hole. It would not be scanned, and it
        // would also not be counted as scanned, skipped or unread — it would
        // simply not exist, and `prune_to` would then delete any findings it
        // already had. herdr reports absent context as an empty string, so this
        // is reachable rather than theoretical.
        let Some(pane_id) = text(pane, "pane_id") else {
            continue;
        };
        let workspace_id = text(pane, "workspace_id").unwrap_or_default();
        panes.push(PaneRef {
            pane_id: pane_id.to_string(),
            workspace_id: workspace_id.to_string(),
            tab_id: text(pane, "tab_id").unwrap_or_default().to_string(),
            workspace_label: labels
                .iter()
                .find(|(id, _)| *id == workspace_id)
                .map_or(workspace_id, |(_, label)| *label)
                .to_string(),
            // The agents array wins over `panes[].agent` when both are present:
            // it is where a user-chosen name lives.
            agent: agent_names
                .iter()
                .find(|(id, _)| *id == pane_id)
                .map(|(_, name)| (*name).to_string())
                .or_else(|| text(pane, "agent").map(str::to_string)),
            title: text(pane, "terminal_title_stripped")
                .or_else(|| text(pane, "terminal_title"))
                .map(str::to_string),
            cwd: text(pane, "cwd").map(PathBuf::from),
        });
    }
    panes
}
