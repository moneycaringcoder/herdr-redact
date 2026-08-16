//! herdr socket client.
//!
//! Newline-delimited JSON over the socket at `HERDR_SOCKET_PATH`. The server
//! answers exactly one request per connection and then closes, so every call
//! must be able to reconnect and retry once — see docs/herdr-protocol.md.
//!
//! Two response shapes in this file nest their payload one level below `result`
//! (`snapshot` and `read`). Both are read explicitly and both treat an absent
//! object as a hard error, because in each case the quiet fallback — no panes,
//! no text — is indistinguishable from a legitimately idle session.

use std::fmt;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::config;
use crate::model::{PaneRef, PaneText};
use crate::Result;

/// Long enough that a busy server is not mistaken for a dead one, short enough
/// that the scan loop can never wedge behind one call.
const IO_TIMEOUT: Duration = Duration::from_secs(15);

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

/// Error code from a herdr error envelope, or `None` for a transport failure.
pub fn error_code<'a>(err: &'a (dyn std::error::Error + 'static)) -> Option<&'a str> {
    err.downcast_ref::<HerdrError>().map(|e| e.code.as_str())
}

/// Split so that only transport failures are retried. Retrying a rejected
/// request would just be rejected again, and would double-count against herdr's
/// own error accounting.
enum Failure {
    Transport(String),
    Protocol(HerdrError),
}

#[derive(Debug)]
pub struct Herdr {
    socket_path: PathBuf,
    next_id: u64,
}

impl Herdr {
    pub fn connect() -> Result<Self> {
        let socket_path = socket_path()?;
        // Dial once so a missing server is reported here, with the path, rather
        // than as a confusing failure inside the first call.
        dial(&socket_path)?;
        Ok(Self {
            socket_path,
            next_id: 0,
        })
    }

    /// One `session.snapshot` call, reduced to the panes.
    ///
    /// Every pane is returned, agent or not; filtering to agent panes is the
    /// caller's decision because `--all-panes` exists.
    pub fn panes(&mut self) -> Result<Vec<PaneRef>> {
        let result = self.call("session.snapshot", json!({}))?;
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
        )?;
        Ok(())
    }

    pub fn notify(&mut self, title: &str, body: &str) -> Result<()> {
        self.call("notification.show", json!({ "title": title, "body": body }))?;
        Ok(())
    }

    fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        self.next_id += 1;
        let id = format!("redact:{}", self.next_id);
        match self.call_once(&id, method, &params) {
            Ok(result) => Ok(result),
            Err(Failure::Protocol(err)) => Err(Box::new(err)),
            // One request per connection is the normal path, not an error path:
            // the server EOFs after answering, so the connection we would reuse
            // is already gone. The same retry carries the client across a
            // `herdr update --handoff`.
            Err(Failure::Transport(first)) => match self.call_once(&id, method, &params) {
                Ok(result) => Ok(result),
                Err(Failure::Protocol(err)) => Err(Box::new(err)),
                Err(Failure::Transport(second)) => {
                    Err(format!("{method} failed twice: {first}; on retry: {second}").into())
                }
            },
        }
    }

    fn call_once(
        &self,
        id: &str,
        method: &str,
        params: &Value,
    ) -> std::result::Result<Value, Failure> {
        let stream = dial(&self.socket_path).map_err(|e| Failure::Transport(e.to_string()))?;

        // `params` is mandatory and must be an object — never null, `{}` when
        // empty.
        let params = if params.is_object() {
            params.clone()
        } else {
            Value::Object(Map::new())
        };
        let mut line = serde_json::to_string(&json!({
            "id": id,
            "method": method,
            "params": params,
        }))
        .map_err(|e| Failure::Transport(format!("could not encode request: {e}")))?;
        line.push('\n');

        (&stream)
            .write_all(line.as_bytes())
            .and_then(|()| (&stream).flush())
            .map_err(|e| Failure::Transport(format!("write to {method} failed: {e}")))?;

        // A pane read can be hundreds of kilobytes, and `read_line` on a
        // BufReader grows to fit, so the whole line is read before parsing.
        let mut response = String::new();
        BufReader::new(&stream)
            .read_line(&mut response)
            .map_err(|e| Failure::Transport(format!("read of {method} response failed: {e}")))?;
        if response.trim().is_empty() {
            return Err(Failure::Transport(
                "server closed the connection without answering".into(),
            ));
        }

        let value: Value = serde_json::from_str(response.trim_end())
            .map_err(|e| Failure::Transport(format!("malformed response to {method}: {e}")))?;

        if let Some(err) = value.get("error") {
            return Err(Failure::Protocol(HerdrError {
                code: text(err, "code").unwrap_or("unknown_error").to_string(),
                message: text(err, "message").unwrap_or("no message").to_string(),
            }));
        }
        match value.get("result") {
            Some(result) => Ok(result.clone()),
            None => Err(Failure::Transport(format!(
                "response to {method} carried neither result nor error"
            ))),
        }
    }
}

fn dial(socket_path: &Path) -> Result<UnixStream> {
    let stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("cannot reach herdr at {}: {e}", socket_path.display()))?;
    // Without these a half-open socket parks the scan loop forever.
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(stream)
}

fn socket_path() -> Result<PathBuf> {
    if let Some(path) = config::non_empty_env("HERDR_SOCKET_PATH") {
        return Ok(PathBuf::from(path));
    }
    let config_home = config::non_empty_env("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| config::non_empty_env("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or("HERDR_SOCKET_PATH is unset and neither XDG_CONFIG_HOME nor HOME is set")?;
    Ok(config_home.join("herdr").join("herdr.sock"))
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
