# herdr socket notes for redact (verified against herdr 0.8.0, protocol 19)

Working notes for this plugin's socket client. Everything below was captured
from a live herdr 0.8.0 server with a raw socket probe and from the bundled
schema (`herdr api schema --json`), not inferred from documentation. The
transport, badge and daemon-lifecycle sections repeat what
`herdr-collide/docs/herdr-protocol.md` established; the `pane.read` section is
new and is where this plugin's traps live.

## Transport

`HERDR_SOCKET_PATH` is injected into every command herdr spawns. Fall back to
`$XDG_CONFIG_HOME/herdr/herdr.sock` only for hand invocation. Treat an
empty-string env var as unset.

Framing is **newline-delimited JSON**. Not length-prefixed. There is no
`jsonrpc` field.

```
request : {"id":"<string>","method":"<name>","params":{...}}\n
success : {"id":"<string>","result":{"type":"<snake_case>",...}}\n
failure : {"id":"<string>","error":{"code":"<string>","message":"<string>"}}\n
```

- `id` must be a **string**.
- `params` is **mandatory and must be an object** — send `{}` for methods that
  take no parameters, never `null`.
- The server answers **one request per connection** and then sends EOF. Every
  call must be able to reconnect and retry once; that retry is also what carries
  the client across a `herdr update --handoff`.

## `pane.read` — the method this plugin is built on

```json
{"id":"redact:1","method":"pane.read","params":{
  "pane_id":"w16:p1","source":"recent_unwrapped","lines":400}}
```

Params (`PaneReadParams`): `pane_id` and `source` are **required**; `lines`,
`format` (`text` | `ansi`, default `text`) and `strip_ansi` (default `true`) are
optional.

### Trap 1 — the result is nested under `read`

```json
{"id":"redact:1","result":{"type":"pane_read","read":{
  "pane_id":"w16:p1","workspace_id":"w16","tab_id":"w16:t1",
  "source":"recent_unwrapped","format":"text",
  "text":"…","revision":0,"truncated":false}}}
```

Exactly the same shape trap as `session.snapshot`, whose arrays live under
`result.snapshot`. A client that reads `result.text` gets `None` and, if it
degrades quietly, reports a pane with no output — indistinguishable from an idle
pane. **Treat a missing `read` object as a hard error**, never as empty text.

### Trap 2 — the wire spelling of the source is snake_case

The CLI takes `--source recent-unwrapped` (hyphen). The socket takes
`recent_unwrapped` (underscore) and rejects the hyphen outright:

```
{"code":"invalid_request","message":"invalid request: unknown variant
 `recent-unwrapped`, expected one of `visible`, `recent`, `recent_unwrapped`,
 `detection` at line 1 column 115"}
```

That is a loud failure, which is the good case. Omitting `source` entirely is
also loud: `missing field \`source\``.

### Trap 3 — `revision` in the read result is always 0

`PaneInfo.revision` from `pane.list`/`session.snapshot` is a real, moving
counter (observed 6183 on a busy pane). `PaneReadResult.revision` was **0 for
every pane and every source** in the live capture, including panes whose
`PaneInfo.revision` was non-zero.

So `PaneReadResult.revision` **cannot** be used to skip an unchanged pane. A
scanner that did would never scan anything and would report a permanently clean
session. Change detection has to come from the text itself (this plugin hashes
it) or from `PaneInfo.revision` in the snapshot.

### Other observed behaviour

- `truncated` is `true` when `lines` cuts the available output short, `false`
  otherwise. It is a useful "you are not seeing everything" signal for the UI.
- With no scrollback present, `visible`, `recent`, `recent_unwrapped` and
  `detection` all return the same text; `recent_unwrapped` differs by joining
  soft-wrapped lines, which is what a scanner wants — a secret split across a
  wrap boundary is invisible to a line-oriented matcher.
- Unknown pane: `{"code":"pane_not_found","message":"pane nosuch:p9 not found"}`.
  That is data (a pane closed under us), not a transport failure.

## `session.snapshot` — params `{}`

Result is `{"type":"session_snapshot","snapshot":{…}}`; the arrays live one level
down under `snapshot`. Flat sibling arrays joined by ID:

```
snapshot.workspaces[]  workspace_id, number, label, focused, pane_count, …
snapshot.panes[]       pane_id, terminal_id, workspace_id, tab_id, focused,
                       agent?, agent_status, revision, cwd?, foreground_cwd?,
                       terminal_title?, terminal_title_stripped?, tokens?,
                       agent_session?, scroll?
snapshot.agents[]      pane_id, tab_id, workspace_id, agent, agent_session, name?
snapshot.tabs[] snapshot.layouts[]
```

For this plugin the interesting field is `panes[].agent`: present and non-empty
on a pane running an agent, **absent entirely** on a plain shell pane. That is
the default scan filter.

`panes[].tokens` is a readback of what plugins have set, which makes it useful
for verifying our own writes in tests and live.

## Badges

### `workspace.report_metadata` — the space sidebar

Required: `workspace_id`, `source`, `tokens`. `tokens` is a **merge patch** —
omitted names untouched, `null` deletes. Max 16 keys per report, 32 stored per
target. Names match `^[A-Za-z0-9_-]{1,32}$`; **no `$` on the wire** (the `$`
prefix is herdr's `config.toml` row syntax). `ttl_ms` is 1..86_400_000.

### `pane.report_metadata` — the agent sidebar

Same token semantics, keyed on `pane_id` instead. **Verified live**: setting
`{"pane_id":"w16:p1","source":"moneycaringcoder.redact",
"tokens":{"redact_secret":"! 1"},"ttl_ms":20000}` returns `{"type":"ok"}`, and
the token reads back in `pane.list` alongside herdr's own `title`, `provider`,
`context` and `limit` tokens. Clearing with a `null` value removes it.

Setting tokens through `pane.report_metadata` does **not** claim the pane as an
agent — that is `pane.report_agent`, which this plugin never calls. So there is
no risk of a spare pane rendering as a live idle agent, and no untracked
no-TTL state left behind by a killed daemon.

Observed on 0.8.0: sending `ttl_ms` alongside a `null` (clear) is accepted
rather than rejected. We still omit it, matching the documented contract, so a
stricter server would not break us.

This plugin badges the **pane** (the agent row, where the finding actually is)
and the **workspace** (the space row, so it is visible when the agent row is
collapsed). Both use TTL so the badge self-heals if the daemon is killed.

### Colour by token name

herdr renders a token value as flat text and cannot colour by content, so
severity travels in the token *name*. Exactly one is lit at a time; the others
are cleared.

```
redact_secret   a high-confidence provider credential, unacknowledged
redact_weak     only low-confidence findings (env-style assignment), unacknowledged
```

Nothing renders until the user's `config.toml` names the tokens, which is what
`--setup` is for. Rows reload live via `herdr server reload-config`.

## `notification.show` — params `{title, body?, sound?, position?}`

Answers `{"type":"notification_show","shown":…,"reason":…}`, not `{"type":"ok"}`.

## Daemon lifecycle

`[[startup]]` hooks run on both a fresh server start and a live handoff, so one
`--restore` verb covers both. A daemon herdr spawned as a child would die with
herdr; `--enable` re-execs the binary as `--daemon` detached via `setsid()` in
`pre_exec`.

State lives in `HERDR_PLUGIN_STATE_DIR`:

- `updater.pid` — is a daemon live right now (guard against pid reuse by
  comparing `/proc/<pid>/comm` on Linux)
- `enabled` — did the user ever ask for one

| verb | behaviour |
|---|---|
| `--enable` | mark enabled **first**, no-op if a live pid exists, else spawn detached |
| `--disable` | mark disabled **first**, request stop, **await exit**, then sweep every current pane and workspace over a fresh connection |
| `--toggle` | disable if live, else enable |
| `--restore` | silent no-op unless the enabled marker is set and no daemon is live |

## Plugin execution environment

Commands are argv arrays run with **no shell**, cwd = plugin root, and a minimal
`PATH`. Plugins run on the **server** host. `herdr plugin link .` does not run
`[[build]]`; `herdr plugin install` does. Logs are in-server only
(`herdr plugin log list`).
