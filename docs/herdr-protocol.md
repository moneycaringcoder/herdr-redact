# herdr socket notes for redact (verified against herdr 0.8.0 and 0.8.2)

Working notes for this plugin's socket client. The original observations were
captured from a live herdr 0.8.0 server (protocol 19) with a raw socket probe and
from the bundled schema (`herdr api schema --json`), not inferred from
documentation. The scanning-relevant observations were revalidated on
2026-08-27 against a locally installed herdr 0.8.2 server (protocol 20). That
revalidation used the same raw
newline-delimited JSON transport: 40 `pane.read` calls covered ten existing
panes and all four sources, passive revision monitoring covered all ten panes,
and framing, error and subscription probes used metadata-only requests. No
input was sent to a pane. The one 0.8.0 capture that had used `pane.send_text`
was therefore checked against the 0.8.2 implementation and upstream discussion
rather than repeated; that provenance is called out at trap 4.

The transport, badge and daemon-lifecycle sections repeat what
`herdr-collide/docs/herdr-protocol.md` established; the `pane.read` section is
where this plugin's traps live.

## 0.8.0 to 0.8.2

There is no 0.8.1 tag or changelog entry; upstream goes directly from 0.8.0 to
0.8.2. The scanner-adjacent part of the delta was reviewed from the 0.8.2
changelog and schema. It adds `pane.input.set`, right-click passthrough through
`pane.split.right_click`, experimental pane graphics layers, `agent_blocked`
rejection when prompting an agent already at a question or approval, and
marketplace indexing. None changes the pane-read or output-event contract the
scanner depends on, so the minimum herdr version remains 0.8.0.

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

The 0.8.2 probes reconfirmed all three constraints. Sending two
`session.snapshot` requests in one write produced one response for the first ID
and then a connection reset; a normal single request produced one response and
EOF.

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

Revalidated on 0.8.2: all 40 reads across ten panes and `visible`, `recent`,
`recent_unwrapped` and `detection` returned `revision: 0`. Nine of those panes
had a non-zero `PaneInfo.revision`.

So `PaneReadResult.revision` **cannot** be used to skip an unchanged pane. A
scanner that did would never scan anything and would report a permanently clean
session. Change detection has to come from the text itself; this plugin hashes
it.

### Trap 4 — `PaneInfo.revision` is not an output counter either

The obvious repair for trap 3 is to use the *other* revision — the one on
`PaneInfo`, from `pane.list` and `session.snapshot`, which unlike the read
result's is a real moving counter (observed at 6183 on a busy pane). Reading a
pane only when its snapshot revision has moved would turn a thirty-round-trip
cycle into two or three.

It does not work. Verified live: a pane at revision 6 was sent
`echo revision-probe\n` through `pane.send_text`, produced output, and had its
screen change — and the revision was still 6 two seconds later, and still 6
after that.

The 0.8.2 revalidation did not repeat that write probe: no input was sent to any
pane. During a 20.2-second passive sample of ten panes, 192 text-digest changes
all happened in intervals where `PaneInfo.revision` also moved, so that passive
sample alone neither reproduces nor disproves the 0.8.0 capture. The 0.8.2
implementation still makes the semantics unambiguous: `PaneInfo.revision` is
`TerminalState.revision`, which changes with the stripped terminal title, while
`PaneReadResult.revision` is still hard-coded to zero. Upstream
[Discussion #2831](https://github.com/herdrdev/herdr/discussions/2831) also
records that the `pane.list` revision does not track content. The 0.8.0
conclusion therefore still holds, with source and upstream-discussion
provenance rather than a second pane-write capture.

Whatever `PaneInfo.revision` counts, it is not "this pane produced output". Do
not build change detection on it. This plugin hashes the text it read and
compares the hash, which costs a round trip per pane per cycle and is the
reason the cycle needs a time budget at all.

### Trap 5 — the event machinery cannot watch a session for output

Traps 3 and 4 rule out both revision counters, which leaves the question of why
this plugin polls at all when the schema carries events. This was checked
against the bundled schemas for protocol 19 and protocol 20 and against a live
0.8.2 server on 2026-08-27. The capability needed is "tell me, on one
connection, when any pane printed something", and it still does not exist.

`pane_output_changed` still exists as an `EventKind`, an `EventData` shape and
an `EventMatch` variant, and that match still requires a `pane_id`. It is not a
usable per-pane wait in production, either: a live 0.8.2 `events.wait` request
for it returned `unsupported_event_wait_match` because production waits support
pane agent-status matches only. Upstream
[Discussion #2831](https://github.com/herdrdev/herdr/discussions/2831) confirms
that no production path emits this event, and the plugin-manifest hook allowlist
deliberately excludes it until high-volume output-change hook semantics exist.

`events.subscribe` **does** stream many events down one connection. The 0.8.0
capture saw `subscription_started` followed by 51 further frames in five
seconds; a 0.8.2 `pane.updated` subscription saw the acknowledgement and 31
frames in three seconds. But the subscription enum still has no
`pane.output_changed` member: a live request for it was rejected as an unknown
variant. The pane-related members remain `pane.created`, `pane.closed`,
`pane.updated`, `pane.focused`, `pane.moved`, `pane.exited`,
`pane.agent_detected`, `pane.output_matched`, `pane.agent_status_changed` and
`pane.scroll_changed`.

Two of those look like a way in and are not:

- `pane.output_matched` takes a substring or regex and returns `matched_line`.
  Building on it hands detection to herdr's regex engine, which throws away every
  structural check that buys this plugin its precision — the JWT header that must
  really decode to JSON carrying `alg`, the checksums the provider rules
  recompute, `has_varied_body`, `plausible_secret_value` — and it asks the server
  to send the raw line containing the credential back over the socket into a code
  path that is not `scan.rs`. That breaks both of the rules in CONTRIBUTING.md.
- `pane.updated` is subscribable session-wide but is not an output signal.
  `PaneInfo.revision` has the title-oriented semantics described by trap 4, and
  Discussion #2831 records same-status content changes that produce no signal.
  A scanner built on `pane.updated` would miss output while appearing to watch,
  which is the worst failure shape available.

So the poll stays, and the cycle keeps its deadline and its rotation. Revisit if
herdr adds a session-wide output-changed subscription; shortening the poll
interval is not the substitute, because it spends more read budget to shrink the
window and makes the truncation notes worse.

### Read latency is per-pane and can be seconds

Measured on a live session of 37 panes with about twenty agents running:
`session.snapshot` answered in 0.02 s, and `pane.read` answered in **0.0 s for
most panes but 0.7–1.7 s for some** — consistently the ones in split layouts
with small viewports, and not correlated with how much text came back.

The smaller 0.8.2 revalidation session did not reproduce that slow tail: 40
reads across ten panes ranged from 0.0002 to 0.0042 s, with a 0.0006 s median.
That is a measurement of this session, not evidence that the 0.8.0 busy-session
worst case disappeared, so the deadline and rotation requirements remain.

At a second a pane, thirty panes is half a minute. Two consequences for anything
that polls every pane:

1. Give the whole cycle a deadline, or a slow server turns "scan every five
   seconds" into a cycle that never returns and a badge that is never pushed.
2. Resume where the last cycle stopped. A deadline with no rotation reads the
   first few panes for ever and never reaches the rest, which is a permanent
   blind spot dressed up as a clean session.

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
