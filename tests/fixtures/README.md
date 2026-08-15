# Test fixtures

Captured from a **live herdr 0.8.0 server** (protocol 19) with a raw socket
probe, then redacted: `/home/amadeo` became `/home/dev`, agent-session UUIDs
became zeros, and terminal titles became a neutral string. Nothing else was
changed — not the key names, not the nesting, not the fields this crate ignores.

That last part is the point. A reply carrying only what the client reads cannot
catch the client reading the wrong thing. Both of these payloads nest the real
content one level below `result` (`snapshot`, `read`), and a client that reads
`result.panes` or `result.text` gets nothing while reporting success.

| file | method | captured from |
|---|---|---|
| `session_snapshot.json` | `session.snapshot` | a live 10-pane session, trimmed to four representative panes |
| `pane_read.json` | `pane.read` | a live pane, body replaced with synthetic build output |

`session_snapshot.json` deliberately keeps one pane (`w0:p1`) with **no `agent`
key at all**, because that absence is the default scan filter, and two panes in
one workspace, because a workspace badge has to aggregate.

**Never put a real credential in this directory.** Positive detection vectors
live in the scanner's own corpus and are structurally valid but obviously fake.
