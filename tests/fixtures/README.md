# Test fixtures

Captured from a **live herdr 0.8.0 server** (protocol 19) with a raw socket
probe, then redacted: `/home/amadeo` became `/home/dev`, agent-session UUIDs
became zeros, and terminal titles became a neutral string. Nothing else was
changed — not the key names, not the nesting, not the fields this crate ignores.

That last part is the point. A reply carrying only what the client reads cannot
catch the client reading the wrong thing. All three payloads nest the real
content one level below `result` (`snapshot`, `read`, or `process_info`), and a
client that reads the corresponding fields directly from `result` gets nothing
while reporting success.

| file | method | captured from |
|---|---|---|
| `session_snapshot.json` | `session.snapshot` | a live 10-pane session, trimmed to four representative panes |
| `pane_read.json` | `pane.read` | a live pane, body replaced with synthetic build output |
| `pane_process_info.json` | `pane.process_info` | a live pane running `curl` |
| `sarif-2.1.0.json` | SARIF output validation | SchemaStore's draft-07 rendering of the OASIS SARIF 2.1.0 errata01 schema |

`sarif-2.1.0.json` is the exact document our output's `$schema` field points at,
retrieved from SchemaStore on 2026-08-22. Its SHA-256 is
`7c9688f0a1c4a4e1649ecc78521087e664729c1dff56ee8212ff195c7b16132a`; it is
vendored so the test suite validates offline rather than trusting the network.

`session_snapshot.json` deliberately keeps one pane (`w0:p1`) with **no `agent`
key at all**, because that absence is the default scan filter, and two panes in
one workspace, because a workspace badge has to aggregate.

`pane_process_info.json` deliberately plants an obviously fake credential in
`argv` and `cmdline`; it proves the client never reads either field.

**Never put a real credential in this directory.** Positive detection vectors
live in the scanner's own corpus and are structurally valid but obviously fake.
