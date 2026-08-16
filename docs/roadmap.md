# Roadmap

Ideas for future work, kept in the order they would most improve the plugin. None
of this is committed to a release, and nothing here is a promise.

Everything below stays inside the two rules the plugin rests on: **a secret value
never leaves the scanner**, and **precision beats recall every time**. An idea that
would raise recall by making the scanner cry wolf does not belong here, however
clever it is.

## Correctness and honesty

### Remove the `entropy` configuration key

It is currently accepted, does nothing, and records a note saying so. The README
already explains why a Shannon-entropy heuristic cannot survive a page of base64
in terminal output, so this is not a feature waiting to be built — it is a
configuration key that promises something the project has decided against.

A key that a user can set and that silently changes nothing is worse than no key.
Removing it, and saying why in the changelog, is more honest than leaving a
placeholder that reads like an unfinished feature.

### Backfill scrollback when the watcher starts

Each cycle reads the most recent `lines` lines of each pane, so a credential that
scrolled past before the watcher was enabled is never found. Reading the available
scrollback once at startup would close the gap between "I turned this on" and "this
has been watching all along", which is the gap most likely to embarrass someone.

The budget and the round-robin behaviour still apply; a backfill that cannot see
the whole history must say so, exactly as a truncated cycle does now.

### Report finding provenance

A finding names the pane it appeared in. It does not name what put it there. The
command, or the agent turn, that produced the line is the thing a person needs in
order to fix the cause rather than acknowledge the symptom.

## Reacting faster

### Event-driven scanning

The scanner polls, so a five-second badge is a five-second-old badge. Upstream
[Discussion #2831](https://github.com/herdrdev/herdr/discussions/2831) proposes
`pane.output_changed` and revision semantics. If that lands, scanning on change
rather than on a timer removes the lag without raising the read budget.

This is blocked on upstream and should not be worked around with a shorter
interval, which would only spend more of the read budget to shrink the window.

## Configuration and tuning

### Per-repository and per-workspace configuration

One rule set for every workspace is wrong for anyone who works across a company
repository and a personal one. Overlays keyed by workspace or repository root
would let the noisy repository silence a pattern without weakening the scan
everywhere else.

### Author allowlist entries from the findings pane

Silencing a false positive currently means writing a regex into a configuration
file by hand. Acknowledging a finding with "and always ignore this exact value"
should be able to write that entry, correctly escaped, on the user's behalf.

The escaping is the point: a hand-written allowlist regex that accidentally
matches more than intended is a silent hole in a security tool.

### Versioned rule packs

Detection rule names are public interface — the allowlist and the notification
rate limiter key on them. Named, versioned bundles of rules would let a team share
the set it needs without every rule shipping in the default, and without renaming
anything already in use.

### A calibration mode

`--calibrate` would run the current rule set over a sample of the user's own real
pane output and report what it *would* have fired on, without badging anything.

Precision is the product, and precision is measurable. Letting someone measure it
against their own terminal before they trust it is a stronger argument than any
README claim.

## Coverage, precision-first

### More provider rules

Each of these has a distinctive enough shape to match without guessing:

- Postgres and MySQL connection URLs carrying a password
- JDBC connection strings
- Docker registry auth blobs
- Kubernetes service-account tokens
- Vault tokens

Each new rule needs a corpus entry that proves it fires, and a negative entry that
proves it does not fire on the nearest innocent lookalike. A rule that cannot be
given the second one should not ship.

### Multi-line secrets beyond key blocks

Private key blocks are handled. JSON and YAML credentials printed across several
lines are not, and both are ordinary output from cloud tooling.

## Living with it

### Per-rule rotation guidance

A finding says a key leaked. It does not say where to go and revoke it. A link to
the provider's rotation page, per rule, turns the acknowledgement step into a fix.

This stays advisory. The plugin does not rotate, revoke, or contact a provider,
and that should not change.

### Quiet mode

Screen-sharing or recording a demo is exactly when badges are most distracting and
least useful, and exactly when someone might uninstall the plugin rather than mute
it for ten minutes. A timed pause is a better answer than an uninstall.

### `--explain <rule>`

The README explains why each rule is shaped the way it is, and why several obvious
candidates are deliberately excluded. That reasoning is more useful at the moment a
rule fires, or fails to. Making it queryable from the terminal puts it there.

## Export

### JSON and SARIF findings export

For a security review or an incident write-up. Values stay redacted in the export,
exactly as they are everywhere else the plugin writes.
