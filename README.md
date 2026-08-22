<div align="center">

<img src="docs/img/logo.svg" alt="" width="96" height="96">

# redact

**Warns you when an agent pane has printed a credential — before you screenshot it, stream it, or
paste it into a chat window.**

[![CI](https://github.com/moneycaringcoder/herdr-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/moneycaringcoder/herdr-redact/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![herdr](https://img.shields.io/badge/herdr-%E2%89%A5%200.8.0-8b949e.svg)](https://herdr.dev)
[![no network](https://img.shields.io/badge/network%20calls-none-2da44e.svg)](#what-this-does-not-do)

</div>

## Read this first: what it reads, and what it never writes

**This plugin reads the terminal output of your panes.** That is the whole mechanism, and there is no
version of it that does not. Say that out loud before you install it, because it is the same output
your agents print keys, tokens and connection strings into.

Everything else about it is built to make that safe:

- **Background scanning is opt-in.** A fresh install starts nothing and reads nothing on its own.
  Nothing is read until you either enable the watcher or run a scan yourself, and disabling the
  watcher stops the reading and clears every badge it set. To be exact about which of those is which:
  `--enable` starts the background watcher, and `--once`, `--json`, `--sarif` and the **Redact:
  findings** pane each read panes for as long as you have them open, whether or not the watcher is
  running. A plugin action you invoke is you asking it to look.
- **No secret is ever written anywhere.** Not to a log, not to the state file, not into a toast, not
  into the JSON or SARIF output, not into a badge. A finding records the rule that fired, the pane it
  fired in, the agent and working directory, and the foreground process name and pid herdr reported when
  the finding was first seen. It also records the length of the value, a keyed fingerprint used only
  to recognise the same finding again, and a **masked preview** showing at most the first four and the
  last four characters, and never more than a third of the value. A short value renders as a bare `…`
  and nothing else. The command line and terminal title are deliberately **not** recorded: both can
  contain the credential itself, as in a `curl -H "Authorization: Bearer …"` command.
- **The value exists in one function and then stops existing.** The scanner is a pure function over a
  string; the type it returns has no field a raw value could travel in, so "did we leak it?" is a
  question about one module rather than about the whole program. The test suite holds that line from
  both ends: the scanner's corpus asserts it for every credential it is fed, and every rendering path
  is run against a known fake credential to assert the full value appears in none of its output.
- **It makes no network calls of any kind.** No telemetry, no update check, no reporting service, no
  "verify this key is live" call to a provider. The only thing it talks to is herdr's local socket.
- **It never writes to your panes.** See [what this does not do](#what-this-does-not-do).

Findings and permanent suppressions are kept on your machine, under
`~/.local/state/herdr/plugins/moneycaringcoder.redact/`. `redact --forget` clears both while leaving
the installation's digest key in place.

## Why

Agents `cat .env`, echo tokens into debug logs, and print `curl -H "Authorization: Bearer …"` a dozen
times an hour. Repository scanners like gitleaks and trufflehog do not help, because nothing here is
in the repository: the exposure surface is the terminal, and nothing watches that. It is a real
surface — that pane gets screenshotted into an issue, shared on a stream, or scrolled through in a
meeting.

The hard part is not detection, it is **precision**. A scanner that cries wolf gets uninstalled within
a day, and then protects nothing at all. So the rules here lean hard on structure — a prefix a
provider actually assigns, a JWT header that really base64-decodes to JSON with an `alg` — and a
handful of patterns that could not be made precise are deliberately left out.

## How it works

Each cycle takes one `session.snapshot` over herdr's socket, reads the recent output of each pane
that is running an agent, and scans it. What comes out of the scanner is already masked:

<img src="docs/img/pipeline.svg" alt="Pane output is read over herdr's socket and passed, with the rule set, into the scanner — the only place the matched value ever exists. The scanner emits a masked finding, which goes into the findings store, which drives a sidebar badge and at most one toast per rule per pane. Acknowledging a finding clears its badge; the value is still in scrollback." width="100%">

A finding stays until you acknowledge it. A secret that has scrolled out of view is still in that
pane's scrollback and still exposed, so "it went away on its own" is not a state this plugin has.

The process name and pid are a snapshot of the foreground process when the finding was first seen,
not a claim that the process printed the line. Process context is requested only after a pane produces
a new finding; a failed or empty context lookup does not affect the finding or its badge.

Each cycle has a reading budget, because reading is one round trip per pane and a loaded server can
take over a second for one of them. When the budget runs out the cycle stops, says how many panes it
did not reach, and the next cycle **starts where this one stopped** — so a session larger than one
budget is still covered in full, just over several cycles, and no pane is ever permanently unseen.

Badges are pushed with a TTL of roughly three cycles' worth of wall-clock — the interval plus that
reading budget — which is what makes the display self-healing: kill the watcher and herdr expires the
badges rather than leaving a stale warning on screen forever. Sizing the TTL off the interval alone
made the badge blink out between cycles on a large session, which is why it is not.

## What it looks like

In the sidebar, a pane that has printed something picks up a short badge next to its agent name:

```
  api      claude     ⚠ 2
  ui       codex      ⚑ 1
  docs     claude
```

`⚠ 2` means two confirmed provider credentials; `⚑ 1` means one weak match, which is usually an
`.env`-style assignment. A pane with nothing to report shows nothing at all — an empty cell means "no
findings", not "the plugin is broken". The two marks differ in shape and not only in colour, because
the colour comes from your own config and a badge has to be readable before you have set one. Counts
abbreviate once they get long (`1.2k`, `12k`), and a badge is never wider than six columns, so it
cannot push the agent name off the row.

The full picture lives in the **Redact: findings** overlay pane. This is a real capture, from a
37-pane herdr session with three deliberately fake credentials printed into one shell pane:

```
redact · findings

3 unacknowledged and 0 acknowledged, from 24 panes scanned.
1 pane skipped: not running an agent, named in `ignore_panes`, or this pane.
8 panes could not be read at all, so anything printed there is unexamined. The
  notes at the end say why.
This scan did not complete cleanly, so an empty result here does not mean there
  was nothing there. The notes at the end say what went wrong.

    id      rule               pane    preview    age
  ⚠ 3647e7  Slack token        w16:p5  xoxb…LEEX  41s
  ⚠ b02e47  AWS access key ID  w16:p5  AKI…PLE    41s
  ⚠ bd0fad  GitHub token       w16:p5  ghp_…LE01  41s

legend
  ⚠  a provider credential, not acknowledged
  ⚑  a weak match, not acknowledged
  age is how long ago the finding was first seen. The preview is masked: at most
  the first four and last four characters ever leave the scanner.

notes
  8 pane(s) were not read before this cycle's 30s budget ran out; the next cycle
    starts where this one stopped, so they are read then

The background watcher is off, so nothing is scanned between these runs —
  `redact --enable` starts it.
```

Two things in that capture are worth reading closely, because both are the plugin telling you
something inconvenient rather than something flattering:

- **`AKI…PLE`, not `AKIA…MPLE`.** The mask shows at most four characters at each end *and* never more
  than about a third of the value, so a twenty-character key gets three, not four.
- **Eight panes went unread, and the report says so twice.** That session was loaded enough that
  single pane reads took over a second; the cycle stopped at its budget rather than running on. The
  next cycle picks up where this one stopped, so nothing is permanently unseen — but a report that
  quietly said "nothing found" for those eight panes would have been a lie.

An acknowledged finding stays in the table, marked `✓` and sorted below the live ones, because the
value is still sitting in that pane's scrollback.

`a` acknowledges the selected finding. `s` acknowledges it **and permanently suppresses that exact
value for that rule**. The suppression is global across panes, so the same false positive printed in
another pane stays quiet; it does not suppress a different value from that rule or the same value
reported by a different rule. The store records only the rule's machine name and the keyed digest,
never the value or a regex that could match more than intended. The findings view and JSON report
always disclose the number of active suppressions.

`A` acknowledges every finding, `j`/`k` or the arrow keys move the selection, and `q` quits. The view
reflows down to very narrow panes. Where a pane is too narrow for a table, each finding is stacked and
the agent, working directory, and foreground process when first seen appear on following lines when
herdr supplied them.

**A scan that found nothing and a scan that could not look do not render the same.** Six panes scanned
and clean says so in words; a cycle that hit a problem says the scan did not complete cleanly and
lists what went wrong underneath. That distinction is the one thing in this plugin worth being
pedantic about, because a clean report you cannot trust is worse than no report.

### Verified live

Everything above was run against a live herdr 0.8.0 session rather than mocked up. What was observed,
in order: a scratch shell pane was given three structurally valid but obviously fake credentials; a
scan of the whole 37-pane session reported exactly those three and nothing else, from any of the
other panes, over several runs; `pane.list` showed the badge token `redact_secret: "⚠ 3"` on the
offending pane and on its workspace, stable across cycles; acknowledging one finding from a shell took
the badge to `⚠ 2` within a cycle; acknowledging the rest cleared both badges entirely; and `redact
--disable` swept the tokens and left no process behind.

The precision claim was measured the same way. Before anything fake was printed, a scan of 26 live
agent panes — real editors, real build output, real agent transcripts — reported **zero** findings and
zero notes.

Then the two hardest false positives were printed into the same pane as the fake credentials:

```
GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305
CACHE_KEY=Linux-node-8f14e45fceea167a5a36dedd4bea2543
```

The first is the public signing-key fingerprint every official `python:3.x` image prints on startup;
the second is what a CI runner echoes on every job. Both look exactly like a secret assignment and
neither is one. The same scan that reported the three planted credentials reported **neither of
them**.

## Install

```sh
herdr plugin install moneycaringcoder/herdr-redact
```

Installing runs the plugin's build step for you, so you end up with a compiled `target/release/redact`
and nothing further to do.

To develop against a local checkout instead:

```sh
git clone https://github.com/moneycaringcoder/herdr-redact
cd herdr-redact
cargo build --release          # required: `link` does NOT run the build step
herdr plugin link .
```

`herdr plugin link` deliberately skips the `[[build]]` hook, so the binary every command in
`herdr-plugin.toml` points at will not exist until you build it yourself. Rebuild by hand after every
change.

Removal:

```sh
herdr plugin unlink moneycaringcoder.redact
```

Logs are kept in the server rather than on disk:

```sh
herdr plugin log list --plugin moneycaringcoder.redact
```

## Required: add the tokens to your herdr config

**Nothing renders in the sidebar until you do this.** herdr's default sidebar rows do not name any of
this plugin's tokens, so a freshly installed `redact` will happily scan everything and display none of
it.

The quickest route is the bundled action — run **Redact: set up sidebar (start here)**. It splices the
rows below into your `config.toml`, takes a `config.toml.redact-backup` alongside it first, and
reloads herdr; if the reload fails it puts the backup back byte for byte. **Redact: undo sidebar
setup** restores that backup.

To do it by hand, add the two tokens to `~/.config/herdr/config.toml`. The agent sidebar is where the
finding actually is; the spaces sidebar carries it too, because an agent panel can be collapsed and a
badge nobody can see protects nobody:

```toml
[ui.sidebar.agents]
rows = [
  ["state_icon", "workspace"],
  ["branch",
    { token = "$redact_weak",   fg = "#FFC799" },
    { token = "$redact_secret", fg = "#FF8080" }],
]

[ui.sidebar.spaces]
rows = [
  ["state_icon", "workspace"],
  ["branch",
    { token = "$redact_weak",   fg = "#FFC799" },
    { token = "$redact_secret", fg = "#FF8080" }],
]
```

Then reload:

```sh
herdr server reload-config
```

Sidebar rows reload live — no restart, and no losing your panes.

### Why there are two tokens instead of one

herdr renders a token's *value* as flat text and cannot colour it by content. A single `$redact_status`
token could say `⚠ 2`, but it could never say it in red. So severity is encoded in the token *name*:
the plugin lights exactly one of `redact_weak` or `redact_secret` at a time and clears the other, and
each name carries its own `fg` in your config. The `$` prefix belongs to herdr's config row syntax
only; the names sent over the wire have no `$`.

There is deliberately no token for a clean pane. A pane with nothing to report clears its badge rather
than writing an empty one.

Change the colours to taste. The names must stay exactly as written, and both should be present — if
you leave one out, findings at that level simply show nothing.

## Actions, panes, and verbs

| Action | What it does |
| --- | --- |
| **Redact: set up sidebar (start here)** | Adds the tokens above to `config.toml`, backs it up, reloads herdr |
| **Redact: undo sidebar setup** | Restores the backup that setup took |
| **Redact: scan now** | One-shot scan of every agent pane |
| **Redact: calibrate** | Shows what the active rules would have fired on, without storing findings or setting badges |
| **Redact: JSON snapshot** | The same findings, machine-readable, for scripting |
| **Redact: SARIF snapshot** | SARIF 2.1.0 findings for security review and incident write-ups |
| **Redact: list detection rules** | The rules that are actually active, built-in and yours |
| **Redact: acknowledge all findings** | Clears every current warning |
| **Redact: enable / disable / toggle pane watcher** | Starts or stops background scanning |
| **Redact: quiet for 10 minutes / resume warnings** | Temporarily hides badges and toasts, or ends that pause early |

There is one pane, **Redact: findings**, placed as an overlay. It runs the live view shown above,
refreshes on the configured interval, and acknowledges through the same store the CLI and the daemon
use, so the three never disagree about what you have dismissed. It exits cleanly on `SIGINT`,
`SIGTERM` and `SIGHUP`, and restores your terminal on the way out — including if it panics. If its
stdin is not a terminal it degrades to a refresh-only view rather than failing.

Everything is also available from the command line, which is handy when the plugin is misbehaving:

```
redact — credential warnings for herdr agent panes

Usage: redact [VERB]

Scanning:
  --once              Scan every agent pane once, print the findings, exit
  --calibrate         Report what the active rules would fire on, without badging
  --json              Print the same findings as JSON and exit
  --sarif             Print the same findings as SARIF 2.1.0 and exit
  --watch             Live findings pane (a acknowledges, s permanently suppresses)
  --rules [PANE|PATH] List active rules for the base, pane, or working directory
                      A context containing `:` is read as a pane id; anything
                      else is read as a working-directory path. Which one was
                      used is reported, so a mistyped pane id is visible
  --explain <RULE>    Explain one active detection rule and exit

Findings:
  --ack <ID>          Acknowledge one finding by id or id prefix
  --suppress <ID>     Acknowledge and permanently suppress its exact value
  --suppressions      List active suppressions (rule and short digest only)
  --ack-all           Acknowledge every current finding
  --forget            Clear findings and permanent suppressions

Watcher:
  --enable            Start the background pane watcher
  --disable           Stop it and clear every badge this plugin set
  --toggle            Stop it if running, otherwise start it
  --restore           Restart it only if it was enabled (herdr startup hook)
  --daemon            Run the watcher in the foreground (internal)
  --status            Report whether the watcher is running
  --quiet <DURATION>  Hide badges and toasts for minutes, `10m`, or `1h` (max 4h)
  --loud              End quiet mode early


Sidebar setup:
  --setup             Add redact's tokens to herdr's config.toml and reload
  --setup-rollback    Restore the config.toml backup taken by --setup

Other:
  --interval <SECS>   Scan interval for --watch and --daemon (default: 5)
  --lines <N>         Lines of pane output read per scan (default: 400)
  --all-panes         Scan every pane, not only panes running an agent
  --version           Print version and exit
  --help              Show this help

redact reads the terminal output of your panes. It never writes a secret
anywhere: findings record the rule name, the pane, and a masked preview.
```

Options may come before or after the verb, so `redact --lines 800 --once` and
`redact --once --lines 800` are the same command.

`redact --sarif` prints SARIF 2.1.0 to stdout, so redirect it with a shell when a file is needed:
`redact --sarif > findings.sarif`. Values use exactly the same masked previews as every other output
surface. The export carries the public finding id as a SARIF partial fingerprint and never includes
the keyed digest.

`redact --suppress <ID>` is the command-line equivalent of pressing `s`. `redact --suppressions`
lists only each active rule name and a short keyed digest, never a preview. Suppression is permanent
until `redact --forget` clears it, matches exactly one value for one rule, and applies globally across
panes.

The watcher is off until you enable it. Once enabled it survives a herdr restart and a
`herdr update --handoff`: a startup hook re-spawns it, but only if you had it enabled when herdr went
away. Disabling it stops the watcher and sweeps every badge this plugin set, so nothing stale is left
behind.

`redact --quiet <DURATION>` is a timed display pause for screen sharing and demos. A bare number is
minutes; `10m` and `1h` are also accepted. Pauses longer than four hours are clamped to four hours.
`redact --loud` ends the pause early. The plugin actions provide a ten-minute pause and an immediate
resume.

Quiet mode hides badges and notifications, but it does **not** stop reading panes. The watcher keeps
scanning, recording findings, and saving its store, and the findings pane keeps listing what it finds.
Use `redact --disable` when you want to stop the watcher from reading panes; quiet is not a substitute
for disable.

## Configuration

Configuration is a JSON file at `$HERDR_PLUGIN_CONFIG_DIR/config.json`. herdr injects that directory
when it runs the plugin; when you run the binary yourself it resolves to the same place herdr would
use, `~/.config/herdr/plugins/config/moneycaringcoder.redact/config.json`, so both routes read one
file. Every key is optional and overrides just that default, and unknown keys are ignored, so a config
written for a newer version will not break an older binary. A missing file is the normal case; a
malformed one prints a warning and falls back to the defaults rather than taking the scanner down.

| Key | Default | What it does |
| --- | --- | --- |
| `interval_seconds` | `5` | How often the watcher and the findings pane rescan. Clamped to 1–3600. `--interval <SECS>` overrides it for one run. |
| `lines` | `400` | Lines of output read per pane per cycle. Clamped to 1–20000. Bigger means more history and more to scan. `--lines <N>` overrides it for one run. |
| `backfill_lines` | `5000` | Lines of retained scrollback requested the first time the watcher reads each pane. Clamped to 1–20000; `0` disables backfill. `--once`, `--json` and `--sarif` never backfill, because they are interactive commands whose latency you are waiting on. |
| `scan_all_panes` | `false` | Scan every pane rather than only panes running an agent. See [widening the scan](#widening-the-scan). `--all-panes` overrides it for one run. |
| `env_assignments` | `true` | The `.env`-style assignment heuristic (`FOO_TOKEN=…`). Reports at weak confidence, with its own badge token. |
| `rule_packs` | `["default"]` | Compiled-in rule packs to add. The `default` pack is always active; `[]` therefore means default only, never no scanning. Unknown names produce a note and are ignored. |
| `notify` | `true` | Post a herdr toast for a new finding. Rate limited to one per rule per pane per watcher run regardless. |
| `patterns` | `[]` | Your own rules. Each is `{ name, regex, label?, strong?, former_names? }`; `strong` defaults to `true`. |
| `allowlist` | `[]` | Regexes that suppress a finding. A finding is dropped when one matches either the value or the line it was found on. |
| `ignore_panes` | `[]` | Pane ids never read at all. The escape hatch for a pane that is deliberately full of test credentials. |
| `max_findings` | `500` | Cap on stored findings, so one pathological pane cannot grow the state file without bound. Oldest acknowledged findings are dropped first. |
| `overlays` | `[]` | Pane-context overrides selected by workspace id, workspace label, or working-directory path prefix. |

A config file that still sets `entropy` is ignored, exactly as any unknown key is.

A worked example — an internal token format, and two things this repository prints constantly that are
not worth being told about:

```json
{
  "interval_seconds": 10,
  "lines": 800,
  "patterns": [
    {
      "name": "acme_deploy_key",
      "label": "Acme deploy key",
      "regex": "\\bacme_dk_[A-Za-z0-9]{32}\\b",
      "strong": true
    },
    {
      "name": "internal_session_hint",
      "label": "Internal session id",
      "regex": "\\bsess-[0-9a-f]{16}\\b",
      "strong": false,
      "former_names": ["internal_session_id"]
    }
  ],
  "allowlist": [
    "EXAMPLE_ONLY",
    "^\\s*#",
    "tests/fixtures/"
  ],
  "ignore_panes": ["w3:p2"]
}
```

A `patterns` entry whose regex does not compile is a hard error from `redact --rules`: you typed it,
you are looking right at it, and a rule silently dropped is a rule you think is protecting you. Every
scanning path, on the other hand, falls back to the built-in rules and says so in its notes, because
one bad line in a config file must not be able to stop the scanner.

A `patterns` entry may also list `former_names`: the names that rule used to
have. A rule name is what the state file, `--explain`, and the `pattern` and
`ruleId` fields of the JSON and SARIF output key on, so renaming a rule you have
been suppressing values under would otherwise bring every one of those values
straight back. A stored suppression or finding that names a former name is
rewritten to the current name, and the rename is reported — on stderr by
`--rules` and `--explain`, and in the scan notes that reach the findings pane —
so a configuration naming the old name keeps working while telling you to update
it. A former name that is blank, or that collides with a rule that is actually
active, is a hard error rather than an ambiguous lookup.

`redact --rules` prints the base rule set. Pass a current pane id
(`redact --rules w1:p2`) or a working-directory path
(`redact --rules /home/me/repos/company-app`) to print the effective rules for
that context, which answers "is my pattern working here" without trusting this
README.

The two are told apart by a single rule: **a context containing a `:` is read as
a pane id, and anything else is read as a working-directory path.** So
`redact --rules myword` is a relative-path lookup, not a pane lookup, and it
matches no overlay. Which reading was used is printed before the listing, so a
pane id typed wrongly shows up as a path rather than as an empty result.

### Per-workspace and per-repository overlays

An overlay has a `match` object containing exactly one of `workspace_id`,
`workspace_label`, or `path_prefix`, plus any of the optional configuration keys
from the table above. A path prefix is matched against the pane working
directory reported by `session.snapshot`; redact never walks the working tree or
looks for a `.git` directory.

This configuration keeps a personal-key detector active everywhere, but
allowlists its distinctive test value in a noisy company repository. A pane in
the personal repository still reports the same value:

```json
{
  "patterns": [
    {
      "name": "personal_api_key",
      "label": "Personal API key",
      "regex": "\\bpersonal_pk_[A-Za-z0-9]{24}\\b"
    }
  ],
  "overlays": [
    {
      "match": {
        "path_prefix": "/home/me/work/company-app"
      },
      "allowlist": [
        "\\bpersonal_pk_EXAMPLEEXAMPLEEXAMPLE\\b"
      ],
      "notify": false
    }
  ]
}
```

The other matcher forms are `"match": {"workspace_id": "w3"}` and
`"match": {"workspace_label": "Company"}`.

Overlay order is significant. For each scalar (`interval_seconds`, `lines`,
`scan_all_panes`, `env_assignments`, `notify`, and `max_findings`), the first
matching overlay that sets it wins. Lists (`patterns`, `allowlist`, and
`ignore_panes`) from **all** matching overlays append to the base lists in file
order; overlays never replace a list. Path prefixes are also applied in file
order, not longest-prefix order, so a matching short prefix followed by a
matching longer prefix contributes both lists in that declared order.

A malformed overlay is ignored with a note while the top-level configuration
continues to scan. It never turns a configuration typo into a dead scanner. An
empty or whitespace-only `path_prefix` counts as malformed for that purpose:
every path starts with the empty one, so honouring it would silently apply the
overlay to every pane in the session. There is no catch-all matcher, on purpose
— an overlay that matches more than you meant looks exactly like one that works.

## Widening the scan

Agent panes are scanned by default, because that is the stated exposure surface and it keeps the
volume of text low. But the shell where somebody actually ran `cat .env` is very often **not** an
agent pane — it is the ordinary terminal in the next split.

To scan every pane:

```sh
redact --all-panes --once      # one run
```

```json
{ "scan_all_panes": true }     // permanently
```

Be aware of what you are trading. Every pane means more output to read on every cycle, and more
chances for something credential-shaped to appear in output that was never a secret — a fixture file
being catted, a test log, somebody's `--help`. The rules are the same either way, so the precision is
the same; there is simply more text for them to be precise about. If a particular pane is noisy,
`ignore_panes` is cheaper than turning the whole thing off.

## Calibrating against your own output

Precision is easiest to trust when you can measure it against the terminal output you actually see.
`redact --calibrate` runs the active rules over one snapshot using the normal pane filter, line limit
and cycle budget, then groups what **would** have fired by rule. Samples are masked before they leave
the scanner. Calibration does not create the state directory, store findings, set badges or show
notifications.

For a representative precision check, include ordinary shell panes as well as agent panes:

```sh
redact --all-panes --calibrate
```

Read an incomplete result literally. A pane that could not be read, a pane truncated by the line
limit, or a cycle budget that ran out is reported as incomplete rather than as clean. Raise `lines`
when the history you want to measure is older than the configured limit.

## Detection rules

Each rule is `name` — what the state file, `--explain`, and the JSON and SARIF output key on — and a
confidence. Strong findings light
`redact_secret`; weak ones light `redact_weak`.

`redact --explain <rule>` also prints advisory rotation guidance. For provider-specific rules this is
a plain-text link to the provider's own token-management or revocation page; redact never fetches the
link and never opens a browser. Generic heuristics have no provider page by nature, because the value
does not identify who issued it; `--explain` says that explicitly instead of guessing.

Every built-in rule belongs to a named, versioned pack. The `default` pack at version 1 is the exact
rule set that shipped before packs: configuring another pack only adds rules and never removes a
default rule. Rule names are stable public interface: a rename happens only in a major release, and
the old name resolves to the new rule for at least one minor cycle, reported every time it is used.
The compiled-in
`narrow` pack at version 1 is intentionally empty today; it is the seam for future precise formats
whose relevance is too specialized for every user, without demoting any protection already in the
default set. `redact --rules` appends each rule's pack and version after the existing name and
confidence columns; custom patterns have no compiled-in pack or version and show `-` for both.

| Rule | Catches | Confidence |
| --- | --- | --- |
| `aws_access_key_id` | `AKIA` or `ASIA` plus 16 base32 characters | strong |
| `aws_secret_access_key` | 40 base64 characters, but only next to the key name AWS itself uses | strong |
| `aws_principal_id` | `AROA`, `AIDA`, `AGPA`, `ANPA`, `ANVA`, `AIPA`, `APKA` plus 16 | weak |
| `github_token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` | strong |
| `github_pat` | fine-grained `github_pat_…` | strong |
| `anthropic_api_key` | `sk-ant-…` | strong |
| `openai_api_key` | `sk-proj-`, `sk-svcacct-`, `sk-admin-`, or `sk-` plus 48 characters | strong |
| `stripe_secret_key` | `sk_live_`, `rk_live_` | strong |
| `slack_token` | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` | strong |
| `slack_webhook_url` | `https://hooks.slack.com/services/…` | strong |
| `google_api_key` | `AIza…` | strong |
| `google_oauth_client_secret` | `GOCSPX-…` | strong |
| `gitlab_pat` | `glpat-…` | strong |
| `npm_token` | `npm_…` | strong |
| `pypi_token` | `pypi-AgEIcHlwaS5vcmc…` | strong |
| `sendgrid_api_key` | `SG.…` | strong |
| `huggingface_token` | `hf_…` | strong |
| `age_secret_key` | `AGE-SECRET-KEY-1…`, the private half only — `age1…` is a public key and is ignored | strong |
| `jdbc_url_password` | `password` query parameters or properties in a `jdbc:` connection string, after placeholder filtering | strong |
| `docker_registry_auth` | Docker registry `"auth"` values that decode to exactly `username:password` | strong |
| `vault_token` | modern Vault `hvs.`, `hvb.`, and `hvr.` tokens | strong |
| `jwt` | three base64url segments **whose header really decodes to JSON with `alg`** | strong |
| `private_key_block` | `-----BEGIN … PRIVATE KEY-----`, including one cut off by the line budget | strong |
| `url_credentials` | a password embedded in a URL, `scheme://user:pass@host` | weak |
| `http_bearer_token` | `Authorization: Bearer …` | weak |
| `env_assignment` | `FOO_TOKEN=…` and `foo_secret: …` at the start of a line | weak |
| `multiline_credential` | secret-looking JSON/YAML keys whose quoted or block-scalar value continues on later lines | weak |

### What is deliberately not caught

Precision is the product, so several obvious candidates are left out on purpose:

- **Stripe test keys** (`sk_test_`, `rk_test_`). They live in public documentation, CI fixtures and
  sample apps, and leaking one costs nothing. Firing on them is pure cry-wolf.
- **Twilio.** The `AC…`/`SK…` SIDs are identifiers rather than secrets, and the auth token is 32 bare
  hex characters — indistinguishable from a git object id.
- **Cloudflare API tokens.** Forty characters of `[A-Za-z0-9_-]` with no prefix at all.
- **AWS principal identifiers as credentials.** `AROA…`, `AIDA…` and friends are matched, but at
  *weak* confidence and under their own rule name, because they are identifiers rather than secrets
  and full-length ones appear in ordinary `aws sts get-caller-identity` output. Only `AKIA` and
  `ASIA` — the prefixes that really are access keys — report as strong.
- **Kubernetes projected service-account tokens as a separate rule.** They are JWTs and are already
  reported at strong confidence under `jwt`, whose structural check decodes the header and requires a
  JSON `alg` field.
- **Postgres and MySQL connection URLs as a separate rule.** URLs carrying a password are already
  reported, at weak confidence, under `url_credentials`. A second strong rule would rename what users
  already see, and break every stored suppression and every export consumer that keys on the old name.
- **Legacy Vault `s.` tokens.** A two-character prefix, one character of which is a full stop, cannot
  support a strong claim. Only the modern `hvs.`, `hvb.`, and `hvr.` forms are matched.
- **Multi-line joins starting at bare `auth`.** `auth` does not pass the secret-name filter: widening
  that filter would make ordinary authentication configuration noisy. Pretty-printed Docker
  `config.json` keeps its base64 value on one line, where `docker_registry_auth` already covers it.
- **Generic "high-entropy" strings.** A 32- or 40-character hex or base64 run with no surrounding
  context is a commit id, a checksum, a UUID, an image blob, or a minified bundle far more often than
  it is a key.
- **The entropy heuristic.** Shannon entropy over terminal output is the false-positive machine this
  plugin exists to avoid being, and there is no version of it that survives a page of base64.

The `.env`-style assignment rule is the one broad heuristic that does ship, which is why it reports at
weak confidence and gets its own badge colour. It is anchored to the start of a line, insists the name
looks like a secret and not like a red herring, and drops values that are obviously placeholders
(`changeme`, `true`, `localhost`, `xxx`).

The name test is deliberately narrow: `*_TOKEN`, `*_SECRET`, `PASSWORD`, `*_PASSWORD`,
`*_PASSPHRASE`, `*_CREDENTIALS`, and the qualified key names `*_API_KEY`, `*_SECRET_KEY`,
`*_PRIVATE_KEY`, `*_ACCESS_KEY`. A bare `*_KEY` does **not** qualify, because `GPG_KEY` is printed by
every official `python:3.x` image, `CACHE_KEY` by every CI runner, and `routing_key`,
`partition_key`, `idempotency_key`, `app_key` and `bucket_key` by ordinary application logs. Losing
`SIGNING_KEY` and `ENCRYPTION_KEY` to that rule is the price, and it is the right way round: a rule
that fires on a `python:3.x` startup banner would be uninstalled by the end of the day.

Add what your team uses through `patterns`, and silence what your repository prints through
`allowlist`. Both are ordinary regexes.

## What this does not do

It never acts on a finding. Acting on a false positive inside somebody's terminal — clearing a pane
mid-command, interrupting an agent that was fine — would be far worse than a missed warning, so it is
not a feature that exists to be misfired. Specifically:

- **It never writes to a pane.** No keystrokes, no commands, no `clear`, no interrupt, no signal to
  anything it did not start.
- **It never edits a repository.** It does not run git, does not touch files in your working tree, and
  has no opinion about your `.gitignore`.
- **It never rotates or revokes anything.** Rotation guidance is advisory text only. It never opens a
  browser, fetches a guidance link, contacts a provider, or tries to find out whether a key is live.
- **It never phones home.** No telemetry, no update check, no crash reporting. It makes no network
  calls of any kind; the only socket it opens is herdr's, on your machine.
- **It never stores a secret**, in any file it writes, including the ones you would send a maintainer
  to debug it.

The one file outside its own state directory it will ever write is your herdr `config.toml`, and only
when you run `--setup` — which takes a backup first, refuses to clobber an existing one, is additive
(nothing is ever deleted), is a no-op the second time, and restores the backup byte for byte if herdr
rejects the result.

## Limitations

Worth knowing before you trust it:

- **It polls.** Panes are read on the refresh interval and not before, so a five-second badge is a
  five-second-old badge.
- **It sees retained scrollback, not unlimited history.** The first time the watcher reaches each pane
  it requests `backfill_lines`; later cycles request the most recent `lines` lines. herdr may retain
  less than requested, and the report says when either window was truncated rather than implying it
  saw everything. The first cycle after `--enable` is therefore more expensive, and the first badge
  may arrive later on a large session; the cycle deadline can spread panes' first deep reads over
  later cycles.
- **Only agent panes, by default.** See [widening the scan](#widening-the-scan).
- **Acknowledgement is not remediation.** Acknowledging a finding clears a badge. The value is still
  in that pane's scrollback, and still in whatever wrote it there. Rotate the key.
- **Recall is traded for precision, on purpose.** A key format nobody can match precisely is a key
  format this plugin does not report. It is designed to be believable rather than exhaustive.
- **Linux and macOS only.** The watcher relies on Unix process and signal behaviour, and the plugin
  declares those two platforms.

## Contributing

Bug reports, questions, documentation fixes and new detection rules are all welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md) for what makes a change easy to merge, and in particular for the
two rules the project rests on: a secret value never leaves the scanner, and precision beats recall
every time.

**Please never paste a real credential** — not in an issue, not in a pull request, not in a test
vector, not even an expired one. A missed format is a useful report and a structurally valid fake is
exactly as useful as the real thing. For a false positive, replace the value with something the same
shape.

Found a way to make this plugin leak the thing it is meant to protect? That is a security issue, not
a bug report: see [SECURITY.md](SECURITY.md), which also carries the full threat model — a table of
everything the plugin holds and where it lives.

By taking part you agree to the [code of conduct](CODE_OF_CONDUCT.md).

## Licence

MIT. See [LICENSE](LICENSE).
