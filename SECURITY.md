# Security policy

## Reporting a vulnerability

Please report security issues privately, through GitHub's
[private vulnerability reporting](https://github.com/moneycaringcoder/herdr-redact/security/advisories/new)
rather than as a public issue.

You can expect an acknowledgement within a few days. Since this is a
single-maintainer project, please don't read silence as dismissal — follow up if
you have heard nothing after a week.

If you would rather not use GitHub's reporting flow, open a public issue saying
only that you have found a security problem and would like a private channel,
with no details, and one will be arranged.

**If your report involves a secret you found leaked by this plugin, do not paste
the secret.** A rule name, a pane description and a screenshot with the value
blacked out is enough to reproduce.

## The threat model

redact reads the terminal output of your panes. That is the most sensitive thing
a herdr plugin can do, and it is the whole point: the exposure surface for an
agent that runs `cat .env` is the terminal, which nothing else watches.

Everything below follows from that.

### What the plugin holds, and where

| thing | where it lives | contains a secret? |
|---|---|---|
| pane text | process memory, for the duration of one scan | yes, transiently |
| a `Match` | process memory | no — masked preview, length, keyed digest |
| `findings.json` | `~/.local/state/herdr/plugins/moneycaringcoder.redact/` | no |
| `digest.key` | the same directory, mode `0600` | no |
| badge tokens | herdr's in-memory session state | no — a count |
| toast bodies | herdr's notification surface | no — rule name and masked preview |
| stdout of any verb | your terminal | no |

The masked preview shows at most the first four and last four characters of a
value, and never more than about a third of it. `tests/never_leaks.rs` asserts
this as a property over every positive detection vector: the full value must not
appear in any output the plugin produces, including `Debug` renderings and the
persisted state file.

`digest.key` is per-installation keying material for the identity digest stored
in `findings.json`. It exists so that the persisted record of "this same finding
again" is not an unkeyed hash of a possibly low-entropy value. It is not a
secret in itself, and losing it costs you nothing but your acknowledgements.

### What counts as a security issue here

- **Any full or partial secret value reaching a place it should not.** A log
  line, the state file, a toast body, a JSON dump, an error message, a panic
  message, a `Debug` impl. This is the bug class the plugin exists to avoid
  creating, and it is the most serious thing you can report.
- **A masked preview that reveals too much** — more than four characters at
  either end, or more than about a third of a short value.
- **Any write to a pane.** redact never sends text or keys to a pane, never
  clears one, and never sends an interrupt. A path that does is a serious bug:
  acting on a false positive in somebody's terminal is far worse than a missed
  warning.
- **Any write outside the plugin's own state directory** and, for the setup
  action, the user's `config.toml`. `tests/no_stray_writes.rs` fingerprints the
  filesystem around a full run.
- **Any network call.** redact makes none at all, so outbound traffic is a bug by
  definition. There is no telemetry, no update check, and no reporting service.
- **Editing a user's `config.toml` incorrectly.** The setup action modifies a
  file the plugin does not own; corrupting it, or losing the backup that makes
  the change reversible, is in scope.
- **A pathological input that hangs or exhausts memory.** The plugin is fed
  arbitrary terminal output by construction, so a regex that backtracks
  catastrophically or an allocation proportional to attacker-chosen input is a
  denial of service on the user's own machine.
- **Command injection through a config value.** The only subprocess this plugin
  ever runs is `herdr server reload-config`, with an argv array and no shell. A
  way around that is worth reporting.

### What is out of scope

- **A missed credential.** The plugin deliberately trades recall for precision:
  a scanner that cries wolf gets uninstalled and then protects nothing. A missed
  format is an ordinary feature request, and a good one — please open an issue
  with a structurally valid but fake example.
- **A false positive.** Also an ordinary bug, and also very welcome, but not a
  security issue. Please include the line that triggered it, with the value
  replaced.
- The plugin executing rules you gave it yourself in `config.json`.
- Issues in herdr itself. Those belong upstream, though a report here is welcome
  if redact could work around one.

## Supported versions

The most recent release is supported. Given the size of the project, fixes are
made on `main` and released rather than backported.
