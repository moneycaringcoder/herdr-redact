# Changelog

Notable changes to redact. Dates are ISO-8601.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project uses [semantic versioning](https://semver.org/spec/v2.0.0.html).

**Detection rule names are part of the public interface.** The allowlist and the
notification rate limiter key on them, so renaming one is a breaking change and
will only happen in a major release, with the old name accepted as an alias for
at least one minor cycle.

## [Unreleased]

## [0.1.0] - 2026-08-16

### Added

- First release. Scans the recent output of every agent pane on an interval,
  reports credential-shaped strings as findings, and badges the pane's agent row
  and its workspace row in herdr's sidebar.
- High-precision provider rules plus a `.env`-style assignment heuristic at a
  lower confidence, each with its own badge token so the two can be coloured
  differently.
- User-supplied `patterns` and `allowlist`, both regular expressions.
- Findings persist until acknowledged, and acknowledgements persist across
  restarts.
- `--setup`, which splices the sidebar tokens into the user's `config.toml`
  behind a backup and a rollback.

### Not included, deliberately

- **No entropy heuristic.** The flag exists and does nothing; see the note in
  `src/scan.rs`. It is the false-positive machine this plugin exists to avoid
  being.
- **No action on a finding.** redact never writes to a pane, clears one, or
  sends an interrupt. Acting on a false positive in somebody's terminal is worse
  than a missed warning.
- **No network calls of any kind.**
