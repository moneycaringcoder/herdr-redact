# Changelog

Notable changes to redact. Dates are ISO-8601.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project uses [semantic versioning](https://semver.org/spec/v2.0.0.html).

**Detection rule names are part of the public interface.** The allowlist and the
notification rate limiter key on them, so renaming one is a breaking change and
will only happen in a major release, with the old name accepted as an alias for
at least one minor cycle.

## [Unreleased]

### Changed

- `min_herdr_version` is now `0.8.0`, up from `0.7.5`, and the README badge
  agrees. The old floor was reasoned from when the socket APIs redact calls
  first appeared; it was never exercised against a 0.7.x server. 0.8.0 is the
  latest stable herdr and the only version redact has been developed and
  verified against, so the manifest now states a tested claim rather than an
  inferred one. **Installing on herdr 0.7.5 through 0.7.x, which the manifest
  previously permitted, will now be refused.** If you are on one of those and
  redact worked for you, say so on the issue tracker and the floor can come back
  down with evidence behind it.

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
