# Changelog

Notable changes to redact. Dates are ISO-8601.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project uses [semantic versioning](https://semver.org/spec/v2.0.0.html).

**Detection rule names are part of the public interface.** The allowlist and the
notification rate limiter key on them, so renaming one is a breaking change and
will only happen in a major release, with the old name accepted as an alias for
at least one minor cycle.

## [Unreleased]

### Added

- Tag-triggered release automation. Pushing `vX.Y.Z` runs the full suite on
  Linux and macOS and publishes the GitHub release with notes taken from that
  version's changelog section — but only after an identity gate has confirmed
  that the tag, `Cargo.toml`, `Cargo.lock` and `herdr-plugin.toml` all name the
  same version and that the changelog section for it exists and is not empty.
  The manifest version is the one the marketplace displays and the one easiest
  to forget, so it is checked explicitly.
- An advisory upstream canary. Once a day it resolves one exact herdr `master`
  commit, fetches the API schema herdr generates from its own types at that
  revision, and checks that the five methods redact calls, the parameters it
  sends, and the pane and snapshot fields it reads are all still there. It is
  scheduled and manual only, it is not a required check, and a red canary is a
  signal to read herdr's recent changes rather than a reason to hold a pull
  request.
- A finding now records where it came from, not just which pane it appeared in:
  the agent, the pane's working directory, and the name and pid of the
  foreground process at the moment the finding was first seen. It shows in the
  narrow-pane view and in `--json`. The command line and the terminal title are
  deliberately **not** recorded, in either place: `curl -H "Authorization:
  Bearer …"` is a command line, a shell sets its title to the command it is
  running, and storing either would write the credential into the state file
  that this plugin promises never contains one. The process is described as what
  was running when the finding was first seen, never as what produced it,
  because that is the part herdr can actually tell us.
- Three detection rules, each with a positive vector and negative vectors for
  the nearest innocent lookalike: `jdbc_url_password` (a password carried in a
  JDBC connection string, anchored on the `jdbc:` scheme so it cannot decay into
  a generic `password=` matcher), `docker_registry_auth` (the `"auth"` field of
  a Docker registry credential, base64-decoded and required to contain exactly
  one `:` with a plausible password half, so a pasted image layer stays quiet),
  and `vault_token` (`hvs.`, `hvb.` and `hvr.`).
- Corpus coverage proving two formats are already caught and deliberately get no
  rule of their own: a Kubernetes projected service-account token is a JWT and
  reports under `jwt`, and a Postgres or MySQL URL carrying a password reports
  under `url_credentials` at weak confidence. A second rule for either would
  double-report one credential and give the allowlist two names to silence.
- `redact --calibrate`, which runs the active rule set over your own pane output
  and reports what it *would* have fired on, badging nothing and acknowledging
  nothing. Precision is what this plugin sells, and precision is measurable;
  measuring it against your own terminal before trusting it is a better argument
  than anything in this README. It writes nothing at all — not a finding, not the
  digest key, not even the state directory, because it never constructs the store
  in the first place. `--all-panes` is worth pairing with it: the noisiest surface
  is the one worth measuring.
- `redact --explain <rule>`, which prints why a detection rule is shaped the way
  it is: what it matches structurally, at what confidence, and what near-misses
  it deliberately refuses. That reasoning was only in the README, and it is most
  useful at the moment a rule fires or fails to. An unknown name lists the rules
  whose names are close and exits non-zero; a name from your own `patterns` says
  so rather than pretending to a built-in explanation. The explanations live
  beside the rules in `src/scan.rs`, and a test asserts the README's rule table
  and the compiled rule set still name the same rules at the same confidences,
  so the table cannot drift from the code.

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

### Removed

- The `entropy` configuration key. It was accepted, did nothing, and recorded a
  note saying so — a key you can set that silently changes nothing is worse than
  no key, and this was never a feature waiting to be built. A Shannon-entropy
  heuristic over terminal output is the false-positive machine this plugin
  exists to avoid being, and the project has decided against it rather than
  deferred it. A config file that still sets `entropy` keeps loading: it is now
  an unknown key, and unknown keys are ignored, so nothing breaks and nothing
  needs editing.

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
