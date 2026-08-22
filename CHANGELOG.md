# Changelog

Notable changes to redact. Dates are ISO-8601.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project uses [semantic versioning](https://semver.org/spec/v2.0.0.html).

**Detection rule names are part of the public interface.** The state file keys
its findings and its permanent suppressions on them, `redact --explain` takes
one, and they are the `pattern` and `ruleId` fields of the JSON and SARIF
output, so renaming one is a breaking change and will only happen in a major
release, with the old name accepted as an alias for at least one minor cycle.

## [Unreleased]

### Added

- A public rule catalogue, [`docs/rules.md`](docs/rules.md): every compiled-in
  rule with its confidence, pack and version, rotation guidance, any former
  names, and the structural checks it applies as well as what it deliberately
  rejects. Precision bought by structure is this plugin's central claim, and
  until now it could only be read as Rust. The file is generated from the
  compiled rule set and a test fails if the committed copy differs, because a
  stale catalogue does not merely go out of date — it makes a false claim about
  what is being detected. Its per-rule prose is each rule's own `explain` text,
  the same words `redact --explain` prints, so there is one source and nothing
  to keep in sync by hand. A further test runs the shipped scanner over the
  catalogue and fails on a strong match, so the documentation cannot start
  carrying the thing it documents.
- SARIF output is now validated against the SARIF 2.1.0 schema in the test
  suite. A snapshot test proves the output has not changed; it cannot prove a
  consumer can read it, and SARIF exists to be read by tools this repository
  does not control. The schema is vendored — the exact SchemaStore document our
  own `$schema` field points at, with its retrieval date and checksum recorded
  next to it — so validation runs offline, like everything else here. The gate
  carries negative controls that mutate valid output until the schema rejects
  it, because a validator that accepted anything would have passed in silence.
  The validator is a hand-written draft-07 subset rather than a schema crate:
  the smallest one tried tripled this crate's dependency count, ICU stack
  included, for a test-only oracle. It hard-fails on any schema keyword it does
  not implement, so it can never quietly under-validate, and a test proves it
  rejects a violation of every keyword it claims.
- A scan-cost benchmark, `cargo bench --bench scan_cost`, so the cost of the
  thing this plugin does on every cycle is measured rather than assumed. It runs
  the pure scanner over deterministic pane-like corpora — the 400-line default
  window, the 5 000-line default backfill, the 20 000-line largest window a user
  can configure, a sparse-match variant, a weak-candidate-heavy variant, and a
  1 MiB single line — checks each corpus produces the matches it is supposed to
  before timing it, and reports cost per line and throughput. It adds no
  dependency, because a number humans read is not worth a dependency tree, and
  it uses the bench profile, which inherits the size-optimised release profile
  the plugin actually ships. On a Ryzen 7 7800X3D that is about 380 ns per line,
  roughly 215 MiB/s, so the largest configurable window costs about 7.6 ms —
  0.025% of the minimum cycle budget, which exists for the socket round trip per
  pane rather than for the scan. The README now states that figure instead of
  leaving the reading budget looking like a magic number. It is deliberately not
  a required CI check: timings on shared runners are noisy, and a noisy required
  performance gate is worse than none.
- Rule name aliases, so the promise above can be kept rather than only made. A
  rule may now carry former names: a compiled-in rename ledger covers the
  built-in rules, and a `patterns` entry may list its own `former_names` for a
  team that renames an internal format. The ledger is empty today because no
  shipped rule has ever been renamed, which is the point — the mechanism has to
  exist before the rename, not after it. A stored suppression or finding that
  names a retired rule is rewritten to the current name, so a rename cannot
  resurrect a value someone dismissed for good or re-notify a finding they had
  already acknowledged, and `redact --explain <former-name>` answers for the
  rule that replaced it. Every use of a retired name is reported — `--rules`
  and `--explain` say so on stderr, and the scan notes carry it into the
  findings pane — because a configuration that keeps working in silence is one
  nobody ever updates.

### Fixed

- The note above these release sections named the allowlist and the
  notification rate limiter as the things that key on a rule name. Neither
  does: an allowlist entry is a regex matched against the value or the line it
  was found on, and the rate limiter lives for one watcher run, so no rename
  can outlive it. The note now names what really keys on a rule name — the
  state file, `--explain`, and the `pattern` and `ruleId` fields of the JSON
  and SARIF output — and the promise it makes is implemented.
- A finding whose line number is unknown produced invalid SARIF. `StoredFinding`
  reads an absent `line` as zero, and SARIF requires a region's `startLine` to
  be at least one, so exporting such a finding emitted a document a conforming
  consumer must reject. The physical location now carries no region at all in
  that case, which is what SARIF is for: the pane is still named, and a line
  nobody observed is not invented to fill the field. Found by the new schema
  gate on its first run, which is the argument for having one.

## [0.1.1] - 2026-08-18

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
- Per-workspace and per-repository configuration, through an `overlays` list.
  An overlay matches on the workspace id, the workspace label, or a prefix of
  the pane's working directory, and carries the same keys the top level does, so
  the noisy repository can silence one pattern without weakening the scan
  everywhere else. Scalars take the first matching overlay that names them and
  lists append from every match, because an overlay that quietly replaced your
  allowlist would be a silent hole. An empty path prefix is rejected as
  malformed rather than honoured as a catch-all: it would match every pane while
  the user believed their overlay was scoped. `redact --rules <pane-or-path>`
  prints the rules actually in force for that context, since an overlay system
  whose result cannot be printed is one nobody can debug.
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
- The watcher now reads each pane's available scrollback once, the first time it
  reaches that pane, and the ordinary window on every cycle after that. Until
  now a credential that scrolled past before you enabled the watcher was never
  found, which is the gap between "I turned this on" and "this has been watching
  all along". The depth is `backfill_lines`, 5000 by default; `0` restores the
  old behaviour exactly. The cycle budget and the round-robin are unchanged, so
  a large session simply spreads its backfill over several cycles — and a
  backfill that could not reach the whole history says so in a note of its own,
  distinct from the one about the ordinary window. `--once` and `--json` do not
  backfill: they are interactive verbs, and this is the watcher's blind spot.
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
- Permanent suppression of one exact value, from the findings pane with `s` or
  from the command line with `--suppress <ID>`, plus `--suppressions` to list
  what you have silenced. Silencing a false positive used to mean hand-writing a
  regex into a config file, and a hand-written allowlist regex that matches more
  than you intended is a silent hole in a security tool. A suppression cannot
  over-match at all: it is the rule name plus the keyed digest, so it matches
  exactly one value and nothing else — and because the plugin never has the
  value, there was never a regex it could have written for you. It is global
  across panes, since the same fixture value in another pane is the same false
  positive. The count of active suppressions is always on screen and in
  `--json`, including when there are no findings at all, because a scanner that
  has been told to ignore things must never be quiet about it. `--forget` clears
  them.
- Named, versioned rule packs. Every rule now belongs to a pack, `rule_packs`
  selects which are active, and `--rules` prints the pack and version beside
  each rule so you can see the detection surface you are actually running.
  Packs are compiled in — nothing is fetched, and no rule is ever renamed by
  one. Every shipped rule stays in `default`, unchanged in name, confidence and
  order, and a golden test now pins that list so it cannot drift. The second
  pack, `narrow`, ships empty on purpose: demoting a rule that people are
  already protected by would weaken them silently, so it stands as the seam for
  precise formats too specialised for everyone. Packs only ever add rules, an
  unknown pack name is a note rather than a dead scanner, and an empty
  `rule_packs` list means the default set rather than nothing at all.

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
