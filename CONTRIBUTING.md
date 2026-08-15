# Contributing to redact

Contributions are genuinely welcome — bug reports, questions, documentation
fixes, new detection rules, and code. This document exists so you know what to
expect before you spend time on something, not to put obstacles in front of you.

The project is maintained by one person. That means review is attentive but not
instant, and it means every change is read carefully before it lands. Please
don't take questions on a pull request as resistance; they are how the
maintainer stays confident in code that reads other people's terminals.

## The two rules that matter

**1. A secret value never leaves `src/scan.rs`.**

That module is the only place a matched credential ever exists, and only for the
duration of one call to `scan`. Everything that crosses a module boundary lives
in `src/model.rs` and carries a masked preview, a length and a keyed digest
instead of a value. There is deliberately no field anywhere that *could* hold
one.

So: don't add a value to `Match`, don't put one in a label, an error message, a
panic message, an `eprintln!`, or a `Debug` impl. `tests/never_leaks.rs` runs
every positive detection vector through the whole plugin and asserts the full
value appears in none of the output, including the persisted state file. If your
change makes that test fail, the test is right and the change is wrong.

**2. Precision beats recall, every time.**

A scanner that cries wolf gets uninstalled within a day, and then it protects
nobody. The negative corpus in `tests/scan_corpus.rs` is a collection of things
that appear in terminals all day — git SHAs, UUIDs, base64 image blobs, English
words beginning `sk-` — and it is asserted at **100% precision**. Any false
positive fails the suite.

This is why there is no entropy heuristic on by default, and why several plausible
rules were deliberately left out. A missed exotic key format is an acceptable
cost; a warning on ordinary build output is not.

## Adding a detection rule

The most useful contribution this project can receive. To make one easy to merge:

- Add the rule with a **stable machine name**. The allowlist and the notification
  rate limiter key on it, so renaming one later is a breaking change for users.
- Add a **structurally valid but obviously fake** positive vector. Never a real
  credential, not even an expired one, not even your own. Use `EXAMPLE`, `FAKE`,
  or repeated characters as filler.
- Add whatever **negative** vectors your rule makes newly risky. If you match a
  40-character base64 run, show what stops it firing on a base64 image.
- Say what the format actually is and where you confirmed it. "The provider
  documents this prefix here" is worth a line of comment.
- Prefer a rule anchored on a distinctive prefix over one anchored on length and
  charset. `ghp_` plus 36 base62 is safe; 36 base62 on its own is not.

If you cannot match a format precisely, it is fine — better, even — to leave it
out and say so in the README's table of what is deliberately not caught.

## Getting set up

```sh
git clone https://github.com/moneycaringcoder/herdr-redact
cd herdr-redact
cargo build --release
herdr plugin link .          # note: `link` does NOT run the build step
```

Rebuild by hand after every change, since `herdr plugin link` deliberately skips
the `[[build]]` hook.

Before opening a pull request:

```sh
cargo fmt --all
cargo clippy --all-targets --locked -- -D warnings
cargo test --all
```

CI runs exactly these on Linux and macOS with the current stable toolchain. If
your local Rust is older than CI's, clippy will pass locally and fail there —
`rustup update stable` first if in doubt.

No test requires a running herdr. The socket tests stand up a real Unix socket in
a temp directory and reply with payloads captured from a live server; see
`tests/fixtures/README.md` for why the fixtures keep fields the code ignores.

## What makes a change easy to merge

**A test that fails before your fix and passes after it.** This matters more here
than in most projects, because the bugs this plugin attracts are *invisible*
ones: a wrong answer with no error, which looks exactly like a correct answer. A
scanner that silently stops scanning reports a permanently clean session, and
nothing about that looks wrong.

**Tests built from observed behaviour, not assumed behaviour.** A fake that
encodes your assumption tests nothing. If you are testing against herdr, capture
real output first — `herdr api snapshot`, a raw socket probe — and encode that.
`docs/herdr-protocol.md` records three traps found exactly this way, including
one field that always reads zero and would silently disable the whole scanner if
you trusted it.

**Verification against something real.** If a change affects what a user sees,
run it against a live herdr session — print an obviously fake credential into a
scratch pane of your own and watch what happens — and say what you observed. A
passing suite is necessary and not sufficient.

**Comments that say why, not what.** The code is full of small, load-bearing
decisions that look arbitrary until explained: why severity rides the token
*name*, why the acknowledgement fingerprint ignores the line number, why the
disable path waits for the daemon to exit. If your change encodes a decision like
that, leave the reason behind.

## What to expect from review

- Small fixes — a typo, a clear bug with a test, a documentation correction — are
  usually merged quickly and without ceremony.
- A new detection rule gets discussed in terms of its false-positive surface, not
  its usefulness. Expect to be asked "what ordinary output could this fire on?"
- Anything that changes what the plugin writes, anywhere, gets the closest
  reading in the project.
- Larger features are best raised as an issue first, so you don't build something
  the project then declines. "Would you take a PR that does X?" is always a fine
  question.

## Scope

redact deliberately does a narrow thing well. In scope: detection quality, fewer
false positives, clearer output, better documentation, performance on large pane
buffers, Linux and macOS support.

Out of scope, and why:

- **Acting on a finding.** No clearing a pane, no sending an interrupt, no
  editing a file. Acting on a false positive in somebody's terminal is far worse
  than a missed warning, and the plugin cannot tell the difference at the moment
  it would have to decide.
- **Writing to any repository.** redact does not touch git at all.
- **Anything requiring a network call.** No telemetry, no reporting service, no
  update checks, no "verify this key against the provider" — that last one would
  transmit the very thing the plugin exists to protect.
- **Storing the secret**, for deduplication, for verification, or for
  convenience. The keyed digest is deliberately all there is.
- **Windows.** Not refused on principle, but the socket layer, daemon detachment
  and terminal handling are Unix-shaped, and there is no way to test it here.

## Reporting bugs

Please include the output of `redact --json`, your `herdr --version`, and what
you expected to see instead. If it involves the sidebar, the relevant part of
your `config.toml` helps too.

**Redact freely, and never paste a real secret.** For a false positive, replace
the value with something the same shape. For a missed detection, a structurally
valid fake is exactly as useful as the real thing.

## Security

Please don't open a public issue for a security problem. See
[SECURITY.md](SECURITY.md).

## Licence

By contributing, you agree that your contributions are licensed under the MIT
Licence, the same terms that cover the project.
