<!--
Thanks for contributing. Nothing here is meant to be a hurdle — delete any
section that does not apply. A one-line typo fix needs a one-line description.

Please do not paste a real credential anywhere in this pull request, including
in test vectors, screenshots, and logs. A structurally valid fake is exactly as
useful.
-->

## What this changes

<!-- What the change does, and why. If it fixes an issue, link it. -->

## How it was verified

<!--
Which of these you did. The suite passing is necessary but often not
sufficient: the bugs this plugin attracts are wrong answers with no error, and
a scanner that has silently stopped scanning looks exactly like a clean session.
-->

- [ ] `cargo fmt --all` and `cargo clippy --all-targets -- -D warnings` are clean
- [ ] `cargo test --all` passes
- [ ] There is a test that fails without this change
- [ ] Ran against a live herdr session, with what I observed described below

<!-- If it changes what a user sees, paste the before and after. -->

## If you added or changed a detection rule

<!-- Delete this section otherwise. -->

- [ ] The rule has a stable machine name, and I did not rename an existing one
- [ ] There is a positive vector that is structurally valid and obviously fake
- [ ] I added negative vectors for the ordinary output this rule could fire on
- [ ] `tests/scan_corpus.rs` still asserts 100% precision on the negative corpus

<!-- What ordinary terminal output could this rule fire on, and what stops it? -->

## If you touched anything that produces output

<!-- Delete this section otherwise. -->

- [ ] `tests/never_leaks.rs` still passes
- [ ] No new field, message, log line or `Debug` impl can carry a secret value
- [ ] Nothing new is written outside the plugin's own state directory
