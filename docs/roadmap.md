# Roadmap

Ideas for future work, kept in the order they would most improve the plugin. None
of this is committed to a release, and nothing here is a promise.

Everything below stays inside the two rules the plugin rests on: **a secret value
never leaves the scanner**, and **precision beats recall every time**. An idea that
would raise recall by making the scanner cry wolf does not belong here, however
clever it is.

## Reacting faster

### Event-driven scanning

The scanner polls, so a five-second badge is a five-second-old badge. Upstream
[Discussion #2831](https://github.com/herdrdev/herdr/discussions/2831) proposes
`pane.output_changed` and revision semantics. If that lands, scanning on change
rather than on a timer removes the lag without raising the read budget.

This is blocked on upstream and should not be worked around with a shorter
interval, which would only spend more of the read budget to shrink the window.

The event surface was rechecked against herdr 0.8.2 on 2026-08-27.
`pane.output_changed` remains a non-emitted event type rather than a usable
subscription, so the upstream-blocked conclusion is unchanged and
`min_herdr_version` stays at 0.8.0. The captures and why each attempted
workaround either breaks one of the two rules or claims more than it can prove
are recorded in [the protocol notes](herdr-protocol.md) and
[issue #15](https://github.com/moneycaringcoder/herdr-redact/issues/15).

