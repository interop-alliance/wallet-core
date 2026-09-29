# 0023: Structured outcomes also emit as diagnostics events

- Status: accepted
- Date: 2026-09-29
- Driving work: the design for a ceremony-outcome event channel over the
  logging seam, approved 2026-09-29. Extracted at that design's approval,
  from its amendment of the logging-seam design's rule on where new log
  sites belong.
- Affects: `@interop/wallet-core` (the ceremony entry points and the
  mender runner, which gain emits), freewallet (its app-implemented
  ceremonies, its mender report sites, and its e2e fixture), dcw (its twin
  emit item).

## Context

The logging seam was adopted under a rule: it replaces existing console
calls, and it does not invite new sites where a typed error or a
structured outcome is the right channel. That rule keeps diagnostics from
competing with the caller contract.

The ceremony event channel adds new sites, and most of them sit beside a
structured outcome. A ceremony that returns `{ failed: [] }` today will
also emit a `clean` event. Read literally, the rule forbids exactly that.

The need is real. The outcome object reaches the caller and stops there.
An agent reading the dev NDJSON file, or an e2e test asserting that no
mender failed, has no other way to see it.

## Decision

The rule is amended. Outcome-shaped telemetry through the shared ceremony
event vocabulary (`decisions/0022`) is a stated exception. An emit site
may sit beside a structured outcome, and a clean success emits too.

The event duplicates the outcome into the diagnostics stream. It does not
replace it. Every outcome object and every refusal class stays as it is,
and remains the caller contract.

No production code branches on a ceremony event. Test fixtures may, and
the e2e fixture that reads the dev NDJSON file exists to. The helpers are
fire-and-forget over the structural `Logger` port and offer no
subscription.

## Rejected Alternatives

- **Events in place of the structured outcome objects.** Outcome objects
  are the caller contract. A channel nothing may branch on cannot carry
  one. Unifying how menders report is the mender registry's job, not the
  log's.
- **A dedicated observer API (`onCeremonyEvent(listener)`).** Sinks are
  already the process-wide fan-out. A subscription surface would invite
  production code to branch on log events.
- **Keeping the rule literal, and reading outcomes only where they are
  returned.** Then the login chain's best-effort stages stay invisible to
  anything but their immediate caller, which is the problem the channel
  exists to solve.

## Consequences

- Log volume grows on acting runs. `clean` lands at info, so an acting
  ceremony adds one always-dispatched line.
- Two channels now describe one run. The outcome object is authoritative.
  A test may assert that the event matches it, and the per-ceremony suites
  do.
- The exception is scoped to the shared vocabulary. A free-form warn
  beside a structured outcome is still outside the rule.
- The logging package's own record that typed-error-only packages adopt
  no logger is unaffected. wallet-core already has best-effort paths and
  already takes the port.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. Production code is found branching on a ceremony event. Remove the
   branch first. If the need is real, it belongs in the outcome object or
   a typed error, not in this channel.
2. The event volume costs a real consumer (a production console, a
   diagnostics export) more than the visibility is worth. Then narrow the
   emitting levels rather than dropping the exception.
