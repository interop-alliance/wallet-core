# 0024: Ceremony events live in wallet-core and emit from entry points

- Status: accepted
- Date: 2026-09-29
- Driving work: the design for a ceremony-outcome event channel over the
  logging seam, approved 2026-09-29. Extracted at that design's approval,
  from its do-not-reopen rejections of where the vocabulary lives and
  where events are emitted.
- Affects: `@interop/wallet-core` (`src/ceremonyEvents.ts`, the ceremony
  entry points, the mender runner), `@interop/logger` (what it does not
  carry), freewallet (its wrappers over shared ceremonies, its converger
  modules, and its existing warn sites).

## Context

The ceremony event vocabulary (`decisions/0022`) needs a home, and each
event needs one emitting site. Both questions have tempting wrong answers.

A logging package looks like the natural home for a logging vocabulary.
But the vocabulary is wallet-domain: ceremony ids, invariant ids, mend
outcomes. The logging package is leaf infrastructure that nothing
wallet-layer sits below.

Emit sites have the same pull toward "everywhere". A ceremony runs through
wrappers and shared tails, and a mender through its converger module. If
each layer emitted, one user action would produce several outcome events,
and a reader could not count runs.

## Decision

The vocabulary and the emit helpers live in wallet-core, in the root-level
leaf module `src/ceremonyEvents.ts`. It imports only the ceremony and
mender vocabularies and the local `Logger` type, so every layer may import
it. The helpers take the `Logger` as a parameter. No ceremony entry-point
signature changes, and no new namespace or port method is added.

The module that implements a ceremony emits its outcome, from its public
entry points only:

- A wallet-core ceremony emits from its wallet-core entry point.
- An app-implemented ceremony emits from its app module. The emit moves if
  the implementation moves.
- A wrapper over a shared ceremony adds no second outcome.
- A shared tail invoked from another ceremony (the roster-and-cascade tail
  that retirement, disconnect, forget, and recovery run) emits nothing of
  its own.

One user action yields one outcome event.

Mender events come from the places that already see every report entry:
the mender runner for chain registrations, and each report call site for
routing and ceremony-tail entries. Converger modules emit nothing.

Existing warn sites keep their messages and `data` shapes. Reserved keys
appear only on helper-emitted events.

## Rejected Alternatives

- **The vocabulary in `@interop/logger`.** It is wallet-domain and would
  pull wallet types into leaf infrastructure. The logging package stays
  vocabulary-free. Do not reopen.
- **A per-mender-module emit.** The runner and the report sites already
  see every entry, so a converger-level emit would duplicate them and
  spread the vocabulary into modules that need none. Do not reopen.
- **Retrofitting reserved keys onto the existing warn sites.** It widens
  the test blast radius for no query gain over the new events. The one
  exception, freewallet's ceremony-tail info line, is recorded in
  `decisions/0022`. A later change may merge a site whose prose warn
  duplicates a helper event, one site at a time.
- **An outcome event from every layer a ceremony passes through.** It
  makes outcome events uncountable as runs, which is the one property a
  reader needs from them.

## Consequences

- The mender event and a ceremony event can both describe one run when a
  mender acts by re-running a ceremony. That is intended, and the re-run
  carries its own `run` id (`decisions/0022`).
- Adding an emit to a new ceremony means converting its entry point, not
  its wrapper. An app wrapper author has nothing to add.
- The logging package's `dist/` stays free of wallet types, and
  wallet-core's `dist/` stays free of the logging package's specifier.
- Readers querying by `msg` and reserved keys must still expect older
  prose warns carrying `data.invariant` or `data.outcome`. Filter on `msg`
  as well as the keys.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A second, non-wallet domain needs the same stage and outcome event
   shape. A domain-neutral core might then move down a layer, with the
   wallet ids staying in wallet-core.
2. A ceremony's implementation is split so that no single public entry
   point sees both its first stage and its return. Then the ownership rule
   needs a stated owner for that ceremony, not an emit in every half.
