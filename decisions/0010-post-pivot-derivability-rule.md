# 0010: The post-pivot derivability rule

- Status: accepted
- Date: 2026-08-24
- Driving work: a saga-lens audit of the ceremony inventory's tear behavior --
  locating each ceremony's pivot and checking every pre- and post-pivot write
  -- combined with an evaluation of distributed-transaction patterns for
  client-side use, which concluded that two-phase commit and compensation are
  structurally unavailable (the server holds no locks; loudness makes log
  appends irreversible) and that the transferable pattern is Percolator's
  primary commit record over single-resource compare-and-swap.
- Affects: wallet-core (ARCHITECTURE.md's "Ceremonies and cascades" section,
  and every ceremony module's stage order); freewallet and dcw as consumers
  of the shared stage orders and as designers of their own app-side
  ceremonies, checked against this rule at the design gate.

## Context

Every ceremony in this system is a multi-request sequence over a storage
host that offers no cross-resource transaction primitive: no prepare/commit,
no locks held across requests, no multi-resource atomic batch. A same-Space
atomic batch was considered on the server side and declined for now, so the
rule below has to hold without one.

Compensation -- undoing an earlier write once a later one fails -- is
unavailable by construction. The system's loudness property requires that
any exercise of credential-derived authority extend a hash-chained log
before it reads or grants anything; that log is append-only, so a
compensating "undo" entry is not a real option once an entry has landed. A
ceremony can be finished only by moving forward; rolling it back is not an
available operation.

The ceremony inventory already half-states the discipline this decision
names outright. "Every stage detects its own completion from durable state
alone" (the shared principle above) says a torn ceremony must be resumable;
persist-before-publish says the write that arms a mender must land before
the log entry it defends against. Neither statement names the pivot itself,
or gives a designer a per-write test to run before code is written.

## Decision

Every ceremony has a pivot: the first durable write after which backward
recovery is impossible and the ceremony is committed. In this system the
pivot is almost always a hash-chained log entry, and that entry IS the
ceremony's commit record, in the sense Percolator gives a transaction's
primary row: there is no separate checkpoint resource and no intent record
anywhere in the inventory.

Every write a ceremony makes sits on one side of its pivot, and each side
carries its own condition:

1. **Before the pivot**, a write must be inert until the pivot lands.
   Verification at use time is what makes a pre-staged write inert. A
   pre-staged unlock record, a roster wrap, or a delegation grants nothing
   to a reader until the entry that licenses it verifies.
2. **After the pivot**, a write must be re-derivable from the pivot entry
   plus durable state, so that any authorized party can roll the ceremony
   forward to completion without needing anything that existed only in the
   tab that started it.

This generalizes persist-before-publish: key material is the write that
must precede the pivot, because nothing derives a client's seed after the
fact. The rule states the same requirement for every kind of write, not
just key material, and gives it a name: the pivot. It also gives a
mechanical test. For each write in a proposed ceremony, name which side of
the pivot it sits on, and confirm it meets that side's condition.

## Rejected Alternatives

- **Client-side two-phase commit.** The server holds no locks and offers no
  prepare phase; a coordinator (the browser tab) that dies mid-ceremony
  would leave the server-held state neither committed nor released, and
  every enrolled reader would have to know to break the lock. Nothing in
  the storage protocol supports it.
- **Compensation / backward recovery.** Rejected outright by the loudness
  design: an entry that extended the log cannot be un-extended, so "undo
  the last write" is not an available primitive once a log write has
  landed.
- **Intent records, in the style DynamoDB-client transactions use.** A
  dedicated intent resource written before the "real" writes, cleaned up
  after. Rejected because it is a second source of truth that can itself
  tear (the intent record and the writes it describes can diverge), against
  the standing discipline that every ceremony's state is read out of the
  durable artifacts themselves, not a description of them. Worth
  revisiting only if the ceremony count grows enough that per-ceremony
  pivot-finding stops scaling by hand.
- **Wait for a server-side atomic multi-resource batch.** Declined on the
  server side for now. The rule composes with such a primitive if one ever
  lands (a batch could replace several pre-pivot writes with one, or move a
  pivot earlier) rather than being replaced by it.

## Consequences

Every ceremony in the inventory can be read row by row against this rule:
name its pivot, then classify each of its other writes as pre- or
post-pivot and check the corresponding condition. Two known reorderings the
audit surfaced remain to be applied. One is the durable recovery spend's
window, where the new client's key set and the replacement code's record
are not yet durable when the add-and-retire entry -- the pivot -- lands.
The other is the self-enrollment ladder-VM strike's window, which has the
same shape. Both are write-ordering fixes, not new mechanisms.

Applying the rule at design time moves mender work in a specific direction:
a ceremony designed against it needs a mender that verifies an invariant
already holds (the common case, a no-op re-run) rather than a mender that
finishes someone else's unfinished authority. It does not reach every
failure mode. A reader that is not cooperating with the rest of the system
-- the server's own current-key-set evaluation of a request, a third-party
resolver reading the log independently -- sees whatever the log states at
the instant it reads, and no per-write rule about a single ceremony's
durability changes when that becomes visible. That stays a placement
question for the pivot itself, not something this rule can settle.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A server-side atomic multi-resource batch, or a leased-Space primitive,
   becomes available. Some ceremonies may then collapse several pre-pivot
   writes into one, though the rule itself does not change.
2. The ceremony count grows large enough that intent records (rejected
   above) become worth their added surface -- for instance, because
   per-ceremony pivot audits stop being tractable by hand.
3. A ceremony is found where no write ordering can satisfy either side of
   the rule: the write can be neither made inert before the pivot nor made
   re-derivable after it. That would mean the rule itself needs a third
   case, not just a fix to the ceremony.
