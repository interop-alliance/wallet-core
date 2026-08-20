# 0006: Generation GC observables, stage order, and the GenerationCollect digest

- Status: accepted
- Date: 2026-08-19
- Amended: 2026-08-20 -- Renamed: the identifier is now called the
  generation id (`generationId`) module-wide; formerly "segment".
- Amended: 2026-08-20 -- Implementation details settled (Dmitri):
  the digest's `firstEntry` / `lastEntry` quote the collected log's
  first and last entries' `versionTime` strings verbatim (the digest
  outlives the log and does not launder its source), and `entryCount`
  is the log's total entry count, genesis included -- an entry count,
  deliberately not a visit count. The quarterly cadence is read off
  the `versionTime` of the account-log entry that established the
  current pointer value (no local timestamp anywhere; per-account,
  zero extra reads at login). The quiet bound carries a one-hour
  skew-margin grace floor (`GENERATION_QUIET_GRACE_MS`). The swap
  tail and orphan cleanup are one rule: the collect fan-out runs
  predicate-driven at every durable login over every non-pointed
  `gen-` collection (revoke blind, digest, delete; per-generation
  collected failures), so a torn GC resumes at the next login rather
  than the next quarter, and a log-less collection is deleted without
  a digest row while a collection whose log fails verification is
  kept and reported.
- Driving work: the public-computer posture redesign for the browser
  wallet -- companion generations are garbage-collected by wholesale
  replacement (new DID, new collection, old collection deleted), and
  the ceremony's observable state, stage order, and owner-side record
  had to be pinned
- Affects: wallet-core `clients`/`space` (the GC ceremony and the
  activity-type map); the wallet-activity collections freewallet and
  dcw write; the companion profile's spec text

## Context

GC replaces a companion generation: mint a fresh companion DID in a
fresh `gen-` collection, re-point the account document's
delegated-clients service entry, delete the old collection. Every
wallet-core ceremony detects completion from durable state alone (no
checkpoint resources), so GC needed a completion predicate over what
actually remains observable. Two facts constrain it: zcap revocation
is enforced but unreadable (POST only, no read endpoint), and the
delete destroys the old generation's log -- the owner's only record of
the window's visits -- along with the capability bytes a revocation
POST needs.

## Decision

- No marker resource. The account document's pointer-update entry is
  the record: permanent, versionTime-stamped, hash-chained, its
  serviceEndpoint string embedding the auxiliary Space id and the
  generation id -- the account log alone carries the ordered
  history of every generation and swap moment. Hostile substitution
  is bounded by account-log continuity (the chain-head pin) plus the
  server clause's pointer equality (a substituted pointer kills the
  prior generation's delegations rather than coexisting with them),
  and deliberately not by an observable: a routine swap and a hostile
  one are both pointer updates made with the same account update
  authority, so a marker written by that authority proves nothing.
- Completion predicate, checkable half only: exactly one `gen-`
  collection exists in the auxiliary Space, and it is the one the
  pointer names -- a pure predicate over the pointer (authoritative
  side) and the `gen-` prefix listing (derived side). The
  "no unexpired delegation names a dead generation" conjunct is
  demoted to an ordering obligation: it is unverifiable by
  construction (no revocation read API; the dead generation's
  delegation object is destroyed with its collection).
  (Amended 2026-08-19, the public-computer posture design's
  delta-review resolution: the guard's "live entry" predicate is the
  24-hour max-visit quiet bound -- a generation is GC-quiet when its
  newest entry's `versionTime` is over 24 hours old. The bound defers
  GC only; it never expires a session. A visit outliving it merely
  loses guaranteed guard protection, and in the rare case a quarterly
  pass lands on one, the session's next authorization failure maps to
  the generation-lapse retry state. The horizon is wallet GC policy
  over a timestamp the log already carries, never a stored or wire
  value.)
- Stage order: mint + genesis; install the new generation's
  delegation service entry; revoke the old generation's delegation;
  re-point; digest; delete. The revoke lands before the re-point,
  closing the window where a fail-open non-conforming server still
  honors the old delegation -- and the revocation POST needs the
  capability bytes the delete destroys, so revoke-before-delete is
  forced twice over. The window where the pointer still names a
  generation with a dead delegation is harmless: the live-entry guard
  (with a skew-margin grace floor) means GC runs only when no live
  session is on the old generation. (Amended 2026-08-19, the
  public-computer posture design's delta-review resolution -- the
  concurrent-enrollment ordering
  rule, required 2026-08-17 but not carried into the original
  sign-off: a transient enrollment landing between the guard
  check and the re-point yields a session whose generation the
  pointer then abandons and whose delegation is already revoked.
  The enrollee closes the race: after its enrollment append it
  re-reads the generation pointer, and on a mismatch it
  re-enrolls into the fresh generation -- one extra read,
  convergent under retry.)
- Resume contract: a resumed GC re-POSTs the revocation blind and
  treats the server's 400 already-revoked answer as success;
  collection deletion is idempotent, so the delete stage re-runs
  free.
- The owner-side digest is a summary row: one wallet-activity record
  per collected generation, activity type `GenerationCollect` (the
  map's PascalCase object-verb precedent), summary
  `Collected companion generation "<generationId>".`, `object` =
  `{ generationId, firstEntry, lastEntry, entryCount }`, and id = the
  generationId verbatim (allowlist-safe where the activity id
  doubles as the resource id, and unambiguous beside the uuidv7 ids
  every other activity carries). Both activity write paths are
  create-only and an encrypted row keys on the nondeterministic
  envelope hash, so a torn re-run writes a second row; the
  deterministic payload id buys read-time collapse through the
  store's documented dedupe model.
- Orphan discovery: a durable login lists `gen-` prefix matches
  against the pointer. A torn GC's old generation, a torn signup's
  orphan, and a double-genesis loser need no distinguishing --
  treatment is identical (pairing-free convergence: one rule cleans
  anything an earlier torn run left behind). The live-entry guard
  applies to the pointed generation only; an unpointed generation
  authorizes nothing under pointer equality, so nothing inside it
  ever defers deletion. (Amended 2026-08-19, the public-computer
  posture design's delta review: this originally read "so an
  unexpired VM inside it never defers deletion" -- vestigial
  per-VM-expiry phrasing; the sidecar carries no VM `expires`, and
  pointer equality alone carries the argument. The guard's "live
  entry" predicate for the POINTED generation is the 24-hour quiet
  bound, resolved 2026-08-19 -- see the amendment on the
  completion-predicate bullet above.)

## Rejected Alternatives

- An owner-side marker resource: duplicates the account log, is a
  checkpoint resource, and cannot distinguish hostile from routine.
- Keeping the delegation conjunct in the completion predicate:
  unverifiable, so it could never be evaluated, only assumed.
- Making the conjunct checkable via recorded revocation state: the
  marker resource by another door.
- Re-point before revoke: a fail-open window removed for free by the
  other order.
- Dropping the digest: the window's visits would leave no record
  surviving the delete.
- Full per-entry digest detail: bulky rows in a synced encrypted
  collection, more wire surface, no named consumer.
- Format: `CompanionGenerationCollect` (no three-word precedent in
  the type map), `GenerationRetire`, counts interpolated into the
  summary text, visit-centric wording (conflates entries with
  visits), and namespaced or hash-derived ids (the generation id is
  already
  random, never reused, and human-linkable to the pointer entry).

## Consequences

- GC deletes the owner's only per-entry record of the window's
  visits; detection of a past compromise ends at the digest's
  granularity (generation id, first/last entry times, entry count). That
  loss is the accepted price of the bounded-window privacy story.
- The account log gains one permanent pointer-update entry per GC
  cycle; cadence is fixed-period so the rhythm leaks little.
- The activity-type map gains `GenerationCollect`; the
  generation-id-derived
  id is a deliberate exception to the uuidv7 convention and readers
  must not assume activity ids are UUIDs.
- Wallets must retain the old generation's delegation bytes until the
  revocation POST succeeds; a GC that deletes first cannot revoke.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The zcap revocation protocol gains a read endpoint; the demoted
   conjunct could then rejoin the completion predicate as a checkable
   clause.
2. A consumer needs per-visit forensic detail past GC; add a richer
   digest variant beside the summary row, never inflate the summary
   row itself.
