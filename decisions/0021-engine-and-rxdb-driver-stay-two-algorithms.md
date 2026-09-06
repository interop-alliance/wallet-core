# 0021: The sync engine and the RxDB driver stay two algorithms

- Status: accepted
- Date: 2026-09-05
- Driving work: the extraction design for the WAS replication driver for
  RxDB, approved 2026-09-05. Extracted at that design's approval, from its
  do-not-reopen rejection of unifying the two replica implementations and
  from its answer on a shared controller shell.
- Affects: `@interop/wallet-core` `sync` (the engine: `engine.ts`,
  `pull.ts`, `push.ts`, `remint.ts`, `types.ts`, `collections.ts`, and the
  `SyncStore` seam), `@interop/was-sync` (the RxDB driver and its
  controller core), `@interop/was-client` `./sync` (the shared port, wire
  types, error classes, predicates, and `SyncStatus`), dcw
  (`app/lib/sync/`, `app/model/syncStore.ts`, `syncManager.ts`), freewallet
  and was-react (the driver's consumers).

## Context

Two replica-side implementations of WAS replication exist, and both are
production code. wallet-core's engine (`SyncEngine`, `runPull` / `runPush`
over the `SyncStore` seam) is dcw's replication path. The RxDB driver, now
`@interop/was-sync`, is freewallet's and was-react's. Both speak
was-client's sync port and the same wire profile: the `changes` feed and
its checkpoint rule, conditional writes, tombstones, and the `Key-Epoch`
stamp.

Two implementations of one wire profile looks like duplication, and the
extraction that gave the driver its own package is the natural moment to
propose merging them. The same proposal has a smaller sibling: one shared,
platform-neutral lifecycle shell behind dcw's `syncManager.ts` and the
package's controller core, since both start replication, poll, and react
to coming back online.

## Decision

The engine and the RxDB driver stay two algorithms. Do not reopen.

The reason is the shape of the loops rather than the amount of code. The
engine drives its `SyncStore`: it asks for a page, applies it
transactionally, and owns the ordering. RxDB drives the driver: RxDB calls
the pull and push handlers, owns the transaction and the checkpoint store,
and runs the conflict handler. The loops are inverted, so the part the two
genuinely share is the types and the wire rules. Those are already shared,
through `@interop/was-client/sync`: the port, `WireDoc`, `SyncCheckpoint`,
`DocCipher`, the error classes with their `err.name` predicates, and
`SyncStatus`. Anything new the two must agree on goes down into was-client
rather than sideways into a merged module.

The cross-replica conformance harness is how the pair is held to one wire.
It drives the package's driver and wallet-core's engine against a single
server fake and one feed.

No shared lifecycle shell is minted either. dcw's `syncManager.ts` is a
multi-profile manager with a per-profile debounce, a re-startable stop, and
ceremony hooks and encryption helpers on the same class. The package's
controller core is a single-session serialized queue with a terminal stop
and one RxDB replication per collection. The overlap is a poll timer plus
an offline-to-online edge, about thirty lines listening to different
platform events. Each side keeps its own.

## Rejected Alternatives

- **Wrap RxDB in a `SyncStore` and run the engine over it.** The engine
  would then own the loop, and RxDB's conflict handler, checkpoint
  machinery, and change stream would be bypassed or reimplemented above
  them. The apps use RxDB precisely for those, so this trades the working
  half for the shared half.
- **Reimplement RxDB's replication protocol inside the engine.** The same
  cost from the other direction, plus a permanent obligation to track
  RxDB's protocol across its own releases, in a package dcw installs and
  RxDB never runs in.
- **A shared platform-neutral lifecycle shell for the two controllers.**
  The two lifecycles disagree on their central rules: a terminal stop
  against a re-startable one, a single session against many profiles, and
  a serialized queue against a debounce. Forcing one shape on both would
  add a configuration surface larger than the thirty lines it saves.
- **Keep the driver in wallet-core beside the engine so a later merge is
  cheap.** wallet-core's `decisions/0009` and the driver's own placement
  record answer this: an `rxdb` peer on a wallet library that dcw installs
  inverts the layer map, and the merge it would make cheap is the one this
  record declines.

## Consequences

- Two implementations must keep encoding one wire. A change to the wire
  profile lands twice, and the conformance harness is the guard that says
  they still agree. That harness does not run in CI today, so the manual
  run at each release step is load-bearing.
- The shared vocabulary has one owner, was-client. A rule both sides need
  belongs there, which keeps the two from drifting through private copies.
  The last-write-wins comparator is the cautionary case: two copies of one
  rule disagreed on a mixed parseable and unparseable stamp pair until the
  extraction removed one.
- Whether the engine itself stays in wallet-core is a separate question
  from unification, and it stays open. Moving the engine into the driver's
  package is deliberately deferred rather than rejected, and the package's
  RxDB-free root entry was left free for it. This record says only that
  arriving there would still be two algorithms under one package name.
- dcw is unaffected. It drives the engine, installs no RxDB, and keeps its
  own manager.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. RxDB gains a replication mode in which the caller drives the loop and
   supplies the transaction. That removes the inversion this record rests
   on, and the merge becomes a real option rather than a rewrite.
2. Both browser apps stop using RxDB, so the driver's remaining consumers
   are ones the engine could serve directly. Then one algorithm survives
   and the question answers itself.
3. A third replica implementation appears. Then the pair is a family, and
   the answer is a conformance profile the implementations are tested
   against, rather than one algorithm they are merged into.
