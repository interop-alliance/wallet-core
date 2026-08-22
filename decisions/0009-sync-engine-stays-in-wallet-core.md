# 0009: The sync engine stays in wallet-core

- Status: accepted
- Date: 2026-08-22
- Driving work: the packaging pass that followed the `display` extraction,
  asking whether the `sync` subpath (the WAS replication engine core) should
  likewise leave wallet-core for `@interop/was-client` or a package of its own
- Affects: wallet-core `sync` (kept; the root barrel keeps re-exporting it);
  was-client `./sync` (stays port and wire contract only, gains no replica
  seam); social-core (stays zero-dependency; gains no resolver); dcw (its engine
  consumer sites under `app/lib/sync/` and `app/model/syncStore.ts` are
  unchanged) and freewallet (its RxDB driver keeps consuming the port directly
  and `resolveContactHeadConflict` from wallet-core)

## Context

The `sync` subpath is technically separable today: zero internal imports, two
external dependencies (`@interop/was-client/sync` for the port and wire types it
re-exports, `@interop/social-core` for `contactsConflict.ts` alone), and no
crypto in its own graph. That made it look like the `display` case, which left
for `@interop/vc-display` because its audience was any VC viewer.

The consumer map says otherwise. The engine layer (`SyncEngine`, `runPull` /
`runPush`, `SyncStore`, `SyncedCollectionSpec`, `remintPendingEnvelopes`) has
one production consumer, dcw. freewallet's production code imports exactly one
symbol from the subpath, `resolveContactHeadConflict`; its RxDB driver is built
on `@interop/was-client/sync` directly, and `SyncEngine` reaches freewallet only
through the cross-replica conformance harness. No non-wallet consumer exists:
was-react depends on wallet-core but never on `sync`. Neither app imports the
root barrel.

Three constraints on the neighbors:

- was-client's scope is transport and the wire contract. The ecosystem map's
  rule is that was-client knows nothing of wallets, and its `./sync` entry is
  held crypto-free by an import-graph test. It depends on neither wallet-core
  nor social-core.
- social-core is zero-dependency by construction (`package.json` carries no
  `dependencies` key). `remotePayloadWins` is a pure comparison over
  `{ updatedAt, writerId }`; it knows nothing of envelopes.
- `contactsConflict.ts` needs both: a `DocCipher` and `isEncryptedEnvelope` to
  reach the sealed fields, and `remotePayloadWins` to compare them.

The engine itself is replica policy rather than transport: migrate-once,
pull-before-migrate, `ensureProvisioned` ahead of every push, the
adopt-and-re-mint rule, `onPullApplied`. That is the class of behavior two
replicas must encode identically or split a feed, the selection rule for what
lives in wallet-core, and it is the surface
`docs/cross-replica-sync-compatibility.md` records conformance against.

## Decision

The `sync` subpath stays in `@interop/wallet-core`, engine and resolver
together:

1. `src/sync/` keeps the engine core (`engine.ts`, `pull.ts`, `push.ts`,
   `remint.ts`, `types.ts`, `collections.ts`) and the root barrel keeps
   re-exporting it beside `space`. The subpath-isolation rule (the root serves
   no signing / KMS / document-loader graph) is what serves any future
   non-wallet consumer; no separate package is needed for that.
2. `contactsConflict.ts` stays here as well. wallet-core is the one layer that
   already depends on both was-client and social-core, so it is the only place
   the decrypt-then-compare rule can live without adding a dependency to a
   neighbor.
3. was-client's `./sync` stays the port and wire contract (`WasSyncPort`,
   `WireDoc`, `SyncCheckpoint`, `DocCipher`, the error classes,
   `createWasSyncPort`); the replica-side `SyncStore` seam does not move there.

## Rejected Alternatives

- Fold the engine into `@interop/was-client/sync`. The engine is replica policy,
  which the ecosystem map keeps out of was-client. The move would also split the
  subpath regardless: `contactsConflict.ts` cannot follow (was-client would gain
  a social-core dependency, inverting the layer map), so freewallet's one import
  would stay behind in wallet-core anyway. was-client would grow a `SyncStore`
  seam with a single implementer.
- A new `@interop/was-sync-engine` package. One production consumer (dcw), so
  one more package to version and publish with nothing driving it. The `display`
  precedent does not transfer: that module had an audience beyond the wallets,
  this one does not.
- Move `contactsConflict.ts` to social-core. It would give a deliberately
  zero-dependency package a dependency on `@interop/was-client/sync` for
  `isEncryptedEnvelope` and `DocCipher`, making the contacts data model
  storage-aware.

## Consequences

- The `sync` subpath's "only non-wallet audience" stays hypothetical and is
  served by the root barrel's isolation, not by packaging. The cost accepted is
  that a future non-wallet engine consumer takes a dependency on wallet-core, a
  package whose other subpaths carry the wallet ceremonies it does not need;
  subpath isolation keeps that a dependency in name only.
- freewallet continues to consume two sync surfaces: the port from was-client
  and the resolver from wallet-core. That asymmetry is accepted as the honest
  shape of its driver, which predates the shared engine.
- No follow-up move item is created. The roadmap item that drove this record
  closes on the record alone.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A non-wallet consumer of the engine layer appears (was-react replicating a
   shared collection into an app, a verifier site caching a feed). Then the
   extraction target is a new package, not was-client, and `contactsConflict.ts`
   stays behind in wallet-core either way.
2. freewallet retires its RxDB driver for the shared engine. That makes the
   engine the sole sync path of both replicas, which strengthens the case for
   staying put; it is listed here because it changes the consumer map this
   record rests on.
3. was-client's scope changes to take on replica-side seams for a reason of its
   own, at which point `SyncStore` belongs beside them.
