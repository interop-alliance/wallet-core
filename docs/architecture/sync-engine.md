<!-- Part of wallet-core's architecture docs. The map, the key hierarchy,
     the ceremony inventory, the permanent wire-level constants, and the
     glossary are in ../../ARCHITECTURE.md; this file holds one topic in full. -->

# The sync engine (`sync`)

`SyncEngine` drives exactly **one `(replica, collection)` feed**: single-flight
(concurrent `sync()` calls coalesce), migrate-once (pull-before-migrate ordering
avoids server-side duplicates), exponential backoff with jitter -- every side
effect injected via `SyncEngineDeps`.

- The **wire contract and port** (`WasSyncPort`, `WireDoc`, `SyncCheckpoint`,
  `MasterState`, `WriteAck`, `DocCipher`, the conflict/not-found errors) are
  defined in `@interop/was-client/sync` and re-exported here, so an engine
  consumer imports one package. This module owns the replica side: the
  `SyncStore` seam, `runPull` / `runPush`, and the engine.
- **The server's `ETag` is opaque and never rebuilt.** It carries a per-record
  generation marker ahead of the content `version`, so a validator can only be
  echoed back verbatim rather than synthesized from a bare revision number. A
  `SyncedRow` persists `etag` alongside `version`. `SyncStore.markPushed` /
  `markDeletedPushed` record the write's acked `etag` from its `WriteAck`, pull
  ingestion (`applyPulledPage`) records each `WireDoc`'s `etag` (and `metaEtag`,
  on a collection that syncs metadata), and `adoptLatest` records the re-read
  `MasterState.etag`. Every conditional write's `ifMatch` comes from that stored
  string.
- **The three wire signals are classified by `err.name`.** The refusal classes'
  rule covers this module too (see "The user key roster: delivery, never source"
  in keys-and-descriptor-logs.md). `WasSyncConflictError` and
  `WasSyncNotFoundError` are raised inside the app's injected `WasSyncPort`,
  `UnknownEpochError` inside its `DocCipher`, and either seam can resolve to a
  second copy of `@interop/was-client`. An `instanceof` miss is silent and
  expensive here: every push `412` becomes a fatal cycle error, and
  `remintPendingEnvelopes` rethrows instead of re-minting, which would push
  permanently unroutable envelopes onto a shared content-addressed feed. So
  `@interop/was-client/sync` exports `isSyncConflictError` /
  `isSyncNotFoundError` / `isUnknownEpochError` beside the classes that assign
  the names they match. `push.ts` and `remint.ts` import them from there. This
  module re-exports none of them: one owner per name.
- The engine owns the `DocCipher` and **decrypts outside the store transaction**
  -- store methods never see key material.
- **Descriptor-before-first-content-push.** A collection's descriptor (with its
  epoch roster) is published before the collection's first content push, so no
  envelope reaches the feed sealed under an epoch the published descriptor does
  not carry. The engine enforces it structurally: `ensureProvisioned` -- which
  for an encrypted collection must include the descriptor publication -- runs
  ahead of every cycle's migration sweep and push, so a lazy minter always mints
  under the settled descriptor. An eager minter (envelopes minted at local write
  time against a cached descriptor) that loses the descriptor create to another
  provisioner follows the **adopt-and-re-mint rule**: adopt the winner's
  descriptor (the create is CAS and never clobbers), then
  `remintPendingEnvelopes` re-encrypts every pending row the adopted cipher
  cannot route under the winner's current epoch, before the next push. That is
  legal because pending (never-acked) envelopes have no feed existence, so the
  re-mint may re-key them (`SyncStore.replacePending`, the optional seam only
  eager minters implement). The engine memoizes `ensureProvisioned` once a call
  resolves; a call that throws is not memoized. The caller invalidates the memo
  (`SyncEngine.invalidateProvisioning`) whenever the account's provisioning
  state can have changed under the replica: an unlock with a fresh key set, a
  re-bind to a different account pointer, or a recovery. `keys`'s
  `walletSpaceProvisioner` builds the closure this seam expects for a wallet
  Space -- the provisioning two-step as one call, single-flight across
  concurrent callers, throwing `WalletSpaceProvisioningError` when the epoch
  install left a collection behind, so the engine never memoizes a torn run. An
  optional `remintPending` dep runs every cycle right after provisioning and
  ahead of the migration sweep and the push, so an eager minter's create-loss
  re-mint always finishes before anything else reaches the feed.
- `runPush` covers the **content sub-resource only**. The
  independently-versioned metadata half (`putMeta` / `metaVersion`) stays in the
  `@interop/was-sync` RxDB driver, since no wallet Space collection versions
  metadata independently. Content-addressed collections get create/delete only;
  mutable collections get create-then-`If-Match`-update with `412` settled by
  the injected `ResolveConflict`.
- `contactsConflict.ts` resolves the one mutable collection (`contacts`) by LWW.
  It lives here rather than in social-core because deciding requires decrypting
  both sides (the `updatedAt` / `writerId` pair is sealed in the envelope); the
  comparison itself is social-core's `remotePayloadWins`. It **fails safe to
  remote** on any unreachable field.
- `SyncedCollectionSpec<Tx, RefreshContext>` is **only a shape**, not a registry
  -- the concrete registry stays app-side because writers bind to the app's
  transaction handle and read-model refresh. `space`'s `SpaceCollectionSpec` is
  the strictly narrower _layout_ spec; this is the _drivable_ one.
- [docs/cross-replica-sync-compatibility.md](../cross-replica-sync-compatibility.md)
  records the cross-replica conformance results between DCW's `SyncEngine` and
  the `@interop/was-sync` RxDB driver: what converges, which divergences are
  tolerated by construction, and the harness notes. Read it before touching
  pull/push semantics.
- The module stays here by decision. `decisions/0009` records why the engine
  (replica policy, not transport) and the contacts resolver live in this package
  rather than in was-client, social-core, or a package of their own, and what
  would reopen the question.
