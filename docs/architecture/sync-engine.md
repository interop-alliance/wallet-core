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
- **The server's `ETag` is opaque and never rebuilt.** Its form is
  `"<generation>.<ms>.<counter>.<originId>"`, with no revision number to read,
  so a validator can only be echoed back verbatim. The wire carries no `version`
  either: a record's write stamp is `(updatedAt, updatedAtCounter, originId)`,
  minted at the writing origin, and this engine reads none of it. Preconditions
  key on the validator, and the contacts last-write-wins rule reads the payload.
  A `SyncedResourceReplica` persists `etag` beside its own `acked` flag, which
  says whether the server has ever acknowledged the replica. The flag is the
  replica's, since an ack carries no revision and `etag` presence cannot stand
  in for it: a server that hides the `ETag` header acks with no validator.
  `SyncStore.markPushed` / `markDeletedPushed` set `acked` and record the
  write's `etag` from its `WriteAck`, pull ingestion (`applyPulledPage`) records
  each `WireDoc`'s `etag` (and `metaEtag`, on a collection that syncs metadata),
  and `adoptLatest` records the re-read `MasterState.etag`. Every conditional
  write's `ifMatch` comes from that stored string, and `runPush` sends it only
  on an acked replica; a never-acked one is a create with `If-None-Match: *`.
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
- **Every decrypt is addressed.** `decryptDoc` (`SyncEngineDeps`) and the two
  `contactsConflict.ts` decrypt helpers (`contactHeadPayloadOf`,
  `resolveContactHeadConflict`) take `{ id, envelope }`, matching
  `DocCipher.decrypt`'s required `id`. The id is the feed document's own
  `doc.id`, the resource id the replica read the body under. `projectionForDoc`
  (and `runPull`) pass it on every pulled document; `remintPendingEnvelopes`
  (`remint.ts`) passes `replica.id`; `contactsConflict.ts` passes the contested
  resource's id on both the local and remote sides. A document whose envelope
  was sealed under a different resource's id fails the cipher's
  envelope-to-resource binding check with `IntegrityError`. Which half of that
  check fires depends on how the document was written. A content-addressed
  collection's envelope carries no sealed resource id, so the codec re-derives
  the id from the ciphertext; a mutable head written under a minted id carries
  the id inside the AEAD-bound `was.resource` header and is compared against it
  directly. `projectionForDoc` classifies that refusal with was-client's
  `isIntegrityError` and warns
  `Skipping synced document sealed for another resource id (no projection)`,
  distinct from the existing
  `Skipping undecryptable synced document (no projection)`. The projection
  outcome is unchanged either way: `none`. Its body is still stored, the
  checkpoint still advances past it, and one such document cannot wedge the
  feed. The distinct message exists so a caller can count the refusal apart from
  ordinary undecryptable noise, not so it can treat each one as tampering: the
  legacy contacts documents below raise it too, on every fresh replica
  bootstrap, so what distinguishes a tampering host is the rate rather than the
  event. `contactsConflict.ts` answers the same refusal differently, and
  deliberately: it **rethrows**. Scoring it as one more unreachable side would
  hand the conflict to the fail-safe default and discard the refusal, so a
  misfiled or tampered envelope would settle a conflict silently. Rethrowing
  leaves the resolver and fails the replication cycle, matching
  `@interop/was-sync`'s own last-write-wins resolver on the same seam. A side
  this replica merely holds no key for (`UnknownEpochError`, `KeyUnwrapError`)
  is unaffected: it stays unreachable, an unreachable local side hands the
  conflict to the remote master, an unreachable remote side leaves the local
  body to win, and neither side is ever compared on a body it could not open.
  Both directions fail the cycle: a misbound remote side and a misbound local
  side are refused alike, and no winner comes back. The optional
  `onIntegrityRefusal({ side, err })` callback names the refused side, firing
  once per side (both can be refused in one conflict) before the first refusal
  is rethrown unchanged.
- **A pending resource replica sealed for another id does not block the
  re-mint.** `remintPendingEnvelopes` treats the same `IntegrityError` as a skip
  of that resource replica: it logs it and moves on, rather than aborting the
  pass. Aborting would strand every other pending resource replica under the
  losing epoch, and since the re-mint is the gate before the next push, the
  eager minter's descriptor adoption would never complete.
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
  `remintPendingEnvelopes` re-encrypts every pending resource replica the
  adopted cipher cannot route under the winner's current epoch, before the next
  push. That is legal because pending (never-acked) envelopes have no feed
  existence, so the re-mint may re-key them (`SyncStore.replacePending`, the
  optional seam only eager minters implement). The engine memoizes
  `ensureProvisioned` once a call resolves; a call that throws is not memoized.
  The caller invalidates the memo (`SyncEngine.invalidateProvisioning`) whenever
  the account's provisioning state can have changed under the replica: an unlock
  with a fresh key set, a re-bind to a different account pointer, or a recovery.
  `keys`'s `walletSpaceProvisioner` builds the closure this seam expects for a
  wallet Space -- the provisioning two-step as one call, single-flight across
  concurrent callers, throwing `WalletSpaceProvisioningError` when the epoch
  install left a collection behind, so the engine never memoizes a torn run. An
  optional `remintPending` dep runs every cycle right after provisioning and
  ahead of the migration sweep and the push, so an eager minter's create-loss
  re-mint always finishes before anything else reaches the feed.
- `runPush` covers the **content sub-resource only**. The
  independently-validated metadata half (`putMeta` / `metaEtag`) stays in the
  `@interop/was-sync` RxDB driver, since no wallet Space collection versions
  metadata independently. Content-addressed collections get create/delete only;
  mutable collections get create-then-`If-Match`-update with `412` settled by
  the injected `ResolveConflict`.
- **Writer attribution rides every write.** `SyncEngineDeps.writerId` is the
  replica's WAS `writerId` label. It is minted and kept app-side, and the engine
  never mints, persists, or derives one. When it is present, `runPush` declares
  it as the `Writer-Id` header on every content write and delete. When it is
  absent, no label is sent. Under the server's declare-or-clear rule that clears
  any stored label, so a push never leaves a previous writer's label in place.
  The label is host-visible plaintext. A session that must not reveal a stable
  label to the host leaves it absent or passes a per-session one.
- **Echo suppression is an optimization, and must not change what converges.**
  `runPull` offers a page's live documents that carry the engine's own
  `writerId` and an `etag` to the optional `SyncStore.heldRevisions` seam. The
  store answers with the ids whose resource replica already records exactly that
  `etag`. Each confirmed document skips the decrypt and applies with a `none`
  projection. Its stored metadata and the checkpoint advance as usual. The label
  alone licenses nothing, since a host can rewrite it. What licenses the skip is
  the store's `etag` match, so a forged label on a revision this replica does
  not hold still decrypts. Suppression is off when no `writerId` is injected or
  the store omits `heldRevisions`. Tombstones, unlabeled documents, and foreign
  labels are processed as before. `runPull` reports the skips as `suppressed`.
- `contactsConflict.ts` resolves the one mutable collection (`contacts`) by LWW.
  It lives here rather than in social-core because deciding requires decrypting
  both sides (the `updatedAt` / `writerId` pair is sealed in the envelope); the
  comparison itself is social-core's `remotePayloadWins`. It **fails safe to
  remote** on any unreachable field, with one exception: the cipher's
  `IntegrityError` is rethrown rather than scored unreachable, so it fails the
  replication cycle (see the addressed-decrypt bullet above). When a cipher is
  passed, a plaintext (non-envelope) body is unreachable too. An older writer or
  a host put it there, and the app's reads refuse it, so its stamp must not beat
  a valid envelope. Plaintext is compared only when no cipher is passed.
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
