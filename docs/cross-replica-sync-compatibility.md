# Cross-replica sync compatibility contract

Status: established 2026-08-03 by the cross-replica conformance exercise
(`freewallet/tests/conformance/crossReplica.test.ts`, run via
`pnpm run test:conformance` in freewallet); re-run green (12/12) 2026-08-10
against the epoch-from-birth provisioning (wallet-core 0.22.0 / was-client
0.29.1), and green (11/11) 2026-09-16 against was-client 0.67.0's
resource-binding check, which retired the legacy-row scenario. Two wallets, one
Space: the mobile wallet (DCW) replicating with `@interop/wallet-core/sync`'s
`SyncEngine`, and the web wallet (freewallet) replicating with the RxDB driver,
which ships from `@interop/was-sync` and is consumed by freewallet and was-react
(it sat in `freewallet/src/lib/sync/` when the exercise ran), both driven
against a real in-process `was-teaching-server` with the real
`createWasSyncPort` and the real `createEdvDocCipher` on each side.

This document records what the exercise **proved**, the divergences it found
that are **tolerated by construction** (either side may rely on them staying
tolerated), and the **open defects** it caught. Amend it whenever the exercise
changes; the test file is the executable form of this contract.

## Proven

- **One identity, two derivations.** Both replicas derive their agents
  independently from the same seed through `@interop/was-client/identity`
  (`agentsFromSeed`) and arrive at the same `controllerDid` and the same
  `deriveSpaceId` Space -- and each replica's cipher decrypts envelopes the
  other encrypted.
- **Mutable head (`contacts`) round-trips both directions**, including an
  in-place edit of a document the other replica authored: one server resource
  per contact, the row id stable across edits, no duplicate rows on either side.
- **DCW in-place edits a freewallet-authored contact** (formerly the one open
  defect). Fixed from both ends: freewallet's contacts cipher is now built to
  the spec (`idDerivation: 'random'`) and `addContact` keys the row with the
  cipher-minted EDV id, and was-client's update path (`EdvCodec.encode` with
  `current`) accepts a pre-existing resource id verbatim (the id is already on
  the server, so the create-time URL-leak guard does not apply). Both edit
  directions are exercised.
- **An envelope is read only under the id it was sealed for** (retired the
  legacy-row tolerance, 2026-09-16). was-client 0.66.0 made `DocCipher.decrypt`
  verify the binding, so a body served under a foreign id raises
  `IntegrityError` rather than decrypting. That refuses the shape the pre-fix
  freewallet write path left on servers -- an app-minted uuidv7 resource id
  carrying a content-mode envelope, whose content-derived id is not the uuid --
  and the scenario that pinned its editability is gone from the exercise.
  Neither wallet migrates those rows: they read as undecryptable, and the
  replication driver classifies them apart from a key failure, as a body sealed
  for another resource id. A still-pending one is left where it is by
  `remintPendingEnvelopes` rather than aborting the pass.
- **Edit collisions converge.** Both replicas run the same LWW rule
  (`remotePayloadWins` from `@interop/social-core`) over the decrypted heads, in
  DCW's `resolveConflict` and in the RxDB driver's `conflictHandler`. A
  concurrent edit of the same contact converges to the same winner on both
  replicas, in either direction of who syncs first, within two sync cycles of
  the loser.
- **Content-addressed (`private-credentials`) and append-only
  (`contacts-history`) collections round-trip both directions.** All three
  id/mutation models are covered.
- **Deletes propagate both directions** as server tombstones in the change feed
  (with the freewallet caveat under "tolerated divergences").
- **Provisioning does not clobber.** The Space was created by one wallet
  (freewallet in the exercise) and the other attached without re-provisioning;
  collection configuration survived.
- **Epoch-from-birth provisioning converges across replicas (re-run
  2026-08-10).** The harness now runs the shared provisioning two-step before
  any content moves: each collection is declared encrypted, then its key
  epoch[0] is installed create-if-absent (`ensureFirstEpoch`, the same install
  `ensureWalletSpaceEpochs` fans out), and BOTH replicas' ciphers are built from
  the resulting epoch-bearing descriptor -- there is no single-key path anywhere
  in the exercise anymore (was-client 0.29.x refuses an epoch-less descriptor
  fail-closed). Every scenario -- both edit directions, the collision
  convergence, deletes -- holds unchanged under epoch-sealed envelopes: every
  envelope now carries its `was.epoch` binding and each replica routes the
  other's envelopes through the shared epoch roster.

## Tolerated divergences (by construction, now pinned)

- **EDV `sequence` is advisory on the wire; the server ETag `version` is the
  enforced concurrency control.** Both replicas now update a head in place
  through `DocCipher.encryptUpdate`, advancing the envelope's EDV `sequence`
  from the prior stored envelope -- but a `sequence: 0` envelope at any revision
  count is a legal thing to find, since freewallet's plaintext-prior fallback
  writes one. The exercise pins the tolerance: an updater accepts whatever
  `sequence` the `current` envelope carries and advances from it. Neither side
  may start _enforcing_ EDV sequence continuity across replicas without a
  coordinated change here.
- **Content-addressed ids do not deduplicate across replicas.** The
  content-derived id is a hash of the _ciphertext_ (`EdvCodec` derives it after
  encryption, fresh JWE nonce every time), so the same logical payload added on
  both replicas yields two server documents. Dedup is an application-layer
  concern (DCW's `credentialHash`); do not rely on the id for it.
- **Contact resource ids are opaque strings on the wire.** Freewallet rows mint
  spec-format EDV ids (its `storageManager.#buildCiphers` passes each collection
  spec's `idDerivation`), and an updater takes a pre-existing id verbatim rather
  than inferring anything from its format; was-client asserts the EDV format on
  creates only. What an id may no longer disagree with is the envelope stored
  under it, which the binding check settles at read time.
- **Freewallet's push does not consume the write's ETag** (`pushWrites` design:
  the acked version round-trips on the next pull). Consequence, demonstrated
  live in the exercise: a delete pushed _before_ that next pull carries a stale
  `If-Match`, 412s, and the contacts conflict handler's tombstone fallback (any
  non-decryptable side keeps `realMasterState`) silently drops the delete,
  resurrecting the contact locally. The live app's continuous poll loop closes
  this window in practice; the harness pulls the ack before deleting. DCW does
  not share the window -- its engine stamps the acked version at push time
  (`markPushed({version})`). Worth revisiting if freewallet's poll cadence ever
  grows long.

## Ordering invariants (stated 2026-08-09)

- **Descriptor-before-first-content-push.** A collection's encryption descriptor
  -- carrying its key-epoch roster from birth -- is published before the
  collection's first content push, so no envelope reaches the feed sealed under
  an epoch the published descriptor does not carry. In DCW the `SyncEngine`
  enforces this structurally: `ensureProvisioned` (which must include the
  descriptor publication, `provisionWalletSpace` + `ensureWalletSpaceEpochs`;
  `walletSpaceProvisioner` builds that closure) runs ahead of every cycle's
  migration sweep and push, memoized once it resolves and invalidated by the app
  on an unlock, a re-bind, or a recovery. An optional `remintPending` dep runs
  right after provisioning, still ahead of the sweep and the push. The RxDB
  driver owes the same ordering: its provisioning step must settle before its
  first `pushWrites` (in the app, `ensureUserCollections` plus the epoch install
  complete before login does, and replication starts after login). The
  2026-08-10 harness setup honors the ordering -- both descriptors are installed
  before either replica's first push -- though it does not race a push against a
  mid-flight install, and the adopt-and-re-mint path below stays
  harness-unexercised (no scenario yet drives two concurrent provisioners).
- **Adopt-and-re-mint on a descriptor create loss.** An eager minter -- a
  replica minting envelopes at local write time against a cached descriptor --
  that loses the descriptor create to another provisioner adopts the winner's
  descriptor (the create is CAS, never clobbering) and re-mints every pending
  envelope the adopted cipher cannot route under the winner's current epoch
  before pushing (`@interop/wallet-core/sync`'s `remintPendingEnvelopes`, over
  the optional `SyncStore.replacePending` seam). This is legal exactly because
  pending (never-acked) envelopes have no feed existence, so the re-mint may
  re-key them; rows already on the feed are never re-minted. In DCW the path is
  theoretical (never-linked profiles mint no envelopes; the lazy sweep runs
  post-pull, online) -- the rule binds any consumer that mints eagerly.

## Open defects

None. The one defect the exercise caught -- DCW could not in-place edit a
freewallet-authored (uuid-id) contact, rejected by was-client's `assertDocId` --
is fixed and moved to "Proven" above. Both candidate fixes were applied:
was-client's update path accepts a pre-existing resource id verbatim (the
DCW-facing fix), and freewallet's cipher construction was brought back to the
spec so rows mint `'random'` EDV ids (which also stops uuidv7's embedded
creation timestamp leaking onto the URLs of an encrypted collection).

Rows the pre-fix path wrote are not a defect but a stated loss: the
resource-binding check refuses them, and no migration is planned.

## Harness notes

- The exercise stands in only for the app-local persistence glue: DCW's SQLite
  `SyncStore` is an in-memory store mirroring `dcw/app/model/syncedDoc.ts`
  reconciliation (kept in step with `dcw/test-node/contactsSyncEngine.test.ts`),
  and freewallet's `BrowserStore` write paths are reproduced verbatim over a
  memory RxDB. Engine, port, cipher, schema, conflict handler, and LWW rule are
  the real parts on both sides -- as is, since 2026-08-10, the provisioning
  two-step (`ensureSpaceAndCollection` declare + `ensureFirstEpoch` install) the
  ciphers are built from.
- This exercise is how the two replica implementations are held to one wire.
  They are not collapsing into one: `decisions/0021` records that the engine and
  the RxDB driver stay two algorithms, since the loops are inverted, and names
  this harness as the guard that they still agree.
