# Cross-replica sync compatibility contract

Status: established 2026-08-03 by the cross-replica conformance exercise
(`freewallet/tests/conformance/crossReplica.test.ts`, run via
`pnpm run test:conformance` in freewallet). Two wallets, one Space: the mobile
wallet (DCW) replicating with `@interop/wallet-core/sync`'s `SyncEngine`, and
the web wallet (freewallet) replicating with its own RxDB adapter
(`freewallet/src/lib/sync/`), both driven against a real in-process
`was-teaching-server` with the real `createWasSyncPort` and the real
`createEdvDocCipher` on each side.

This document records what the exercise **proved**, the divergences it found
that are **tolerated by construction** (either side may rely on them staying
tolerated), and the **open defects** it caught. Amend it whenever the exercise
changes; the test file is the executable form of this contract.

## Proven

- **One identity, two derivations.** Both replicas derive their agents
  independently from the same seed through `@interop/wallet-core/identity`
  (`agentsFromSeed`) and arrive at the same `controllerDid` and the same
  `deriveSpaceId` Space -- and each replica's cipher decrypts envelopes the
  other encrypted.
- **Mutable head (`contacts`) round-trips both directions**, including an
  in-place edit of a document the other replica authored: one server resource
  per contact, the row id stable across edits, no duplicate rows on either
  side.
- **DCW in-place edits a freewallet-authored contact** (formerly the one open
  defect). Fixed from both ends: freewallet's contacts cipher is now built to
  the spec (`idDerivation: 'random'`) and `addContact` keys the row with the
  cipher-minted EDV id, and was-client's update path (`EdvCodec.encode` with
  `current`) accepts a pre-existing resource id verbatim (the id is already on
  the server, so the create-time URL-leak guard does not apply). Both edit
  directions are exercised.
- **Legacy freewallet rows stay first-class.** Rows authored by the pre-fix
  write path -- an app-minted uuidv7 resource id carrying a content-mode
  fresh-encrypt envelope (`sequence: 0`) -- replicate to DCW, are edited in
  place by DCW under the uuid id (sequence advancing from the legacy 0), and
  round-trip back. No migration of existing rows is needed or performed;
  both id universes coexist per resource forever.
- **Edit collisions converge.** Both replicas run the same LWW rule
  (`remotePayloadWins` from `@interop/social-core`) over the decrypted heads,
  in DCW's `resolveConflict` and in freewallet's RxDB `conflictHandler`. A
  concurrent edit of the same contact converges to the same winner on both
  replicas, in either direction of who syncs first, within two sync cycles of
  the loser.
- **Content-addressed (`private-credentials`) and append-only
  (`contacts-history`) collections round-trip both directions.** All three
  id/mutation models are covered.
- **Deletes propagate both directions** as server tombstones in the change
  feed (with the freewallet caveat under "tolerated divergences").
- **Provisioning does not clobber.** The Space was created by one wallet
  (freewallet in the exercise) and the other attached without
  re-provisioning; collection configuration survived.

## Tolerated divergences (by construction, now pinned)

- **EDV `sequence` is advisory on the wire; the server ETag `version` is the
  enforced concurrency control.** Both replicas now update a head in place
  through `DocCipher.encryptUpdate`, advancing the envelope's EDV `sequence`
  from the prior stored envelope -- but servers hold envelopes written by the
  old freewallet path (fresh `cipher.encrypt` every save, so `sequence: 0` at
  any revision count), and freewallet's plaintext-prior fallback still writes
  them. The exercise pins the tolerance: an updater accepts a `sequence: 0`
  envelope as `current` whatever the revision and advances from it. Neither
  side may start *enforcing* EDV sequence continuity across replicas without
  a coordinated change here.
- **Content-addressed ids do not deduplicate across replicas.** The
  content-derived id is a hash of the *ciphertext* (`EdvCodec` derives it
  after encryption, fresh JWE nonce every time), so the same logical payload
  added on both replicas yields two server documents. Dedup is an
  application-layer concern (DCW's `credentialHash`); do not rely on the id
  for it.
- **Contact resource ids are opaque strings on the wire.** New freewallet
  rows mint spec-format EDV ids (its `storageManager.#buildCiphers` now
  passes each collection spec's `idDerivation`), but uuidv7 ids from the
  pre-fix path live on servers indefinitely. A reader or updater must accept
  either id universe verbatim and may not infer anything from the id format;
  was-client asserts the EDV format on creates only.
- **Freewallet's push does not consume the write's ETag** (`pushWrites`
  design: the acked version round-trips on the next pull). Consequence,
  demonstrated live in the exercise: a delete pushed *before* that next pull
  carries a stale `If-Match`, 412s, and the contacts conflict handler's
  tombstone fallback (any non-decryptable side keeps `realMasterState`)
  silently drops the delete, resurrecting the contact locally. The live
  app's continuous poll loop closes this window in practice; the harness
  pulls the ack before deleting. DCW does not share the window -- its engine
  stamps the acked version at push time (`markPushed({version})`). Worth
  revisiting if freewallet's poll cadence ever grows long.

## Ordering invariants (stated 2026-08-09, not yet harness-exercised)

- **Descriptor-before-first-content-push.** A collection's encryption
  descriptor -- carrying its key-epoch roster from birth -- is published
  before the collection's first content push, so no envelope reaches the feed
  sealed under an epoch the published descriptor does not carry. In DCW the
  `SyncEngine` enforces this structurally: `ensureProvisioned` (which must
  include the descriptor publication, `provisionWalletSpace` +
  `ensureWalletSpaceEpochs`) runs ahead of every cycle's migration sweep and
  push. Freewallet's RxDB driver owes the same ordering: its provisioning
  step must settle before its first `pushWrites`.
- **Adopt-and-re-mint on a descriptor create loss.** An eager minter --
  a replica minting envelopes at local write time against a cached
  descriptor -- that loses the descriptor create to another provisioner
  adopts the winner's descriptor (the create is CAS, never clobbering) and
  re-mints every pending envelope the adopted cipher cannot route under the
  winner's current epoch before pushing
  (`@interop/wallet-core/sync`'s `remintPendingEnvelopes`, over the optional
  `SyncStore.replacePending` seam). This is legal exactly because pending
  (never-acked) envelopes have no feed existence, so the re-mint may re-key
  them; rows already on the feed are never re-minted. In DCW the path is
  theoretical (never-linked profiles mint no envelopes; the lazy sweep runs
  post-pull, online) -- the rule binds any consumer that mints eagerly.

## Open defects

None. The one defect the exercise caught -- DCW could not in-place edit a
freewallet-authored (uuid-id) contact, rejected by was-client's `assertDocId`
-- is fixed and moved to "Proven" above. Both candidate fixes were applied:
was-client's update path accepts a pre-existing resource id verbatim (the
DCW-facing fix, and what keeps legacy uuid rows editable with no migration),
and freewallet's cipher construction was brought back to the spec so new rows
mint `'random'` EDV ids (which also stops uuidv7's embedded creation
timestamp leaking onto the URLs of an encrypted collection).

## Harness notes

- The exercise stands in only for the app-local persistence glue: DCW's
  SQLite `SyncStore` is an in-memory store mirroring
  `dcw/app/model/syncedDoc.ts` reconciliation (kept in step with
  `dcw/test-node/contactsSyncEngine.test.ts`), and freewallet's
  `BrowserStore` write paths are reproduced verbatim over a memory RxDB.
  Engine, port, cipher, schema, conflict handler, and LWW rule are the real
  parts on both sides.
- This exercise is the gate on collapsing the two engines (the
  `./sync/rxdb` extraction idea): once collapsed, it becomes the regression
  test that the collapse did not change behavior.
