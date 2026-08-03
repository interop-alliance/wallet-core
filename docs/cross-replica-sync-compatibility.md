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
  enforced concurrency control.** DCW updates a head in place through
  `DocCipher.encryptUpdate`, which advances the envelope's EDV `sequence`
  from the prior stored envelope. Freewallet updates through a fresh
  `cipher.encrypt` (`browserStore.updateContact`), so its stored envelope is
  `sequence: 0` on *every* save, whatever the resource's revision count. The
  exercise pins both directions: DCW's `encryptUpdate` accepts a
  freewallet-authored `sequence: 0` envelope as `current` and advances it to
  1, and freewallet decrypts DCW's advanced-sequence envelopes. Neither side
  may start *enforcing* EDV sequence continuity across replicas without a
  coordinated change here.
- **Content-addressed ids do not deduplicate across replicas.** The
  content-derived id is a hash of the *ciphertext* (`EdvCodec` derives it
  after encryption, fresh JWE nonce every time), so the same logical payload
  added on both replicas yields two server documents. Dedup is an
  application-layer concern (DCW's `credentialHash`); do not rely on the id
  for it.
- **Freewallet's contacts cipher runs `idDerivation: 'content'`** (its
  `storageManager.#buildCiphers` passes no `idDerivation`, so every cipher
  takes the default) while `CONTACTS_COLLECTION_SPEC` says `'random'`. This
  stays harmless only because freewallet mints the row id itself and
  discards the cipher's derived id -- but it is the root of the open defect
  below, and the eventual fix should bring the cipher construction back to
  the spec.
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

## Open defects

- **DCW cannot in-place edit a freewallet-authored contact.** Freewallet
  mints uuidv7 row ids for contacts (`browserStore.addContact`), and those
  ids are pushed as the server resource ids. DCW's `encryptUpdate` runs the
  id through was-client's `assertDocId` (full multibase/multihash check,
  guarding against human-readable ids leaking onto URLs), which rejects a
  uuid -- so a DCW user cannot edit any contact authored on the web wallet.
  Pinned by the exercise ("pins the open defect" test); flips loudly when
  fixed. Candidate fixes, one of which must be chosen deliberately:
  - freewallet adopts the cipher-minted EDV id as the contacts row id
    (following the spec's `idDerivation: 'random'`), with a migration story
    for existing uuid-keyed rows; or
  - was-client's update path (`EdvCodec.encode` with `current`) accepts a
    pre-existing resource id verbatim -- the id is already on the server, so
    the leak-prevention rationale does not apply to updates.

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
