/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The ladder-anchored ceremonies on the ACCOUNT log -- everything a standing
 * credential's ladder does to the world-readable `did.jsonl` beyond the
 * split-configuration edits (which stay in `unlock/standingWebvh.ts`):
 *
 * - {@link createLadderAnchoredAccountLog} / {@link ensureLadderAnchoredDidWebvh}
 *   -- the genesis of an account with zero enrolled durable clients, anchored
 *   on the credential's ladder alone (rung 0 signs, the ladder VM and the
 *   credential's `keyAgreement` inventory fold into the one entry).
 * - {@link selfEnrollWebvhClient} -- the self-enrolling continuation a fresh
 *   browser runs with nothing but the credential: two entries through the
 *   record's delegated `did.jsonl` bridge --
 *
 *   1. **Reveal + commit**: ladder rung `i` joins `updateKeys` (its hash
 *      stands committed, which is what makes the entry verify) and
 *      `nextKeyHashes` extends with the new ordinary client's update- and
 *      staged-key hashes plus `hash(rung i + 1)` -- the credential's next
 *      standing commitment.
 *   2. **Add + retire the rung**: signed by the new client's update key
 *      (revealed from the commit), this entry publishes the new client's
 *      verification methods and update key and drops the spent rung and its
 *      hash. The credential's own inventory -- its `keyAgreement` entry and the
 *      freshly committed `hash(rung i + 1)` -- stands untouched, ready for
 *      the next self-enrollment. Nothing is spent, and no replacement exists.
 *      When the account was LADDER-ANCHORED, the same atomic entry removes
 *      the ladder VM from the document and its relations -- the transitional
 *      key exists only while no durable client does, and folding the removal
 *      in leaves no window with neither.
 *
 * - {@link forgetWebvhClient} -- self-enrollment in reverse: one atomic
 *   ladder-signed removal entry through the bridge takes a durable client's
 *   whole document inventory out; the last enrolled durable client refuses
 *   ({@link LastDurableClientForgetError}).
 * - {@link installLadderVmWebvh} / {@link forgetLastWebvhClient} -- the two
 *   entries of the LAST durable client's forget (decision 0004's 2026-08-19
 *   amendment): an install entry publishing the ladder VM while the client
 *   stands (the both-present transitional state), then -- after the
 *   revocations the composed ceremony runs in between -- a removal entry
 *   that takes the client out while the installed VM keeps the account
 *   ladder-anchored. The composed ceremony is `forgetLast.ts`.
 *
 * Which rung is current is recovered from the log itself
 * (`attributeLadderRung`, fail-closed); a lost compare-and-swap race re-runs,
 * re-attributes, and climbs to the winner's committed rung -- the
 * retry-up-the-ladder resolution. Every stage is idempotent and resumable
 * from durable state alone, on the recovery continuation's pattern.
 */
import { deriveNextKeyHash, updateDID } from '@interop/did-method-webvh'
import type {
  DIDDoc,
  DIDLog,
  VerificationMethod
} from '@interop/did-method-webvh'
import {
  assertCarryOverCommitments,
  concludeWithPublishedLog,
  createLadderAnchoredWebvhLog,
  didWebvhControllerTemplate,
  genesisNextKeyHashes,
  ladderVerificationMethod,
  markedVerificationMethodPair,
  pinOfLog,
  publishWebvhLog,
  putLogResource,
  readPublishedLog,
  relationIds,
  updateKeySigner,
  withLogConflictRetry
} from '../webvh/didWebvh.js'
import type {
  ClientWebvhUpdateKeys,
  WebvhEnrollmentKeys,
  WebvhIdStore
} from '../webvh/didWebvh.js'
import { accountLogPinId } from '../webvh/verifyLog.js'
import type { ResourceLogPinStore } from '../resourceLog/index.js'
import { ladderVmIds } from '../webvh/listClients.js'
import {
  clientRemovalFields,
  clientRemovalTarget,
  type RevokedClientKeys
} from '../webvh/revokeClient.js'
import {
  readLogOrThrow,
  unlockKeyVerificationMethod,
  type UnlockKeyAgreementPublication,
  type UnlockLogStore
} from '../unlock/standingWebvh.js'
import {
  attributeLadderRung,
  ladderRung,
  ladderVmKeyMultibase
} from './ladder.js'

/**
 * LADDER-ANCHORED GENESIS: assembles the one-entry did:webvh log of an account
 * with zero enrolled durable clients, anchored on the minting credential's
 * ladder alone. Everything derives from the ladder seed: rung 0 is the sole
 * `updateKeys` member and signs the entry, `nextKeyHashes` commits rung 0's
 * own carry-over hash plus rung 1 (the staged rung) -- the carry-over hash is
 * what the first durable self-enrollment's reveal-and-commit entry,
 * re-stating `updateKeys` containing rung 0, requires --
 * and the ladder VM (the stable sibling) is published under `assertionMethod`
 * and `capabilityDelegation` only. The credential's `keyAgreement`
 * entry is FOLDED INTO GENESIS -- no enrolled client exists to run the
 * separate bind entry ({@link publishUnlockKey}) -- so the genesis
 * `keyAgreement` array holds only the credential's entry.
 *
 * The ladder-anchored window this opens is closed by the credential's first
 * durable self-enrollment ({@link selfEnrollWebvhClient}), whose add entry
 * atomically publishes the client, retires rung 0, and removes the ladder VM.
 *
 * The caller owns publication (conditional, create-only) and the pointer
 * write that follows; this assembles and signs the log only.
 *
 * @param options {object}
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed
 * @param options.keyAgreement {UnlockKeyAgreementPublication}   the
 *   credential's key-agreement publication (commitment or verbatim)
 * @returns {Promise<{ log: DIDLog, webDoc: object, did: string }>}
 */
export async function createLadderAnchoredAccountLog({
  wasServerUrl,
  spaceId,
  ladderSeed,
  keyAgreement
}: {
  wasServerUrl: string
  spaceId: string
  ladderSeed: Uint8Array
  keyAgreement: UnlockKeyAgreementPublication
}): Promise<{ log: DIDLog; webDoc: object; did: string }> {
  const rung0 = await ladderRung({ ladderSeed, index: 0 })
  const rung1 = await ladderRung({ ladderSeed, index: 1 })
  const controllerTemplate = didWebvhControllerTemplate({
    wasServerUrl,
    spaceId
  })
  return createLadderAnchoredWebvhLog({
    wasServerUrl,
    spaceId,
    ladderVmKeyMultibase: await ladderVmKeyMultibase({ ladderSeed }),
    credentialKeyAgreementMethod: unlockKeyVerificationMethod({
      did: controllerTemplate,
      keyAgreement
    }),
    updateKeyPublicKeyMultibase: rung0.keyMultibase,
    nextKeyHashes: await genesisNextKeyHashes({
      activeKeyMultibase: rung0.keyMultibase,
      stagedKeyMultibase: rung1.keyMultibase
    }),
    signer: await updateKeySigner({ seed: rung0.seed })
  })
}

/**
 * LADDER-ANCHORED GENESIS AS AN ENSURE: probe, adopt, or create-and-publish --
 * {@link createLadderAnchoredAccountLog} with the durable-flow `ensureDidWebvh`
 * convention wrapped around it. The convergence rule is what makes signup a
 * ceremony rather than a bare create: `createDID` timestamps the genesis
 * entry, so a naive re-run of a torn signup mints a DIFFERENT SCID and its
 * create-if-absent PUT can never land. So a published log is ADOPTED instead
 * -- iff `attributeLadderRung` attributes its update parameters to this
 * credential's ladder (rung revealed or committed; a foreign log fails
 * closed with `LadderAttributionError` and is never built on).
 *
 * The publish is a conditional create-if-absent, so a concurrent signup's
 * winner is adopted on the conflict re-run rather than erased. On the create
 * path a supplied `pinStore` is written from the log this run minted (the
 * account-log trust-on-first-use convention: the creator knows the true
 * genesis); on the probe path the read itself carries the pin check.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed
 * @param options.keyAgreement {UnlockKeyAgreementPublication}   the
 *   credential's key-agreement publication (commitment or verbatim)
 * @param [options.expectedDid] {string}   the DID the published log must
 *   resolve to, when the caller holds the account pointer; a heal login on a
 *   fresh terminal legitimately holds none
 * @param [options.pinStore] {ResourceLogPinStore}   this client's chain-head
 *   pins; the account log's slot is keyed by `accountLogPinId` over the
 *   `spaceId` above
 * @returns {Promise<{ did: string }>}
 */
export async function ensureLadderAnchoredDidWebvh(options: {
  idStore: WebvhIdStore
  wasServerUrl: string
  spaceId: string
  ladderSeed: Uint8Array
  keyAgreement: UnlockKeyAgreementPublication
  expectedDid?: string
  pinStore?: ResourceLogPinStore
}): Promise<{ did: string }> {
  return withLogConflictRetry(() => ensureLadderAnchoredDidWebvhOnce(options))
}

/**
 * One attempt of {@link ensureLadderAnchoredDidWebvh}, re-invoked by the
 * conflict retry.
 *
 * @param options {object}   see {@link ensureLadderAnchoredDidWebvh}
 * @returns {Promise<{ did: string }>}
 */
async function ensureLadderAnchoredDidWebvhOnce({
  idStore,
  wasServerUrl,
  spaceId,
  ladderSeed,
  keyAgreement,
  expectedDid,
  pinStore
}: {
  idStore: WebvhIdStore
  wasServerUrl: string
  spaceId: string
  ladderSeed: Uint8Array
  keyAgreement: UnlockKeyAgreementPublication
  expectedDid?: string
  pinStore?: ResourceLogPinStore
}): Promise<{ did: string }> {
  const logId = accountLogPinId({ spaceId })
  const published = await readPublishedLog({
    idStore,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore ? { pinStore, logId } : {})
  })
  if (published) {
    // Adoption: a torn earlier signup (or a concurrent one) already published
    // the log. Adopt it iff this credential's ladder attributes it -- the
    // ladder-anchored analog of the durable path's "authorizes one of this
    // client's seeds" check. The attribution accepts a revealed rung too, so
    // an account that has since self-enrolled a durable client (retiring
    // rung 0) still adopts here rather than hard-failing.
    await attributeLadderRung({ ladderSeed, published })
    // Heals a did.json left lagging by a torn earlier publish.
    const { did } = await concludeWithPublishedLog({ idStore, published })
    return { did }
  }
  const created = await createLadderAnchoredAccountLog({
    wasServerUrl,
    spaceId,
    ladderSeed,
    keyAgreement
  })
  await publishWebvhLog({
    idStore,
    log: created.log,
    webDoc: created.webDoc,
    // Create-if-absent: a concurrent signup that already published its own
    // log wins, and this run re-reads and adopts (or refuses) instead of
    // erasing it.
    ifNoneMatch: true
  })
  // Trust-on-first-use, established by the creator itself: this run minted the
  // genesis, so the pin it writes needs no served log to be believed.
  if (pinStore) {
    await pinStore.write({ logId, pin: pinOfLog(created.log) })
  }
  return { did: created.did }
}

/**
 * Publishes `did.jsonl` through the narrow seam -- the log only, never
 * `did.json` (the bridge delegation covers nothing else; the enrolled session
 * republishes the projection once it is the controller). Conditional on the
 * read the entry was built on; a lost race surfaces as a
 * `WebvhLogConflictError` (the mapping lives in `putLogResource`).
 *
 * @param options {object}
 * @param options.store {UnlockLogStore}
 * @param options.log {DIDLog}
 * @param [options.ifMatch] {string}   publish only if `did.jsonl` is unchanged
 * @returns {Promise<void>}
 */
async function publishLogOnly({
  store,
  log,
  ifMatch
}: {
  store: UnlockLogStore
  log: DIDLog
  ifMatch?: string
}): Promise<void> {
  await putLogResource({ store, log, ifMatch })
}

/**
 * SELF-ENROLLMENT (run by the credential-derived client through the delegated
 * `did.jsonl` PUT): writes the standing continuation described in the module
 * doc -- the reveal-and-commit entry signed by the attributed ladder rung,
 * then the add entry signed by the new ordinary client's update key, which
 * also retires the spent rung. Resumable from durable state alone: a
 * completed continuation is detected by the new client's update key already
 * being authorized (no-op), a torn one by the attribution finding the rung
 * already revealed. Both entries publish conditionally on the read they were
 * built on, and a race lost to a concurrent ceremony re-runs from the top --
 * re-attributing, which is exactly the retry-up-the-ladder resolution.
 *
 * @param options {object}
 * @param options.store {UnlockLogStore}   public log read + delegated PUT
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed, from
 *   its unlock record
 * @param options.newClientKeys {WebvhEnrollmentKeys}   the new ordinary
 *   client's public halves
 * @param options.newClientUpdateSeeds {ClientWebvhUpdateKeys}   the new
 *   client's update-key seeds (minted by the self-enrolling flow, which
 *   therefore holds them and can sign the add entry)
 * @param [options.expectedDid] {string}   the account DID the log must resolve
 *   to, from the credential-authenticated pointer
 * @param [options.pinStore] {ResourceLogPinStore}   this client's chain-head
 *   pins; every read both entries are built on is checked against the pinned
 *   head (a served prefix is refused before the reveal entry lands, not only
 *   by a verify that follows both entries), and the pin advances to each
 *   entry as it publishes
 * @param [options.logId] {string}   the account log's pin slot
 *   (`accountLogPinId({ spaceId })`); required whenever a `pinStore` is
 *   supplied
 * @returns {Promise<{ did: string, webDoc?: object }>}   the account DID and,
 *   when the add entry ran here, the final `did.json` projection for the
 *   enrolled session to republish
 */
export async function selfEnrollWebvhClient(options: {
  store: UnlockLogStore
  ladderSeed: Uint8Array
  newClientKeys: WebvhEnrollmentKeys
  newClientUpdateSeeds: ClientWebvhUpdateKeys
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; webDoc?: object }> {
  return withLogConflictRetry(() => selfEnrollWebvhClientOnce(options))
}

/**
 * One attempt of {@link selfEnrollWebvhClient}, re-invoked by the conflict
 * retry.
 *
 * @param options {object}   see {@link selfEnrollWebvhClient}
 * @returns {Promise<{ did: string, webDoc?: object }>}
 */
async function selfEnrollWebvhClientOnce({
  store,
  ladderSeed,
  newClientKeys,
  newClientUpdateSeeds,
  expectedDid,
  pinStore,
  logId
}: {
  store: UnlockLogStore
  ladderSeed: Uint8Array
  newClientKeys: WebvhEnrollmentKeys
  newClientUpdateSeeds: ClientWebvhUpdateKeys
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; webDoc?: object }> {
  // Each attempt's own read is what the CAS publish is built on, so the
  // continuity check runs here -- and again on the retry-up-the-ladder
  // re-run -- not only on the verify that follows both entries.
  const pinned = {
    ...(pinStore ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {})
  }
  let published = await readLogOrThrow({
    store,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...pinned
  })

  // Already complete (a torn earlier run finished the add entry): the new
  // client's update key is authorized, which only the add entry writes.
  if (published.updateKeys.includes(newClientKeys.updateKeyMultibase)) {
    return { did: published.did }
  }

  // Which rung is current, recovered from the log itself. Fails closed with
  // `LadderAttributionError` for a revoked (or never-bound) credential and
  // for any ambiguous history.
  const { rung, state } = await attributeLadderRung({ ladderSeed, published })
  const nextRung = await ladderRung({ ladderSeed, index: rung.index + 1 })
  const rungHash = await deriveNextKeyHash(rung.keyMultibase)
  const newUpdateHash = await deriveNextKeyHash(
    newClientKeys.updateKeyMultibase
  )
  const newStagedHash = await deriveNextKeyHash(
    newClientKeys.stagedUpdateKeyMultibase
  )
  const nextRungHash = await deriveNextKeyHash(nextRung.keyMultibase)

  // The reveal-and-commit entry, skipped when a torn earlier run already
  // published it (the rung revealed AND every needed hash committed).
  const revealed = state === 'revealed'
  const committed = [newUpdateHash, newStagedHash, nextRungHash].every(hash =>
    published.nextKeyHashes.includes(hash)
  )
  if (!revealed || !committed) {
    await assertCarryOverCommitments({ published })
    const signer = await updateKeySigner({ seed: rung.seed })
    const updated = await updateDID({
      log: published.log,
      signer,
      alsoKnownAsWeb: true,
      updateKeys: [...new Set([...published.updateKeys, rung.keyMultibase])],
      // The spent rung's own hash is kept through this entry (so a resumed
      // commit can re-state the revealed key); the add entry drops it, while
      // the next rung's hash stays as the credential's standing commitment.
      nextKeyHashes: [
        ...new Set([
          ...published.nextKeyHashes,
          rungHash,
          newUpdateHash,
          newStagedHash,
          nextRungHash
        ])
      ]
    })
    await publishLogOnly({ store, log: updated.log, ifMatch: published.etag })
    // Advance the pin to what the reveal entry just published, so the re-read
    // below (and any read after a tear here) refuses a host that rolls the
    // log back behind it.
    if (pinStore && logId !== undefined) {
      await pinStore.write({ logId, pin: pinOfLog(updated.log) })
    }
    // The same account the reveal entry just extended, under the same pin.
    published = await readLogOrThrow({
      store,
      expectedDid: published.did,
      ...pinned
    })
  }

  // The add entry: the new client's verification methods and update key in;
  // the spent rung's key and hash out. The credential's keyAgreement entry
  // and the next rung's committed hash stand untouched. Signed by the new
  // client's update key, whose hash the commit entry just committed.
  const { did, doc } = published
  const vmId = (publicKeyMultibase: string) => `${did}#${publicKeyMultibase}`
  // When this is the FIRST durable enrollment of a ladder-anchored account, the
  // same atomic entry ends the ladder-anchored window: every ladder VM (the
  // relation-asymmetry recognition) leaves the document and its relations
  // here, so no window exists where the account has neither a durable client
  // nor the ladder VM. On an account with enrolled clients the recognition
  // finds none and the filters are no-ops.
  const ladderVms = ladderVmIds({ doc })
  const addedMethods: VerificationMethod[] = markedVerificationMethodPair({
    controller: did,
    signingKeyMultibase: newClientKeys.signingKeyMultibase,
    keyAgreementKeyMultibase: newClientKeys.keyAgreementKeyMultibase
  })
  const existingMethods = (doc.verificationMethod ?? []) as VerificationMethod[]
  const verificationMethods = [
    ...existingMethods.filter(
      method =>
        !addedMethods.some(added => added.id === method.id) &&
        (method.id === undefined || !ladderVms.includes(method.id))
    ),
    ...addedMethods
  ]
  const withReference = (
    relation: Array<string | { id?: string }> | undefined,
    id: string
  ) =>
    [...new Set([...relationIds(relation), id])].filter(
      referencedId => !ladderVms.includes(referencedId)
    )
  const signingVmId = vmId(newClientKeys.signingKeyMultibase)

  const signer = await updateKeySigner({
    seed: newClientUpdateSeeds.updateSeed
  })
  const updated = await updateDID({
    log: published.log,
    signer,
    alsoKnownAsWeb: true,
    updateKeys: [
      ...new Set([
        ...published.updateKeys.filter(key => key !== rung.keyMultibase),
        newClientKeys.updateKeyMultibase
      ])
    ],
    nextKeyHashes: published.nextKeyHashes.filter(hash => hash !== rungHash),
    verificationMethods,
    authentication: withReference(doc.authentication, signingVmId),
    assertionMethod: withReference(doc.assertionMethod, signingVmId),
    keyAgreement: withReference(
      doc.keyAgreement,
      vmId(newClientKeys.keyAgreementKeyMultibase)
    ),
    capabilityInvocation: withReference(doc.capabilityInvocation, signingVmId),
    capabilityDelegation: withReference(doc.capabilityDelegation, signingVmId)
  })
  // Conditional on the read this entry was built on: the re-read above when
  // the commit entry ran here, the first read when it was skipped.
  await publishLogOnly({ store, log: updated.log, ifMatch: published.etag })
  // Advance the pin to what this entry just published, so a host rolling the
  // log back straight afterwards is refused on the next read.
  if (pinStore && logId !== undefined) {
    await pinStore.write({ logId, pin: pinOfLog(updated.log) })
  }
  return { did: updated.did, webDoc: updated.webDoc }
}

/**
 * Thrown when the client being forgotten is the account's LAST enrolled
 * durable client. Removing it through this entry would leave the document
 * with no client and no ladder verification method -- an account nothing can
 * invoke for -- so that case is its own ceremony (the two-entry
 * ladder-VM-install shape), and this primitive refuses rather than
 * transitioning the account by accident.
 *
 * **`name` is a stable contract.** It is always the string
 * `'LastDurableClientForgetError'`, and a consumer should match on that
 * rather than on `instanceof`: a wallet app that links this package (or holds
 * two copies of it through a dependency tree) gets a different class object
 * for the same error, so `instanceof` silently fails there while the name
 * does not.
 */
export class LastDurableClientForgetError extends Error {
  constructor() {
    super(
      'did:webvh: the client being forgotten is the last enrolled durable ' +
        'client; forgetting it takes the ladder-anchored transition ceremony, ' +
        'not the plain removal entry.'
    )
    this.name = 'LastDurableClientForgetError'
  }
}

/**
 * FORGET (run by the forgetting client itself, through the standing
 * credential's bridge): removes THIS browser's enrolled client from the
 * published document in ONE atomic ladder-signed entry -- self-enrollment in
 * reverse, collapsed to a single entry because a removal reveals no new key.
 * The signer is the credential's current ladder rung, recovered from the log
 * itself ({@link attributeLadderRung}): its hash stands committed by the
 * credential's inventory (or the rung is already revealed), which is exactly
 * what lets it reveal itself in the entry it signs under prerotation. The
 * entry's members are the revocation removal's, verbatim
 * (`clientRemovalTarget` / `clientRemovalFields`, shared with
 * `revokeWebvhClient` so the two removal shapes cannot drift): the client's
 * verification methods out of the document and all five relations, its update
 * key out of `updateKeys`, and its carry-over and staged hashes out of
 * `nextKeyHashes` -- plus the acting rung into `updateKeys` with its own hash
 * kept committed (the carry-over convention).
 *
 * Atomicity is the point of the one-entry shape: no torn state exists where
 * the rung is revealed and the client still stands. The honest residue is the
 * acting rung itself -- no entry can remove its own signing key, so the rung
 * stands REVEALED in `updateKeys` afterwards (the same standing state the
 * ladder-anchored accounts live in). That is credential-held authority, not
 * the forgotten client's: only the ladder seed derives it, the credential's
 * next self-enrollment consumes and retires it, and retiring the credential
 * itself strikes it (`attributeLadderInventory`).
 *
 * Forgetting the LAST enrolled durable client is refused
 * ({@link LastDurableClientForgetError}): that transition -- to the
 * client-less, ladder-anchored state -- is its own two-entry ceremony.
 *
 * Idempotent: a client with no remaining presence is a no-op that returns the
 * published state unchanged, so a naive re-run after a torn ceremony
 * converges. The entry publishes conditionally on the log this call read; a
 * lost race re-runs, re-attributes, and rebases on the winner's head.
 *
 * @param options {object}
 * @param options.store {UnlockLogStore}   the credential's delegated
 *   `did.jsonl` bridge store
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed
 * @param options.forgottenClient {RevokedClientKeys}   this client's public
 *   halves; an `updateKeyMultibase` the log does not authorize (stale, or the
 *   staged key) is re-derived from the log
 * @param [options.knownLatentHashes] {string[]}   standing latent commitments
 *   the caller vouches for (the recovery registry's update-key hashes),
 *   excluded from the staged-hash attribution
 * @param [options.expectedDid] {string}   the account DID the log must resolve
 *   to, from the caller's stored account pointer
 * @param [options.pinStore] {ResourceLogPinStore}   the caller's chain-head
 *   pins: the read inside each attempt is checked against the pinned head
 *   (a served truncated prefix is refused as a `rollback` before anything is
 *   built on it), and the pin advances to the head this entry publishes
 * @param [options.logId] {string}   the account log's pin slot
 *   (`accountLogPinId({ spaceId })`); required whenever a `pinStore` is
 *   supplied
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}   the account
 *   DID and the document and log as the removal entry leaves them (unchanged
 *   on the idempotent no-op path)
 */
export async function forgetWebvhClient(options: {
  store: UnlockLogStore
  ladderSeed: Uint8Array
  forgottenClient: RevokedClientKeys
  knownLatentHashes?: string[]
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  return withLogConflictRetry(() =>
    clientForgetEntryOnce({ ...options, transition: false })
  )
}

/**
 * THE LAST-CLIENT REMOVAL ENTRY (the two-entry transition ceremony's second
 * entry): {@link forgetWebvhClient}'s removal shape with the last-client
 * refusal inverted -- the forgotten client IS the last enrolled durable
 * client, and the account stays invocable because the ladder VM the install
 * entry published ({@link installLadderVmWebvh}) remains in the document. A
 * document NOT carrying this credential's ladder VM refuses: publishing the
 * entry would strand the account with neither a durable client nor the
 * ladder anchor. Run only from the composed ceremony
 * (`forgetLastDurableClient`), which sequences the install entry and the
 * delegation revocations before it.
 *
 * @param options {object}   see {@link forgetWebvhClient}
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}
 */
export async function forgetLastWebvhClient(options: {
  store: UnlockLogStore
  ladderSeed: Uint8Array
  forgottenClient: RevokedClientKeys
  knownLatentHashes?: string[]
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  return withLogConflictRetry(() =>
    clientForgetEntryOnce({ ...options, transition: true })
  )
}

/**
 * One attempt of {@link forgetWebvhClient} or {@link forgetLastWebvhClient},
 * re-invoked by the conflict retry. The two share everything but the guard:
 * the plain forget refuses the last durable client, the transition removal
 * requires the ladder VM already installed instead.
 *
 * @param options {object}   see {@link forgetWebvhClient}, plus:
 * @param options.transition {boolean}   `true` for the last-client removal
 *   entry (require the installed ladder VM), `false` for the plain forget
 *   (refuse the last client)
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}
 */
async function clientForgetEntryOnce({
  store,
  ladderSeed,
  forgottenClient,
  knownLatentHashes = [],
  expectedDid,
  pinStore,
  logId,
  transition
}: {
  store: UnlockLogStore
  ladderSeed: Uint8Array
  forgottenClient: RevokedClientKeys
  knownLatentHashes?: string[]
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
  transition: boolean
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  // Each attempt's own read is what the CAS publish is built on, so the
  // continuity check runs here, not only on the orchestrator's pre-read.
  const published = await readLogOrThrow({
    store,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {})
  })
  const { did, doc } = published

  const target = await clientRemovalTarget({
    published,
    client: forgottenClient
  })
  if (!target.present) {
    // Already forgotten (a torn earlier run finished the entry). No did.json
    // heal here: the bridge covers did.jsonl only.
    return { did, doc, log: published.log }
  }

  if (transition) {
    // The no-neither invariant, checked rather than assumed: the removal may
    // only publish while the ladder VM stands in the document (the install
    // entry ran), or the account would land with nothing that can anchor it.
    const ladderVmId = `${did}#${await ladderVmKeyMultibase({ ladderSeed })}`
    if (!ladderVmIds({ doc }).includes(ladderVmId)) {
      throw new Error(
        'did:webvh: the ladder VM is not installed in the document; the ' +
          'last-client removal entry would strand the account (the install ' +
          'entry runs first).'
      )
    }
  } else {
    // The last-client refusal: capabilityInvocation lists exactly the
    // enrolled clients' signing keys (a recovery code's key is
    // keyAgreement-only and the KMS convenience authentication-only), so the
    // forgotten client standing alone there means removing it strands the
    // account.
    const invocationIds = relationIds(doc.capabilityInvocation)
    if (
      invocationIds.includes(target.signingVmId) &&
      invocationIds.every(id => id === target.signingVmId)
    ) {
      throw new LastDurableClientForgetError()
    }
  }

  // Which rung is current, recovered from the log itself. Fails closed with
  // `LadderAttributionError` for a revoked (or never-bound) credential and
  // for any ambiguous history.
  const { rung } = await attributeLadderRung({ ladderSeed, published })
  const rungHash = await deriveNextKeyHash(rung.keyMultibase)
  await assertCarryOverCommitments({ published })

  // The ladder vouches for its own commitments: a self-enrolled client's
  // staged hash was committed in the same reveal entry as the next rung's
  // hash, so without these the staged-hash attribution cannot tell the two
  // apart. Every hash a reveal entry can have committed is for a rung at or
  // one past the current index.
  const ladderHashes: string[] = []
  for (let index = 0; index <= rung.index + 1; index++) {
    const laddered = await ladderRung({ ladderSeed, index })
    ladderHashes.push(await deriveNextKeyHash(laddered.keyMultibase))
  }
  const fields = await clientRemovalFields({
    published,
    target,
    knownLatentHashes: [...knownLatentHashes, ...ladderHashes]
  })
  const signer = await updateKeySigner({ seed: rung.seed })
  const updated = await updateDID({
    log: published.log,
    signer,
    alsoKnownAsWeb: true,
    ...fields,
    // The acting rung reveals itself in the entry it signs (its hash stands
    // committed, or the rung is already revealed), and its own hash is kept
    // committed so the carry-over convention holds for the next entry.
    updateKeys: [...new Set([...fields.updateKeys, rung.keyMultibase])],
    nextKeyHashes: [...new Set([...fields.nextKeyHashes, rungHash])]
  })
  await publishLogOnly({ store, log: updated.log, ifMatch: published.etag })
  // Advance the pin to what this entry just published, so a host rolling the
  // log back straight afterwards is refused on the next read.
  if (pinStore && logId !== undefined) {
    await pinStore.write({ logId, pin: pinOfLog(updated.log) })
  }
  return { did: updated.did, doc: updated.doc, log: updated.log }
}

/**
 * THE LADDER-VM INSTALL ENTRY (the two-entry transition ceremony's first
 * entry): publishes the credential's ladder VM -- the stable sibling, under
 * `assertionMethod` and `capabilityDelegation` only -- while the last durable
 * client's whole inventory stays untouched: the both-present transitional
 * state the no-neither invariant permits. The entry is ladder-signed by the
 * attributed rung, which reveals itself into `updateKeys` with its own hash
 * kept committed (the carry-over convention), exactly the removal entry's
 * rung math -- so a torn ceremony's re-run re-attributes the now-revealed
 * rung and carries on.
 *
 * This entry is what makes the transition's document version INVENTORY-CHANGING
 * under the ceremony-tail license (the ladder-VM set gains a member), so the
 * ceremony's ONE ladder-signed roster append anchors here -- and it is what
 * lets the delegation revocations that follow verify their ladder-signed
 * chains against the currently resolved document while the still-standing
 * client signs the invocations.
 *
 * Idempotent: a document already carrying this credential's ladder VM (by
 * the relation-asymmetry recognition) returns unchanged with
 * `installed: false`. The entry publishes conditionally on the log this call
 * read; a lost race re-runs, re-attributes, and rebases on the winner's
 * head.
 *
 * @param options {object}
 * @param options.store {UnlockLogStore}   the credential's delegated
 *   `did.jsonl` bridge store
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed
 * @param [options.expectedDid] {string}   the account DID the log must resolve
 *   to, from the caller's stored account pointer
 * @param [options.pinStore] {ResourceLogPinStore}   the caller's chain-head
 *   pins: the read inside each attempt is checked against the pinned head,
 *   and the pin advances to the head this entry publishes
 * @param [options.logId] {string}   the account log's pin slot
 *   (`accountLogPinId({ spaceId })`); required whenever a `pinStore` is
 *   supplied
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog, installed: boolean }>}
 *   the account DID and the document and log as the install entry leaves them
 *   (unchanged on the idempotent no-op path); `installed` says whether the
 *   entry ran on this call
 */
export async function installLadderVmWebvh(options: {
  store: UnlockLogStore
  ladderSeed: Uint8Array
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog; installed: boolean }> {
  return withLogConflictRetry(() => installLadderVmWebvhOnce(options))
}

/**
 * One attempt of {@link installLadderVmWebvh}, re-invoked by the conflict
 * retry.
 *
 * @param options {object}   see {@link installLadderVmWebvh}
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog, installed: boolean }>}
 */
async function installLadderVmWebvhOnce({
  store,
  ladderSeed,
  expectedDid,
  pinStore,
  logId
}: {
  store: UnlockLogStore
  ladderSeed: Uint8Array
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog; installed: boolean }> {
  // Each attempt's own read is what the CAS publish is built on, so the
  // continuity check runs here, not only on the orchestrator's pre-read.
  const published = await readLogOrThrow({
    store,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {})
  })
  const { did, doc } = published
  const ladderVmKey = await ladderVmKeyMultibase({ ladderSeed })
  const ladderVmId = `${did}#${ladderVmKey}`
  if (ladderVmIds({ doc }).includes(ladderVmId)) {
    // Already installed (a torn earlier run published the entry, or the
    // account is mid-transition).
    return { did, doc, log: published.log, installed: false }
  }

  // Which rung is current, recovered from the log itself. Fails closed with
  // `LadderAttributionError` for a revoked (or never-bound) credential and
  // for any ambiguous history.
  const { rung } = await attributeLadderRung({ ladderSeed, published })
  const rungHash = await deriveNextKeyHash(rung.keyMultibase)
  await assertCarryOverCommitments({ published })

  const existingMethods = (doc.verificationMethod ?? []) as VerificationMethod[]
  const verificationMethods = [
    ...existingMethods.filter(method => method.id !== ladderVmId),
    ladderVerificationMethod({
      controller: did,
      publicKeyMultibase: ladderVmKey
    })
  ]
  // The ladder VM's relation asymmetry: `assertionMethod` and
  // `capabilityDelegation` only -- no `authentication`, no
  // `capabilityInvocation` -- which is also what keeps it out of every client
  // listing.
  const withVm = (relation: Array<string | { id?: string }> | undefined) => [
    ...new Set([...relationIds(relation), ladderVmId])
  ]
  const signer = await updateKeySigner({ seed: rung.seed })
  const updated = await updateDID({
    log: published.log,
    signer,
    alsoKnownAsWeb: true,
    // The acting rung reveals itself in the entry it signs (its hash stands
    // committed, or the rung is already revealed), and its own hash is kept
    // committed so the carry-over convention holds for the next entry.
    updateKeys: [...new Set([...published.updateKeys, rung.keyMultibase])],
    nextKeyHashes: [...new Set([...published.nextKeyHashes, rungHash])],
    verificationMethods,
    authentication: relationIds(doc.authentication),
    assertionMethod: withVm(doc.assertionMethod),
    keyAgreement: relationIds(doc.keyAgreement),
    capabilityInvocation: relationIds(doc.capabilityInvocation),
    capabilityDelegation: withVm(doc.capabilityDelegation)
  })
  await publishLogOnly({ store, log: updated.log, ifMatch: published.etag })
  // Advance the pin to what this entry just published, so a host rolling the
  // log back straight afterwards is refused on the next read.
  if (pinStore && logId !== undefined) {
    await pinStore.write({ logId, pin: pinOfLog(updated.log) })
  }
  return {
    did: updated.did,
    doc: updated.doc,
    log: updated.log,
    installed: true
  }
}
