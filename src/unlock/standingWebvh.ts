/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The did:webvh half of the standing unlock-credential lifecycle: the split
 * posture every unlock method holds under the standing model, and the
 * self-enrolling continuation a fresh browser runs with nothing but the
 * credential in hand.
 *
 * At bind time the document gains the credential's `keyAgreement` entry --
 * the key verbatim for a high-entropy credential (a passkey PRF output, a
 * recovery code), or a `MultikeyCommitment` entry for a low-entropy-derived
 * key (a passphrase), so the world-readable document carries a check on the
 * key without carrying the key -- and `nextKeyHashes` gains the hash of the
 * credential's current update key (a ladder rung, or a code's single derived
 * key).
 * Decryption standing, authority latent: the credential's update key joins
 * `updateKeys` nowhere, and both entries are deliberately unmarked, so client
 * listings (keyed on `capabilityInvocation`) and revocation removals never
 * see them. {@link publishUnlockKey} / {@link removeUnlockKey} are one merged
 * add/remove pair, shared verbatim by the recovery-code wrappers.
 *
 * Self-enrollment ({@link selfEnrollWebvhClient}) is the recovery
 * continuation generalized to a non-spending credential: two entries through
 * the record's delegated `did.jsonl` bridge --
 *
 * 1. **Reveal + commit**: ladder rung `i` joins `updateKeys` (its hash stands
 *    committed, which is what makes the entry verify) and `nextKeyHashes`
 *    extends with the new ordinary client's update- and staged-key hashes
 *    plus `hash(rung i + 1)` -- the credential's next standing commitment.
 * 2. **Add + retire the rung**: signed by the new client's update key
 *    (revealed from the commit), this entry publishes the new client's
 *    verification methods and update key and drops the spent rung and its
 *    hash. The credential's own posture -- its `keyAgreement` entry and the
 *    freshly committed `hash(rung i + 1)` -- stands untouched, ready for the
 *    next self-enrollment. Nothing is spent, and no replacement exists.
 *    When the account was LADDER-ANCHORED
 *    ({@link createLadderAnchoredAccountLog}), the same atomic entry removes the ladder VM from the document and its
 *    relations -- the transitional key exists only while no durable client
 *    does, and folding the removal in leaves no window with neither.
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
  BYOE_CONTEXT_URL,
  concludeWithPublishedLog,
  createLadderAnchoredWebvhLog,
  didWebvhControllerTemplate,
  genesisNextKeyHashes,
  markedVerificationMethodPair,
  MULTIKEY_COMMITMENT_VM_TYPE,
  MULTIKEY_VM_TYPE,
  pinOfLog,
  publishUpdatedLog,
  publishWebvhLog,
  putLogResource,
  readPublishedLog,
  relationIds,
  updateKeyMultibase,
  updateKeySigner,
  withLogConflictRetry
} from '../webvh/didWebvh.js'
import { accountLogPinId } from '../webvh/verifyLog.js'
import type { ResourceLogPinStore } from '../resourceLog/index.js'
import { ladderVmIds } from '../webvh/listClients.js'
import type {
  ClientWebvhUpdateKeys,
  PublishedWebvhLog,
  WebvhEnrollmentKeys,
  WebvhIdStore
} from '../webvh/didWebvh.js'
import {
  attributeLadderRung,
  ladderRung,
  ladderVmKeyMultibase
} from './ladder.js'

/**
 * The narrow store seam the self-enrollment continuation writes through: a
 * public read of the log and the delegated `did.jsonl` PUT. A subset of
 * {@link WebvhIdStore}, so an app's remote-store class satisfies it too.
 */
export type UnlockLogStore = Pick<
  WebvhIdStore,
  'getIdResourceRaw' | 'putIdResource'
>

/**
 * How a credential's key-agreement key is published in the document: the key
 * verbatim (a high-entropy credential -- passkey PRF, recovery code), or its
 * hash commitment (`keyAgreementCommitment`) for a low-entropy-derived key.
 * A commitment withholds the key material and gives the roster's recipient
 * resolver a document-anchored check to verify a roster-carried key against.
 */
export type UnlockKeyAgreementPublication =
  { publicKeyMultibase: string } | { commitment: string }

/**
 * A standing credential's public posture as the document and log carry it:
 * its key-agreement publication and the update key whose hash stands in
 * `nextKeyHashes` (ladder rung 0 at bind time; a code's single derived key).
 */
export interface StandingUnlockKeys {
  keyAgreement: UnlockKeyAgreementPublication
  updateKeyMultibase: string
}

/**
 * The verification-method id a credential's key-agreement entry publishes
 * under: `<did>#<multibase>` for a verbatim key (indistinguishable by id from
 * any other keyAgreement entry), `<did>#<commitment>` for a commitment entry
 * (the commitment string is deterministic, so the id is too).
 *
 * @param options {object}
 * @param options.did {string}   the account's did:webvh
 * @param options.keyAgreement {UnlockKeyAgreementPublication}
 * @returns {string}
 */
export function unlockKeyVmId({
  did,
  keyAgreement
}: {
  did: string
  keyAgreement: UnlockKeyAgreementPublication
}): string {
  const fragment =
    'publicKeyMultibase' in keyAgreement
      ? keyAgreement.publicKeyMultibase
      : keyAgreement.commitment
  return `${did}#${fragment}`
}

/**
 * The credential's `keyAgreement` verification method: an ordinary unmarked
 * entry carrying either the key verbatim (a `Multikey` with
 * `publicKeyMultibase`) or its hash commitment (a `MultikeyCommitment` with
 * `publicKeyCommitment` -- the document convention for a low-entropy-derived
 * key, which withholds the key material and gives the roster resolver a
 * document-anchored check). Controlled by the account and deliberately
 * unmarked: a credential is not a listed client, so its entry must never
 * carry the controller marker a client listing or a revocation removal
 * matches on.
 *
 * @param options {object}
 * @param options.did {string}   the account's did:webvh
 * @param options.keyAgreement {UnlockKeyAgreementPublication}
 * @returns {VerificationMethod}
 */
export function unlockKeyVerificationMethod({
  did,
  keyAgreement
}: {
  did: string
  keyAgreement: UnlockKeyAgreementPublication
}): VerificationMethod {
  const id = unlockKeyVmId({ did, keyAgreement })
  if ('publicKeyMultibase' in keyAgreement) {
    return {
      id,
      type: MULTIKEY_VM_TYPE,
      controller: did,
      publicKeyMultibase: keyAgreement.publicKeyMultibase
    }
  }
  return {
    id,
    type: MULTIKEY_COMMITMENT_VM_TYPE,
    controller: did,
    publicKeyCommitment: keyAgreement.commitment
  } as VerificationMethod
}

/**
 * LADDER-ANCHORED GENESIS: assembles the one-entry did:webvh log of an account
 * with zero enrolled durable clients, anchored on the minting credential's
 * ladder alone. Everything derives from the ladder seed: rung 0 is the sole
 * `updateKeys` member and signs the entry, `nextKeyHashes` commits rung 0's
 * own carry-over hash plus rung 1 (the staged rung) -- the carry-over hash is
 * what the first durable self-enrollment's reveal-and-commit entry,
 * re-stating `updateKeys` containing rung 0, requires --
 * and the ladder VM (the stable sibling) is published under `assertionMethod`
 * and `capabilityDelegation` only. The credential's `keyAgreement` posture
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
 * Reads and resolves the published log through the narrow store seam.
 *
 * @param options {object}
 * @param options.store {UnlockLogStore}
 * @param [options.expectedDid] {string}   the account DID the log must resolve
 *   to, where the caller holds one
 * @returns {Promise<PublishedWebvhLog>}
 */
async function readLogOrThrow({
  store,
  expectedDid
}: {
  store: UnlockLogStore
  expectedDid?: string
}): Promise<PublishedWebvhLog> {
  // readPublishedLog only calls getIdResourceRaw, so the narrow seam is safe.
  const published = await readPublishedLog({
    idStore: store as WebvhIdStore,
    ...(expectedDid !== undefined ? { expectedDid } : {})
  })
  if (!published) {
    throw new Error('did:webvh: did.jsonl is missing; nothing to enroll into.')
  }
  return published
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
 * BIND (run by an enrolled client, root authority): publishes a standing
 * credential's split posture into the document -- one entry adding the
 * credential's `keyAgreement` entry (verbatim or commitment) and committing
 * its current update key's hash in `nextKeyHashes`. The update key joins
 * `updateKeys` nowhere. Idempotent: a posture already published is a no-op,
 * so re-running a torn bind converges. The entry publishes conditionally on
 * the log this call read; a race lost to a concurrent ceremony re-runs and
 * rebases on the new head.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.updateKeys {ClientWebvhUpdateKeys}   the BINDING client's own
 *   did:webvh update-key seeds
 * @param options.unlockKeys {StandingUnlockKeys}   the credential's public
 *   posture
 * @param [options.expectedDid] {string}   the account DID the log must resolve
 *   to, from the caller's stored account pointer
 * @param [options.verb] {string}   what the caller is doing, for the
 *   pending-rotation refusal message (e.g. `'issuing a recovery code'`)
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}   the account
 *   DID and the document and log as this call leaves them (unchanged when the
 *   posture was already settled), which is what the caller's roster-side half
 *   converges onto
 */
export async function publishUnlockKey(options: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  unlockKeys: StandingUnlockKeys
  expectedDid?: string
  verb?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  return withLogConflictRetry(() =>
    setUnlockKeyPostureOnce({ ...options, polarity: 'publish' })
  )
}

/**
 * REMOVAL (run by an enrolled client, root authority): removes a standing
 * credential's posture from the document -- its `keyAgreement` entry and its
 * committed update-key hash -- in one entry. Idempotent. The roster-side half
 * (rotating the user key epoch off the credential's wrap) is the caller's,
 * and runs after this so the resolver's document no longer backs the removed
 * entry.
 *
 * @param options {object}   see {@link publishUnlockKey}
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}   see
 *   {@link publishUnlockKey}
 */
export async function removeUnlockKey(options: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  unlockKeys: StandingUnlockKeys
  expectedDid?: string
  verb?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  return withLogConflictRetry(() =>
    setUnlockKeyPostureOnce({ ...options, polarity: 'remove' })
  )
}

/**
 * One attempt of the merged posture edit, re-invoked by the conflict retry.
 * The publish and remove polarities are one function because the entry they
 * build is the same edit with the set operations inverted -- a divergence
 * between two copies would be published into an append-only log.
 *
 * @param options {object}   see {@link publishUnlockKey}, plus `polarity`
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}
 */
async function setUnlockKeyPostureOnce({
  idStore,
  updateKeys,
  unlockKeys,
  expectedDid,
  verb,
  polarity
}: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  unlockKeys: StandingUnlockKeys
  expectedDid?: string
  verb?: string
  polarity: 'publish' | 'remove'
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  const published = await readLogOrThrow({
    store: idStore,
    ...(expectedDid !== undefined ? { expectedDid } : {})
  })
  const { did, doc } = published
  const keyHash = await deriveNextKeyHash(unlockKeys.updateKeyMultibase)
  const vmId = unlockKeyVmId({ did, keyAgreement: unlockKeys.keyAgreement })

  const vmPresent = (doc.verificationMethod ?? []).some(
    method => method.id === vmId
  )
  const hashCommitted = published.nextKeyHashes.includes(keyHash)
  const settled =
    polarity === 'publish'
      ? vmPresent && hashCommitted
      : !vmPresent && !hashCommitted
  if (settled) {
    return { did, doc, log: published.log }
  }

  const activeKey = await updateKeyMultibase({ seed: updateKeys.updateSeed })
  if (!published.updateKeys.includes(activeKey)) {
    throw new Error(
      "did:webvh: the published log does not authorize this client's active " +
        'update key; finalize the pending rotation before ' +
        `${verb ?? 'changing an unlock credential'}.`
    )
  }
  await assertCarryOverCommitments({ published })

  const existingMethods = (doc.verificationMethod ?? []) as VerificationMethod[]
  const signer = await updateKeySigner({ seed: updateKeys.updateSeed })
  const nextKeyHashes =
    polarity === 'publish'
      ? [...new Set([...published.nextKeyHashes, keyHash])]
      : published.nextKeyHashes.filter(hash => hash !== keyHash)
  const verificationMethods =
    polarity === 'publish'
      ? [
          ...existingMethods.filter(method => method.id !== vmId),
          unlockKeyVerificationMethod({
            did,
            keyAgreement: unlockKeys.keyAgreement
          })
        ]
      : existingMethods.filter(method => method.id !== vmId)
  const keyAgreement =
    polarity === 'publish'
      ? [...new Set([...relationIds(doc.keyAgreement), vmId])]
      : relationIds(doc.keyAgreement).filter(id => id !== vmId)

  const updated = await updateDID({
    log: published.log,
    signer,
    alsoKnownAsWeb: true,
    // A commitment entry's terms are defined by the byoe context, so the
    // posture publish appends it to the carried-forward context. The append
    // is deduplicated, so a document already carrying it is unchanged.
    additionalContext: [BYOE_CONTEXT_URL],
    updateKeys: published.updateKeys,
    nextKeyHashes,
    verificationMethods,
    authentication: relationIds(doc.authentication),
    assertionMethod: relationIds(doc.assertionMethod),
    keyAgreement,
    capabilityInvocation: relationIds(doc.capabilityInvocation),
    capabilityDelegation: relationIds(doc.capabilityDelegation)
  })
  await publishUpdatedLog({ idStore, updated, ifMatch: published.etag })
  return { did: updated.did, doc: updated.doc, log: updated.log }
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
  expectedDid
}: {
  store: UnlockLogStore
  ladderSeed: Uint8Array
  newClientKeys: WebvhEnrollmentKeys
  newClientUpdateSeeds: ClientWebvhUpdateKeys
  expectedDid?: string
}): Promise<{ did: string; webDoc?: object }> {
  let published = await readLogOrThrow({
    store,
    ...(expectedDid !== undefined ? { expectedDid } : {})
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
    // The same account the reveal entry just extended.
    published = await readLogOrThrow({ store, expectedDid: published.did })
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
  return { did: updated.did, webDoc: updated.webDoc }
}
