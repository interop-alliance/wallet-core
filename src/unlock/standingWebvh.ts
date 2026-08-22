/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The did:webvh INVENTORY half of the standing unlock-credential lifecycle: the
 * split configuration every unlock method holds under the standing model, as one
 * merged add/remove document edit.
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
 * The ceremonies that EXERCISE a credential's ladder against the account log
 * -- the ladder-anchored genesis, the self-enrolling continuation, the
 * one-entry forget -- live in `clientAnnex/ladderAnchored.ts`. What stays
 * here is the verify-side half every wallet needs regardless of account configuration.
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
  MULTIKEY_COMMITMENT_VM_TYPE,
  MULTIKEY_VM_TYPE,
  publishUpdatedLog,
  readPublishedLog,
  relationIds,
  updateKeyMultibase,
  updateKeySigner,
  withLogConflictRetry
} from '../webvh/didWebvh.js'
import { ladderVmIds } from '../webvh/listClients.js'
import type {
  ClientWebvhUpdateKeys,
  PublishedWebvhLog,
  WebvhIdStore
} from '../webvh/didWebvh.js'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
// The one deliberate base-side dependency on the annex subpath, pinned as an
// exception in the lint rule: `removeUnlockKey` resolves the retired
// credential's CURRENT ladder inventory from the log itself (the shared
// attribution helpers in `clientAnnex/ladder.ts`), never touching the annex
// log machinery, and derives the credential's ladder VM id from a supplied
// seed so the removal strikes that too.
import {
  attributeLadderInventory,
  ladderVmKeyMultibase
} from '../clientAnnex/ladder.js'

/**
 * The narrow store seam the self-enrolling and delegated-bridge ceremonies
 * write through: a public read of the log and the delegated `did.jsonl` PUT.
 * A subset of {@link WebvhIdStore}, so an app's remote-store class satisfies
 * it too.
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
 * A standing credential's public inventory as the document and log carry it:
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
 * Reads and resolves the published log through the narrow store seam.
 *
 * @param options {object}
 * @param options.store {UnlockLogStore}
 * @param [options.expectedDid] {string}   the account DID the log must resolve
 *   to, where the caller holds one
 * @param [options.pinStore] {ResourceLogPinStore}   the caller's chain-head
 *   pins; a served log that is a rollback, a fork, or an identity switch
 *   against the pinned head is refused (`ResourceLogContinuityError`)
 * @param [options.logId] {string}   the account log's pin slot
 *   (`accountLogPinId({ spaceId })`); required whenever a `pinStore` is
 *   supplied
 * @returns {Promise<PublishedWebvhLog>}
 */
export async function readLogOrThrow({
  store,
  expectedDid,
  pinStore,
  logId
}: {
  store: UnlockLogStore
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<PublishedWebvhLog> {
  // readPublishedLog only calls getIdResourceRaw, so the narrow seam is safe.
  const published = await readPublishedLog({
    idStore: store as WebvhIdStore,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {})
  })
  if (!published) {
    throw new Error('did:webvh: did.jsonl is missing; nothing to enroll into.')
  }
  return published
}

/**
 * BIND (run by an enrolled client, root authority): publishes a standing
 * credential's split configuration into the document -- one entry adding the
 * credential's `keyAgreement` entry (verbatim or commitment) and committing
 * its current update key's hash in `nextKeyHashes`. The update key joins
 * `updateKeys` nowhere. Idempotent: an inventory already published is a no-op,
 * so re-running a torn bind converges. The entry publishes conditionally on
 * the log this call read; a race lost to a concurrent ceremony re-runs and
 * rebases on the new head.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.updateKeys {ClientWebvhUpdateKeys}   the BINDING client's own
 *   did:webvh update-key seeds
 * @param options.unlockKeys {StandingUnlockKeys}   the credential's public
 *   inventory
 * @param [options.expectedDid] {string}   the account DID the log must resolve
 *   to, from the caller's stored account pointer
 * @param [options.verb] {string}   what the caller is doing, for the
 *   pending-rotation refusal message (e.g. `'issuing a recovery code'`)
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}   the account
 *   DID and the document and log as this call leaves them (unchanged when the
 *   inventory was already settled), which is what the caller's roster-side half
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
    setUnlockKeyInventoryOnce({ ...options, polarity: 'publish' })
  )
}

/**
 * REMOVAL (run by an enrolled client, root authority): removes a standing
 * credential's inventory from the document -- its `keyAgreement` entry and
 * everything of its ladder that still stands -- in one entry. Idempotent. The
 * roster-side half (rotating the user key epoch off the credential's wrap) is
 * the caller's, and runs after this so the resolver's document no longer
 * backs the removed entry.
 *
 * The recorded `unlockKeys.updateKeyMultibase` is treated as an ANCHOR, not
 * as truth: a credential that has self-enrolled since its bind advanced its
 * standing commitment past the recorded rung, so the removal resolves the
 * ladder's current inventory from the log itself
 * ({@link attributeLadderInventory}) and strikes all of it -- every committed
 * hash the ladder accounts for AND, for a torn self-enrollment, the revealed
 * rung key still sitting in `updateKeys` (plus the never-claimed hashes its
 * reveal entry committed). Trusting the recorded multibase alone would leave
 * the live rung commitment standing: a latent re-seizure credential via the
 * reveal mechanism. A supplied `ladderSeed` strengthens the attribution (every
 * rung known a priori, independent of the anchor's staleness); without it the
 * log walk alone resolves the inventory. For a single-key credential (a
 * recovery code, a never-self-enrolled bind) the resolution degenerates to
 * exactly the recorded key's hash, as before.
 *
 * The seed also names the credential's LADDER VM -- the stable sibling a
 * last-client forget's install entry publishes under `assertionMethod` and
 * `capabilityDelegation`, left standing by a forget torn after that entry --
 * and the removal strikes it in the same entry, so a retired seed no longer
 * signs governed-log appends or account delegations. The sibling is derived
 * from the seed alone, with nothing in the log attributing it to a ladder, so
 * a removal without the seed leaves it: rotation is the remedy for a leaked
 * seed exactly when the ceremony holds the credential.
 *
 * @param options {object}   see {@link publishUnlockKey}, plus
 *   `[ladderSeed]` -- the retired credential's ladder seed, when in hand
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}   see
 *   {@link publishUnlockKey}
 */
export async function removeUnlockKey(options: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  unlockKeys: StandingUnlockKeys
  ladderSeed?: Uint8Array
  expectedDid?: string
  verb?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  return withLogConflictRetry(() =>
    setUnlockKeyInventoryOnce({ ...options, polarity: 'remove' })
  )
}

/**
 * One attempt of the merged inventory edit, re-invoked by the conflict retry.
 * The publish and remove polarities are one function because the entry they
 * build is the same edit with the set operations inverted -- a divergence
 * between two copies would be published into an append-only log.
 *
 * @param options {object}   see {@link publishUnlockKey}, plus `polarity`
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}
 */
async function setUnlockKeyInventoryOnce({
  idStore,
  updateKeys,
  unlockKeys,
  ladderSeed,
  expectedDid,
  verb,
  polarity
}: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  unlockKeys: StandingUnlockKeys
  ladderSeed?: Uint8Array
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
  // The remove polarity strikes the ladder's CURRENT inventory, resolved from
  // the log with the recorded key as anchor -- never just the recorded key's
  // hash, which a self-enrollment since the bind leaves stale (see
  // {@link removeUnlockKey}). The credential's own verification-method id
  // goes along: it is what tells the walk a climb from a spend, so the
  // removal never annexes the commitment a spend handed to its replacement.
  const inventory =
    polarity === 'remove'
      ? await attributeLadderInventory({
          log: published.log,
          anchorKeyMultibase: unlockKeys.updateKeyMultibase,
          credentialVmId: vmId,
          ...(ladderSeed ? { ladderSeed } : {})
        })
      : { revealedKeys: [], committedHashes: [] }
  const removedHashes = new Set(inventory.committedHashes)
  const removedKeys = new Set(inventory.revealedKeys)
  // The credential's ladder VM, where one stands: the stable sibling a
  // last-client forget's install entry publishes, which stays behind when
  // that forget is torn after its first entry. It is derived from the ladder
  // seed and nothing else, so ownership is attributable only with the seed in
  // hand; a removal without it leaves the sibling standing (see
  // {@link removeUnlockKey}).
  const ladderVmId =
    polarity === 'remove' && ladderSeed
      ? `${did}#${await ladderVmKeyMultibase({ ladderSeed })}`
      : undefined
  const ladderVmPresent =
    ladderVmId !== undefined && ladderVmIds({ doc }).includes(ladderVmId)
  const struckIds = new Set([vmId, ...(ladderVmPresent ? [ladderVmId!] : [])])
  const hashCommitted = published.nextKeyHashes.includes(keyHash)
  const settled =
    polarity === 'publish'
      ? vmPresent && hashCommitted
      : !vmPresent &&
        !ladderVmPresent &&
        removedHashes.size === 0 &&
        removedKeys.size === 0
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
      : published.nextKeyHashes.filter(hash => !removedHashes.has(hash))
  // A torn self-enrollment leaves a revealed rung in `updateKeys`; the remove
  // polarity strikes it in the same entry as its hash, keeping the carry-over
  // invariant self-consistent. On the publish polarity and the ordinary
  // committed-only removal this is the published set unchanged.
  const statedUpdateKeys =
    polarity === 'publish'
      ? published.updateKeys
      : published.updateKeys.filter(key => !removedKeys.has(key))
  const verificationMethods =
    polarity === 'publish'
      ? [
          ...existingMethods.filter(method => method.id !== vmId),
          unlockKeyVerificationMethod({
            did,
            keyAgreement: unlockKeys.keyAgreement
          })
        ]
      : existingMethods.filter(
          method => method.id === undefined || !struckIds.has(method.id)
        )
  // On the remove polarity every relation drops the struck ids: the
  // credential's entry sits under `keyAgreement` alone and the ladder VM under
  // `assertionMethod` and `capabilityDelegation` alone, so one filter serves
  // all five without restating either placement here.
  const relation = (
    ids: Array<string | { id?: string }> | undefined
  ): string[] =>
    polarity === 'publish'
      ? relationIds(ids)
      : relationIds(ids).filter(id => !struckIds.has(id))
  const keyAgreement =
    polarity === 'publish'
      ? [...new Set([...relationIds(doc.keyAgreement), vmId])]
      : relation(doc.keyAgreement)

  const updated = await updateDID({
    log: published.log,
    signer,
    alsoKnownAsWeb: true,
    // A commitment entry's terms are defined by the byoe context, so the
    // inventory publish appends it to the carried-forward context. The append
    // is deduplicated, so a document already carrying it is unchanged.
    additionalContext: [BYOE_CONTEXT_URL],
    updateKeys: statedUpdateKeys,
    nextKeyHashes,
    verificationMethods,
    authentication: relation(doc.authentication),
    assertionMethod: relation(doc.assertionMethod),
    keyAgreement,
    capabilityInvocation: relation(doc.capabilityInvocation),
    capabilityDelegation: relation(doc.capabilityDelegation)
  })
  await publishUpdatedLog({ idStore, updated, ifMatch: published.etag })
  return { did: updated.did, doc: updated.doc, log: updated.log }
}
