/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The forget ceremony: a remembered browser's durable client removes ITSELF
 * from the account, through the standing unlock credential's bridge, before
 * the app wipes its local state. Self-enrollment in reverse, run with what a
 * live durable session already holds -- the credential's ladder seed and its
 * delegated `did.jsonl` bridge -- and refused for the account's last enrolled
 * durable client ({@link LastDurableClientForgetError}), whose forget is the
 * ladder-anchored transition, a separate ceremony.
 *
 * The stage order INVERTS the revocation cascade's document-edit-first rule,
 * and the inversion is forced twice over: once the removal entry lands, the
 * forgetting client's key is out of `assertionMethod` at the post-edit head,
 * so it can sign no roster append (the entry-proof rule), and its WAS
 * invocations stop verifying (the current-key-set rule), so the collection
 * fan-out cannot run either -- while a ladder-signed append is licensed only
 * at a posture-changing document version, which a not-last-client removal is
 * not. So:
 *
 * 1. **The roster rotation**, PRE-edit, signed by the still-enrolled
 *    forgetting client: the user key rotates off this client's wrap, retired
 *    by its roster kid explicitly (document convergence cannot drop a client
 *    the document still lists). The fresh key is read back through the
 *    CREDENTIAL's standing wrap -- the forgetting client just retired its
 *    own -- which the rotation fan-out keeps escrowed into every epoch.
 * 2. **The collection fan-out**, still under this client's invocation
 *    authority: every encrypted collection re-epochs onto the fresh key, so
 *    writes stop landing under epochs a later holder of this browser's
 *    residue could open.
 * 3. **The removal entry** ({@link forgetWebvhClient}): one atomic
 *    ladder-signed entry through the bridge takes the client's whole document
 *    footprint out. The app's local wipe runs after this ceremony returns, so
 *    a tear anywhere before the entry reads as "not forgotten" and a re-click
 *    resumes.
 *
 * Torn-state map: a run torn after stage 1 leaves the account rotated off a
 * client the document still lists -- writes already land under the fresh key,
 * the client-key record still stands, and the re-run's rotation no-ops (the
 * wrap is already gone) while its later stages finish. Torn after stage 3
 * (the removal published, the app's wipe not run) is the
 * finish-the-wipe state the app's next login maps. What no re-run needs:
 * the roster log's head stays anchored BEFORE the removal entry -- no signer
 * this ceremony holds may append after it -- which is exactly the unsealed
 * state any other enrolled client's login sweep detects and seals.
 *
 * There is deliberately no recovery-delegation or generation-delegation
 * re-mint stage: the forgetting client cannot re-mint with a key that dies at
 * stage 3 (the replacement would rot moments later), so a delegation this
 * client had signed is left to the standing self-heals (a durable login's
 * bridge refresh and `ensureGenerationDelegationCurrent` on the
 * account-document axis).
 *
 * The honest limitation is the cascade's, as everywhere: ciphertext this
 * browser already fetched stays forensically recoverable from its storage,
 * and old epochs stay open to keys it already held. The rotation stops future
 * reads; the wipe removes the local copies.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import { readPublishedLog, relationIds } from '../webvh/didWebvh.js'
import type { WebvhIdStore } from '../webvh/didWebvh.js'
import type { RevokedClientKeys } from '../webvh/revokeClient.js'
import {
  cascadeCollectionsToUserKey,
  readUserKeyRoster,
  rosterRecipientKid,
  rotateUserKeyRoster,
  type CascadeCollections,
  type UserKey,
  type UserKeyCascadeResult
} from '../keys/index.js'
import {
  forgetWebvhClient,
  LastDurableClientForgetError,
  type UnlockLogStore
} from './standingWebvh.js'

/**
 * What a completed forget reports: whether the roster's wrap for the
 * forgotten client was actually retired on this run (a re-run of a
 * torn-after-rotation ceremony reports `false`), the per-collection fan-out
 * result, the document as the removal entry left it, and -- when the account
 * has a roster -- the rotated key with the roster descriptor it was read
 * from.
 */
export interface DurableClientForgetResult {
  rotated: boolean
  collections: UserKeyCascadeResult
  did: string
  document: object
  userKey?: UserKey
  rosterDescriptor?: CollectionEncryption
}

/**
 * Forgets one enrolled durable client -- this browser's own -- from its
 * account. See the module doc for the stage order (rotation and fan-out
 * BEFORE the removal entry, the self-forget inversion) and the torn-state
 * map. The caller runs the local wipe only after this resolves.
 *
 * @param options {object}
 * @param options.logStore {UnlockLogStore}   the credential's delegated
 *   `did.jsonl` bridge store; also serves the ceremony's public pre-edit
 *   read. The caller is expected to have verified the account log under its
 *   own chain-head pins in the same session (the ceremony re-reads through
 *   the seam and checks `expectedDid`, but carries no pin store itself)
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed
 * @param options.forgottenClient {RevokedClientKeys}   this client's public
 *   halves; an `updateKeyMultibase` the log does not authorize (stale, or the
 *   staged key) is re-derived from the log
 * @param options.forgottenKeyAgreementKeyMultibase {string}   this client's
 *   identity key-agreement key (the X25519 twin), naming its roster wrap
 * @param [options.knownLatentHashes] {string[]}   standing latent commitments
 *   the caller vouches for (the recovery registry's update-key hashes),
 *   excluded from the staged-hash attribution
 * @param options.expectedDid {string}   the account DID from the caller's
 *   stored account pointer
 * @param options.rosterStore {EncryptionDescriptorStore}   the
 *   `key-map/user-key.jsonl` roster store, signing as the forgetting client
 * @param options.credentialKeyAgreementKey {IKeyAgreementKey}   the standing
 *   credential's key-agreement key -- the recipient whose wrap survives the
 *   rotation, reading the fresh key back and unwrapping the generations for
 *   the fan-out
 * @param [options.userKey] {UserKey}   this client's cached user key
 * @param [options.pinnedEpochId] {string}   the locally pinned latest-seen
 *   roster epoch
 * @param [options.onUserKeyAdopted] {Function}   persists a rotated key:
 *   called with `{ userKey, latestEpochId, descriptor }` after the roster
 *   read and BEFORE the fan-out
 * @param options.collections {CascadeCollections}   the fan-out's work
 * @returns {Promise<DurableClientForgetResult>}
 */
export async function forgetDurableClient({
  logStore,
  ladderSeed,
  forgottenClient,
  forgottenKeyAgreementKeyMultibase,
  knownLatentHashes,
  expectedDid,
  rosterStore,
  credentialKeyAgreementKey,
  userKey,
  pinnedEpochId,
  onUserKeyAdopted,
  collections
}: {
  logStore: UnlockLogStore
  ladderSeed: Uint8Array
  forgottenClient: RevokedClientKeys
  forgottenKeyAgreementKeyMultibase: string
  knownLatentHashes?: string[]
  expectedDid: string
  rosterStore: EncryptionDescriptorStore
  credentialKeyAgreementKey: IKeyAgreementKey
  userKey?: UserKey
  pinnedEpochId?: string | null
  onUserKeyAdopted?: (adopted: {
    userKey: UserKey
    latestEpochId: string
    descriptor: CollectionEncryption
  }) => Promise<void>
  collections: CascadeCollections
}): Promise<DurableClientForgetResult> {
  // The pre-edit read, doing double duty: the last-client refusal must fire
  // BEFORE the rotation (or a refused forget would already have retired this
  // client's wrap), and the rotation's recipient resolver needs the pre-edit
  // document (which still keys every other recipient).
  const published = await readPublishedLog({
    // readPublishedLog only calls getIdResourceRaw, so the narrow seam is
    // safe.
    idStore: logStore as WebvhIdStore,
    expectedDid
  })
  if (!published) {
    throw new Error('did:webvh: did.jsonl is missing; nothing to forget from.')
  }
  const signingVmId = `${published.did}#${forgottenClient.signingKeyMultibase}`
  const invocationIds = relationIds(published.doc.capabilityInvocation)
  if (
    invocationIds.includes(signingVmId) &&
    invocationIds.every(id => id === signingVmId)
  ) {
    throw new LastDurableClientForgetError()
  }

  // Stages 1 and 2: the roster rotation off this client's wrap and the
  // collection fan-out, both under this client's still-standing authority.
  let rotated = false
  let read: { userKey: UserKey; descriptor: CollectionEncryption } | undefined
  let cascade: UserKeyCascadeResult = { outcomes: {}, failed: [] }
  const current = await rosterStore.read()
  if (current !== null) {
    const forgottenKid = rosterRecipientKid({
      signingKeyMultibase: forgottenClient.signingKeyMultibase,
      keyAgreementKeyMultibase: forgottenKeyAgreementKeyMultibase
    })
    let descriptor = current.descriptor
    const currentEpoch = (descriptor.epochs ?? []).find(
      epoch => epoch.id === descriptor.currentEpoch
    )
    const wrapped = currentEpoch?.recipients.some(
      entry => entry.header.kid === forgottenKid
    )
    if (wrapped) {
      descriptor = await rotateUserKeyRoster({
        store: rosterStore,
        document: published.doc,
        retireRecipientId: forgottenKid
      })
      rotated = true
    }
    // The fresh key comes back through the credential's standing wrap -- this
    // client's own is gone from the current epoch -- with the continuity and
    // possession checks still running on the threaded descriptor.
    const adopted = await readUserKeyRoster({
      store: rosterStore,
      descriptor,
      ...(userKey ? { userKey } : {}),
      clientKeyAgreementKey: credentialKeyAgreementKey,
      pinnedEpochId
    })
    if (adopted.rotated) {
      await onUserKeyAdopted?.({
        userKey: adopted.userKey,
        latestEpochId: adopted.latestEpochId,
        descriptor: adopted.descriptor
      })
    }
    read = { userKey: adopted.userKey, descriptor: adopted.descriptor }
    cascade = await cascadeCollectionsToUserKey({
      collectionIds:
        typeof collections.collectionIds === 'function'
          ? await collections.collectionIds()
          : collections.collectionIds,
      storeFor: collections.storeFor,
      ...(collections.isEncrypted
        ? { isEncrypted: collections.isEncrypted }
        : {}),
      rosterDescriptor: adopted.descriptor,
      clientKeyAgreementKey: credentialKeyAgreementKey,
      userKey: adopted.userKey
    })
  }

  // Stage 3: the atomic ladder-signed removal entry, through the bridge.
  const removed = await forgetWebvhClient({
    store: logStore,
    ladderSeed,
    forgottenClient,
    ...(knownLatentHashes ? { knownLatentHashes } : {}),
    expectedDid
  })

  return {
    rotated,
    collections: cascade,
    did: removed.did,
    document: removed.doc,
    ...(read
      ? { userKey: read.userKey, rosterDescriptor: read.descriptor }
      : {})
  }
}
