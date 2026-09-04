/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The forget ceremony: a remembered browser's enrolled client removes ITSELF
 * from the account, through the standing unlock credential's bridge, before
 * the app wipes its local state. Self-enrollment in reverse, run with what a
 * live remembered session already holds -- the credential's ladder seed and its
 * delegated `did.jsonl` bridge -- and refused for the account's last enrolled
 * client ({@link LastEnrolledClientForgetError}), whose forget is the
 * ladder-anchored transition, a separate ceremony.
 *
 * The stage order INVERTS the revocation cascade's document-edit-first rule,
 * and the inversion is forced twice over: once the removal entry lands, the
 * forgetting client's key is out of `assertionMethod` at the post-edit head,
 * so it can sign no roster append (the entry-proof rule), and its WAS
 * invocations stop verifying (the current-key-set rule), so the collection
 * fan-out cannot run either -- while a ladder-signed append is licensed only
 * at a inventory-changing document version, which a not-last-client removal is
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
 *    inventory out. The app's local wipe runs after this ceremony returns, so
 *    a tear anywhere before the entry reads as "not forgotten" and a re-click
 *    resumes. The post-removal `did:web` projection is PUT through
 *    `clientLogStore` immediately BEFORE that entry: the entry itself
 *    publishes `did.jsonl` alone (the bridge covers nothing else), and this
 *    client's authority ends at it, so the projection has to be written while
 *    it can still be written. That store is required for exactly this reason
 *    -- without it `did.json` would keep naming this client until a later
 *    writer ran `ensureDidWebProjection`, and a `did:web` verifier would
 *    accept the forgotten key meanwhile (WAS authorization would not: the
 *    server resolves the controller from `did.jsonl`).
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
 * client had signed is left to the standing self-heals (a remembered login's
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
import { relationIds } from '../resourceLog/document.js'
import { readPublishedLogOrThrow } from '../webvh/didWebvh.js'
import type { WebvhIdStore } from '../webvh/didWebvh.js'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import type { RevokedClientKeys } from '../webvh/revokeClient.js'
import {
  retireRosterRecipientAndCascade,
  rosterRecipientKid,
  type CascadeCollections,
  type UserKey,
  type UserKeyAdoptedHook,
  type UserKeyCascadeResult
} from '../keys/index.js'
import {
  forgetWebvhClient,
  LastEnrolledClientForgetError
} from './ladderAnchored.js'
import type { UnlockLogStore } from '../unlock/standingWebvh.js'

/**
 * What a completed forget reports: whether the roster's wrap for the
 * forgotten client was actually retired on this run (a re-run of a
 * torn-after-rotation ceremony reports `false`), the per-collection fan-out
 * result, the document as the removal entry left it, and -- when the account
 * has a roster -- the rotated key with the roster descriptor it was read
 * from.
 */
export interface EnrolledClientForgetResult {
  rotated: boolean
  collections: UserKeyCascadeResult
  did: string
  document: object
  userKey?: UserKey
  rosterDescriptor?: CollectionEncryption
}

/**
 * Forgets one enrolled client -- this browser's own -- from its
 * account. See the module doc for the stage order (rotation and fan-out
 * BEFORE the removal entry, the self-forget inversion) and the torn-state
 * map. The caller runs the local wipe only after this resolves.
 *
 * @param options {object}
 * @param options.logStore {UnlockLogStore}   the credential's delegated
 *   `did.jsonl` bridge store; also serves the ceremony's public pre-edit
 *   read
 * @param options.clientLogStore {object}   the account's `id` collection
 *   store invoked under THIS (still-standing) enrolled client's root
 *   authority. Used for one thing: the post-removal `did:web` projection PUT
 *   that precedes the removal entry (see stage 3 in the module doc)
 * @param [options.pinStore] {ResourceLogPinStore}   this client's chain-head
 *   pins. Every read the ceremony makes -- the pre-edit read the roster
 *   rotation's recipient document comes from, and the removal entry's own
 *   read inside its conflict-retry loop -- is checked against the pinned
 *   head, so a served truncated prefix is refused (`ResourceLogContinuityError`,
 *   `rollback`) before any roster append or log publish, and the pin
 *   advances to the head the removal entry publishes. Without it the
 *   ceremony checks `expectedDid` only
 * @param [options.logId] {string}   the account log's pin slot
 *   (`accountLogPinId({ spaceId })`); required whenever a `pinStore` is
 *   supplied
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
 * @returns {Promise<EnrolledClientForgetResult>}
 */
export async function forgetEnrolledClient({
  logStore,
  clientLogStore,
  pinStore,
  logId,
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
  clientLogStore: Pick<WebvhIdStore, 'getIdResourceRaw' | 'putIdResource'>
  pinStore?: ResourceLogPinStore
  logId?: string
  ladderSeed: Uint8Array
  forgottenClient: RevokedClientKeys
  forgottenKeyAgreementKeyMultibase: string
  knownLatentHashes?: string[]
  expectedDid: string
  rosterStore: EncryptionDescriptorStore
  credentialKeyAgreementKey: IKeyAgreementKey
  userKey?: UserKey
  pinnedEpochId?: string | null
  onUserKeyAdopted?: UserKeyAdoptedHook
  collections: CascadeCollections
}): Promise<EnrolledClientForgetResult> {
  // The pre-edit read, doing double duty: the last-client refusal must fire
  // BEFORE the rotation (or a refused forget would already have retired this
  // client's wrap), and the rotation's recipient resolver needs the pre-edit
  // document (which still keys every other recipient).
  const published = await readPublishedLogOrThrow({
    idStore: logStore,
    expectedDid,
    ...(pinStore ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {}),
    missingMessage: 'did:webvh: did.jsonl is missing; nothing to forget from.'
  })
  const signingVmId = `${published.did}#${forgottenClient.signingKeyMultibase}`
  const invocationIds = relationIds(published.doc.capabilityInvocation)
  if (
    invocationIds.includes(signingVmId) &&
    invocationIds.every(id => id === signingVmId)
  ) {
    throw new LastEnrolledClientForgetError()
  }

  // Stages 1 and 2: the roster rotation off this client's wrap and the
  // collection fan-out, both under this client's still-standing authority
  // -- the shared recipient-retiring tail, anchored at the pre-edit head
  // this read verified (the orchestrator sets the roster store's minimum
  // controller version there, so a store wired over a stale cached view
  // still appends under a view that carries every recipient the rotation
  // resolves). The wrap is retired by its roster kid explicitly, since the
  // document still lists this client, and the fresh key comes back through
  // the credential's standing wrap.
  const tail = await retireRosterRecipientAndCascade({
    rosterStore,
    did: published.did,
    doc: published.doc,
    log: published.log,
    retireRecipientId: rosterRecipientKid({
      signingKeyMultibase: forgottenClient.signingKeyMultibase,
      keyAgreementKeyMultibase: forgottenKeyAgreementKeyMultibase
    }),
    ...(userKey ? { userKey } : {}),
    readBackKeyAgreementKey: credentialKeyAgreementKey,
    pinnedEpochId,
    ...(onUserKeyAdopted ? { onUserKeyAdopted } : {}),
    collections
  })

  // Stage 3: the atomic ladder-signed removal entry, through the bridge.
  const removed = await forgetWebvhClient({
    store: logStore,
    projectionStore: clientLogStore,
    ladderSeed,
    forgottenClient,
    ...(knownLatentHashes ? { knownLatentHashes } : {}),
    expectedDid,
    ...(pinStore ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {})
  })

  return {
    rotated: tail.rotated,
    collections: tail.collections,
    did: removed.did,
    document: removed.doc,
    ...(tail.userKey && tail.rosterDescriptor
      ? { userKey: tail.userKey, rosterDescriptor: tail.rosterDescriptor }
      : {})
  }
}
