/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The shared roster-and-cascade tail every account-membership ceremony ends
 * with: once a ceremony has published its own did:webvh document edit --
 * disconnecting an enrolled client, retiring a standing unlock credential --
 * what remains is the same two stages, and they are the same code.
 *
 * 1. **The user key rotation** in the wrap-set roster, recipients resolved
 *    from the document the edit itself just resolved to (no re-fetch of the
 *    log the ceremony just extended). On a log-governed roster store this
 *    function itself guarantees post-edit anchoring: the controller view built
 *    from the edit's own post-edit log is set as the store's minimum controller
 *    version (`setMinimumControllerVersion`) before anything roster-side
 *    runs, so the rotation and the seal backstop anchor at or past the edit
 *    even where the app's injected controller resolution still serves a
 *    cached pre-edit view. The
 *    roster delivers, never sources, so the stage names no recipient at all:
 *    it converges the roster onto that document (the login sweep's own path),
 *    retiring every current-epoch recipient the document no longer keys in one
 *    rotation. An account with no roster yet stops here: the document edit has
 *    landed, so the membership change IS in force, with nothing to rotate. On
 *    a sealable (log-governed) roster store, the seal backstop follows: a
 *    rotation that no-op'd appended nothing, so the roster log may still be
 *    anchored before the document edit -- `seal()` re-anchors it with an
 *    idempotent no-op entry, best-effort and reported rather than thrown.
 * 2. **The collection fan-out**: every encrypted collection is re-epoch'd onto
 *    the fresh key in parallel, so writes stop landing under epochs the
 *    removed party can still decrypt. Failures are collected per collection
 *    and never abort the fan-out.
 *
 * Convergence is the design: both stages detect their own completion from
 * durable state alone -- the roster no-ops once every current-epoch recipient
 * is document-backed, and a collection is stale exactly when its current
 * epoch names a non-current key generation -- so a mid-cascade crash strands
 * nothing permanently and a naive full re-run finishes it (the login-time
 * completion sweep is the standing backstop).
 *
 * The tail has two entry points over the same preamble and fan-out.
 * `rotateRosterToDocumentAndCascade` is the document-converging one above,
 * for a ceremony whose document edit has already landed.
 * `retireRosterRecipientAndCascade` is the recipient-naming one: for a
 * ceremony that must rotate BEFORE its own document edit -- the two forget
 * ceremonies, where the forgetting client can sign nothing after its removal
 * entry -- the document still lists the retiring recipient, so convergence
 * would retire nothing, and the caller names the roster kid to retire
 * instead. That entry point reads the fresh key back through a key the
 * caller names (the standing credential's, whose wrap survives the rotation)
 * and runs no seal backstop: with the document edit still ahead, there is no
 * removal to seal against, and on the last-client transition the rotation
 * itself is the one ladder-signed append its anchor licenses.
 */
import type { DIDDoc, DIDLog } from '@interop/did-method-webvh'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import { webvhResourceLogController } from '../resourceLog/index.js'
import {
  cascadeCollectionsToUserKey,
  type UserKeyCascadeResult
} from './userKeyCascade.js'
import { isSealableDescriptorStore } from './rosterLogStore.js'
import {
  convergeUserKeyRosterToDocument,
  readUserKeyRoster,
  rosterWrapsRecipient,
  rotateUserKeyRoster
} from './userKeyRoster.js'
import type { UserKey } from './userKey.js'

/**
 * What the roster's seal backstop reported: `sealed` (the roster log's head
 * still anchored before the document edit, and the backstop append landed),
 * `noop` (already sealed -- the rotation itself was the sealing append, or a
 * re-run found nothing to do), or `failed` (the seal could not run; carried
 * in `error`, never thrown -- the ceremony stays a resumable success and the
 * login sweep re-seals).
 */
export interface RosterSealReport {
  outcome: 'sealed' | 'noop' | 'failed'
  error?: unknown
}

/**
 * Where the cascade's collection fan-out gets its work: which encrypted
 * collections exist (only the app knows -- a mobile replica names the
 * collections it replicates, a web wallet also lists the app-provisioned ones
 * remotely) and how each one's descriptor store and encryption declaration are
 * reached.
 */
export interface CascadeCollections {
  collectionIds: string[] | (() => Promise<string[]>)
  storeFor: (collectionId: string) => EncryptionDescriptorStore
  isEncrypted?: (collectionId: string) => Promise<boolean>
}

/**
 * What the shared tail reports: whether the roster rotated on this run -- a
 * re-run of an already-complete ceremony reports `false`; the
 * document-converging entry point reads it off the adopting read, so a
 * caller holding no cached key sees `true` on its first read either way,
 * while the recipient-retiring one reports whether THIS call appended -- the roster's
 * seal-backstop report (present when the roster store is sealable and the
 * roster stage ran), the per-collection fan-out result, and the rotated key
 * with the roster descriptor it was read from.
 */
export interface RosterCascadeResult {
  rotated: boolean
  rosterSeal?: RosterSealReport
  collections: UserKeyCascadeResult
  userKey?: UserKey
  rosterDescriptor?: CollectionEncryption
}

/**
 * Resolves the collection ids the fan-out covers, whether they are a fixed set
 * or a listing the app performs.
 *
 * @param options {object}
 * @param options.collections {CascadeCollections}
 * @returns {Promise<string[]>}
 */
async function collectionIdsOf({
  collections
}: {
  collections: CascadeCollections
}): Promise<string[]> {
  const { collectionIds } = collections
  return typeof collectionIds === 'function'
    ? await collectionIds()
    : collectionIds
}

/**
 * The post-edit anchoring guarantee, shared by both entry points: the roster
 * appends -- and the seal backstop's removal detection -- must run under a
 * controller view that includes the log the ceremony is anchoring at, or the
 * rotation anchors before it (a revocation's rotation leaves the log
 * unsealed with the seal blind to the removal; the last-client transition's
 * ladder-signed rotation lands before its reinstall version and the
 * ceremony-tail license refuses it). Rather than leaving that to the
 * injected store's own controller wiring, the view built from the ceremony's
 * log is set as the store's minimum controller version; a fresher resolved
 * view still wins. A store that is not log-governed has no controller view
 * to anchor and is left alone. Exported for the one caller that reads the
 * roster before its anchoring entry exists (the last-client transition's
 * pre-pair probe, anchored at the pre-transition head it verified).
 *
 * @param options {object}
 * @param options.rosterStore {EncryptionDescriptorStore}
 * @param options.did {string}
 * @param options.log {DIDLog}
 */
export function anchorRosterStoreAt({
  rosterStore,
  did,
  log
}: {
  rosterStore: EncryptionDescriptorStore
  did: string
  log: DIDLog
}): void {
  if (isSealableDescriptorStore(rosterStore)) {
    rosterStore.setMinimumControllerVersion({
      controller: webvhResourceLogController({ did, log })
    })
  }
}

/**
 * The adopting read after a rotation: the roster read on the threaded
 * descriptor (the continuity and possession checks still run on it), then
 * the caller's `onUserKeyAdopted` when the key rotated on this run.
 *
 * @param options {object}
 * @param options.rosterStore {EncryptionDescriptorStore}
 * @param options.descriptor {CollectionEncryption}   the rotation's own
 *   verified result, so one run acquires the roster once for both halves
 * @param [options.userKey] {UserKey}
 * @param options.readBackKeyAgreementKey {IKeyAgreementKey}
 * @param [options.pinnedEpochId] {string}
 * @param [options.onUserKeyAdopted] {Function}
 * @returns {Promise<object>}
 */
async function adoptRotatedUserKey({
  rosterStore,
  descriptor,
  userKey,
  readBackKeyAgreementKey,
  pinnedEpochId,
  onUserKeyAdopted
}: {
  rosterStore: EncryptionDescriptorStore
  descriptor: CollectionEncryption
  userKey?: UserKey
  readBackKeyAgreementKey: IKeyAgreementKey
  pinnedEpochId?: string | null
  onUserKeyAdopted?: UserKeyAdoptedHook
}): Promise<{
  rotated: boolean
  userKey: UserKey
  descriptor: CollectionEncryption
}> {
  const read = await readUserKeyRoster({
    store: rosterStore,
    descriptor,
    ...(userKey ? { userKey } : {}),
    clientKeyAgreementKey: readBackKeyAgreementKey,
    pinnedEpochId
  })
  if (read.rotated) {
    await onUserKeyAdopted?.({
      userKey: read.userKey,
      latestEpochId: read.latestEpochId,
      descriptor: read.descriptor
    })
  }
  return {
    rotated: read.rotated,
    userKey: read.userKey,
    descriptor: read.descriptor
  }
}

/**
 * The collection fan-out, in parallel -- run even when the roster was found
 * already rotated (a re-run after a crash), because the staleness rule finds
 * exactly the stranded collections.
 *
 * @param options {object}
 * @param options.collections {CascadeCollections}
 * @param options.rosterDescriptor {CollectionEncryption}
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   the key that
 *   unwraps the roster's generations for the per-collection re-epoch
 * @param options.userKey {UserKey}
 * @returns {Promise<UserKeyCascadeResult>}
 */
async function fanOutToCollections({
  collections,
  rosterDescriptor,
  clientKeyAgreementKey,
  userKey
}: {
  collections: CascadeCollections
  rosterDescriptor: CollectionEncryption
  clientKeyAgreementKey: IKeyAgreementKey
  userKey: UserKey
}): Promise<UserKeyCascadeResult> {
  return cascadeCollectionsToUserKey({
    collectionIds: await collectionIdsOf({ collections }),
    storeFor: collections.storeFor,
    ...(collections.isEncrypted
      ? { isEncrypted: collections.isEncrypted }
      : {}),
    rosterDescriptor,
    clientKeyAgreementKey,
    userKey
  })
}

/**
 * Persists a rotated key: called with `{ userKey, latestEpochId, descriptor }`
 * after the roster read and BEFORE the fan-out. The key and the epoch pin
 * must persist atomically.
 */
export type UserKeyAdoptedHook = (adopted: {
  userKey: UserKey
  latestEpochId: string
  descriptor: CollectionEncryption
}) => Promise<void>

/**
 * Runs the roster rotation (with its seal backstop) and the collection
 * fan-out over the document a ceremony's own edit just published. See the
 * module doc for the order and the convergence story.
 *
 * @param options {object}
 * @param options.rosterStore {EncryptionDescriptorStore}   the
 *   `key-map/user-key.jsonl` roster store
 * @param options.did {string}   the account's did:webvh
 * @param options.doc {DIDDoc}   the document as the ceremony's edit left it
 * @param options.log {DIDLog}   the post-edit log, which the minimum
 *   controller version is built from
 * @param [options.userKey] {UserKey}   this client's cached user key
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key -- its roster entry
 * @param [options.pinnedEpochId] {string}   the locally pinned latest-seen
 *   roster epoch
 * @param [options.onUserKeyAdopted] {UserKeyAdoptedHook}   persists a
 *   rotated key
 * @param options.collections {CascadeCollections}   the fan-out's work
 * @returns {Promise<RosterCascadeResult>}
 */
export async function rotateRosterToDocumentAndCascade({
  rosterStore,
  did,
  doc,
  log,
  userKey,
  clientKeyAgreementKey,
  pinnedEpochId,
  onUserKeyAdopted,
  collections
}: {
  rosterStore: EncryptionDescriptorStore
  did: string
  doc: DIDDoc
  log: DIDLog
  userKey?: UserKey
  clientKeyAgreementKey: IKeyAgreementKey
  pinnedEpochId?: string | null
  onUserKeyAdopted?: UserKeyAdoptedHook
  collections: CascadeCollections
}): Promise<RosterCascadeResult> {
  anchorRosterStoreAt({ rosterStore, did, log })

  // The roster rotation, recipients resolved from that same document.
  // Whether there IS a roster is settled BY the convergence call itself: a
  // `null` descriptor back means the account has no `key-map/user-key.jsonl`
  // yet (its collections are not encrypted yet), so there is nothing to
  // rotate. The document edit has already landed, so the membership change IS
  // in force -- a completed ceremony with nothing rotated, not a failure.
  // Pairing-free: rather than naming the removed party's kid, the rotation
  // retires every current-epoch recipient the post-edit document no longer
  // keys -- which is exactly that party's entry, plus anything an earlier torn
  // run left behind, in one rotation.
  const converged = await convergeUserKeyRosterToDocument({
    store: rosterStore,
    document: doc,
    ownerKeyAgreementKey: clientKeyAgreementKey
  })
  if (converged.descriptor === null) {
    return { rotated: false, collections: { outcomes: {}, failed: [] } }
  }
  const read = await adoptRotatedUserKey({
    rosterStore,
    descriptor: converged.descriptor,
    userKey,
    readBackKeyAgreementKey: clientKeyAgreementKey,
    pinnedEpochId,
    onUserKeyAdopted
  })

  // The seal backstop: an ordinary rotation is the sealing append by
  // construction, but a rotation that no-op'd (the removed party held no
  // current-epoch wrap -- an orphan entry, or any re-run) appended nothing,
  // leaving the roster log's head anchored before the document edit. Sealing
  // is best-effort and reported, never thrown: the document edit landed, and
  // an unsealed log is durable state the login sweep re-detects and finishes.
  let rosterSeal: RosterSealReport | undefined
  if (isSealableDescriptorStore(rosterStore)) {
    try {
      rosterSeal = { outcome: await rosterStore.seal() }
    } catch (err) {
      rosterSeal = { outcome: 'failed', error: err }
    }
  }

  const cascade = await fanOutToCollections({
    collections,
    rosterDescriptor: read.descriptor,
    clientKeyAgreementKey,
    userKey: read.userKey
  })

  return {
    rotated: read.rotated,
    ...(rosterSeal ? { rosterSeal } : {}),
    collections: cascade,
    userKey: read.userKey,
    rosterDescriptor: read.descriptor
  }
}

/**
 * The recipient-naming entry point: retires ONE named roster recipient and
 * runs the collection fan-out, for a ceremony that rotates BEFORE its own
 * document edit (see the module doc). The document handed in still keys the
 * retiring recipient, so the rotation names its kid explicitly; the fresh key
 * is read back through `readBackKeyAgreementKey`, a recipient whose wrap
 * survives the rotation (the standing credential's, on both forgets). No
 * seal backstop runs here.
 *
 * Every stage detects its own completion from durable state: a recipient the
 * current epoch no longer wraps to skips the append (so a re-run of a
 * torn-after-rotation ceremony attempts no second append at the same anchor,
 * which on a ladder-signed roster the one-shot license would refuse), the
 * read-back adopts whatever the roster now delivers, and the fan-out is
 * staleness-driven. An account with no roster yet reports `rotated: false`
 * with an empty fan-out and no key.
 *
 * @param options {object}
 * @param options.rosterStore {EncryptionDescriptorStore}   the
 *   `key-map/user-key.jsonl` roster store
 * @param options.did {string}   the account's did:webvh
 * @param options.doc {DIDDoc}   the document the rotation's recipients are
 *   resolved from -- the one `log` resolves to
 * @param options.log {DIDLog}   the log the rotation anchors at, which the
 *   minimum controller version is built from: the pre-edit head for a plain
 *   forget, the post-reinstall head for the last-client transition
 * @param options.retireRecipientId {string}   the roster kid to retire
 * @param [options.userKey] {UserKey}   this client's cached user key
 * @param options.readBackKeyAgreementKey {IKeyAgreementKey}   the recipient
 *   whose wrap survives the rotation, reading the fresh key back and
 *   unwrapping the generations for the fan-out
 * @param [options.pinnedEpochId] {string}   the locally pinned latest-seen
 *   roster epoch
 * @param [options.onUserKeyAdopted] {UserKeyAdoptedHook}   persists a
 *   rotated key
 * @param options.collections {CascadeCollections}   the fan-out's work
 * @returns {Promise<RosterCascadeResult>}   `rotated` says whether THIS run
 *   retired the recipient's wrap; `rosterSeal` is never present
 * @throws {UserKeyRosterIntegrityError}   the roster's `currentEpoch` names
 *   no epoch in its own list
 */
export async function retireRosterRecipientAndCascade({
  rosterStore,
  did,
  doc,
  log,
  retireRecipientId,
  userKey,
  readBackKeyAgreementKey,
  pinnedEpochId,
  onUserKeyAdopted,
  collections
}: {
  rosterStore: EncryptionDescriptorStore
  did: string
  doc: DIDDoc
  log: DIDLog
  retireRecipientId: string
  userKey?: UserKey
  readBackKeyAgreementKey: IKeyAgreementKey
  pinnedEpochId?: string | null
  onUserKeyAdopted?: UserKeyAdoptedHook
  collections: CascadeCollections
}): Promise<RosterCascadeResult> {
  anchorRosterStoreAt({ rosterStore, did, log })

  const current = await rosterStore.read()
  if (current === null) {
    return { rotated: false, collections: { outcomes: {}, failed: [] } }
  }
  let descriptor = current.descriptor
  let rotated = false
  if (rosterWrapsRecipient({ descriptor, recipientId: retireRecipientId })) {
    descriptor = await rotateUserKeyRoster({
      store: rosterStore,
      document: doc,
      retireRecipientId
    })
    rotated = true
  }
  // The fresh key comes back through the surviving recipient's wrap -- the
  // retired one is gone from the current epoch.
  const read = await adoptRotatedUserKey({
    rosterStore,
    descriptor,
    userKey,
    readBackKeyAgreementKey,
    pinnedEpochId,
    onUserKeyAdopted
  })
  const cascade = await fanOutToCollections({
    collections,
    rosterDescriptor: read.descriptor,
    clientKeyAgreementKey: readBackKeyAgreementKey,
    userKey: read.userKey
  })
  return {
    rotated,
    collections: cascade,
    userKey: read.userKey,
    rosterDescriptor: read.descriptor
  }
}
