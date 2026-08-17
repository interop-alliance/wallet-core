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
 *    from the edit's own post-edit log is set as the store's freshness floor
 *    (`setControllerFloor`) before anything roster-side runs, so the rotation
 *    and the seal backstop anchor at or past the edit even where the app's
 *    injected controller resolution still serves a cached pre-edit view. The
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
  readUserKeyRoster
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
 * What the shared tail reports: whether the roster actually rotated on this
 * run (a re-run of an already-complete ceremony reports `false`), the roster's
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
 * Runs the roster rotation (with its seal backstop) and the collection
 * fan-out over the document a ceremony's own edit just published. See the
 * module doc for the order and the convergence story.
 *
 * @param options {object}
 * @param options.rosterStore {EncryptionDescriptorStore}   the
 *   `key-map/user-key.jsonl` roster store
 * @param options.did {string}   the account's did:webvh
 * @param options.doc {DIDDoc}   the document as the ceremony's edit left it
 * @param options.log {DIDLog}   the post-edit log, which the controller floor
 *   is built from
 * @param [options.userKey] {UserKey}   this client's cached user key
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key -- its roster entry
 * @param [options.pinnedEpochId] {string}   the locally pinned latest-seen
 *   roster epoch
 * @param [options.onUserKeyAdopted] {Function}   persists a rotated key:
 *   called with `{ userKey, latestEpochId, descriptor }` after the roster read
 *   and BEFORE the fan-out. The key and the epoch pin must persist atomically
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
  onUserKeyAdopted?: (adopted: {
    userKey: UserKey
    latestEpochId: string
    descriptor: CollectionEncryption
  }) => Promise<void>
  collections: CascadeCollections
}): Promise<RosterCascadeResult> {
  // The post-edit anchoring guarantee: the roster appends -- and the seal
  // backstop's removal detection -- must run under a controller view that
  // includes the edit the ceremony just published, or the rotation anchors
  // pre-edit and the log stays unsealed with the seal blind to the removal.
  // Rather than leaving that to the injected store's own controller wiring,
  // the view built from the edit's post-edit log is set as the store's floor;
  // a fresher resolved view still wins.
  if (isSealableDescriptorStore(rosterStore)) {
    rosterStore.setControllerFloor({
      controller: webvhResourceLogController({ did, log })
    })
  }

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
    document: doc
  })
  if (converged.descriptor === null) {
    return { rotated: false, collections: { outcomes: {}, failed: [] } }
  }
  // The rotation's own verified result is threaded into the adopting read, so
  // one run acquires the roster once for both halves of the stage (the
  // continuity and possession checks still run on the threaded descriptor).
  const read = await readUserKeyRoster({
    store: rosterStore,
    descriptor: converged.descriptor,
    ...(userKey ? { userKey } : {}),
    clientKeyAgreementKey,
    pinnedEpochId
  })
  if (read.rotated) {
    await onUserKeyAdopted?.({
      userKey: read.userKey,
      latestEpochId: read.latestEpochId,
      descriptor: read.descriptor
    })
  }

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

  // The collection fan-out, in parallel -- run even when this call found the
  // roster already rotated (a re-run after a crash), because the staleness
  // rule finds exactly the stranded collections.
  const cascade = await cascadeCollectionsToUserKey({
    collectionIds: await collectionIdsOf({ collections }),
    storeFor: collections.storeFor,
    ...(collections.isEncrypted
      ? { isEncrypted: collections.isEncrypted }
      : {}),
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
