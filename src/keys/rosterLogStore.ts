/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The log-governed descriptor store: an `EncryptionDescriptorStore` whose
 * resource is governed by a resource log (the Resource Log Profile). Reads
 * resolve to the VERIFIED head entry's state -- chain, proofs, external
 * authorization, and the chain-head pin all checked before any descriptor is
 * handed out -- and writes become signed log appends. Because the seam is
 * unchanged, all of
 * was-client's roster machinery (`initRecipients` / `addRecipient` /
 * `removeRecipient`, with their compare-and-swap retry loops) drives the log
 * without knowing it: a CAS conflict on the log surfaces as the
 * `PreconditionFailedError` those loops already rebase on.
 *
 * This is the enforcement point for "roster state is adopted only from a
 * verified log head": there is no read path around the verifier, and the
 * retired detached `epochsSig` has no successor to check -- the entry proof
 * anchored in the did:webvh document took over its job wholesale.
 *
 * The store is {@link SealableEncryptionDescriptorStore}: `seal()` exposes
 * the resource-log sealing sweep through the descriptor-store seam, so the
 * ceremonies and the login sweep can close the one durable gap the recipient
 * machinery leaves -- a rotation that no-ops (the retiree held no
 * current-epoch wrap) appends nothing, leaving the log's head anchored
 * before the membership change it should have sealed.
 */
import type { CollectionEncryption } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import {
  confirmAppend,
  RESOURCE_LOG_METHOD,
  type ResourceLogStore
} from '@interop/was-client/log'
import {
  buildResourceLogEntry,
  buildResourceLogGenesis,
  readResourceLog,
  ResourceLogClosedError,
  ResourceLogIntegrityError,
  sealResourceLog,
  verifyResourceLog,
  type ResourceLogController,
  type ResourceLogPinStore,
  type ResourceLogSigner,
  type VerifiedResourceLog
} from '../resourceLog/index.js'
import { EPOCH_CONFIGURATION_STATE_TYPE } from '../descriptors/logSource.js'

export { EPOCH_CONFIGURATION_STATE_TYPE }

/**
 * An `EncryptionDescriptorStore` whose resource is governed by a resource
 * log, and can therefore be SEALED: `seal()` runs the sealing sweep
 * (`sealResourceLog`) against the caller's currently verified controller
 * view, appending the idempotent no-op backstop entry when the log's head
 * still anchors before the controller's latest membership change --
 * `'sealed'` -- and writing nothing when the log is already sealed, absent,
 * or has no membership change to seal against -- `'noop'`.
 */
export interface SealableEncryptionDescriptorStore extends EncryptionDescriptorStore {
  seal(): Promise<'sealed' | 'noop'>
}

/**
 * Whether a descriptor store is log-governed and sealable -- the guard the
 * ceremonies and sweeps use to run the seal backstop only where a governing
 * log exists (an ordinary Collection-Description-backed store has nothing to
 * seal).
 *
 * @param store {EncryptionDescriptorStore}
 * @returns {boolean}
 */
export function isSealableDescriptorStore(
  store: EncryptionDescriptorStore
): store is SealableEncryptionDescriptorStore {
  return (
    typeof (store as Partial<SealableEncryptionDescriptorStore>).seal ===
    'function'
  )
}

/**
 * Builds the log-governed `EncryptionDescriptorStore`.
 *
 * The controller view is resolved per operation (never held), so a caller
 * that just edited the account document -- a revocation about to rotate the
 * roster -- writes entries anchored at the post-edit head it now verifies,
 * which is exactly what makes its rotation the sealing append.
 *
 * @param options {object}
 * @param options.log {ResourceLogStore}   the log's transport seam
 * @param options.resolveController {function}   `() => Promise<ResourceLogController>`
 *   -- the caller's currently verified controller view
 *   (`webvhResourceLogController` over a `verifyAccountLog` result)
 * @param options.pinStore {ResourceLogPinStore}   this client's chain-head pin
 *   for this log
 * @param options.signer {ResourceLogSigner}   this client's enrolled signing
 *   key, for the appends this store writes
 * @returns {SealableEncryptionDescriptorStore}
 */
export function logGovernedDescriptorStore({
  log,
  resolveController,
  pinStore,
  signer
}: {
  log: ResourceLogStore
  resolveController: () => Promise<ResourceLogController>
  pinStore: ResourceLogPinStore
  signer: ResourceLogSigner
}): SealableEncryptionDescriptorStore {
  // The verified log observed by the most recent read on this store instance;
  // a replace builds its entry on that head, pinned to the same read's etag,
  // so a stale head loses the CAS instead of forking.
  let lastVerified: VerifiedResourceLog | null = null

  function toState(
    descriptor: CollectionEncryption
  ): CollectionEncryption & { type: string } {
    const { history: _history, ...rest } = descriptor
    return { ...rest, type: EPOCH_CONFIGURATION_STATE_TYPE }
  }

  async function settle({
    entry,
    controller
  }: {
    entry: Parameters<typeof confirmAppend>[0]['entry']
    controller: ResourceLogController
  }): Promise<void> {
    const readBack = await confirmAppend({ store: log, entry })
    const confirmed = await verifyResourceLog({
      entries: readBack.entries,
      controller,
      expectedMethod: RESOURCE_LOG_METHOD,
      pin: await pinStore.read()
    })
    await pinStore.write(confirmed.pin)
    lastVerified = confirmed
  }

  return {
    async read() {
      const controller = await resolveController()
      const current = await readResourceLog({
        store: log,
        controller,
        expectedMethod: RESOURCE_LOG_METHOD,
        pinStore
      })
      if (current === null) {
        lastVerified = null
        return null
      }
      const state = current.verified.state
      if (state.type !== EPOCH_CONFIGURATION_STATE_TYPE) {
        throw new ResourceLogIntegrityError(
          `The governed descriptor log carries state of type ` +
            `"${state.type}", not "${EPOCH_CONFIGURATION_STATE_TYPE}".`
        )
      }
      lastVerified = current.verified
      return {
        descriptor: state as CollectionEncryption,
        etag: current.etag
      }
    },

    async replace(descriptor, { ifMatch }) {
      if (lastVerified === null) {
        throw new Error(
          'Cannot replace the governed descriptor: replace must follow a ' +
            'read on the same store instance.'
        )
      }
      if (ifMatch === undefined) {
        throw new Error(
          'Cannot replace the governed descriptor: the backend returned no ' +
            'validator, and the profile forbids an unconditional write.'
        )
      }
      if (lastVerified.terminal) {
        throw new ResourceLogClosedError({ nextLog: lastVerified.terminal })
      }
      const controller = await resolveController()
      const entry = await buildResourceLogEntry({
        head: lastVerified.head,
        state: toState(descriptor),
        controller,
        signer
      })
      // A stale validator throws PreconditionFailedError here, which the edv
      // machinery's CAS loop re-reads and rebases on.
      await log.append(entry, { ifMatch })
      await settle({ entry, controller })
    },

    async create(descriptor) {
      const controller = await resolveController()
      const genesis = await buildResourceLogGenesis({
        state: toState(descriptor),
        method: RESOURCE_LOG_METHOD,
        controller,
        signer
      })
      // A lost guarded-create race throws PreconditionFailedError, and the
      // edv machinery re-reads and adopts the winner's descriptor.
      await log.create(genesis)
      await settle({ entry: genesis, controller })
    },

    async seal() {
      const controller = await resolveController()
      const { sealed, verified } = await sealResourceLog({
        store: log,
        controller,
        expectedMethod: RESOURCE_LOG_METHOD,
        pinStore,
        signer
      })
      if (verified !== null) {
        lastVerified = verified
      }
      return sealed ? 'sealed' : 'noop'
    }
  }
}
