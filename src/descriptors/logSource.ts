/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The log-governed {@link EncryptionDescriptorSource}: descriptor acquisition
 * for a collection whose encryption descriptor is governed by a resource log
 * (the Resource Log Profile) rather than by its Collection Description. Every
 * read -- including the unknown-epoch refresh's re-read -- resolves to the
 * log's VERIFIED head state: chain, proofs, external authorization against
 * the independently verified controller document, and the chain-head pin all
 * checked before any descriptor is handed out, so a refresh re-verifies the
 * log rather than adopting whatever the host serves. A verified head whose
 * state is not an epoch configuration is refused fail-closed rather than
 * handed out as a descriptor.
 */
import type { CollectionEncryption } from '@interop/was-client'
import { RESOURCE_LOG_METHOD } from '@interop/storage-core'
import {
  readResourceLog,
  ResourceLogIntegrityError,
  type ResourceLogController,
  type ResourceLogPinStore,
  type ResourceLogStore,
  type VerifiedResourceLog
} from '@interop/vh-resource-log'
import type { EncryptionDescriptorSource } from './acquire.js'

/**
 * The state-document schema identifier an encryption descriptor carries in a
 * governed log entry, per WAS-EC.
 */
export const EPOCH_CONFIGURATION_STATE_TYPE = 'WasEpochConfiguration'

/**
 * The one governed epoch-configuration read: the fail-closed boundary that
 * decides whether a served log state may be treated as an encryption
 * descriptor. Resolves the controller view, reads and fully verifies the log
 * (chain, proofs, external authorization, and the chain-head pin, via
 * `readResourceLog`), and refuses a verified head whose state is not a
 * `WasEpochConfiguration` rather than handing it out as a descriptor.
 * Resolves `null` for an absent log (the pre-genesis state) only while no pin
 * is held for it; under a held pin an absent log is refused as a `rollback`,
 * the library's rule. Both governed
 * descriptor consumers -- the log-governed descriptor source below and the
 * roster's log-governed descriptor store -- read through this helper, so a
 * hardening applied here reaches every trusted descriptor read.
 *
 * @param options {object}
 * @param options.store {ResourceLogStore}   the log's transport seam
 * @param options.resolveController {function}
 *   `() => Promise<ResourceLogController>` -- the caller's currently verified
 *   controller view, resolved per operation
 * @param options.pinStore {ResourceLogPinStore}   this client's chain-head
 *   pin for this log
 * @param options.logId {string}   the pin-slot key for this log, from
 *   `resourceLogPinId`
 * @returns {Promise<{ verified: VerifiedResourceLog; descriptor: CollectionEncryption; etag?: string } | null>}
 */
export async function readGovernedEpochConfiguration({
  store,
  resolveController,
  pinStore,
  logId
}: {
  store: ResourceLogStore
  resolveController: () => Promise<ResourceLogController>
  pinStore: ResourceLogPinStore
  logId: string
}): Promise<{
  verified: VerifiedResourceLog
  descriptor: CollectionEncryption
  etag?: string
} | null> {
  const controller = await resolveController()
  const current = await readResourceLog({
    store,
    controller,
    expectedMethod: RESOURCE_LOG_METHOD,
    pinStore,
    logId
  })
  if (current === null) {
    return null
  }
  const state = current.verified.state
  if (state.type !== EPOCH_CONFIGURATION_STATE_TYPE) {
    throw new ResourceLogIntegrityError(
      `The governed descriptor log carries state of type ` +
        `"${state.type}", not "${EPOCH_CONFIGURATION_STATE_TYPE}".`
    )
  }
  return {
    verified: current.verified,
    descriptor: state as CollectionEncryption,
    etag: current.etag
  }
}

/**
 * Builds the {@link EncryptionDescriptorSource} over per-collection resource
 * logs. An absent log resolves `undefined` exactly like an absent
 * Collection Description `encryption` member (a plaintext collection, or one
 * whose provisioning has not landed), unless a pin is held for it, in which
 * case the read refuses as a `rollback`; verification failures throw through --
 * {@link acquireDescriptor} rethrows the refusal classes rather than falling
 * back to the cache.
 *
 * @param options {object}
 * @param options.logFor {function}   `(collectionId) => ResourceLogStore` --
 *   the collection's governing log's transport seam
 * @param options.resolveController {function}
 *   `() => Promise<ResourceLogController>` -- the caller's currently verified
 *   controller view, resolved per operation
 * @param options.pinStore {ResourceLogPinStore}   this client's chain-head
 *   pins, keyed per log
 * @param options.logIdFor {function}   `(collectionId) => string` -- the
 *   collection's descriptor log's pin-slot key, typically built with
 *   `resourceLogPinId`
 * @returns {EncryptionDescriptorSource}
 */
export function logGovernedDescriptorSource({
  logFor,
  resolveController,
  pinStore,
  logIdFor
}: {
  logFor: (collectionId: string) => ResourceLogStore
  resolveController: () => Promise<ResourceLogController>
  pinStore: ResourceLogPinStore
  logIdFor: (collectionId: string) => string
}): EncryptionDescriptorSource {
  return {
    async collectionEncryption({ collectionId }) {
      const current = await readGovernedEpochConfiguration({
        store: logFor(collectionId),
        resolveController,
        pinStore,
        logId: logIdFor(collectionId)
      })
      if (current === null) {
        return undefined
      }
      return current.descriptor
    }
  }
}
