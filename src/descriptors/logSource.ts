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
import {
  WAS_RESOURCE_LOG_METHOD,
  type ResourceLogStore
} from '@interop/was-client/log'
import {
  readResourceLog,
  ResourceLogIntegrityError,
  type ResourceLogController,
  type ResourceLogPinStore
} from '../resourceLog/index.js'
import type { EncryptionDescriptorSource } from './acquire.js'

/**
 * The state-document schema identifier an encryption descriptor carries in a
 * governed log entry, per WAS-EC.
 */
export const EPOCH_CONFIGURATION_STATE_TYPE = 'WasEpochConfiguration'

/**
 * Builds the {@link EncryptionDescriptorSource} over per-collection resource
 * logs. An absent log resolves `undefined` exactly like an absent
 * Collection Description `encryption` member (a plaintext collection, or one
 * whose provisioning has not landed); verification failures throw through --
 * {@link acquireDescriptor} rethrows the refusal classes rather than falling
 * back to the cache.
 *
 * @param options {object}
 * @param options.logFor {function}   `(collectionId) => ResourceLogStore` --
 *   the collection's governing log's transport seam
 * @param options.resolveController {function}
 *   `() => Promise<ResourceLogController>` -- the caller's currently verified
 *   controller view, resolved per operation
 * @param options.pinStoreFor {function}   `(collectionId) =>
 *   ResourceLogPinStore` -- this client's chain-head pin for the collection's
 *   log
 * @returns {EncryptionDescriptorSource}
 */
export function logGovernedDescriptorSource({
  logFor,
  resolveController,
  pinStoreFor
}: {
  logFor: (collectionId: string) => ResourceLogStore
  resolveController: () => Promise<ResourceLogController>
  pinStoreFor: (collectionId: string) => ResourceLogPinStore
}): EncryptionDescriptorSource {
  return {
    async collectionEncryption({ collectionId }) {
      const controller = await resolveController()
      const current = await readResourceLog({
        store: logFor(collectionId),
        controller,
        expectedMethod: WAS_RESOURCE_LOG_METHOD,
        pinStore: pinStoreFor(collectionId)
      })
      if (current === null) {
        return undefined
      }
      const state = current.verified.state
      if (state.type !== EPOCH_CONFIGURATION_STATE_TYPE) {
        throw new ResourceLogIntegrityError(
          `The governed descriptor log carries state of type ` +
            `"${state.type}", not "${EPOCH_CONFIGURATION_STATE_TYPE}".`
        )
      }
      return state as CollectionEncryption
    }
  }
}
