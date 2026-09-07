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
import {
  EPOCH_CONFIGURATION_STATE_TYPE,
  readGovernedEpochConfiguration
} from '@interop/was-client/edv'
import {
  resourceLogPinId,
  type ResourceLogController,
  type ResourceLogPinStore,
  type ResourceLogStore
} from '@interop/vh-resource-log'
import { KEY_MAP_COLLECTION } from '../space/collections.js'
import type { EncryptionDescriptorSource } from './acquire.js'

/**
 * The governed read boundary and the state-document schema identifier live in
 * `@interop/was-client/edv` (the pointer-following collection store reads
 * through the same helper); re-exported here so the roster store and this
 * module's consumers keep one import site.
 */
export { EPOCH_CONFIGURATION_STATE_TYPE, readGovernedEpochConfiguration }

/**
 * The pin-slot key for a collection's governing descriptor log: the slot a
 * keyed `ResourceLogPinStore` holds that log's chain-head pin under,
 * `space/<spaceId>/key-map/<collectionId>.jsonl`. The library names it, as it
 * names the account log's (`accountLogPinId`) and the roster's
 * (`userKeyRosterPinId`) slots, so no app builds one of its own: the shape is
 * host-free on purpose -- the Space id is what stays stable across a claimed
 * host move, so a log served from a new host still lands in the same slot and
 * is checked against the held pin rather than opening a fresh
 * trust-on-first-use slate. The resource half mirrors the roster log's home
 * (`key-map/user-key.jsonl`): a governing log lives in the plaintext,
 * capability-gated key-map collection, beside the roster, since a log stored
 * inside the encrypted collection it governs would itself be sealed.
 *
 * @param options {object}
 * @param options.spaceId {string}   the data Space id
 * @param options.collectionId {string}   the governed collection
 * @returns {string}
 */
export function collectionDescriptorLogPinId({
  spaceId,
  collectionId
}: {
  spaceId: string
  collectionId: string
}): string {
  return resourceLogPinId({
    spaceId,
    collectionId: KEY_MAP_COLLECTION.id,
    resourceId: `${collectionId}.jsonl`
  })
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
 *   pins, keyed per log; each collection's slot is
 *   {@link collectionDescriptorLogPinId} over `spaceId`
 * @param options.spaceId {string}   the data Space the collections belong to
 * @returns {EncryptionDescriptorSource}
 */
export function logGovernedDescriptorSource({
  logFor,
  resolveController,
  pinStore,
  spaceId
}: {
  logFor: (collectionId: string) => ResourceLogStore
  resolveController: () => Promise<ResourceLogController>
  pinStore: ResourceLogPinStore
  spaceId: string
}): EncryptionDescriptorSource {
  return {
    async collectionEncryption({ collectionId }) {
      const current = await readGovernedEpochConfiguration({
        store: logFor(collectionId),
        resolveController,
        pinStore,
        logId: collectionDescriptorLogPinId({ spaceId, collectionId })
      })
      if (current === null) {
        return undefined
      }
      return current.descriptor
    }
  }
}
