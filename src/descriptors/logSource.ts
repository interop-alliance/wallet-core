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
 *
 * The log lives at the collection's own `meta/log` sub-resource
 * (`COLLECTION_HISTORY_LOG_SUBRESOURCE`), inside the URL subtree of the
 * collection it governs. A share grantee or a connected app already holds a
 * read capability over that subtree, so the same grant that lets them read
 * the collection lets them verify its descriptor's history: no second grant,
 * and no capability over the account's `key-map` collection.
 *
 * Reads here run under the collection-descriptor log CLASS: a ladder-signed
 * append to one of these logs admits on `assertionMethod` membership alone,
 * the roster's ceremony-tail license binding the roster log only. A reader
 * that inherited the roster's rule would refuse a served log its own wallet
 * wrote.
 */
import {
  EPOCH_CONFIGURATION_STATE_TYPE,
  readGovernedEpochConfiguration,
  type EncryptionDescriptorSource
} from '@interop/was-client/edv'
import {
  collectionLogPinId,
  type ResourceLogPinStore,
  type ResourceLogStore
} from '@interop/vh-resource-log'
import {
  controllerForLogClass,
  type WebvhResourceLogController
} from '../resourceLog/index.js'

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
 * `space/<spaceId>/<collectionId>/meta/log`. The library names it, as it
 * names the account log's (`accountLogPinId`) and the roster's
 * (`userKeyRosterPinId`) slots, so no app builds one of its own.
 *
 * The slot follows the log's placement: the log is the collection's own
 * `meta/log` sub-resource, inside the URL subtree of the collection it
 * governs, so the read capability a share grantee or a connected app already
 * holds covers it. The shape is host-free on purpose -- the Space id is what
 * stays stable across a claimed host move, so a log served from a new host
 * still lands in the same slot and is checked against the held pin rather
 * than opening a fresh trust-on-first-use slate.
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
  return collectionLogPinId({ spaceId, collectionId })
}

/**
 * Builds the {@link EncryptionDescriptorSource} over per-collection resource
 * logs. An absent log resolves `undefined` exactly like an absent
 * Collection Description `encryption` member (a plaintext collection, or one
 * whose provisioning has not landed), unless a pin is held for it, in which
 * case the read refuses as a `rollback`; verification failures throw through --
 * was-client's `acquireDescriptor` rethrows the refusal classes rather than
 * falling back to the cache.
 *
 * Every read runs under the collection-descriptor log class
 * ({@link controllerForLogClass}), so a ladder-signed append verifies on
 * `assertionMethod` membership alone. Without that narrowing a reader would
 * inherit the roster's ceremony-tail license and refuse a served log its own
 * wallet's standing credential wrote.
 *
 * @param options {object}
 * @param options.logFor {function}   `(collectionId) => ResourceLogStore` --
 *   the collection's governing log's transport seam (was-client's
 *   `resourceLogStore({ collection })` over the collection's `meta/log`)
 * @param options.resolveController {function}
 *   `() => Promise<WebvhResourceLogController>` -- the caller's currently
 *   verified controller view, resolved per operation and narrowed here to
 *   this log class
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
  resolveController: () => Promise<WebvhResourceLogController>
  pinStore: ResourceLogPinStore
  spaceId: string
}): EncryptionDescriptorSource {
  return {
    async collectionEncryption({ collectionId }) {
      const current = await readGovernedEpochConfiguration({
        store: logFor(collectionId),
        resolveController: async () =>
          controllerForLogClass({
            controller: await resolveController(),
            logClass: 'collection-descriptor'
          }),
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
