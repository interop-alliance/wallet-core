/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The descriptor store over ONE encrypted collection's governing history log
 * -- the collection's own `meta/log` sub-resource, whose verified head state
 * IS its `encryption` descriptor. The sibling of the user key roster's
 * builder ({@link userKeyRosterDescriptorStore}), over the same wrapped
 * `logGovernedDescriptorStore`: reads resolve to the verified head, writes
 * are signed appends, and `create` is the guarded genesis (`If-None-Match:
 * *`) that declares the Collection governed. The server derives the
 * Collection Description's `encryption` member from that log, so a governed
 * collection's descriptor is never client-written into its Description.
 *
 * The transport seam is was-client's `resourceLogStore({ collection })`, so
 * the handle passed in is the whole address: the store derives its own
 * chain-head pin slot from the handle's Space and collection ids
 * ({@link collectionDescriptorLogPinId}), and no caller names a `logId`.
 */
import type { Collection } from '@interop/was-client'
import { resourceLogStore } from '@interop/was-client/log'
import type {
  ResourceLogPinStore,
  ResourceLogSigner
} from '@interop/vh-resource-log'
import { collectionDescriptorLogPinId } from '../descriptors/logSource.js'
import type { WebvhResourceLogController } from '../resourceLog/index.js'
import {
  logGovernedDescriptorStore,
  type SealableEncryptionDescriptorStore
} from './rosterLogStore.js'

/**
 * Builds the log-governed, sealable descriptor store over one collection's
 * governing history log.
 *
 * Reads resolve to the log's verified head (chain, entry proofs, external
 * authorization against the independently verified account document, and the
 * chain-head pin, all checked before a descriptor is handed out); writes are
 * signed appends of the full next state; `create` is the guarded genesis that
 * declares the Collection governed -- the epoch[0] install
 * ({@link ensureIndexedFirstEpoch}) is what runs it. `seal()` is the backstop
 * for a rotation that no-op'd and so left the log anchored before the account
 * document's latest membership change, and `setMinimumControllerVersion` is
 * the post-edit anchor a ceremony sets so its appends never resolve to a
 * cached pre-edit view.
 *
 * The signer is the same `ResourceLogSigner` the roster takes: an enrolled
 * client's account key ({@link userKeyRosterLogSigner}), or a standing
 * credential's ladder VM on a credential-anchored account.
 *
 * The store's class is `collection-descriptor`, so a ladder-signed append is
 * admitted on `assertionMethod` membership at the anchored version alone.
 * The ceremony-tail license binds the user key roster log only: a descriptor
 * append escrows one recipient into one collection, lands as a hash-chained
 * entry attributable to that credential, and is auditable by the account's
 * clients.
 *
 * @param options {object}
 * @param options.collection {Collection}   the collection handle whose
 *   `meta/log` is the log; its `spaceId` and `id` are what the pin slot is
 *   derived from, and its capability wiring is what every request rides
 * @param options.resolveController {function}
 *   `() => Promise<WebvhResourceLogController>` -- the caller's currently
 *   verified controller view (`webvhResourceLogController` over a
 *   `verifyAccountLog` result), resolved per operation
 * @param options.pinStore {ResourceLogPinStore}   this client's chain-head
 *   pins, keyed per log
 * @param options.signer {ResourceLogSigner}   the signing key the appends
 *   this store writes are proved by. It must be listed under
 *   `assertionMethod` in the account document at the version the append
 *   anchors at, so a ceremony that strikes a key builds its collection stores
 *   on one its own edit leaves standing
 * @returns {SealableEncryptionDescriptorStore}
 */
export function collectionDescriptorLogStore({
  collection,
  resolveController,
  pinStore,
  signer
}: {
  collection: Collection
  resolveController: () => Promise<WebvhResourceLogController>
  pinStore: ResourceLogPinStore
  signer: ResourceLogSigner
}): SealableEncryptionDescriptorStore {
  return logGovernedDescriptorStore({
    log: resourceLogStore({ collection }),
    resolveController,
    pinStore,
    logId: collectionDescriptorLogPinId({
      spaceId: collection.spaceId,
      collectionId: collection.id
    }),
    signer,
    logClass: 'collection-descriptor'
  })
}
