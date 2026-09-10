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
 *
 * Over it sit the two lookup builders every consumer of the
 * `(collectionId) => store` seam takes (the geneses' `collectionStoreFor`,
 * the epoch installers' and the cascade's `storeFor`):
 * {@link collectionDescriptorStores}, which takes the collection reach and
 * the controller resolver as functions, and {@link accountCollectionStores},
 * the bare-parts convenience over it for callers with no session, resolving
 * the controller through {@link accountControllerResolver}.
 */
import type { DIDLog } from '@interop/did-method-webvh'
import type { ZcapClient } from '@interop/ezcap'
import {
  WasClient,
  type Collection,
  type IZcap,
  type Space
} from '@interop/was-client'
import { resourceLogStore } from '@interop/was-client/log'
import type {
  ResourceLogPinStore,
  ResourceLogSigner
} from '@interop/vh-resource-log'
import { collectionDescriptorLogPinId } from '../descriptors/logSource.js'
import type { WebvhResourceLogController } from '../resourceLog/index.js'
import { accountControllerResolver } from '../webvh/verifyLog.js'
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

/**
 * The per-collection store lookup the epoch installers
 * ({@link ensureWalletSpaceEpochs}, {@link walletSpaceProvisioner}), the
 * geneses' `collectionStoreFor`, and the cascade's
 * `CascadeCollections.storeFor` take.
 */
export type CollectionStoreFor = (
  collectionId: string
) => SealableEncryptionDescriptorStore

/**
 * Builds the per-collection store lookup from a collection reach and a
 * controller resolver, both functions: the generic builder a caller with a
 * live session wires with its own verified-log memo and a collection handle
 * that rides whatever capability the session holds at call time (a transient
 * visit's generation delegation, renewed mid-run included).
 *
 * Each lookup builds a fresh store over {@link collectionDescriptorLogStore}
 * for the collection named, sharing the resolver, the pin store, and the
 * signer across them; nothing is reached until the first lookup, so a lookup
 * handed to a ceremony that never installs or rotates an epoch costs nothing.
 *
 * @param options {object}
 * @param options.collectionFor {function}   `(collectionId) => Collection` --
 *   how the caller reaches a collection handle (a `Space` handle's
 *   `collection()`, or a wrapper that rides a capability the caller renews)
 * @param options.resolveController {function}
 *   `() => Promise<WebvhResourceLogController>` -- the caller's currently
 *   verified controller view, resolved per operation
 * @param options.pinStore {ResourceLogPinStore}   this client's chain-head
 *   pins, keyed per log
 * @param options.signer {ResourceLogSigner}   the signing key every store's
 *   appends are proved by; it must be listed under `assertionMethod` in the
 *   account document at the version each append anchors at
 * @returns {CollectionStoreFor}
 */
export function collectionDescriptorStores({
  collectionFor,
  resolveController,
  pinStore,
  signer
}: {
  collectionFor: (collectionId: string) => Collection
  resolveController: () => Promise<WebvhResourceLogController>
  pinStore: ResourceLogPinStore
  signer: ResourceLogSigner
}): CollectionStoreFor {
  return collectionId =>
    collectionDescriptorLogStore({
      collection: collectionFor(collectionId),
      resolveController,
      pinStore,
      signer
    })
}

/**
 * Builds the per-collection store lookup from bare parts, for callers with
 * no session: the geneses, the mend, the recovery continuations, and a
 * wallet whose every caller acts on its account with a signing client and a
 * pin store. The parameter shape is {@link userKeyRosterDescriptorStore}'s,
 * plus the account DID and the optional account log, so the roster store and
 * its per-collection twin are built from the same parts.
 *
 * The controller view is {@link accountControllerResolver}'s, built here
 * over the same parts, so a fan-out over every collection verifies the
 * account log once. A caller that also builds the roster store and wants one
 * verification for the pair builds that resolver itself and hands it to
 * both {@link userKeyRosterDescriptorStore} and
 * {@link collectionDescriptorStores}. Nothing is reached until the first
 * lookup, so a lookup handed to a ceremony that never installs or rotates an
 * epoch costs nothing.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}   the storage server the account
 *   lives on
 * @param options.zcapClient {ZcapClient}   the signing client every request
 *   rides
 * @param options.spaceId {string}   the data Space id
 * @param options.did {string}   the account's did:webvh, the controller
 *   every collection log's entry proofs anchor to
 * @param options.pinStore {ResourceLogPinStore}   this client's chain-head
 *   pins, for the collection logs and for the account log's own slot when
 *   it is verified here
 * @param options.signer {ResourceLogSigner}   the signing key every store's
 *   appends are proved by ({@link userKeyRosterLogSigner} for an enrolled
 *   client, a standing credential's ladder VM on a credential-anchored
 *   account)
 * @param [options.log] {DIDLog}   the account log this run already stands on
 *   (a ceremony that just read or published it); given, no fetch runs
 * @param [options.capability] {IZcap}   an invocation capability every
 *   request rides (a transient visit's generation delegation); absent,
 *   requests invoke the root capability
 * @returns {CollectionStoreFor}
 */
export function accountCollectionStores({
  storageServerUrl,
  zcapClient,
  spaceId,
  did,
  pinStore,
  signer,
  log,
  capability
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  did: string
  pinStore: ResourceLogPinStore
  signer: ResourceLogSigner
  log?: DIDLog
  capability?: IZcap
}): CollectionStoreFor {
  let space: Space | undefined
  return collectionDescriptorStores({
    collectionFor: collectionId => {
      space ??= new WasClient({
        serverUrl: storageServerUrl,
        zcapClient
      }).space(spaceId, { capability })
      return space.collection(collectionId)
    },
    resolveController: accountControllerResolver({
      did,
      spaceId,
      host: storageServerUrl,
      pinStore,
      log
    }),
    pinStore,
    signer
  })
}
