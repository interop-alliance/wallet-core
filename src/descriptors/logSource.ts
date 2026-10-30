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
 * checked before any descriptor is handed out, so a refresh adopts nothing
 * the verifier did not pass. A verified head whose state is not an epoch
 * configuration is refused fail-closed rather than handed out as a
 * descriptor.
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
 *
 * A repeat read of one collection resumes from the log this source last
 * verified for it, handed to the verifier as `previous`, so an unknown-epoch
 * re-acquire or a re-opened cipher verifies only the entries added since. A
 * served log that does not extend it is verified in full, with a first
 * read's refusals.
 */
import {
  EPOCH_CONFIGURATION_STATE_TYPE,
  readGovernedEpochConfiguration
} from '@interop/was-client/edv/core'
import type { EncryptionDescriptorSource } from '@interop/was-client/edv'
import { canonicalSpaceUrl, collectionLogUrl } from '@interop/was-client/paths'
import type {
  ResourceLogPinStore,
  ResourceLogStore,
  VerifiedResourceLog
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
 * keyed `ResourceLogPinStore` holds that log's chain-head pin under. The slot
 * is the log's own URL, `{spaceUrl}{collectionId}/meta/log` (was-client's
 * `collectionLogUrl`). The library names it, as it names the account log's
 * (`accountLogPinId`) and the roster's (`userKeyRosterPinId`) slots, so no
 * app builds one of its own.
 *
 * The slot follows the log's placement: the log is the collection's own
 * `meta/log` sub-resource, inside the URL subtree of the collection it
 * governs, so the read capability a share grantee or a connected app already
 * holds covers it. It is keyed on the URL rather than on a Space id because
 * the reader receives a Space URL and does not parse an id off it, and a
 * fixed Space may carry no id. The account and roster slots stay id-keyed,
 * since their readers hold the DID, which encodes the Space id. The one
 * consequence of the split is that a collection log served from a new host
 * lands in a new slot and is trusted afresh there, where the account log on
 * the same client is still checked against its held pin.
 *
 * The URL is canonicalized by the helper, so every serialization of one
 * Space names the same slot.
 *
 * @param options {object}
 * @param options.spaceUrl {string}   the data Space's URL
 * @param options.collectionId {string}   the governed collection
 * @returns {string}
 * @throws {ValidationError}   when `spaceUrl` is not a Space URL, or the
 *   collection id is a reserved segment at an origin root
 */
export function collectionDescriptorLogPinId({
  spaceUrl,
  collectionId
}: {
  spaceUrl: string
  collectionId: string
}): string {
  return collectionLogUrl({ spaceUrl, collectionId })
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
 * The source declares `verifiesHistory: true`, and a wrapper around it must
 * forward the flag. A consumer passes `requireGoverned: true` to was-client's
 * `acquireDescriptor`, `acquireDescriptors`, or `createRefreshingEdvDocCipher`
 * for every `edv` collection it expects to be governed. Under that option a
 * descriptor is adopted only through a source that declares the flag, with or
 * without a `history` member, and a plain source is refused with
 * `UnverifiedDescriptorError` before any fetch. Without it a host could strip
 * `history` from the served projection and serve an epoch it minted, which a
 * plain reader cannot tell from an honest point-state descriptor.
 *
 * A repeat read of a collection resumes from the log this source last
 * verified for it, so a source should be built once per session and shared,
 * rather than once per acquisition.
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
 *   {@link collectionDescriptorLogPinId} over `spaceUrl`
 * @param options.spaceUrl {string}   the URL of the data Space the
 *   collections belong to, as received (a grant's chain root, a stored
 *   pointer); no id is read off it
 * @returns {EncryptionDescriptorSource}
 * @throws {ValidationError}   when `spaceUrl` is not a Space URL (not an
 *   absolute `http(s)` URL, or carrying a query, a fragment, or an empty
 *   path segment); refused here, at build time, since a refusal raised
 *   inside a read would be taken for a transport failure by was-client's
 *   `acquireDescriptor` and answered from the cache
 */
export function logGovernedDescriptorSource({
  logFor,
  resolveController,
  pinStore,
  spaceUrl
}: {
  logFor: (collectionId: string) => ResourceLogStore
  resolveController: () => Promise<WebvhResourceLogController>
  pinStore: ResourceLogPinStore
  spaceUrl: string
}): EncryptionDescriptorSource {
  // Validation only: refuse a malformed Space URL here, at build time, rather
  // than inside a read. The slot builder canonicalizes on its own, so the two
  // call sites agree without this call.
  canonicalSpaceUrl(spaceUrl)
  // Per collection, the log its last read verified; the next read of that
  // collection resumes from it when the served log still extends it.
  const lastVerified = new Map<string, VerifiedResourceLog>()
  return {
    // Every read below resolves the governing log's verified head, which is
    // the governed descriptor by construction. The head carries no `history`
    // member (the log rule keeps it projection-only); the flag is what
    // `requireGoverned` admits the source on.
    verifiesHistory: true,
    async collectionEncryption({ collectionId }) {
      const current = await readGovernedEpochConfiguration({
        store: logFor(collectionId),
        resolveController: async () =>
          controllerForLogClass({
            controller: await resolveController(),
            logClass: 'collection-descriptor'
          }),
        pinStore,
        logId: collectionDescriptorLogPinId({ spaceUrl, collectionId }),
        previous: lastVerified.get(collectionId) ?? null
      })
      if (current === null) {
        lastVerified.delete(collectionId)
        return undefined
      }
      lastVerified.set(collectionId, current.verified)
      return current.descriptor
    }
  }
}
