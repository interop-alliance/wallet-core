/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The descriptor store over a Space's user key wrap-set roster -- since the
 * roster became log-governed, over its resource log (`key-map/user-key.jsonl`).
 * Standalone rather than a method on a wallet's remote-store class, because the
 * login-time direct read checks the roster BEFORE any storage client (or
 * cipher) is built: it takes the bare signing client instead of a store
 * instance.
 *
 * The `plaintext` collection override is load-bearing twice over. Without it
 * the client decides plaintext vs encrypted by describing the collection
 * first, and a 404 from an absent Space or collection then surfaces as an
 * encryption error rather than as an absent roster; and on an encrypted
 * collection the EDV codec would compute the write preconditions itself, so
 * the log's compare-and-swap append guard would not be honored.
 */
import { WasClient } from '@interop/was-client'
import type { ZcapClient } from '@interop/ezcap'
import { resourceLogStore } from '@interop/was-client/log'
import type {
  ResourceLogController,
  ResourceLogPinStore,
  ResourceLogSigner
} from '../resourceLog/index.js'
import {
  KEY_MAP_COLLECTION,
  USER_KEY_ROSTER_LOG_RESOURCE
} from '../space/collections.js'
import {
  logGovernedDescriptorStore,
  type SealableEncryptionDescriptorStore
} from './rosterLogStore.js'

/**
 * Builds the log-governed descriptor store over the user key roster in a
 * data Space: reads resolve to the verified head of
 * `key-map/user-key.jsonl`, writes append to it.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}   the session's root signing client
 * @param options.spaceId {string}   the data Space id
 * @param options.resolveController {function}
 *   `() => Promise<ResourceLogController>` -- the caller's currently verified
 *   controller view (`webvhResourceLogController` over a `verifyAccountLog`
 *   result), resolved per operation so post-edit writers anchor at the head
 *   they just verified
 * @param options.pinStore {ResourceLogPinStore}   this client's chain-head
 *   pin for the roster log
 * @param options.signer {ResourceLogSigner}   this client's enrolled signing
 *   key ({@link userKeyRosterLogSigner})
 * @returns {SealableEncryptionDescriptorStore}
 */
export function userKeyRosterDescriptorStore({
  storageServerUrl,
  zcapClient,
  spaceId,
  resolveController,
  pinStore,
  signer
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  resolveController: () => Promise<ResourceLogController>
  pinStore: ResourceLogPinStore
  signer: ResourceLogSigner
}): SealableEncryptionDescriptorStore {
  const was = new WasClient({ serverUrl: storageServerUrl, zcapClient })
  const collection = was
    .space(spaceId)
    .collection(KEY_MAP_COLLECTION.id, { encryption: 'plaintext' })
  return logGovernedDescriptorStore({
    log: resourceLogStore({
      resource: collection.resource(USER_KEY_ROSTER_LOG_RESOURCE)
    }),
    resolveController,
    pinStore,
    signer
  })
}
