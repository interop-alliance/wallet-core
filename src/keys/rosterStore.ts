/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The descriptor store over a Space's user key wrap-set roster
 * (`key-map/user-key.json`). Standalone rather than a method on a wallet's
 * remote-store class, because the login-time direct read checks the roster
 * BEFORE any storage client (or cipher) is built: it takes the bare signing
 * client instead of a store instance.
 *
 * The `plaintext` collection override is load-bearing. Without it the client
 * decides plaintext vs encrypted by describing the collection first, and a 404
 * from an absent Space or collection then surfaces as an encryption error
 * rather than as an absent roster.
 */
import { WasClient } from '@interop/was-client'
import type { ZcapClient } from '@interop/ezcap'
import {
  resourceDescriptorStore,
  type EncryptionDescriptorStore
} from '@interop/was-client/edv'
import {
  KEY_MAP_COLLECTION,
  USER_KEY_ROSTER_RESOURCE
} from '../space/collections.js'

/**
 * Builds the compare-and-swap descriptor store over `key-map/user-key.json` in
 * a data Space.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}   the session's root signing client
 * @param options.spaceId {string}   the data Space id
 * @returns {EncryptionDescriptorStore}
 */
export function userKeyRosterDescriptorStore({
  storageServerUrl,
  zcapClient,
  spaceId
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
}): EncryptionDescriptorStore {
  const was = new WasClient({ serverUrl: storageServerUrl, zcapClient })
  const collection = was
    .space(spaceId)
    .collection(KEY_MAP_COLLECTION.id, { encryption: 'plaintext' })
  return resourceDescriptorStore({
    resource: collection.resource(USER_KEY_ROSTER_RESOURCE)
  })
}
