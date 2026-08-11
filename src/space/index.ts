/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/space` subpath: the wallet Space layout contract two
 * WAS-enabled wallet apps share.
 *
 * - The shared collection ids and descriptive specs (`private-credentials`,
 *   `public-credentials`, `wallet-activity`; the contacts identity contract
 *   stays in `@interop/social-core`, spread into the wallet-Space specs here),
 *   and the provisioning rosters that split them into synced feeds vs.
 *   provisioned-but-not-synced system collections.
 * - The system collections and resource names that carry identity and key
 *   material (`id`, `key-map`, `keyring`; `did.json`, `did.jsonl`, `keys.json`,
 *   `user-key.jsonl`, `keyring.json`) -- outside the synced set, never replicated.
 * - `provisionWalletSpace`, the one-shot full-roster provisioner every
 *   controller-tier wallet client runs (create-if-absent, never clobbering
 *   settled configuration). It declares the encrypted collections; their
 *   epoch[0] install is the EDV-bearing `ensureWalletSpaceEpochs` in
 *   `@interop/wallet-core/keys`, kept out of this crypto-free module.
 * - The `wallet-activity` wire shape (`WalletActivity`) and the pure
 *   `addHistory*` payload builders.
 * - `publicCredentialUrl`, the world-readable shared-credential URL both
 *   replicas derive identically.
 * - The `was-link` QR hand-off contract (`buildWasLinkPayload` /
 *   `parseWasLinkPayload` / `encodeWasLinkSecret`).
 */
export {
  WALLET_SPACE_NAME,
  PRIVATE_CREDENTIALS_COLLECTION,
  PUBLIC_CREDENTIALS_COLLECTION,
  WALLET_ACTIVITY_COLLECTION,
  PRIVATE_CREDENTIALS_COLLECTION_SPEC,
  PUBLIC_CREDENTIALS_COLLECTION_SPEC,
  WALLET_ACTIVITY_COLLECTION_SPEC,
  CONTACTS_SPACE_COLLECTION_SPEC,
  CONTACTS_HISTORY_SPACE_COLLECTION_SPEC,
  WALLET_SPACE_SYNCED_SPECS,
  WALLET_SPACE_SYSTEM_SPECS,
  WALLET_SPACE_PROVISION_ROSTER
} from './collections.js'
export {
  ID_COLLECTION,
  KEY_MAP_COLLECTION,
  KEYRING_COLLECTION,
  ID_COLLECTION_SPEC,
  KEY_MAP_COLLECTION_SPEC,
  DID_DOCUMENT_RESOURCE,
  DID_LOG_RESOURCE,
  DID_KEYS_RESOURCE,
  USER_KEY_ROSTER_LOG_RESOURCE,
  CLIENT_LABELS_RESOURCE,
  KEYRING_RESOURCE
} from './collections.js'
export type { SpaceProvisionSpec, SpaceCollectionSpec } from './collections.js'

export { provisionWalletSpace } from './provisioning.js'

export {
  ACTIVITY_TYPE,
  addHistoryNewAccount,
  addHistorySpaceCreated,
  addHistoryCredentialCreated,
  addHistoryCredentialDeleted,
  addHistoryCredentialShared,
  addHistoryCredentialUnshared,
  addHistoryLogin,
  addHistoryWalletLogin,
  addHistoryAppRevoke,
  addHistoryClientRevoked
} from './activity.js'
export type { WalletActivity, ActivityGrant } from './activity.js'

export { publicCredentialUrl } from './publicLink.js'

export {
  encodeWasLinkSecret,
  buildWasLinkPayload,
  parseWasLinkPayload
} from './wasLink.js'
export type { WasLinkPayload } from './wasLink.js'

export { HumanReadableError } from './errors.js'
