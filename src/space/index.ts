/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/space` subpath: the wallet Space layout contract two
 * WAS-enabled wallet apps share.
 *
 * - The shared collection ids and descriptive specs (`private-credentials`,
 *   `public-credentials`, `wallet-activity`). The contacts collections stay in
 *   `@interop/social-core`.
 * - The system collections and resource names that carry identity and key
 *   material (`id`, `key-map`, `keyring`; `did.json`, `did.jsonl`, `keys.json`,
 *   `puk.json`, `keyring.json`) -- outside the synced set, never replicated.
 * - The `wallet-activity` wire shape (`WalletActivity`) and the pure
 *   `addHistory*` payload builders.
 * - `publicCredentialUrl`, the world-readable shared-credential URL both
 *   replicas derive identically.
 * - The `was-link` QR hand-off contract (`buildWasLinkPayload` /
 *   `parseWasLinkPayload` / `encodeWasLinkSecret`).
 */
export {
  PRIVATE_CREDENTIALS_COLLECTION,
  PUBLIC_CREDENTIALS_COLLECTION,
  WALLET_ACTIVITY_COLLECTION,
  PRIVATE_CREDENTIALS_COLLECTION_SPEC,
  PUBLIC_CREDENTIALS_COLLECTION_SPEC,
  WALLET_ACTIVITY_COLLECTION_SPEC,
  WALLET_SPACE_COLLECTION_SPECS
} from './collections.js'
export {
  ID_COLLECTION,
  KEY_MAP_COLLECTION,
  KEYRING_COLLECTION,
  DID_DOCUMENT_RESOURCE,
  DID_LOG_RESOURCE,
  DID_KEYS_RESOURCE,
  PUK_ROSTER_RESOURCE,
  CLIENT_LABELS_RESOURCE,
  KEYRING_RESOURCE
} from './collections.js'
export type { SpaceCollectionSpec } from './collections.js'

export {
  ACTIVITY_TYPE,
  addHistoryNewAccount,
  addHistorySpaceCreated,
  addHistoryCredentialCreated,
  addHistoryCredentialDeleted,
  addHistoryCredentialShared,
  addHistoryCredentialUnshared,
  addHistoryLogin,
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
