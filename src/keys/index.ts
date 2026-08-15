/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/keys` subpath: the user key and its
 * wrap-set roster -- recipient zero of every encrypted collection, and the one
 * channel that delivers it to each enrolled wallet client.
 *
 * - `mintUserKey` / `userKeyVaultKeys` -- minting the account's user key and
 *   rebuilding the
 *   vault key-agreement key + resolver from stored material.
 * - `encodeClientKeyRecord` / `decodeClientKeyRecord` -- the contents codec and
 *   strict validation of the local client-key record each client keeps its own
 *   key material in (storage and wrapping stay app-side).
 * - `ensureUserKeyRoster` / `addUserKeyRosterRecipient` / `readUserKeyRoster` /
 *   `userKeyRosterRecipientResolver` -- the user key roster over the
 *   was-client descriptor-store seam, with the client-side guards a
 *   resource-hosted descriptor needs (the governing resource log, the
 *   latest-seen epoch pin, and a recipient resolver backed by the locally
 *   verified did:webvh document).
 * - `userKeyRosterDescriptorStore` / `logGovernedDescriptorStore` -- that
 *   descriptor store: reads resolve to the roster log's verified head
 *   (`key-map/user-key.jsonl`), writes append signed entries; built from a
 *   bare signing client for the login-time direct read. Sealable
 *   (`SealableEncryptionDescriptorStore` / `isSealableDescriptorStore`):
 *   `seal()` appends the idempotent backstop entry when the log's head still
 *   anchors before the account document's latest membership change.
 * - `rosterRecipientKid` -- the one builder of a client's roster kid, shared by
 *   the enrollment wrap and the roster read. A retiring rotation names no kid:
 *   it converges onto the account document instead.
 * - `convergeUserKeyRosterToDocument` -- the standing detector for a revocation
 *   cascade torn between the document edit and the roster rotation: a roster
 *   recipient the document no longer keys is rotated away from.
 * - `readClientLabels` / `setClientLabel` / `removeClientLabel` /
 *   `wasClientLabelsStore` -- the enrolled-client display labels
 *   (`key-map/client-labels.json`), the record a "your wallets" surface names
 *   clients from, and the WAS-backed store they run through.
 * - `rotateUserKeyRoster` / `unwrapUserKeyGenerations` /
 *   `rotateCollectionEpochsToUserKey`
 *   / `cascadeCollectionsToUserKey` / `userKeyAsRecipient` -- the user key rotation
 *   cascade: the roster rotation off a revoked recipient, the per-collection
 *   re-epoch that brings an encrypted collection onto the roster's current
 *   user key, and the parallel best-effort fan-out over the collections the wallet
 *   names (also the completion sweep's driver).
 * - `ensureWalletSpaceEpochs` -- the provision-time epoch[0] install for the
 *   wallet Space's encrypted collections, the EDV-bearing second step of
 *   `provisionWalletSpace`.
 * - `ensureIndexedFirstEpoch` -- one collection's epoch[0] plus its
 *   blinded-index HMAC key, adopting a pre-blind-index roster as-is.
 */
export { mintUserKey, userKeyVaultKeys } from './userKey.js'
export type { UserKey } from './userKey.js'

export {
  assertEnrolledClientKeyRecord,
  decodeClientKeyRecord,
  encodeClientKeyRecord,
  parseClientRecordUserKey,
  parseClientRecordWebvhKeys
} from './clientKeyRecord.js'
export type {
  ClientKeyRecord,
  ClientKeyRecordJson,
  EnrolledClientKeyRecord
} from './clientKeyRecord.js'

export {
  addUserKeyRosterRecipient,
  convergeUserKeyRosterToDocument,
  ensureUserKeyRoster,
  UserKeyRosterContinuityError,
  UserKeyRosterIntegrityError,
  UserKeyRosterUnwrapError,
  userKeyRosterLogSigner,
  userKeyRosterRecipientResolver,
  readUserKeyRoster,
  rosterRecipientKid,
  rotateUserKeyRoster
} from './userKeyRoster.js'
export {
  cascadeCollectionsToUserKey,
  userKeyAsRecipient,
  rotateCollectionEpochsToUserKey,
  unwrapUserKeyGenerations
} from './userKeyCascade.js'
export type {
  CollectionUserKeyRotationOutcome,
  UserKeyCascadeResult
} from './userKeyCascade.js'
export type {
  UserKeyRosterReadResult,
  RosterRecipientDocument
} from './userKeyRoster.js'

export { userKeyRosterDescriptorStore } from './rosterStore.js'
export {
  EPOCH_CONFIGURATION_STATE_TYPE,
  isSealableDescriptorStore,
  logGovernedDescriptorStore
} from './rosterLogStore.js'
export type { SealableEncryptionDescriptorStore } from './rosterLogStore.js'

export {
  ensureIndexedFirstEpoch,
  ensureWalletSpaceEpochs
} from './spaceEpochs.js'
export type { WalletSpaceEpochsResult } from './spaceEpochs.js'

export {
  readClientLabels,
  removeClientLabel,
  setClientLabel
} from './clientLabels.js'
export type { ClientLabelsRecord, ClientLabelsStore } from './clientLabels.js'

export { wasClientLabelsStore } from './wasLabelsStore.js'
