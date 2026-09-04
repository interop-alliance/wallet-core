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
 * - `currentEpochOf` -- the one implementation of "resolve a descriptor's
 *   current epoch, refusing a `currentEpoch` that names no epoch in its own
 *   list" (`UserKeyRosterIntegrityError`); every roster and collection
 *   descriptor read that needs the current epoch goes through it.
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
 * - `convergeUserKeyRosterToDocument` -- the standing detector for a ceremony
 *   torn between its document edit and its roster append, in two directions
 *   and one append: a roster recipient the document no longer keys is rotated
 *   away from, and an enrolled client the document keys that holds no wrap is
 *   escrowed into every epoch.
 * - `enrolledClientRosterRecipients` -- the enrolled clients a document keys,
 *   as roster recipients; the escrow direction's candidate list.
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
 * - `rotateRosterToDocumentAndCascade` -- the shared roster-and-cascade tail
 *   every account-membership ceremony ends with (a client disconnected, a
 *   standing unlock credential retired): the post-edit minimum controller version, the
 *   convergence rotation with its seal backstop, and the collection fan-out
 *   onto the fresh user key.
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
  isEnrolledClientKeyRecord,
  parseClientRecordPending,
  parseClientRecordUserKey,
  parseClientRecordWebvhKeys
} from './clientKeyRecord.js'
export type {
  ClientKeyRecord,
  ClientKeyRecordJson,
  ClientKeyRecordPending,
  EnrolledClientKeyRecord
} from './clientKeyRecord.js'

export {
  addUserKeyRosterRecipient,
  convergeUserKeyRosterToDocument,
  currentEpochOf,
  enrolledClientRosterRecipients,
  ensureUserKeyRoster,
  UserKeyRosterContinuityError,
  UserKeyRosterIntegrityError,
  UserKeyRosterUnwrapError,
  userKeyRosterLogSigner,
  userKeyRosterRecipientResolver,
  readUserKeyRoster,
  replaceUserKeyRosterRecipients,
  rosterRecipientKid,
  rosterRecipientsToRetire,
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
export { rotateRosterToDocumentAndCascade } from './userKeyRosterCascade.js'
export type {
  CascadeCollections,
  RosterCascadeResult,
  RosterSealReport
} from './userKeyRosterCascade.js'
export type { UserKeyRosterReadResult } from './userKeyRoster.js'
export type { KeyAgreementDocument } from '../resourceLog/document.js'

export {
  userKeyRosterDescriptorStore,
  userKeyRosterPinId
} from './rosterStore.js'
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
