/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/keys` subpath: the per-user key (PUK) and its
 * wrap-set roster -- recipient zero of every encrypted collection, and the one
 * channel that delivers it to each enrolled wallet client.
 *
 * - `mintPuk` / `pukVaultKeys` -- minting the account's PUK and rebuilding the
 *   vault key-agreement key + resolver from stored material.
 * - `encodeClientKeyRecord` / `decodeClientKeyRecord` -- the contents codec and
 *   strict validation of the local client-key record each client keeps its own
 *   key material in (storage and wrapping stay app-side).
 * - `ensurePukRoster` / `addPukRosterRecipient` / `readPukRoster` /
 *   `pukRosterRecipientResolver` -- the `key-map/puk.json` roster over the
 *   was-client descriptor-store seam, with the three client-side guards a
 *   resource-hosted descriptor needs (`epochsMac`, the latest-seen epoch pin,
 *   and a recipient resolver backed by the locally verified did:webvh
 *   document).
 * - `pukRosterDescriptorStore` -- that descriptor store, built from a bare
 *   signing client for the login-time direct read.
 * - `rosterRecipientKid` -- the one builder of a client's roster kid, shared by
 *   the enrollment wrap, the roster read, and the rotation that retires it.
 * - `convergePukRosterToDocument` -- the standing detector for a revocation
 *   cascade torn between the document edit and the roster rotation: a roster
 *   recipient the document no longer keys is rotated away from.
 * - `readClientLabels` / `setClientLabel` / `removeClientLabel` /
 *   `wasClientLabelsStore` -- the enrolled-client display labels
 *   (`key-map/client-labels.json`), the record a "your wallets" surface names
 *   clients from, and the WAS-backed store they run through.
 * - `rotatePukRoster` / `unwrapPukGenerations` / `rotateCollectionEpochsToPuk`
 *   / `cascadeCollectionsToPuk` / `pukAsRecipient` -- the PUK rotation
 *   cascade: the roster rotation off a revoked recipient, the per-collection
 *   re-epoch that brings an encrypted collection onto the roster's current
 *   PUK, and the parallel best-effort fan-out over the collections the wallet
 *   names (also the completion sweep's driver).
 */
export { mintPuk, pukVaultKeys } from './puk.js'
export type { Puk } from './puk.js'

export {
  assertEnrolledClientKeyRecord,
  decodeClientKeyRecord,
  encodeClientKeyRecord,
  parseClientRecordPuk,
  parseClientRecordWebvhKeys
} from './clientKeyRecord.js'
export type {
  ClientKeyRecord,
  ClientKeyRecordJson,
  EnrolledClientKeyRecord
} from './clientKeyRecord.js'

export {
  addPukRosterRecipient,
  convergePukRosterToDocument,
  ensurePukRoster,
  PukRosterContinuityError,
  PukRosterIntegrityError,
  PukRosterUnwrapError,
  pukRosterRecipientResolver,
  readPukRoster,
  rosterRecipientKid,
  rotatePukRoster
} from './pukRoster.js'
export {
  cascadeCollectionsToPuk,
  pukAsRecipient,
  rotateCollectionEpochsToPuk,
  unwrapPukGenerations
} from './pukCascade.js'
export type {
  CollectionPukRotationOutcome,
  PukCascadeResult
} from './pukCascade.js'
export type {
  PukRosterReadResult,
  RosterRecipientDocument
} from './pukRoster.js'

export { pukRosterDescriptorStore } from './rosterStore.js'

export {
  readClientLabels,
  removeClientLabel,
  setClientLabel
} from './clientLabels.js'
export type { ClientLabelsRecord, ClientLabelsStore } from './clientLabels.js'

export { wasClientLabelsStore } from './wasLabelsStore.js'
