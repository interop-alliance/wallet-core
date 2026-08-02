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
 * - `ensurePukRoster` / `addPukRosterRecipient` / `readPukRoster` /
 *   `pukRosterRecipientResolver` -- the `key-map/puk.json` roster over the
 *   was-client descriptor-store seam, with the three client-side guards a
 *   resource-hosted descriptor needs (`epochsMac`, the latest-seen epoch pin,
 *   and a recipient resolver backed by the locally verified did:webvh
 *   document).
 * - `pukRosterDescriptorStore` -- that descriptor store, built from a bare
 *   signing client for the login-time direct read.
 * - `rotatePukRoster` / `unwrapPukGenerations` / `rotateCollectionEpochsToPuk`
 *   / `pukAsRecipient` -- the PUK rotation cascade: the roster rotation off a
 *   revoked recipient, and the per-collection re-epoch that brings every
 *   encrypted collection onto the roster's current PUK (also the completion
 *   sweep's per-collection op).
 */
export { mintPuk, pukVaultKeys } from './puk.js'
export type { Puk } from './puk.js'

export {
  addPukRosterRecipient,
  ensurePukRoster,
  PukRosterContinuityError,
  PukRosterIntegrityError,
  PukRosterUnwrapError,
  pukRosterRecipientResolver,
  readPukRoster,
  rotatePukRoster
} from './pukRoster.js'
export {
  pukAsRecipient,
  rotateCollectionEpochsToPuk,
  unwrapPukGenerations
} from './pukCascade.js'
export type { CollectionPukRotationOutcome } from './pukCascade.js'
export type {
  PukRosterReadResult,
  RosterRecipientDocument
} from './pukRoster.js'

export { pukRosterDescriptorStore } from './rosterStore.js'
