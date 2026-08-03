/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/webvh` subpath: the account's did:webvh identity --
 * the hash-chained, self-certifying DID log hosted in the world-readable `id`
 * collection of the user's WAS Space, whose document is the enrolled-client
 * roster.
 *
 * - `ensureDidWebvh` / `rotateWebvhUpdateKey` / `enrollWebvhClient` /
 *   `revokeWebvhClient` -- provisioning, per-client update-key rotation, the
 *   two-entry client enrollment ceremony, and the one-entry client
 *   revocation edit, all over the narrow `WebvhIdStore` seam.
 * - `listEnrolledWebvhClients` -- the enrolled-client listing over a
 *   caller-verified log (keyed on `capabilityInvocation`, update keys
 *   recovered by log attribution), for a "your wallets" surface.
 * - `delegationKeyInDocument` -- the current-key-set rule for one recorded
 *   delegation: does the document still publish the key that signed it (a
 *   missing key id reads as "cannot be checked", so: no).
 * - `verifyAccountLog` -- the verification step every one of those ceremonies
 *   runs first: fetch the world-readable log, resolve it locally, refuse a log
 *   that resolves to another DID.
 * - `wasWebvhIdStore` -- the WAS-backed `WebvhIdStore` the ceremonies write
 *   through.
 * - `repairKeyBindings` -- the lost-`keys.json` recovery path.
 * - `webvhZcapClient` / `webvhSigner` / `didKeyZcapClient` -- ZCap signing
 *   under the account's did:webvh verification-method id (and the
 *   pre-promotion did:key form).
 *
 * Kept out of the root export: this subpath pulls the did:webvh, ed25519, and
 * ezcap dependency graph (the same isolation pattern as `./identity`).
 */
export {
  didWebvhControllerTemplate,
  ensureDidWebvh,
  enrollWebvhClient,
  mintClientWebvhUpdateKeys,
  relationIds,
  repairKeyBindings,
  rotateWebvhUpdateKey,
  updateKeyMultibase
} from './didWebvh.js'
export { AccountLogMissingError, verifyAccountLog } from './verifyLog.js'
export { wasWebvhIdStore } from './wasIdStore.js'
export {
  attributeClientUpdateKey,
  delegationKeyInDocument,
  documentKeyMultibases,
  keyAgreementTwinMultibase,
  listEnrolledWebvhClients
} from './listClients.js'
export type {
  EnrolledWebvhClient,
  PublishedKeyDocument
} from './listClients.js'
export {
  revokeWebvhClient,
  StagedCommitmentAmbiguousError
} from './revokeClient.js'
export type { RevokedClientKeys } from './revokeClient.js'
export type {
  ClientWebvhUpdateKeys,
  DidWebvhBlock,
  DidWebKeyMapV2,
  WebvhClientKeys,
  WebvhEnrollmentKeys,
  WebvhIdStore
} from './didWebvh.js'

export { multibaseOf } from './didWeb.js'
export type { DidWebKey, DidWebKeyMap } from './didWeb.js'

export {
  clientSigningKeyMultibase,
  didKeyZcapClient,
  isWebvhDid,
  webvhCapabilityAgent,
  webvhSigner,
  webvhZcapClient
} from './zcap.js'
export type { ICapabilityAgent } from './zcap.js'
