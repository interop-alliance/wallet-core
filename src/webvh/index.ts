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
 * - `markedVerificationMethodPair` -- the one builder of a client's published
 *   verification-method pair (the account-controlled signing method plus the
 *   key-agreement method under the controller marker), which every write site
 *   uses and which refuses a key-agreement key that is not the signing key's
 *   canonical X25519 twin (`keyAgreementTwinMultibase`).
 * - `listEnrolledWebvhClients` -- the enrolled-client listing over a
 *   caller-verified log (keyed on `capabilityInvocation`, update keys
 *   recovered by log attribution), for a "your wallets" surface.
 * - `ladderVmIds` / `relationIds` / `resolvedKeyAgreementMethods` /
 *   `credentialKeyAgreementMethods` -- the account-document reading
 *   conventions, defined once in the dependency-free leaf beside the
 *   resource-log controller adapter (`resourceLog/document.ts`) so the
 *   ceremony-tail license reads a document exactly as the listings do, and
 *   surfaced here, their public home: relation resolution, the ladder VM's
 *   recognition by relation asymmetry (a `capabilityDelegation` member absent
 *   from `capabilityInvocation`), and the credential class. The ladder VM's
 *   write-side builders are surfaced by `@interop/wallet-core/clientAnnex`.
 * - `keyAgreementCommitment` / `commitmentMatchesKey` -- the
 *   `MultikeyCommitment` wire rule: the bare sha2-256 multihash, base64url
 *   no-pad, over a key-agreement key's decoded multikey bytes, and the
 *   decode-based check that verifies a candidate key against a published
 *   commitment.
 * - `delegationKeyInDocument` -- the current-key-set rule for one recorded
 *   delegation: does the document still list the key that signed it under
 *   `capabilityDelegation` (a key kept under another relation alone does not
 *   count, and a missing key id reads as "cannot be checked", so: no).
 * - `standingZcapStale` / `recordedZcapStale` -- the composed house staleness
 *   rule every re-mint pass and renewal stage asks (expiry, signer death, and
 *   the caller's retiring set), over a delegation in hand or over the
 *   `keyId` / `expires` scalars a registry entry records.
 * - `verifyAccountLog` -- the verification step every one of those ceremonies
 *   runs first: fetch the world-readable log, resolve it locally, refuse a log
 *   that resolves to another DID.
 * - `wasWebvhIdStore` -- the WAS-backed `WebvhIdStore` the ceremonies write
 *   through, over the parameterized `wasWebvhLogStore` (any collection's
 *   `did.jsonl`), which also serves a client-annex generation's log.
 * - `ensureDidWebProjection` / `putDidWebProjection` -- the `did:web`
 *   projection (`id/did.json`) writers. The publish tails PUT it
 *   unconditionally behind a won log compare-and-swap; the ensure compares
 *   the served document against the one the resolved log derives and writes
 *   only on a difference -- re-resolving through the caller's optional
 *   `refresh` before it does, and writing under a compare-and-swap on its own
 *   read, so a newer projection is never overwritten. The ensure is the mender
 *   for a projection a
 *   ladder-signed entry left behind, since `publishEntryPinned` writes the log
 *   alone -- run by any caller holding a writer for the `id` collection, which
 *   on a client-less account means a transient visit under its generation
 *   delegation.
 * - `delegatedWebvhLogStore` -- the same narrow log seam served through a
 *   pre-minted delegation (the unlock record's account-log bridge, the
 *   annex sibling), with the CAS/ETag discipline preserved: a failed
 *   precondition on the delegated PUT surfaces under the seam's
 *   `PreconditionFailedError` name, so lost races still map to
 *   `WebvhLogConflictError`.
 * - `WebvhLogConflictError` / `withLogConflictRetry` -- the lost-race outcome
 *   of a ceremony's conditional `did.jsonl` publish, and the rebase-by-re-run
 *   wrapper every ceremony here already applies to itself.
 * - `webvhZcapClient` / `webvhSigner` / `didKeyZcapClient` -- ZCap signing
 *   under the account's did:webvh verification-method id (and the
 *   pre-promotion did:key form).
 *
 * Kept out of the root export: this subpath pulls the did:webvh, ed25519, and
 * ezcap dependency graph (the same isolation pattern as `./identity`).
 */
export {
  assertCanonicalClientKeys,
  BYOE_CONTEXT_URL,
  clientKeyAgreementController,
  commitmentMatchesKey,
  didWebvhControllerTemplate,
  ensureDidWebvh,
  enrollWebvhClient,
  keyAgreementCommitment,
  keyAgreementTwinMultibase,
  MULTIKEY_COMMITMENT_VM_TYPE,
  markedVerificationMethodPair,
  mintClientWebvhUpdateKeys,
  rotateWebvhUpdateKey,
  servedHead,
  updateKeyMultibase,
  WebvhLogConflictError,
  withLogConflictRetry
} from './didWebvh.js'
export {
  accountLogPinId,
  AccountLogMissingError,
  verifiedAccountLogOf,
  verifyAccountLog
} from './verifyLog.js'
export type { VerifiedAccountLog } from './verifyLog.js'
export { wasWebvhIdStore, wasWebvhLogStore } from './wasIdStore.js'
export type { WebvhLogResourceStore } from './wasIdStore.js'
export {
  ensureDidWebProjection,
  putDidWebProjection
} from './didWebProjection.js'
export { delegatedWebvhLogStore } from './delegatedLogStore.js'
export type { DelegatedWebvhLogStore } from './delegatedLogStore.js'
export {
  delegationProofKeyId,
  recordedZcapStale,
  STANDING_ZCAP_TTL_MS,
  standingZcapStale,
  ZCAP_RENEWAL_WINDOW_MS,
  zcapExpiring
} from './standingZcap.js'
export {
  attributeClientUpdateKey,
  delegationKeyInDocument,
  documentKeyMultibases,
  listEnrolledWebvhClients,
  markedKeyAgreementMethods,
  markedKeyAgreementMultibases
} from './listClients.js'
export type {
  EnrolledWebvhClient,
  PublishedKeyDocument
} from './listClients.js'
export {
  credentialKeyAgreementMethods,
  ladderVmIds,
  relationIds,
  resolvedKeyAgreementMethods
} from '../resourceLog/document.js'
export type {
  KeyAgreementDocument,
  ResolvedKeyAgreementMethod
} from '../resourceLog/document.js'
export {
  revokeWebvhClient,
  StagedCommitmentAmbiguousError
} from './revokeClient.js'
export type { RevokedClientKeys } from './revokeClient.js'
export type {
  ClientWebvhUpdateKeys,
  CreatedWebvhLog,
  DidWebvhBlock,
  DidWebKeyMapV2,
  KmsAuthenticationBinding,
  PublishedWebvhLog,
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
