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
 * - `ladderVerificationMethod` / `ladderVmIds` /
 *   `createLadderAnchoredWebvhLog` -- the ladder VM (the stable sibling a
 *   standing credential publishes while the account has no enrolled durable
 *   client): its one write-side builder, its recognition by relation
 *   asymmetry (a `capabilityDelegation` member absent from
 *   `capabilityInvocation`), and the ladder-anchored genesis log machinery the
 *   unlock layer's `createLadderAnchoredAccountLog` drives.
 * - `keyAgreementCommitment` / `commitmentMatchesKey` -- the
 *   `MultikeyCommitment` wire rule: the bare sha2-256 multihash, base64url
 *   no-pad, over a key-agreement key's decoded multikey bytes, and the
 *   decode-based check that verifies a candidate key against a published
 *   commitment.
 * - `delegationKeyInDocument` -- the current-key-set rule for one recorded
 *   delegation: does the document still publish the key that signed it (a
 *   missing key id reads as "cannot be checked", so: no).
 * - `verifyAccountLog` -- the verification step every one of those ceremonies
 *   runs first: fetch the world-readable log, resolve it locally, refuse a log
 *   that resolves to another DID.
 * - `wasWebvhIdStore` -- the WAS-backed `WebvhIdStore` the ceremonies write
 *   through, over the parameterized `wasWebvhLogStore` (any collection's
 *   `did.jsonl`), which also serves a companion generation's log.
 * - `delegatedWebvhLogStore` -- the same narrow log seam served through a
 *   pre-minted delegation (the unlock record's account-log bridge, the
 *   companion sibling), with the CAS/ETag discipline preserved: a failed
 *   precondition on the delegated PUT surfaces under the seam's
 *   `PreconditionFailedError` name, so lost races still map to
 *   `WebvhLogConflictError`.
 * - The companion generation machinery (`mintGenerationId` /
 *   `createCompanionLog` / `ensureCompanionSpace` /
 *   `mintCompanionGeneration` / `companionLogStore` / `companionLogPinId`)
 *   -- the disposable sidecar did:webvh holding transient per-visit
 *   verification methods: `gen-<random>` generation identity, the typed
 *   auxiliary companion Space, and the static-rung-0 genesis posture
 *   (prerotation on, no witnesses, portability off, a bare zero-VM
 *   document; the log publishes first, the account document's
 *   `#DelegatedClients` pointer moves second).
 * - `repairKeyBindings` -- the lost-`keys.json` recovery path.
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
  BYOE_CONTEXT_URL,
  clientKeyAgreementController,
  commitmentMatchesKey,
  createLadderAnchoredWebvhLog,
  didWebvhControllerTemplate,
  ensureDidWebvh,
  enrollWebvhClient,
  keyAgreementCommitment,
  keyAgreementTwinMultibase,
  ladderVerificationMethod,
  MULTIKEY_COMMITMENT_VM_TYPE,
  markedVerificationMethodPair,
  mintClientWebvhUpdateKeys,
  relationIds,
  repairKeyBindings,
  rotateWebvhUpdateKey,
  updateKeyMultibase,
  WebvhLogConflictError,
  withLogConflictRetry
} from './didWebvh.js'
export {
  accountLogPinId,
  AccountLogMissingError,
  verifyAccountLog
} from './verifyLog.js'
export { wasWebvhIdStore, wasWebvhLogStore } from './wasIdStore.js'
export type { WebvhLogResourceStore } from './wasIdStore.js'
export { delegatedWebvhLogStore } from './delegatedLogStore.js'
export type { DelegatedWebvhLogStore } from './delegatedLogStore.js'
export {
  assertGenerationId,
  clampGrantExpires,
  COMPANION_SPACE_TYPE,
  companionDidParts,
  companionLogPinId,
  companionLogStore,
  CompanionRungUncommittedError,
  createCompanionLog,
  DELEGATED_CLIENTS_DELEGATION_ACTIONS,
  DELEGATED_CLIENTS_DELEGATION_TTL_MS,
  DELEGATED_CLIENTS_SERVICE_TYPE,
  delegatedClientsDelegationSpaceId,
  delegatedClientsPointer,
  delegatedClientsServiceEntry,
  embeddedGenerationDelegation,
  enrollCompanionTransientClient,
  enrollTransientClient,
  ensureCompanionSpace,
  ensureGenerationDelegationCurrent,
  GENERATION_DELEGATION_ACTIONS,
  GENERATION_DELEGATION_SERVICE_TYPE,
  GENERATION_DELEGATION_TTL_MS,
  GENERATION_ID_PREFIX,
  generationDelegationServiceEntry,
  mintCompanionGeneration,
  mintCredentialCompanionGeneration,
  mintDelegatedClientsDelegation,
  mintGenerationDelegation,
  mintGenerationId,
  setDelegatedClientsPointer
} from './companion.js'
export type { CompanionWriteStore } from './companion.js'
export {
  companionGcDue,
  delegatedClientsPointerEstablishedAt,
  GENERATION_GC_PERIOD_MS,
  GENERATION_QUIET_BOUND_MS,
  GENERATION_QUIET_GRACE_MS,
  generationQuiet,
  runCompanionGc
} from './companionGc.js'
export type {
  CompanionGcReport,
  CompanionGcSwapOutcome
} from './companionGc.js'
export {
  STANDING_ZCAP_TTL_MS,
  ZCAP_RENEWAL_WINDOW_MS,
  zcapExpiring
} from './standingZcap.js'
export {
  attributeClientUpdateKey,
  delegationKeyInDocument,
  documentKeyMultibases,
  ladderVmIds,
  listEnrolledWebvhClients,
  markedKeyAgreementMethods,
  markedKeyAgreementMultibases
} from './listClients.js'
export type {
  EnrolledWebvhClient,
  PublishedKeyDocument
} from './listClients.js'
export { resolvedKeyAgreementMethods } from './keyAgreement.js'
export type { KeyAgreementDocument } from './keyAgreement.js'
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
  ladderVmAgent,
  ladderVmZcapClient,
  webvhCapabilityAgent,
  webvhSigner,
  webvhZcapClient
} from './zcap.js'
export type { ICapabilityAgent } from './zcap.js'
