/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/clientAnnex` subpath: the client annex -- the
 * authoring and maintenance surface of everything anchored on a standing
 * credential's ladder rather than on an enrolled durable client. One boundary
 * rule holds throughout: this subpath imports from the base subpaths;
 * nothing in the base imports from it (enforced in the lint pass, with one
 * pinned exception -- `unlock/standingWebvh.ts` uses the shared ladder
 * attribution helpers here, never the annex log machinery). The verify-side
 * halves every wallet needs regardless of posture stay in the base: the
 * resource-log ladder-append license and `ControllerPosture` ladder-key
 * computation (`resourceLog`), `ladderVmIds` recognition (`webvh`), the
 * unlock-record codec with its `ladder` and `delegatedClients` members
 * (`unlock`), the standing-zcap staleness policy and the generalized log
 * store seams (`webvh`), and the `GenerationCollect` activity builder
 * (`space`).
 *
 * - The ladder (`ladder.ts`): rung and ladder-VM derivation from the record's
 *   random seed, and the shared attribution walks (`attributeLadderRung`,
 *   `attributeLadderPosture`) that recover the ladder's state from the
 *   published log itself.
 * - The annex log (`log.ts`) and its GC (`gc.ts`): the disposable sidecar
 *   did:webvh of GC'd generations holding transient per-visit verification
 *   methods, the generation delegation, the account document's
 *   `#DelegatedClients` pointer, and the quarterly swap-and-collect.
 * - ZCap signing as the ladder VM (`zcap.ts`): `ladderVmZcapClient` and the
 *   bootstrap `ladderVmAgent`.
 * - The ladder-anchored account-log ceremonies (`ladderAnchored.ts`):
 *   ladder-anchored genesis, the self-enrolling continuation, the one-entry
 *   forget -- plus the composed flows around them (`selfEnroll.ts`,
 *   `forget.ts`), the credential-anchored account genesis
 *   (`credentialAnchoredGenesis.ts`), and the transient-recovery
 *   continuation (`recoveryLadderAnchored.ts`).
 *
 * The subsystem's decision records are the subpath's reading list:
 * `decisions/0002` (annex log update authority is static rung 0),
 * `decisions/0003` (generation identity and the ladder HKDF label family),
 * `decisions/0005` (the `delegatedClients` sealed record member),
 * `decisions/0006` (generation GC observables and the `GenerationCollect`
 * digest), and `decisions/0007` (the reveal entry's hash order).
 */
export {
  attributeLadderPosture,
  attributeLadderRung,
  clientAnnexRung,
  clientAnnexRungSeed,
  generateLadderSeed,
  LADDER_MAX_SCAN,
  LadderAttributionError,
  ladderRung,
  ladderRungSeed,
  ladderVmKeyMultibase,
  ladderVmSeed
} from './ladder.js'
export type {
  LadderRung,
  LadderRungState,
  LadderStandingPosture
} from './ladder.js'

export {
  assertGenerationId,
  clampGrantExpires,
  CLIENT_ANNEX_SPACE_TYPE,
  clientAnnexDidParts,
  clientAnnexLogPinId,
  clientAnnexLogStore,
  ClientAnnexRungUncommittedError,
  commitClientAnnexRung,
  createClientAnnexLog,
  DELEGATED_CLIENTS_DELEGATION_ACTIONS,
  DELEGATED_CLIENTS_DELEGATION_TTL_MS,
  DELEGATED_CLIENTS_SERVICE_TYPE,
  delegatedClientsDelegationMinter,
  delegatedClientsDelegationSpaceId,
  delegatedClientsPointer,
  delegatedClientsServiceEntry,
  embeddedGenerationDelegation,
  enrollClientAnnexTransientClient,
  enrollTransientClient,
  ensureClientAnnexSpace,
  ensureGenerationDelegationCurrent,
  GENERATION_DELEGATION_ACTIONS,
  GENERATION_DELEGATION_SERVICE_TYPE,
  GENERATION_DELEGATION_TTL_MS,
  GENERATION_ID_PREFIX,
  generationDelegationHistory,
  generationDelegationServiceEntry,
  mintClientAnnexGeneration,
  mintCredentialClientAnnexGeneration,
  mintDelegatedClientsDelegation,
  mintGenerationDelegation,
  mintGenerationId,
  retireClientAnnexRung,
  revokeTreatingAlreadyRevokedAsSuccess,
  servicesPointedAtClientAnnex,
  setDelegatedClientsPointer
} from './log.js'
export type { ClientAnnexWriteStore } from './log.js'

export {
  clientAnnexGcDue,
  delegatedClientsPointerEstablishedAt,
  GENERATION_GC_PERIOD_MS,
  GENERATION_QUIET_BOUND_MS,
  GENERATION_QUIET_GRACE_MS,
  generationQuiet,
  runClientAnnexGc,
  swapClientAnnexGeneration
} from './gc.js'
export type { ClientAnnexGcReport, ClientAnnexGcSwapOutcome } from './gc.js'

export { ladderVmAgent, ladderVmZcapClient } from './zcap.js'

export {
  createLadderAnchoredAccountLog,
  ensureLadderAnchoredDidWebvh,
  forgetLastWebvhClient,
  forgetWebvhClient,
  installLadderVmWebvh,
  LastDurableClientForgetError,
  selfEnrollWebvhClient
} from './ladderAnchored.js'

export { selfEnrollClientCore } from './selfEnroll.js'

export { forgetDurableClient } from './forget.js'
export type { DurableClientForgetResult } from './forget.js'

export {
  forgetLastDurableClient,
  RecordRemintFailedError
} from './forgetLast.js'
export type {
  GenerationDelegationRetirement,
  LastDurableClientForgetResult,
  UnlockMethodsRemintReach
} from './forgetLast.js'

export {
  ensureCredentialAnchoredAccountGenesis,
  mintCredentialAnchoredAccountKeySet
} from './credentialAnchoredGenesis.js'

export { recoverWebvhLadderAnchored } from './recoveryLadderAnchored.js'

// The ladder VM's pure document builder and the ladder-anchored genesis log
// assembly stay defined in `webvh/didWebvh.ts` (the genesis document
// builder's two-armed clientKeys XOR ladderVm signature is base API, and the
// ladder arm calls `ladderVerificationMethod` internally), but this subpath
// is their public home.
export {
  createLadderAnchoredWebvhLog,
  ladderVerificationMethod
} from '../webvh/didWebvh.js'
