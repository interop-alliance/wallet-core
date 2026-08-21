/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/unlock` subpath: standing unlock credentials --
 * every unlock method (passphrase, passkey PRF, recovery code) as a standing
 * credential in the recovery-code posture, with self-enrolling login. The
 * recovery subpath's spend-on-use flows sit on top of the machinery here.
 *
 * - `standingClientFromUnlockSeed` / `unlockClientIdentityFromSeed` -- the
 *   deterministic client identity a credential derives (roster wrap target,
 *   binding MAC key), shared with the recovery-code derivation.
 * - `generateLadderSeed` / `ladderRung` / `attributeLadderRung` -- the
 *   update-key ladder: latent-and-consumed did:webvh update authority from a
 *   random seed carried in the unlock record, current rung recovered from the
 *   log itself, ambiguity failing closed. `ladderVmKeyMultibase` derives the
 *   ladder VM (the stable sibling), the document-visible key a ladder-anchored
 *   account anchors on.
 * - `createLadderAnchoredAccountLog` -- the ladder-anchored genesis log: an
 *   account with zero enrolled durable clients, `updateKeys` = [rung 0], the ladder
 *   VM under `assertionMethod` and `capabilityDelegation` only, and the
 *   credential's `keyAgreement` posture folded into genesis. The window it
 *   opens is closed atomically by the first durable self-enrollment's add
 *   entry.
 * - `wrapUnlockRecord` / `unwrapUnlockRecord` / `remintUnlockRecordDelegations`
 *   -- the unlock record codec: the credential-authenticated shell-and-core
 *   layout (controller, email, pointer under the binding MAC; the bridge and
 *   companion-Space `delegatedClients` delegations re-mintable; the ladder
 *   seed sealed and carried verbatim).
 * - `publishUnlockKey` / `removeUnlockKey` -- the merged document posture
 *   edit, parameterized by credential class: a verbatim `keyAgreement` entry,
 *   or a `MultikeyCommitment` entry for a low-entropy-derived key.
 * - `retireUnlockCredential` -- the retirement ceremony behind "change my
 *   passphrase" and "remove this passkey": the posture edit, then the shared
 *   roster rotation and collection fan-out off the retired credential's wrap.
 * - `selfEnrollWebvhClient` / `selfEnrollClientCore` -- the self-enrolling
 *   continuation (reveal a rung, add an ordinary client, retire the rung) and
 *   the composed completion a fresh browser runs end to end.
 * - `forgetWebvhClient` / `forgetDurableClient` -- self-enrollment in
 *   reverse: one atomic ladder-signed removal entry through the bridge, and
 *   the forget ceremony around it (roster rotation and collection fan-out
 *   BEFORE the entry -- the self-forget inversion). The last enrolled durable
 *   client refuses (`LastDurableClientForgetError`); its forget is the
 *   ladder-anchored transition, a separate ceremony.
 *
 * Kept out of the root export: this subpath pulls the webkms-client / ezcap /
 * was-client dependency graph (the same isolation pattern as `./keyring`).
 */
export {
  standingClientFromUnlockSeed,
  STANDING_CLIENT_SALT,
  unlockClientIdentityFromSeed
} from './standingClient.js'
export type {
  StandingUnlockClient,
  UnlockClientIdentity
} from './standingClient.js'

export {
  attributeLadderPosture,
  attributeLadderRung,
  companionRung,
  companionRungSeed,
  generateLadderSeed,
  LADDER_MAX_SCAN,
  LADDER_SEED_BYTES,
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
  computeUnlockBinding,
  remintUnlockRecordDelegations,
  UnlockBindingError,
  unlockRecordBinding,
  unwrapUnlockRecord,
  wrapUnlockRecord
} from './unlockRecord.js'
export type {
  SealedRecordMember,
  SignedUnlockRecord,
  UnlockRecordContents,
  UnlockRecordProofState
} from './unlockRecord.js'

export {
  createLadderAnchoredAccountLog,
  ensureLadderAnchoredDidWebvh,
  forgetWebvhClient,
  LastDurableClientForgetError,
  publishUnlockKey,
  removeUnlockKey,
  selfEnrollWebvhClient,
  unlockKeyVerificationMethod,
  unlockKeyVmId
} from './standingWebvh.js'
export type {
  StandingUnlockKeys,
  UnlockKeyAgreementPublication,
  UnlockLogStore
} from './standingWebvh.js'

export { retireUnlockCredential } from './retire.js'
export type {
  CompanionPostureRetirement,
  UnlockCredentialRetirementResult
} from './retire.js'

export { selfEnrollClientCore } from './selfEnroll.js'

export { forgetDurableClient } from './forget.js'
export type { DurableClientForgetResult } from './forget.js'
