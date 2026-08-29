/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/unlock` subpath: standing unlock credentials --
 * every unlock method (passphrase, passkey PRF, recovery code) as a standing
 * credential in the recovery-code configuration, with self-enrolling login. The
 * recovery subpath's spend-on-use flows sit on top of the machinery here.
 *
 * - `standingClientFromUnlockSeed` / `unlockClientIdentityFromSeed` -- the
 *   deterministic client identity a credential derives (roster wrap target,
 *   binding MAC key), shared with the recovery-code derivation.
 * - `wrapUnlockRecord` / `unwrapUnlockRecord` / `remintUnlockRecordDelegations`
 *   -- the unlock record codec: the credential-authenticated shell-and-core
 *   layout (controller, email, pointer under the binding MAC; the bridge and
 *   client-annex Space `delegatedClients` delegations re-mintable; the ladder
 *   seed sealed and carried verbatim, its `LADDER_SEED_BYTES` size owned by
 *   the record format).
 * - `publishUnlockKey` / `removeUnlockKey` -- the merged document inventory
 *   edit, parameterized by credential class: a verbatim `keyAgreement` entry,
 *   or a `MultikeyCommitment` entry for a low-entropy-derived key.
 * - `retireUnlockCredential` -- the retirement ceremony behind "change my
 *   passphrase" and "remove this passkey": the inventory edit, then the shared
 *   roster rotation and collection fan-out off the retired credential's wrap.
 *
 * The ladder itself, and every ceremony that exercises it (the ladder-anchored
 * genesis, self-enrollment, the forget ceremony), live in
 * `@interop/wallet-core/clientAnnex` -- what stays here is the inventory and
 * record machinery every wallet needs regardless of account configuration.
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
  computeUnlockBinding,
  LADDER_SEED_BYTES,
  recordSealedRecipientKeys,
  remintUnlockRecordDelegations,
  UnlockBindingError,
  unlockRecordBinding,
  unlockRecordSealedTo,
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
  LadderInventoryDriftError,
  publishUnlockKey,
  removeUnlockKey,
  unlockKeyVerificationMethod,
  unlockKeyVmId
} from './standingWebvh.js'
export type {
  LadderVmRemovalReport,
  StandingUnlockKeys,
  UnlockKeyAgreementPublication,
  UnlockLogStore
} from './standingWebvh.js'

export { retireUnlockCredential } from './retire.js'
export type {
  ClientAnnexInventoryRetirement,
  UnlockCredentialRetirementResult
} from './retire.js'
