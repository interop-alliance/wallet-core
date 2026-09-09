/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/recovery` subpath: recovery codes on the roster
 * identity model -- a code as a standing unlock credential that retires on
 * spend.
 *
 * - `generateRecoveryCode` / `formatRecoveryCode` / `normalizeRecoveryCode` /
 *   `decodeRecoveryCode` / `RECOVERY_KDF` -- the format layer and the code's
 *   own unlock-derivation parameter set (its salt distinct from every other
 *   unlock method's).
 * - `recoveryClientFromCode` -- the deterministic client key set: unlock
 *   identity, client seed (signing + key-agreement pair), binding MAC key,
 *   and the update-key ladder seed, whose rung 0 is the did:webvh update key
 *   whose hash stands pre-committed and whose VM signs the code's own bridge.
 * - The record codec lives in `@interop/wallet-core/unlock` now
 *   (`wrapUnlockRecord` / `unwrapUnlockRecord`, re-exported here): a
 *   recovery record is an unlock record with no ladder member (the code's
 *   ladder seed derives from the code bytes rather than riding the record) --
 *   the account pointer plus the pre-minted PUT-on-`did.jsonl` bridge
 *   delegation (never a seed, never a user key wrap), signed under the
 *   mixed-signer policy
 *   (the code's unlock key at issuance, an enrolled client's account key on
 *   a re-mint), with the account core authenticated by a MAC under a
 *   code-derived key, so a storage host can never redirect recovery at
 *   another account.
 * - `publishRecoveryKey` / `removeRecoveryKey` / `recoverWebvhClient` -- the
 *   document half: issuance's split configuration and revocation's removal (thin
 *   wrappers over the unlock subpath's merged inventory core) and the
 *   self-enrolling recovery continuation. Its ladder-anchored variant (the
 *   transient-recovery continuation, `recoverWebvhLadderAnchored`) lives in
 *   `@interop/wallet-core/clientAnnex`.
 * - `recoverySpendRetirementFromLog` -- the retirement report of a spend
 *   whose add-and-retire entry already stands, read back off the log: what a
 *   resume that never re-enters the continuation drops registry entries and
 *   deletes unlock Spaces for, and which retired credentials kept a rung.
 * - `delegateLogWrite` / `delegationProofKeyId` /
 *   `recordedDelegationFields` -- the authorization bridge: the pre-minted
 *   PUT-on-`did.jsonl` delegation builder, and the registry fields a record's
 *   delegations stand for. A bridge is signed by its own credential's ladder
 *   VM, so no ceremony re-mints another credential's.
 *
 * Kept out of the root export: this subpath pulls the capability-agent / ezcap /
 * was-client dependency graph (the same isolation pattern as `./keyring`).
 */
export {
  decodeRecoveryCode,
  formatRecoveryCode,
  generateRecoveryCode,
  normalizeRecoveryCode,
  RECOVERY_CODE_BYTES,
  RECOVERY_KDF,
  RecoveryCodeInvalidError,
  recoveryClientFromCode
} from './recoveryCode.js'
export type { RecoveryClient } from './recoveryCode.js'

export {
  computeUnlockBinding,
  remintUnlockRecordDelegations,
  UnlockBindingError,
  unlockRecordBinding,
  unwrapUnlockRecord,
  wrapUnlockRecord
} from '../unlock/unlockRecord.js'
export type {
  SignedUnlockRecord,
  UnlockRecordContents,
  UnlockRecordProofState
} from '../unlock/unlockRecord.js'

export {
  delegateLogWrite,
  delegationProofKeyId,
  RECOVERY_DELEGATION_TTL_MS,
  recordedDelegationFields,
  ZCAP_RENEWAL_WINDOW_MS,
  zcapExpiring
} from './recoveryDelegation.js'

export { recoverySpendRetirementFromLog } from './continuation.js'
export type { RecoverySpendRetirement } from './continuation.js'

export {
  publishRecoveryKey,
  recoverWebvhClient,
  RecoveryCredentialStandingError,
  RecoveryKeyNotCommittedError,
  recoveryVmId,
  removeRecoveryKey
} from './recoveryWebvh.js'
export type {
  RecoveryLogStore,
  RecoveryPublicKeys,
  ReplacementRecoveryPublicKeys
} from './recoveryWebvh.js'
