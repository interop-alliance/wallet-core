/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/recovery` subpath: recovery codes on the roster
 * identity model -- a code as a minimal always-enrolled wallet client.
 *
 * - `generateRecoveryCode` / `formatRecoveryCode` / `normalizeRecoveryCode` /
 *   `decodeRecoveryCode` / `RECOVERY_KDF` -- the format layer and the code's
 *   own unlock-derivation parameter set (its salt distinct from every other
 *   unlock method's).
 * - `recoveryClientFromCode` -- the deterministic client key set:
 *   unlock identity, client seed (signing + key-agreement pair), and the
 *   single did:webvh update key whose hash stands pre-committed.
 * - The record codec lives in `@interop/wallet-core/unlock` now
 *   (`wrapUnlockRecord` / `unwrapUnlockRecord`, re-exported here): a
 *   recovery record is an unlock record with no ladder member -- the account
 *   pointer plus the pre-minted PUT-on-`did.jsonl` bridge delegation (never
 *   a seed, never a user key wrap), signed under the mixed-signer policy
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
 * - `delegateLogWrite` / `delegationProofKeyId` /
 *   `remintRecoveryDelegations` -- the authorization bridge: the pre-minted
 *   PUT-on-`did.jsonl` delegation builder and the revocation cascade's
 *   re-mint of the delegations a document edit rotted, behind injected
 *   app seams (management-zcap client factory, storage URL, registry
 *   read/record).
 *
 * Kept out of the root export: this subpath pulls the webkms-client / ezcap /
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
  remintRecoveryDelegations,
  ZCAP_RENEWAL_WINDOW_MS,
  zcapExpiring
} from './recoveryDelegation.js'
export type {
  RecordRemintOutcome,
  RecoveryDelegationEntry
} from './recoveryDelegation.js'

export {
  publishRecoveryKey,
  recoverWebvhClient,
  RecoveryKeyNotCommittedError,
  recoveryVmId,
  removeRecoveryKey
} from './recoveryWebvh.js'
export type { RecoveryLogStore, RecoveryPublicKeys } from './recoveryWebvh.js'
