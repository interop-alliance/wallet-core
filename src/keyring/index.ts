/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/keyring` subpath: the unlock layer -- how an
 * unlock secret (a passphrase, a passkey PRF output) locates an account
 * without authorizing anything against it.
 *
 * - `deriveUnlockIdentity` / `KEYRING_KDF` / `unlockSpaceIdFor` -- the
 *   wire-level unlock derivation (implemented over `@noble/hashes`, so it runs
 *   unchanged where WebCrypto's `deriveBits` is unavailable) and the unlock
 *   Space addressing convention.
 * - `wrapKeyringRecord` / `unwrapKeyringRecord` -- the
 *   `{ version, encryption, wrapped, proof }` account-pointer record codec.
 * - `recordSignerFromAgent` / `signRecordFrame` / `verifyRecordProof` /
 *   `RecordProofError` -- the record's authenticity layer: the proof over the
 *   frame members by the unlock identity's signing key, verified before any
 *   decryption, so a storage host cannot substitute a record it sealed itself.
 * - `mintRecordEncryption` / `recordCipher` / `parseRecordFrame` /
 *   `parseRecordCreatedAt` -- the record-own-epoch envelope construction the
 *   codec seals with plus the frame and plaintext validation it opens with,
 *   exported so an app's own locally stored records seal and unseal the same
 *   way (under their own cipher context) rather than re-deriving the
 *   construction.
 * - `ensureUnlockSpace` / `getUnlockKeyring` / `putUnlockKeyring` /
 *   `deleteUnlockSpace` / `deleteUnlockSpaceWithCapability` -- the unlock
 *   Space's lifecycle and its one resource.
 * - `fetchKeyringRecord` -- the composed lookup (derive, read, unwrap); an
 *   app's caching, pinning, and client-key persistence wrap around it.
 *
 * Kept out of the root export: this subpath pulls the webkms-client / ezcap /
 * was-client dependency graph (the same isolation pattern as `./identity`).
 */
export {
  deriveUnlockIdentity,
  KEYRING_KDF,
  UNLOCK_HANDLE,
  UNLOCK_KEY_NAME,
  unlockSpaceIdFor
} from './kdf.js'
export type { UnlockIdentity, UnlockKdf } from './kdf.js'

export {
  KEYRING_RECORD_VERSION,
  mintRecordEncryption,
  parseRecordCreatedAt,
  parseRecordFrame,
  parseRecordPointer,
  recordCipher,
  RecordProofError,
  recordProofKeyMultibase,
  recordSignerFromAgent,
  signRecordFrame,
  unwrapKeyringRecord,
  verifyRecordProof,
  wrapKeyringRecord
} from './record.js'
export type {
  AccountPointer,
  KeyringRecordContents,
  RecordProof,
  RecordSigner,
  SignedRecord
} from './record.js'

export {
  deleteUnlockSpace,
  deleteUnlockSpaceWithCapability,
  ensureUnlockSpace,
  getUnlockKeyring,
  putUnlockKeyring,
  putUnlockKeyringWithCapability,
  UNLOCK_SPACE_NAME
} from './unlockSpace.js'

export { fetchKeyringRecord } from './fetch.js'
