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
 * - `wrapKeyringRecord` / `unwrapKeyringRecord` -- the `{ version, wrapped }`
 *   account-pointer record codec.
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
  parseRecordPointer,
  unwrapKeyringRecord,
  wrapKeyringRecord
} from './record.js'
export type { AccountPointer, KeyringRecordContents } from './record.js'

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
