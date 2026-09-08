/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A cheap stand-in for the passphrase parameter set, for tests whose subject
 * is a record codec or a ceremony rather than the KDF itself
 * (`keyring-kdf.test.ts` pins that one): an HKDF expansion in place of the
 * shipped memory-hard Argon2id stretch, which costs a 64 MiB allocation and a
 * visible fraction of a second per derivation.
 */
import type { UnlockKdf } from '../../../src/keyring/index.js'

export const FAST_KDF: UnlockKdf = {
  version: 1,
  algorithm: 'HKDF',
  hash: 'SHA-256',
  salt: 'wallet-core/test/keyring-record',
  info: 'unlock-seed'
}
