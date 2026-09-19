/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The user key's Ed25519 signing half: the seed derivation, the record signer
 * over it, and the public multibase a reader's allowlist holds. Kept apart from
 * `./userKey.js` because the record signer loads the keyring proof code, which
 * a caller that only mints or rebuilds the key-agreement half has no use for.
 */
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { recordSignerFromSeed } from '../keyring/record.js'
import type { RecordSigner } from '../keyring/record.js'
import { USER_KEY_SALT, type UserKey } from './userKey.js'

/**
 * The one info label under {@link USER_KEY_SALT}. Permanent, like the salt.
 */
const USER_KEY_SIGNING_INFO = 'signing'

/**
 * The number of bytes the signing expansion produces (a 32-byte Ed25519 seed).
 */
const USER_KEY_SIGNING_SEED_BYTES = 32

/**
 * Derives the 32-byte Ed25519 seed of the user key's signing half from the
 * key-agreement half's raw secret: HKDF-SHA256 under {@link USER_KEY_SALT},
 * info `signing`. Deterministic and wire-level -- the same user key always
 * yields the same signing key, which is what lets one holder sign a record
 * another holder verifies with nothing server-served in hand.
 *
 * @param options {object}
 * @param options.userKey {UserKey}
 * @returns {Uint8Array}
 */
export function userKeySigningSeed({
  userKey
}: {
  userKey: UserKey
}): Uint8Array {
  const encoder = new TextEncoder()
  return hkdf(
    sha256,
    userKey.secret,
    encoder.encode(USER_KEY_SALT),
    encoder.encode(USER_KEY_SIGNING_INFO),
    USER_KEY_SIGNING_SEED_BYTES
  )
}

/**
 * The user key's record signer: the keyring record's signing seam over the
 * derived Ed25519 half, for an app-side record sealed to the vault KAK
 * (`signRecordFrame`). Its `keyMultibase` is exactly what a reader's
 * allowlist holds, so a writer that already has the signer reads the multibase
 * off it rather than calling {@link userKeySigningKeyMultibase} as well.
 *
 * @param options {object}
 * @param options.userKey {UserKey}
 * @returns {Promise<RecordSigner>}
 */
export async function userKeyRecordSigner({
  userKey
}: {
  userKey: UserKey
}): Promise<RecordSigner> {
  return recordSignerFromSeed({ seed: userKeySigningSeed({ userKey }) })
}

/**
 * The public multibase of the user key's signing half: the one key a reader
 * accepts on a record sealed under this user key, handed to
 * `verifyRecordProof` as its allowlist. For a reader alone -- a writer takes
 * the same value off {@link userKeyRecordSigner}'s `keyMultibase`.
 *
 * @param options {object}
 * @param options.userKey {UserKey}
 * @returns {Promise<string>}
 */
export async function userKeySigningKeyMultibase({
  userKey
}: {
  userKey: UserKey
}): Promise<string> {
  const { keyMultibase } = await userKeyRecordSigner({ userKey })
  return keyMultibase
}
