/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The unlock derivation: an unlock secret (a passphrase, or a passkey PRF
 * output) to the 32-byte unlock seed. `unlockIdentity.ts` expands that seed
 * into the unlock identity that locates an account's keyring record and
 * wraps/unwraps it. Nothing about the account is derivable from the secret.
 *
 * This file's only runtime imports are `@noble/hashes` modules, so an offline
 * caller that only derives a seed loads no identity or proof dependencies.
 * Keep it that way.
 *
 * The derivation is wire-level: two wallet apps must produce byte-identical
 * output for the same secret and parameter set, or the same passphrase would
 * address two different unlock Spaces. It is therefore implemented over
 * `@noble/hashes` rather than WebCrypto's `crypto.subtle.deriveBits`, which
 * React Native does not provide; Argon2id and HKDF are both fully specified
 * (RFC 9106 / RFC 5869), so any two implementations agree bit for bit.
 */
import { argon2idAsync } from '@noble/hashes/argon2.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256, sha512 } from '@noble/hashes/sha2.js'

/**
 * The number of bytes an unlock derivation produces (a 32-byte seed, which is
 * what `CapabilityAgent.fromSeed` takes).
 */
const UNLOCK_SEED_BYTES = 32

/**
 * Unlock-derivation parameters, one variant per KDF family: Argon2id
 * (memory-hard) stretches a low-entropy passphrase; HKDF expands
 * already-uniform key material (e.g. a passkey PRF output). Each unlock method
 * pins its own parameter set -- and its own salt, so two methods can never
 * derive the same unlock identity. The `version` is one counter per unlock
 * method, recording which parameter set produced that method's derivation;
 * the keyring record's own `version` is stamped separately.
 *
 * The Argon2id arm carries no `hash` member: Argon2 fixes Blake2b internally.
 * `memory` is in KiB (RFC 9106's and noble's unit); the RFC's `m` / `t` / `p`
 * are named `memory` / `passes` / `parallelism`.
 */
export type UnlockKdf =
  | {
      version: number
      algorithm: 'Argon2id'
      memory: number
      passes: number
      parallelism: number
      salt: string
    }
  | {
      version: number
      algorithm: 'HKDF'
      hash: string
      salt: string
      info: string
    }

/**
 * Argon2id parameters for the passphrase unlock derivation
 * (`unlockSeed = Argon2id(passphrase)`): 64 MiB of memory, 3 passes,
 * parallelism 1, a 32-byte tag. The memory and pass counts are those of RFC
 * 9106 section 4's second recommended option (m = 64 MiB, t = 3, p = 4); the
 * parallelism is a deliberate departure from that option's four lanes. It
 * stays 1 because noble is single-threaded, so a higher value changes the
 * bytes and buys no speed. Passphrase version 2 pins exactly
 * these parameters; version 1 was PBKDF2-600k over SHA-256 under the salt
 * `freewallet/keyring/unlock/v1`, and it was replaced outright rather than
 * kept beside this set, so a passphrase bound under it no longer addresses
 * its unlock Space. The KDF's own `version` is what records the parameter
 * set: the keyring record's frame version is unchanged, since a record cannot
 * be read before its derivation has already succeeded, so a version inside it
 * could never steer a lookup. The salt is a fixed app-wide constant -- login
 * stays passphrase-only, with no email (or other) input mixed into the
 * derivation. Every unlock method's KDF carries a distinct salt, so two
 * methods can never derive the same unlock Space.
 */
export const KEYRING_KDF: UnlockKdf = {
  version: 2,
  algorithm: 'Argon2id',
  memory: 65_536,
  passes: 3,
  parallelism: 1,
  salt: 'freewallet/keyring/unlock/argon2id/v1'
}

/**
 * HKDF parameters for the backup credential's unlock derivation
 * (`unlockSeed = HKDF(secret)`), where the secret is the 32 random bytes a
 * backup bundle packs (`@interop/wallet-backup`'s `backup-credential.json`).
 * The bytes are uniform key material, so no memory-hard stretching is needed,
 * the same reasoning as the passkey's PRF output. The salt differs from every
 * other unlock method's, so a backup credential can never derive another
 * method's unlock Space; as with `KEYRING_KDF`, `version` pins the parameter
 * set and the salt is permanent: a changed salt orphans every credential a
 * bundle already packs.
 */
export const BACKUP_CREDENTIAL_KDF: UnlockKdf = {
  version: 1,
  algorithm: 'HKDF',
  hash: 'SHA-256',
  salt: 'freewallet/keyring/backup-credential/v1',
  info: 'freewallet/unlock-seed'
}

/**
 * The noble hash constructor a WebCrypto hash name selects for the HKDF arm,
 * so the derivation matches `crypto.subtle.deriveBits` for the same
 * parameters.
 *
 * @param hash {string}   a WebCrypto digest name (`SHA-256`, `SHA-512`)
 * @returns {object}   the noble hash
 */
function nobleHash(hash: string) {
  if (hash === 'SHA-256') {
    return sha256
  }
  if (hash === 'SHA-512') {
    return sha512
  }
  throw new Error(`Unsupported unlock KDF hash "${hash}".`)
}

/**
 * Derives the 32-byte unlock seed from an unlock secret, branching on the KDF
 * family: Argon2id stretches a passphrase, HKDF expands already-uniform key
 * material such as a passkey PRF output.
 *
 * Exported for the standing-credential derivation (`unlock/standingClient`):
 * a standing unlock method expands its client identity and binding MAC key
 * from this same seed under distinct HKDF salts, so the expensive stretch
 * runs once per typed secret.
 *
 * @param options {object}
 * @param options.secret {string | Uint8Array}
 * @param options.kdf {UnlockKdf}
 * @returns {Promise<Uint8Array>}
 */
export async function deriveUnlockSeed({
  secret,
  kdf
}: {
  secret: string | Uint8Array
  kdf: UnlockKdf
}): Promise<Uint8Array> {
  // Copy a bytes secret into a fresh buffer: a caller's slice may be a view
  // into a larger buffer, and the codecs below read the whole view.
  const secretBytes =
    typeof secret === 'string'
      ? new TextEncoder().encode(secret)
      : new Uint8Array(secret)
  const salt = new TextEncoder().encode(kdf.salt)
  if (kdf.algorithm === 'Argon2id') {
    return argon2idAsync(secretBytes, salt, {
      m: kdf.memory,
      t: kdf.passes,
      p: kdf.parallelism,
      dkLen: UNLOCK_SEED_BYTES
    })
  }
  return hkdf(
    nobleHash(kdf.hash),
    secretBytes,
    salt,
    new TextEncoder().encode(kdf.info),
    UNLOCK_SEED_BYTES
  )
}
