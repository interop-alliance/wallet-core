/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The unlock derivation: an unlock secret (a passphrase, or a passkey PRF
 * output) to the unlock identity that locates an account's keyring record and
 * wraps/unwraps it. Nothing about the account is derivable from the secret --
 * the identity's only jobs are addressing the minimal unlock Space and holding
 * the key-agreement key the keyring record is encrypted to.
 *
 * The derivation is wire-level: two wallet apps must produce byte-identical
 * output for the same secret and parameter set, or the same passphrase would
 * address two different unlock Spaces. It is therefore implemented over
 * `@noble/hashes` rather than WebCrypto's `crypto.subtle.deriveBits`, which
 * React Native does not provide; PBKDF2 and HKDF are both fully specified
 * (RFC 8018 / RFC 5869), so the two implementations agree bit for bit.
 */
import { CapabilityAgent } from '@interop/webkms-client'
import { base64urlnopad } from '@scure/base'
import { hkdf } from '@noble/hashes/hkdf.js'
import { pbkdf2Async } from '@noble/hashes/pbkdf2.js'
import { sha256, sha512 } from '@noble/hashes/sha2.js'
import { agentsFromKeyAgent } from '../identity/agents.js'
import { recordSignerFromAgent } from './record.js'

/**
 * The load-bearing `CapabilityAgent` derivation names for an unlock identity
 * (the counterpart of the data identity's bootstrap names): every unlock
 * derivation runs through these exact strings, so they can never change
 * without stranding existing accounts.
 */
export const UNLOCK_HANDLE = 'unlock'
export const UNLOCK_KEY_NAME = 'unlock-key'

/**
 * The number of bytes an unlock derivation produces (a 32-byte seed, which is
 * what `CapabilityAgent.fromSeed` takes).
 */
const UNLOCK_SEED_BYTES = 32

/**
 * Unlock-derivation parameters, one variant per KDF family: PBKDF2 stretches
 * a low-entropy passphrase; HKDF expands already-uniform key material (e.g. a
 * passkey PRF output). Each unlock method pins its own parameter set -- and
 * its own salt, so two methods can never derive the same unlock identity.
 * The `version` records which parameter set produced a derivation; the
 * keyring record's own `version` is stamped separately.
 */
export type UnlockKdf =
  | {
      version: number
      algorithm: 'PBKDF2'
      iterations: number
      hash: string
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
 * PBKDF2 parameters for the passphrase unlock derivation
 * (`unlockSeed = PBKDF2(passphrase)`). Version 1 pins exactly these
 * parameters; the keyring record's `version` field records which set produced
 * it, so changing any of them (iterations, hash, salt) requires minting a new
 * record version rather than silently breaking existing unlock derivations.
 * The salt is a fixed app-wide constant -- login stays passphrase-only, with
 * no email (or other) input mixed into the derivation. Every unlock method's
 * KDF carries a distinct salt, so two methods can never derive the same
 * unlock Space.
 */
export const KEYRING_KDF: UnlockKdf = {
  version: 1,
  algorithm: 'PBKDF2',
  iterations: 600_000,
  hash: 'SHA-256',
  salt: 'freewallet/keyring/unlock/v1'
}

/**
 * The noble hash constructor a WebCrypto hash name selects, so the derivation
 * matches `crypto.subtle.deriveBits` for the same parameters.
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
 * family: PBKDF2 stretches a passphrase, HKDF expands already-uniform key
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
  const hash = nobleHash(kdf.hash)
  const salt = new TextEncoder().encode(kdf.salt)
  if (kdf.algorithm === 'PBKDF2') {
    return pbkdf2Async(hash, secretBytes, salt, {
      c: kdf.iterations,
      dkLen: UNLOCK_SEED_BYTES
    })
  }
  return hkdf(
    hash,
    secretBytes,
    salt,
    new TextEncoder().encode(kdf.info),
    UNLOCK_SEED_BYTES
  )
}

/**
 * Derives the full unlock identity from an unlock secret: the unlock
 * CapabilityAgent, a ZcapClient that can both invoke and delegate (the
 * unlock agent delegates a management zcap on its own Space to the account
 * controller at bind time), the unlock KAK + resolver for wrap/unwrap, the
 * record signer that signs and verifies the keyring record's proof, and the
 * unlock Space id. Performs no I/O -- the derivation seam for tests and future
 * unlock methods.
 *
 * @param options {object}
 * @param options.secret {string | Uint8Array}
 * @param options.kdf {UnlockKdf}
 * @returns {Promise<object>}
 */
export async function deriveUnlockIdentity({
  secret,
  kdf
}: {
  secret: string | Uint8Array
  kdf: UnlockKdf
}) {
  const seed = await deriveUnlockSeed({ secret, kdf })
  return unlockIdentityFromSeed({ seed })
}

/**
 * Assembles the unlock identity from an already-derived 32-byte unlock seed.
 * The seam that lets an app run the expensive stretch once per typed secret:
 * `deriveUnlockSeed` yields the seed, and both this assembly and the
 * standing-credential expansion (`unlock/standingClient`) consume it.
 *
 * @param options {object}
 * @param options.seed {Uint8Array}   the method's 32-byte unlock seed
 * @returns {Promise<object>}
 */
export async function unlockIdentityFromSeed({ seed }: { seed: Uint8Array }) {
  const agent = await CapabilityAgent.fromSeed({
    seed,
    handle: UNLOCK_HANDLE,
    keyName: UNLOCK_KEY_NAME
  })
  // The unlock KAK is the Montgomery form of the unlock signing key -- the same
  // derivation the client side uses (`agentsFromSeed`), so a returning user
  // reconstitutes the exact key that wrapped the keyring record.
  const { zcapClient, keyAgreementKey, keyResolver } = agentsFromKeyAgent({
    keyAgent: agent
  })

  // The record signer is the unlock signing key itself, named by its public
  // multibase: the keyring record's proof is made and checked against a key
  // that derives from the secret, so the storage host never holds it and a
  // fresh client holds the verification prior by construction.
  const recordSigner = recordSignerFromAgent({ keyAgent: agent })

  const spaceId = unlockSpaceIdFor({ did: agent.id })
  return {
    agent,
    zcapClient,
    keyAgreementKey,
    keyResolver,
    recordSigner,
    spaceId
  }
}

/**
 * The unlock Space id an unlock identity addresses:
 * `base64url(SHA-256(did))`, unpadded -- a discovery convention, not an
 * authorization one (holding the id grants nothing).
 *
 * @param options {object}
 * @param options.did {string}   the unlock identity's did:key
 * @returns {string}
 */
export function unlockSpaceIdFor({ did }: { did: string }): string {
  return base64urlnopad.encode(sha256(new TextEncoder().encode(did)))
}

/**
 * The derived unlock identity, as `deriveUnlockIdentity` returns it.
 */
export type UnlockIdentity = Awaited<ReturnType<typeof deriveUnlockIdentity>>
