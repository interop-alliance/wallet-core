/**
 * Unit tests for the unlock derivation (`src/keyring/kdf.ts`). The derivation
 * is wire-level -- the same secret must address the same unlock Space in every
 * wallet app -- and it is implemented over `@noble/hashes` because React
 * Native has no `crypto.subtle.deriveBits`. These tests cross-check that
 * implementation against WebCrypto's for the PBKDF2 and HKDF families at
 * realistic parameters, check the Argon2id implementation against RFC 9106's
 * published vector (WebCrypto has no Argon2), so a divergence can never ship
 * silently, and pin the unlock Space id derivation, the shipped Argon2id
 * parameter set, and the bytes it derives for one fixed passphrase.
 */
import { describe, expect, it } from 'vitest'
import { webcrypto } from 'node:crypto'
import { deriveSpaceId } from '@interop/was-client/sync'
import { argon2idAsync } from '@noble/hashes/argon2.js'
import { base64urlnopad, hex } from '@scure/base'
import {
  deriveUnlockIdentity,
  deriveUnlockSeed,
  KEYRING_KDF,
  unlockSpaceIdFor,
  type UnlockKdf
} from '../../src/keyring/kdf.js'

const subtle = webcrypto.subtle

/**
 * The 32-byte unlock seed WebCrypto derives for a parameter set -- the
 * reference implementation the shipped derivation must match byte for byte.
 */
async function webCryptoUnlockSeed({
  secret,
  kdf
}: {
  secret: string | Uint8Array
  kdf: UnlockKdf
}): Promise<Uint8Array> {
  const secretBytes =
    typeof secret === 'string'
      ? new TextEncoder().encode(secret)
      : new Uint8Array(secret)
  const salt = new TextEncoder().encode(kdf.salt)
  if (kdf.algorithm === 'PBKDF2') {
    const baseKey = await subtle.importKey(
      'raw',
      secretBytes,
      'PBKDF2',
      false,
      ['deriveBits']
    )
    const bits = await subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations: kdf.iterations,
        hash: kdf.hash
      },
      baseKey,
      256
    )
    return new Uint8Array(bits)
  }
  if (kdf.algorithm !== 'HKDF') {
    throw new Error('WebCrypto has no Argon2 to cross-check against.')
  }
  const baseKey = await subtle.importKey('raw', secretBytes, 'HKDF', false, [
    'deriveBits'
  ])
  const bits = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: kdf.hash,
      salt,
      info: new TextEncoder().encode(kdf.info)
    },
    baseKey,
    256
  )
  return new Uint8Array(bits)
}

/**
 * The seed behind a derived identity, recovered from the identity itself: two
 * derivations agree exactly when their unlock Space ids (and therefore their
 * did:keys) agree, which is the property that matters on the wire.
 */
async function unlockSpaceIdFromSeed(seed: Uint8Array): Promise<string> {
  const { CapabilityAgent } = await import('@interop/webkms-client')
  const agent = await CapabilityAgent.fromSeed({
    seed,
    handle: 'unlock',
    keyName: 'unlock-key'
  })
  return unlockSpaceIdFor({ did: agent.id })
}

describe('the unlock derivation matches WebCrypto', () => {
  it('PBKDF2 at the retired passphrase version 1 parameters (600k iterations, SHA-256)', async () => {
    const kdf: UnlockKdf = {
      version: 1,
      algorithm: 'PBKDF2',
      iterations: 600_000,
      hash: 'SHA-256',
      salt: 'freewallet/keyring/unlock/v1'
    }
    const secret = 'correct horse battery staple'
    const derived = await deriveUnlockIdentity({ secret, kdf })
    const reference = await webCryptoUnlockSeed({ secret, kdf })

    expect(derived.spaceId).toBe(await unlockSpaceIdFromSeed(reference))
  }, 30_000)

  it('PBKDF2 with SHA-512 and a different salt/iteration count', async () => {
    const kdf: UnlockKdf = {
      version: 1,
      algorithm: 'PBKDF2',
      iterations: 10_000,
      hash: 'SHA-512',
      salt: 'wallet-core/test/pbkdf2'
    }
    const secret = 'a passphrase with unicode: passe-partout'
    const derived = await deriveUnlockIdentity({ secret, kdf })
    const reference = await webCryptoUnlockSeed({ secret, kdf })

    expect(derived.spaceId).toBe(await unlockSpaceIdFromSeed(reference))
  })

  it('HKDF over a passkey-PRF-shaped 32-byte secret', async () => {
    const kdf: UnlockKdf = {
      version: 1,
      algorithm: 'HKDF',
      hash: 'SHA-256',
      salt: 'freewallet/keyring/passkey/v1',
      info: 'freewallet/unlock-seed'
    }
    const secret = new Uint8Array(32)
    for (let index = 0; index < secret.length; index++) {
      secret[index] = (index * 7 + 3) % 256
    }
    const derived = await deriveUnlockIdentity({ secret, kdf })
    const reference = await webCryptoUnlockSeed({ secret, kdf })

    expect(derived.spaceId).toBe(await unlockSpaceIdFromSeed(reference))
  })
})

describe('the Argon2id derivation', () => {
  it('matches RFC 9106 section 5.3 (the published Argon2id vector)', async () => {
    // The vector mixes in a secret key and associated data, which the unlock
    // derivation never uses, so it runs against the library under exactly the
    // option mapping `deriveUnlockSeed` applies (`m` KiB, `t` passes, `p`).
    const out = await argon2idAsync(
      new Uint8Array(32).fill(0x01),
      new Uint8Array(16).fill(0x02),
      {
        m: 32,
        t: 3,
        p: 4,
        dkLen: 32,
        key: new Uint8Array(8).fill(0x03),
        personalization: new Uint8Array(12).fill(0x04)
      }
    )
    expect(hex.encode(out)).toBe(
      '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659'
    )
  })

  it('derives the same bytes through deriveUnlockSeed as the library does', async () => {
    // Distinct pass and lane counts, so a transposed `t` / `p` mapping in
    // `deriveUnlockSeed` changes the bytes (equal counts derive identically).
    const kdf: UnlockKdf = {
      version: 2,
      algorithm: 'Argon2id',
      memory: 64,
      passes: 2,
      parallelism: 3,
      salt: 'wallet-core/test/argon2id'
    }
    const secret = 'a passphrase with unicode: passe-partout'
    const derived = await deriveUnlockSeed({ secret, kdf })
    const reference = await argon2idAsync(
      new TextEncoder().encode(secret),
      new TextEncoder().encode(kdf.salt),
      { m: 64, t: 2, p: 3, dkLen: 32 }
    )
    expect(hex.encode(derived)).toBe(hex.encode(reference))
  })
})

describe('the shipped unlock parameter set', () => {
  it('pins the wire-level Argon2id parameters', () => {
    expect(KEYRING_KDF).toEqual({
      version: 2,
      algorithm: 'Argon2id',
      memory: 65_536,
      passes: 3,
      parallelism: 1,
      salt: 'freewallet/keyring/unlock/argon2id/v1'
    })
  })

  it('pins the bytes one fixed passphrase derives under the frozen set', async () => {
    // The byte-for-byte guarantee the other wallet app relies on: the same
    // passphrase must address the same unlock Space from every replica. The
    // frozen hex was confirmed against the reference C implementation
    // (libargon2, `argon2id_hash_raw` at m = 65536, t = 3, p = 1), so it
    // pins the parameter set independently of noble.
    const seed = await deriveUnlockSeed({
      secret: 'correct horse battery staple',
      kdf: KEYRING_KDF
    })
    expect(hex.encode(seed)).toBe(
      '9a21d3b6e2dc1285869468725dc68b2f75ae15e2297e50daa0d0e62762430b1e'
    )
  }, 30_000)

  it('refuses an unsupported hash rather than deriving something else', async () => {
    await expect(
      deriveUnlockIdentity({
        secret: 'x',
        kdf: {
          version: 1,
          algorithm: 'HKDF',
          hash: 'SHA-1',
          salt: 's',
          info: 'i'
        }
      })
    ).rejects.toThrow('Unsupported unlock KDF hash')
  })
})

describe('unlockSpaceIdFor', () => {
  const did = 'did:key:z6MkExampleUnlockIdentity'

  it('is the unpadded base64url of SHA-256 over the did', async () => {
    const digest = new Uint8Array(
      await subtle.digest('SHA-256', new TextEncoder().encode(did))
    )
    expect(unlockSpaceIdFor({ did })).toBe(base64urlnopad.encode(digest))
  })

  it('is byte-identical to was-client deriveSpaceId over the did', () => {
    // Pinned against the shared derivation itself, not a frozen literal: the
    // unlock Space address is every account's one durable locator, so the two
    // must never drift apart.
    expect(unlockSpaceIdFor({ did })).toBe(deriveSpaceId(did))
  })
})
