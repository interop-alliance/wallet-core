/**
 * Unit tests for the unlock derivation (`src/keyring/kdf.ts`). The derivation
 * is wire-level -- the same secret must address the same unlock Space in every
 * wallet app -- and it is implemented over `@noble/hashes` because React
 * Native has no `crypto.subtle.deriveBits`. These tests cross-check that
 * implementation against WebCrypto's for both KDF families at realistic
 * parameters, so a divergence can never ship silently, and pin the unlock
 * Space id derivation and the shipped PBKDF2 parameter set.
 */
import { describe, expect, it } from 'vitest'
import { webcrypto } from 'node:crypto'
import { base64urlnopad } from '@scure/base'
import {
  deriveUnlockIdentity,
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
  it('PBKDF2 at the shipped parameters (600k iterations, SHA-256)', async () => {
    const secret = 'correct horse battery staple'
    const derived = await deriveUnlockIdentity({ secret, kdf: KEYRING_KDF })
    const reference = await webCryptoUnlockSeed({ secret, kdf: KEYRING_KDF })

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

describe('the shipped unlock parameter set', () => {
  it('pins the wire-level PBKDF2 parameters', () => {
    expect(KEYRING_KDF).toEqual({
      version: 1,
      algorithm: 'PBKDF2',
      iterations: 600_000,
      hash: 'SHA-256',
      salt: 'freewallet/keyring/unlock/v1'
    })
  })

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
  it('is the unpadded base64url of SHA-256 over the did', async () => {
    const did = 'did:key:z6MkExampleUnlockIdentity'
    const digest = new Uint8Array(
      await subtle.digest('SHA-256', new TextEncoder().encode(did))
    )
    expect(unlockSpaceIdFor({ did })).toBe(base64urlnopad.encode(digest))
  })
})
