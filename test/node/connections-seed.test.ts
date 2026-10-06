/**
 * Unit tests for the pairwise seed's keyed tag
 * (`src/connections/resourceId.ts`: `connectionSeedTag`,
 * `verifyConnectionSeedTag`) and the pairwise did:key derived from a tagged
 * seed (`src/connections/didKey.ts`: `connectionDidKey`).
 */
import { describe, expect, it } from 'vitest'
import { SHA256HMACKey } from '@interop/data-integrity-core'
import { base64urlnopad } from '@scure/base'
import { agentsFromSeed } from '@interop/was-client/identity'
import {
  connectionDidKey,
  connectionSeedTag,
  decodeConnectionSeed,
  verifyConnectionSeedTag
} from '../../src/connections/index.js'
import {
  HMAC_KEY,
  OTHER_HMAC_KEY,
  OTHER_SEED,
  SEED,
  SEED_BYTES
} from './fixtures/memoryConnections.js'

describe('connectionSeedTag', () => {
  it('mints a 32-byte tag that verifies under the same key', async () => {
    const seedTag = await connectionSeedTag({ hmacKey: HMAC_KEY, seed: SEED })
    expect(decodeConnectionSeed(seedTag)).toHaveLength(32)
    expect(seedTag).toHaveLength(43)
    await expect(
      verifyConnectionSeedTag({ hmacKey: HMAC_KEY, seed: SEED, seedTag })
    ).resolves.toBe(true)
  })

  it('is deterministic and derives the same tag from a resolved key', async () => {
    const raw = await connectionSeedTag({ hmacKey: HMAC_KEY, seed: SEED })
    const resolved = await SHA256HMACKey.fromSecret({
      id: 'urn:uuid:blinding',
      secret: HMAC_KEY
    })
    await expect(
      connectionSeedTag({ hmacKey: resolved, seed: SEED })
    ).resolves.toBe(raw)
    await expect(
      connectionSeedTag({ hmacKey: HMAC_KEY, seed: SEED })
    ).resolves.toBe(raw)
  })

  it('fails over another seed, under another key, or on a malformed value', async () => {
    const seedTag = await connectionSeedTag({ hmacKey: HMAC_KEY, seed: SEED })
    await expect(
      verifyConnectionSeedTag({ hmacKey: HMAC_KEY, seed: OTHER_SEED, seedTag })
    ).resolves.toBe(false)
    await expect(
      verifyConnectionSeedTag({ hmacKey: OTHER_HMAC_KEY, seed: SEED, seedTag })
    ).resolves.toBe(false)
    await expect(
      verifyConnectionSeedTag({ hmacKey: HMAC_KEY, seed: 'short', seedTag })
    ).resolves.toBe(false)
    await expect(
      verifyConnectionSeedTag({ hmacKey: HMAC_KEY, seed: SEED, seedTag: 'x' })
    ).resolves.toBe(false)
  })

  it('keeps the seed arm apart from the resource id arms', async () => {
    // The tag's input is the prefix plus the raw seed bytes, so a tag is
    // never the MAC of a `did:` or `writer:` arm over the same key.
    const seedTag = await connectionSeedTag({ hmacKey: HMAC_KEY, seed: SEED })
    const prefix = new TextEncoder().encode('connections/v1|seed:')
    const input = new Uint8Array(prefix.length + SEED_BYTES.length)
    input.set(prefix)
    input.set(SEED_BYTES, prefix.length)
    const resolved = await SHA256HMACKey.fromSecret({
      id: 'urn:uuid:blinding',
      secret: HMAC_KEY
    })
    const mac = await resolved.sign({ data: input })
    expect(base64urlnopad.encode(mac)).toBe(seedTag)
  })

  it('refuses to tag a malformed seed', async () => {
    await expect(
      connectionSeedTag({ hmacKey: HMAC_KEY, seed: 'nope' })
    ).rejects.toThrow(TypeError)
  })
})

describe('connectionDidKey', () => {
  it('derives the did:key agentsFromSeed derives, deterministically', async () => {
    const seedTag = await connectionSeedTag({ hmacKey: HMAC_KEY, seed: SEED })
    const first = await connectionDidKey({
      hmacKey: HMAC_KEY,
      seed: SEED,
      seedTag
    })
    const second = await connectionDidKey({
      hmacKey: HMAC_KEY,
      seed: SEED,
      seedTag
    })
    const { controllerDid } = await agentsFromSeed({ seed: SEED_BYTES })
    expect(first.did).toBe(controllerDid)
    expect(second.did).toBe(first.did)
    expect(first.did.startsWith('did:key:z6Mk')).toBe(true)
    expect(first.keyAgent.id).toBe(first.did)
    expect(typeof first.zcapClient.delegate).toBe('function')
  })

  it('refuses a seed whose tag fails', async () => {
    const seedTag = await connectionSeedTag({ hmacKey: HMAC_KEY, seed: SEED })
    await expect(
      connectionDidKey({ hmacKey: OTHER_HMAC_KEY, seed: SEED, seedTag })
    ).rejects.toThrow(/seed tag does not verify/)
    await expect(
      connectionDidKey({ hmacKey: HMAC_KEY, seed: OTHER_SEED, seedTag })
    ).rejects.toThrow(/seed tag does not verify/)
  })
})
