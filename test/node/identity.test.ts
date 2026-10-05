/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The WAS identity derivation, homed at `@interop/was-client/identity`. The
 * fixture values are byte-critical: they pin the exact keys every account
 * derives through under the `'bootstrap'` / `'bootstrap-key'` names, run here
 * against the was-client home so any later was-client release stays
 * byte-identical. If any fixture here changes, existing wallets are stranded
 * -- that is a bug in the change, not in the test.
 */
import { describe, it, expect } from 'vitest'
import { CapabilityAgent } from '@interop/capability-agent'

import {
  BOOTSTRAP_HANDLE,
  BOOTSTRAP_KEY_NAME,
  agentsFromSecret,
  agentsFromSeed,
  singleKeyResolver
} from '@interop/was-client/identity'

const SECRET = 'test-passphrase'
// The fixture for the string-secret path (DCW profiles).
const SECRET_DID = 'did:key:z6MkpLgNBDTZxHy56eemacRARY5G7qFXJPy4KL9hyuQPcAk4'
const SECRET_KAK_PUB = 'z6LSjkbuR8aSb8JR37g4QZL7V7sTiwndu8WLNY7MsWGuXNfr'

// seed = bytes 0..31; the fixture for the seed path (Freewallet keyring /
// guest sessions).
const SEED = new Uint8Array(32).map((_, i) => i)
const SEED_DID = 'did:key:z6MkozBx9SvxwfZmNnu1dWfXtFLPRHMQWnsqAPHmJzcQZzUB'
const SEED_KAK_PUB = 'z6LScgAqXnkdmKURvGjcyYfxJEvPKvmLNYVjrDddQdh7j3Ce'

describe('bootstrap constants', () => {
  it('pins the derivation handle and key name', () => {
    expect(BOOTSTRAP_HANDLE).toBe('bootstrap')
    expect(BOOTSTRAP_KEY_NAME).toBe('bootstrap-key')
  })
})

describe('agentsFromSecret', () => {
  it('derives the app-fixture identity from a string secret', async () => {
    const agents = await agentsFromSecret({ secret: SECRET })
    expect(agents.keyAgent.id).toBe(SECRET_DID)
    expect(agents.keyAgreementKey.id).toBe(`${SECRET_DID}#${SECRET_KAK_PUB}`)
  })

  it('is deterministic across calls', async () => {
    const a = await agentsFromSecret({ secret: SECRET })
    const b = await agentsFromSecret({ secret: SECRET })
    expect(a.keyAgent.id).toBe(b.keyAgent.id)
    expect(a.keyAgreementKey.id).toBe(b.keyAgreementKey.id)
  })

  it('matches seedFromSecret + agentsFromSeed (the stored-seed path)', async () => {
    const seed = await CapabilityAgent.seedFromSecret({
      secret: SECRET,
      handle: BOOTSTRAP_HANDLE
    })
    const fromSeed = await agentsFromSeed({ seed })
    expect(fromSeed.keyAgent.id).toBe(SECRET_DID)
    expect(fromSeed.keyAgreementKey.id).toBe(`${SECRET_DID}#${SECRET_KAK_PUB}`)
  })
})

describe('agentsFromSeed', () => {
  it('derives the app-fixture identity from a 32-byte seed', async () => {
    const agents = await agentsFromSeed({ seed: SEED })
    expect(agents.keyAgent.id).toBe(SEED_DID)
    expect(agents.keyAgreementKey.id).toBe(`${SEED_DID}#${SEED_KAK_PUB}`)
  })

  it('does NOT equal hashing the seed as a secret (fromSeed skips the salted hash)', async () => {
    const viaSeed = await agentsFromSeed({ seed: SEED })
    const viaSecret = await agentsFromSecret({
      secret: new TextDecoder().decode(SEED)
    })
    expect(viaSecret.keyAgent.id).not.toBe(viaSeed.keyAgent.id)
  })
})

describe('derived agents shape', () => {
  it('wires the ZcapClient with the bootstrap signer for invocation and delegation', async () => {
    const agents = await agentsFromSecret({ secret: SECRET })
    const signer = agents.keyAgent.getSigner()
    expect(signer.id.startsWith(`${SECRET_DID}#`)).toBe(true)
    const zcap = agents.zcapClient as unknown as {
      invocationSigner: { id: string }
      delegationSigner: { id: string }
    }
    expect(zcap.invocationSigner.id).toBe(signer.id)
    expect(zcap.delegationSigner.id).toBe(signer.id)
  })

  it('resolves its own KAK through the bundled keyResolver and rejects others', async () => {
    const agents = await agentsFromSecret({ secret: SECRET })
    const resolved = await agents.keyResolver({
      id: agents.keyAgreementKey.id
    })
    expect(resolved).toEqual({
      id: agents.keyAgreementKey.id,
      type: 'X25519KeyAgreementKey2020',
      publicKeyMultibase: SECRET_KAK_PUB
    })
    await expect(
      agents.keyResolver({ id: 'did:key:other#key' })
    ).rejects.toThrow('Unknown key id')
  })
})

describe('singleKeyResolver', () => {
  const keyAgreementKey = {
    id: 'did:key:zTest#zKak',
    type: 'X25519KeyAgreementKey2020',
    publicKeyMultibase: 'zKak'
  }

  it('resolves exactly the supplied key', async () => {
    const resolve = singleKeyResolver({ keyAgreementKey })
    expect(await resolve({ id: keyAgreementKey.id })).toEqual(keyAgreementKey)
  })

  it('throws for any other id, including undefined', async () => {
    const resolve = singleKeyResolver({ keyAgreementKey })
    await expect(resolve({ id: 'did:key:zOther#zKey' })).rejects.toThrow(
      'Unknown key id "did:key:zOther#zKey".'
    )
    await expect(resolve({})).rejects.toThrow('Unknown key id')
  })
})
