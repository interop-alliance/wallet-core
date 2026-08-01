/**
 * Unit tests for the per-user key module (`src/keys/puk.ts`) and the
 * recipient-zero substitution: a fresh PUK minted via the was-client epoch
 * construction, its vault-key reconstruction being stable across sessions
 * (encrypt in one session, decrypt after a rebuild from the stored material),
 * the PUK serving as recipient zero of a real key-epoch roster while a
 * grantee's side of the roster decrypts unchanged, and the permanent
 * pre-epoch tolerance path under a PUK-keyed cipher. The epoch machinery runs
 * unmocked against an in-memory marker store.
 */
import { describe, expect, it } from 'vitest'
import { base64urlnopad } from '@scure/base'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { PreconditionFailedError } from '@interop/was-client'
import type { CollectionEncryption } from '@interop/was-client'
import {
  createEdvDocCipher,
  epochKeyIdFor,
  initRecipients,
  ownerRecipient,
  type MarkerStore
} from '@interop/was-client/edv'
import { mintPuk, pukVaultKeys, type Puk } from '../../src/keys/puk.js'

const COLLECTION_ID = 'private-credentials'

/**
 * Round-trips a PUK through the string form the keyring record stores it in,
 * simulating what a later login recovers: no object identity survives, only
 * the serialized material.
 */
function reserializePuk(puk: Required<Puk>): Puk {
  const stored = {
    id: puk.id,
    secret: base64urlnopad.encode(puk.secret),
    signingSeed: base64urlnopad.encode(puk.signingSeed)
  }
  return {
    id: stored.id,
    secret: base64urlnopad.decode(stored.secret),
    signingSeed: base64urlnopad.decode(stored.signingSeed)
  }
}

/**
 * A minimal in-memory `MarkerStore` with a monotonic version counter as the
 * compare-and-swap etag, so `initRecipients` runs its real write path.
 */
function memoryMarkerStore(): MarkerStore {
  let marker: CollectionEncryption | null = null
  let version = 0
  return {
    async read() {
      return marker
        ? { marker: structuredClone(marker), etag: `v${version}` }
        : null
    },
    async replace(next, { ifMatch }: { ifMatch?: string }) {
      if (ifMatch !== `v${version}`) {
        throw new PreconditionFailedError('stale marker etag')
      }
      marker = next
      version++
    },
    async create(next) {
      if (marker) {
        throw new PreconditionFailedError('marker already exists')
      }
      marker = next
      version++
    }
  }
}

/**
 * A generated grantee key pair (an app's identity KAK, or a share grantee's
 * derived recipient key -- structurally the same thing) plus its single-key
 * resolver.
 */
async function generateGranteeKey(): Promise<{
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}> {
  const key = await X25519KeyAgreementKey2020.generate({
    controller: 'did:key:z6MkTestGranteeController'
  })
  const keyResolver: IKeyResolver = async () => ({
    id: key.id!,
    type: key.type,
    publicKeyMultibase: key.publicKeyMultibase
  })
  return { keyAgreementKey: key as IKeyAgreementKey, keyResolver }
}

describe('mintPuk', () => {
  it('mints an X25519 did:key id and 32-byte key material', async () => {
    const puk = await mintPuk()
    expect(puk.id.startsWith('did:key:z')).toBe(true)
    expect(puk.secret).toHaveLength(32)
    expect(puk.signingSeed).toHaveLength(32)
  })

  it('mints independent randomness per call', async () => {
    const first = await mintPuk()
    const second = await mintPuk()
    expect(second.id).not.toBe(first.id)
    expect(Array.from(second.secret)).not.toEqual(Array.from(first.secret))
    expect(Array.from(second.signingSeed)).not.toEqual(
      Array.from(first.signingSeed)
    )
  })
})

describe('pukVaultKeys', () => {
  it('reconstructs the self-describing KAK the roster machinery expects', async () => {
    const puk = await mintPuk()
    const { keyAgreementKey, keyResolver } = pukVaultKeys({ puk })
    expect(keyAgreementKey.id).toBe(epochKeyIdFor(puk.id))
    // The recipient entry a marker stores for the PUK is well-formed.
    const recipient = ownerRecipient({ keyAgreementKey })
    expect(recipient.id).toBe(keyAgreementKey.id)
    // The single-key resolver answers for the PUK's own kid.
    const resolved = await keyResolver({ id: keyAgreementKey.id })
    expect(resolved.publicKeyMultibase).toBeDefined()
  })

  it('round-trips an encrypted document across a session rebuild', async () => {
    const puk = await mintPuk()
    const writer = await createEdvDocCipher({
      ...pukVaultKeys({ puk }),
      collectionId: COLLECTION_ID
    })
    const { envelope } = await writer.encrypt({ data: { secretNote: 'hi' } })

    // "Logout/login": rebuild the vault keys from the serialized PUK alone.
    const reader = await createEdvDocCipher({
      ...pukVaultKeys({ puk: reserializePuk(puk) }),
      collectionId: COLLECTION_ID
    })
    expect(await reader.decrypt({ envelope })).toEqual({ secretNote: 'hi' })
  })
})

describe('the PUK as recipient zero of a key-epoch roster', () => {
  it('lets both the owner and a grantee decrypt an epoch write', async () => {
    const puk = await mintPuk()
    const owner = pukVaultKeys({ puk })
    const grantee = await generateGranteeKey()

    const store = memoryMarkerStore()
    const marker = await initRecipients({
      store,
      recipients: [
        ownerRecipient({ keyAgreementKey: owner.keyAgreementKey }),
        ownerRecipient({ keyAgreementKey: grantee.keyAgreementKey })
      ]
    })

    const ownerCipher = await createEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      encryption: marker
    })
    const { envelope } = await ownerCipher.encrypt({
      data: { shared: 'payload' }
    })

    // The owner reads back through a rebuilt session (recipient zero = PUK).
    const rebuiltOwnerCipher = await createEdvDocCipher({
      ...pukVaultKeys({ puk: reserializePuk(puk) }),
      collectionId: COLLECTION_ID,
      encryption: marker
    })
    expect(await rebuiltOwnerCipher.decrypt({ envelope })).toEqual({
      shared: 'payload'
    })

    // The grantee's side is untouched by the recipient-zero substitution: it
    // unwraps the epoch with its own identity KAK, exactly as before.
    const granteeCipher = await createEdvDocCipher({
      ...grantee,
      collectionId: COLLECTION_ID,
      encryption: marker
    })
    expect(await granteeCipher.decrypt({ envelope })).toEqual({
      shared: 'payload'
    })
  })

  it('keeps reading pre-epoch single-recipient envelopes (permanent tolerance)', async () => {
    const puk = await mintPuk()
    const owner = pukVaultKeys({ puk })

    // Written before any roster existed: sealed straight to the PUK's KAK.
    const preEpochCipher = await createEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID
    })
    const { envelope } = await preEpochCipher.encrypt({
      data: { legacy: 'envelope' }
    })

    // A roster appears later (the collection's first share); the epoch-aware
    // cipher must still route the pre-epoch envelope through the direct codec.
    const grantee = await generateGranteeKey()
    const marker = await initRecipients({
      store: memoryMarkerStore(),
      recipients: [
        ownerRecipient({ keyAgreementKey: owner.keyAgreementKey }),
        ownerRecipient({ keyAgreementKey: grantee.keyAgreementKey })
      ]
    })
    const epochAwareCipher = await createEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      encryption: marker
    })
    expect(await epochAwareCipher.decrypt({ envelope })).toEqual({
      legacy: 'envelope'
    })
  })
})
