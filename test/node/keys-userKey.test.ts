/**
 * Unit tests for the user key module (`src/keys/userKey.ts`) and the
 * recipient-zero substitution: a fresh user key minted via the was-client epoch
 * construction, its vault-key reconstruction being stable across sessions
 * (encrypt in one session, decrypt after a rebuild from the stored material),
 * and the user key serving as recipient zero of a real key-epoch roster while
 * a grantee's side of the roster decrypts unchanged. The epoch machinery runs
 * unmocked against an in-memory descriptor store.
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
  type EncryptionDescriptorStore
} from '@interop/was-client/edv'
import {
  mintUserKey,
  userKeyVaultKeys,
  type UserKey
} from '../../src/keys/userKey.js'

const COLLECTION_ID = 'private-credentials'

/**
 * Round-trips a user key through the string form the keyring record stores it
 * in, simulating what a later login recovers: no object identity survives, only
 * the serialized material.
 */
function reserializeUserKey(userKey: Required<UserKey>): UserKey {
  const stored = {
    id: userKey.id,
    secret: base64urlnopad.encode(userKey.secret),
    signingSeed: base64urlnopad.encode(userKey.signingSeed)
  }
  return {
    id: stored.id,
    secret: base64urlnopad.decode(stored.secret),
    signingSeed: base64urlnopad.decode(stored.signingSeed)
  }
}

/**
 * A minimal in-memory `EncryptionDescriptorStore` with a monotonic version
 * counter as the compare-and-swap etag, so `initRecipients` runs its real
 * write path.
 */
function memoryDescriptorStore(): EncryptionDescriptorStore {
  let descriptor: CollectionEncryption | null = null
  let version = 0
  return {
    async read() {
      return descriptor
        ? { descriptor: structuredClone(descriptor), etag: `v${version}` }
        : null
    },
    async replace(next, { ifMatch }: { ifMatch?: string }) {
      if (ifMatch !== `v${version}`) {
        throw new PreconditionFailedError('stale descriptor etag')
      }
      descriptor = next
      version++
    },
    async create(next) {
      if (descriptor) {
        throw new PreconditionFailedError('descriptor already exists')
      }
      descriptor = next
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

describe('mintUserKey', () => {
  it('mints an X25519 did:key id and 32-byte key material', async () => {
    const userKey = await mintUserKey()
    expect(userKey.id.startsWith('did:key:z')).toBe(true)
    expect(userKey.secret).toHaveLength(32)
    expect(userKey.signingSeed).toHaveLength(32)
  })

  it('mints independent randomness per call', async () => {
    const first = await mintUserKey()
    const second = await mintUserKey()
    expect(second.id).not.toBe(first.id)
    expect(Array.from(second.secret)).not.toEqual(Array.from(first.secret))
    expect(Array.from(second.signingSeed)).not.toEqual(
      Array.from(first.signingSeed)
    )
  })
})

describe('userKeyVaultKeys', () => {
  it('reconstructs the self-describing KAK the roster machinery expects', async () => {
    const userKey = await mintUserKey()
    const { keyAgreementKey, keyResolver } = userKeyVaultKeys({ userKey })
    expect(keyAgreementKey.id).toBe(epochKeyIdFor(userKey.id))
    // The recipient entry a descriptor stores for the user key is well-formed.
    const recipient = ownerRecipient({ keyAgreementKey })
    expect(recipient.id).toBe(keyAgreementKey.id)
    // The single-key resolver answers for the user key's own kid.
    const resolved = await keyResolver({ id: keyAgreementKey.id })
    expect(resolved.publicKeyMultibase).toBeDefined()
  })

  it('round-trips an encrypted document across a session rebuild', async () => {
    const userKey = await mintUserKey()
    const owner = userKeyVaultKeys({ userKey })
    const descriptor = await initRecipients({
      store: memoryDescriptorStore(),
      recipients: [ownerRecipient({ keyAgreementKey: owner.keyAgreementKey })]
    })
    const writer = await createEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      encryption: descriptor
    })
    const { envelope } = await writer.encrypt({ data: { secretNote: 'hi' } })

    // "Logout/login": rebuild the vault keys from the serialized user key alone.
    const reader = await createEdvDocCipher({
      ...userKeyVaultKeys({ userKey: reserializeUserKey(userKey) }),
      collectionId: COLLECTION_ID,
      encryption: descriptor
    })
    expect(await reader.decrypt({ envelope })).toEqual({ secretNote: 'hi' })
  })
})

describe('the user key as recipient zero of a key-epoch roster', () => {
  it('lets both the owner and a grantee decrypt an epoch write', async () => {
    const userKey = await mintUserKey()
    const owner = userKeyVaultKeys({ userKey })
    const grantee = await generateGranteeKey()

    const store = memoryDescriptorStore()
    const descriptor = await initRecipients({
      store,
      recipients: [
        ownerRecipient({ keyAgreementKey: owner.keyAgreementKey }),
        ownerRecipient({ keyAgreementKey: grantee.keyAgreementKey })
      ]
    })

    const ownerCipher = await createEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      encryption: descriptor
    })
    const { envelope } = await ownerCipher.encrypt({
      data: { shared: 'payload' }
    })

    // The owner reads back through a rebuilt session (recipient zero = user key).
    const rebuiltOwnerCipher = await createEdvDocCipher({
      ...userKeyVaultKeys({ userKey: reserializeUserKey(userKey) }),
      collectionId: COLLECTION_ID,
      encryption: descriptor
    })
    expect(await rebuiltOwnerCipher.decrypt({ envelope })).toEqual({
      shared: 'payload'
    })

    // The grantee's side is untouched by the recipient-zero substitution: it
    // unwraps the epoch with its own identity KAK, exactly as before.
    const granteeCipher = await createEdvDocCipher({
      ...grantee,
      collectionId: COLLECTION_ID,
      encryption: descriptor
    })
    expect(await granteeCipher.decrypt({ envelope })).toEqual({
      shared: 'payload'
    })
  })
})
