/**
 * Unit tests for the collection encryption-descriptor module
 * (`src/descriptors/`): descriptor acquisition (fetch + cache + the cached
 * fallback when the description cannot be fetched), the
 * once-per-collection-per-session unknown-epoch refresh policy, and the
 * self-refreshing EDV document cipher -- the last driven through real EDV
 * codecs over real epoch rosters minted with the was-client recipient
 * primitives, so an envelope written under a rotated descriptor really fails
 * to decrypt under a stale one.
 */
import { describe, expect, it } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { PreconditionFailedError } from '@interop/was-client'
import type { CollectionEncryption } from '@interop/was-client'
import {
  createEdvDocCipher,
  initRecipients,
  ownerRecipient,
  removeRecipient,
  UnknownEpochError,
  type EncryptionDescriptorStore
} from '@interop/was-client/edv'
import { singleKeyResolver } from '../../src/identity/keyResolver.js'
import {
  acquireDescriptor,
  acquireDescriptors,
  type EncryptionDescriptorCache,
  type EncryptionDescriptorSource
} from '../../src/descriptors/acquire.js'
import { DescriptorRefreshPolicy } from '../../src/descriptors/refresh.js'
import { createRefreshingEdvDocCipher } from '../../src/descriptors/cipher.js'

const COLLECTION_ID = 'private-credentials'

/** An in-memory `EncryptionDescriptorCache` with write counting. */
function memoryCache(): EncryptionDescriptorCache & {
  writes: number
  _get(collectionId: string): CollectionEncryption | undefined
  _set(collectionId: string, descriptor: CollectionEncryption): void
} {
  const descriptors = new Map<string, CollectionEncryption>()
  return {
    writes: 0,
    async readDescriptor({ collectionId }) {
      const descriptor = descriptors.get(collectionId)
      return descriptor ? structuredClone(descriptor) : undefined
    },
    async writeDescriptor({ collectionId, descriptor }) {
      this.writes++
      descriptors.set(collectionId, structuredClone(descriptor))
    },
    _get(collectionId) {
      return descriptors.get(collectionId)
    },
    _set(collectionId, descriptor) {
      descriptors.set(collectionId, descriptor)
    }
  }
}

/**
 * An `EncryptionDescriptorSource` with fetch counting, served from a mutable
 * per-collection map; a collection id in `failing` throws instead.
 */
function memorySource(): EncryptionDescriptorSource & {
  fetches: number
  failing: Set<string>
  _set(collectionId: string, descriptor: CollectionEncryption | undefined): void
} {
  const descriptors = new Map<string, CollectionEncryption | undefined>()
  return {
    fetches: 0,
    failing: new Set<string>(),
    async collectionEncryption({ collectionId }) {
      this.fetches++
      if (this.failing.has(collectionId)) {
        throw new Error(`network down for "${collectionId}"`)
      }
      const descriptor = descriptors.get(collectionId)
      return descriptor ? structuredClone(descriptor) : undefined
    },
    _set(collectionId, descriptor) {
      descriptors.set(collectionId, descriptor)
    }
  }
}

/**
 * The in-memory compare-and-swap `EncryptionDescriptorStore` the was-client
 * recipient primitives (initRecipients / removeRecipient) run their real
 * write path against, to mint real epoch rosters for the cipher tests.
 */
function memoryDescriptorStore(): EncryptionDescriptorStore & {
  _getDescriptor(): CollectionEncryption | null
} {
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
    },
    _getDescriptor() {
      return descriptor ? structuredClone(descriptor) : null
    }
  }
}

/** A reader: an X25519 key-agreement key in did:key form, plus its resolver. */
async function makeReader(): Promise<{
  keyAgreementKey: IKeyAgreementKey
  keyResolver: ReturnType<typeof singleKeyResolver>
}> {
  const kak = await X25519KeyAgreementKey2020.generate()
  const publicKeyMultibase = kak.publicKeyMultibase as string
  const did = `did:key:${publicKeyMultibase}`
  kak.controller = did
  kak.id = `${did}#${publicKeyMultibase}`
  const keyAgreementKey = kak as IKeyAgreementKey
  return {
    keyAgreementKey,
    keyResolver: singleKeyResolver({ keyAgreementKey })
  }
}

/**
 * Mints a real two-epoch history for one owner: `descriptor1` (owner + a
 * second reader), then a rotation that removes the second reader, yielding
 * `descriptor2` whose `currentEpoch` the descriptor1-built cipher has never
 * seen.
 */
async function mintRotatedDescriptors(owner: {
  keyAgreementKey: IKeyAgreementKey
}): Promise<{
  descriptor1: CollectionEncryption
  descriptor2: CollectionEncryption
}> {
  const other = await makeReader()
  const store = memoryDescriptorStore()
  const descriptor1 = await initRecipients({
    store,
    recipients: [
      ownerRecipient({ keyAgreementKey: owner.keyAgreementKey }),
      ownerRecipient({ keyAgreementKey: other.keyAgreementKey })
    ]
  })
  const descriptor2 = await removeRecipient({
    store,
    recipientId: other.keyAgreementKey.id as string,
    pull: async () => {}
  })
  return { descriptor1, descriptor2 }
}

const sampleDescriptor = (): CollectionEncryption => ({
  scheme: 'edv',
  version: 1,
  currentEpoch: 'did:key:z6LSepoch',
  epochs: [{ id: 'did:key:z6LSepoch', recipients: [] }]
})

describe('acquireDescriptor', () => {
  it('caches and returns a fetched descriptor', async () => {
    const source = memorySource()
    const cache = memoryCache()
    const descriptor = sampleDescriptor()
    source._set(COLLECTION_ID, descriptor)

    const acquired = await acquireDescriptor({
      source,
      cache,
      collectionId: COLLECTION_ID
    })
    expect(acquired).toEqual(descriptor)
    expect(cache._get(COLLECTION_ID)).toEqual(descriptor)
    expect(cache.writes).toBe(1)
  })

  it('resolves undefined on a successful no-descriptor fetch, leaving the cache in place', async () => {
    const source = memorySource()
    const cache = memoryCache()
    cache._set(COLLECTION_ID, sampleDescriptor())

    const acquired = await acquireDescriptor({
      source,
      cache,
      collectionId: COLLECTION_ID
    })
    expect(acquired).toBeUndefined()
    // The cached copy is deliberately not cleared (mirrors the offline path).
    expect(cache._get(COLLECTION_ID)).toBeDefined()
  })

  it('falls back to the cached copy when the fetch fails, reporting the error', async () => {
    const source = memorySource()
    const cache = memoryCache()
    const descriptor = sampleDescriptor()
    cache._set(COLLECTION_ID, descriptor)
    source.failing.add(COLLECTION_ID)
    const seen: string[] = []

    const acquired = await acquireDescriptor({
      source,
      cache,
      collectionId: COLLECTION_ID,
      onFetchError: (_err, { collectionId }) => seen.push(collectionId)
    })
    expect(acquired).toEqual(descriptor)
    expect(seen).toEqual([COLLECTION_ID])
  })

  it('resolves undefined when the fetch fails and nothing is cached', async () => {
    const source = memorySource()
    source.failing.add(COLLECTION_ID)
    const acquired = await acquireDescriptor({
      source,
      cache: memoryCache(),
      collectionId: COLLECTION_ID
    })
    expect(acquired).toBeUndefined()
  })

  it('reads the cache alone when no source is supplied', async () => {
    const cache = memoryCache()
    const descriptor = sampleDescriptor()
    cache._set(COLLECTION_ID, descriptor)
    const acquired = await acquireDescriptor({
      cache,
      collectionId: COLLECTION_ID
    })
    expect(acquired).toEqual(descriptor)
  })
})

describe('acquireDescriptors', () => {
  it('aggregates only the collections that resolve a descriptor', async () => {
    const source = memorySource()
    const cache = memoryCache()
    const descriptor = sampleDescriptor()
    source._set('contacts', descriptor)
    source.failing.add('wallet-activity')
    cache._set('wallet-activity', descriptor)

    const descriptors = await acquireDescriptors({
      source,
      cache,
      collectionIds: ['contacts', 'contacts-history', 'wallet-activity']
    })
    expect(Object.keys(descriptors).sort()).toEqual([
      'contacts',
      'wallet-activity'
    ])
    expect(source.fetches).toBe(3)
  })
})

describe('DescriptorRefreshPolicy', () => {
  it('spends one refresh + one re-read on the first unknown-epoch report', async () => {
    let refreshes = 0
    let reads = 0
    const policy = new DescriptorRefreshPolicy({
      refresh: async () => {
        refreshes++
      }
    })
    const value = await policy.readWithRefresh({
      collectionId: COLLECTION_ID,
      read: async () => {
        reads++
        // The re-read (after the refresh) no longer reports unknown rows.
        return { value: reads, unknownEpoch: reads === 1 }
      }
    })
    expect(value).toBe(2)
    expect(refreshes).toBe(1)
    expect(reads).toBe(2)
  })

  it('never refreshes the same collection twice in one session, but guards per collection', async () => {
    const refreshed: string[] = []
    const policy = new DescriptorRefreshPolicy({
      refresh: async ({ collectionId }) => {
        refreshed.push(collectionId)
      }
    })
    const unknownRead = async () => ({ value: 'v', unknownEpoch: true })

    await policy.readWithRefresh({
      collectionId: COLLECTION_ID,
      read: unknownRead
    })
    await policy.readWithRefresh({
      collectionId: COLLECTION_ID,
      read: unknownRead
    })
    await policy.readWithRefresh({
      collectionId: 'contacts',
      read: unknownRead
    })
    expect(refreshed).toEqual([COLLECTION_ID, 'contacts'])
  })

  it('reset re-arms the guard, for one collection or all', async () => {
    const refreshed: string[] = []
    const policy = new DescriptorRefreshPolicy({
      refresh: async ({ collectionId }) => {
        refreshed.push(collectionId)
      }
    })
    const unknownRead = async () => ({ value: 'v', unknownEpoch: true })

    await policy.readWithRefresh({
      collectionId: COLLECTION_ID,
      read: unknownRead
    })
    policy.reset({ collectionId: COLLECTION_ID })
    await policy.readWithRefresh({
      collectionId: COLLECTION_ID,
      read: unknownRead
    })
    policy.reset()
    await policy.readWithRefresh({
      collectionId: COLLECTION_ID,
      read: unknownRead
    })
    expect(refreshed).toEqual([COLLECTION_ID, COLLECTION_ID, COLLECTION_ID])
  })
})

describe('createRefreshingEdvDocCipher', () => {
  it('stays on the single-key path when no descriptor resolves anywhere', async () => {
    const owner = await makeReader()
    const cipher = await createRefreshingEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      source: memorySource(),
      cache: memoryCache()
    })
    const { envelope, epoch } = await cipher.encrypt({
      data: { hello: 'world' }
    })
    expect(epoch).toBeUndefined()
    expect(await cipher.decrypt({ envelope })).toEqual({ hello: 'world' })
  })

  it("encrypts under the acquired descriptor's current epoch", async () => {
    const owner = await makeReader()
    const { descriptor1 } = await mintRotatedDescriptors(owner)
    const source = memorySource()
    source._set(COLLECTION_ID, descriptor1)

    const cipher = await createRefreshingEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      source,
      cache: memoryCache()
    })
    const { envelope, epoch } = await cipher.encrypt({ data: { n: 1 } })
    expect(epoch).toBe(descriptor1.currentEpoch)
    expect(await cipher.decrypt({ envelope })).toEqual({ n: 1 })
  })

  it('refreshes exactly once on an unknown-epoch decrypt: re-read, swap, retry', async () => {
    const owner = await makeReader()
    const { descriptor1, descriptor2 } = await mintRotatedDescriptors(owner)
    const source = memorySource()
    const cache = memoryCache()
    source._set(COLLECTION_ID, descriptor1)

    const reader = await createRefreshingEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      source,
      cache
    })
    expect(source.fetches).toBe(1)

    // Another replica rotates (descriptor2) and writes under the fresh epoch.
    source._set(COLLECTION_ID, descriptor2)
    const writer = await createEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      encryption: descriptor2
    })
    const one = await writer.encrypt({ data: { n: 1 } })
    const two = await writer.encrypt({ data: { n: 2 } })
    expect(one.epoch).toBe(descriptor2.currentEpoch)

    // First unknown-epoch decrypt drives the one re-read + swap + retry...
    expect(await reader.decrypt({ envelope: one.envelope })).toEqual({ n: 1 })
    expect(source.fetches).toBe(2)
    expect(cache._get(COLLECTION_ID)).toEqual(descriptor2)
    // ...and later fresh-epoch decrypts ride the swapped cipher, no refetch.
    expect(await reader.decrypt({ envelope: two.envelope })).toEqual({ n: 2 })
    expect(source.fetches).toBe(2)
  })

  it('propagates UnknownEpochError for a foreign envelope without a second re-read', async () => {
    const owner = await makeReader()
    const { descriptor1 } = await mintRotatedDescriptors(owner)
    const source = memorySource()
    source._set(COLLECTION_ID, descriptor1)

    const reader = await createRefreshingEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      source,
      cache: memoryCache()
    })
    const stranger = await makeReader()
    const foreign = await createEdvDocCipher({
      ...stranger,
      collectionId: COLLECTION_ID
    })
    const { envelope } = await foreign.encrypt({ data: { n: 1 } })

    // The first foreign envelope spends the one refresh (the descriptor is
    // unchanged, so the retry fails the same way)...
    await expect(reader.decrypt({ envelope })).rejects.toThrow(
      UnknownEpochError
    )
    expect(source.fetches).toBe(2)
    // ...and a later one neither refetches nor loops.
    await expect(reader.decrypt({ envelope })).rejects.toThrow(
      UnknownEpochError
    )
    expect(source.fetches).toBe(2)
  })

  it('builds from the cached descriptor when the description cannot be fetched', async () => {
    const owner = await makeReader()
    const { descriptor2 } = await mintRotatedDescriptors(owner)
    const source = memorySource()
    source.failing.add(COLLECTION_ID)
    const cache = memoryCache()
    cache._set(COLLECTION_ID, descriptor2)
    const errors: unknown[] = []

    const cipher = await createRefreshingEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      source,
      cache,
      onFetchError: err => errors.push(err)
    })
    // Offline, the previously-shared collection keeps encrypting under its
    // current epoch (the cached descriptor).
    const { envelope, epoch } = await cipher.encrypt({ data: { n: 1 } })
    expect(epoch).toBe(descriptor2.currentEpoch)
    expect(await cipher.decrypt({ envelope })).toEqual({ n: 1 })
    expect(errors).toHaveLength(1)
  })

  it('is inert (no refresh) without a source: an unknown-epoch decrypt propagates', async () => {
    const owner = await makeReader()
    const { descriptor1, descriptor2 } = await mintRotatedDescriptors(owner)
    const cache = memoryCache()
    cache._set(COLLECTION_ID, descriptor1)

    const reader = await createRefreshingEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      cache
    })
    const writer = await createEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      encryption: descriptor2
    })
    const { envelope } = await writer.encrypt({ data: { n: 1 } })
    await expect(reader.decrypt({ envelope })).rejects.toThrow(
      UnknownEpochError
    )
  })

  it('supports the in-place update path through the wrapper', async () => {
    const owner = await makeReader()
    const { descriptor1 } = await mintRotatedDescriptors(owner)
    const source = memorySource()
    source._set(COLLECTION_ID, descriptor1)

    const cipher = await createRefreshingEdvDocCipher({
      ...owner,
      collectionId: 'contacts',
      idDerivation: 'random',
      source: (() => {
        const s = memorySource()
        s._set('contacts', descriptor1)
        return s
      })(),
      cache: memoryCache()
    })
    const created = await cipher.encrypt({ data: { name: 'Ada' } })
    if (!cipher.encryptUpdate) {
      throw new Error('wrapper lost encryptUpdate')
    }
    const updated = await cipher.encryptUpdate({
      id: created.id,
      data: { name: 'Ada Lovelace' },
      current: created.envelope
    })
    expect(updated.id).toBe(created.id)
    expect(await cipher.decrypt({ envelope: updated.envelope })).toEqual({
      name: 'Ada Lovelace'
    })
  })
})
