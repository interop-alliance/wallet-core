/**
 * Unit tests for the collection encryption-descriptor module
 * (`src/descriptors/`): descriptor acquisition (fetch + cache + the cached
 * fallback whenever the description yields no descriptor, thrown or empty), the
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
import { RESOURCE_LOG_METHOD } from '@interop/storage-core'
import { singleKeyResolver } from '../../src/identity/keyResolver.js'
import {
  acquireDescriptor,
  acquireDescriptors,
  type EncryptionDescriptorCache,
  type EncryptionDescriptorSource
} from '../../src/descriptors/acquire.js'
import {
  EPOCH_CONFIGURATION_STATE_TYPE,
  logGovernedDescriptorSource
} from '../../src/descriptors/logSource.js'
import { logGovernedDescriptorStore } from '../../src/keys/rosterLogStore.js'
import { DescriptorRefreshPolicy } from '../../src/descriptors/refresh.js'
import { createRefreshingEdvDocCipher } from '../../src/descriptors/cipher.js'
import { remintPendingEnvelopes } from '../../src/sync/remint.js'
import type { Json, SyncStore } from '../../src/sync/types.js'
import {
  appendResourceLog,
  createResourceLog,
  memoryResourceLogPinStore,
  resourceLogPinId,
  ResourceLogContinuityError,
  ResourceLogIntegrityError
} from '@interop/vh-resource-log'
import { makeRosterClient } from './fixtures/rosterClient.js'
import { fakeController, memoryLogStore } from './fixtures/resourceLog.js'

const COLLECTION_ID = 'private-credentials'

/**
 * An in-memory `EncryptionDescriptorCache` with write counting; with
 * `failReads` set, every read throws (the cache seam's errors throw through).
 */
function memoryCache(): EncryptionDescriptorCache & {
  writes: number
  failReads: boolean
  _get(collectionId: string): CollectionEncryption | undefined
  _set(collectionId: string, descriptor: CollectionEncryption): void
} {
  const descriptors = new Map<string, CollectionEncryption>()
  return {
    writes: 0,
    failReads: false,
    async readDescriptor({ collectionId }) {
      if (this.failReads) {
        throw new Error(`descriptor cache unreadable for "${collectionId}"`)
      }
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

  it('falls back to the cached copy on an empty description (a masked 404), leaving the cache in place', async () => {
    const source = memorySource()
    const cache = memoryCache()
    const descriptor = sampleDescriptor()
    cache._set(COLLECTION_ID, descriptor)

    // An empty description is ambiguous: WAS serves the same shape for an
    // unauthorized read as for an unencrypted collection.
    const acquired = await acquireDescriptor({
      source,
      cache,
      collectionId: COLLECTION_ID
    })
    expect(acquired).toEqual(descriptor)
    // The cached copy is deliberately not cleared (mirrors the offline path).
    expect(cache._get(COLLECTION_ID)).toBeDefined()
  })

  it('resolves undefined on an empty description with nothing cached', async () => {
    const acquired = await acquireDescriptor({
      source: memorySource(),
      cache: memoryCache(),
      collectionId: COLLECTION_ID
    })
    expect(acquired).toBeUndefined()
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

  it('rethrows a log-governed source refusal instead of falling back (matched by name)', async () => {
    const cache = memoryCache()
    cache._set(COLLECTION_ID, sampleDescriptor())
    const onFetchError = () => {
      throw new Error('a refusal must not be observed as a swallowed fetch')
    }
    // A fabricated log, and a fork off the pinned history: security signals
    // a warm cache must not paper over.
    for (const refusal of [
      new ResourceLogIntegrityError('fabricated'),
      new ResourceLogContinuityError({ reason: 'fork', pinnedHead: '2-x' })
    ]) {
      await expect(
        acquireDescriptor({
          source: {
            collectionEncryption: async () => {
              throw refusal
            }
          },
          cache,
          collectionId: COLLECTION_ID,
          onFetchError
        })
      ).rejects.toThrow(refusal.message)
    }
  })

  it('falls back to the cache on a continuity rollback (reconcilable divergence)', async () => {
    const cache = memoryCache()
    const descriptor = sampleDescriptor()
    cache._set(COLLECTION_ID, descriptor)
    const observed: unknown[] = []
    const acquired = await acquireDescriptor({
      source: {
        collectionEncryption: async () => {
          throw new ResourceLogContinuityError({
            reason: 'rollback',
            pinnedHead: '2-x'
          })
        }
      },
      cache,
      collectionId: COLLECTION_ID,
      onFetchError: err => {
        observed.push(err)
      }
    })
    // Nothing rolled-back is adopted and the pin never regressed (the
    // verifier refused before pinning); the cached copy serves meanwhile.
    expect(acquired).toEqual(descriptor)
    expect(observed).toHaveLength(1)
  })
})

describe('logGovernedDescriptorSource', () => {
  const GOVERNED_ID = 'app-notes'
  const GOVERNED_LOG_ID = resourceLogPinId({
    spaceId: 'space-under-test',
    collectionId: GOVERNED_ID,
    resourceId: 'encryption.jsonl'
  })

  /**
   * A governed collection: its descriptor lives as the state of a resource
   * log signed by an enrolled client (alice) under a versioned controller.
   */
  async function makeGoverned() {
    const alice = await makeRosterClient()
    const controller = fakeController({
      versions: [{ versionId: '1-v1', keys: [alice.signingKeyMultibase] }]
    })
    const log = memoryLogStore()
    const pinStore = memoryResourceLogPinStore()
    const descriptor = {
      ...sampleDescriptor(),
      type: EPOCH_CONFIGURATION_STATE_TYPE
    }
    await createResourceLog({
      store: log,
      controller,
      method: RESOURCE_LOG_METHOD,
      pinStore: memoryResourceLogPinStore(),
      logId: GOVERNED_LOG_ID,
      signer: alice.logSigner,
      state: descriptor
    })
    const source = logGovernedDescriptorSource({
      logFor: () => log,
      resolveController: async () => controller,
      pinStore,
      logIdFor: () => GOVERNED_LOG_ID
    })
    return { alice, controller, log, pinStore, descriptor, source }
  }

  it('serves the verified head state as the descriptor, through acquireDescriptor', async () => {
    const { descriptor, source } = await makeGoverned()
    const cache = memoryCache()
    const acquired = await acquireDescriptor({
      source,
      cache,
      collectionId: GOVERNED_ID
    })
    expect(acquired).toEqual(descriptor)
    expect(cache._get(GOVERNED_ID)).toEqual(descriptor)
  })

  it('refuses an absent log under a held pin as a rollback, not as unprovisioned', async () => {
    const alice = await makeRosterClient()
    const controller = fakeController({
      versions: [{ versionId: '1-v1', keys: [alice.signingKeyMultibase] }]
    })
    const log = memoryLogStore()
    const pinStore = memoryResourceLogPinStore()
    const { verified } = await createResourceLog({
      store: log,
      controller,
      method: RESOURCE_LOG_METHOD,
      pinStore,
      logId: GOVERNED_LOG_ID,
      signer: alice.logSigner,
      state: { type: EPOCH_CONFIGURATION_STATE_TYPE, ...sampleDescriptor() }
    })
    log._setEntries(null)
    const source = logGovernedDescriptorSource({
      logFor: () => log,
      resolveController: async () => controller,
      pinStore,
      logIdFor: () => GOVERNED_LOG_ID
    })
    await expect(
      source.collectionEncryption({ collectionId: GOVERNED_ID })
    ).rejects.toMatchObject({
      name: 'ResourceLogContinuityError',
      reason: 'rollback',
      pinnedHead: verified.pin.head
    })
  })

  it('resolves undefined on an absent log (an unprovisioned collection)', async () => {
    const alice = await makeRosterClient()
    const source = logGovernedDescriptorSource({
      logFor: () => memoryLogStore(),
      resolveController: async () =>
        fakeController({
          versions: [{ versionId: '1-v1', keys: [alice.signingKeyMultibase] }]
        }),
      pinStore: memoryResourceLogPinStore(),
      logIdFor: () => GOVERNED_LOG_ID
    })
    expect(
      await source.collectionEncryption({ collectionId: GOVERNED_ID })
    ).toBeUndefined()
  })

  it('the unknown-epoch refresh re-reads AND re-verifies: a tampered log refuses despite a warm cache', async () => {
    const { log, source } = await makeGoverned()
    const cache = memoryCache()
    // First (healthy) acquisition warms the cache -- the refresh path's
    // second read must still refuse a log that no longer verifies.
    await acquireDescriptor({ source, cache, collectionId: GOVERNED_ID })
    const entries = log._getEntries()!
    ;(entries[0]!.state as { currentEpoch?: string }).currentEpoch =
      'did:key:z6LSsmuggled'
    log._setEntries(entries)

    await expect(
      acquireDescriptor({ source, cache, collectionId: GOVERNED_ID })
    ).rejects.toThrow(ResourceLogIntegrityError)
  })

  it('falls back to the cached copy on a served rollback, adopting nothing', async () => {
    const { alice, controller, log, descriptor, source } = await makeGoverned()
    const cache = memoryCache()
    // Advance the log (a rotation-shaped append) and pin its head.
    await appendResourceLog({
      store: log,
      controller,
      expectedMethod: RESOURCE_LOG_METHOD,
      pinStore: memoryResourceLogPinStore(),
      logId: GOVERNED_LOG_ID,
      signer: alice.logSigner,
      buildState: () => ({ ...descriptor, version: 2 })
    })
    const advanced = await acquireDescriptor({
      source,
      cache,
      collectionId: GOVERNED_ID
    })
    expect(advanced).toEqual({ ...descriptor, version: 2 })

    // The host replays the shorter history: the read refuses (rollback), and
    // acquisition serves the last verified copy from the cache.
    log._setEntries(log._getEntries()!.slice(0, 1))
    const acquired = await acquireDescriptor({
      source,
      cache,
      collectionId: GOVERNED_ID
    })
    expect(acquired).toEqual({ ...descriptor, version: 2 })
  })

  it('refuses a verified head whose state is not an epoch configuration', async () => {
    const alice = await makeRosterClient()
    const controller = fakeController({
      versions: [{ versionId: '1-v1', keys: [alice.signingKeyMultibase] }]
    })
    const log = memoryLogStore()
    await createResourceLog({
      store: log,
      controller,
      method: RESOURCE_LOG_METHOD,
      pinStore: memoryResourceLogPinStore(),
      logId: GOVERNED_LOG_ID,
      signer: alice.logSigner,
      state: { type: 'SomethingElse', payload: 1 }
    })
    const source = logGovernedDescriptorSource({
      logFor: () => log,
      resolveController: async () => controller,
      pinStore: memoryResourceLogPinStore(),
      logIdFor: () => GOVERNED_LOG_ID
    })
    // Through acquireDescriptor, the refusal rethrows past a warm cache.
    const cache = memoryCache()
    cache._set(GOVERNED_ID, sampleDescriptor())
    await expect(
      acquireDescriptor({ source, cache, collectionId: GOVERNED_ID })
    ).rejects.toThrow(/carries state of type/)
  })
})

describe('logGovernedDescriptorStore (the create path under the edv machinery)', () => {
  const GOVERNED_LOG_ID = resourceLogPinId({
    spaceId: 'space-under-test',
    collectionId: 'app-notes',
    resourceId: 'encryption.jsonl'
  })

  it('initRecipients by a non-member signer against an existing log loses the create race, adopting the winner', async () => {
    // alice (enrolled) already initialized the roster; mallory (never listed
    // by the controller) reads nothing, then finds the log at create time --
    // the guarded-create race. The genesis is refused pre-write, which the
    // store translates into the port's conflict class so was-client's CAS
    // loop re-reads and adopts the winner: mallory's outcome is exactly a
    // member loser's (alice's descriptor, resolved as-is), not a
    // log-integrity verdict, and the served log is untouched.
    const alice = await makeRosterClient()
    const mallory = await makeRosterClient()
    const controller = fakeController({
      versions: [{ versionId: '1-v1', keys: [alice.signingKeyMultibase] }]
    })
    const log = memoryLogStore()
    const winner = await initRecipients({
      store: logGovernedDescriptorStore({
        log,
        resolveController: async () => controller,
        pinStore: memoryResourceLogPinStore(),
        logId: GOVERNED_LOG_ID,
        signer: alice.logSigner
      }),
      recipients: [ownerRecipient({ keyAgreementKey: alice.kak })]
    })
    expect(log._getEntries()).toHaveLength(1)

    let reads = 0
    const racedLog = {
      ...log,
      async read() {
        // The first read (the CAS loop's) sees no log yet; every later one,
        // the store's own lost-race read included, sees alice's.
        reads++
        return reads === 1 ? null : log.read()
      }
    }
    const loser = logGovernedDescriptorStore({
      log: racedLog,
      resolveController: async () => controller,
      pinStore: memoryResourceLogPinStore(),
      logId: GOVERNED_LOG_ID,
      signer: mallory.logSigner
    })
    const adopted = await initRecipients({
      store: loser,
      recipients: [ownerRecipient({ keyAgreementKey: mallory.kak })]
    })
    expect(adopted).toMatchObject(winner)
    expect(log._getEntries()).toHaveLength(1)
    expect((await loser.read())!.descriptor).toMatchObject(winner)
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
  it('refuses to build fail-closed when no descriptor resolves anywhere', async () => {
    // Every encrypted collection's descriptor carries an epoch roster from
    // provisioning; a cipher for a collection whose descriptor resolves
    // nowhere must refuse rather than encrypt straight to a key-agreement key.
    const owner = await makeReader()
    await expect(
      createRefreshingEdvDocCipher({
        ...owner,
        collectionId: COLLECTION_ID,
        source: memorySource(),
        cache: memoryCache()
      })
    ).rejects.toThrow('no encryption descriptor available')
  })

  it('builds from the cached descriptor when the description comes back empty', async () => {
    // A masked 404 (an unauthorized or transient read) is indistinguishable
    // from an unencrypted collection, so the warm cache still serves it --
    // the collection must not go down for the session.
    const owner = await makeReader()
    const { descriptor2 } = await mintRotatedDescriptors(owner)
    const cache = memoryCache()
    cache._set(COLLECTION_ID, descriptor2)

    const cipher = await createRefreshingEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      source: memorySource(),
      cache
    })
    const { envelope, epoch } = await cipher.encrypt({ data: { n: 1 } })
    expect(epoch).toBe(descriptor2.currentEpoch)
    expect(await cipher.decrypt({ envelope })).toEqual({ n: 1 })
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
    // A stranger writing under its own independently minted epoch roster --
    // an epoch the reader's descriptor (current or refetched) never carries.
    const stranger = await makeReader()
    const foreignDescriptor = await initRecipients({
      store: memoryDescriptorStore(),
      recipients: [
        ownerRecipient({ keyAgreementKey: stranger.keyAgreementKey })
      ]
    })
    const foreign = await createEdvDocCipher({
      ...stranger,
      collectionId: COLLECTION_ID,
      encryption: foreignDescriptor
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

  it('rethrows the original UnknownEpochError when the refresh itself fails, and retries later', async () => {
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
    const writer = await createEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      encryption: descriptor2
    })
    const { envelope } = await writer.encrypt({ data: { n: 1 } })

    // Nothing answers the re-read: the description is unreachable and the
    // cache cannot be read either, so the rebuild rejects.
    source.failing.add(COLLECTION_ID)
    cache.failReads = true
    await expect(reader.decrypt({ envelope })).rejects.toThrow(
      UnknownEpochError
    )
    expect(source.fetches).toBe(2)

    // A failed refresh is not spent: once the description is reachable again
    // the next unknown-epoch decrypt refreshes and routes the envelope.
    source.failing.delete(COLLECTION_ID)
    cache.failReads = false
    source._set(COLLECTION_ID, descriptor2)
    expect(await reader.decrypt({ envelope })).toEqual({ n: 1 })
    expect(source.fetches).toBe(3)
  })

  it('keeps a failed refresh classifiable by the create-loss re-mint', async () => {
    // The re-mint classifies on `err instanceof UnknownEpochError` to find the
    // pending rows it exists to repair; a build failure surfacing instead
    // would abort the whole sweep on the first such row.
    const owner = await makeReader()
    const { descriptor1 } = await mintRotatedDescriptors(owner)
    const source = memorySource()
    const cache = memoryCache()
    source._set(COLLECTION_ID, descriptor1)

    const cipher = await createRefreshingEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      source,
      cache
    })
    // A pending envelope minted under a descriptor the adopted one does not
    // carry (the lost create), plus the stale cipher that can still open it.
    const loser = await makeReader()
    const loserDescriptor = await initRecipients({
      store: memoryDescriptorStore(),
      recipients: [ownerRecipient({ keyAgreementKey: loser.keyAgreementKey })]
    })
    const loserCipher = await createEdvDocCipher({
      ...loser,
      collectionId: COLLECTION_ID,
      encryption: loserDescriptor
    })
    const pending = await loserCipher.encrypt({ data: { name: 'cred-1' } })

    source.failing.add(COLLECTION_ID)
    cache.failReads = true
    const replaced: Array<{ id: string; newId: string }> = []
    const store = {
      getDirtyRows: async () => [
        {
          id: pending.id,
          version: 0,
          updatedAt: '',
          deleted: false,
          data: pending.envelope as unknown as Json
        }
      ],
      replacePending: async (options: { id: string; newId: string }) => {
        replaced.push({ id: options.id, newId: options.newId })
        return { applied: true }
      }
    } as unknown as SyncStore & {
      replacePending: NonNullable<SyncStore['replacePending']>
    }

    const result = await remintPendingEnvelopes({
      store,
      cipher,
      decryptStale: async ({ envelope }) =>
        (await loserCipher.decrypt({ envelope })) as Json
    })
    expect(result).toEqual({ pending: 1, reminted: 1 })
    expect(replaced).toHaveLength(1)
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
