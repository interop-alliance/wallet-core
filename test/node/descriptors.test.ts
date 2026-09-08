/**
 * Unit tests for the log-governed descriptor source (`src/descriptors/`):
 * every read resolves to the governing resource log's verified head state,
 * keyed per collection by `collectionDescriptorLogPinId`, runs under the
 * collection-descriptor log class, and refuses what the verifier refuses --
 * exercised both directly and through was-client's `acquireDescriptor`, whose
 * cache fallback the refusal classes must rethrow past. The acquisition,
 * refresh-policy, and self-refreshing-cipher tests live in
 * `@interop/was-client` beside the moved code.
 */
import { describe, expect, it } from 'vitest'
import type { CollectionEncryption } from '@interop/was-client'
import {
  acquireDescriptor,
  initRecipients,
  ownerRecipient,
  type EncryptionDescriptorCache
} from '@interop/was-client/edv'
import { RESOURCE_LOG_METHOD } from '@interop/storage-core'
import {
  collectionDescriptorLogPinId,
  EPOCH_CONFIGURATION_STATE_TYPE,
  logGovernedDescriptorSource,
  readGovernedEpochConfiguration
} from '../../src/descriptors/logSource.js'
import { controllerForLogClass } from '../../src/resourceLog/index.js'
import { logGovernedDescriptorStore } from '../../src/keys/rosterLogStore.js'
import {
  appendResourceLog,
  createResourceLog,
  collectionLogPinId,
  memoryResourceLogPinStore
} from '@interop/vh-resource-log'
import { makeRosterClient } from './fixtures/rosterClient.js'
import { fakeController, memoryLogStore } from './fixtures/resourceLog.js'

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

const sampleDescriptor = (): CollectionEncryption => ({
  scheme: 'edv',
  version: 1,
  currentEpoch: 'did:key:z6LSepoch',
  epochs: [{ id: 'did:key:z6LSepoch', recipients: [] }]
})

describe('collectionDescriptorLogPinId', () => {
  it("names a host-free slot under the collection's own subtree", () => {
    // The log lives at the collection's `meta/log` sub-resource, so the read
    // capability a share grantee or a connected app already holds covers it.
    expect(
      collectionDescriptorLogPinId({ spaceId: 'sp', collectionId: 'app-notes' })
    ).toBe(collectionLogPinId({ spaceId: 'sp', collectionId: 'app-notes' }))
    expect(
      collectionDescriptorLogPinId({ spaceId: 'sp', collectionId: 'app-notes' })
    ).toBe('space/sp/app-notes/meta/log')
  })
})

describe('logGovernedDescriptorSource', () => {
  const GOVERNED_ID = 'app-notes'
  const SPACE_ID = 'space-under-test'
  const GOVERNED_LOG_ID = collectionDescriptorLogPinId({
    spaceId: SPACE_ID,
    collectionId: GOVERNED_ID
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
      spaceId: SPACE_ID
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
      spaceId: SPACE_ID
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
      spaceId: SPACE_ID
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
    ).rejects.toMatchObject({ name: 'ResourceLogIntegrityError' })
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
      spaceId: SPACE_ID
    })
    // Through acquireDescriptor, the refusal rethrows past a warm cache.
    const cache = memoryCache()
    cache._set(GOVERNED_ID, sampleDescriptor())
    await expect(
      acquireDescriptor({ source, cache, collectionId: GOVERNED_ID })
    ).rejects.toThrow(/carries state of type/)
  })

  it('serves a ladder-signed append the roster class would refuse', async () => {
    // The read side runs under the collection-descriptor class: a
    // ladder-signed append anchored at a version that changed nothing is
    // exactly the shape the roster log's ceremony-tail license refuses, and
    // a reader that inherited that rule would refuse a served log its own
    // wallet's standing credential wrote.
    const ladder = await makeRosterClient()
    const version = (versionId: string) => ({
      versionId,
      keys: [ladder.signingKeyMultibase],
      ladderKeys: [ladder.signingKeyMultibase],
      inventoryKeys: ['credA']
    })
    const beforeEdit = fakeController({ versions: [version('1-v1')] })
    const unchangedEdit = fakeController({
      versions: [version('1-v1'), version('2-v2')]
    })
    const log = memoryLogStore()
    const genesis = {
      ...sampleDescriptor(),
      type: EPOCH_CONFIGURATION_STATE_TYPE
    }
    const rotated = {
      ...genesis,
      currentEpoch: 'did:key:zRotatedEpoch'
    }
    await createResourceLog({
      store: log,
      controller: beforeEdit,
      method: RESOURCE_LOG_METHOD,
      pinStore: memoryResourceLogPinStore(),
      logId: GOVERNED_LOG_ID,
      signer: ladder.logSigner,
      state: genesis
    })
    // The append runs under this log's own class, exactly as the governed
    // store does: membership at the anchored version is the whole rule.
    await appendResourceLog({
      store: log,
      controller: controllerForLogClass({
        controller: unchangedEdit,
        logClass: 'collection-descriptor'
      }),
      expectedMethod: RESOURCE_LOG_METHOD,
      pinStore: memoryResourceLogPinStore(),
      logId: GOVERNED_LOG_ID,
      signer: ladder.logSigner,
      buildState: () => rotated
    })

    const source = logGovernedDescriptorSource({
      logFor: () => log,
      resolveController: async () => unchangedEdit,
      pinStore: memoryResourceLogPinStore(),
      spaceId: SPACE_ID
    })
    expect(
      await source.collectionEncryption({ collectionId: GOVERNED_ID })
    ).toEqual(rotated)

    // The same served log, read under the roster log's rule, is refused.
    await expect(
      readGovernedEpochConfiguration({
        store: log,
        resolveController: async () =>
          controllerForLogClass({
            controller: unchangedEdit,
            logClass: 'user-key-roster'
          }),
        pinStore: memoryResourceLogPinStore(),
        logId: GOVERNED_LOG_ID
      })
    ).rejects.toMatchObject({ name: 'ResourceLogLicenseError' })
  })
})

describe('logGovernedDescriptorStore (the create path under the edv machinery)', () => {
  const GOVERNED_LOG_ID = collectionDescriptorLogPinId({
    spaceId: 'space-under-test',
    collectionId: 'app-notes'
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
        signer: alice.logSigner,
        logClass: 'user-key-roster'
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
      signer: mallory.logSigner,
      logClass: 'user-key-roster'
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
