/**
 * `ensureWalletSpaceEpochs`: the provision-time epoch[0] install for the
 * wallet Space's encrypted collections. Drives the real `ensureFirstEpoch`
 * CAS/create path against in-memory descriptor stores reached through the
 * `storeFor` lookup the install now takes, and asserts every encrypted roster
 * collection gains a fresh epoch[0] wrapped to the user key -- fresh random,
 * never the user-key generation itself -- while an already-installed roster is
 * adopted untouched. Also covers the partial-outcome contract: a failing
 * collection lands in `failed` without discarding the descriptors the other
 * collections settled on.
 */
import { describe, expect, it, vi } from 'vitest'

import type { CollectionEncryption, WasClient } from '@interop/was-client'
import { ensureFirstEpoch, resolveEpochKeys } from '@interop/was-client/edv'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import {
  ResourceLogContinuityError,
  ResourceLogIntegrityError
} from '@interop/vh-resource-log'

import { WALLET_SPACE_PROVISION_ROSTER } from '../../src/space/index.js'
import { mintUserKey, userKeyVaultKeys } from '../../src/keys/userKey.js'
import { provisionWalletSpace } from '../../src/space/provisioning.js'
import {
  ensureIndexedFirstEpoch,
  ensureWalletSpaceEpochs,
  WalletSpaceProvisioningError,
  walletSpaceProvisioner
} from '../../src/keys/spaceEpochs.js'
import { userKeyAsRecipient } from '../../src/keys/userKeyCascade.js'
import { memoryDescriptorStores } from './fixtures/descriptorStores.js'

// The container ensure is the crypto-free first step; the factory tests below
// are about the closure's shape (order, single flight, refusal), so the step
// is stubbed and only counted.
vi.mock('../../src/space/provisioning.js', () => ({
  provisionWalletSpace: vi.fn(async () => {})
}))

const spaceId = 'SPACE'
const controllerDid = 'did:key:z6MkController'

// The container ensure is mocked out, so the provisioner's storage client is
// only ever passed through to it.
const was = {} as unknown as WasClient

const EDV_ROSTER_IDS = WALLET_SPACE_PROVISION_ROSTER.filter(
  spec => spec.encryption === 'edv'
).map(spec => spec.collectionId)

// The plaintext roster collections have no descriptor to install onto, so
// their stores cannot create one -- the labelled-failure case below.
const PLAINTEXT_ROSTER_IDS = new Set(
  WALLET_SPACE_PROVISION_ROSTER.filter(spec => spec.encryption !== 'edv').map(
    spec => spec.collectionId
  )
)

/**
 * The stores every test drives: create-if-absent per collection, with the
 * plaintext roster collections uncreatable.
 *
 * @param [options] {object}
 * @param [options.failFor] {function}
 * @param [options.rejectNullishFor] {function}
 * @returns {object}
 */
function fakeStores(
  options: {
    failFor?: (collectionId: string) => boolean
    rejectNullishFor?: (collectionId: string) => boolean
  } = {}
) {
  return memoryDescriptorStores({
    ...options,
    uncreatableFor: collectionId => PLAINTEXT_ROSTER_IDS.has(collectionId)
  })
}

/**
 * A store whose every read raises the given refusal -- one collection's
 * governing log served in a state the verifier will not accept.
 *
 * @param error {unknown}   what the read raises
 * @returns {EncryptionDescriptorStore}
 */
function refusingStore(error: unknown): EncryptionDescriptorStore {
  return {
    async read(): Promise<never> {
      throw error
    },
    async replace() {},
    async create() {}
  }
}

describe('ensureWalletSpaceEpochs', () => {
  it('installs a fresh epoch[0] wrapped to the user key on every encrypted roster collection', async () => {
    const { storeFor, descriptorOf } = fakeStores()
    const userKey = await mintUserKey()

    const { outcomes, failed } = await ensureWalletSpaceEpochs({
      storeFor,
      spaceId,
      userKey
    })

    expect(failed).toEqual([])
    expect(Object.keys(outcomes).sort()).toEqual([...EDV_ROSTER_IDS].sort())
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(outcomes[collectionId]!.installed).toBe(true)
      const descriptor = descriptorOf(collectionId)!
      // The outcome carries the settled descriptor, so a caller building the
      // adopted cipher never re-fetches what it was just handed.
      expect(outcomes[collectionId]!.descriptor).toEqual(descriptor)
      expect(descriptor.epochs).toHaveLength(1)
      expect(descriptor.currentEpoch).toBe(descriptor.epochs![0]!.id)
      // epoch[0] is a fresh random epoch key, never the user-key generation.
      expect(descriptor.currentEpoch).not.toBe(userKey.id)
      // The user key (recipient zero) unwraps it.
      const keys = await resolveEpochKeys({
        encryption: descriptor,
        keyAgreementKey: userKeyVaultKeys({ userKey }).keyAgreementKey
      })
      expect(keys!.readKeys).toHaveLength(1)
      expect(keys!.writeEpoch).toBe(descriptor.currentEpoch)
    }
    // Distinct collections get distinct epoch keys.
    const epochIds = EDV_ROSTER_IDS.map(
      collectionId => descriptorOf(collectionId)!.currentEpoch
    )
    expect(new Set(epochIds).size).toBe(epochIds.length)
  })

  it('installs the blinded-index HMAC key alongside epoch[0]', async () => {
    const { storeFor, descriptorOf } = fakeStores()
    const userKey = await mintUserKey()

    await ensureWalletSpaceEpochs({ storeFor, spaceId, userKey })

    for (const collectionId of EDV_ROSTER_IDS) {
      const hmac = descriptorOf(collectionId)!.hmac!
      expect(hmac).toBeDefined()
      expect(hmac.id).toMatch(/^urn:uuid:/)
      expect(hmac.type).toBe('Sha256HmacKey2019')
      // Wrapped to the same initial recipient set as epoch[0].
      expect(hmac.recipients).toHaveLength(1)
    }
    // Distinct collections get distinct blinding keys.
    const hmacIds = EDV_ROSTER_IDS.map(
      collectionId => descriptorOf(collectionId)!.hmac!.id
    )
    expect(new Set(hmacIds).size).toBe(hmacIds.length)
  })

  it('adopts the installed blinded-index key on a re-run', async () => {
    const { storeFor, descriptorOf, writes } = fakeStores()
    const userKey = await mintUserKey()
    await ensureWalletSpaceEpochs({ storeFor, spaceId, userKey })
    const installedIds = EDV_ROSTER_IDS.map(
      collectionId => descriptorOf(collectionId)!.hmac!.id
    )
    const writesAfterInstall = writes.length

    await ensureWalletSpaceEpochs({ storeFor, spaceId, userKey })

    expect(writes.length).toBe(writesAfterInstall)
    expect(
      EDV_ROSTER_IDS.map(collectionId => descriptorOf(collectionId)!.hmac!.id)
    ).toEqual(installedIds)
  })

  it('adopts a pre-blind-index roster as-is instead of refusing it', async () => {
    const { storeFor, descriptorOf } = fakeStores()
    const userKey = await mintUserKey()
    const store = storeFor('private-credentials')
    // A collection provisioned before blind-index support: epoch[0], no hmac.
    await ensureFirstEpoch({
      store,
      recipients: [userKeyAsRecipient({ userKey })]
    })
    const before = structuredClone(descriptorOf('private-credentials'))

    const { installed, descriptor } = await ensureIndexedFirstEpoch({
      store,
      recipients: [userKeyAsRecipient({ userKey })]
    })

    expect(installed).toBe(false)
    expect(descriptor.hmac).toBeUndefined()
    expect(descriptorOf('private-credentials')).toEqual(before)
  })

  it('rethrows a non-EncryptionError unchanged', async () => {
    const { storeFor } = fakeStores({
      failFor: collectionId => collectionId === 'private-credentials'
    })
    const userKey = await mintUserKey()

    await expect(
      ensureIndexedFirstEpoch({
        store: storeFor('private-credentials'),
        recipients: [userKeyAsRecipient({ userKey })]
      })
    ).rejects.toThrow('Service unavailable for "private-credentials".')
  })

  it('propagates a nullish rejection as it is, without the unindexed retry', async () => {
    const { storeFor, writes } = fakeStores({
      rejectNullishFor: collectionId => collectionId === 'private-credentials'
    })
    const userKey = await mintUserKey()

    const settled = await ensureIndexedFirstEpoch({
      store: storeFor('private-credentials'),
      recipients: [userKeyAsRecipient({ userKey })]
    }).then(
      () => ({ rejected: false as const }),
      (err: unknown) => ({
        rejected: true as const,
        err
      })
    )

    expect(settled.rejected).toBe(true)
    if (!settled.rejected) {
      throw new Error('unreachable')
    }
    expect(settled.err).toBeUndefined()
    expect(writes).toEqual([])
  })

  it('adopts an existing roster untouched on a re-run (installed: false, no write)', async () => {
    const { storeFor, writes, descriptorOf } = fakeStores()
    const userKey = await mintUserKey()
    await ensureWalletSpaceEpochs({ storeFor, spaceId, userKey })
    const settled = EDV_ROSTER_IDS.map(collectionId =>
      structuredClone(descriptorOf(collectionId))
    )
    const writesAfterInstall = writes.length

    const rerun = await ensureWalletSpaceEpochs({ storeFor, spaceId, userKey })

    expect(rerun.failed).toEqual([])
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(rerun.outcomes[collectionId]!.installed).toBe(false)
      // The adopted descriptor comes back too, so `installed: false` need not
      // be read as "nothing to do" -- it is also the plain re-run steady state.
      expect(rerun.outcomes[collectionId]!.descriptor).toEqual(
        descriptorOf(collectionId)
      )
    }
    expect(writes.length).toBe(writesAfterInstall)
    expect(
      EDV_ROSTER_IDS.map(collectionId => descriptorOf(collectionId))
    ).toEqual(settled)
  })

  it('installs behind a roster descriptor whose current epoch IS the user key', async () => {
    const { storeFor, descriptorOf } = fakeStores()
    const userKey = await mintUserKey()
    const rosterDescriptor = {
      currentEpoch: userKey.id,
      epochs: [{ id: userKey.id, recipients: [] }]
    } as unknown as CollectionEncryption

    const result = await ensureWalletSpaceEpochs({
      storeFor,
      spaceId,
      userKey,
      rosterDescriptor
    })

    expect(result.skipped).toBeUndefined()
    expect(result.failed).toEqual([])
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(result.outcomes[collectionId]!.installed).toBe(true)
      expect(descriptorOf(collectionId)!.epochs).toHaveLength(1)
    }
  })

  it('refuses the fan-out whole when the roster delivers another key (skipped, nothing written)', async () => {
    const { storeFor, writes, descriptorOf } = fakeStores()
    const userKey = await mintUserKey()
    const delivered = await mintUserKey()
    const rosterDescriptor = {
      currentEpoch: delivered.id,
      epochs: [{ id: delivered.id, recipients: [] }]
    } as unknown as CollectionEncryption

    const result = await ensureWalletSpaceEpochs({
      storeFor,
      spaceId,
      userKey,
      rosterDescriptor
    })

    expect(result).toEqual({
      outcomes: {},
      failed: [],
      skipped: { rosterEpochId: delivered.id }
    })
    expect(writes).toEqual([])
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(descriptorOf(collectionId)).toBeUndefined()
    }
  })

  it('refuses a malformed roster descriptor naming no current epoch alike', async () => {
    const { storeFor, writes } = fakeStores()
    const userKey = await mintUserKey()

    const result = await ensureWalletSpaceEpochs({
      storeFor,
      spaceId,
      userKey,
      rosterDescriptor: { epochs: [] } as unknown as CollectionEncryption
    })

    expect(result).toEqual({ outcomes: {}, failed: [], skipped: {} })
    expect(writes).toEqual([])
  })

  it('covers explicitly named collections instead of the roster', async () => {
    const { storeFor, descriptorOf, writes } = fakeStores()
    const userKey = await mintUserKey()

    const { outcomes, failed } = await ensureWalletSpaceEpochs({
      storeFor,
      spaceId,
      userKey,
      collectionIds: ['private-credentials']
    })

    expect(failed).toEqual([])
    expect(Object.keys(outcomes)).toEqual(['private-credentials'])
    expect(outcomes['private-credentials']!.installed).toBe(true)
    expect(writes).toEqual(['private-credentials'])
    expect(descriptorOf('private-credentials')!.epochs).toHaveLength(1)
  })

  it('collects a labelled failure naming the failing collection', async () => {
    const { storeFor } = fakeStores()
    const userKey = await mintUserKey()

    // A plaintext collection has no descriptor to install onto; its store
    // cannot create one and the install surfaces the collection by name.
    const { outcomes, failed } = await ensureWalletSpaceEpochs({
      storeFor,
      spaceId,
      userKey,
      collectionIds: ['public-credentials']
    })

    expect(outcomes).toEqual({})
    expect(failed).toHaveLength(1)
    expect(failed[0]!.collectionId).toBe('public-credentials')
    expect((failed[0]!.error as Error).message).toBe(
      'Error installing the first key epoch for collection ' +
        '"public-credentials" in space "SPACE".'
    )
    expect((failed[0]!.error as Error).cause).toBeDefined()
  })

  it('keeps the other collections outcomes when one collection fails', async () => {
    // The partial-outcome contract: `wallet-activity` hits a transient failure
    // while `private-credentials` settles. A caller that must re-mint pending
    // envelopes under the settled descriptor still learns what settled,
    // instead of one throw discarding every outcome.
    const { storeFor, descriptorOf } = fakeStores({
      failFor: collectionId => collectionId === 'wallet-activity'
    })
    const userKey = await mintUserKey()

    const { outcomes, failed } = await ensureWalletSpaceEpochs({
      storeFor,
      spaceId,
      userKey
    })

    expect(failed).toHaveLength(1)
    expect(failed[0]!.collectionId).toBe('wallet-activity')
    expect(Object.keys(outcomes).sort()).toEqual(
      EDV_ROSTER_IDS.filter(
        collectionId => collectionId !== 'wallet-activity'
      ).sort()
    )
    for (const collectionId of Object.keys(outcomes)) {
      expect(outcomes[collectionId]!.installed).toBe(true)
      expect(outcomes[collectionId]!.descriptor).toEqual(
        descriptorOf(collectionId)
      )
    }
  })

  it('carries a collection log integrity refusal in failed verbatim, never throwing', async () => {
    // A fabricated governing log is a security signal, and the report says
    // so by the refusal's own name (unwrapped, unlike an ordinary failure);
    // the settled collections are still reported.
    const { storeFor, descriptorOf } = fakeStores()
    const userKey = await mintUserKey()
    const refusingStoreFor = (collectionId: string) =>
      collectionId === 'wallet-activity'
        ? refusingStore(
            new ResourceLogIntegrityError(
              'entry 2 carries a proof no listed key made'
            )
          )
        : storeFor(collectionId)

    const { outcomes, failed } = await ensureWalletSpaceEpochs({
      storeFor: refusingStoreFor,
      spaceId,
      userKey
    })

    expect(failed).toHaveLength(1)
    expect(failed[0]!.collectionId).toBe('wallet-activity')
    expect(failed[0]!.error).toMatchObject({
      name: 'ResourceLogIntegrityError'
    })
    expect(Object.keys(outcomes).sort()).toEqual(
      EDV_ROSTER_IDS.filter(
        collectionId => collectionId !== 'wallet-activity'
      ).sort()
    )
    expect(descriptorOf('private-credentials')!.epochs).toHaveLength(1)
  })

  it('refuses a missing storeFor with a TypeError before any write', async () => {
    const userKey = await mintUserKey()
    await expect(
      ensureWalletSpaceEpochs({
        spaceId,
        userKey
      } as unknown as Parameters<typeof ensureWalletSpaceEpochs>[0])
    ).rejects.toThrow(TypeError)
  })

  it('keeps a continuity rollback a per-collection failure', async () => {
    // The predicate's carve-out: a rollback is reconcilable divergence,
    // possibly nothing worse than replication lag.
    const { storeFor } = fakeStores()
    const userKey = await mintUserKey()
    const laggingStoreFor = (collectionId: string) =>
      collectionId === 'wallet-activity'
        ? refusingStore(
            new ResourceLogContinuityError({
              reason: 'rollback',
              pinnedHead: '3-zHead'
            })
          )
        : storeFor(collectionId)

    const { outcomes, failed } = await ensureWalletSpaceEpochs({
      storeFor: laggingStoreFor,
      spaceId,
      userKey
    })

    expect(failed).toHaveLength(1)
    expect(failed[0]!.collectionId).toBe('wallet-activity')
    expect(((failed[0]!.error as Error).cause as Error).name).toBe(
      'ResourceLogContinuityError'
    )
    expect(Object.keys(outcomes).sort()).toEqual(
      EDV_ROSTER_IDS.filter(
        collectionId => collectionId !== 'wallet-activity'
      ).sort()
    )
  })
})

describe('walletSpaceProvisioner', () => {
  it('runs the two-step in order and hands the settled report to onSettled', async () => {
    const { storeFor, descriptorOf } = fakeStores()
    const userKey = await mintUserKey()
    vi.mocked(provisionWalletSpace).mockClear()
    const settled: string[][] = []

    const ensureProvisioned = walletSpaceProvisioner({
      was,
      spaceId,
      controllerDid,
      userKey,
      storeFor,
      onSettled: result => {
        settled.push(Object.keys(result.outcomes).sort())
      }
    })
    await ensureProvisioned()

    expect(provisionWalletSpace).toHaveBeenCalledWith({
      was,
      spaceId,
      controllerDid
    })
    expect(settled).toEqual([[...EDV_ROSTER_IDS].sort()])
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(descriptorOf(collectionId)!.epochs).toHaveLength(1)
    }
  })

  it('is single-flight: concurrent calls share one in-flight run', async () => {
    const { storeFor, writes } = fakeStores()
    const userKey = await mintUserKey()
    vi.mocked(provisionWalletSpace).mockClear()

    const ensureProvisioned = walletSpaceProvisioner({
      was,
      spaceId,
      controllerDid,
      userKey,
      storeFor
    })
    await Promise.all([ensureProvisioned(), ensureProvisioned()])

    expect(provisionWalletSpace).toHaveBeenCalledTimes(1)
    expect(writes).toHaveLength(EDV_ROSTER_IDS.length)

    // A later call runs again (the engine memoizes; the closure does not).
    await ensureProvisioned()
    expect(provisionWalletSpace).toHaveBeenCalledTimes(2)
  })

  it('refuses when a collection was left without its epoch, naming it, after handing the partial report on', async () => {
    const { storeFor } = fakeStores({
      failFor: collectionId => collectionId === 'wallet-activity'
    })
    const userKey = await mintUserKey()
    const settled: unknown[] = []

    const ensureProvisioned = walletSpaceProvisioner({
      was,
      spaceId,
      controllerDid,
      userKey,
      storeFor,
      onSettled: result => {
        settled.push(result)
      }
    })
    const err = await ensureProvisioned().catch(caught => caught)

    expect(err).toBeInstanceOf(WalletSpaceProvisioningError)
    expect(err.name).toBe('WalletSpaceProvisioningError')
    expect(err.message).toContain('"wallet-activity"')
    expect(
      err.failed.map((entry: { collectionId: string }) => entry.collectionId)
    ).toEqual(['wallet-activity'])
    // The settled collections still reach the hook, ahead of the refusal.
    expect(settled).toHaveLength(1)
    expect(
      Object.keys((settled[0] as { outcomes: object }).outcomes).sort()
    ).toEqual(EDV_ROSTER_IDS.filter(id => id !== 'wallet-activity').sort())
  })
})
