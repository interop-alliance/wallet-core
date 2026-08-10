/**
 * `ensureWalletSpaceEpochs`: the provision-time epoch[0] install for the
 * wallet Space's encrypted collections. Drives the real `ensureFirstEpoch`
 * CAS/create path against a recording fake of the was-client Collection
 * Description surface, and asserts every encrypted roster collection gains a
 * fresh epoch[0] wrapped to the user key -- fresh random, never the user-key
 * generation itself -- while an already-installed roster is adopted untouched.
 * Also covers the partial-outcome contract: a failing collection lands in
 * `failed` without discarding the descriptors the other collections settled on.
 */
import { describe, expect, it } from 'vitest'

import type { WasClient } from '@interop/was-client'
import { PreconditionFailedError } from '@interop/was-client'
import type { CollectionEncryption } from '@interop/was-client'
import { resolveEpochKeys } from '@interop/was-client/edv'

import { WALLET_SPACE_PROVISION_ROSTER } from '../../src/space/index.js'
import { mintUserKey, userKeyVaultKeys } from '../../src/keys/userKey.js'
import { ensureWalletSpaceEpochs } from '../../src/keys/spaceEpochs.js'

const spaceId = 'SPACE'

const EDV_ROSTER_IDS = WALLET_SPACE_PROVISION_ROSTER.filter(
  spec => spec.encryption === 'edv'
).map(spec => spec.collectionId)

// The Collection Description fields the descriptor-store adapter reads and
// writes back (`id` / `type` and the rest stay server-side in this fake).
interface StoredDescription {
  name?: string
  backend?: unknown
  encryption?: CollectionEncryption
}

/**
 * A fake was client hosting per-collection Collection Descriptions with real
 * etag semantics, as left by `provisionWalletSpace`: every roster collection
 * declared, the encrypted ones carrying a bare epoch-less `edv` descriptor.
 */
function fakeWas({
  // Throws on every Description read for a matching collection id -- the
  // transient server failure the partial-outcome contract is about.
  failFor
}: { failFor?: (collectionId: string) => boolean } = {}) {
  const descriptions = new Map<
    string,
    { description: StoredDescription; version: number }
  >()
  for (const spec of WALLET_SPACE_PROVISION_ROSTER) {
    descriptions.set(spec.collectionId, {
      description: {
        name: spec.name,
        ...(spec.encryption === 'edv'
          ? { encryption: { scheme: 'edv', version: 1 } }
          : {})
      },
      version: 0
    })
  }
  const replaces: string[] = []
  const was = {
    space: (requestedSpaceId: string) => {
      expect(requestedSpaceId).toBe(spaceId)
      return {
        collection: (collectionId: string) => ({
          describeWithEtag: async () => {
            if (failFor?.(collectionId)) {
              throw new Error(`Service unavailable for "${collectionId}".`)
            }
            const entry = descriptions.get(collectionId)
            return entry
              ? {
                  description: structuredClone(entry.description),
                  etag: `v${entry.version}`
                }
              : null
          },
          replaceDescription: async (
            description: StoredDescription,
            { ifMatch }: { ifMatch?: string }
          ) => {
            const entry = descriptions.get(collectionId)!
            if (ifMatch !== `v${entry.version}`) {
              throw new PreconditionFailedError('stale description etag')
            }
            entry.description = structuredClone(description)
            entry.version++
            replaces.push(collectionId)
          }
        })
      }
    }
  } as unknown as WasClient
  const descriptorOf = (collectionId: string): CollectionEncryption =>
    descriptions.get(collectionId)!.description.encryption!
  return { was, replaces, descriptorOf }
}

describe('ensureWalletSpaceEpochs', () => {
  it('installs a fresh epoch[0] wrapped to the user key on every encrypted roster collection', async () => {
    const { was, descriptorOf } = fakeWas()
    const userKey = await mintUserKey()

    const { outcomes, failed } = await ensureWalletSpaceEpochs({
      was,
      spaceId,
      userKey
    })

    expect(failed).toEqual([])
    expect(Object.keys(outcomes).sort()).toEqual([...EDV_ROSTER_IDS].sort())
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(outcomes[collectionId]!.installed).toBe(true)
      const descriptor = descriptorOf(collectionId)
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
      collectionId => descriptorOf(collectionId).currentEpoch
    )
    expect(new Set(epochIds).size).toBe(epochIds.length)
  })

  it('adopts an existing roster untouched on a re-run (installed: false, no write)', async () => {
    const { was, replaces, descriptorOf } = fakeWas()
    const userKey = await mintUserKey()
    await ensureWalletSpaceEpochs({ was, spaceId, userKey })
    const settled = EDV_ROSTER_IDS.map(collectionId =>
      structuredClone(descriptorOf(collectionId))
    )
    const writesAfterInstall = replaces.length

    const rerun = await ensureWalletSpaceEpochs({ was, spaceId, userKey })

    expect(rerun.failed).toEqual([])
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(rerun.outcomes[collectionId]!.installed).toBe(false)
      // The adopted descriptor comes back too, so `installed: false` need not
      // be read as "nothing to do" -- it is also the plain re-run steady state.
      expect(rerun.outcomes[collectionId]!.descriptor).toEqual(
        descriptorOf(collectionId)
      )
    }
    expect(replaces.length).toBe(writesAfterInstall)
    expect(
      EDV_ROSTER_IDS.map(collectionId => descriptorOf(collectionId))
    ).toEqual(settled)
  })

  it('covers explicitly named collections instead of the roster', async () => {
    const { was, descriptorOf, replaces } = fakeWas()
    const userKey = await mintUserKey()

    const { outcomes, failed } = await ensureWalletSpaceEpochs({
      was,
      spaceId,
      userKey,
      collectionIds: ['private-credentials']
    })

    expect(failed).toEqual([])
    expect(Object.keys(outcomes)).toEqual(['private-credentials'])
    expect(outcomes['private-credentials']!.installed).toBe(true)
    expect(replaces).toEqual(['private-credentials'])
    expect(descriptorOf('private-credentials').epochs).toHaveLength(1)
  })

  it('collects a labelled failure naming the failing collection', async () => {
    const { was } = fakeWas()
    const userKey = await mintUserKey()

    // A plaintext collection has no descriptor to install onto; the adapter
    // refuses it and the install surfaces the collection by name.
    const { outcomes, failed } = await ensureWalletSpaceEpochs({
      was,
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
    const { was, descriptorOf } = fakeWas({
      failFor: collectionId => collectionId === 'wallet-activity'
    })
    const userKey = await mintUserKey()

    const { outcomes, failed } = await ensureWalletSpaceEpochs({
      was,
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
})
