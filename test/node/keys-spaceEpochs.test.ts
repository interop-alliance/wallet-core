/**
 * `ensureWalletSpaceEpochs`: the provision-time epoch[0] install for the
 * wallet Space's encrypted collections. Drives the real `ensureFirstEpoch`
 * CAS/create path against a recording fake of the was-client Collection
 * Description surface, and asserts every encrypted roster collection gains a
 * fresh epoch[0] wrapped to the user key -- fresh random, never the user-key
 * generation itself -- while an already-installed roster is adopted untouched.
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
function fakeWas() {
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

    const installed = await ensureWalletSpaceEpochs({ was, spaceId, userKey })

    expect(Object.keys(installed).sort()).toEqual([...EDV_ROSTER_IDS].sort())
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(installed[collectionId]).toBe(true)
      const descriptor = descriptorOf(collectionId)
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

    for (const collectionId of EDV_ROSTER_IDS) {
      expect(rerun[collectionId]).toBe(false)
    }
    expect(replaces.length).toBe(writesAfterInstall)
    expect(
      EDV_ROSTER_IDS.map(collectionId => descriptorOf(collectionId))
    ).toEqual(settled)
  })

  it('covers explicitly named collections instead of the roster', async () => {
    const { was, descriptorOf, replaces } = fakeWas()
    const userKey = await mintUserKey()

    const installed = await ensureWalletSpaceEpochs({
      was,
      spaceId,
      userKey,
      collectionIds: ['private-credentials']
    })

    expect(installed).toEqual({ 'private-credentials': true })
    expect(replaces).toEqual(['private-credentials'])
    expect(descriptorOf('private-credentials').epochs).toHaveLength(1)
  })

  it('throws a labelled error naming the failing collection', async () => {
    const { was } = fakeWas()
    const userKey = await mintUserKey()

    // A plaintext collection has no descriptor to install onto; the adapter
    // refuses it and the install surfaces the collection by name.
    await expect(
      ensureWalletSpaceEpochs({
        was,
        spaceId,
        userKey,
        collectionIds: ['public-credentials']
      })
    ).rejects.toThrow(
      'Error installing the first key epoch for collection ' +
        '"public-credentials" in space "SPACE".'
    )
  })
})
