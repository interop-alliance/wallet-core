/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * `provisionWalletSpace`: the one-shot full-roster provisioner. Drives a
 * recording fake of the was-client surface `ensureSpaceAndCollection` touches
 * (`space().describe` / `.configure`, `space().collection().describeWithEtag`
 * / `.configure` / `.replaceDescription` / `.isPublic` / `.setPublic`) and
 * asserts the layout every
 * wallet client provisions identically, plus the non-clobbering behavior over
 * an already-provisioned Space.
 */
import { describe, expect, it } from 'vitest'

import type { WasClient } from '@interop/was-client'

import {
  provisionWalletSpace,
  WALLET_SPACE_NAME,
  WALLET_SPACE_PROVISION_ROSTER
} from '../../src/space/index.js'

interface CollectionConfigure {
  collectionId: string
  name?: string
  encryption?: { scheme: string; version?: number }
  force?: boolean
  current?: unknown
}

function fakeWas({
  provisioned = false,
  legacyDescriptor = false,
  failConfigure
}: {
  // When true, every describe reports the Space/collections as already
  // existing and the public policies as already granted. An `edv` collection
  // serves what a governed server derives from its history log's head: the
  // epoch-bearing descriptor stamped with the `history` member. A
  // client-written descriptor (no `history`) is what `legacyDescriptor`
  // serves instead.
  provisioned?: boolean
  // With `provisioned`, every `edv` collection serves a client-written
  // descriptor -- an account provisioned before collections were governed.
  legacyDescriptor?: boolean
  // Throws on a collection configure matching (collectionId, and whether the
  // call declares an encryption descriptor) -- undefined fails nothing.
  failConfigure?: (call: CollectionConfigure) => boolean
} = {}) {
  const specs = new Map(
    WALLET_SPACE_PROVISION_ROSTER.map(spec => [spec.collectionId, spec])
  )
  const calls = {
    spaceConfigures: [] as Array<{
      spaceId: string
      name?: string
      controller?: string
    }>,
    collectionConfigures: [] as CollectionConfigure[],
    setPublics: [] as string[]
  }
  const was = {
    space: (spaceId: string) => ({
      describe: async () =>
        provisioned
          ? {
              id: spaceId,
              type: ['Space'],
              name: WALLET_SPACE_NAME,
              controller: 'did:webvh:x'
            }
          : null,
      configure: async (opts: { name?: string; controller?: string }) => {
        calls.spaceConfigures.push({ spaceId, ...opts })
        // Mirror the real `Space.configure`, which returns the description it
        // wrote -- what `ensureSpace` hands back for the fan-out to thread.
        return { id: spaceId, type: ['Space'], ...opts }
      },
      // The guarded create `ensureSpace` runs on an absent Space; recorded
      // beside the configures, since it is the same write.
      replaceDescription: async (opts: {
        name?: string
        controller?: string
      }) => {
        calls.spaceConfigures.push({ spaceId, ...opts })
        return {
          description: { id: spaceId, type: ['Space'], ...opts },
          etag: '"1"'
        }
      },
      collection: (collectionId: string) => ({
        describeWithEtag: async () => {
          if (!provisioned) {
            return null
          }
          const spec = specs.get(collectionId)
          return {
            description: {
              name: spec?.name,
              ...(spec?.encryption === 'edv'
                ? {
                    encryption: {
                      scheme: 'edv',
                      version: 1,
                      ...(legacyDescriptor
                        ? {}
                        : {
                            currentEpoch: 'did:key:z6LSepoch0',
                            epochs: [
                              { id: 'did:key:z6LSepoch0', recipients: [] }
                            ],
                            history: {
                              method: 'resource-log:0.1',
                              resource: `https://was.test/space/${spaceId}/${collectionId}/meta/log`
                            }
                          })
                    }
                  }
                : {})
            },
            etag: '"1"'
          }
        },
        // The guarded create on an absent collection (recorded as a
        // configure, since it is the same write). The compare-and-swapped
        // late declaration is never driven: a provisioned Space here always
        // carries its descriptors.
        replaceDescription: async (
          description: {
            name?: string
            encryption?: { scheme: string; version?: number }
          },
          { ifNoneMatch }: { ifMatch?: string; ifNoneMatch?: boolean }
        ) => {
          if (!ifNoneMatch || provisioned) {
            throw new Error(
              `Unexpected replaceDescription of "${collectionId}".`
            )
          }
          const call = { collectionId, ...description }
          if (failConfigure?.(call)) {
            throw new Error(`Refused configure of "${collectionId}".`)
          }
          calls.collectionConfigures.push(call)
          return { description, etag: '"1"' }
        },
        configure: async (opts: {
          name?: string
          encryption?: { scheme: string; version?: number }
          force?: boolean
          current?: unknown
        }) => {
          const call = { collectionId, ...opts }
          if (failConfigure?.(call)) {
            throw new Error(`Refused configure of "${collectionId}".`)
          }
          calls.collectionConfigures.push(call)
        },
        isPublic: async () => provisioned,
        setPublic: async () => {
          calls.setPublics.push(collectionId)
        }
      })
    })
  } as unknown as WasClient
  return { was, calls }
}

const spaceId = 'SPACE'
const controllerDid = 'did:key:zController'

describe('provisionWalletSpace', () => {
  it('provisions every roster collection with its declared config', async () => {
    const { was, calls } = fakeWas()

    await provisionWalletSpace({ was, spaceId, controllerDid })

    // The absent Space is created ONCE, before the fan-out, with the
    // app-neutral name and the controller. Ensuring it inside the fan-out
    // instead cost one create per roster entry, since no branch can observe
    // another's.
    expect(calls.spaceConfigures).toEqual([
      // No `current` is threaded in: the create merges against the re-read
      // inside `configure`, not against the absent describe this ensure made.
      { spaceId, name: WALLET_SPACE_NAME, controller: controllerDid }
    ])

    // Every collection is configured exactly once, under its roster display
    // name, and NONE of them carries an `encryption` member: an `edv` roster
    // collection is ensured as `'governed'`, so its descriptor is the
    // server's to derive from the governing log its epoch[0] install creates.
    // A Description written with a descriptor here could never be governed.
    expect(
      new Map(calls.collectionConfigures.map(call => [call.collectionId, call]))
    ).toEqual(
      new Map(
        WALLET_SPACE_PROVISION_ROSTER.map(spec => [
          spec.collectionId,
          {
            collectionId: spec.collectionId,
            name: spec.name
          }
        ])
      )
    )
    expect(
      calls.collectionConfigures.filter(call => call.encryption !== undefined)
    ).toEqual([])

    // World read lands on exactly the public collections.
    expect([...calls.setPublics].sort()).toEqual(
      WALLET_SPACE_PROVISION_ROSTER.filter(s => s.isPublic)
        .map(s => s.collectionId)
        .sort()
    )
    expect(calls.setPublics).toContain('id')
    expect(calls.setPublics).toContain('public-credentials')
  })

  it('issues no writes over an already-provisioned Space', async () => {
    // The enrolled-client heal path's settled case: a client that joined a
    // Space another wallet provisioned re-runs the full roster and touches
    // nothing -- no Space reconfigure, no descriptor re-declaration (whose
    // bare re-send would drop appended key epochs), no policy rewrite.
    const { was, calls } = fakeWas({ provisioned: true })

    await provisionWalletSpace({ was, spaceId, controllerDid })

    expect(calls.spaceConfigures).toEqual([])
    expect(calls.collectionConfigures).toEqual([])
    expect(calls.setPublics).toEqual([])
  })

  it('refuses a collection born with a client-written descriptor, writing nothing', async () => {
    // An account provisioned before its collections were governed: the
    // server holds a declared descriptor immutable and derives a governed
    // one from the history log, so the two are exclusive and such a
    // collection can never be governed. It is refused rather than adopted;
    // the account is re-provisioned from scratch.
    const { was, calls } = fakeWas({
      provisioned: true,
      legacyDescriptor: true
    })

    await expect(
      provisionWalletSpace({ was, spaceId, controllerDid })
    ).rejects.toThrow('Error provisioning collection')
    expect(calls.spaceConfigures).toEqual([])
    expect(calls.collectionConfigures).toEqual([])
    expect(calls.setPublics).toEqual([])
  })

  it('throws (with a labelled error) when a collection ensure fails', async () => {
    const { was } = fakeWas({
      failConfigure: call => call.collectionId === 'key-map'
    })

    await expect(
      provisionWalletSpace({ was, spaceId, controllerDid })
    ).rejects.toThrow('Error provisioning collection "key-map"')
  })

  it('throws (with a labelled error) when an encrypted collection ensure fails', async () => {
    const { was } = fakeWas({
      failConfigure: call => call.collectionId === 'wallet-activity'
    })

    await expect(
      provisionWalletSpace({ was, spaceId, controllerDid })
    ).rejects.toThrow('Error provisioning collection "wallet-activity"')
  })
})
