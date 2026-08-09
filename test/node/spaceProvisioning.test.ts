/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * `provisionWalletSpace`: the one-shot full-roster provisioner. Drives a
 * recording fake of the was-client surface `ensureSpaceAndCollection` touches
 * (`space().configure`, `space().collection().configure` / `.setPublic`) and
 * asserts the layout every wallet app provisions identically.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { WasClient } from '@interop/was-client'

import {
  provisionWalletSpace,
  WALLET_SPACE_NAME,
  WALLET_SPACE_PROVISION_ROSTER
} from '../../src/space/index.js'

interface CollectionConfigure {
  collectionId: string
  name?: string
  encryption?: { scheme: string }
  force?: boolean
}

function fakeWas({
  failConfigure
}: {
  // Throws on a collection configure matching (collectionId, and whether the
  // call declares an encryption descriptor) -- undefined fails nothing.
  failConfigure?: (call: CollectionConfigure) => boolean
} = {}) {
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
      configure: async (opts: { name?: string; controller?: string }) => {
        calls.spaceConfigures.push({ spaceId, ...opts })
      },
      collection: (collectionId: string) => ({
        configure: async (opts: {
          name?: string
          encryption?: { scheme: string }
          force?: boolean
        }) => {
          const call = { collectionId, ...opts }
          if (failConfigure?.(call)) {
            throw new Error(`Refused configure of "${collectionId}".`)
          }
          calls.collectionConfigures.push(call)
        },
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

afterEach(() => {
  vi.restoreAllMocks()
})

describe('provisionWalletSpace', () => {
  it('provisions every roster collection with its declared config', async () => {
    const { was, calls } = fakeWas()

    await provisionWalletSpace({ was, spaceId, controllerDid })

    // The Space itself is (re)configured once per collection ensure, always
    // with the app-neutral name and the controller.
    expect(calls.spaceConfigures).toHaveLength(
      WALLET_SPACE_PROVISION_ROSTER.length
    )
    for (const configure of calls.spaceConfigures) {
      expect(configure).toEqual({
        spaceId,
        name: WALLET_SPACE_NAME,
        controller: controllerDid
      })
    }

    // Every collection is configured exactly once, under its roster display
    // name, with the encryption declaration matching its spec.
    expect(
      new Map(calls.collectionConfigures.map(c => [c.collectionId, c]))
    ).toEqual(
      new Map(
        WALLET_SPACE_PROVISION_ROSTER.map(spec => [
          spec.collectionId,
          spec.encryption === 'edv'
            ? {
                collectionId: spec.collectionId,
                name: spec.name,
                encryption: { scheme: 'edv' }
              }
            : {
                collectionId: spec.collectionId,
                name: spec.name,
                force: true
              }
        ])
      )
    )

    // World read lands on exactly the public collections.
    expect([...calls.setPublics].sort()).toEqual(
      WALLET_SPACE_PROVISION_ROSTER.filter(s => s.isPublic)
        .map(s => s.collectionId)
        .sort()
    )
    expect(calls.setPublics).toContain('id')
    expect(calls.setPublics).toContain('public-credentials')
  })

  it('retries an encrypted collection with a name-only configure', async () => {
    // The epoch refusal: a full ensure that re-declares `encryption` on a
    // descriptor already carrying key epochs is rejected; the name-only
    // configure merges forward and succeeds.
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { was, calls } = fakeWas({
      failConfigure: call =>
        call.collectionId === 'private-credentials' &&
        call.encryption !== undefined
    })

    await provisionWalletSpace({ was, spaceId, controllerDid })

    const retried = calls.collectionConfigures.filter(
      c => c.collectionId === 'private-credentials'
    )
    expect(retried).toEqual([
      { collectionId: 'private-credentials', name: 'Verifiable Credentials' }
    ])
    expect(warn).toHaveBeenCalledOnce()
  })

  it('throws (with the original cause) when a plaintext ensure fails', async () => {
    // A plaintext collection gets no name-only retry: the failure cannot be
    // the epoch refusal, so it surfaces.
    const { was } = fakeWas({
      failConfigure: call => call.collectionId === 'key-map'
    })

    await expect(
      provisionWalletSpace({ was, spaceId, controllerDid })
    ).rejects.toThrow('Error provisioning collection "key-map"')
  })

  it('throws when the name-only retry also fails', async () => {
    const { was } = fakeWas({
      failConfigure: call => call.collectionId === 'wallet-activity'
    })

    await expect(
      provisionWalletSpace({ was, spaceId, controllerDid })
    ).rejects.toThrow('Error provisioning collection "wallet-activity"')
  })
})
