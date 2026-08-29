/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * `provisionWalletSpace`: the one-shot full-roster provisioner. Drives a
 * recording fake of the was-client surface `ensureSpaceAndCollection` touches
 * (`space().describe` / `.configure`, `space().collection().describe` /
 * `.configure` / `.isPublic` / `.setPublic`) and asserts the layout every
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
  failConfigure
}: {
  // When true, every describe reports the Space/collections as already
  // existing (collections with an encryption descriptor where declared) and
  // the public policies as already granted.
  provisioned?: boolean
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
          ? { name: WALLET_SPACE_NAME, controller: 'did:webvh:x' }
          : null,
      configure: async (opts: { name?: string; controller?: string }) => {
        calls.spaceConfigures.push({ spaceId, ...opts })
        // Mirror the real `Space.configure`, which returns the description it
        // wrote -- what `ensureSpace` hands back for the fan-out to thread.
        return { id: spaceId, type: ['Space'], ...opts }
      },
      collection: (collectionId: string) => ({
        describe: async () => {
          if (!provisioned) {
            return null
          }
          const spec = specs.get(collectionId)
          return {
            name: spec?.name,
            ...(spec?.encryption === 'edv'
              ? { encryption: { scheme: 'edv', version: 1 } }
              : {})
          }
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
      // `current: null` is the describe this ensure already made, threaded in
      // so `configure` does not repeat it.
      { spaceId, name: WALLET_SPACE_NAME, controller: controllerDid, current: null }
    ])

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
                current: null,
                encryption: { scheme: 'edv', version: 1 }
              }
            : {
                collectionId: spec.collectionId,
                name: spec.name,
                current: null,
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
