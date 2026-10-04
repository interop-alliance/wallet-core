/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The wallet Space provisioning two-step against the real server: on a Space
 * that is already laid out, a second `provisionWalletSpace` and an
 * `ensureWalletSpaceEpochs` over settled epochs only read. The suite also
 * pins the served shapes a fake Space must mirror: the Space Metadata
 * object's `id`, `controller`, and container `url`, and each roster
 * collection's description: bare after provisioning alone (a public `id`
 * collection, no `encryption` member anywhere), and after the epoch install
 * a server-derived `encryption` naming its governing history log on each
 * encrypted collection and none on a plaintext one.
 */
import { RESOURCE_LOG_METHOD } from '@interop/storage-core'
import { WasClient } from '@interop/was-client'
import { agentsFromSeed } from '@interop/was-client/identity'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import type { RequestFaults } from 'was-teaching-server/testing'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { mintSpaceId } from '../../src/genesis/index.js'
import {
  accountCollectionStores,
  ensureWalletSpaceEpochs,
  userKeyRosterDescriptorStore,
  userKeyRosterLogSigner
} from '../../src/keys/index.js'
import { webvhResourceLogController } from '../../src/resourceLog/index.js'
import {
  ID_COLLECTION,
  provisionWalletSpace,
  WALLET_SPACE_PROVISION_ROSTER
} from '../../src/space/index.js'
import { encryptedWalletCollectionIds } from '../../src/space/collections.js'
import { buildEnrolledClientAccount } from '../../src/testing/index.js'
import { didKeyZcapClient, verifyAccountLog } from '../../src/webvh/index.js'
import { bootServer } from './fixtures/credentialAnchoredAccount.js'

/**
 * The recorded requests whose method is anything but a read.
 *
 * @param options {object}
 * @param options.faults {RequestFaults}
 * @returns {RequestFaults['requests']}
 */
function nonReadRequests({ faults }: { faults: RequestFaults }) {
  return faults.requests.filter(
    record => record.method !== 'GET' && record.method !== 'HEAD'
  )
}

describe('wallet Space provisioning run twice against the real server', () => {
  let server: Awaited<ReturnType<typeof bootServer>>

  beforeAll(async () => {
    server = await bootServer()
  })

  afterAll(async () => {
    await server.close()
  })

  it('re-provisions a bare Space with reads only and serves the described layout', async () => {
    const { keyAgent } = await agentsFromSeed({
      seed: crypto.getRandomValues(new Uint8Array(32))
    })
    const controllerDid = keyAgent.id
    const was = new WasClient({
      serverUrl: server.serverUrl,
      zcapClient: didKeyZcapClient({ keyAgent })
    })
    const spaceId = mintSpaceId()

    await provisionWalletSpace({ was, spaceId, controllerDid })
    server.faults.reset()
    await provisionWalletSpace({ was, spaceId, controllerDid })

    // The record is not empty: the run did reach the server.
    expect(server.faults.requests.length).toBeGreaterThan(0)
    const writes = nonReadRequests({ faults: server.faults })
    expect(
      writes,
      `the second run wrote: ${JSON.stringify(writes, null, 2)}`
    ).toEqual([])

    // A fake's Space Metadata object must carry its own `id` (a description
    // without one was the defect fakes once served).
    const space = was.space(spaceId)
    const description = await space.describe()
    expect(description).not.toBeNull()
    expect(description!.id).toBe(spaceId)
    expect(description!.controller).toBe(controllerDid)
    expect(description!.url).toMatch(new RegExp(`/space/${spaceId}/$`))

    for (const spec of WALLET_SPACE_PROVISION_ROSTER) {
      const collection = space.collection(spec.collectionId)
      const collectionDescription = await collection.describe()
      expect(collectionDescription, spec.collectionId).not.toBeNull()
      expect(collectionDescription!.id).toBe(spec.collectionId)
      // Every collection is created bare: an encrypted one is declared by its
      // governing log's genesis, which `ensureWalletSpaceEpochs` runs, so
      // provisioning alone leaves no `encryption` member on any of them.
      expect(
        collectionDescription!.encryption,
        spec.collectionId
      ).toBeUndefined()
      expect(await collection.isPublic(), spec.collectionId).toBe(spec.isPublic)
    }
    expect(await space.collection(ID_COLLECTION.id).isPublic()).toBe(true)
  })

  it('re-runs both steps as an enrolled client on a provisioned account with reads only', async () => {
    const account = await buildEnrolledClientAccount({
      serverUrl: server.serverUrl
    })
    const {
      accountDid: did,
      spaceId,
      serverUrl: host,
      client: { zcapClient, userKey, agents }
    } = account
    const signer = userKeyRosterLogSigner({ keyAgent: agents.keyAgent })
    const rosterRead = await userKeyRosterDescriptorStore({
      storageServerUrl: host,
      zcapClient,
      spaceId,
      resolveController: async () =>
        webvhResourceLogController({
          did,
          log: (await verifyAccountLog({ did, spaceId, host })).log
        }),
      pinStore: memoryResourceLogPinStore(),
      signer
    }).read()
    if (rosterRead === null) {
      throw new Error('test: the account has no roster')
    }
    const was = new WasClient({ serverUrl: host, zcapClient })

    server.faults.reset()
    await provisionWalletSpace({ was, spaceId, controllerDid: did })
    const result = await ensureWalletSpaceEpochs({
      storeFor: accountCollectionStores({
        storageServerUrl: host,
        zcapClient,
        spaceId,
        did,
        pinStore: memoryResourceLogPinStore(),
        signer
      }),
      userKey,
      rosterDescriptor: rosterRead.descriptor,
      spaceId
    })

    // The record is not empty: the run did reach the server.
    expect(server.faults.requests.length).toBeGreaterThan(0)
    const writes = nonReadRequests({ faults: server.faults })
    expect(
      writes,
      `the login-time re-run wrote: ${JSON.stringify(writes, null, 2)}`
    ).toEqual([])

    expect(result.skipped).toBeUndefined()
    expect(result.failed).toEqual([])
    expect(new Set(Object.keys(result.outcomes))).toEqual(
      new Set(encryptedWalletCollectionIds())
    )
    for (const [collectionId, outcome] of Object.entries(result.outcomes)) {
      expect(outcome.installed, collectionId).toBe(false)
      const { descriptor } = outcome
      expect(
        descriptor.epochs?.map(epoch => epoch.id),
        collectionId
      ).toContain(descriptor.currentEpoch)
    }

    // The served shape a fake must mirror once the epochs are installed: an
    // encrypted collection's `encryption` is the server-derived member naming
    // its governing history log, and a plaintext collection carries none.
    const space = was.space(spaceId)
    const encrypted = new Set(encryptedWalletCollectionIds())
    for (const spec of WALLET_SPACE_PROVISION_ROSTER) {
      const collectionDescription = await space
        .collection(spec.collectionId)
        .describe()
      expect(collectionDescription, spec.collectionId).not.toBeNull()
      if (encrypted.has(spec.collectionId)) {
        expect(
          collectionDescription!.encryption?.history,
          spec.collectionId
        ).toMatchObject({ method: RESOURCE_LOG_METHOD })
      } else {
        expect(
          collectionDescription!.encryption,
          spec.collectionId
        ).toBeUndefined()
      }
    }
  })
})
