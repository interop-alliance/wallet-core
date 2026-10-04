/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The WAS v0.5 ceremony round trip against the reference server, over one
 * credential-anchored account: establish it, rotate an epoch, mend a torn
 * annex, and delete a Space. The tests run in order and share the account.
 *
 * What the suite pins is the v0.5 contract a fake must mirror:
 *
 * - the served service description names WAS version `0.5`;
 * - the single-verb Space capability's verb-and-target pair, `DELETE` on the
 *   canonical Space URL (trailing slash) and `GET` on the Space Metadata
 *   object at `meta`, both minted by the ladder VM over the Space's
 *   synthesized root and admitted by the server;
 * - the `meta` existence probe the annex mend runs when the pointed annex
 *   Space is gone, answered 404 for a deleted Space.
 *
 * The epoch rotation is the recovery-code revocation's tail as a transient
 * session on the credential runs it: `removeRecoveryKey` strikes the code's
 * inventory in one ladder-signed entry, then
 * `rotateRosterToDocumentAndCascade` converges the roster onto the post-edit
 * document (the ceremony-tail license's inventory-changing shape) and fans
 * out to every encrypted collection. A second cascade run is all no-ops.
 */
import { WasClient } from '@interop/was-client'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'
import { spaceMeta, spacePath, toUrl } from '@interop/was-client/paths'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import {
  clientAnnexDidParts,
  deleteSpaceWithCapability,
  ensureCredentialClientAnnexGeneration,
  ladderVmAgent,
  ladderVmZcapClient,
  mintSpaceRootVerbCapability
} from '../../src/clientAnnex/index.js'
import {
  accountCollectionStores,
  rosterWrapsRecipient,
  rotateRosterToDocumentAndCascade,
  userKeyRosterDescriptorStore,
  userKeyRosterLogSigner
} from '../../src/keys/index.js'
import type { UserKey } from '../../src/keys/index.js'
import { removeRecoveryKey } from '../../src/recovery/index.js'
import { webvhResourceLogController } from '../../src/resourceLog/index.js'
import { ID_COLLECTION } from '../../src/space/index.js'
import { encryptedWalletCollectionIds } from '../../src/space/collections.js'
import { buildRecoveryCodeAccount } from '../../src/testing/index.js'
import type { EstablishedAccount } from '../../src/testing/index.js'
import {
  delegatedWebvhLogStore,
  didKeyZcapClient,
  verifyAccountLog
} from '../../src/webvh/index.js'
import type { WebvhIdStore } from '../../src/webvh/index.js'
import {
  bootServer,
  bridgeLogStore,
  transientVisit
} from './fixtures/credentialAnchoredAccount.js'

/**
 * The transient session's stores on the account's credential, wired as the
 * builder's ladder context wires them: the roster store invoked by the
 * visit's annex VM under the generation delegation and signed by the ladder
 * VM, and the collection descriptor stores over the same invoker and signer.
 *
 * @param options {object}
 * @param options.account {EstablishedAccount}
 * @param options.visit {object}   the transient visit's invoker, capability
 *   and pins
 * @param options.visit.zcapClient {object}
 * @param options.visit.generationDelegation {IZcap}
 * @param options.visit.pinStore {ResourceLogPinStore}
 * @returns {Promise<object>}   `{ rosterStore, collectionStoresFor }`
 */
async function sessionStores({
  account,
  visit
}: {
  account: EstablishedAccount
  visit: Awaited<ReturnType<typeof transientVisit>>
}) {
  const { serverUrl, spaceId, accountDid, ladderSeed } = account
  const signer = userKeyRosterLogSigner({
    keyAgent: await ladderVmAgent({ ladderSeed })
  })
  const rosterStore = userKeyRosterDescriptorStore({
    storageServerUrl: serverUrl,
    zcapClient: visit.zcapClient,
    spaceId,
    resolveController: async () =>
      webvhResourceLogController({
        did: accountDid,
        log: (
          await verifyAccountLog({
            did: accountDid,
            spaceId,
            host: serverUrl,
            pinStore: visit.pinStore
          })
        ).log
      }),
    pinStore: visit.pinStore,
    signer,
    capability: visit.generationDelegation
  })
  const collectionStoresFor = ({
    log
  }: {
    log: Awaited<ReturnType<typeof verifyAccountLog>>['log']
  }) =>
    accountCollectionStores({
      storageServerUrl: serverUrl,
      zcapClient: visit.zcapClient,
      spaceId,
      did: accountDid,
      pinStore: visit.pinStore,
      signer,
      log,
      capability: visit.generationDelegation
    })
  return { rosterStore, collectionStoresFor }
}

describe('the WAS v0.5 ceremony round trip against the reference server', () => {
  let server: Awaited<ReturnType<typeof bootServer>>
  let account: Awaited<ReturnType<typeof buildRecoveryCodeAccount>>
  // The account as the annex mend leaves it: the fresh annex Space id and
  // the bridge and sibling the record was re-sealed with.
  let mended: EstablishedAccount

  beforeAll(async () => {
    server = await bootServer()
  })

  afterAll(async () => {
    await server.close()
  })

  it('serves WAS 0.5 and establishes a credential-anchored account', async () => {
    const { serverUrl } = server
    const service = await new WasClient({
      serverUrl,
      zcapClient: didKeyZcapClient({
        keyAgent: await ladderVmAgent({
          ladderSeed: crypto.getRandomValues(new Uint8Array(32))
        })
      })
    }).service()
    expect(service.description.specs['https://w3id.org/pws']?.[0]).toEqual(
      expect.objectContaining({ version: '0.5' })
    )
    expect(service.version).toBe('0.5')

    account = await buildRecoveryCodeAccount({ serverUrl })
    expect(account.accountDid).toMatch(/^did:webvh:/)
  })

  it('rotates the user key epoch off a revoked recovery code, then no-ops', async () => {
    const { accountDid, ladderSeed } = account
    const visit = await transientVisit({ account })
    const { rosterStore, collectionStoresFor } = await sessionStores({
      account,
      visit
    })
    const before = await rosterStore.read()
    expect(before).not.toBeNull()
    const { client, recoveryKid } = account.recovery
    expect(
      rosterWrapsRecipient({
        descriptor: before!.descriptor,
        recipientId: recoveryKid
      })
    ).toBe(true)

    // The document edit: the code's whole inventory, struck in one entry
    // signed by the acting credential's ladder through the bridge.
    const removed = await removeRecoveryKey({
      idStore: bridgeLogStore({
        account,
        pinStore: visit.pinStore
      }) as WebvhIdStore,
      signer: { kind: 'ladder', ladderSeed },
      recovery: {
        keyAgreementKeyMultibase: client.keyAgreementKeyMultibase,
        updateKeyMultibase: client.updateKeyMultibase
      },
      expectedDid: accountDid
    })

    const cascade = async ({ userKey }: { userKey?: UserKey } = {}) =>
      rotateRosterToDocumentAndCascade({
        rosterStore,
        ...(userKey ? { userKey } : {}),
        did: accountDid,
        doc: removed.doc,
        log: removed.log,
        clientKeyAgreementKey: account.standing.agents
          .keyAgreementKey as IKeyAgreementKey,
        collections: {
          collectionIds: encryptedWalletCollectionIds(),
          storeFor: collectionStoresFor({ log: removed.log })
        }
      })

    const first = await cascade()
    expect(first.rotated).toBe(true)
    expect(first.collections.failed).toEqual([])
    const collectionIds = encryptedWalletCollectionIds()
    expect(Object.keys(first.collections.outcomes).sort()).toEqual(
      [...collectionIds].sort()
    )
    for (const outcome of Object.values(first.collections.outcomes)) {
      expect(outcome).not.toBe('noop')
    }

    const after = await rosterStore.read()
    expect(after!.descriptor.currentEpoch).not.toBe(
      before!.descriptor.currentEpoch
    )
    expect(
      rosterWrapsRecipient({
        descriptor: after!.descriptor,
        recipientId: recoveryKid
      })
    ).toBe(false)
    expect(
      rosterWrapsRecipient({
        descriptor: after!.descriptor,
        recipientId: account.standing.recipientKid
      })
    ).toBe(true)

    // A second run over the same document, holding the key the first run
    // adopted, finds every stage complete. Without a cached key the adopting
    // read reports `rotated: true` on any run.
    const second = await cascade({ userKey: first.userKey })
    expect(second.rotated).toBe(false)
    expect(second.collections.failed).toEqual([])
    expect(Object.keys(second.collections.outcomes).sort()).toEqual(
      [...collectionIds].sort()
    )
    for (const outcome of Object.values(second.collections.outcomes)) {
      expect(outcome).toBe('noop')
    }
    expect(second.rosterDescriptor!.currentEpoch).toBe(
      after!.descriptor.currentEpoch
    )
  })

  it('mends an annex whose Space was deleted through a DELETE-only capability', async () => {
    const { serverUrl, spaceId, accountDid, annexSpaceId, ladderSeed } = account
    const { standing } = account

    // The tear: the ladder VM delegates a DELETE-only child of the annex
    // Space's root to the standing client, which deletes the Space.
    const capability = await mintSpaceRootVerbCapability({
      zcapClient: await ladderVmZcapClient({ accountDid, ladderSeed }),
      storageServerUrl: serverUrl,
      spaceId: annexSpaceId,
      verb: 'DELETE',
      controller: standing.clientDid
    })
    expect(capability.allowedAction).toEqual(['DELETE'])
    expect(capability.invocationTarget).toBe(
      `${serverUrl}/space/${annexSpaceId}/`
    )
    expect(capability.invocationTarget).toBe(
      toUrl({ serverUrl, path: spacePath(annexSpaceId) })
    )
    expect(
      await deleteSpaceWithCapability({
        storageServerUrl: serverUrl,
        zcapClient: standing.agents.zcapClient,
        spaceId: annexSpaceId,
        capability
      })
    ).toEqual({ outcome: 'deleted' })

    server.faults.reset()
    const pinStore = memoryResourceLogPinStore()
    const verified = await verifyAccountLog({
      did: accountDid,
      spaceId,
      host: serverUrl,
      pinStore
    })
    const rebinds: Array<{ delegation: IZcap; delegatedClients: IZcap }> = []
    const outcome = await ensureCredentialClientAnnexGeneration({
      wasServerUrl: serverUrl,
      spaceId,
      account: { did: accountDid, doc: verified.doc, log: verified.log },
      ladderSeed,
      standingClient: {
        did: standing.clientDid,
        zcapClient: standing.agents.zcapClient
      },
      bootstrapWasFor: ({ keyAgent }) =>
        new WasClient({
          serverUrl,
          zcapClient: didKeyZcapClient({ keyAgent })
        }),
      delegation: account.bridge,
      delegatedClients: account.sibling,
      idStoreFor: ({ delegation }) =>
        delegatedWebvhLogStore({
          host: serverUrl,
          spaceId,
          collectionId: ID_COLLECTION.id,
          delegation,
          zcapClient: standing.agents.zcapClient,
          pinStore
        }) as WebvhIdStore,
      onRebindRecord: async ({ delegation, delegatedClients }) => {
        rebinds.push({ delegation, delegatedClients })
      }
    })
    expect(outcome).toMatchObject({
      pointedSpaceMissing: true,
      spaceMinted: true,
      generationMinted: true,
      siblingReminted: true
    })
    const freshSpaceId = clientAnnexDidParts({
      did: outcome.clientAnnexDid
    }).spaceId
    expect(freshSpaceId).not.toBe(annexSpaceId)
    expect(rebinds).toHaveLength(1)

    // The existence probe: two GETs of the gone Space's Metadata object,
    // each a real 404. The standing client invokes the ladder-delegated
    // GET-only child first, then the ladder VM's bare did:key root-invokes.
    const metaPath = spaceMeta(annexSpaceId)
    expect(metaPath).toBe(`/space/${annexSpaceId}/meta`)
    const bareLadderDid = (await ladderVmAgent({ ladderSeed })).id!.split(
      '#'
    )[0]
    expect(
      server.faults.requests.filter(record => record.path === metaPath)
    ).toEqual([
      { method: 'GET', path: metaPath, did: standing.clientDid, status: 404 },
      { method: 'GET', path: metaPath, did: bareLadderDid, status: 404 }
    ])

    mended = {
      ...account,
      annexSpaceId: freshSpaceId,
      bridge: rebinds[0]!.delegation,
      sibling: rebinds[0]!.delegatedClients
    }
    const visit = await transientVisit({ account: mended })
    expect(visit.clientAnnexDid).toBe(outcome.clientAnnexDid)
    expect(await visit.readRoster()).toBe(200)
  })

  it('deletes the account Space through a DELETE-only capability', async () => {
    const { serverUrl, spaceId, accountDid, ladderSeed, standing } = mended
    const ladderClient = await ladderVmZcapClient({ accountDid, ladderSeed })

    // The GET arm names the Space Metadata object and reads it while the
    // Space stands.
    const probe = await mintSpaceRootVerbCapability({
      zcapClient: ladderClient,
      storageServerUrl: serverUrl,
      spaceId,
      verb: 'GET',
      controller: standing.clientDid
    })
    expect(probe.allowedAction).toEqual(['GET'])
    expect(probe.invocationTarget).toBe(`${serverUrl}/space/${spaceId}/meta`)
    const metaResponse = await new WasClient({
      serverUrl,
      zcapClient: standing.agents.zcapClient
    }).request({ path: spaceMeta(spaceId), method: 'GET', capability: probe })
    expect(metaResponse.status).toBe(200)

    const capability = await mintSpaceRootVerbCapability({
      zcapClient: ladderClient,
      storageServerUrl: serverUrl,
      spaceId,
      verb: 'DELETE',
      controller: standing.clientDid
    })
    expect(capability.allowedAction).toEqual(['DELETE'])
    expect(capability.invocationTarget).toBe(`${serverUrl}/space/${spaceId}/`)
    const deleteAccountSpace = async () =>
      deleteSpaceWithCapability({
        storageServerUrl: serverUrl,
        zcapClient: standing.agents.zcapClient,
        spaceId,
        capability
      })
    expect(await deleteAccountSpace()).toEqual({ outcome: 'deleted' })
    expect(await deleteAccountSpace()).toEqual({ outcome: 'not-found' })

    const unauthenticated = await fetch(`${serverUrl}/space/${spaceId}/meta`)
    await unauthenticated.text()
    expect(unauthenticated.status).toBe(404)

    await expect(
      verifyAccountLog({
        did: accountDid,
        spaceId,
        host: serverUrl,
        pinStore: memoryResourceLogPinStore()
      })
    ).rejects.toMatchObject({ name: 'AccountLogMissingError' })
  })
})
