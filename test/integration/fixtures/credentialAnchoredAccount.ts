/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The integration tier's account builder: a credential-anchored account made
 * by the package's own ceremonies against a real `was-teaching-server` booted
 * in process, with no fake store anywhere.
 *
 * `establishAccount` runs `establishCredentialAnchoredAccount`, the signup
 * ceremony itself. Its result is a ladder-anchored account log publishing the
 * credential's ladder VM and no enrolled client, an annex generation whose
 * ladder-VM-signed generation delegation is embedded in its document, and the
 * account document's pointer naming that generation. The unlock record the
 * ceremony binds twice is held in memory: its codec and its storage are the
 * wallet's, and nothing here reads it back beyond the two delegations it
 * carries.
 *
 * `transientVisit` is the credential-only visit's own composition: a per-visit
 * key enrolled into the pointed generation through the record's sibling
 * delegation (`enrollTransientClient`), invoking as `<annexDid>#<vm>` under the
 * embedded generation delegation.
 *
 * The credential is a random unlock seed, so no KDF runs.
 */
import { WasClient } from '@interop/was-client'
import type { IZcap } from '@interop/data-integrity-core'
import { agentsFromSeed } from '@interop/was-client/identity'
import { resourcePath } from '@interop/was-client/paths'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import { openTempBackend, startTestServer } from 'was-teaching-server/testing'
import type { RequestFaults } from 'was-teaching-server/testing'

import {
  clientAnnexDidParts,
  delegatedClientsPointer,
  embeddedGenerationDelegation,
  enrollTransientClient,
  establishCredentialAnchoredAccount,
  ladderVmAgent
} from '../../../src/clientAnnex/index.js'
import { mintSpaceId } from '../../../src/genesis/index.js'
import {
  accountCollectionStores,
  userKeyRosterDescriptorStore,
  userKeyRosterLogSigner
} from '../../../src/keys/index.js'
import { webvhResourceLogController } from '../../../src/resourceLog/index.js'
import {
  ID_COLLECTION,
  KEY_MAP_COLLECTION,
  USER_KEY_ROSTER_LOG_RESOURCE
} from '../../../src/space/index.js'
import {
  generateLadderSeed,
  standingClientFromUnlockSeed
} from '../../../src/unlock/index.js'
import {
  clientSigningKeyMultibase,
  delegatedWebvhLogStore,
  didKeyZcapClient,
  verifyAccountLog,
  wasWebvhIdStore,
  webvhZcapClient
} from '../../../src/webvh/index.js'

/**
 * A server booted in process on an ephemeral port over a fresh temp dir. The
 * `fastify.close()` behind `close` removes the dir. Clients are built only
 * after this resolves, since zcap targets embed the port. `faults` is the
 * server's request fault seam: it records every request, and a test arms it
 * to refuse, drop the response of, or hold a chosen one.
 *
 * @returns {Promise<{ serverUrl: string, faults: RequestFaults, close: () => Promise<void> }>}
 */
export async function bootServer(): Promise<{
  serverUrl: string
  faults: RequestFaults
  close: () => Promise<void>
}> {
  const { fastify, serverUrl, faults } = await startTestServer({
    backend: await openTempBackend({ prefix: 'wallet-core-integration-' })
  })
  return { serverUrl, faults, close: () => fastify.close() }
}

/**
 * A fresh credential and the account Space id it will be carried under: a
 * random ladder seed, and the standing client derived from a random unlock
 * seed.
 *
 * @returns {Promise<object>}   `{ spaceId, ladderSeed, standing }`
 */
export async function mintCredential() {
  return {
    spaceId: mintSpaceId(),
    ladderSeed: generateLadderSeed(),
    standing: await standingClientFromUnlockSeed({
      unlockSeed: crypto.getRandomValues(new Uint8Array(32))
    })
  }
}

/**
 * Establishes a credential-anchored account on the server, through one run of
 * the signup ceremony. Each call is one run with its own in-memory pins, as a
 * fresh tab's would be, so a test re-running a torn establishment passes the
 * same `credential` again.
 *
 * @param options {object}
 * @param options.serverUrl {string}   the booted server's URL
 * @param [options.credential] {object}   from `mintCredential`; a fresh one
 *   when omitted
 * @returns {Promise<object>}   the account's ids, the credential's ladder seed
 *   and standing client, and the bridge and sibling delegations the re-bind
 *   carried
 */
export async function establishAccount({
  serverUrl,
  credential
}: {
  serverUrl: string
  credential?: Awaited<ReturnType<typeof mintCredential>>
}) {
  const { spaceId, ladderSeed, standing } =
    credential ?? (await mintCredential())
  const pinStore = memoryResourceLogPinStore()
  const bootstrapAgent = await ladderVmAgent({ ladderSeed })
  const bootstrapZcap = didKeyZcapClient({ keyAgent: bootstrapAgent })
  const bootstrapWas = new WasClient({ serverUrl, zcapClient: bootstrapZcap })
  const signer = userKeyRosterLogSigner({ keyAgent: bootstrapAgent })

  // The unlock record, held in memory. The re-bind is the last call, and the
  // one carrying the sibling delegation.
  const binds: Array<{ delegation: IZcap; delegatedClients?: IZcap }> = []
  const establishment = await establishCredentialAnchoredAccount({
    wasServerUrl: serverUrl,
    spaceId,
    ladderSeed,
    standing: {
      clientDid: standing.clientDid,
      keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase,
      recipientKid: standing.recipientKid,
      keyAgreementKey: standing.agents.keyAgreementKey
    },
    // A random seed is a high-entropy credential.
    lowEntropy: false,
    bindRecord: async ({ delegation, delegatedClients }) => {
      binds.push({
        delegation,
        ...(delegatedClients ? { delegatedClients } : {})
      })
      return {
        createdAt: new Date(Date.now() + binds.length).toISOString(),
        unlockSpaceId: 'unlock-space-held-in-memory'
      }
    },
    rosterStoreFor: ({ did, log }) =>
      userKeyRosterDescriptorStore({
        storageServerUrl: serverUrl,
        zcapClient: bootstrapZcap,
        spaceId,
        resolveController: async () => webvhResourceLogController({ did, log }),
        pinStore,
        signer
      }),
    collectionStoreFor: ({ did, log }) =>
      accountCollectionStores({
        storageServerUrl: serverUrl,
        zcapClient: bootstrapZcap,
        spaceId,
        did,
        pinStore,
        signer,
        log
      }),
    bootstrapWasFor: () => bootstrapWas,
    idStore: wasWebvhIdStore({ was: bootstrapWas, spaceId, pinStore })
  })

  const record = binds.at(-1)
  if (!record?.delegatedClients) {
    throw new Error('fixture: the re-bind carried no sibling delegation')
  }
  const pointed = delegatedClientsPointer({ doc: establishment.accountLog.doc })
  if (pointed === undefined) {
    throw new Error('fixture: the establishment left no pointer')
  }
  return {
    serverUrl,
    spaceId,
    accountDid: establishment.did,
    annexSpaceId: clientAnnexDidParts({ did: pointed }).spaceId,
    ladderSeed,
    standing,
    bridge: record.delegation,
    sibling: record.delegatedClients
  }
}

export type EstablishedAccount = Awaited<ReturnType<typeof establishAccount>>

/**
 * The account log's store over the record's bridge delegation (PUT on
 * `did.jsonl`), invoked by the standing client: the authority a
 * credential-only visit writes account entries through.
 *
 * @param options {object}
 * @param options.account {EstablishedAccount}
 * @param options.pinStore {ResourceLogPinStore}   the visit's chain-head pins
 * @returns {DelegatedWebvhLogStore}
 */
export function bridgeLogStore({
  account,
  pinStore
}: {
  account: EstablishedAccount
  pinStore: ResourceLogPinStore
}) {
  return delegatedWebvhLogStore({
    host: account.serverUrl,
    spaceId: account.spaceId,
    collectionId: ID_COLLECTION.id,
    delegation: account.bridge,
    zcapClient: account.standing.agents.zcapClient,
    pinStore
  })
}

/**
 * One credential-only visit: a fresh per-visit key enrolled into whichever
 * generation the account document points at now, and a reader that invokes
 * the generation delegation embedded in that generation's document.
 *
 * @param options {object}
 * @param options.account {EstablishedAccount}
 * @returns {Promise<object>}   the generation the visit enrolled into, its
 *   generation delegation, the visit's pin store, and `readRoster`, which
 *   GETs the user key roster log (`key-map/user-key.jsonl`, a
 *   capability-gated Resource) as the annex VM under that delegation and
 *   resolves to the response status
 */
export async function transientVisit({
  account
}: {
  account: EstablishedAccount
}) {
  const { serverUrl, spaceId, accountDid, annexSpaceId, ladderSeed } = account
  const pinStore = memoryResourceLogPinStore()
  const { keyAgent } = await agentsFromSeed({
    seed: crypto.getRandomValues(new Uint8Array(32))
  })
  const enrolled = await enrollTransientClient({
    readAccountDocument: async () =>
      (
        await verifyAccountLog({
          did: accountDid,
          spaceId,
          host: serverUrl,
          pinStore
        })
      ).doc,
    storeForGenerationId: generationId =>
      delegatedWebvhLogStore({
        host: serverUrl,
        spaceId: annexSpaceId,
        collectionId: generationId,
        delegation: account.sibling,
        zcapClient: account.standing.agents.zcapClient,
        pinStore
      }),
    ladderSeed,
    transientKeyMultibase: clientSigningKeyMultibase({ keyAgent })
  })
  const generationDelegation = embeddedGenerationDelegation({
    doc: enrolled.doc
  })
  if (generationDelegation === undefined) {
    throw new Error('fixture: the generation carries no delegation')
  }
  const was = new WasClient({
    serverUrl,
    zcapClient: webvhZcapClient({ keyAgent, did: enrolled.clientAnnexDid })
  })
  return {
    clientAnnexDid: enrolled.clientAnnexDid,
    generationDelegation,
    pinStore,
    readRoster: async () => {
      const response = await was.request({
        path: resourcePath(
          spaceId,
          KEY_MAP_COLLECTION.id,
          USER_KEY_ROSTER_LOG_RESOURCE
        ),
        method: 'GET',
        capability: generationDelegation
      })
      // Drained, so the connection goes idle and the server can close.
      await response.text()
      return response.status
    }
  }
}

/**
 * The HTTP status a raw signed request failed with, from the thrown error's
 * own `status`, or `undefined` when the request resolved or failed below
 * HTTP.
 *
 * @param request {Promise<unknown>}
 * @returns {Promise<number | undefined>}
 */
export async function refusalStatus(
  request: Promise<unknown>
): Promise<number | undefined> {
  try {
    await request
  } catch (err) {
    const status = (err as { status?: unknown })?.status
    return typeof status === 'number' ? status : undefined
  }
  return undefined
}
