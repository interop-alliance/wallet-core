/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The integration tier's account builder: a credential-anchored account made
 * by the package's own ceremonies against a real `was-teaching-server` booted
 * in process, with no fake store anywhere.
 *
 * `mintCredential` and `establishAccount` come from the package's shared
 * account builder (`src/testing/`), re-exported here. `establishAccount` runs
 * `establishCredentialAnchoredAccount`, the signup ceremony itself. Its
 * result is a ladder-anchored account log publishing the credential's ladder
 * VM and no enrolled client, an annex generation whose ladder-VM-signed
 * generation delegation is embedded in its document, and the account
 * document's pointer naming that generation. This file keeps what only the
 * integration tier needs: the server boot (the one import of
 * `was-teaching-server/testing`) and the visit and refusal helpers.
 *
 * `transientVisit` is the credential-only visit's own composition: a per-visit
 * key enrolled into the pointed generation through the record's sibling
 * delegation (`enrollTransientClient`), invoking as `<annexDid>#<vm>` under the
 * embedded generation delegation.
 */
import { WasClient } from '@interop/was-client'
import { agentsFromSeed } from '@interop/was-client/identity'
import { resourcePath } from '@interop/was-client/paths'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import { openTempBackend, startTestServer } from 'was-teaching-server/testing'
import type { RequestFaults } from 'was-teaching-server/testing'

import {
  embeddedGenerationDelegation,
  enrollTransientClient
} from '../../../src/clientAnnex/index.js'
import {
  ID_COLLECTION,
  KEY_MAP_COLLECTION,
  USER_KEY_ROSTER_LOG_RESOURCE
} from '../../../src/space/index.js'
import {
  clientSigningKeyMultibase,
  delegatedWebvhLogStore,
  verifyAccountLog,
  webvhZcapClient
} from '../../../src/webvh/index.js'
import type { EstablishedAccount } from '../../../src/testing/index.js'

export { establishAccount, mintCredential } from '../../../src/testing/index.js'
export type { EstablishedAccount } from '../../../src/testing/index.js'

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
 *   generation delegation, the zcap client invoking it as the annex VM, the
 *   visit's pin store, and `readRoster`, which
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
  const zcapClient = webvhZcapClient({ keyAgent, did: enrolled.clientAnnexDid })
  const was = new WasClient({ serverUrl, zcapClient })
  return {
    clientAnnexDid: enrolled.clientAnnexDid,
    generationDelegation,
    zcapClient,
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
