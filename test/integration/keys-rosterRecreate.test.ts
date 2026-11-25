/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A delete and re-create of the user key roster log, against the real server.
 * The party is a transient visit: a per-visit key invoking under the
 * generation delegation, holding a credential's ladder VM key. It deletes
 * `key-map/user-key.jsonl` and creates a new log there whose first entry the
 * ladder VM signs, carrying a user key of its own choosing.
 *
 * This suite pins what happens today (the known gap WC-322). The server
 * admits both requests. A reader holding the old log's chain-head pin refuses
 * the new one. A reader with no pin accepts it and takes the substituted user
 * key, since nothing in the account document names the roster log. No unit
 * fake models the server half.
 *
 * The second case separates the two parties. One credential's holder replaces
 * the log, and a visit on the account's other credential takes the
 * substituted key.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { PwsClient } from '@interop/pws-client'
import { initRecipients } from '@interop/pws-client/edv/core'
import { collectionUrl, resourceUrl } from '@interop/pws-client/paths'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'

import { ladderVmAgent } from '../../src/clientAnnex/index.js'
import {
  ensureUserKeyRoster,
  mintUserKey,
  readUserKeyRoster,
  userKeyRosterDescriptorStore,
  userKeyRosterLogSigner
} from '../../src/keys/index.js'
import {
  KEY_MAP_COLLECTION,
  PRIVATE_CREDENTIALS_COLLECTION,
  USER_KEY_ROSTER_LOG_RESOURCE,
  plaintextCollection
} from '../../src/space/index.js'
import { buildSecondCredentialAccount } from '../../src/testing/index.js'
import { accountControllerResolver } from '../../src/webvh/index.js'
import {
  bootServer,
  establishAccount,
  refusalStatus,
  transientVisit
} from './fixtures/credentialAnchoredAccount.js'
import type { EstablishedAccount } from './fixtures/credentialAnchoredAccount.js'

/**
 * One credential's transient visit and its reach onto the roster log. Every
 * store invokes as the visit's annex VM under the generation delegation and
 * signs as the credential's ladder VM. Only the chain-head pins differ
 * between two stores of one party.
 *
 * @param options {object}
 * @param options.account {EstablishedAccount}   the account as this
 *   credential holds it
 * @returns {Promise<object>}   `{ rosterStore, readRoster, deleteRoster }`
 */
async function rosterParty({ account }: { account: EstablishedAccount }) {
  const { baseServerUrl, spaceId, accountDid, ladderSeed, standing } = account
  const visit = await transientVisit({ account })
  const signer = userKeyRosterLogSigner({
    keyAgent: await ladderVmAgent({ ladderSeed })
  })
  const rosterStore = (pinStore: ResourceLogPinStore) =>
    userKeyRosterDescriptorStore({
      baseServerUrl,
      zcapClient: visit.zcapClient,
      spaceId,
      resolveController: accountControllerResolver({
        did: accountDid,
        pinStore
      }),
      pinStore,
      signer,
      capability: visit.generationDelegation
    })
  const pws = new PwsClient({ baseServerUrl, zcapClient: visit.zcapClient })
  return {
    rosterStore,
    readRoster: (pinStore: ResourceLogPinStore) =>
      readUserKeyRoster({
        store: rosterStore(pinStore),
        clientKeyAgreementKey: standing.agents.keyAgreementKey
      }),
    deleteRoster: async (): Promise<number> => {
      const response = await pws.request({
        url: resourceUrl({
          spaceUrl: pws.space(spaceId).url,
          collectionId: KEY_MAP_COLLECTION.id,
          resourceId: USER_KEY_ROSTER_LOG_RESOURCE
        }),
        method: 'DELETE',
        capability: visit.generationDelegation
      })
      // Drained, so the connection goes idle and the server can close.
      await response.text()
      return response.status
    }
  }
}

describe('a delete and re-create of the user key roster log', () => {
  let server: Awaited<ReturnType<typeof bootServer>>

  beforeAll(async () => {
    server = await bootServer()
  })

  afterAll(async () => {
    await server.close()
  })

  it('is admitted under the generation delegation and accepted by a reader with no pin', async () => {
    const account = await establishAccount({
      baseServerUrl: server.baseServerUrl
    })
    const party = await rosterParty({ account })

    // A reader that met the account's own roster and pinned its log.
    const pinnedReader = memoryResourceLogPinStore()
    const original = await party.readRoster(pinnedReader)
    expect(original).not.toBeNull()

    // The delete, as the annex VM under the generation delegation.
    expect(await party.deleteRoster()).toBe(204)

    // The re-create: the package's own guarded create over a store with no
    // pin, so it builds a new first entry, ladder-VM-signed, wrapping a user
    // key the account never held.
    const substitute = await mintUserKey()
    await ensureUserKeyRoster({
      store: party.rosterStore(memoryResourceLogPinStore()),
      userKey: substitute,
      clientKeyAgreementKey: account.standing.agents.keyAgreementKey
    })
    expect(substitute.id).not.toBe(original!.userKey.id)

    // A reader with no pin takes the substituted key with no refusal.
    const fresh = await party.readRoster(memoryResourceLogPinStore())
    expect(fresh?.userKey.id).toBe(substitute.id)

    // The reader that pinned the original log refuses the replacement.
    await expect(party.readRoster(pinnedReader)).rejects.toMatchObject({
      name: 'ResourceLogContinuityError'
    })
  })

  it("hands one credential's substituted key to a visit on the other credential", async () => {
    const account = await buildSecondCredentialAccount({
      baseServerUrl: server.baseServerUrl
    })
    const owner = await rosterParty({ account })
    // The second credential's holder, on a visit of its own: its ladder VM
    // signs, and its per-visit key rides the same generation delegation.
    const other = await rosterParty({
      account: { ...account, ...account.second }
    })

    // Both credentials read the account's roster to the same user key. The
    // owner's reader pins the log.
    const ownerPinned = memoryResourceLogPinStore()
    const original = await owner.readRoster(ownerPinned)
    const seenByOther = await other.readRoster(memoryResourceLogPinStore())
    expect(seenByOther?.userKey.id).toBe(original?.userKey.id)

    // What the second credential needs of the owner is public: the served
    // roster names the owner's recipient kid, whose fragment is its
    // key-agreement key.
    const ownerKid = account.standing.recipientKid
    expect(JSON.stringify(seenByOther!.descriptor)).toContain(ownerKid)
    expect(
      ownerKid.endsWith(`#${account.standing.keyAgreementKeyMultibase}`)
    ).toBe(true)

    // The second credential deletes the log and creates a new one, its first
    // entry signed by its own ladder VM and wrapped to both credentials.
    expect(await other.deleteRoster()).toBe(204)
    const substitute = await mintUserKey()
    await initRecipients({
      store: other.rosterStore(memoryResourceLogPinStore()),
      recipients: [
        {
          id: ownerKid,
          publicKeyMultibase: ownerKid.slice(ownerKid.indexOf('#') + 1)
        },
        {
          id: account.second.standing.recipientKid,
          publicKeyMultibase: account.second.standing.keyAgreementKeyMultibase
        }
      ],
      epoch: { epochId: substitute.id, secret: substitute.secret }
    })
    expect(substitute.id).not.toBe(original!.userKey.id)

    // A later visit on the owner's credential, with no pin, unwraps the
    // substituted key under its own key-agreement key.
    const laterVisit = await rosterParty({ account })
    const adopted = await laterVisit.readRoster(memoryResourceLogPinStore())
    expect(adopted?.userKey.id).toBe(substitute.id)

    // The owner's reader that pinned the original log refuses.
    await expect(owner.readRoster(ownerPinned)).rejects.toMatchObject({
      name: 'ResourceLogContinuityError'
    })
  })

  it("cannot do the same to a collection's governing history log", async () => {
    const account = await establishAccount({
      baseServerUrl: server.baseServerUrl
    })
    const { baseServerUrl, spaceId } = account
    const visit = await transientVisit({ account })
    const pws = new PwsClient({ baseServerUrl, zcapClient: visit.zcapClient })
    const collectionId = PRIVATE_CREDENTIALS_COLLECTION
    const collection = plaintextCollection({
      pws,
      spaceId,
      collectionId,
      capability: visit.generationDelegation
    })
    const send = async (url: string): Promise<number> => {
      const response = await pws.request({
        url,
        method: 'DELETE',
        capability: visit.generationDelegation
      })
      // Drained, so the connection goes idle and the server can close.
      await response.text()
      return response.status
    }
    const statusOf = async (url: string): Promise<number | undefined> => {
      try {
        return await send(url)
      } catch (err) {
        return refusalStatus(Promise.reject(err))
      }
    }

    // The log the establishment's epoch install created.
    const stored = await collection.getHistoryLog()
    expect(stored?.etag).toBeDefined()

    // The log sub-resource serves no DELETE, and Delete Collection is the
    // controller's alone, so the generation delegation reaches neither.
    expect(await statusOf(collection.historyLogUrl)).toBe(405)
    // The server masks the refused invocation as a 404.
    expect(
      await statusOf(
        collectionUrl({ spaceUrl: pws.space(spaceId).url, collectionId })
      )
    ).toBe(404)

    // A write that replaces the stored first entry is refused with a 412,
    // under the stored validator and as a guarded create alike. The server
    // admits a body only when the stored log is a prefix of it.
    const [firstLine] = stored!.body.split('\n')
    const replaced =
      JSON.stringify({
        ...(JSON.parse(firstLine!) as object),
        versionTime: new Date(0).toISOString()
      }) + '\n'
    expect(
      await refusalStatus(
        collection.putHistoryLog(replaced, { ifMatch: stored!.etag })
      )
    ).toBe(412)
    expect(
      await refusalStatus(
        collection.putHistoryLog(replaced, { ifNoneMatch: true })
      )
    ).toBe(412)

    // The log stands as it was.
    expect((await collection.getHistoryLog())?.body).toBe(stored!.body)
  })
})
