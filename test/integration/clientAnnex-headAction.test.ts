/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The action vocabulary against the real server: a HEAD request is authorized
 * as a `GET`, so the generation delegation, which lists no `HEAD`, admits one,
 * and the client-annex clause refuses a ladder-signed delegation that does
 * list `HEAD`. No unit fake models either rule. The client half is
 * pws-client signing a HEAD request under the `GET` action.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { PwsClient } from '@interop/pws-client'
import { resourceUrl, rootCapabilityId } from '@interop/pws-client/paths'
import type { IZcap } from '@interop/data-integrity-core'

import {
  GENERATION_DELEGATION_ACTIONS,
  ladderVmZcapClient
} from '../../src/clientAnnex/index.js'
import {
  KEY_MAP_COLLECTION,
  USER_KEY_ROSTER_LOG_RESOURCE
} from '../../src/space/index.js'
import {
  bootServer,
  establishAccount,
  refusalStatus,
  transientVisit
} from './fixtures/credentialAnchoredAccount.js'

describe('the action vocabulary against the real server', () => {
  let server: Awaited<ReturnType<typeof bootServer>>

  beforeAll(async () => {
    server = await bootServer()
  })

  afterAll(async () => {
    await server.close()
  })

  it('admits a HEAD under the generation delegation and refuses one that lists HEAD', async () => {
    const account = await establishAccount({
      baseServerUrl: server.baseServerUrl
    })
    const { baseServerUrl, spaceId, accountDid, ladderSeed } = account
    const visit = await transientVisit({ account })
    const pws = new PwsClient({ baseServerUrl, zcapClient: visit.zcapClient })
    const spaceUrl = pws.space(spaceId).url
    const rosterUrl = resourceUrl({
      spaceUrl,
      collectionId: KEY_MAP_COLLECTION.id,
      resourceId: USER_KEY_ROSTER_LOG_RESOURCE
    })
    const probe = async ({
      method,
      capability
    }: {
      method: 'GET' | 'HEAD'
      capability: IZcap
    }): Promise<number> => {
      const response = await pws.request({ url: rosterUrl, method, capability })
      // Drained, so the connection goes idle and the server can close.
      await response.text()
      return response.status
    }

    // The standing delegation lists the four actions and no HEAD, and a HEAD
    // of a capability-gated Resource passes under it.
    expect(visit.generationDelegation.allowedAction).toEqual(
      GENERATION_DELEGATION_ACTIONS
    )
    expect(
      await probe({ method: 'HEAD', capability: visit.generationDelegation })
    ).toBe(200)

    // The same delegation with HEAD listed beside the four: signed by the same
    // ladder VM, for the same generation and target. The clause refuses it
    // with the server's masked 404, for a GET as for a HEAD.
    const ladderClient = await ladderVmZcapClient({ accountDid, ladderSeed })
    const mint = async (allowedActions: string[]): Promise<IZcap> =>
      (await ladderClient.delegate({
        capability: rootCapabilityId(spaceUrl),
        invocationTarget: spaceUrl,
        controller: visit.clientAnnexDid,
        allowedActions,
        expires: new Date(Date.now() + 60 * 60 * 1000)
      })) as IZcap
    // The control: the four actions alone pass, so the refusal below is the
    // listed HEAD and not the delegation being minted outside the document.
    expect(
      await probe({
        method: 'GET',
        capability: await mint([...GENERATION_DELEGATION_ACTIONS])
      })
    ).toBe(200)
    const listingHead = await mint(['HEAD', ...GENERATION_DELEGATION_ACTIONS])
    expect(
      await refusalStatus(probe({ method: 'GET', capability: listingHead }))
    ).toBe(404)
    expect(
      await refusalStatus(probe({ method: 'HEAD', capability: listingHead }))
    ).toBe(404)
  })
})
