/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The server's pointer-equality clause, against the real server: a
 * ladder-signed generation delegation verifies only while the account
 * document's delegated-clients pointer names its generation. Once the pointer
 * moves to a fresh generation, the old one's delegation refuses, even though
 * its signer, the ladder VM, still stands. No unit fake simulates the clause.
 *
 * The pointer moves the way a credential-only visit moves it: a fresh
 * generation minted through the record's sibling delegation, its delegation
 * ladder-signed, and the pointer entry moved as the ladder through the
 * bridge (`mintPointedClientAnnexGeneration` over `movePointerAsLadder`).
 * Nothing revokes the old delegation, so the clause alone decides.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import { WasClient } from '@interop/was-client'

import {
  delegatedClientsPointer,
  ladderSignedGenerationDelegationMinter,
  mintPointedClientAnnexGeneration,
  movePointerAsLadder
} from '../../src/clientAnnex/index.js'
import {
  ladderVmKeyMultibase,
  ladderVmKeyMultibases,
  type WebvhIdStore
} from '../../src/webvh/index.js'
import {
  bootServer,
  bridgeLogStore,
  establishAccount,
  refusalStatus,
  transientVisit
} from './fixtures/credentialAnchoredAccount.js'

describe('the pointer-equality clause against the real server', () => {
  let server: Awaited<ReturnType<typeof bootServer>>

  beforeAll(async () => {
    server = await bootServer()
  })

  afterAll(async () => {
    await server.close()
  })

  it("stops verifying a generation's delegation once the pointer moves off it", async () => {
    const account = await establishAccount({ serverUrl: server.serverUrl })
    const { serverUrl, spaceId, accountDid, annexSpaceId, ladderSeed } = account
    const visit = await transientVisit({ account })
    expect(await visit.readRoster()).toBe(200)

    // A fresh generation, then the pointer entry naming it.
    const pinStore = memoryResourceLogPinStore()
    const moved = await mintPointedClientAnnexGeneration({
      was: new WasClient({
        serverUrl,
        zcapClient: account.standing.agents.zcapClient
      }),
      wasServerUrl: serverUrl,
      spaceId: annexSpaceId,
      controller: accountDid,
      ladderSeed,
      capability: account.sibling,
      pinStore,
      mintGenerationDelegation: ladderSignedGenerationDelegationMinter({
        accountDid,
        ladderSeed,
        wasServerUrl: serverUrl,
        spaceId
      }),
      point: clientAnnexDid =>
        movePointerAsLadder({
          // The bridge serves the log read and the `did.jsonl` PUT, all a
          // log-only pointer entry uses. The parameter is typed wider.
          idStore: bridgeLogStore({ account, pinStore }) as WebvhIdStore,
          ladderSeed,
          clientAnnexDid,
          accountDid
        })
    })
    expect(moved.clientAnnexDid).not.toBe(visit.clientAnnexDid)
    const { doc } = moved.pointed
    expect(delegatedClientsPointer({ doc })).toBe(moved.clientAnnexDid)
    // The old delegation's signer still stands: only the pointer moved.
    expect(ladderVmKeyMultibases({ doc })).toContain(
      await ladderVmKeyMultibase({ ladderSeed })
    )

    // The earlier visit's invocation, under its unexpired delegation, now
    // refuses with the server's masked 404.
    expect(await refusalStatus(visit.readRoster())).toBe(404)

    // A visit enrolled into the generation the pointer names now reads the
    // same Resource, so the refusal is the clause and not a missing target.
    const next = await transientVisit({ account })
    expect(next.clientAnnexDid).toBe(moved.clientAnnexDid)
    expect(await next.readRoster()).toBe(200)
  })
})
