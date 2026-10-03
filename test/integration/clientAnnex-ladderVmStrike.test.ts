/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The current-key-set rule applied to a delegation link, against the real
 * server: a generation delegation signed by a ladder VM verifies while that
 * VM stands in the account document, and stops verifying once the strike
 * entry takes it out. No unit fake models this. A fake keeps the delegation
 * alive after its signer leaves the document, which is how a repair that
 * strikes the VM behind the visit's own delegation passes a unit suite.
 *
 * The account comes from the signup ceremony, the visit from the transient
 * enrollment, and the strike from `strikeLadderVmWebvh` through the record's
 * bridge delegation: the same writes a wallet makes.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import {
  installLadderVmWebvh,
  strikeLadderVmWebvh
} from '../../src/clientAnnex/index.js'
import {
  ladderVmKeyMultibase,
  ladderVmKeyMultibases,
  verifyAccountLog
} from '../../src/webvh/index.js'
import {
  bootServer,
  bridgeLogStore,
  establishAccount,
  refusalStatus,
  transientVisit
} from './fixtures/credentialAnchoredAccount.js'

describe('a ladder-VM-signed generation delegation against the real server', () => {
  let server: Awaited<ReturnType<typeof bootServer>>

  beforeAll(async () => {
    server = await bootServer()
  })

  afterAll(async () => {
    await server.close()
  })

  it('stops verifying once the ladder VM leaves the account document', async () => {
    const account = await establishAccount({ serverUrl: server.serverUrl })
    const ladderVm = await ladderVmKeyMultibase({
      ladderSeed: account.ladderSeed
    })
    const visit = await transientVisit({ account })

    // The delegation in hand is the ladder VM's own signature.
    expect(visit.generationDelegation).toMatchObject({
      proof: { verificationMethod: `${account.accountDid}#${ladderVm}` }
    })

    // While the VM stands, the visit reads a capability-gated Resource.
    expect(await visit.readRoster()).toBe(200)

    // The strike entry, signed by the ladder's current rung and published
    // through the bridge.
    const struck = await strikeLadderVmWebvh({
      store: bridgeLogStore({ account, pinStore: visit.pinStore }),
      ladderSeed: account.ladderSeed,
      expectedDid: account.accountDid
    })
    expect(struck.struck).toBe(true)
    const served = await verifyAccountLog({
      did: account.accountDid,
      spaceId: account.spaceId,
      host: account.serverUrl
    })
    expect(ladderVmKeyMultibases({ doc: served.doc })).not.toContain(ladderVm)

    // The same invocation, under the same unexpired delegation, now refuses.
    // The server masks an unauthorized invocation as a 404, and the roster
    // Resource read a moment ago is still there.
    expect(await refusalStatus(visit.readRoster())).toBe(404)

    // The record's bridge is a ladder-VM-signed delegation too, so the same
    // rule refuses the write that would put the VM back through it.
    expect(
      await refusalStatus(
        installLadderVmWebvh({
          store: bridgeLogStore({ account, pinStore: visit.pinStore }),
          ladderSeed: account.ladderSeed,
          expectedDid: account.accountDid
        })
      )
    ).toBe(404)
  })
})
