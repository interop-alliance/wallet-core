/**
 * Adversarial unit tests for the resource-log verifier
 * (`src/resourceLog/verify.ts`): the WC-1 provenance properties re-proven
 * against the log design. A fabricated log (attacker-signed, tampered state,
 * broken chain, forged SCID) is refused as integrity failure; a served log
 * that verifies but conflicts with the chain-head pin (rollback, fork with
 * evidence retention, SCID/method switch) is refused as continuity failure;
 * the external-authorization rule is checked at the anchored controller
 * version with anchor monotonicity (the revoked-signer-after-seal case);
 * terminal handover entries close the log; and handover links verify from
 * both sides.
 */
import { describe, expect, it } from 'vitest'
import { buildVersionId, deriveHash } from '@interop/did-method-webvh'
import type { ResourceLogEntry } from '@interop/was-client/log'
import {
  buildResourceLogEntry,
  buildResourceLogGenesis,
  isTerminalResourceLogEntry,
  ResourceLogContinuityError,
  ResourceLogIntegrityError,
  verifyResourceLog,
  verifyResourceLogHandover,
  type ResourceLogController
} from '../../src/resourceLog/index.js'
import { makeRosterClient } from './fixtures/rosterClient.js'
import {
  buildTerminalEntry,
  CONTROLLER_DID,
  fakeController
} from './fixtures/resourceLog.js'

const METHOD = 'resource-log:0.1'

/**
 * A two-entry log written by one enrolled client against a single-version
 * controller -- the positive baseline most cases below start from.
 */
async function makeBaselineLog() {
  const alice = await makeRosterClient()
  const controller = fakeController({
    versions: [{ versionId: '1-v1', keys: [alice.signingKeyMultibase] }]
  })
  const genesis = await buildResourceLogGenesis({
    state: { type: 'TestState', value: 1 },
    method: METHOD,
    controller,
    signer: alice.logSigner
  })
  const second = await buildResourceLogEntry({
    head: genesis,
    state: { type: 'TestState', value: 2 },
    controller,
    signer: alice.logSigner
  })
  return { alice, controller, genesis, second, entries: [genesis, second] }
}

describe('verifyResourceLog (positive paths)', () => {
  it('verifies a genesis + append round-trip and resolves head state and pin', async () => {
    const { controller, entries, genesis, second } = await makeBaselineLog()
    const verified = await verifyResourceLog({
      entries,
      controller,
      expectedMethod: METHOD
    })
    expect(verified.method).toBe(METHOD)
    expect(verified.scid).toBe((genesis.parameters as { scid: string }).scid)
    expect(verified.head).toEqual(second)
    expect(verified.state).toEqual({ type: 'TestState', value: 2 })
    expect(verified.pin).toEqual({
      method: METHOD,
      scid: verified.scid,
      head: second.versionId
    })
    expect(verified.terminal).toBeNull()
    expect(verified.previousLog).toBeNull()
  })

  it('accepts a served log that extends the pinned history', async () => {
    const { controller, entries, genesis } = await makeBaselineLog()
    const afterGenesis = await verifyResourceLog({
      entries: [genesis],
      controller,
      expectedMethod: METHOD
    })
    const verified = await verifyResourceLog({
      entries,
      controller,
      expectedMethod: METHOD,
      pin: afterGenesis.pin
    })
    expect(verified.pin.head).toBe(entries[1]!.versionId)
  })

  it('verifies an unversioned-controller log with anchorless proofs', async () => {
    const alice = await makeRosterClient()
    const controller = fakeController({
      versions: [],
      currentKeys: [alice.signingKeyMultibase]
    })
    const genesis = await buildResourceLogGenesis({
      state: { type: 'TestState', value: 1 },
      method: METHOD,
      controller,
      signer: alice.logSigner
    })
    expect(genesis.proof[0]!.verificationMethod).toBe(
      `${CONTROLLER_DID}#${alice.signingKeyMultibase}`
    )
    const verified = await verifyResourceLog({
      entries: [genesis],
      controller,
      expectedMethod: METHOD
    })
    expect(verified.state).toEqual({ type: 'TestState', value: 1 })
  })
})

describe('verifyResourceLog (fabrication refusals)', () => {
  it('refuses an empty log', async () => {
    const { controller } = await makeBaselineLog()
    await expect(
      verifyResourceLog({ entries: [], controller, expectedMethod: METHOD })
    ).rejects.toThrow(ResourceLogIntegrityError)
  })

  it('refuses a log declaring a different format identifier', async () => {
    const { controller, entries } = await makeBaselineLog()
    await expect(
      verifyResourceLog({
        entries,
        controller,
        expectedMethod: 'some-other-log:1.0'
      })
    ).rejects.toThrow(/declares format/)
  })

  it('refuses a genesis whose SCID does not recompute', async () => {
    const { controller, genesis } = await makeBaselineLog()
    const forged = structuredClone(genesis)
    ;(forged.parameters as { scid: string }).scid = 'QmForgedScid'
    await expect(
      verifyResourceLog({
        entries: [forged],
        controller,
        expectedMethod: METHOD
      })
    ).rejects.toThrow(/SCID does not verify/)
  })

  it('refuses a tampered entry state (the proof no longer verifies)', async () => {
    const { controller, entries, genesis } = await makeBaselineLog()
    const tampered = structuredClone(entries)
    // Re-chain the hash over the tampered state so the failure isolates to
    // the proof: the attacker can recompute hashes, never signatures.
    tampered[1]!.state = { type: 'TestState', value: 999 }
    const rehash = await deriveHash({
      versionId: genesis.versionId,
      versionTime: tampered[1]!.versionTime,
      parameters: tampered[1]!.parameters,
      state: tampered[1]!.state
    })
    tampered[1]!.versionId = buildVersionId(2, rehash)
    await expect(
      verifyResourceLog({
        entries: tampered,
        controller,
        expectedMethod: METHOD
      })
    ).rejects.toThrow(/failed proof verification/)
  })

  it('refuses a broken hash chain (a stated head is never accepted)', async () => {
    const { controller, entries } = await makeBaselineLog()
    const tampered = structuredClone(entries)
    tampered[1]!.versionId = '2-QmNotTheRealHash'
    await expect(
      verifyResourceLog({
        entries: tampered,
        controller,
        expectedMethod: METHOD
      })
    ).rejects.toThrow(/hash-chain/)
  })

  it('refuses a spliced entry forged atop a legitimate prefix', async () => {
    // The attacker holds a real key pair, correctly hash-chains its entry onto
    // the served log, and signs it -- but the controller document backs no
    // such key, so the external-authorization rule refuses the whole log.
    const { controller, genesis } = await makeBaselineLog()
    const attacker = await makeRosterClient()
    const attackerView = fakeController({
      versions: [{ versionId: '1-v1', keys: [attacker.signingKeyMultibase] }]
    })
    const spliced = await buildResourceLogEntry({
      head: genesis,
      state: { type: 'TestState', value: 666 },
      controller: attackerView,
      signer: attacker.logSigner
    })
    await expect(
      verifyResourceLog({
        entries: [genesis, spliced],
        controller,
        expectedMethod: METHOD
      })
    ).rejects.toThrow(/does not list under assertionMethod/)
  })

  it('refuses an entry signed under a different controller DID', async () => {
    const { alice, genesis } = await makeBaselineLog()
    const otherController = fakeController({
      did: 'did:webvh:QmOther:example.com:space:xyz:id',
      versions: [{ versionId: '1-v1', keys: [alice.signingKeyMultibase] }]
    })
    await expect(
      verifyResourceLog({
        entries: [genesis],
        controller: otherController,
        expectedMethod: METHOD
      })
    ).rejects.toThrow(/different controller/)
  })

  it('refuses an anchorless proof against a versioned controller', async () => {
    const alice = await makeRosterClient()
    const unversioned = fakeController({
      versions: [],
      currentKeys: [alice.signingKeyMultibase]
    })
    const genesis = await buildResourceLogGenesis({
      state: { type: 'TestState', value: 1 },
      method: METHOD,
      controller: unversioned,
      signer: alice.logSigner
    })
    const versioned = fakeController({
      versions: [{ versionId: '1-v1', keys: [alice.signingKeyMultibase] }]
    })
    await expect(
      verifyResourceLog({
        entries: [genesis],
        controller: versioned,
        expectedMethod: METHOD
      })
    ).rejects.toThrow(/no entry anchor/)
  })

  it('refuses an anchored proof against an unversioned controller', async () => {
    const { alice, genesis } = await makeBaselineLog()
    const unversioned = fakeController({
      versions: [],
      currentKeys: [alice.signingKeyMultibase]
    })
    await expect(
      verifyResourceLog({
        entries: [genesis],
        controller: unversioned,
        expectedMethod: METHOD
      })
    ).rejects.toThrow(/unversioned controller/)
  })

  it('refuses an anchor naming an unknown controller version', async () => {
    const { alice, genesis } = await makeBaselineLog()
    const otherVersions = fakeController({
      versions: [
        { versionId: '1-elsewhere', keys: [alice.signingKeyMultibase] }
      ]
    })
    await expect(
      verifyResourceLog({
        entries: [genesis],
        controller: otherVersions,
        expectedMethod: METHOD
      })
    ).rejects.toThrow(/unknown controller/)
  })

  it('refuses a revoked signer anchoring behind the seal (anchor monotonicity)', async () => {
    // Controller v1 backs alice AND bob; v2 drops bob (the revocation edit).
    // Alice's sealing append anchors at v2; bob then appends anchored at v1,
    // where his key still has membership -- monotonicity is what refuses it.
    const alice = await makeRosterClient()
    const bob = await makeRosterClient()
    const v1Only = fakeController({
      versions: [
        {
          versionId: '1-v1',
          keys: [alice.signingKeyMultibase, bob.signingKeyMultibase]
        }
      ]
    })
    const both = fakeController({
      versions: [
        {
          versionId: '1-v1',
          keys: [alice.signingKeyMultibase, bob.signingKeyMultibase]
        },
        { versionId: '2-v2', keys: [alice.signingKeyMultibase] }
      ]
    })
    const genesis = await buildResourceLogGenesis({
      state: { type: 'TestState', value: 1 },
      method: METHOD,
      controller: v1Only,
      signer: alice.logSigner
    })
    const seal = await buildResourceLogEntry({
      head: genesis,
      state: { type: 'TestState', value: 2 },
      controller: both,
      signer: alice.logSigner
    })
    const behindSeal = await buildResourceLogEntry({
      head: seal,
      state: { type: 'TestState', value: 3 },
      controller: v1Only,
      signer: bob.logSigner
    })
    // The sealed prefix itself verifies...
    await expect(
      verifyResourceLog({
        entries: [genesis, seal],
        controller: both,
        expectedMethod: METHOD
      })
    ).resolves.toBeDefined()
    // ...and bob's v1-anchored continuation is refused.
    await expect(
      verifyResourceLog({
        entries: [genesis, seal, behindSeal],
        controller: both,
        expectedMethod: METHOD
      })
    ).rejects.toThrow(/monotone/)
  })
})

describe('verifyResourceLog (parse-shape refusals)', () => {
  it('refuses an entry with extra or missing members', async () => {
    const { controller, entries } = await makeBaselineLog()
    const extra = structuredClone(entries)
    ;(extra[1] as unknown as Record<string, unknown>).extra = true
    await expect(
      verifyResourceLog({ entries: extra, controller, expectedMethod: METHOD })
    ).rejects.toThrow(/five members/)

    const missing = structuredClone(entries) as unknown as Array<
      Record<string, unknown>
    >
    delete missing[1]!.versionTime
    await expect(
      verifyResourceLog({
        entries: missing as unknown as ResourceLogEntry[],
        controller,
        expectedMethod: METHOD
      })
    ).rejects.toThrow(/five members/)
  })

  it('refuses parameters the profile does not define for the position (fail-closed)', async () => {
    const { controller, entries } = await makeBaselineLog()
    const tampered = structuredClone(entries)
    // The deleted did:webvh key-management parameters in particular.
    tampered[1]!.parameters = { updateKeys: [] } as never
    await expect(
      verifyResourceLog({
        entries: tampered,
        controller,
        expectedMethod: METHOD
      })
    ).rejects.toThrow(/does not define for its position/)
  })

  it('refuses a state without a type schema identifier', async () => {
    const { controller, entries } = await makeBaselineLog()
    const tampered = structuredClone(entries)
    delete (tampered[1]!.state as { type?: string }).type
    await expect(
      verifyResourceLog({
        entries: tampered,
        controller,
        expectedMethod: METHOD
      })
    ).rejects.toThrow(/state.type/)
  })

  it('refuses a state carrying the projection-only history member', async () => {
    const { controller, entries } = await makeBaselineLog()
    const tampered = structuredClone(entries)
    ;(tampered[1]!.state as Record<string, unknown>).history = {
      method: METHOD,
      resource: 'https://example.com/log'
    }
    await expect(
      verifyResourceLog({
        entries: tampered,
        controller,
        expectedMethod: METHOD
      })
    ).rejects.toThrow(/history/)
  })

  it('refuses a malformed versionTime', async () => {
    const { controller, entries } = await makeBaselineLog()
    const tampered = structuredClone(entries)
    tampered[1]!.versionTime = 'not-a-timestamp'
    await expect(
      verifyResourceLog({
        entries: tampered,
        controller,
        expectedMethod: METHOD
      })
    ).rejects.toThrow(/versionTime/)
  })

  it('refuses an entry with no proof array', async () => {
    const { controller, entries } = await makeBaselineLog()
    const tampered = structuredClone(entries)
    tampered[1]!.proof = []
    await expect(
      verifyResourceLog({
        entries: tampered,
        controller,
        expectedMethod: METHOD
      })
    ).rejects.toThrow(/no proof array/)
  })
})

describe('verifyResourceLog (continuity against the chain-head pin)', () => {
  it('refuses a stale-head replay (rollback behind the pin)', async () => {
    const { controller, entries, genesis } = await makeBaselineLog()
    const full = await verifyResourceLog({
      entries,
      controller,
      expectedMethod: METHOD
    })
    await expect(
      verifyResourceLog({
        entries: [genesis],
        controller,
        expectedMethod: METHOD,
        pin: full.pin
      })
    ).rejects.toMatchObject({
      name: 'ResourceLogContinuityError',
      reason: 'rollback'
    })
  })

  it('refuses a fork off the pinned history and retains the served evidence', async () => {
    const { alice, controller, entries, genesis } = await makeBaselineLog()
    const full = await verifyResourceLog({
      entries,
      controller,
      expectedMethod: METHOD
    })
    // The host serves an alternate second entry: internally consistent,
    // legitimately signed, but not the history this client pinned.
    const forkedSecond = await buildResourceLogEntry({
      head: genesis,
      state: { type: 'TestState', value: 42 },
      controller,
      signer: alice.logSigner
    })
    const forked = [genesis, forkedSecond]
    let refusal: unknown
    try {
      await verifyResourceLog({
        entries: forked,
        controller,
        expectedMethod: METHOD,
        pin: full.pin
      })
    } catch (err) {
      refusal = err
    }
    expect(refusal).toBeInstanceOf(ResourceLogContinuityError)
    const continuity = refusal as ResourceLogContinuityError
    expect(continuity.reason).toBe('fork')
    expect(continuity.pinnedHead).toBe(full.pin.head)
    // Both logs are signed: the served entries ride along as transferable
    // evidence of equivocation.
    expect(continuity.servedEntries).toEqual(forked)
  })

  it('refuses an SCID switch under the pinned location', async () => {
    const { alice, controller, entries } = await makeBaselineLog()
    const full = await verifyResourceLog({
      entries,
      controller,
      expectedMethod: METHOD
    })
    const replacement = await buildResourceLogGenesis({
      state: { type: 'TestState', value: 1 },
      method: METHOD,
      controller,
      signer: alice.logSigner,
      versionTime: '2026-01-02T03:04:05Z'
    })
    await expect(
      verifyResourceLog({
        entries: [replacement],
        controller,
        expectedMethod: METHOD,
        pin: full.pin
      })
    ).rejects.toMatchObject({
      name: 'ResourceLogContinuityError',
      reason: 'scid-switch'
    })
  })

  it('refuses a method switch under the pinned location', async () => {
    const { controller, entries } = await makeBaselineLog()
    const full = await verifyResourceLog({
      entries,
      controller,
      expectedMethod: METHOD
    })
    await expect(
      verifyResourceLog({
        entries,
        controller,
        expectedMethod: METHOD,
        pin: { ...full.pin, method: 'some-other-log:1.0' }
      })
    ).rejects.toMatchObject({
      name: 'ResourceLogContinuityError',
      reason: 'method-switch'
    })
  })
})

describe('terminal handover entries', () => {
  it('recognizes and verifies a well-formed terminal entry', async () => {
    const { alice, controller, entries, second } = await makeBaselineLog()
    const terminal = await buildTerminalEntry({
      head: second,
      nextLog: { method: METHOD, scid: 'QmSuccessorScid' },
      controller,
      signer: alice.logSigner
    })
    expect(isTerminalResourceLogEntry(terminal)).toBe(true)
    const verified = await verifyResourceLog({
      entries: [...entries, terminal],
      controller,
      expectedMethod: METHOD
    })
    expect(verified.terminal).toEqual({
      method: METHOD,
      scid: 'QmSuccessorScid'
    })
    // The closed log's state is still the (unchanged) head state.
    expect(verified.state).toEqual(second.state)
  })

  it('refuses a log continuing past a terminal entry', async () => {
    const { alice, controller, entries, second } = await makeBaselineLog()
    const terminal = await buildTerminalEntry({
      head: second,
      nextLog: { method: METHOD, scid: 'QmSuccessorScid' },
      controller,
      signer: alice.logSigner
    })
    const past = await buildResourceLogEntry({
      head: terminal,
      state: { type: 'TestState', value: 3 },
      controller,
      signer: alice.logSigner
    })
    await expect(
      verifyResourceLog({
        entries: [...entries, terminal, past],
        controller,
        expectedMethod: METHOD
      })
    ).rejects.toThrow(/continues past a terminal/)
  })

  it('refuses a terminal entry that changes the resource state', async () => {
    const { alice, controller, entries, second } = await makeBaselineLog()
    // Correctly hash-chained and signed over a differing state, so only the
    // state-equality rule can refuse it.
    const differing = await buildTerminalEntryWithState({
      head: second,
      state: { type: 'TestState', value: 777 },
      nextLog: { method: METHOD, scid: 'QmSuccessorScid' },
      controller,
      signer: alice.logSigner
    })
    await expect(
      verifyResourceLog({
        entries: [...entries, differing],
        controller,
        expectedMethod: METHOD
      })
    ).rejects.toThrow(/changes no resource state/)
  })
})

/**
 * A terminal entry whose state deliberately differs from its predecessor's --
 * hash-chained and signed correctly so the state-equality rule alone refuses
 * it.
 */
async function buildTerminalEntryWithState({
  head,
  state,
  nextLog,
  controller,
  signer
}: {
  head: ResourceLogEntry
  state: ResourceLogEntry['state']
  nextLog: { method: string; scid: string }
  controller: ResourceLogController
  signer: Parameters<typeof buildTerminalEntry>[0]['signer']
}): Promise<ResourceLogEntry> {
  const entry = await buildTerminalEntry({
    head: { ...head, state },
    nextLog,
    controller,
    signer
  })
  return entry
}

describe('verifyResourceLogHandover', () => {
  /**
   * A closed prior log and its verified successor, linked per the profile:
   * the terminal entry names the successor's SCID/method, the successor's
   * genesis carries `previousLog` naming the prior SCID and the terminal
   * entry's immediate predecessor.
   */
  async function makeHandover() {
    const { alice, controller, entries, second, genesis } =
      await makeBaselineLog()
    const successorGenesisOf = async (previousLog: {
      scid: string
      head: string
    }) =>
      buildResourceLogGenesis({
        state: { type: 'TestState', value: 2 },
        method: METHOD,
        controller,
        signer: alice.logSigner,
        previousLog
      })
    const priorScid = (genesis.parameters as { scid: string }).scid
    const successorGenesis = await successorGenesisOf({
      scid: priorScid,
      head: second.versionId
    })
    const successorScid = (successorGenesis.parameters as { scid: string }).scid
    // The prior log closes NAMING the successor, then one more entry lands on
    // the successor -- the terminal chains off `second`, and `previousLog.head`
    // must equal the terminal's immediate predecessor (`second`).
    const terminal = await buildTerminalEntry({
      head: second,
      nextLog: { method: METHOD, scid: successorScid },
      controller,
      signer: alice.logSigner
    })
    const prior = await verifyResourceLog({
      entries: [...entries, terminal],
      controller,
      expectedMethod: METHOD
    })
    const successor = await verifyResourceLog({
      entries: [successorGenesis],
      controller,
      expectedMethod: METHOD
    })
    return { alice, controller, prior, successor, successorGenesisOf }
  }

  it('verifies a well-linked handover', async () => {
    const { prior, successor } = await makeHandover()
    expect(() => verifyResourceLogHandover({ prior, successor })).not.toThrow()
    expect(successor.previousLog).toEqual({
      scid: prior.scid,
      head: prior.entries[prior.entries.length - 2]!.versionId
    })
  })

  it('refuses a handover from a log that is not closed', async () => {
    const { controller, entries } = await makeBaselineLog()
    const open = await verifyResourceLog({
      entries,
      controller,
      expectedMethod: METHOD
    })
    const { successor } = await makeHandover()
    expect(() => verifyResourceLogHandover({ prior: open, successor })).toThrow(
      ResourceLogContinuityError
    )
  })

  it('refuses a successor the terminal entry does not name', async () => {
    const { prior } = await makeHandover()
    const { successor: unrelated } = await makeHandover()
    expect(() =>
      verifyResourceLogHandover({ prior, successor: unrelated })
    ).toThrow(ResourceLogContinuityError)
  })

  it('refuses a successor whose previousLog.head is not the terminal predecessor', async () => {
    const { controller, prior, successorGenesisOf } = await makeHandover()
    const wrongHead = await successorGenesisOf({
      scid: prior.scid,
      head: prior.entries[0]!.versionId
    })
    const successor = await verifyResourceLog({
      entries: [wrongHead],
      controller,
      expectedMethod: METHOD
    })
    expect(() => verifyResourceLogHandover({ prior, successor })).toThrow(
      ResourceLogContinuityError
    )
  })
})
