/**
 * Tests for the seedless ladder-rung attribution
 * (`src/resourceLog/ladderRungs.ts`): which update keys the account log names
 * as rungs of which standing ladder, which is the conjunct the ceremony-tail
 * license's third shape rests on. The walk is narrow on purpose, so the cases
 * below are as much about what it refuses to attribute -- an enrolled client's
 * update key above all -- as about what it names. The climb cases cover the
 * shape a self-enrollment leaves behind, where the ladder's next rung is
 * revealed entries later than the entry that introduced its VM.
 */
import { describe, expect, it } from 'vitest'
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import type { DIDLog } from '@interop/did-method-webvh'
import { attributeLadderRungsPerVersion } from '../../src/resourceLog/index.js'

const DID = 'did:webvh:QmScid:example.com:space:abc:id'
const CLIENT_SIGNING = 'z6MkClientSigning'
const CLIENT_UPDATE = 'z6MkClientUpdateKey'
const LADDER = 'z6MkLadderVm'
const OTHER_LADDER = 'z6MkOtherLadderVm'
const RUNG_ZERO = 'z6MkRungZero'
const CLIENT_STAGED_HASH = 'uClientStagedHash'
const RUNG_ONE = 'z6MkRungOne'
const RUNG_TWO = 'z6MkRungTwo'
const CLIENT_TWO_SIGNING = 'z6MkClientTwoSigning'
const CLIENT_TWO_UPDATE = 'z6MkClientTwoUpdateKey'
const CLIENT_TWO_STAGED_HASH = 'uClientTwoStagedHash'
const FRESH_LADDER = 'z6MkFreshLadderVm'
const FRESH_RUNG_ZERO = 'z6MkFreshRungZero'
const REPLACEMENT_KEY = 'z6MkReplacementCodeKey'
const REPLACEMENT_LADDER = 'z6MkReplacementLadderVm'
const OTHER_RUNG_ZERO = 'z6MkOtherRungZero'

/**
 * One log entry, in the shape the walk reads: the standing parameters, the
 * document's relations, and the update keys that signed it.
 *
 * @param options {object}
 * @param options.versionId {string}
 * @param options.updateKeys {string[]}
 * @param options.nextKeyHashes {string[]}
 * @param options.signers {string[]}
 * @param [options.ladderVms] {string[]}   the ladder VM key multibases
 * @param [options.clients] {string[]}   enrolled clients' signing multibases
 * @returns {object}
 */
function entry({
  versionId,
  updateKeys,
  nextKeyHashes,
  signers,
  ladderVms = [],
  clients = []
}: {
  versionId: string
  updateKeys: string[]
  nextKeyHashes: string[]
  signers: string[]
  ladderVms?: string[]
  clients?: string[]
}) {
  const methodIds = [...clients, ...ladderVms].map(key => `${DID}#${key}`)
  return {
    versionId,
    parameters: { updateKeys, nextKeyHashes },
    state: {
      id: DID,
      verificationMethod: [...clients, ...ladderVms].map(key => ({
        id: `${DID}#${key}`,
        controller: DID,
        publicKeyMultibase: key
      })),
      assertionMethod: methodIds,
      capabilityInvocation: clients.map(key => `${DID}#${key}`),
      capabilityDelegation: methodIds
    },
    proof: signers.map(key => ({
      verificationMethod: `did:key:${key}#${key}`
    }))
  }
}

/**
 * The rung sets the walk names at the last version of a log.
 *
 * @param log {DIDLog}
 * @returns {Promise<Record<string, string[]>>}
 */
async function rungsAtHead(log: DIDLog): Promise<Record<string, string[]>> {
  const snapshots = await attributeLadderRungsPerVersion(log)
  const head = snapshots[snapshots.length - 1] ?? new Map()
  return Object.fromEntries(
    [...head].map(([ladderKey, rungs]) => [ladderKey, [...rungs].sort()])
  )
}

describe('attributeLadderRungsPerVersion', () => {
  it('names rung 0 at a ladder-anchored genesis that reveals it', async () => {
    const log = [
      entry({
        versionId: '1-v1',
        updateKeys: [RUNG_ZERO],
        nextKeyHashes: [await deriveNextKeyHash(RUNG_ZERO)],
        signers: [RUNG_ZERO],
        ladderVms: [LADDER]
      })
    ] as unknown as DIDLog
    expect(await rungsAtHead(log)).toEqual({ [LADDER]: [RUNG_ZERO] })
  })

  it('names rung 0 of a bind that only commits it, once the log reveals it', async () => {
    const rungHash = await deriveNextKeyHash(RUNG_ZERO)
    const clientHash = await deriveNextKeyHash(CLIENT_STAGED_HASH)
    const genesis = entry({
      versionId: '1-v1',
      updateKeys: [CLIENT_UPDATE],
      nextKeyHashes: [clientHash],
      signers: [CLIENT_UPDATE],
      clients: [CLIENT_SIGNING]
    })
    // The bind an enrolled client signs: the ladder VM arrives with its rung
    // committed rather than revealed.
    const bind = entry({
      versionId: '2-v2',
      updateKeys: [CLIENT_UPDATE],
      nextKeyHashes: [clientHash, rungHash],
      signers: [CLIENT_UPDATE],
      ladderVms: [LADDER],
      clients: [CLIENT_SIGNING]
    })
    const beforeReveal = await attributeLadderRungsPerVersion([
      genesis,
      bind
    ] as unknown as DIDLog)
    expect(beforeReveal[1]?.get(LADDER)).toBeUndefined()

    // The credential's first ladder-signed ceremony reveals the rung.
    const reveal = entry({
      versionId: '3-v3',
      updateKeys: [CLIENT_UPDATE, RUNG_ZERO],
      nextKeyHashes: [clientHash, rungHash],
      signers: [RUNG_ZERO],
      ladderVms: [LADDER],
      clients: [CLIENT_SIGNING]
    })
    expect(
      await rungsAtHead([genesis, bind, reveal] as unknown as DIDLog)
    ).toEqual({ [LADDER]: [RUNG_ZERO] })
  })

  it('never names an enrolled client update key as a rung', async () => {
    const rungHash = await deriveNextKeyHash(RUNG_ZERO)
    const clientHash = await deriveNextKeyHash(CLIENT_UPDATE)
    const genesis = entry({
      versionId: '1-v1',
      updateKeys: [RUNG_ZERO],
      nextKeyHashes: [rungHash],
      signers: [RUNG_ZERO],
      ladderVms: [LADDER]
    })
    // A ladder-signed enrollment approval: the commit entry stages the new
    // client's hashes, the add entry publishes the client and its update key.
    const commit = entry({
      versionId: '2-v2',
      updateKeys: [RUNG_ZERO],
      nextKeyHashes: [rungHash, clientHash, CLIENT_STAGED_HASH],
      signers: [RUNG_ZERO],
      ladderVms: [LADDER]
    })
    const add = entry({
      versionId: '3-v3',
      updateKeys: [RUNG_ZERO, CLIENT_UPDATE],
      nextKeyHashes: [rungHash, clientHash, CLIENT_STAGED_HASH],
      signers: [RUNG_ZERO],
      ladderVms: [LADDER],
      clients: [CLIENT_SIGNING]
    })
    expect(
      await rungsAtHead([genesis, commit, add] as unknown as DIDLog)
    ).toEqual({ [LADDER]: [RUNG_ZERO] })
  })

  it('climbs to rung 1 after a self-enrollment spends rung 0', async () => {
    const rungZeroHash = await deriveNextKeyHash(RUNG_ZERO)
    const rungOneHash = await deriveNextKeyHash(RUNG_ONE)
    const clientHash = await deriveNextKeyHash(CLIENT_UPDATE)
    // The ladder-anchored genesis: rung 0 revealed, rung 1 committed last.
    const genesis = entry({
      versionId: '1-v1',
      updateKeys: [RUNG_ZERO],
      nextKeyHashes: [rungZeroHash, rungOneHash],
      signers: [RUNG_ZERO],
      ladderVms: [LADDER]
    })
    // The self-enrollment: a reveal-and-commit entry reusing rung 0 (it
    // authorizes no key of its own), then the add entry that publishes the
    // client and retires rung 0.
    const reveal = entry({
      versionId: '2-v2',
      updateKeys: [RUNG_ZERO],
      nextKeyHashes: [
        rungZeroHash,
        rungOneHash,
        clientHash,
        CLIENT_STAGED_HASH
      ],
      signers: [RUNG_ZERO],
      ladderVms: [LADDER]
    })
    const add = entry({
      versionId: '3-v3',
      updateKeys: [CLIENT_UPDATE],
      nextKeyHashes: [rungOneHash, clientHash, CLIENT_STAGED_HASH],
      signers: [CLIENT_UPDATE],
      ladderVms: [LADDER],
      clients: [CLIENT_SIGNING]
    })
    // The credential's next ladder-signed ceremony reveals rung 1.
    const climb = entry({
      versionId: '4-v4',
      updateKeys: [CLIENT_UPDATE, RUNG_ONE],
      nextKeyHashes: [
        rungOneHash,
        clientHash,
        CLIENT_STAGED_HASH,
        await deriveNextKeyHash(RUNG_TWO)
      ],
      signers: [RUNG_ONE],
      ladderVms: [LADDER],
      clients: [CLIENT_SIGNING]
    })

    const snapshots = await attributeLadderRungsPerVersion([
      genesis,
      reveal,
      add,
      climb
    ] as unknown as DIDLog)
    // The add entry retires rung 0 and reveals no rung of its own, so the
    // ladder holds nothing the version authorizes.
    expect(snapshots[2]?.get(LADDER)).toBeUndefined()
    expect(
      await rungsAtHead([genesis, reveal, add, climb] as unknown as DIDLog)
    ).toEqual({ [LADDER]: [RUNG_ONE] })
  })

  it('climbs again after a second self-enrollment, and never names a client key', async () => {
    const rungZeroHash = await deriveNextKeyHash(RUNG_ZERO)
    const rungOneHash = await deriveNextKeyHash(RUNG_ONE)
    const rungTwoHash = await deriveNextKeyHash(RUNG_TWO)
    const clientHash = await deriveNextKeyHash(CLIENT_UPDATE)
    const clientTwoHash = await deriveNextKeyHash(CLIENT_TWO_UPDATE)
    const log = [
      entry({
        versionId: '1-v1',
        updateKeys: [RUNG_ZERO],
        nextKeyHashes: [rungZeroHash, rungOneHash],
        signers: [RUNG_ZERO],
        ladderVms: [LADDER]
      }),
      entry({
        versionId: '2-v2',
        updateKeys: [RUNG_ZERO],
        nextKeyHashes: [
          rungZeroHash,
          rungOneHash,
          clientHash,
          CLIENT_STAGED_HASH
        ],
        signers: [RUNG_ZERO],
        ladderVms: [LADDER]
      }),
      entry({
        versionId: '3-v3',
        updateKeys: [CLIENT_UPDATE],
        nextKeyHashes: [rungOneHash, clientHash, CLIENT_STAGED_HASH],
        signers: [CLIENT_UPDATE],
        ladderVms: [LADDER],
        clients: [CLIENT_SIGNING]
      }),
      // The second self-enrollment reveals rung 1 and commits, in the
      // ratified order, the new client's two hashes and then rung 2's.
      entry({
        versionId: '4-v4',
        updateKeys: [CLIENT_UPDATE, RUNG_ONE],
        nextKeyHashes: [
          rungOneHash,
          clientHash,
          CLIENT_STAGED_HASH,
          clientTwoHash,
          CLIENT_TWO_STAGED_HASH,
          rungTwoHash
        ],
        signers: [RUNG_ONE],
        ladderVms: [LADDER],
        clients: [CLIENT_SIGNING]
      }),
      entry({
        versionId: '5-v5',
        updateKeys: [CLIENT_UPDATE, CLIENT_TWO_UPDATE],
        nextKeyHashes: [
          rungTwoHash,
          clientHash,
          CLIENT_STAGED_HASH,
          clientTwoHash,
          CLIENT_TWO_STAGED_HASH
        ],
        signers: [CLIENT_TWO_UPDATE],
        ladderVms: [LADDER],
        clients: [CLIENT_SIGNING, CLIENT_TWO_SIGNING]
      }),
      entry({
        versionId: '6-v6',
        updateKeys: [CLIENT_UPDATE, CLIENT_TWO_UPDATE, RUNG_TWO],
        nextKeyHashes: [
          rungTwoHash,
          clientHash,
          CLIENT_STAGED_HASH,
          clientTwoHash,
          CLIENT_TWO_STAGED_HASH
        ],
        signers: [RUNG_TWO],
        ladderVms: [LADDER],
        clients: [CLIENT_SIGNING, CLIENT_TWO_SIGNING]
      })
    ] as unknown as DIDLog
    expect(await rungsAtHead(log)).toEqual({ [LADDER]: [RUNG_TWO] })
  })

  it('never climbs onto a client update key a ladder-signed approval authorized', async () => {
    const rungZeroHash = await deriveNextKeyHash(RUNG_ZERO)
    const rungOneHash = await deriveNextKeyHash(RUNG_ONE)
    const clientHash = await deriveNextKeyHash(CLIENT_UPDATE)
    const stagedHash = await deriveNextKeyHash(CLIENT_TWO_UPDATE)
    const genesis = entry({
      versionId: '1-v1',
      updateKeys: [RUNG_ZERO],
      nextKeyHashes: [rungZeroHash, rungOneHash],
      signers: [RUNG_ZERO],
      ladderVms: [LADDER]
    })
    // The ladder-signed enrollment approval: the commit entry REUSES rung 0,
    // so it authorizes no key at all and stages nothing of the ladder's; the
    // add entry authorizes the client's update key, whose hash sat first
    // among the commit's additions rather than last.
    const commit = entry({
      versionId: '2-v2',
      updateKeys: [RUNG_ZERO],
      nextKeyHashes: [rungZeroHash, rungOneHash, clientHash, stagedHash],
      signers: [RUNG_ZERO],
      ladderVms: [LADDER]
    })
    const add = entry({
      versionId: '3-v3',
      updateKeys: [RUNG_ZERO, CLIENT_UPDATE],
      nextKeyHashes: [rungZeroHash, rungOneHash, clientHash, stagedHash],
      signers: [RUNG_ZERO],
      ladderVms: [LADDER],
      clients: [CLIENT_SIGNING]
    })
    // The client then self-rotates onto its staged key, which signs its own
    // reveal -- the one other shape that authorizes exactly one self-signing
    // key. Its hash was committed last by the approval's commit entry, so
    // only the "the committer authorized and signed one key" conjunct keeps
    // it out.
    const rotation = entry({
      versionId: '4-v4',
      updateKeys: [RUNG_ZERO, CLIENT_TWO_UPDATE],
      nextKeyHashes: [rungZeroHash, rungOneHash, stagedHash],
      signers: [CLIENT_TWO_UPDATE],
      ladderVms: [LADDER],
      clients: [CLIENT_SIGNING]
    })
    expect(
      await rungsAtHead([genesis, commit, add, rotation] as unknown as DIDLog)
    ).toEqual({ [LADDER]: [RUNG_ZERO] })
  })

  it('never climbs onto the replacement credential a recovery spend hands off to', async () => {
    const rungZeroHash = await deriveNextKeyHash(RUNG_ZERO)
    const clientHash = await deriveNextKeyHash(CLIENT_UPDATE)
    const freshRungZeroHash = await deriveNextKeyHash(FRESH_RUNG_ZERO)
    const replacementHash = await deriveNextKeyHash(REPLACEMENT_KEY)
    const genesis = entry({
      versionId: '1-v1',
      updateKeys: [CLIENT_UPDATE],
      nextKeyHashes: [clientHash],
      signers: [CLIENT_UPDATE],
      clients: [CLIENT_SIGNING]
    })
    // Issuance: the code's ladder VM and its one committed rung, bound by an
    // enrolled client. Nothing of the code's is authorized yet.
    const issuance = entry({
      versionId: '2-v2',
      updateKeys: [CLIENT_UPDATE],
      nextKeyHashes: [clientHash, rungZeroHash],
      signers: [CLIENT_UPDATE],
      ladderVms: [LADDER],
      clients: [CLIENT_SIGNING]
    })
    // The spend's reveal-and-commit entry: the code's rung 0 revealed and
    // signing, the fresh credential's rung pair committed adjacently, and the
    // REPLACEMENT code's update-key hash last. That last position is a
    // handover rather than a climb, which is what the VM guard below reads.
    const reveal = entry({
      versionId: '3-v3',
      updateKeys: [CLIENT_UPDATE, RUNG_ZERO],
      nextKeyHashes: [
        clientHash,
        rungZeroHash,
        freshRungZeroHash,
        await deriveNextKeyHash(RUNG_TWO),
        replacementHash
      ],
      signers: [RUNG_ZERO],
      ladderVms: [LADDER],
      clients: [CLIENT_SIGNING]
    })
    // The spend's rung 0 IS attributed while the code stands.
    const beforeHandoff = await attributeLadderRungsPerVersion([
      genesis,
      issuance,
      reveal
    ] as unknown as DIDLog)
    expect([...(beforeHandoff[2]?.get(LADDER) ?? [])]).toEqual([RUNG_ZERO])

    // The add-and-retire entry publishes the fresh credential's ladder VM
    // and the REPLACEMENT code's beside it, and strikes the spent code's,
    // landing the account client-less. Two VMs introduced together name a
    // rung for neither.
    const addAndRetire = entry({
      versionId: '4-v4',
      updateKeys: [FRESH_RUNG_ZERO],
      nextKeyHashes: [freshRungZeroHash, replacementHash],
      signers: [RUNG_ZERO],
      ladderVms: [FRESH_LADDER, REPLACEMENT_LADDER]
    })
    // Later, the replacement code is spent and reveals its own key. Its hash
    // sat last under the spent code's rung, so only the struck ladder VM
    // stops the walk reading the handover as a climb.
    const replacementSpend = entry({
      versionId: '5-v5',
      updateKeys: [FRESH_RUNG_ZERO, REPLACEMENT_KEY],
      nextKeyHashes: [freshRungZeroHash, replacementHash],
      signers: [REPLACEMENT_KEY],
      ladderVms: [FRESH_LADDER, REPLACEMENT_LADDER]
    })
    const head = await rungsAtHead([
      genesis,
      issuance,
      reveal,
      addAndRetire,
      replacementSpend
    ] as unknown as DIDLog)
    expect(head[LADDER]).toBeUndefined()
    expect(Object.values(head).flat()).not.toContain(REPLACEMENT_KEY)
  })

  it('names no rung for either of two ladder VMs one entry introduces', async () => {
    const log = [
      entry({
        versionId: '1-v1',
        updateKeys: [RUNG_ZERO],
        nextKeyHashes: [await deriveNextKeyHash(RUNG_ZERO)],
        signers: [RUNG_ZERO],
        ladderVms: [LADDER, OTHER_LADDER]
      })
    ] as unknown as DIDLog
    expect(await rungsAtHead(log)).toEqual({})
  })

  it('names no rung when the introducing entry matches neither shape', async () => {
    // Two keys authorized at the introduction: nothing says which is the
    // ladder's, so the walk refuses rather than picking one.
    const log = [
      entry({
        versionId: '1-v1',
        updateKeys: [RUNG_ZERO, CLIENT_UPDATE],
        nextKeyHashes: [await deriveNextKeyHash(RUNG_ZERO)],
        signers: [RUNG_ZERO],
        ladderVms: [LADDER],
        clients: [CLIENT_SIGNING]
      })
    ] as unknown as DIDLog
    expect(await rungsAtHead(log)).toEqual({})
  })
  it('anchors a ladder-branch bind on its committed rung while the acting ladder climbs', async () => {
    const rungZeroHash = await deriveNextKeyHash(RUNG_ZERO)
    const rungOneHash = await deriveNextKeyHash(RUNG_ONE)
    const clientHash = await deriveNextKeyHash(CLIENT_UPDATE)
    const otherRungZeroHash = await deriveNextKeyHash(OTHER_RUNG_ZERO)
    // The ladder-anchored genesis, then the self-enrollment that retires rung
    // 0 and leaves rung 1 committed: the credential's next ceremony must
    // reveal a rung the account does not yet authorize.
    const genesis = entry({
      versionId: '1-v1',
      updateKeys: [RUNG_ZERO],
      nextKeyHashes: [rungZeroHash, rungOneHash],
      signers: [RUNG_ZERO],
      ladderVms: [LADDER]
    })
    const reveal = entry({
      versionId: '2-v2',
      updateKeys: [RUNG_ZERO],
      nextKeyHashes: [
        rungZeroHash,
        rungOneHash,
        clientHash,
        CLIENT_STAGED_HASH
      ],
      signers: [RUNG_ZERO],
      ladderVms: [LADDER]
    })
    const add = entry({
      versionId: '3-v3',
      updateKeys: [CLIENT_UPDATE],
      nextKeyHashes: [rungOneHash, clientHash, CLIENT_STAGED_HASH],
      signers: [CLIENT_UPDATE],
      ladderVms: [LADDER],
      clients: [CLIENT_SIGNING]
    })
    // The ladder-branch bind: the ACTING credential's rung 1 reveals itself
    // in the entry that introduces the second credential's ladder VM and
    // commits its rung-0 hash.
    const bind = entry({
      versionId: '4-v4',
      updateKeys: [CLIENT_UPDATE, RUNG_ONE],
      nextKeyHashes: [
        rungOneHash,
        clientHash,
        CLIENT_STAGED_HASH,
        otherRungZeroHash
      ],
      signers: [RUNG_ONE],
      ladderVms: [LADDER, OTHER_LADDER],
      clients: [CLIENT_SIGNING]
    })
    const atBind = await attributeLadderRungsPerVersion([
      genesis,
      reveal,
      add,
      bind
    ] as unknown as DIDLog)
    // The acting ladder climbed onto rung 1; the bound ladder holds only a
    // commitment, so it is named nowhere yet -- and rung 1 is not credited to
    // it.
    expect([...(atBind[3]?.get(LADDER) ?? [])]).toEqual([RUNG_ONE])
    expect(atBind[3]?.get(OTHER_LADDER)).toBeUndefined()

    // The bound credential's own first ceremony reveals its rung 0.
    const boundReveal = entry({
      versionId: '5-v5',
      updateKeys: [CLIENT_UPDATE, RUNG_ONE, OTHER_RUNG_ZERO],
      nextKeyHashes: [
        rungOneHash,
        clientHash,
        CLIENT_STAGED_HASH,
        otherRungZeroHash
      ],
      signers: [OTHER_RUNG_ZERO],
      ladderVms: [LADDER, OTHER_LADDER],
      clients: [CLIENT_SIGNING]
    })
    expect(
      await rungsAtHead([
        genesis,
        reveal,
        add,
        bind,
        boundReveal
      ] as unknown as DIDLog)
    ).toEqual({
      [LADDER]: [RUNG_ONE],
      [OTHER_LADDER]: [OTHER_RUNG_ZERO]
    })
  })

  it('anchors a ladder-branch bind whose acting rung stands revealed already', async () => {
    const rungZeroHash = await deriveNextKeyHash(RUNG_ZERO)
    const rungOneHash = await deriveNextKeyHash(RUNG_ONE)
    const otherRungZeroHash = await deriveNextKeyHash(OTHER_RUNG_ZERO)
    const genesis = entry({
      versionId: '1-v1',
      updateKeys: [RUNG_ZERO],
      nextKeyHashes: [rungZeroHash, rungOneHash],
      signers: [RUNG_ZERO],
      ladderVms: [LADDER]
    })
    // Rungs are reused: the acting rung is already authorized, so the bind
    // entry authorizes no key at all and the commitment arm reads it exactly
    // as it reads a bind an enrolled client signs.
    const bind = entry({
      versionId: '2-v2',
      updateKeys: [RUNG_ZERO],
      nextKeyHashes: [rungZeroHash, rungOneHash, otherRungZeroHash],
      signers: [RUNG_ZERO],
      ladderVms: [LADDER, OTHER_LADDER]
    })
    const boundReveal = entry({
      versionId: '3-v3',
      updateKeys: [RUNG_ZERO, OTHER_RUNG_ZERO],
      nextKeyHashes: [rungZeroHash, rungOneHash, otherRungZeroHash],
      signers: [OTHER_RUNG_ZERO],
      ladderVms: [LADDER, OTHER_LADDER]
    })
    expect(
      await rungsAtHead([genesis, bind, boundReveal] as unknown as DIDLog)
    ).toEqual({
      [LADDER]: [RUNG_ZERO],
      [OTHER_LADDER]: [OTHER_RUNG_ZERO]
    })
  })
})
