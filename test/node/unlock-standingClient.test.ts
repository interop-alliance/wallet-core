/**
 * Unit tests for the standing-credential derivations (`src/unlock/`): the
 * client identity and binding MAC key expanded from an unlock seed
 * (determinism, distinctness across seeds, the canonical twin and roster-kid
 * invariants), and the update-key ladder (rung determinism, and the
 * fail-closed log attribution in its committed, revealed, absent, and
 * ambiguous states).
 */
import { describe, expect, it } from 'vitest'
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import {
  standingClientFromUnlockSeed,
  unlockClientIdentityFromSeed
} from '../../src/unlock/standingClient.js'
import {
  attributeLadderRung,
  generateLadderSeed,
  LADDER_SEED_BYTES,
  LadderAttributionError,
  ladderRung,
  ladderRungSeed
} from '../../src/unlock/ladder.js'
import { keyAgreementTwinMultibase } from '../../src/webvh/didWebvh.js'

describe('standingClientFromUnlockSeed', () => {
  const unlockSeed = new Uint8Array(32).fill(3)

  it('derives the same key set from the same unlock seed', async () => {
    const client = await standingClientFromUnlockSeed({ unlockSeed })
    const again = await standingClientFromUnlockSeed({
      unlockSeed: new Uint8Array(unlockSeed)
    })
    expect(client.clientDid.startsWith('did:key:z6Mk')).toBe(true)
    expect(client.keyAgreementKeyMultibase.startsWith('z6LS')).toBe(true)
    expect(again.clientDid).toBe(client.clientDid)
    expect(again.recipientKid).toBe(client.recipientKid)
    expect(again.bindingMacKey).toEqual(client.bindingMacKey)
    // The client seed itself differs from the unlock seed: the expansions are
    // salted, so the unlock identity and the client identity never collide.
    expect(Array.from(client.clientSeed)).not.toEqual(Array.from(unlockSeed))
  })

  it('derives unrelated key sets from different unlock seeds', async () => {
    const client = await standingClientFromUnlockSeed({ unlockSeed })
    const other = await standingClientFromUnlockSeed({
      unlockSeed: new Uint8Array(32).fill(4)
    })
    expect(other.clientDid).not.toBe(client.clientDid)
    expect(other.bindingMacKey).not.toEqual(client.bindingMacKey)
  })

  it('publishes the canonical X25519 twin and the matching roster kid', async () => {
    const client = await standingClientFromUnlockSeed({ unlockSeed })
    expect(client.keyAgreementKeyMultibase).toBe(
      keyAgreementTwinMultibase({
        signingKeyMultibase: client.signingKeyMultibase
      })
    )
    // The roster kid is exactly the key-agreement key's own id, so the wrap
    // minted at bind time is the one a fresh browser's roster read looks for.
    expect(client.recipientKid).toBe(client.agents.keyAgreementKey.id)
  })

  it('shares the identity assembly with the recovery derivation', async () => {
    const identity = await unlockClientIdentityFromSeed({
      clientSeed: new Uint8Array(32).fill(9)
    })
    expect(identity.recipientKid).toBe(
      `${identity.clientDid}#${identity.keyAgreementKeyMultibase}`
    )
  })
})

describe('the update-key ladder', () => {
  it('derives deterministic, distinct rungs', async () => {
    const ladderSeed = generateLadderSeed()
    expect(ladderSeed).toHaveLength(LADDER_SEED_BYTES)
    const rung0 = await ladderRung({ ladderSeed, index: 0 })
    const rung1 = await ladderRung({ ladderSeed, index: 1 })
    expect(rung0.keyMultibase.startsWith('z6Mk')).toBe(true)
    expect(rung1.keyMultibase).not.toBe(rung0.keyMultibase)
    expect((await ladderRung({ ladderSeed, index: 0 })).keyMultibase).toBe(
      rung0.keyMultibase
    )
    expect(ladderRungSeed({ ladderSeed, index: 0 })).toEqual(rung0.seed)
    expect(() => ladderRungSeed({ ladderSeed, index: -1 })).toThrow(
      /Invalid ladder rung index/
    )
  })

  it('attributes the committed rung, preferring a revealed one mid-ceremony', async () => {
    const ladderSeed = generateLadderSeed()
    const rung2 = await ladderRung({ ladderSeed, index: 2 })
    const rung3 = await ladderRung({ ladderSeed, index: 3 })

    // Steady state: only hash(rung 2) stands.
    const committed = await attributeLadderRung({
      ladderSeed,
      published: {
        updateKeys: ['z6MkSomeClientKey'],
        nextKeyHashes: [await deriveNextKeyHash(rung2.keyMultibase)]
      }
    })
    expect(committed.state).toBe('committed')
    expect(committed.rung.index).toBe(2)

    // Torn self-enrollment: rung 2 revealed (its hash kept), hash(rung 3)
    // committed -- the revealed rung wins, so the resumed add entry signs
    // with it.
    const torn = await attributeLadderRung({
      ladderSeed,
      published: {
        updateKeys: ['z6MkSomeClientKey', rung2.keyMultibase],
        nextKeyHashes: [
          await deriveNextKeyHash(rung2.keyMultibase),
          await deriveNextKeyHash(rung3.keyMultibase)
        ]
      }
    })
    expect(torn.state).toBe('revealed')
    expect(torn.rung.index).toBe(2)
  })

  it('fails closed when no rung, or more than one, matches', async () => {
    const ladderSeed = generateLadderSeed()
    const rung0 = await ladderRung({ ladderSeed, index: 0 })
    const rung5 = await ladderRung({ ladderSeed, index: 5 })

    // No rung: revoked, never bound, or the wrong account's ladder.
    await expect(
      attributeLadderRung({
        ladderSeed,
        published: { updateKeys: [], nextKeyHashes: ['QmSomethingElse'] }
      })
    ).rejects.toThrow(LadderAttributionError)

    // Two committed rungs is a history no legitimate ceremony produces.
    await expect(
      attributeLadderRung({
        ladderSeed,
        published: {
          updateKeys: [],
          nextKeyHashes: [
            await deriveNextKeyHash(rung0.keyMultibase),
            await deriveNextKeyHash(rung5.keyMultibase)
          ]
        }
      })
    ).rejects.toThrow(LadderAttributionError)

    // The scan bound is honored: a rung past maxScan is never derived.
    await expect(
      attributeLadderRung({
        ladderSeed,
        published: {
          updateKeys: [],
          nextKeyHashes: [await deriveNextKeyHash(rung5.keyMultibase)]
        },
        maxScan: 3
      })
    ).rejects.toThrow(LadderAttributionError)
  })
})
