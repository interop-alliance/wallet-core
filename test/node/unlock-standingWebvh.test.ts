/**
 * Unit tests for the standing-credential did:webvh lifecycle
 * (`src/unlock/standingWebvh.ts`) against an in-memory store: the merged
 * posture edit publishing a hash-commitment `keyAgreement` entry (and
 * removing it), and the self-enrolling continuation -- reveal a ladder rung,
 * add an ordinary client, retire the rung, leave the credential's posture
 * standing on the next rung -- including its resumability, its repeatability
 * (the second self-enrollment climbs the ladder), and the fail-closed
 * attribution after a removal.
 */
import { describe, expect, it } from 'vitest'
import {
  defaultWebvhLogVerifier,
  deriveNextKeyHash,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import {
  attributeLadderPosture,
  generateLadderSeed,
  ladderRung
} from '../../src/unlock/ladder.js'
import {
  publishUnlockKey,
  removeUnlockKey,
  selfEnrollWebvhClient,
  unlockKeyVmId
} from '../../src/unlock/standingWebvh.js'
import type { StandingUnlockKeys } from '../../src/unlock/standingWebvh.js'
import { LadderAttributionError } from '../../src/unlock/ladder.js'
import {
  ensureDidWebvh,
  keyAgreementCommitment,
  mintClientWebvhUpdateKeys,
  updateKeyMultibase,
  type ClientWebvhUpdateKeys,
  type WebvhIdStore
} from '../../src/webvh/didWebvh.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-unlock'

/**
 * Provisions a fresh in-memory did:webvh log for one enrolled client.
 */
async function provisionedLog(): Promise<{
  idStore: WebvhIdStore
  log: () => string | undefined
  updateKeys: ClientWebvhUpdateKeys
  did: string
}> {
  const { idStore, log } = memoryIdStore()
  const updateKeys = await mintClientWebvhUpdateKeys()
  const { did } = await ensureDidWebvh({
    idStore,
    wasServerUrl: WAS_URL,
    spaceId: SPACE_ID,
    clientKeys: { ...CANONICAL_CLIENT_KEYS[0] },
    updateKeys
  })
  return { idStore, log, updateKeys, did }
}

/**
 * Resolves the store's current log with full verification.
 */
async function resolved(log: () => string | undefined) {
  const result = await resolveDIDFromLog(readLogFromString(log()!), {
    verifier: defaultWebvhLogVerifier
  })
  expect(result.meta.error).toBeUndefined()
  return result
}

/**
 * A standing passphrase-shaped credential: a fresh ladder and its
 * commitment-published posture (rung 0 committed, key-agreement key hashed).
 */
async function standingCredential() {
  const ladderSeed = generateLadderSeed()
  const rung0 = await ladderRung({ ladderSeed, index: 0 })
  const keyAgreementKeyMultibase =
    CANONICAL_CLIENT_KEYS[9].keyAgreementKeyMultibase
  const unlockKeys: StandingUnlockKeys = {
    keyAgreement: {
      commitment: await keyAgreementCommitment({ keyAgreementKeyMultibase })
    },
    updateKeyMultibase: rung0.keyMultibase
  }
  return { ladderSeed, rung0, keyAgreementKeyMultibase, unlockKeys }
}

/**
 * A freshly minted ordinary client's public halves plus its update seeds.
 */
async function mintedNewClient(index: number) {
  const seeds = await mintClientWebvhUpdateKeys()
  return {
    seeds,
    keys: {
      ...CANONICAL_CLIENT_KEYS[index]!,
      updateKeyMultibase: await updateKeyMultibase({ seed: seeds.updateSeed }),
      stagedUpdateKeyMultibase: await updateKeyMultibase({
        seed: seeds.stagedSeed
      })
    }
  }
}

describe('the standing unlock-key posture', () => {
  it('publishes a hash-commitment keyAgreement entry, idempotently, and removes it', async () => {
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const { unlockKeys, rung0 } = await standingCredential()

    const published = await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys
    })
    let state = await resolved(log)
    const vmId = unlockKeyVmId({ did, keyAgreement: unlockKeys.keyAgreement })
    const method = state.doc?.verificationMethod?.find(
      entry => entry.id === vmId
    ) as { publicKeyCommitment?: string; controller?: string } | undefined
    // The entry carries the commitment, never the key; it is
    // account-controlled (unmarked) and appears ONLY under keyAgreement --
    // in particular not under authentication (the library's default purpose
    // for an unwired verification method).
    expect(method?.publicKeyCommitment).toBe(
      'commitment' in unlockKeys.keyAgreement
        ? unlockKeys.keyAgreement.commitment
        : undefined
    )
    expect(method?.controller).toBe(did)
    expect(state.doc?.keyAgreement).toContain(vmId)
    expect(state.doc?.authentication).not.toContain(vmId)
    expect(state.doc?.capabilityInvocation).not.toContain(vmId)
    // Authority latent: the hash committed, the rung authorized nowhere.
    expect(state.meta.updateKeys).not.toContain(rung0.keyMultibase)
    expect(state.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(rung0.keyMultibase)
    )

    // The post-edit document and log come back, so the caller's roster-side
    // half converges onto the document this entry just published.
    expect(published.did).toBe(did)
    expect(published.doc.keyAgreement).toContain(vmId)
    expect(published.log.length).toBe(readLogFromString(log()!).length)

    // Idempotent re-run publishes nothing, and re-states the same document.
    const entries = readLogFromString(log()!).length
    const settled = await publishUnlockKey({ idStore, updateKeys, unlockKeys })
    expect(readLogFromString(log()!).length).toBe(entries)
    expect(settled.doc.keyAgreement).toContain(vmId)
    expect(settled.log.length).toBe(entries)

    // Removal takes both halves out, idempotently.
    const removed = await removeUnlockKey({ idStore, updateKeys, unlockKeys })
    expect(removed.doc.keyAgreement ?? []).not.toContain(vmId)
    await removeUnlockKey({ idStore, updateKeys, unlockKeys })
    state = await resolved(log)
    expect(state.doc?.keyAgreement ?? []).not.toContain(vmId)
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(rung0.keyMultibase)
    )
  })
})

describe('the self-enrolling continuation', () => {
  it('reveals the rung, adds an ordinary client, retires the rung, and climbs on the next run', async () => {
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const credential = await standingCredential()
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys
    })
    const entriesAfterBind = readLogFromString(log()!).length

    const first = await mintedNewClient(3)
    const outcome = await selfEnrollWebvhClient({
      store: idStore,
      ladderSeed: credential.ladderSeed,
      newClientKeys: first.keys,
      newClientUpdateSeeds: first.seeds,
      expectedDid: did
    })
    expect(outcome.did).toBe(did)
    expect(outcome.webDoc).toBeDefined()
    expect(readLogFromString(log()!).length).toBe(entriesAfterBind + 2)

    let state = await resolved(log)
    // The new client is an ordinary enrolled client: both VMs, all four
    // signing relations, update key authorized, staged key committed.
    expect(state.meta.updateKeys).toContain(first.keys.updateKeyMultibase)
    expect(state.doc?.capabilityInvocation).toContain(
      `${did}#${first.keys.signingKeyMultibase}`
    )
    expect(state.doc?.keyAgreement).toContain(
      `${did}#${first.keys.keyAgreementKeyMultibase}`
    )
    expect(state.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(first.keys.stagedUpdateKeyMultibase)
    )
    // The spent rung is retired; the next rung's hash stands as the
    // credential's standing commitment; the posture entry is untouched.
    const rung1 = await ladderRung({
      ladderSeed: credential.ladderSeed,
      index: 1
    })
    expect(state.meta.updateKeys).not.toContain(credential.rung0.keyMultibase)
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(credential.rung0.keyMultibase)
    )
    expect(state.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(rung1.keyMultibase)
    )
    expect(state.doc?.keyAgreement).toContain(
      unlockKeyVmId({ did, keyAgreement: credential.unlockKeys.keyAgreement })
    )

    // Resumable: a re-run with the same key material is a no-op.
    await selfEnrollWebvhClient({
      store: idStore,
      ladderSeed: credential.ladderSeed,
      newClientKeys: first.keys,
      newClientUpdateSeeds: first.seeds,
      expectedDid: did
    })
    expect(readLogFromString(log()!).length).toBe(entriesAfterBind + 2)

    // The next self-enrollment climbs the ladder: rung 1 reveals and
    // retires, rung 2 commits.
    const second = await mintedNewClient(4)
    await selfEnrollWebvhClient({
      store: idStore,
      ladderSeed: credential.ladderSeed,
      newClientKeys: second.keys,
      newClientUpdateSeeds: second.seeds,
      expectedDid: did
    })
    state = await resolved(log)
    const rung2 = await ladderRung({
      ladderSeed: credential.ladderSeed,
      index: 2
    })
    expect(state.meta.updateKeys).toContain(second.keys.updateKeyMultibase)
    expect(state.meta.updateKeys).not.toContain(rung1.keyMultibase)
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(rung1.keyMultibase)
    )
    expect(state.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(rung2.keyMultibase)
    )
  })

  it('refuses to self-enroll once the posture is removed', async () => {
    const { idStore, updateKeys, did } = await provisionedLog()
    const credential = await standingCredential()
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys
    })
    await removeUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys
    })
    const fresh = await mintedNewClient(5)
    await expect(
      selfEnrollWebvhClient({
        store: idStore,
        ladderSeed: credential.ladderSeed,
        newClientKeys: fresh.keys,
        newClientUpdateSeeds: fresh.seeds,
        expectedDid: did
      })
    ).rejects.toThrow(LadderAttributionError)
  })
})

describe('retiring a credential past rung 0', () => {
  /**
   * Binds a standing credential and self-enrolls one ordinary client through
   * it, leaving the credential's standing commitment at rung 1 while its
   * recorded posture (the registry shape) still names rung 0.
   */
  async function boundAndEnrolled() {
    const provisioned = await provisionedLog()
    const credential = await standingCredential()
    await publishUnlockKey({
      idStore: provisioned.idStore,
      updateKeys: provisioned.updateKeys,
      unlockKeys: credential.unlockKeys
    })
    const enrolled = await mintedNewClient(3)
    await selfEnrollWebvhClient({
      store: provisioned.idStore,
      ladderSeed: credential.ladderSeed,
      newClientKeys: enrolled.keys,
      newClientUpdateSeeds: enrolled.seeds,
      expectedDid: provisioned.did
    })
    return { ...provisioned, credential, enrolled }
  }

  it('strikes the live rung commitment when the recorded posture is stale', async () => {
    const { idStore, log, updateKeys, did, credential, enrolled } =
      await boundAndEnrolled()
    const rung1 = await ladderRung({
      ladderSeed: credential.ladderSeed,
      index: 1
    })
    let state = await resolved(log)
    expect(state.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(rung1.keyMultibase)
    )

    // The removal names the STALE bind-time posture (rung 0), the shape a
    // never-refreshed registry entry supplies -- and no ladder seed.
    await removeUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys
    })
    state = await resolved(log)
    const vmId = unlockKeyVmId({
      did,
      keyAgreement: credential.unlockKeys.keyAgreement
    })
    expect(state.doc?.keyAgreement ?? []).not.toContain(vmId)
    // The LIVE commitment (rung 1) is gone, not just the stale rung 0's.
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(rung1.keyMultibase)
    )
    // The innocent enrolled client is untouched: update key authorized,
    // staged commitment standing.
    expect(state.meta.updateKeys).toContain(enrolled.keys.updateKeyMultibase)
    expect(state.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(enrolled.keys.updateKeyMultibase)
    )
    expect(state.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(enrolled.keys.stagedUpdateKeyMultibase)
    )

    // The retired credential can no longer self-enroll, and a re-run of the
    // removal is a settled no-op.
    const fresh = await mintedNewClient(5)
    await expect(
      selfEnrollWebvhClient({
        store: idStore,
        ladderSeed: credential.ladderSeed,
        newClientKeys: fresh.keys,
        newClientUpdateSeeds: fresh.seeds,
        expectedDid: did
      })
    ).rejects.toThrow(LadderAttributionError)
    const entries = readLogFromString(log()!).length
    await removeUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys
    })
    expect(readLogFromString(log()!).length).toBe(entries)
  })

  it('retires a torn self-enrollment cleanly: revealed rung and unclaimed hashes out', async () => {
    const { idStore, log, updateKeys, did, credential, enrolled } =
      await boundAndEnrolled()

    // Tear the SECOND self-enrollment between its two entries: the reveal
    // entry lands (rung 1 into updateKeys; the pending client's update- and
    // staged-key hashes plus rung 2's committed), the add entry does not.
    let puts = 0
    const tearing = {
      getIdResourceRaw: idStore.getIdResourceRaw.bind(idStore),
      putIdResource: async (
        ...args: Parameters<WebvhIdStore['putIdResource']>
      ) => {
        puts += 1
        if (puts > 1) {
          throw new Error('torn: the add entry never landed')
        }
        return idStore.putIdResource(...args)
      }
    }
    const pendingClient = await mintedNewClient(4)
    await expect(
      selfEnrollWebvhClient({
        store: tearing as WebvhIdStore,
        ladderSeed: credential.ladderSeed,
        newClientKeys: pendingClient.keys,
        newClientUpdateSeeds: pendingClient.seeds,
        expectedDid: did
      })
    ).rejects.toThrow('torn')
    const rung1 = await ladderRung({
      ladderSeed: credential.ladderSeed,
      index: 1
    })
    const rung2 = await ladderRung({
      ladderSeed: credential.ladderSeed,
      index: 2
    })
    let state = await resolved(log)
    expect(state.meta.updateKeys).toContain(rung1.keyMultibase)

    // The stale-anchored, seed-less attribution accounts for the whole torn
    // footprint: the revealed rung, its own kept hash, the pending client's
    // two hashes, and rung 2's commitment.
    const posture = await attributeLadderPosture({
      log: readLogFromString(log()!),
      anchorKeyMultibase: credential.rung0.keyMultibase
    })
    expect(posture.revealedKeys).toEqual([rung1.keyMultibase])
    expect(new Set(posture.committedHashes)).toEqual(
      new Set([
        await deriveNextKeyHash(rung1.keyMultibase),
        await deriveNextKeyHash(pendingClient.keys.updateKeyMultibase),
        await deriveNextKeyHash(pendingClient.keys.stagedUpdateKeyMultibase),
        await deriveNextKeyHash(rung2.keyMultibase)
      ])
    )

    // Retirement with the stale posture and the ladder seed in hand.
    await removeUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed
    })
    state = await resolved(log)
    expect(state.meta.updateKeys).not.toContain(rung1.keyMultibase)
    for (const hash of posture.committedHashes) {
      expect(state.meta.nextKeyHashes).not.toContain(hash)
    }
    // The completed first enrollment is untouched.
    expect(state.meta.updateKeys).toContain(enrolled.keys.updateKeyMultibase)
    expect(state.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(enrolled.keys.stagedUpdateKeyMultibase)
    )

    // The log stays extendable: a later ceremony's carry-over check passes
    // (a leftover revealed key without its hash would wedge it).
    const another = await standingCredential()
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: another.unlockKeys
    })
    state = await resolved(log)
    expect(state.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(another.rung0.keyMultibase)
    )
  })
})
