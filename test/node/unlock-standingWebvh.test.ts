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
import { generateLadderSeed, ladderRung } from '../../src/unlock/ladder.js'
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
