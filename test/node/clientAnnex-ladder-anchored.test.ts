/**
 * Unit tests for the ladder-anchored account configuration: the ladder VM (the stable
 * sibling key derived once from a credential's ladder seed), the ladder-anchored
 * genesis log (`createLadderAnchoredAccountLog` -- zero enrolled durable clients,
 * update authority on ladder rung 0, the credential's keyAgreement inventory
 * folded into genesis), the relation-asymmetry recognition (`ladderVmIds`),
 * and the first durable self-enrollment's atomic add entry, which publishes
 * the client, retires rung 0, and removes the ladder VM in one entry.
 */
import { describe, expect, it } from 'vitest'
import {
  defaultWebvhLogVerifier,
  deriveNextKeyHash,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import {
  generateLadderSeed,
  ladderRung,
  ladderVmKeyMultibase
} from '../../src/clientAnnex/ladder.js'
import {
  createLadderAnchoredAccountLog,
  selfEnrollWebvhClient
} from '../../src/clientAnnex/ladderAnchored.js'
import { unlockKeyVmId } from '../../src/unlock/standingWebvh.js'
import type { UnlockKeyAgreementPublication } from '../../src/unlock/standingWebvh.js'
import {
  keyAgreementCommitment,
  mintClientWebvhUpdateKeys,
  pinOfLog,
  putLogResource,
  updateKeyMultibase
} from '../../src/webvh/didWebvh.js'
import type { WebvhIdStore } from '../../src/webvh/didWebvh.js'
import {
  ladderVmIds,
  listEnrolledWebvhClients
} from '../../src/webvh/listClients.js'
import { selfEnrollClientCore } from '../../src/clientAnnex/selfEnroll.js'
import { accountLogPinId } from '../../src/webvh/verifyLog.js'
import {
  memoryResourceLogPinStore,
  ResourceLogContinuityError
} from '@interop/vh-resource-log'
import { memoryIdStore } from './fixtures/memoryIdStore.js'
import { truncatingLogStore } from './fixtures/truncatingLogStore.js'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-ladder-anchored'

/**
 * The account log's pin slot for this suite's fixtures.
 */
const LOG_ID = accountLogPinId({ spaceId: SPACE_ID })

/**
 * Resolves a log string with full verification.
 */
async function resolvedLog(logText: string) {
  const result = await resolveDIDFromLog(readLogFromString(logText), {
    verifier: defaultWebvhLogVerifier
  })
  expect(result.meta.error).toBeUndefined()
  return result
}

/**
 * A ladder-anchored account: a fresh ladder, its genesis log created (and, when a
 * store is passed, published as `did.jsonl`).
 */
async function ladderAnchoredAccount({
  keyAgreement,
  idStore
}: {
  keyAgreement: UnlockKeyAgreementPublication
  idStore?: WebvhIdStore
}) {
  const ladderSeed = generateLadderSeed()
  const created = await createLadderAnchoredAccountLog({
    wasServerUrl: WAS_URL,
    spaceId: SPACE_ID,
    ladderSeed,
    keyAgreement
  })
  if (idStore) {
    await putLogResource({ store: idStore, log: created.log })
  }
  return { ladderSeed, ...created }
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

describe('the ladder VM (the stable sibling)', () => {
  it('derives one stable key, distinct from every rung', async () => {
    const ladderSeed = generateLadderSeed()
    const vmKey = await ladderVmKeyMultibase({ ladderSeed })
    expect(await ladderVmKeyMultibase({ ladderSeed })).toBe(vmKey)
    for (let index = 0; index < 5; index++) {
      const rung = await ladderRung({ ladderSeed, index })
      expect(rung.keyMultibase).not.toBe(vmKey)
    }
    const otherSeed = generateLadderSeed()
    expect(await ladderVmKeyMultibase({ ladderSeed: otherSeed })).not.toBe(
      vmKey
    )
  })
})

describe('the ladder-anchored genesis', () => {
  it('anchors a resolvable log on the ladder alone, inventory folded in', async () => {
    const ladderSeed = generateLadderSeed()
    // A high-entropy credential's inventory: the key published verbatim.
    const keyAgreement = {
      publicKeyMultibase: CANONICAL_CLIENT_KEYS[9]!.keyAgreementKeyMultibase
    }
    const { log, webDoc, did } = await createLadderAnchoredAccountLog({
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      ladderSeed,
      keyAgreement
    })
    expect(webDoc).toBeDefined()

    const rung0 = await ladderRung({ ladderSeed, index: 0 })
    const rung1 = await ladderRung({ ladderSeed, index: 1 })
    const vmKey = await ladderVmKeyMultibase({ ladderSeed })
    const state = await resolvedLog(log.map(e => JSON.stringify(e)).join('\n'))
    expect(state.did).toBe(did)

    // Update authority is ladder-only: rung 0 active, rung 1 staged, plus
    // rung 0's own carry-over hash (which the first durable self-enrollment's
    // reveal-and-commit entry, re-stating updateKeys containing rung 0,
    // requires).
    expect(state.meta.updateKeys).toEqual([rung0.keyMultibase])
    expect(state.meta.nextKeyHashes).toEqual([
      await deriveNextKeyHash(rung0.keyMultibase),
      await deriveNextKeyHash(rung1.keyMultibase)
    ])
    expect(log[0]!.parameters.portable).toBe(true)

    // The exact published shape of the ladder VM, and its two relations.
    const doc = state.doc!
    const ladderVmId = `${did}#${vmKey}`
    expect(doc.verificationMethod).toContainEqual({
      id: ladderVmId,
      type: 'Multikey',
      controller: did,
      publicKeyMultibase: vmKey
    })
    expect(doc.assertionMethod).toEqual([ladderVmId])
    expect(doc.capabilityDelegation).toEqual([ladderVmId])
    expect(doc.authentication ?? []).toEqual([])
    expect(doc.capabilityInvocation ?? []).toEqual([])

    // The genesis keyAgreement holds only the credential's inventory entry.
    const inventoryVmId = unlockKeyVmId({ did, keyAgreement })
    expect(doc.keyAgreement).toEqual([inventoryVmId])
    expect(doc.verificationMethod).toHaveLength(2)

    // Recognition by relation asymmetry, and structural exclusion from the
    // client listing.
    expect(ladderVmIds({ doc })).toEqual([ladderVmId])
    expect(listEnrolledWebvhClients({ log })).toEqual([])
  })
})

describe('the first durable self-enrollment from a ladder-anchored account', () => {
  it('publishes the client, retires rung 0, and removes the ladder VM in one atomic add entry', async () => {
    const { idStore, log } = memoryIdStore()
    const keyAgreement = {
      commitment: await keyAgreementCommitment({
        keyAgreementKeyMultibase:
          CANONICAL_CLIENT_KEYS[9]!.keyAgreementKeyMultibase
      })
    }
    const account = await ladderAnchoredAccount({ keyAgreement, idStore })
    const { ladderSeed, did } = account
    const vmKey = await ladderVmKeyMultibase({ ladderSeed })
    const ladderVmId = `${did}#${vmKey}`

    const client = await mintedNewClient(3)
    const outcome = await selfEnrollWebvhClient({
      store: idStore,
      ladderSeed,
      newClientKeys: client.keys,
      newClientUpdateSeeds: client.seeds,
      expectedDid: did
    })
    expect(outcome.did).toBe(did)

    // Genesis, reveal-and-commit, add: three entries.
    const entries = readLogFromString(log()!)
    expect(entries).toHaveLength(3)

    const state = await resolvedLog(log()!)
    const doc = state.doc!

    // The client is an ordinary enrolled client: both VMs, all four signing
    // relations, update key authorized, staged key committed.
    const signingVmId = `${did}#${client.keys.signingKeyMultibase}`
    expect(state.meta.updateKeys).toContain(client.keys.updateKeyMultibase)
    for (const relation of [
      doc.authentication,
      doc.assertionMethod,
      doc.capabilityInvocation,
      doc.capabilityDelegation
    ]) {
      expect(relation).toContain(signingVmId)
    }
    expect(doc.keyAgreement).toContain(
      `${did}#${client.keys.keyAgreementKeyMultibase}`
    )
    expect(listEnrolledWebvhClients({ log: entries })).toHaveLength(1)

    // The ladder-anchored window is closed: rung 0 retired from updateKeys and
    // nextKeyHashes, the ladder VM out of the document and both its
    // relations, nothing recognized as a ladder VM any more.
    const rung0 = await ladderRung({ ladderSeed, index: 0 })
    const rung1 = await ladderRung({ ladderSeed, index: 1 })
    expect(state.meta.updateKeys).not.toContain(rung0.keyMultibase)
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(rung0.keyMultibase)
    )
    expect(doc.verificationMethod?.map(method => method.id)).not.toContain(
      ladderVmId
    )
    expect(doc.assertionMethod ?? []).not.toContain(ladderVmId)
    expect(doc.capabilityDelegation ?? []).not.toContain(ladderVmId)
    expect(ladderVmIds({ doc })).toEqual([])

    // The credential's own standing is untouched: its keyAgreement entry stands,
    // and rung 1's hash remains its standing commitment.
    expect(doc.keyAgreement).toContain(unlockKeyVmId({ did, keyAgreement }))
    expect(state.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(rung1.keyMultibase)
    )

    // Atomicity: the reveal-and-commit entry (entry 2) leaves the ladder VM
    // untouched -- a delegation it signed keeps verifying mid-ceremony --
    // and exactly the add entry removes it.
    const revealState = entries[1]!.state as {
      capabilityDelegation?: string[]
      verificationMethod?: Array<{ id?: string }>
    }
    expect(revealState.capabilityDelegation).toContain(ladderVmId)
    expect(revealState.verificationMethod?.map(method => method.id)).toContain(
      ladderVmId
    )

    // Resumable: a re-run with the same key material is a no-op.
    await selfEnrollWebvhClient({
      store: idStore,
      ladderSeed,
      newClientKeys: client.keys,
      newClientUpdateSeeds: client.seeds,
      expectedDid: did
    })
    expect(readLogFromString(log()!)).toHaveLength(3)
  })

  /**
   * A ladder-anchored account published into a fresh store, its keyAgreement
   * commitment taken from a canonical key.
   */
  async function publishedAccount() {
    const { idStore, log: logText } = memoryIdStore()
    const keyAgreement = {
      commitment: await keyAgreementCommitment({
        keyAgreementKeyMultibase:
          CANONICAL_CLIENT_KEYS[9]!.keyAgreementKeyMultibase
      })
    }
    const account = await ladderAnchoredAccount({ keyAgreement, idStore })
    return { idStore, logText, ...account }
  }

  /**
   * Runs `selfEnrollClientCore` against a store. The core's stages past the
   * two log entries (the verify, the roster read) are never reached by the
   * refusals under test, so the credential key is a placeholder.
   */
  async function runCore({
    store,
    ladderSeed,
    did,
    pinStore
  }: {
    store: WebvhIdStore
    ladderSeed: Uint8Array
    did: string
    pinStore: ReturnType<typeof memoryResourceLogPinStore>
  }): Promise<unknown> {
    try {
      await selfEnrollClientCore({
        pointer: { did, spaceId: SPACE_ID, host: WAS_URL },
        ladderSeed,
        credentialKeyAgreementKey: {} as never,
        logStore: store,
        accountLogPinStore: pinStore
      })
    } catch (err) {
      return err
    }
    return undefined
  }

  it('advances the chain-head pin to each entry it publishes', async () => {
    const { idStore, logText, ladderSeed, did } = await publishedAccount()
    const pinStore = memoryResourceLogPinStore()
    const client = await mintedNewClient(4)

    await selfEnrollWebvhClient({
      store: idStore,
      ladderSeed,
      newClientKeys: client.keys,
      newClientUpdateSeeds: client.seeds,
      expectedDid: did,
      pinStore,
      logId: LOG_ID
    })

    // The reveal entry advanced the pin first; the add entry's head is what
    // stands afterwards.
    expect(readLogFromString(logText()!)).toHaveLength(3)
    expect(await pinStore.read({ logId: LOG_ID })).toEqual(
      pinOfLog(readLogFromString(logText()!))
    )
  })

  it('refuses a served prefix of the pinned log before the reveal-and-commit entry lands', async () => {
    const { idStore, logText, ladderSeed, did } = await publishedAccount()
    // A second entry past genesis, so a prefix of the pinned log exists.
    const first = await mintedNewClient(4)
    await selfEnrollWebvhClient({
      store: idStore,
      ladderSeed,
      newClientKeys: first.keys,
      newClientUpdateSeeds: first.seeds,
      expectedDid: did
    })
    const pinStore = memoryResourceLogPinStore()
    await pinStore.write({
      logId: LOG_ID,
      pin: pinOfLog(readLogFromString(logText()!))
    })
    const { store } = truncatingLogStore({ idStore, dropEntries: 1 })
    const logBefore = logText()

    const caught = await runCore({ store, ladderSeed, did, pinStore })

    expect(caught).toBeInstanceOf(ResourceLogContinuityError)
    expect((caught as ResourceLogContinuityError).reason).toBe('rollback')
    expect(logText()).toBe(logBefore)
  })

  it('refuses a prefix served only to the post-reveal re-read, before the add entry lands', async () => {
    const { idStore, logText, ladderSeed, did } = await publishedAccount()
    const pinStore = memoryResourceLogPinStore()
    // The first read (the one the reveal entry is built on) sees the full
    // log and establishes the pin; the reveal entry advances it; the re-read
    // the add entry would be built on is served a prefix behind that.
    const { store, counter } = truncatingLogStore({
      idStore,
      dropEntries: 1,
      fromRead: 2
    })

    const caught = await runCore({ store, ladderSeed, did, pinStore })

    expect(caught).toBeInstanceOf(ResourceLogContinuityError)
    expect((caught as ResourceLogContinuityError).reason).toBe('rollback')
    expect(counter.reads).toBe(2)
    // Genesis plus the reveal-and-commit entry; no add entry.
    expect(readLogFromString(logText()!)).toHaveLength(2)
    expect(await pinStore.read({ logId: LOG_ID })).toEqual(
      pinOfLog(readLogFromString(logText()!))
    )
  })
})
