/**
 * Unit tests for the ladder-anchored account configuration: the ladder VM (the stable
 * sibling key derived once from a credential's ladder seed), the ladder-anchored
 * genesis log (`createLadderAnchoredAccountLog` -- zero enrolled clients,
 * update authority on ladder rung 0, the credential's keyAgreement inventory
 * folded into genesis), the relation-asymmetry recognition (`ladderVmIds`),
 * and the first self-enrollment's atomic add entry, which publishes
 * the client, retires rung 0, and removes the ladder VM in one entry.
 */
import { describe, expect, it, vi } from 'vitest'
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
  BuiltOnHeadNotReachedError,
  createLadderAnchoredAccountLog,
  selfEnrollWebvhClient
} from '../../src/clientAnnex/ladderAnchored.js'
import { agentsFromSeed } from '../../src/identity/agents.js'
import { clientSigningKeyMultibase } from '../../src/webvh/zcap.js'
import { unlockKeyVmId } from '../../src/unlock/standingWebvh.js'
import type { UnlockKeyAgreementPublication } from '../../src/unlock/standingWebvh.js'
import {
  keyAgreementCommitment,
  mintClientWebvhUpdateKeys,
  pinOfLog,
  putLogResource,
  updateKeyMultibase
} from '../../src/webvh/didWebvh.js'
import type {
  ClientWebvhUpdateKeys,
  WebvhIdStore
} from '../../src/webvh/didWebvh.js'
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

// `selfEnrollClientCore`'s stages past the two log entries -- the
// world-readable verify and the roster read/escrow -- speak to a WAS server,
// which no unit test has. They are stubbed so the ceremony half (the entries,
// the seam, the resume) can be driven end to end through the core; every
// module keeps its real exports but the four network-bound ones.
vi.mock('../../src/webvh/verifyLog.js', async importOriginal => {
  const actual =
    await importOriginal<typeof import('../../src/webvh/verifyLog.js')>()
  return {
    ...actual,
    verifyAccountLog: async () => ({
      doc: {},
      log: [],
      updateKeys: [],
      nextKeyHashes: []
    })
  }
})
vi.mock('../../src/webvh/zcap.js', async importOriginal => {
  const actual =
    await importOriginal<typeof import('../../src/webvh/zcap.js')>()
  return { ...actual, webvhZcapClient: () => ({}) }
})
vi.mock('../../src/keys/rosterStore.js', () => ({
  userKeyRosterDescriptorStore: () => ({})
}))
vi.mock('../../src/keys/userKeyRoster.js', async importOriginal => {
  const actual =
    await importOriginal<typeof import('../../src/keys/userKeyRoster.js')>()
  return {
    ...actual,
    readUserKeyRoster: async () => ({
      userKey: {},
      latestEpochId: 'epoch-0'
    }),
    addUserKeyRosterRecipient: async () => ({})
  }
})

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

/**
 * The KMS key map a KMS-keeping wallet threads into the genesis -- bare
 * multibase fragments, the enrolled-client genesis suite's shape.
 */
const KMS_AUTH_MULTIBASE = 'z6MkAuthConvenience'
const KMS_DID_WEB_KEYS = {
  authentication: {
    vmId: `did:web:example#${KMS_AUTH_MULTIBASE}`,
    kmsKeyId: 'kms/keys/auth'
  },
  keyAgreement: {
    vmId: 'did:web:example#z6LSAgree',
    kmsKeyId: 'kms/keys/agree'
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
    // rung 0's own carry-over hash (which the first self-enrollment's
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

  it('folds the KMS authentication VM in under authentication only', async () => {
    const ladderSeed = generateLadderSeed()
    const keyAgreement = {
      publicKeyMultibase: CANONICAL_CLIENT_KEYS[9]!.keyAgreementKeyMultibase
    }
    const { log, did } = await createLadderAnchoredAccountLog({
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: KMS_DID_WEB_KEYS,
      ladderSeed,
      keyAgreement
    })

    const vmKey = await ladderVmKeyMultibase({ ladderSeed })
    const state = await resolvedLog(log.map(e => JSON.stringify(e)).join('\n'))
    const doc = state.doc!
    const ladderVmId = `${did}#${vmKey}`
    const kmsVmId = `${did}#${KMS_AUTH_MULTIBASE}`

    // The KMS convenience key: published under the account's own controller,
    // referenced from authentication ONLY.
    expect(doc.verificationMethod).toContainEqual({
      id: kmsVmId,
      type: 'Multikey',
      controller: did,
      publicKeyMultibase: KMS_AUTH_MULTIBASE
    })
    expect(doc.authentication).toEqual([kmsVmId])
    expect(doc.assertionMethod).toEqual([ladderVmId])
    expect(doc.capabilityDelegation).toEqual([ladderVmId])
    expect(doc.capabilityInvocation ?? []).toEqual([])

    // The ladder VM and the credential's inventory are unchanged beside it:
    // no KMS key enters keyAgreement, and nothing invocable exists.
    const inventoryVmId = unlockKeyVmId({ did, keyAgreement })
    expect(doc.keyAgreement).toEqual([inventoryVmId])
    expect(doc.verificationMethod).toHaveLength(3)
    expect(ladderVmIds({ doc })).toEqual([ladderVmId])
    expect(listEnrolledWebvhClients({ log })).toEqual([])
  })
})

describe('the first self-enrollment from a ladder-anchored account', () => {
  it('publishes the client and retires rung 0, leaving the ladder VM standing', async () => {
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
      onCommitted: async () => {},
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

    // Rung 0 is spent: out of updateKeys and out of nextKeyHashes. The ladder
    // VM is NOT: its life is keyed to the credential, so it stands in the
    // document and in both its relations beside the freshly enrolled client.
    const rung0 = await ladderRung({ ladderSeed, index: 0 })
    const rung1 = await ladderRung({ ladderSeed, index: 1 })
    expect(state.meta.updateKeys).not.toContain(rung0.keyMultibase)
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(rung0.keyMultibase)
    )
    expect(doc.verificationMethod?.map(method => method.id)).toContain(
      ladderVmId
    )
    expect(doc.assertionMethod ?? []).toContain(ladderVmId)
    expect(doc.capabilityDelegation ?? []).toContain(ladderVmId)
    expect(ladderVmIds({ doc })).toEqual([ladderVmId])

    // The credential's own standing is untouched: its keyAgreement entry stands,
    // and rung 1's hash remains its standing commitment.
    expect(doc.keyAgreement).toContain(unlockKeyVmId({ did, keyAgreement }))
    expect(state.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(rung1.keyMultibase)
    )

    // The reveal-and-commit entry (entry 2) leaves the ladder VM untouched
    // too, so a delegation it signed verifies across the whole ceremony.
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
      onCommitted: async () => {},
      expectedDid: did
    })
    expect(readLogFromString(log()!)).toHaveLength(3)
  })

  it("appends the reveal entry's new hashes in decision 0007's order", async () => {
    // The append order of a reveal-and-commit entry's NEW commitments is wire
    // behavior (`decisions/0007-ladder-reveal-hash-order.md`): the new
    // client's update-key hash, then its staged-key hash, then the ladder's
    // next rung -- last among the additions, which is what a seedless walk
    // reads to tell the ladder's commitment from the client's staged one.
    // Driven on the SECOND self-enrollment, where the next rung's hash is not
    // already committed and so takes a position of its own.
    const { idStore, log } = memoryIdStore()
    const keyAgreement = {
      publicKeyMultibase: CANONICAL_CLIENT_KEYS[9]!.keyAgreementKeyMultibase
    }
    const { ladderSeed, did } = await ladderAnchoredAccount({
      keyAgreement,
      idStore
    })

    for (const index of [3, 4]) {
      const client = await mintedNewClient(index)
      await selfEnrollWebvhClient({
        store: idStore,
        ladderSeed,
        newClientKeys: client.keys,
        newClientUpdateSeeds: client.seeds,
        onCommitted: async () => {},
        expectedDid: did
      })
      if (index !== 4) {
        continue
      }
      // Genesis, then two reveal/add pairs; the second reveal is entry 4.
      const entries = readLogFromString(log()!)
      expect(entries).toHaveLength(5)
      const before = entries[2]!.parameters.nextKeyHashes ?? []
      const reveal = entries[3]!.parameters.nextKeyHashes ?? []
      // Rung 1 stood revealed by this entry, so rung 2 is the ladder's next.
      const rung2 = await ladderRung({ ladderSeed, index: 2 })
      expect(reveal.slice(0, before.length)).toEqual(before)
      expect(reveal.slice(before.length)).toEqual([
        await deriveNextKeyHash(client.keys.updateKeyMultibase),
        await deriveNextKeyHash(client.keys.stagedUpdateKeyMultibase),
        await deriveNextKeyHash(rung2.keyMultibase)
      ])
    }
  })

  it('carries the KMS authentication VM through the add entry, invocation staying client-only', async () => {
    const { idStore, log } = memoryIdStore()
    const ladderSeed = generateLadderSeed()
    const keyAgreement = {
      publicKeyMultibase: CANONICAL_CLIENT_KEYS[9]!.keyAgreementKeyMultibase
    }
    const created = await createLadderAnchoredAccountLog({
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: KMS_DID_WEB_KEYS,
      ladderSeed,
      keyAgreement
    })
    await putLogResource({ store: idStore, log: created.log })
    const { did } = created

    const client = await mintedNewClient(7)
    await selfEnrollWebvhClient({
      store: idStore,
      ladderSeed,
      newClientKeys: client.keys,
      newClientUpdateSeeds: client.seeds,
      onCommitted: async () => {},
      expectedDid: did
    })

    const state = await resolvedLog(log()!)
    const doc = state.doc!
    const signingVmId = `${did}#${client.keys.signingKeyMultibase}`
    const kmsVmId = `${did}#${KMS_AUTH_MULTIBASE}`

    // The convenience key survives the self-enrollment: authentication holds
    // it beside the freshly enrolled client's signing
    // key, and capabilityInvocation is exactly the client -- the KMS VM never
    // gains an invocable relation.
    expect(doc.authentication).toHaveLength(2)
    expect(doc.authentication).toContain(kmsVmId)
    expect(doc.authentication).toContain(signingVmId)
    expect(doc.capabilityInvocation).toEqual([signingVmId])
    expect(doc.verificationMethod?.map(method => method.id)).toContain(kmsVmId)
    // Nothing was struck: the ladder VM stands, and so does the KMS VM.
    expect(ladderVmIds({ doc })).toEqual([
      `${did}#${await ladderVmKeyMultibase({ ladderSeed })}`
    ])
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
   * refusals under test, so the credential key is a placeholder -- and a run
   * that does land both entries fails in those later stages, which is why the
   * error is returned rather than thrown.
   */
  async function runCore({
    store,
    ladderSeed,
    did,
    pinStore,
    onCommitted = async () => {},
    resume
  }: {
    store: WebvhIdStore
    ladderSeed: Uint8Array
    did: string
    pinStore?: ReturnType<typeof memoryResourceLogPinStore>
    onCommitted?: (committed: {
      builtOnHead: { scid: string; versionId: string }
      clientSeed: Uint8Array
      webvhUpdateKeys: ClientWebvhUpdateKeys
    }) => Promise<void>
    resume?: {
      clientSeed: Uint8Array
      webvhUpdateKeys: ClientWebvhUpdateKeys
      builtOnHead: { scid: string; versionId: string }
    }
  }): Promise<unknown> {
    try {
      await selfEnrollClientCore({
        pointer: { did, spaceId: SPACE_ID, host: WAS_URL },
        ladderSeed,
        credentialKeyAgreementKey: {} as never,
        logStore: store,
        onCommitted,
        ...(pinStore ? { accountLogPinStore: pinStore } : {}),
        ...(resume ? { resume } : {})
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
      onCommitted: async () => {},
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

  it('refuses a non-canonical new-client key pair before any read', async () => {
    const { idStore, ladderSeed, did } = await publishedAccount()
    const client = await mintedNewClient(4)
    // The refusal must land before the first read: past it, the reveal entry
    // would publish and the persist seam would fire for a continuation that
    // can only ever throw at the add-entry build.
    let reads = 0
    const store: WebvhIdStore = {
      ...idStore,
      async getIdResourceRaw(options: { resourceId: string }) {
        reads += 1
        return idStore.getIdResourceRaw(options)
      }
    }
    let seamFired = false

    await expect(
      selfEnrollWebvhClient({
        store,
        ladderSeed,
        newClientKeys: {
          ...client.keys,
          keyAgreementKeyMultibase:
            CANONICAL_CLIENT_KEYS[5]!.keyAgreementKeyMultibase
        },
        newClientUpdateSeeds: client.seeds,
        onCommitted: async () => {
          seamFired = true
        },
        expectedDid: did
      })
    ).rejects.toThrow(/canonical X25519 twin/)
    expect(reads).toBe(0)
    expect(seamFired).toBe(false)
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
      onCommitted: async () => {},
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

  /**
   * A store wrapper serving a STALE ETag validator (the live log text
   * unchanged) from the given 1-based `did.jsonl` read onwards -- the
   * interleave a concurrent ceremony produces, which makes the entry built on
   * that read lose its compare-and-swap.
   *
   * @param options {object}
   * @param options.idStore {WebvhIdStore}
   * @param options.fromRead {number}
   * @param [options.reads] {number}   how many reads keep serving the stale
   *   validator (default: every read from `fromRead` on)
   * @returns {WebvhIdStore}
   */
  function staleEtagFromRead({
    idStore,
    fromRead,
    reads = Number.POSITIVE_INFINITY
  }: {
    idStore: WebvhIdStore
    fromRead: number
    reads?: number
  }): WebvhIdStore {
    let count = 0
    return {
      ...idStore,
      async getIdResourceRaw(options: { resourceId: string }) {
        const served = await idStore.getIdResourceRaw(options)
        if (served === undefined) {
          return served
        }
        count += 1
        const staled = count >= fromRead && count < fromRead + reads
        return staled ? { ...served, etag: '"stale"' } : served
      }
    }
  }

  /**
   * The enrollment key set a client seed and its update seeds derive, exactly
   * as `selfEnrollClientCore`'s mint does -- what a resume replays.
   *
   * @param options {object}
   * @param options.clientSeed {Uint8Array}
   * @param options.webvhUpdateKeys {ClientWebvhUpdateKeys}
   * @returns {Promise<object>}   the client's did:key and its public halves
   */
  async function keysFromSeed({
    clientSeed,
    webvhUpdateKeys
  }: {
    clientSeed: Uint8Array
    webvhUpdateKeys: ClientWebvhUpdateKeys
  }) {
    const { keyAgent, keyAgreementKey } = await agentsFromSeed({
      seed: clientSeed
    })
    const { publicKeyMultibase } = keyAgreementKey as unknown as {
      publicKeyMultibase: string
    }
    return {
      clientDid: keyAgent.id,
      keys: {
        signingKeyMultibase: clientSigningKeyMultibase({ keyAgent }),
        keyAgreementKeyMultibase: publicKeyMultibase,
        updateKeyMultibase: await updateKeyMultibase({
          seed: webvhUpdateKeys.updateSeed
        }),
        stagedUpdateKeyMultibase: await updateKeyMultibase({
          seed: webvhUpdateKeys.stagedSeed
        })
      }
    }
  }

  /**
   * The resolved log's final state with every account-specific identifier
   * replaced by a stable label (the DID, the ladder's rungs and their hashes,
   * the ladder VM, the client's update keys and their hashes), so a torn and
   * resumed run on one account can be compared for convergence against an
   * untorn run on another -- whose SCID and ladder seed necessarily differ.
   *
   * @param options {object}
   * @param options.logText {function}
   * @param options.did {string}
   * @param options.ladderSeed {Uint8Array}
   * @param options.keys {object}   the enrolled client's public halves
   * @returns {Promise<object>}   the labeled update parameters and document
   */
  async function convergenceShape({
    logText,
    did,
    ladderSeed,
    keys
  }: {
    logText: () => string | undefined
    did: string
    ladderSeed: Uint8Array
    keys: { updateKeyMultibase: string; stagedUpdateKeyMultibase: string }
  }): Promise<object> {
    const labels = new Map<string, string>([[did, '<account>']])
    for (let index = 0; index <= 2; index++) {
      const rung = await ladderRung({ ladderSeed, index })
      labels.set(rung.keyMultibase, `<rung-${index}>`)
      labels.set(
        await deriveNextKeyHash(rung.keyMultibase),
        `<rung-${index}-hash>`
      )
    }
    labels.set(await ladderVmKeyMultibase({ ladderSeed }), '<ladder-vm>')
    labels.set(keys.updateKeyMultibase, '<client-update>')
    labels.set(
      await deriveNextKeyHash(keys.updateKeyMultibase),
      '<client-update-hash>'
    )
    labels.set(keys.stagedUpdateKeyMultibase, '<client-staged>')
    labels.set(
      await deriveNextKeyHash(keys.stagedUpdateKeyMultibase),
      '<client-staged-hash>'
    )
    const label = (text: string) => {
      let out = text
      for (const [from, to] of labels) {
        out = out.split(from).join(to)
      }
      return out
    }
    const state = await resolvedLog(logText()!)
    return {
      updateKeys: (state.meta.updateKeys ?? []).map(label).sort(),
      nextKeyHashes: (state.meta.nextKeyHashes ?? []).map(label).sort(),
      doc: JSON.parse(label(JSON.stringify(state.doc))) as object
    }
  }

  describe('the persist-before-publish seam', () => {
    it('refuses a call with no onCommitted, before any read', async () => {
      const { idStore, logText, ladderSeed, did } = await publishedAccount()
      const client = await mintedNewClient(5)
      let reads = 0
      const store: WebvhIdStore = {
        ...idStore,
        async getIdResourceRaw(options: { resourceId: string }) {
          reads += 1
          return idStore.getIdResourceRaw(options)
        }
      }

      const ceremony = await selfEnrollWebvhClient({
        store,
        ladderSeed,
        newClientKeys: client.keys,
        newClientUpdateSeeds: client.seeds,
        expectedDid: did
      } as unknown as Parameters<typeof selfEnrollWebvhClient>[0]).catch(
        (err: unknown) => err
      )
      const core = await selfEnrollClientCore({
        pointer: { did, spaceId: SPACE_ID, host: WAS_URL },
        ladderSeed,
        credentialKeyAgreementKey: {} as never,
        logStore: store
      } as unknown as Parameters<typeof selfEnrollClientCore>[0]).catch(
        (err: unknown) => err
      )

      expect(ceremony).toBeInstanceOf(TypeError)
      expect(core).toBeInstanceOf(TypeError)
      expect(reads).toBe(0)
      expect(readLogFromString(logText()!)).toHaveLength(1)
    })

    it('fires exactly once, between the two entries, on the head the add entry is built on', async () => {
      const { idStore, logText, ladderSeed, did } = await publishedAccount()
      const client = await mintedNewClient(5)
      const seen: Array<{
        entries: number
        builtOnHead: { scid: string; versionId: string }
      }> = []

      const outcome = await selfEnrollWebvhClient({
        store: idStore,
        ladderSeed,
        newClientKeys: client.keys,
        newClientUpdateSeeds: client.seeds,
        onCommitted: async ({ builtOnHead }) => {
          seen.push({
            entries: readLogFromString(logText()!).length,
            builtOnHead
          })
        },
        expectedDid: did
      })

      expect(outcome.committed).toBe(true)
      expect(seen).toHaveLength(1)
      // Genesis plus the reveal-and-commit entry stand at hook time; the add
      // entry does not.
      expect(seen[0]!.entries).toBe(2)
      const entries = readLogFromString(logText()!)
      expect(entries).toHaveLength(3)
      // The head handed over IS the head the add entry was then built on.
      expect(seen[0]!.builtOnHead).toEqual({
        scid: entries[0]!.parameters.scid,
        versionId: entries[1]!.versionId
      })
    })

    it('re-fires on a lost compare-and-swap, and the ceremony converges', async () => {
      const { idStore, logText, ladderSeed, did } = await publishedAccount()
      const client = await mintedNewClient(5)
      // The post-reveal re-read of the first attempt alone serves a stale
      // validator, so that attempt's add entry loses its CAS.
      const store = staleEtagFromRead({ idStore, fromRead: 2, reads: 1 })
      const seen: Array<{ scid: string; versionId: string }> = []

      const outcome = await selfEnrollWebvhClient({
        store,
        ladderSeed,
        newClientKeys: client.keys,
        newClientUpdateSeeds: client.seeds,
        onCommitted: async ({ builtOnHead }) => {
          seen.push(builtOnHead)
        },
        expectedDid: did
      })

      expect(outcome.committed).toBe(true)
      // Once per attempt: the seam's contract is idempotent-per-attempt.
      expect(seen).toHaveLength(2)
      expect(seen[1]).toEqual(seen[0])
      expect(readLogFromString(logText()!)).toHaveLength(3)
    })

    it('re-fires on the NEW head when the log genuinely moved between attempts', async () => {
      const { idStore, logText, ladderSeed, did } = await publishedAccount()
      const client = await mintedNewClient(5)
      const other = await mintedNewClient(6)
      let extended = false
      let puts = 0
      // A concurrent ceremony lands a real entry between this attempt's
      // post-reveal read and its add publish -- the interleave a staled
      // validator only simulates. The second conditional PUT is the add
      // entry; the first is this run's own reveal entry.
      const store: WebvhIdStore = {
        ...idStore,
        async putIdResource(options: {
          resourceId: string
          content: object | string
          contentType?: string
          ifMatch?: string
          ifNoneMatch?: boolean
        }) {
          puts += 1
          if (!extended && puts === 2) {
            extended = true
            // The concurrent run publishes its reveal-and-commit entry and
            // then dies in its own seam, leaving the rung revealed.
            await selfEnrollWebvhClient({
              store: idStore,
              ladderSeed,
              newClientKeys: other.keys,
              newClientUpdateSeeds: other.seeds,
              onCommitted: async () => {
                throw new Error('the concurrent run tore in its seam')
              },
              expectedDid: did
            }).catch(() => undefined)
          }
          return idStore.putIdResource(options)
        }
      }
      const seen: Array<{ scid: string; versionId: string }> = []

      const outcome = await selfEnrollWebvhClient({
        store,
        ladderSeed,
        newClientKeys: client.keys,
        newClientUpdateSeeds: client.seeds,
        onCommitted: async ({ builtOnHead }) => {
          seen.push(builtOnHead)
        },
        expectedDid: did
      })

      expect(outcome.committed).toBe(true)
      expect(extended).toBe(true)
      // Genesis, this run's reveal entry, the concurrent reveal entry, and
      // this run's add entry.
      const entries = readLogFromString(logText()!)
      expect(entries).toHaveLength(4)
      // The retry re-fired the seam on the head the concurrent entry left,
      // which is the head the add entry then built on.
      expect(seen).toHaveLength(2)
      expect(seen[1]).not.toEqual(seen[0])
      expect(seen[0]!.versionId).toBe(entries[1]!.versionId)
      expect(seen[1]!.versionId).toBe(entries[2]!.versionId)
      const state = await resolvedLog(logText()!)
      expect(state.meta.updateKeys).toContain(client.keys.updateKeyMultibase)
    })

    it('withholds the pivot entry when the seam throws, and converges on a later run', async () => {
      const torn = await publishedAccount()
      const client = await mintedNewClient(5)
      const persistFailed = new Error('the pending record could not be saved')

      const caught = await selfEnrollWebvhClient({
        store: torn.idStore,
        ladderSeed: torn.ladderSeed,
        newClientKeys: client.keys,
        newClientUpdateSeeds: client.seeds,
        onCommitted: async () => {
          throw persistFailed
        },
        expectedDid: torn.did
      }).catch((err: unknown) => err)

      expect(caught).toBe(persistFailed)
      // Genesis plus the reveal-and-commit entry; the pivot is withheld.
      expect(readLogFromString(torn.logText()!)).toHaveLength(2)

      const resumed = await selfEnrollWebvhClient({
        store: torn.idStore,
        ladderSeed: torn.ladderSeed,
        newClientKeys: client.keys,
        newClientUpdateSeeds: client.seeds,
        onCommitted: async () => {},
        expectedDid: torn.did
      })
      expect(resumed.committed).toBe(true)
      expect(readLogFromString(torn.logText()!)).toHaveLength(3)

      // An untorn run on a fresh account, enrolling the same client: the two
      // final states agree once the account-specific identifiers are labeled.
      const untorn = await publishedAccount()
      await selfEnrollWebvhClient({
        store: untorn.idStore,
        ladderSeed: untorn.ladderSeed,
        newClientKeys: client.keys,
        newClientUpdateSeeds: client.seeds,
        onCommitted: async () => {},
        expectedDid: untorn.did
      })
      expect(
        await convergenceShape({
          logText: torn.logText,
          did: torn.did,
          ladderSeed: torn.ladderSeed,
          keys: client.keys
        })
      ).toEqual(
        await convergenceShape({
          logText: untorn.logText,
          did: untorn.did,
          ladderSeed: untorn.ladderSeed,
          keys: client.keys
        })
      )
    })

    it('fires on the reveal-already-standing path, carrying the standing head', async () => {
      const { idStore, logText, ladderSeed, did } = await publishedAccount()
      const client = await mintedNewClient(5)
      // Torn after the reveal entry, before the add entry.
      await selfEnrollWebvhClient({
        store: idStore,
        ladderSeed,
        newClientKeys: client.keys,
        newClientUpdateSeeds: client.seeds,
        onCommitted: async () => {
          throw new Error('torn')
        },
        expectedDid: did
      }).catch(() => undefined)
      const standing = readLogFromString(logText()!)
      expect(standing).toHaveLength(2)

      const seen: Array<{ scid: string; versionId: string }> = []
      const outcome = await selfEnrollWebvhClient({
        store: idStore,
        ladderSeed,
        newClientKeys: client.keys,
        newClientUpdateSeeds: client.seeds,
        onCommitted: async ({ builtOnHead }) => {
          seen.push(builtOnHead)
        },
        expectedDid: did
      })

      expect(outcome.committed).toBe(true)
      // The re-run publishes no second reveal entry, and the seam still runs
      // -- on the head the standing reveal entry left.
      expect(seen).toEqual([
        {
          scid: standing[0]!.parameters.scid,
          versionId: standing[1]!.versionId
        }
      ])
      expect(readLogFromString(logText()!)).toHaveLength(3)
    })

    it('skips the seam on the completed branch and reports committed: false', async () => {
      const { idStore, logText, ladderSeed, did } = await publishedAccount()
      const client = await mintedNewClient(5)
      let calls = 0
      const options = {
        store: idStore,
        ladderSeed,
        newClientKeys: client.keys,
        newClientUpdateSeeds: client.seeds,
        onCommitted: async () => {
          calls += 1
        },
        expectedDid: did
      }

      const first = await selfEnrollWebvhClient(options)
      const second = await selfEnrollWebvhClient(options)

      expect(first.committed).toBe(true)
      expect(second.committed).toBe(false)
      expect(calls).toBe(1)
      expect(readLogFromString(logText()!)).toHaveLength(3)
    })

    it('hands the core caller the minted key set beside the head, and propagates committed', async () => {
      const { idStore, logText, ladderSeed, did } = await publishedAccount()
      const pointer = { did, spaceId: SPACE_ID, host: WAS_URL }
      // Everything the caller's pending record carries, exactly as it lands in
      // the seam.
      const persisted: Array<{
        builtOnHead: { scid: string; versionId: string }
        clientSeed: Uint8Array
        webvhUpdateKeys: ClientWebvhUpdateKeys
      }> = []

      const first = await selfEnrollClientCore({
        pointer,
        ladderSeed,
        credentialKeyAgreementKey: {} as never,
        logStore: idStore,
        onCommitted: async committed => {
          persisted.push(committed)
        }
      })
      expect(first.committed).toBe(true)
      expect(persisted).toHaveLength(1)
      // The seeds the seam saw are the ones the call minted and returns, so a
      // pending record written there resumes this very client.
      expect(persisted[0]!.clientSeed).toBe(first.clientSeed)
      expect(persisted[0]!.webvhUpdateKeys).toBe(first.webvhUpdateKeys)
      const entries = readLogFromString(logText()!)
      expect(persisted[0]!.builtOnHead).toEqual({
        scid: entries[0]!.parameters.scid,
        versionId: entries[1]!.versionId
      })

      // The same client's pending record, replayed: the mint is skipped, the
      // continuation is already complete, and the seam is never entered.
      const second = await selfEnrollClientCore({
        pointer,
        ladderSeed,
        credentialKeyAgreementKey: {} as never,
        logStore: idStore,
        onCommitted: async committed => {
          persisted.push(committed)
        },
        resume: {
          clientSeed: first.clientSeed,
          webvhUpdateKeys: first.webvhUpdateKeys,
          builtOnHead: persisted[0]!.builtOnHead
        }
      })
      expect(second.committed).toBe(false)
      expect(second.clientDid).toBe(first.clientDid)
      expect(persisted).toHaveLength(1)
      expect(readLogFromString(logText()!)).toHaveLength(3)
    })
  })

  describe('resuming a torn self-enrollment from its pending record', () => {
    /**
     * A pending client-key record's contents, as the core's seam hands them
     * over: the head the pivot entry was to be built on plus the key set that
     * entry publishes.
     */
    type PendingRecord = {
      builtOnHead: { scid: string; versionId: string }
      clientSeed: Uint8Array
      webvhUpdateKeys: ClientWebvhUpdateKeys
    }

    /**
     * Runs `selfEnrollClientCore` and tears it at the given point, leaving the
     * reveal-and-commit entry standing and the pending record written. The
     * record is what the seam handed over, which is the flow a wallet runs.
     * `after-reveal` dies inside the seam (the persist landed, the tab did not
     * come back), `after-hook` returns from the seam and then loses every
     * compare-and-swap the add entry attempts.
     *
     * @param options {object}
     * @param options.account {object}   a `publishedAccount()` fixture
     * @param options.at {string}   `'after-reveal'` or `'after-hook'`
     * @returns {Promise<PendingRecord>}   what the seam persisted
     */
    async function tornRun({
      account,
      at
    }: {
      account: Awaited<ReturnType<typeof publishedAccount>>
      at: 'after-reveal' | 'after-hook'
    }): Promise<PendingRecord> {
      let pending: PendingRecord | undefined
      const store =
        at === 'after-hook'
          ? staleEtagFromRead({ idStore: account.idStore, fromRead: 2 })
          : account.idStore
      await selfEnrollClientCore({
        pointer: { did: account.did, spaceId: SPACE_ID, host: WAS_URL },
        ladderSeed: account.ladderSeed,
        credentialKeyAgreementKey: {} as never,
        logStore: store,
        onCommitted: async committed => {
          pending = committed
          if (at === 'after-reveal') {
            throw new Error('torn inside the seam, after the record landed')
          }
        }
      }).catch(() => undefined)
      // Genesis plus the reveal-and-commit entry; the pivot never landed.
      expect(readLogFromString(account.logText()!)).toHaveLength(2)
      expect(pending).toBeDefined()
      return pending!
    }

    for (const at of ['after-reveal', 'after-hook'] as const) {
      it(`replays the recorded seeds and publishes only the missing entry (torn ${at})`, async () => {
        const account = await publishedAccount()
        const pending = await tornRun({ account, at })
        const { clientSeed, webvhUpdateKeys, builtOnHead } = pending
        const { clientDid, keys } = await keysFromSeed({
          clientSeed,
          webvhUpdateKeys
        })
        // The marker the seam recorded IS the standing reveal entry's head.
        const standing = readLogFromString(account.logText()!)
        expect(builtOnHead).toEqual({
          scid: standing[0]!.parameters.scid,
          versionId: standing[1]!.versionId
        })

        const resumed = await selfEnrollClientCore({
          pointer: { did: account.did, spaceId: SPACE_ID, host: WAS_URL },
          ladderSeed: account.ladderSeed,
          credentialKeyAgreementKey: {} as never,
          logStore: account.idStore,
          onCommitted: async () => {},
          resume: { clientSeed, webvhUpdateKeys, builtOnHead }
        })

        // The mint was skipped: the resumed run enrolled the recorded client,
        // and only the missing add entry was published.
        expect(resumed.committed).toBe(true)
        expect(resumed.clientDid).toBe(clientDid)
        expect(resumed.clientSeed).toBe(clientSeed)
        expect(readLogFromString(account.logText()!)).toHaveLength(3)
        const state = await resolvedLog(account.logText()!)
        expect(state.meta.updateKeys).toContain(keys.updateKeyMultibase)
        expect(state.doc!.capabilityInvocation).toContain(
          `${account.did}#${keys.signingKeyMultibase}`
        )

        // And the account lands where an untorn run enrolling the same client
        // lands.
        const untorn = await publishedAccount()
        await selfEnrollWebvhClient({
          store: untorn.idStore,
          ladderSeed: untorn.ladderSeed,
          newClientKeys: keys,
          newClientUpdateSeeds: webvhUpdateKeys,
          onCommitted: async () => {},
          expectedDid: untorn.did
        })
        expect(
          await convergenceShape({
            logText: account.logText,
            did: account.did,
            ladderSeed: account.ladderSeed,
            keys
          })
        ).toEqual(
          await convergenceShape({
            logText: untorn.logText,
            did: untorn.did,
            ladderSeed: untorn.ladderSeed,
            keys
          })
        )
      })
    }

    it('refuses a marker that cannot be compared, before any read', async () => {
      const account = await publishedAccount()
      const pending = await tornRun({ account, at: 'after-hook' })
      const logBefore = account.logText()
      let reads = 0
      let calls = 0
      const store: WebvhIdStore = {
        ...account.idStore,
        async getIdResourceRaw(options: { resourceId: string }) {
          reads += 1
          return account.idStore.getIdResourceRaw(options)
        }
      }
      const onCommitted = async () => {
        calls += 1
      }
      // Every marker a fail-open resume could carry: absent, and present but
      // empty in either member.
      const malformed = [
        undefined,
        { scid: '', versionId: pending.builtOnHead.versionId },
        { scid: pending.builtOnHead.scid, versionId: '' }
      ]

      for (const builtOnHead of malformed) {
        const core = await selfEnrollClientCore({
          pointer: { did: account.did, spaceId: SPACE_ID, host: WAS_URL },
          ladderSeed: account.ladderSeed,
          credentialKeyAgreementKey: {} as never,
          logStore: store,
          onCommitted,
          resume: {
            clientSeed: pending.clientSeed,
            webvhUpdateKeys: pending.webvhUpdateKeys,
            builtOnHead: builtOnHead as { scid: string; versionId: string }
          }
        }).catch((err: unknown) => err)
        expect(core).toBeInstanceOf(TypeError)
      }

      // The ceremony surface applies the same check to its own optional
      // marker (an absent one is a plain non-resume run, so the refusable
      // shapes are the present-but-uncomparable ones).
      for (const builtOnHead of malformed.slice(1)) {
        const ceremony = await selfEnrollWebvhClient({
          store,
          ladderSeed: account.ladderSeed,
          newClientKeys: (await keysFromSeed(pending)).keys,
          newClientUpdateSeeds: pending.webvhUpdateKeys,
          onCommitted,
          builtOnHead: builtOnHead as { scid: string; versionId: string },
          expectedDid: account.did
        }).catch((err: unknown) => err)
        expect(ceremony).toBeInstanceOf(TypeError)
      }

      expect(reads).toBe(0)
      expect(calls).toBe(0)
      expect(account.logText()).toBe(logBefore)
    })

    it('refuses a served log truncated behind the recorded head, publishing nothing', async () => {
      const account = await publishedAccount()
      const pending = await tornRun({ account, at: 'after-hook' })
      const logBefore = account.logText()
      // The reveal entry the pending record was written against is dropped
      // from what the host serves -- a valid prefix, and one the chain-head
      // pin cannot catch (the pin lags the add entry by construction).
      const { store } = truncatingLogStore({
        idStore: account.idStore,
        dropEntries: 1
      })

      let calls = 0
      const caught = await runCore({
        store,
        ladderSeed: account.ladderSeed,
        did: account.did,
        onCommitted: async () => {
          calls += 1
        },
        resume: pending
      })

      expect((caught as Error).name).toBe('BuiltOnHeadNotReachedError')
      // The refusal precedes the seam: a caller must never be asked to
      // overwrite a good pending record with a truncated head.
      expect(calls).toBe(0)
      expect((caught as BuiltOnHeadNotReachedError).builtOnHead).toEqual(
        pending.builtOnHead
      )
      expect(account.logText()).toBe(logBefore)
    })

    it('refuses a served log carrying another SCID, publishing nothing', async () => {
      const account = await publishedAccount()
      const pending = await tornRun({ account, at: 'after-hook' })
      const logBefore = account.logText()

      let calls = 0
      const caught = await runCore({
        store: account.idStore,
        ladderSeed: account.ladderSeed,
        did: account.did,
        onCommitted: async () => {
          calls += 1
        },
        resume: {
          ...pending,
          builtOnHead: {
            scid: 'QmAnotherAccountEntirely',
            versionId: pending.builtOnHead.versionId
          }
        }
      })

      expect((caught as Error).name).toBe('BuiltOnHeadNotReachedError')
      expect(calls).toBe(0)
      expect(account.logText()).toBe(logBefore)
    })
  })
})
