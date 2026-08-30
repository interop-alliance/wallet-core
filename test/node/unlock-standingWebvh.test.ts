/**
 * Unit tests for the standing-credential did:webvh lifecycle
 * (`src/unlock/standingWebvh.ts`) against an in-memory store: the merged
 * inventory edit publishing a hash-commitment `keyAgreement` entry (and
 * removing it), and the self-enrolling continuation -- reveal a ladder rung,
 * add an ordinary client, retire the rung, leave the credential's inventory
 * standing on the next rung -- including its resumability, its repeatability
 * (the second self-enrollment climbs the ladder), the fail-closed
 * attribution after a removal, and the attribution's signature rule -- a rung
 * left standing revealed by a forget claims only what it actually signed, so
 * retiring one credential never strikes another credential's or a racing
 * enrollment's commitments.
 *
 * The ladder VM rides the same pair: installed by the bind entry, struck by
 * the removal entry, and attributed from the log when the retiring ceremony
 * holds no seed -- on the signer arm where a rung signed the publishing
 * entry, on the co-introduction arm where an enrolled client signed a bind
 * that introduced this credential alone, and on neither where an entry
 * introduced two credential-class members, which leaves the VM standing.
 */
import { describe, expect, it } from 'vitest'
import {
  defaultWebvhLogVerifier,
  deriveNextKeyHash,
  readLogFromString,
  resolveDIDFromLog,
  updateDID
} from '@interop/did-method-webvh'
import { survivingClientKeyProtection } from '../../src/webvh/revokeClient.js'
import {
  attributeLadderInventory,
  attributeRetiredCredentialRungs,
  credentialLadderAnchor,
  generateLadderSeed,
  ladderRung,
  ladderVmKeyMultibase
} from '../../src/clientAnnex/ladder.js'
import {
  publishUnlockKey,
  readLogOrThrow,
  removeUnlockKey,
  unlockKeyVerificationMethod,
  unlockKeyVmId
} from '../../src/unlock/standingWebvh.js'
import {
  createLadderAnchoredAccountLog,
  forgetWebvhClient,
  selfEnrollWebvhClient
} from '../../src/clientAnnex/ladderAnchored.js'
import { ladderVmIds } from '../../src/webvh/listClients.js'
import type { StandingUnlockKeys } from '../../src/unlock/standingWebvh.js'
import { LadderAttributionError } from '../../src/clientAnnex/ladder.js'
import {
  ensureDidWebvh,
  enrollWebvhClient,
  keyAgreementCommitment,
  ladderVerificationMethod,
  mintClientWebvhUpdateKeys,
  publishUpdatedLog,
  putLogResource,
  readPublishedLog,
  relationIds,
  updateKeyMultibase,
  updateKeySigner,
  type ClientWebvhUpdateKeys,
  type WebvhIdStore
} from '../../src/webvh/didWebvh.js'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import { accountLogPinId } from '../../src/webvh/verifyLog.js'
import { DID_LOG_RESOURCE } from '../../src/space/collections.js'
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
 * commitment-published inventory (rung 0 committed, key-agreement key hashed).
 */
async function standingCredential(keyIndex = 9) {
  const ladderSeed = generateLadderSeed()
  const rung0 = await ladderRung({ ladderSeed, index: 0 })
  const keyAgreementKeyMultibase =
    CANONICAL_CLIENT_KEYS[keyIndex]!.keyAgreementKeyMultibase
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

describe('the standing unlock-key inventory', () => {
  it('publishes a hash-commitment keyAgreement entry, idempotently, and removes it', async () => {
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const { unlockKeys, rung0, ladderSeed } = await standingCredential()

    const published = await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys,
      ladderSeed
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
    const settled = await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys,
      ladderSeed
    })
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

describe('the bind read chain-head pin', () => {
  it('refuses a truncated prefix of the pinned log and publishes nothing', async () => {
    const { idStore, log, updateKeys } = await provisionedLog()
    const first = await standingCredential(9)
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: first.unlockKeys,
      ladderSeed: first.ladderSeed
    })

    // Pin the 2-entry head, the way a ceremony's earlier reads would.
    const logId = accountLogPinId({ spaceId: SPACE_ID })
    const pinStore = memoryResourceLogPinStore()
    await readPublishedLog({ idStore, pinStore, logId })
    const pinned = (await pinStore.read({ logId }))!
    expect(pinned.head).toMatch(/^2-/)

    // A valid prefix: same genesis, same SCID, resolves to the same DID --
    // and erases the first credential's bind entry.
    const truncated = log()!.trim().split('\n').slice(0, 1).join('\n') + '\n'
    await idStore.putIdResource({
      resourceId: DID_LOG_RESOURCE,
      content: truncated
    })

    const second = await standingCredential(10)
    const refusal = (await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: second.unlockKeys,
      ladderSeed: second.ladderSeed,
      pinStore,
      logId
    }).catch((err: unknown) => err)) as {
      name: string
      reason: string
      pinnedHead: string
    }

    expect(refusal.name).toBe('ResourceLogContinuityError')
    expect(refusal.reason).toBe('rollback')
    expect(refusal.pinnedHead).toBe(pinned.head)
    // No write reached the store, and the pin never regressed.
    expect(readLogFromString(log()!).length).toBe(1)
    expect(await pinStore.read({ logId })).toEqual(pinned)
  })
})

describe('the self-enrolling continuation', () => {
  it('reveals the rung, adds an ordinary client, retires the rung, and climbs on the next run', async () => {
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const credential = await standingCredential()
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed
    })
    const entriesAfterBind = readLogFromString(log()!).length

    const first = await mintedNewClient(3)
    const outcome = await selfEnrollWebvhClient({
      store: idStore,
      ladderSeed: credential.ladderSeed,
      newClientKeys: first.keys,
      newClientUpdateSeeds: first.seeds,
      onCommitted: async () => {},
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
    // credential's standing commitment; the keyAgreement entry is untouched.
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
      onCommitted: async () => {},
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
      onCommitted: async () => {},
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

  it('refuses to self-enroll once the inventory is removed', async () => {
    const { idStore, updateKeys, did } = await provisionedLog()
    const credential = await standingCredential()
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed
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
        onCommitted: async () => {},
        expectedDid: did
      })
    ).rejects.toThrow(LadderAttributionError)
  })
})

describe('retiring a credential past rung 0', () => {
  /**
   * Binds a standing credential and self-enrolls one ordinary client through
   * it, leaving the credential's standing commitment at rung 1 while its
   * recorded inventory (the registry shape) still names rung 0.
   */
  async function boundAndEnrolled() {
    const provisioned = await provisionedLog()
    const credential = await standingCredential()
    await publishUnlockKey({
      idStore: provisioned.idStore,
      updateKeys: provisioned.updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed
    })
    const enrolled = await mintedNewClient(3)
    await selfEnrollWebvhClient({
      store: provisioned.idStore,
      ladderSeed: credential.ladderSeed,
      newClientKeys: enrolled.keys,
      newClientUpdateSeeds: enrolled.seeds,
      onCommitted: async () => {},
      expectedDid: provisioned.did
    })
    return { ...provisioned, credential, enrolled }
  }

  it('strikes the live rung commitment when the recorded inventory is stale', async () => {
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

    // The removal names the STALE bind-time inventory (rung 0), the shape a
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
        onCommitted: async () => {},
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

  it('keeps a climb residue it can attribute, and releases one it cannot', async () => {
    const { log, did, credential, enrolled } = await boundAndEnrolled()
    const rung1Hash = await deriveNextKeyHash(
      (await ladderRung({ ladderSeed: credential.ladderSeed, index: 1 }))
        .keyMultibase
    )
    const credentialVmId = unlockKeyVmId({
      did,
      keyAgreement: credential.unlockKeys.keyAgreement
    })
    const inventory = async (options: {
      ladderSeed?: Uint8Array
      credentialVmId?: string
    }) =>
      attributeLadderInventory({
        log: readLogFromString(log()!),
        anchorKeyMultibase: credential.rung0.keyMultibase,
        ...options
      })

    // The completed enrollment's residue is the credential's next standing
    // commitment, and either axis attributes it: the seed derives rung 1
    // outright, and the credential's surviving verification method says the
    // ceremony it came out of was a climb.
    expect(
      (await inventory({ ladderSeed: credential.ladderSeed })).committedHashes
    ).toContain(rung1Hash)
    expect((await inventory({ credentialVmId })).committedHashes).toContain(
      rung1Hash
    )

    // With neither, the residue is indistinguishable from the commitment a
    // SPEND hands to its replacement, so it is released rather than claimed:
    // the removal falls back to the recorded key's own hash, which this
    // completed enrollment already retired.
    const unattributed = await inventory({})
    expect(unattributed.committedHashes).toEqual([])
    expect(unattributed.revealedKeys).toEqual([])

    // Under every shape the enrolled client's own hashes transfer away.
    for (const resolvedInventory of [
      await inventory({ ladderSeed: credential.ladderSeed }),
      await inventory({ credentialVmId }),
      unattributed
    ]) {
      expect(resolvedInventory.committedHashes).not.toContain(
        await deriveNextKeyHash(enrolled.keys.updateKeyMultibase)
      )
      expect(resolvedInventory.committedHashes).not.toContain(
        await deriveNextKeyHash(enrolled.keys.stagedUpdateKeyMultibase)
      )
    }
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
        onCommitted: async () => {},
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
    // inventory: the revealed rung, its own kept hash, the pending client's
    // two hashes, and rung 2's commitment. Seed-less, the credential's own
    // verification-method id is what carries the walk past the first
    // completed enrollment -- the credential came out of it standing, so the
    // residue that enrollment left really was its next rung's commitment.
    const inventory = await attributeLadderInventory({
      log: readLogFromString(log()!),
      anchorKeyMultibase: credential.rung0.keyMultibase,
      credentialVmId: unlockKeyVmId({
        did,
        keyAgreement: credential.unlockKeys.keyAgreement
      })
    })
    expect(inventory.revealedKeys).toEqual([rung1.keyMultibase])
    expect(new Set(inventory.committedHashes)).toEqual(
      new Set([
        await deriveNextKeyHash(rung1.keyMultibase),
        await deriveNextKeyHash(pendingClient.keys.updateKeyMultibase),
        await deriveNextKeyHash(pendingClient.keys.stagedUpdateKeyMultibase),
        await deriveNextKeyHash(rung2.keyMultibase)
      ])
    )

    // Retirement with the stale inventory and the ladder seed in hand.
    await removeUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed
    })
    state = await resolved(log)
    expect(state.meta.updateKeys).not.toContain(rung1.keyMultibase)
    for (const hash of inventory.committedHashes) {
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
      unlockKeys: another.unlockKeys,
      ladderSeed: another.ladderSeed
    })
    state = await resolved(log)
    expect(state.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(another.rung0.keyMultibase)
    )
  })
})

/**
 * The documented residue state: an account with the founding client, a bound
 * credential, and a second client that self-enrolled through it and then
 * forgot itself through its bridge -- so the credential's rung 1 stands
 * REVEALED in `updateKeys` indefinitely, with no entry able to remove its own
 * signer.
 */
async function forgottenThroughCredential() {
  const provisioned = await provisionedLog()
  const credential = await standingCredential(9)
  await publishUnlockKey({
    idStore: provisioned.idStore,
    updateKeys: provisioned.updateKeys,
    unlockKeys: credential.unlockKeys,
    ladderSeed: credential.ladderSeed
  })
  const remembered = await mintedNewClient(3)
  await selfEnrollWebvhClient({
    store: provisioned.idStore,
    ladderSeed: credential.ladderSeed,
    newClientKeys: remembered.keys,
    newClientUpdateSeeds: remembered.seeds,
    onCommitted: async () => {},
    expectedDid: provisioned.did
  })
  await forgetWebvhClient({
    store: provisioned.idStore,
    ladderSeed: credential.ladderSeed,
    forgottenClient: {
      signingKeyMultibase: remembered.keys.signingKeyMultibase,
      updateKeyMultibase: remembered.keys.updateKeyMultibase
    },
    expectedDid: provisioned.did
  })
  const rung1 = await ladderRung({
    ladderSeed: credential.ladderSeed,
    index: 1
  })
  const state = await resolved(provisioned.log)
  // The premise of every test below: the rung really is standing revealed.
  expect(state.meta.updateKeys).toContain(rung1.keyMultibase)
  return { ...provisioned, credential, rung1 }
}

describe('the attribution of a rung left standing revealed', () => {
  it('does not annex another credential inventory published while it stands', async () => {
    const { idStore, log, updateKeys, did, credential, rung1 } =
      await forgottenThroughCredential()

    // A second credential binds afterwards -- an entry the founding client
    // signs, committing that credential's rung 0 while the first
    // credential's rung 1 sits revealed.
    const second = await standingCredential(10)
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: second.unlockKeys,
      ladderSeed: second.ladderSeed
    })
    const secondRungHash = await deriveNextKeyHash(second.rung0.keyMultibase)

    // The first credential's inventory is its revealed rung and its own hash
    // -- not a hash some other key committed.
    for (const ladderSeed of [credential.ladderSeed, undefined]) {
      const inventory = await attributeLadderInventory({
        log: readLogFromString(log()!),
        anchorKeyMultibase: credential.rung0.keyMultibase,
        credentialVmId: unlockKeyVmId({
          did,
          keyAgreement: credential.unlockKeys.keyAgreement
        }),
        ...(ladderSeed ? { ladderSeed } : {})
      })
      expect(inventory.revealedKeys).toEqual([rung1.keyMultibase])
      expect(inventory.committedHashes).not.toContain(secondRungHash)
      expect(new Set(inventory.committedHashes)).toEqual(
        new Set([await deriveNextKeyHash(rung1.keyMultibase)])
      )
    }

    // Retiring the first credential leaves the second one's inventory whole.
    await removeUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed
    })
    const state = await resolved(log)
    expect(state.meta.updateKeys).not.toContain(rung1.keyMultibase)
    expect(state.meta.nextKeyHashes).toContain(secondRungHash)
    expect(state.doc?.keyAgreement).toContain(
      unlockKeyVmId({ did, keyAgreement: second.unlockKeys.keyAgreement })
    )

    // The whole point: the surviving credential can still self-enroll a
    // fresh browser. A struck rung-0 commitment would fail closed here, and
    // nothing would ever heal it.
    const fresh = await mintedNewClient(5)
    await selfEnrollWebvhClient({
      store: idStore,
      ladderSeed: second.ladderSeed,
      newClientKeys: fresh.keys,
      newClientUpdateSeeds: fresh.seeds,
      onCommitted: async () => {},
      expectedDid: did
    })
    expect((await resolved(log)).meta.updateKeys).toContain(
      fresh.keys.updateKeyMultibase
    )
  })

  it('does not annex a racing enrollment, nor mis-read its key as a rung', async () => {
    const { idStore, log, updateKeys, did, credential, rung1 } =
      await forgottenThroughCredential()

    // An ordinary enrollment by the founding client: the sparse commit entry
    // (both of the enrollee's hashes) and then the add entry authorizing its
    // update key -- neither signed by the ladder.
    const enrollee = await mintedNewClient(6)
    await enrollWebvhClient({
      idStore,
      updateKeys,
      newClient: enrollee.keys
    })
    const enrolleeUpdateHash = await deriveNextKeyHash(
      enrollee.keys.updateKeyMultibase
    )
    const enrolleeStagedHash = await deriveNextKeyHash(
      enrollee.keys.stagedUpdateKeyMultibase
    )

    for (const ladderSeed of [credential.ladderSeed, undefined]) {
      // Absorbing the commit entry's hashes would then read the add entry's
      // authorized key as a second ladder reveal and wedge the attribution
      // in a permanent LadderAttributionError -- the credential could never
      // be retired again.
      const inventory = await attributeLadderInventory({
        log: readLogFromString(log()!),
        anchorKeyMultibase: credential.rung0.keyMultibase,
        credentialVmId: unlockKeyVmId({
          did,
          keyAgreement: credential.unlockKeys.keyAgreement
        }),
        ...(ladderSeed ? { ladderSeed } : {})
      })
      expect(inventory.revealedKeys).toEqual([rung1.keyMultibase])
      expect(inventory.committedHashes).not.toContain(enrolleeUpdateHash)
      expect(inventory.committedHashes).not.toContain(enrolleeStagedHash)
    }

    // Retirement strikes the rung and nothing of the enrolled client.
    await removeUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed
    })
    const state = await resolved(log)
    expect(state.meta.updateKeys).not.toContain(rung1.keyMultibase)
    expect(state.meta.updateKeys).toContain(enrollee.keys.updateKeyMultibase)
    expect(state.meta.nextKeyHashes).toContain(enrolleeStagedHash)
    expect(state.doc?.capabilityInvocation).toContain(
      `${did}#${enrollee.keys.signingKeyMultibase}`
    )
  })
  it("does not read a bind's trailing neighbor as the rung 1 of a forget-revealed ladder", async () => {
    // The handover condition -- the revealing entry retires a signer of the
    // entry that first committed the rung's hash -- is satisfied on an
    // ordinary account: a forget entry reveals the rung while retiring the
    // client that signed the credential's bind. What keeps it inert there is
    // the last-position rule. This hand-built bind commits a SECOND hash
    // right after the rung's (a shape no emitter writes) and then forgets
    // the binding client through the credential; the neighbor must stay out.
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const credential = await standingCredential(9)
    const victimHash = await deriveNextKeyHash(
      (await mintedNewClient(10)).keys.updateKeyMultibase
    )
    const published = await readLogOrThrow({ store: idStore })
    const bind = await updateDID({
      log: published.log,
      signer: await updateKeySigner({ seed: updateKeys.updateSeed }),
      alsoKnownAsWeb: true,
      updateKeys: published.updateKeys,
      nextKeyHashes: [
        ...published.nextKeyHashes,
        await deriveNextKeyHash(credential.rung0.keyMultibase),
        victimHash
      ],
      verificationMethods: [
        ...((published.doc.verificationMethod ?? []) as Array<{
          id?: string
        }>),
        unlockKeyVerificationMethod({
          did,
          keyAgreement: credential.unlockKeys.keyAgreement
        })
      ] as never,
      authentication: relationIds(published.doc.authentication),
      assertionMethod: relationIds(published.doc.assertionMethod),
      keyAgreement: [
        ...relationIds(published.doc.keyAgreement),
        unlockKeyVmId({ did, keyAgreement: credential.unlockKeys.keyAgreement })
      ],
      capabilityInvocation: relationIds(published.doc.capabilityInvocation),
      capabilityDelegation: relationIds(published.doc.capabilityDelegation)
    })
    await publishUpdatedLog({ idStore, updated: bind, ifMatch: published.etag })

    // A second enrolled client, so forgetting the binding one is the plain
    // removal entry rather than the last-client transition.
    const other = await mintedNewClient(4)
    await enrollWebvhClient({ idStore, updateKeys, newClient: other.keys })
    await forgetWebvhClient({
      store: idStore,
      ladderSeed: credential.ladderSeed,
      forgottenClient: {
        signingKeyMultibase: CANONICAL_CLIENT_KEYS[0]!.signingKeyMultibase,
        updateKeyMultibase: await updateKeyMultibase({
          seed: updateKeys.updateSeed
        })
      },
      expectedDid: did
    })
    const state = await resolved(log)
    expect(state.meta.updateKeys).toContain(credential.rung0.keyMultibase)
    expect(state.meta.updateKeys).not.toContain(
      await updateKeyMultibase({ seed: updateKeys.updateSeed })
    )
    expect(state.meta.nextKeyHashes).toContain(victimHash)

    for (const ladderSeed of [credential.ladderSeed, undefined]) {
      const inventory = await attributeLadderInventory({
        log: readLogFromString(log()!),
        anchorKeyMultibase: credential.rung0.keyMultibase,
        credentialVmId: unlockKeyVmId({
          did,
          keyAgreement: credential.unlockKeys.keyAgreement
        }),
        ...(ladderSeed ? { ladderSeed } : {})
      })
      expect(inventory.revealedKeys).toEqual([credential.rung0.keyMultibase])
      expect(inventory.committedHashes).not.toContain(victimHash)
    }
  })
})

describe("a standing credential's ladder VM", () => {
  /**
   * The ordinary bind from an enrolled client's session: the credential's
   * key-agreement entry, its rung-0 commitment and its ladder VM, all in the
   * one entry `publishUnlockKey` writes.
   */
  async function boundCredential() {
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const credential = await standingCredential()
    const bind = await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed
    })
    const ladderVmId = `${did}#${await ladderVmKeyMultibase({
      ladderSeed: credential.ladderSeed
    })}`
    return { idStore, log, updateKeys, did, credential, ladderVmId, bind }
  }

  it('is installed by the bind entry, and a re-run with the same seed publishes nothing', async () => {
    const { idStore, log, updateKeys, credential, ladderVmId, bind } =
      await boundCredential()
    const state = await resolved(log)
    for (const doc of [bind.doc, state.doc!]) {
      expect(doc.verificationMethod?.map(method => method.id)).toContain(
        ladderVmId
      )
      // The relation asymmetry is the recognition convention, so the VM
      // stands under these two relations and no others.
      expect(doc.assertionMethod ?? []).toContain(ladderVmId)
      expect(doc.capabilityDelegation ?? []).toContain(ladderVmId)
      expect(doc.capabilityInvocation ?? []).not.toContain(ladderVmId)
      expect(doc.authentication ?? []).not.toContain(ladderVmId)
      expect(ladderVmIds({ doc })).toEqual([ladderVmId])
    }

    // The seed is the caller's, so a torn bind's re-run tests idempotence
    // against the SAME VM and publishes nothing.
    const entries = readLogFromString(log()!).length
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed
    })
    expect(readLogFromString(log()!).length).toBe(entries)
  })

  it('leaves with the credential, and a re-run of the removal is settled', async () => {
    const { idStore, log, updateKeys, did, credential, ladderVmId } =
      await boundCredential()
    const vmId = unlockKeyVmId({
      did,
      keyAgreement: credential.unlockKeys.keyAgreement
    })

    const removed = await removeUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed,
      expectedDid: did
    })
    const entries = readLogFromString(log()!).length
    const state = await resolved(log)
    for (const doc of [removed.doc, state.doc!]) {
      expect(doc.verificationMethod?.map(method => method.id)).not.toContain(
        ladderVmId
      )
      expect(doc.assertionMethod ?? []).not.toContain(ladderVmId)
      expect(doc.capabilityDelegation ?? []).not.toContain(ladderVmId)
      expect(ladderVmIds({ doc })).toEqual([])
      // The credential's own inventory goes in the same entry.
      expect(doc.keyAgreement ?? []).not.toContain(vmId)
    }
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(credential.rung0.keyMultibase)
    )
    expect(state.doc?.capabilityInvocation).toContain(
      `${did}#${CANONICAL_CLIENT_KEYS[0]!.signingKeyMultibase}`
    )

    // Settled: a re-run appends nothing.
    await removeUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed,
      expectedDid: did
    })
    expect(readLogFromString(log()!).length).toBe(entries)
  })

  /**
   * Two standing credentials, each with its VM, published by entries with
   * different signers: the FIRST credential's at the ladder-anchored genesis,
   * which its own rung 0 signs, the SECOND's by a bind entry the enrolled
   * client signs. The log therefore attributes the first VM and can attribute
   * the second to no ladder at all.
   */
  async function twoStandingCredentials() {
    const { idStore, log } = memoryIdStore()
    const ladderSeed = generateLadderSeed()
    const keyAgreement = {
      publicKeyMultibase: CANONICAL_CLIENT_KEYS[9]!.keyAgreementKeyMultibase
    }
    const created = await createLadderAnchoredAccountLog({
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
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
    const second = await standingCredential(10)
    await publishUnlockKey({
      idStore,
      updateKeys: client.seeds,
      unlockKeys: second.unlockKeys,
      ladderSeed: second.ladderSeed,
      expectedDid: did
    })
    const rung0 = await ladderRung({ ladderSeed, index: 0 })
    const firstVmId = `${did}#${await ladderVmKeyMultibase({ ladderSeed })}`
    const secondVmId = `${did}#${await ladderVmKeyMultibase({
      ladderSeed: second.ladderSeed
    })}`
    const state = await resolved(log)
    expect(ladderVmIds({ doc: state.doc! }).sort()).toEqual(
      [firstVmId, secondVmId].sort()
    )
    return {
      idStore,
      log,
      did,
      client,
      ladderSeed,
      keyAgreement,
      rung0,
      firstVmId,
      second,
      secondVmId
    }
  }

  it("is struck seedlessly by log attribution, leaving another credential's standing", async () => {
    const { idStore, did, client, keyAgreement, rung0, secondVmId } =
      await twoStandingCredentials()

    // No seed in hand: the retiring credential's VM is the one the log
    // attributes to its ladder, and the other credential's is untouched.
    const removed = await removeUnlockKey({
      idStore,
      updateKeys: client.seeds,
      unlockKeys: { keyAgreement, updateKeyMultibase: rung0.keyMultibase },
      expectedDid: did
    })
    expect(ladderVmIds({ doc: removed.doc })).toEqual([secondVmId])
    expect(removed.doc.keyAgreement ?? []).not.toContain(
      unlockKeyVmId({ did, keyAgreement })
    )
  })

  it("is struck seedlessly from a bind entry an enrolled client signed, leaving the other credential's standing", async () => {
    const { idStore, did, client, second, firstVmId } =
      await twoStandingCredentials()

    // The second credential's VM was published by a bind entry the ENROLLED
    // client signed, so no rung stands behind it and the signer arm claims
    // nothing. The co-introduction arm reaches it: that same entry
    // introduced exactly one credential-class key-agreement member -- this
    // credential's -- and exactly one ladder VM.
    const seedless = await removeUnlockKey({
      idStore,
      updateKeys: client.seeds,
      unlockKeys: second.unlockKeys,
      expectedDid: did
    })
    expect(ladderVmIds({ doc: seedless.doc })).toEqual([firstVmId])
    expect(seedless.doc.keyAgreement ?? []).not.toContain(
      unlockKeyVmId({ did, keyAgreement: second.unlockKeys.keyAgreement })
    )
  })

  it('stands when an entry introduced two credential members, reports itself unclaimed, and comes out under its seed', async () => {
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const retiring = await standingCredential(9)
    const other = await standingCredential(10)
    const retiringVmId = `${did}#${await ladderVmKeyMultibase({
      ladderSeed: retiring.ladderSeed
    })}`

    // One entry introducing TWO credential-class key-agreement members
    // beside a single ladder VM -- the transient recovery's shape. The
    // co-introduction arm's uniqueness guard refuses it, and the entry's
    // signer is the enrolled client, so no arm claims the VM.
    const published = await readPublishedLog({ idStore })
    const updated = await updateDID({
      log: published!.log,
      signer: await updateKeySigner({ seed: updateKeys.updateSeed }),
      alsoKnownAsWeb: true,
      updateKeys: published!.updateKeys,
      nextKeyHashes: [
        ...published!.nextKeyHashes,
        await deriveNextKeyHash(retiring.rung0.keyMultibase)
      ],
      verificationMethods: [
        ...(published!.doc.verificationMethod ?? []),
        unlockKeyVerificationMethod({
          did,
          keyAgreement: retiring.unlockKeys.keyAgreement
        }),
        unlockKeyVerificationMethod({
          did,
          keyAgreement: other.unlockKeys.keyAgreement
        }),
        ladderVerificationMethod({
          controller: did,
          publicKeyMultibase: await ladderVmKeyMultibase({
            ladderSeed: retiring.ladderSeed
          })
        })
      ],
      authentication: relationIds(published!.doc.authentication),
      assertionMethod: [
        ...relationIds(published!.doc.assertionMethod),
        retiringVmId
      ],
      keyAgreement: [
        ...relationIds(published!.doc.keyAgreement),
        unlockKeyVmId({ did, keyAgreement: retiring.unlockKeys.keyAgreement }),
        unlockKeyVmId({ did, keyAgreement: other.unlockKeys.keyAgreement })
      ],
      capabilityInvocation: relationIds(published!.doc.capabilityInvocation),
      capabilityDelegation: [
        ...relationIds(published!.doc.capabilityDelegation),
        retiringVmId
      ]
    })
    await publishUpdatedLog({ idStore, updated, ifMatch: published!.etag })
    expect(ladderVmIds({ doc: updated.doc })).toEqual([retiringVmId])

    const seedless = await removeUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: retiring.unlockKeys,
      expectedDid: did
    })
    expect(ladderVmIds({ doc: seedless.doc })).toEqual([retiringVmId])
    // The seedless strike claimed nothing, and says so: the VM it could not
    // attribute is reported as standing unclaimed rather than read as a
    // clean retirement.
    expect(seedless.ladderVm).toEqual({
      struck: [],
      unclaimed: [retiringVmId]
    })

    // The seed settles ownership where the log cannot.
    const entries = readLogFromString(log()!).length
    const struck = await removeUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: retiring.unlockKeys,
      ladderSeed: retiring.ladderSeed,
      expectedDid: did
    })
    expect(readLogFromString(log()!).length).toBe(entries + 1)
    expect(ladderVmIds({ doc: struck.doc })).toEqual([])
    expect(struck.ladderVm).toEqual({ struck: [retiringVmId], unclaimed: [] })
  })

  it('refuses a strike whose attribution drifts from the caller expectation', async () => {
    const { idStore, log, updateKeys, credential, ladderVmId } =
      await boundCredential()
    const entries = readLogFromString(log()!).length

    // What a caller resolved one read earlier, and what this edit's own
    // attribution now claims, disagree -- a concurrent ceremony, or a host
    // serving two log versions. The edit refuses before writing, so the
    // strike can never diverge from what the caller's dependent-record pass
    // acted on.
    const refusal = await removeUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed,
      expectedLadderVmIds: [`${ladderVmId}-from-another-read`]
    }).catch((err: unknown) => err)

    expect((refusal as Error).name).toBe('LadderInventoryDriftError')
    expect(readLogFromString(log()!).length).toBe(entries)

    // The list the edit's own attribution resolves passes, and the strike
    // lands.
    const struck = await removeUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed,
      expectedLadderVmIds: [ladderVmId]
    })
    expect(readLogFromString(log()!).length).toBe(entries + 1)
    expect(struck.ladderVm.struck).toEqual([ladderVmId])
  })

  it('refuses when the seed and the log attribute different VMs', async () => {
    const { idStore, log, did, client, keyAgreement, rung0, second } =
      await twoStandingCredentials()
    const entries = readLogFromString(log()!).length

    // The recorded anchor names the first credential's ladder while the seed
    // in hand derives the second's. Striking either would take out a
    // surviving credential's key, so the removal refuses and writes nothing.
    const refusal = await removeUnlockKey({
      idStore,
      updateKeys: client.seeds,
      unlockKeys: { keyAgreement, updateKeyMultibase: rung0.keyMultibase },
      ladderSeed: second.ladderSeed,
      expectedDid: did
    }).catch((err: unknown) => err)

    expect(refusal).toBeInstanceOf(LadderAttributionError)
    expect(readLogFromString(log()!).length).toBe(entries)
  })

  it('strikes only the ladder inventory on a KMS-carrying document: the KMS VM survives', async () => {
    // The KMS-carrying variant of the same strike: a ladder-anchored genesis
    // carrying the KMS authentication VM beside the credential's own
    // ladder VM, and a self-enrolled client, which leaves that VM standing.
    const { idStore, log } = memoryIdStore()
    const ladderSeed = generateLadderSeed()
    const keyAgreement = {
      publicKeyMultibase: CANONICAL_CLIENT_KEYS[9]!.keyAgreementKeyMultibase
    }
    const kmsAuthMultibase = 'z6MkAuthConvenience'
    const created = await createLadderAnchoredAccountLog({
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: {
        authentication: {
          vmId: `did:web:example#${kmsAuthMultibase}`,
          kmsKeyId: 'kms/keys/auth'
        },
        keyAgreement: {
          vmId: 'did:web:example#z6LSAgree',
          kmsKeyId: 'kms/keys/agree'
        }
      },
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

    const rung0 = await ladderRung({ ladderSeed, index: 0 })
    const removed = await removeUnlockKey({
      idStore,
      updateKeys: client.seeds,
      unlockKeys: { keyAgreement, updateKeyMultibase: rung0.keyMultibase },
      ladderSeed,
      expectedDid: did
    })

    const kmsVmId = `${did}#${kmsAuthMultibase}`
    const state = await resolved(log)
    for (const doc of [removed.doc, state.doc!]) {
      // The KMS VM is nothing the ladder accounts for: it survives the
      // strike, still under authentication and nowhere invocable.
      expect(doc.verificationMethod?.map(method => method.id)).toContain(
        kmsVmId
      )
      expect(doc.authentication).toContain(kmsVmId)
      expect(doc.capabilityInvocation).toEqual([
        `${did}#${client.keys.signingKeyMultibase}`
      ])
      // The credential's whole inventory is out: its keyAgreement entry and
      // its ladder VM.
      expect(ladderVmIds({ doc })).toEqual([])
      expect(doc.keyAgreement ?? []).not.toContain(
        unlockKeyVmId({ did, keyAgreement })
      )
    }
  })

  it('claims a VM reinstalled by a re-run that minted a fresh ladder seed', async () => {
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const first = await standingCredential(9)
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: first.unlockKeys,
      ladderSeed: first.ladderSeed
    })
    // The establish re-run: the same credential, a fresh ladder seed. Its
    // member already stands, so the reinstall entry introduces none and no
    // rung of the fresh ladder has signed anything yet. Only the hash it
    // commits -- the fresh rung 0's, which IS the caller's anchor -- says
    // whose VM this is.
    const second = await standingCredential(9)
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: second.unlockKeys,
      ladderSeed: second.ladderSeed
    })
    const firstVmId = `${did}#${await ladderVmKeyMultibase({
      ladderSeed: first.ladderSeed
    })}`
    const secondVmId = `${did}#${await ladderVmKeyMultibase({
      ladderSeed: second.ladderSeed
    })}`

    const inventory = await attributeLadderInventory({
      log: readLogFromString(log()!),
      anchorKeyMultibase: second.rung0.keyMultibase,
      credentialVmId: unlockKeyVmId({
        did,
        keyAgreement: second.unlockKeys.keyAgreement
      })
    })
    expect(new Set(inventory.ladderVmIds)).toEqual(
      new Set([firstVmId, secondVmId])
    )

    // The seedless retirement then takes both out, with nothing left
    // unclaimed on the credential's own document inventory.
    const removed = await removeUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: second.unlockKeys
    })
    expect(removed.ladderVm.unclaimed).toEqual([])
    expect(new Set(removed.ladderVm.struck)).toEqual(
      new Set([firstVmId, secondVmId])
    )
    const state = await resolved(log)
    expect(ladderVmIds({ doc: state.doc! })).toEqual([])
  })

  it('does not claim a reinstalled VM on the commitment arm with no credentialVmId', async () => {
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const first = await standingCredential(9)
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: first.unlockKeys,
      ladderSeed: first.ladderSeed
    })
    // The same reinstall shape the arm exists for: a fresh ladder seed for a
    // credential whose member already stands, so the only evidence is the
    // hash the entry commits.
    const second = await standingCredential(9)
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: second.unlockKeys,
      ladderSeed: second.ladderSeed
    })
    const secondVmId = `${did}#${await ladderVmKeyMultibase({
      ladderSeed: second.ladderSeed
    })}`
    const resolvedLog = readLogFromString(log()!)

    // With the id in hand the arm fires and the VM is claimed.
    const claimed = await attributeLadderInventory({
      log: resolvedLog,
      anchorKeyMultibase: second.rung0.keyMultibase,
      credentialVmId: unlockKeyVmId({
        did,
        keyAgreement: second.unlockKeys.keyAgreement
      })
    })
    expect(claimed.ladderVmIds).toContain(secondVmId)

    // Without it the foreign-member guard has nothing to compare against, so
    // the arm must not fire: no VM is claimed.
    const unclaimed = await attributeLadderInventory({
      log: resolvedLog,
      anchorKeyMultibase: second.rung0.keyMultibase
    })
    expect(unclaimed.ladderVmIds).toEqual([])
  })

  it("leaves a sibling credential's VM standing when an entry commits our hash beside its member", async () => {
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const ours = await standingCredential(9)
    const sibling = await standingCredential(10)
    const siblingVmId = `${did}#${await ladderVmKeyMultibase({
      ladderSeed: sibling.ladderSeed
    })}`

    // One entry batching our rung-0 commitment with the SIBLING's member and
    // the sibling's ladder VM. The commitment arm sees a hash we know a
    // priori and one new ladder VM, and the foreign-member guard is what
    // stops it claiming a key that is not ours.
    const published = await readPublishedLog({ idStore })
    const updated = await updateDID({
      log: published!.log,
      signer: await updateKeySigner({ seed: updateKeys.updateSeed }),
      alsoKnownAsWeb: true,
      updateKeys: published!.updateKeys,
      nextKeyHashes: [
        ...published!.nextKeyHashes,
        await deriveNextKeyHash(ours.rung0.keyMultibase)
      ],
      verificationMethods: [
        ...(published!.doc.verificationMethod ?? []),
        unlockKeyVerificationMethod({
          did,
          keyAgreement: sibling.unlockKeys.keyAgreement
        }),
        ladderVerificationMethod({
          controller: did,
          publicKeyMultibase: await ladderVmKeyMultibase({
            ladderSeed: sibling.ladderSeed
          })
        })
      ],
      authentication: relationIds(published!.doc.authentication),
      assertionMethod: [
        ...relationIds(published!.doc.assertionMethod),
        siblingVmId
      ],
      keyAgreement: [
        ...relationIds(published!.doc.keyAgreement),
        unlockKeyVmId({ did, keyAgreement: sibling.unlockKeys.keyAgreement })
      ],
      capabilityInvocation: relationIds(published!.doc.capabilityInvocation),
      capabilityDelegation: [
        ...relationIds(published!.doc.capabilityDelegation),
        siblingVmId
      ]
    })
    await publishUpdatedLog({ idStore, updated, ifMatch: published!.etag })

    const inventory = await attributeLadderInventory({
      log: readLogFromString(log()!),
      anchorKeyMultibase: ours.rung0.keyMultibase,
      credentialVmId: unlockKeyVmId({
        did,
        keyAgreement: ours.unlockKeys.keyAgreement
      })
    })
    expect(inventory.ladderVmIds).toEqual([])
  })

  it('stops the backward walk at an enrolled-client bind entry', async () => {
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const credential = await standingCredential(9)
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed
    })
    const client = await mintedNewClient(7)
    await selfEnrollWebvhClient({
      store: idStore,
      ladderSeed: credential.ladderSeed,
      newClientKeys: client.keys,
      newClientUpdateSeeds: client.seeds,
      onCommitted: async () => {},
      expectedDid: did
    })
    const rung1 = await ladderRung({
      ladderSeed: credential.ladderSeed,
      index: 1
    })
    const ladderVmId = `${did}#${await ladderVmKeyMultibase({
      ladderSeed: credential.ladderSeed
    })}`

    // Anchored on the rung the self-enrollment climbed to. The walk recovers
    // rung 0 and then stops at the bind entry, which authorized no update key
    // of its own -- so the binding client's keys never enter the ladder.
    const inventory = await attributeLadderInventory({
      log: readLogFromString(log()!),
      anchorKeyMultibase: rung1.keyMultibase,
      credentialVmId: unlockKeyVmId({
        did,
        keyAgreement: credential.unlockKeys.keyAgreement
      })
    })
    expect(inventory.ladderVmIds).toEqual([ladderVmId])
    const bindingClientKeys = [
      await updateKeyMultibase({ seed: updateKeys.updateSeed }),
      await updateKeyMultibase({ seed: updateKeys.stagedSeed })
    ]
    for (const key of bindingClientKeys) {
      expect(inventory.revealedKeys).not.toContain(key)
      expect(inventory.committedHashes).not.toContain(
        await deriveNextKeyHash(key)
      )
    }
    for (const key of [
      client.keys.updateKeyMultibase,
      client.keys.stagedUpdateKeyMultibase
    ]) {
      expect(inventory.committedHashes).not.toContain(
        await deriveNextKeyHash(key)
      )
    }
  })

  it('claims nothing from a plain genesis whose document carries no credential member', async () => {
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const credential = await standingCredential(9)
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed
    })

    // The bind's own rung-0 hash is the whole inventory: the founding
    // client's genesis predates the credential's member, so nothing there is
    // reachable backwards.
    const inventory = await attributeLadderInventory({
      log: readLogFromString(log()!),
      anchorKeyMultibase: credential.rung0.keyMultibase,
      credentialVmId: unlockKeyVmId({
        did,
        keyAgreement: credential.unlockKeys.keyAgreement
      })
    })
    expect(inventory.committedHashes).toEqual([
      await deriveNextKeyHash(credential.rung0.keyMultibase)
    ])
    expect(inventory.revealedKeys).toEqual([])
    const state = await resolved(log)
    expect(state.meta.nextKeyHashes.length).toBeGreaterThan(1)
  })

  it('walks back two rungs after two self-enrollments', async () => {
    const { idStore, log } = memoryIdStore()
    const ladderSeed = generateLadderSeed()
    const keyAgreement = {
      publicKeyMultibase: CANONICAL_CLIENT_KEYS[9]!.keyAgreementKeyMultibase
    }
    const created = await createLadderAnchoredAccountLog({
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      ladderSeed,
      keyAgreement
    })
    await putLogResource({ store: idStore, log: created.log })
    const { did } = created
    for (const index of [7, 8]) {
      const client = await mintedNewClient(index)
      await selfEnrollWebvhClient({
        store: idStore,
        ladderSeed,
        newClientKeys: client.keys,
        newClientUpdateSeeds: client.seeds,
        onCommitted: async () => {},
        expectedDid: did
      })
    }
    const rung2 = await ladderRung({ ladderSeed, index: 2 })
    const parsed = readLogFromString(log()!)
    const credentialVmId = unlockKeyVmId({ did, keyAgreement })

    // Two spent rungs behind the anchor, both recovered by the last-position
    // rule read backwards, so the seedless walk matches the seeded one.
    const seedless = await attributeLadderInventory({
      log: parsed,
      anchorKeyMultibase: rung2.keyMultibase,
      credentialVmId
    })
    const seeded = await attributeLadderInventory({
      log: parsed,
      anchorKeyMultibase: rung2.keyMultibase,
      credentialVmId,
      ladderSeed
    })
    expect(seedless).toEqual(seeded)
    expect(seedless.ladderVmIds).toEqual([
      `${did}#${await ladderVmKeyMultibase({ ladderSeed })}`
    ])
  })
})

describe('anchoring a ladder walk from the log alone', () => {
  it("names rung 0's hash from a bind entry an enrolled client signed", async () => {
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const credential = await standingCredential(9)
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed
    })
    const credentialVmId = unlockKeyVmId({
      did,
      keyAgreement: credential.unlockKeys.keyAgreement
    })

    // The bind entry authorizes no key of its own and commits exactly one
    // hash, so that hash is rung 0's.
    const anchor = await credentialLadderAnchor({
      log: readLogFromString(log()!),
      credentialVmId
    })
    expect(anchor).toEqual({
      anchorHash: await deriveNextKeyHash(credential.rung0.keyMultibase)
    })
  })

  it('names rung 0 outright from a self-signed ladder-anchored genesis', async () => {
    const ladderSeed = generateLadderSeed()
    const rung0 = await ladderRung({ ladderSeed, index: 0 })
    const keyAgreementKeyMultibase =
      CANONICAL_CLIENT_KEYS[9]!.keyAgreementKeyMultibase
    const keyAgreement = {
      commitment: await keyAgreementCommitment({ keyAgreementKeyMultibase })
    }
    const { idStore, log } = memoryIdStore()
    const genesis = await createLadderAnchoredAccountLog({
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      ladderSeed,
      keyAgreement
    })
    await putLogResource({ store: idStore, log: genesis.log })

    // The genesis entry reveals rung 0 and signs with it, so the key itself
    // is the anchor rather than a hash.
    const anchor = await credentialLadderAnchor({
      log: readLogFromString(log()!),
      credentialVmId: unlockKeyVmId({ did: genesis.did, keyAgreement })
    })
    expect(anchor).toEqual({ anchorKeyMultibase: rung0.keyMultibase })
  })

  it('walks from a hash anchor to the same inventory a key anchor gives', async () => {
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const credential = await standingCredential(9)
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed
    })
    const credentialVmId = unlockKeyVmId({
      did,
      keyAgreement: credential.unlockKeys.keyAgreement
    })
    const parsed = readLogFromString(log()!)

    const keyAnchored = await attributeLadderInventory({
      log: parsed,
      anchorKeyMultibase: credential.rung0.keyMultibase,
      credentialVmId
    })
    const hashAnchored = await attributeLadderInventory({
      log: parsed,
      anchorHash: await deriveNextKeyHash(credential.rung0.keyMultibase),
      credentialVmId
    })
    const idOnly = await attributeLadderInventory({
      log: parsed,
      credentialVmId
    })
    expect(hashAnchored).toEqual(keyAnchored)
    expect(idOnly).toEqual(keyAnchored)
    expect(keyAnchored.committedHashes).toEqual([
      await deriveNextKeyHash(credential.rung0.keyMultibase)
    ])
  })

  it('refuses a walk with no anchor and no credential id', async () => {
    const { idStore, log, updateKeys } = await provisionedLog()
    const credential = await standingCredential(9)
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed
    })
    await expect(
      attributeLadderInventory({ log: readLogFromString(log()!) })
    ).rejects.toThrow(LadderAttributionError)
  })

  it('leaves a credential unclaimed when its bind entry is ambiguous', async () => {
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const ours = await standingCredential(9)
    const sibling = await standingCredential(10)

    // One entry introducing two credential-class members at once -- the shape
    // a recovery add-and-retire entry writes. Nothing in it says which
    // addition is whose, so the anchor is refused and the retirement strikes
    // nothing of either.
    const published = await readPublishedLog({ idStore })
    const updated = await updateDID({
      log: published!.log,
      signer: await updateKeySigner({ seed: updateKeys.updateSeed }),
      alsoKnownAsWeb: true,
      updateKeys: published!.updateKeys,
      nextKeyHashes: [
        ...published!.nextKeyHashes,
        await deriveNextKeyHash(ours.rung0.keyMultibase),
        await deriveNextKeyHash(sibling.rung0.keyMultibase)
      ],
      verificationMethods: [
        ...(published!.doc.verificationMethod ?? []),
        unlockKeyVerificationMethod({
          did,
          keyAgreement: ours.unlockKeys.keyAgreement
        }),
        unlockKeyVerificationMethod({
          did,
          keyAgreement: sibling.unlockKeys.keyAgreement
        })
      ],
      keyAgreement: [
        ...relationIds(published!.doc.keyAgreement),
        unlockKeyVmId({ did, keyAgreement: ours.unlockKeys.keyAgreement }),
        unlockKeyVmId({ did, keyAgreement: sibling.unlockKeys.keyAgreement })
      ]
    })
    await publishUpdatedLog({ idStore, updated, ifMatch: published!.etag })

    const parsed = readLogFromString(log()!)
    const oursVmId = unlockKeyVmId({
      did,
      keyAgreement: ours.unlockKeys.keyAgreement
    })
    expect(
      await credentialLadderAnchor({ log: parsed, credentialVmId: oursVmId })
    ).toBeUndefined()
    const strike = await attributeRetiredCredentialRungs({
      log: parsed,
      credentialVmIds: [oursVmId]
    })
    expect(strike.struckHashes).toEqual([])
    expect(strike.unclaimedCredentialVmIds).toEqual([oursVmId])
  })

  it('never strikes a hash the caller protects or a surviving key backs', async () => {
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const credential = await standingCredential(9)
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed
    })
    const parsed = readLogFromString(log()!)
    const credentialVmId = unlockKeyVmId({
      did,
      keyAgreement: credential.unlockKeys.keyAgreement
    })
    const rung0Hash = await deriveNextKeyHash(credential.rung0.keyMultibase)

    // Unprotected, the credential's rung is struck.
    const struck = await attributeRetiredCredentialRungs({
      log: parsed,
      credentialVmIds: [credentialVmId]
    })
    expect(struck.struckHashes).toEqual([rung0Hash])
    // The enrolled client's own hash is never a candidate: its key survives
    // the entry, and the carry-over convention re-states that hash.
    expect(struck.struckHashes).not.toContain(
      await deriveNextKeyHash(
        await updateKeyMultibase({ seed: updateKeys.updateSeed })
      )
    )

    // Named as the entry's own commitment, it is left alone.
    const protectedRun = await attributeRetiredCredentialRungs({
      log: parsed,
      credentialVmIds: [credentialVmId],
      protectedHashes: [rung0Hash]
    })
    expect(protectedRun.struckHashes).toEqual([])
    expect(protectedRun.unclaimedCredentialVmIds).toEqual([credentialVmId])
  })
})

describe('the backstops around a credential rung strike', () => {
  it('withholds the whole strike when a listed client has no attributable update key', async () => {
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const credential = await standingCredential(9)
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed
    })
    const credentialVmId = unlockKeyVmId({
      did,
      keyAgreement: credential.unlockKeys.keyAgreement
    })

    // A client published under `capabilityInvocation` by an entry that
    // authorizes no update key of its own: the listing cannot say which key
    // is its active one, which is the row `disconnectEligibility` refuses.
    const orphanSigningKey = CANONICAL_CLIENT_KEYS[10]!.signingKeyMultibase
    const published = await readPublishedLog({ idStore })
    const updated = await updateDID({
      log: published!.log,
      signer: await updateKeySigner({ seed: updateKeys.updateSeed }),
      alsoKnownAsWeb: true,
      updateKeys: published!.updateKeys,
      nextKeyHashes: published!.nextKeyHashes,
      verificationMethods: [
        ...(published!.doc.verificationMethod ?? []),
        {
          id: `${did}#${orphanSigningKey}`,
          type: 'Multikey',
          controller: did,
          publicKeyMultibase: orphanSigningKey
        }
      ],
      capabilityInvocation: [
        ...relationIds(published!.doc.capabilityInvocation),
        `${did}#${orphanSigningKey}`
      ]
    })
    await publishUpdatedLog({ idStore, updated, ifMatch: published!.etag })
    const parsed = readLogFromString(log()!)

    // The protection names it rather than passing over it.
    const protection = await survivingClientKeyProtection({ log: parsed })
    expect(protection.ambiguous).toContain(orphanSigningKey)

    // So nothing is struck, and every retiring credential is reported.
    const strike = await attributeRetiredCredentialRungs({
      log: parsed,
      credentialVmIds: [credentialVmId]
    })
    expect(strike.struckHashes).toEqual([])
    expect(strike.struckKeys).toEqual([])
    expect(strike.unclaimedCredentialVmIds).toEqual([credentialVmId])
    // The bind-anchor read fails closed on the same shape.
    expect(
      await credentialLadderAnchor({ log: parsed, credentialVmId })
    ).toBeUndefined()
  })

  it("vouches for a retiring credential's rung so it cannot be protected as a client's staged hash", async () => {
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const credential = await standingCredential(9)
    const rung0Hash = await deriveNextKeyHash(credential.rung0.keyMultibase)

    // One entry that rotates the founding client onto its staged key AND
    // commits the credential's rung hash first, so the staged attribution
    // finds two candidates and the append-order rule cannot place either:
    // the client's new active key's hash was committed earlier, so it is not
    // among this entry's additions.
    const rotated = await mintClientWebvhUpdateKeys()
    const stagedKey = await updateKeyMultibase({ seed: updateKeys.stagedSeed })
    const published = await readPublishedLog({ idStore })
    const updated = await updateDID({
      log: published!.log,
      // Prerotation verifies the entry against the keys it states, so the
      // rotation entry is signed by the key it reveals.
      signer: await updateKeySigner({ seed: updateKeys.stagedSeed }),
      alsoKnownAsWeb: true,
      updateKeys: [stagedKey],
      nextKeyHashes: [
        ...published!.nextKeyHashes,
        rung0Hash,
        await deriveNextKeyHash(
          await updateKeyMultibase({ seed: rotated.stagedSeed })
        )
      ],
      verificationMethods: [
        ...(published!.doc.verificationMethod ?? []),
        unlockKeyVerificationMethod({
          did,
          keyAgreement: credential.unlockKeys.keyAgreement
        })
      ],
      keyAgreement: [
        ...relationIds(published!.doc.keyAgreement),
        unlockKeyVmId({ did, keyAgreement: credential.unlockKeys.keyAgreement })
      ],
      // Restated, or the entry would drop the founding client out of the
      // relations and there would be no enrolled client left to protect.
      authentication: relationIds(published!.doc.authentication),
      assertionMethod: relationIds(published!.doc.assertionMethod),
      capabilityInvocation: relationIds(published!.doc.capabilityInvocation),
      capabilityDelegation: relationIds(published!.doc.capabilityDelegation)
    })
    await publishUpdatedLog({ idStore, updated, ifMatch: published!.etag })
    const parsed = readLogFromString(log()!)

    // Unvouched, the ambiguity protects every candidate -- the credential's
    // own rung among them.
    const blind = await survivingClientKeyProtection({ log: parsed })
    expect(blind.hashes).toContain(rung0Hash)

    // Vouched for as one of the retiring credentials' own claims, it is
    // pruned before the ambiguity is judged.
    const vouched = await survivingClientKeyProtection({
      log: parsed,
      knownLatentHashes: [rung0Hash]
    })
    expect(vouched.hashes).not.toContain(rung0Hash)
    expect(vouched.ambiguous).toEqual([])
    // The client's own keys are protected either way.
    expect(vouched.keys).toContain(stagedKey)
  })

  it('reports a credential whose claim was only partly struck', async () => {
    const { idStore, log, updateKeys, did } = await provisionedLog()
    const credential = await standingCredential(9)
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed
    })
    const parsed = readLogFromString(log()!)
    const credentialVmId = unlockKeyVmId({
      did,
      keyAgreement: credential.unlockKeys.keyAgreement
    })
    const rung0Hash = await deriveNextKeyHash(credential.rung0.keyMultibase)

    // Withheld by the caller's own protected set: the credential claimed
    // something, nothing of it was struck, and the report says so rather than
    // reading as a clean retirement.
    const withheld = await attributeRetiredCredentialRungs({
      log: parsed,
      credentialVmIds: [credentialVmId],
      protectedHashes: [rung0Hash]
    })
    expect(withheld.struckHashes).toEqual([])
    expect(withheld.unclaimedCredentialVmIds).toEqual([credentialVmId])

    // Unwithheld, the same credential is struck and reported clean.
    const struck = await attributeRetiredCredentialRungs({
      log: parsed,
      credentialVmIds: [credentialVmId]
    })
    expect(struck.struckHashes).toEqual([rung0Hash])
    expect(struck.unclaimedCredentialVmIds).toEqual([])
  })
})
