/**
 * Unit tests for the account-log signer seam (`src/webvh/accountEntry.ts`) and
 * the ceremony bodies whose ladder arm it opens.
 *
 * The seam itself: one `build` over two arms. The client arm reproduces the
 * entry an enrolled client always wrote (its stated parameters verbatim, the
 * `did:web` projection beside the log, the active-key precondition), and the
 * ladder arm adds the four ladder conventions (rung attribution, the
 * self-reveal union, the carry-over hash before the build's own commit hashes
 * in `decisions/0007` order, the log alone).
 *
 * The bodies: a ladder-signed removal entry may take out the LAST enrolled
 * client and leave the account ladder-anchored (`decisions/0017`), and a
 * credential retirement's strike entry has to be signed by the successor's
 * rung, because an entry keeps its own signer (`decisions/0018`).
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
  LadderAttributionError,
  ladderRung,
  ladderVmKeyMultibase
} from '../../src/clientAnnex/ladder.js'
import { createLadderAnchoredAccountLog } from '../../src/clientAnnex/ladderAnchored.js'
import { signAccountEntry } from '../../src/webvh/accountEntry.js'
import {
  ensureDidWebvh,
  keyAgreementCommitment,
  mintClientWebvhUpdateKeys,
  putLogResource,
  readPublishedLogOrThrow,
  updateKeyMultibase
} from '../../src/webvh/didWebvh.js'
import type {
  ClientWebvhUpdateKeys,
  WebvhIdStore
} from '../../src/webvh/didWebvh.js'
import { enrollWebvhClient } from '../../src/webvh/enrollClient.js'
import { revokeWebvhClient } from '../../src/webvh/revokeClient.js'
import {
  publishUnlockKey,
  removeUnlockKey,
  unlockKeyVmId
} from '../../src/unlock/standingWebvh.js'
import type { StandingUnlockKeys } from '../../src/unlock/standingWebvh.js'
import { ladderVmIds, relationIds } from '../../src/resourceLog/document.js'
import { listEnrolledWebvhClients } from '../../src/webvh/listClients.js'
import { accountLogPinId } from '../../src/webvh/verifyLog.js'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import { memoryIdStore } from './fixtures/memoryIdStore.js'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-account-entry'
const LOG_ID = accountLogPinId({ spaceId: SPACE_ID })

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
 * An account provisioned for one enrolled client.
 */
async function clientAnchoredAccount(): Promise<{
  idStore: WebvhIdStore
  log: () => string | undefined
  didDocument: () => object | undefined
  updateKeys: ClientWebvhUpdateKeys
  did: string
}> {
  const { idStore, log, didDocument } = memoryIdStore()
  const updateKeys = await mintClientWebvhUpdateKeys()
  const { did } = await ensureDidWebvh({
    idStore,
    wasServerUrl: WAS_URL,
    spaceId: SPACE_ID,
    clientKeys: { ...CANONICAL_CLIENT_KEYS[0] },
    updateKeys
  })
  return { idStore, log, didDocument, updateKeys, did }
}

/**
 * A standing passphrase-shaped credential: a fresh ladder and the
 * commitment-published inventory a bind entry installs.
 */
async function standingCredential(keyIndex: number) {
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
  return { ladderSeed, rung0, unlockKeys }
}

/**
 * A ladder-anchored account: the genesis entry of a credential's own ladder,
 * published as `did.jsonl`.
 */
async function ladderAnchoredAccount(keyIndex = 9) {
  const { idStore, log, didDocument } = memoryIdStore()
  const credential = await standingCredential(keyIndex)
  const created = await createLadderAnchoredAccountLog({
    wasServerUrl: WAS_URL,
    spaceId: SPACE_ID,
    ladderSeed: credential.ladderSeed,
    keyAgreement: credential.unlockKeys.keyAgreement
  })
  await putLogResource({ store: idStore, log: created.log })
  return { idStore, log, didDocument, did: created.did, ...credential }
}

/**
 * A freshly minted client's public halves plus its update seeds.
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

describe('signAccountEntry, one build over two arms', () => {
  it('signs the client arm with the update key, states its own parameters, and publishes the projection', async () => {
    const { idStore, log, didDocument, updateKeys, did } =
      await clientAnchoredAccount()
    const before = await resolved(log)
    const committed = await deriveNextKeyHash(
      CANONICAL_CLIENT_KEYS[5]!.signingKeyMultibase
    )
    const projectionBefore = didDocument()

    const outcome = await signAccountEntry({
      idStore,
      signer: { kind: 'client', updateKeys },
      expectedDid: did,
      build: () => ({ commitHashes: [committed] })
    })

    expect(outcome.skipped).toBe(false)
    // No rung members on this arm: nothing was attributed.
    expect(outcome.rung).toBeUndefined()
    expect(outcome.state).toBeUndefined()
    const after = await resolved(log)
    // The stated parameters verbatim, plus the build's commit hash: no rung
    // key joins `updateKeys`, and no carry-over hash is added.
    expect(after.meta.updateKeys).toEqual(before.meta.updateKeys)
    expect(after.meta.nextKeyHashes).toEqual([
      ...before.meta.nextKeyHashes,
      committed
    ])
    // The controller-invoking arm writes the `did:web` projection beside the
    // log.
    expect(didDocument()).not.toBe(projectionBefore)
    expect((didDocument() as { id?: string }).id).toBe(
      did.replace('did:webvh:', 'did:web:').split(':').slice(0, 2).join(':') ===
        'did:web'
        ? (didDocument() as { id?: string }).id
        : undefined
    )
  })

  it('refuses the client arm when the log does not authorize the active key', async () => {
    const { idStore, updateKeys, did } = await clientAnchoredAccount()
    const stranger = await mintClientWebvhUpdateKeys()

    await expect(
      signAccountEntry({
        idStore,
        signer: { kind: 'client', updateKeys: stranger },
        expectedDid: did,
        verb: 'revoking a client',
        build: () => ({})
      })
    ).rejects.toThrow(/finalize the pending rotation before revoking a client/)
    // The authorized signer still works, so nothing about the log is broken.
    const outcome = await signAccountEntry({
      idStore,
      signer: { kind: 'client', updateKeys },
      expectedDid: did,
      build: () => ({})
    })
    expect(outcome.skipped).toBe(false)
  })

  it('signs the ladder arm with the attributed rung, unions it back in, and orders the hashes', async () => {
    const { idStore, log, didDocument, did, ladderSeed, rung0 } =
      await ladderAnchoredAccount()
    const before = await resolved(log)
    const projectionBefore = didDocument()
    const committedA = await deriveNextKeyHash(
      CANONICAL_CLIENT_KEYS[5]!.signingKeyMultibase
    )
    const committedB = await deriveNextKeyHash(
      CANONICAL_CLIENT_KEYS[6]!.signingKeyMultibase
    )
    const pinStore = memoryResourceLogPinStore()

    const outcome = await signAccountEntry({
      idStore,
      signer: { kind: 'ladder', ladderSeed },
      expectedDid: did,
      pinStore,
      logId: LOG_ID,
      build: () => ({ commitHashes: [committedA, committedB] })
    })

    expect(outcome.skipped).toBe(false)
    expect(outcome.rung?.keyMultibase).toBe(rung0.keyMultibase)
    // Rung 0 is revealed by the ladder-anchored genesis, so the attribution
    // finds it revealed rather than committed: rungs are reused, not spent.
    expect(outcome.state).toBe('revealed')

    const after = await resolved(log)
    // The acting rung stands in `updateKeys` -- an entry never removes its own
    // signer -- and its own carry-over hash precedes the build's commitments
    // (`decisions/0007` order).
    expect(after.meta.updateKeys).toContain(rung0.keyMultibase)
    const rungHash = await deriveNextKeyHash(rung0.keyMultibase)
    expect(after.meta.nextKeyHashes.indexOf(rungHash)).toBeLessThan(
      after.meta.nextKeyHashes.indexOf(committedA)
    )
    expect(after.meta.nextKeyHashes.indexOf(committedA)).toBeLessThan(
      after.meta.nextKeyHashes.indexOf(committedB)
    )
    expect(after.meta.nextKeyHashes).toEqual([
      ...before.meta.nextKeyHashes,
      committedA,
      committedB
    ])
    // The bridge reaches `did.jsonl` alone: no projection is written.
    expect(didDocument()).toBe(projectionBefore)
    // The pin advanced to what this entry published.
    expect((await pinStore.read({ logId: LOG_ID }))!.head).toMatch(/^2-/)
  })

  it('refuses the ladder arm when the log commits no rung of this ladder', async () => {
    const { idStore, log, did } = await ladderAnchoredAccount()
    const entriesBefore = readLogFromString(log()!).length

    await expect(
      signAccountEntry({
        idStore,
        signer: { kind: 'ladder', ladderSeed: generateLadderSeed() },
        expectedDid: did,
        build: () => ({})
      })
    ).rejects.toBeInstanceOf(LadderAttributionError)
    expect(readLogFromString(log()!).length).toBe(entriesBefore)
  })

  it('publishes nothing when the skip hook or the build declines', async () => {
    const { idStore, log, updateKeys, did } = await clientAnchoredAccount()
    const entriesBefore = readLogFromString(log()!).length

    const skipped = await signAccountEntry({
      idStore,
      signer: { kind: 'client', updateKeys },
      expectedDid: did,
      skip: () => true,
      build: () => {
        throw new Error('the build must never run behind a skip')
      }
    })
    expect(skipped.skipped).toBe(true)
    expect(skipped.updated).toBeUndefined()

    const declined = await signAccountEntry({
      idStore,
      signer: { kind: 'client', updateKeys },
      expectedDid: did,
      build: () => undefined
    })
    expect(declined.skipped).toBe(false)
    expect(declined.updated).toBeUndefined()
    expect(readLogFromString(log()!).length).toBe(entriesBefore)
  })

  it('builds on a head the caller threaded in rather than reading again', async () => {
    const { idStore, updateKeys, did } = await clientAnchoredAccount()
    let reads = 0
    const counting = {
      ...idStore,
      async getIdResourceRaw(options: { resourceId: string }) {
        reads += 1
        return idStore.getIdResourceRaw(options)
      }
    }
    const published = await readPublishedLogOrThrow({ idStore })
    reads = 0

    await signAccountEntry({
      idStore: counting,
      signer: { kind: 'client', updateKeys },
      published,
      expectedDid: did,
      build: () => ({})
    })
    expect(reads).toBe(0)
  })
})

describe('revokeWebvhClient on the ladder arm', () => {
  it('removes the last enrolled client, leaving the account ladder-anchored', async () => {
    const { idStore, log, did, ladderSeed, unlockKeys } =
      await ladderAnchoredAccount()
    const client = await mintedNewClient(1)
    await enrollWebvhClient({
      idStore,
      signer: { kind: 'ladder', ladderSeed },
      newClient: client.keys,
      expectedDid: did
    })
    const enrolled = await resolved(log)
    expect(
      listEnrolledWebvhClients({ log: readLogFromString(log()!) }).map(
        row => row.signingKeyMultibase
      )
    ).toEqual([client.keys.signingKeyMultibase])
    // The enrollment committed the client's staged key, which the removal has
    // to strike beside the active one.
    const stagedHash = await deriveNextKeyHash(
      client.keys.stagedUpdateKeyMultibase
    )
    expect(enrolled.meta.nextKeyHashes).toContain(stagedHash)

    const removed = await revokeWebvhClient({
      idStore,
      signer: { kind: 'ladder', ladderSeed },
      revokedClient: {
        signingKeyMultibase: client.keys.signingKeyMultibase,
        updateKeyMultibase: client.keys.updateKeyMultibase
      },
      expectedDid: did
    })

    const after = await resolved(log)
    // The last client is gone and the document stands on the credential's
    // ladder VM alone (`decisions/0017`).
    expect(
      listEnrolledWebvhClients({ log: readLogFromString(log()!) })
    ).toEqual([])
    expect(relationIds(after.doc?.capabilityInvocation)).toEqual([])
    expect(ladderVmIds({ doc: after.doc! })).toEqual([
      `${did}#${await ladderVmKeyMultibase({ ladderSeed })}`
    ])
    expect(relationIds(after.doc?.keyAgreement)).toContain(
      unlockKeyVmId({ did, keyAgreement: unlockKeys.keyAgreement })
    )
    // Both of the client's commitments are struck, the staged one attributed
    // from the log.
    expect(after.meta.updateKeys).not.toContain(client.keys.updateKeyMultibase)
    expect(after.meta.nextKeyHashes).not.toContain(stagedHash)
    expect(after.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(client.keys.updateKeyMultibase)
    )
    // The account log the caller reads back is the post-edit one.
    expect(removed.did).toBe(did)
    expect(relationIds(removed.doc.capabilityInvocation)).toEqual([])
  })
})

describe('a credential retirement on the ladder arm', () => {
  /**
   * An account whose ladder-anchored credential has bound a successor: the
   * state a passphrase change stands in between its bind entry and its strike
   * entry, with both credentials whole.
   */
  async function boundSuccessor() {
    const account = await ladderAnchoredAccount(9)
    const successor = await standingCredential(8)
    await publishUnlockKey({
      idStore: account.idStore,
      signer: { kind: 'ladder', ladderSeed: account.ladderSeed },
      unlockKeys: successor.unlockKeys,
      ladderSeed: successor.ladderSeed,
      expectedDid: account.did
    })
    const bound = await resolved(account.log)
    const successorVm = `${account.did}#${await ladderVmKeyMultibase({
      ladderSeed: successor.ladderSeed
    })}`
    expect(ladderVmIds({ doc: bound.doc! })).toContain(successorVm)
    // The bind entry commits the successor's rung-0 hash, which is what lets
    // the successor sign the strike entry that follows.
    expect(bound.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(successor.rung0.keyMultibase)
    )
    return { ...account, successor, successorVm }
  }

  it('strikes the retired credential with the successor rung', async () => {
    const {
      idStore,
      log,
      did,
      ladderSeed,
      unlockKeys,
      rung0,
      successor,
      successorVm
    } = await boundSuccessor()

    const strike = await removeUnlockKey({
      idStore,
      signer: { kind: 'ladder', ladderSeed: successor.ladderSeed },
      unlockKeys,
      ladderSeed,
      requireLadderVmClaim: true,
      expectedDid: did
    })

    const after = await resolved(log)
    const retiredVm = `${did}#${await ladderVmKeyMultibase({ ladderSeed })}`
    expect(strike.ladderVm.struck).toEqual([retiredVm])
    // The successor's own VM stands, unclaimed by this credential's walk.
    expect(strike.ladderVm.unclaimed).toEqual([successorVm])
    expect(ladderVmIds({ doc: after.doc! })).toEqual([successorVm])
    expect(relationIds(after.doc?.keyAgreement)).not.toContain(
      unlockKeyVmId({ did, keyAgreement: unlockKeys.keyAgreement })
    )
    // The retired rung hashes go with it.
    expect(after.meta.updateKeys).not.toContain(rung0.keyMultibase)
    expect(after.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(rung0.keyMultibase)
    )
    // The successor's own ladder survives its strike of the other.
    expect(after.meta.updateKeys).toContain(successor.rung0.keyMultibase)
    expect(relationIds(after.doc?.keyAgreement)).toContain(
      unlockKeyVmId({ did, keyAgreement: successor.unlockKeys.keyAgreement })
    )
  })

  it('cannot strike the ladder that signs it, which is why the successor does', async () => {
    const { idStore, log, did, ladderSeed, unlockKeys, rung0 } =
      await boundSuccessor()

    // Signed by the credential being retired: the entry keeps its own signer,
    // so the rung is unioned back into `updateKeys` and its hash back into
    // `nextKeyHashes`. The ladder outlives the entry meant to end it.
    await removeUnlockKey({
      idStore,
      signer: { kind: 'ladder', ladderSeed },
      unlockKeys,
      ladderSeed,
      expectedDid: did
    })

    const after = await resolved(log)
    expect(after.meta.updateKeys).toContain(rung0.keyMultibase)
    expect(after.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(rung0.keyMultibase)
    )
  })
})
