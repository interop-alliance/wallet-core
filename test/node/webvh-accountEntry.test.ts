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
 *
 * And the ladder-arm enrollment approval's residue: the approving rung
 * commits the enrollee's two hashes and then authorizes the enrollee's key
 * while keeping itself in `updateKeys`, so the walk must read the add entry
 * as a transfer to the client rather than a second reveal of the ladder, and
 * the approver must still retire with the enrolled client's inventory
 * standing. A torn approval resumed on the other arm, or resumed after the
 * same credential's self-enrollment climbed the ladder, must leave the same
 * readings: the ladder arm reveals a merely committed rung in an entry of
 * its own before the add entry, and the walk reads the add entry as a
 * transfer whoever signs it.
 */
import { describe, expect, it } from 'vitest'
import { deriveNextKeyHash, readLogFromString } from '@interop/did-method-webvh'
import {
  attributeLadderInventory,
  LadderAttributionError
} from '../../src/webvh/ladder.js'
import {
  ladderRung,
  ladderVmKeyMultibase
} from '../../src/webvh/ladderDerivation.js'
import { generateLadderSeed } from '../../src/unlock/unlockRecord.js'
import {
  createLadderAnchoredAccountLog,
  selfEnrollWebvhClient
} from '../../src/clientAnnex/ladderAnchored.js'
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
  preflightUnlockCredentialRetirement,
  publishUnlockKey,
  removeUnlockKey,
  unlockKeyVmId
} from '../../src/unlock/standingWebvh.js'
import type { StandingUnlockKeys } from '../../src/unlock/standingWebvh.js'
import { ladderVmIds, relationIds } from '../../src/resourceLog/document.js'
import { listEnrolledWebvhClients } from '../../src/webvh/listClients.js'
import { accountLogPinId } from '../../src/webvh/verifyLog.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'
import {
  CANONICAL_CLIENT_KEYS,
  mintedNewClient
} from './fixtures/clientKeys.js'
import { resolved } from './fixtures/resolvedLog.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-account-entry'
const LOG_ID = accountLogPinId({ spaceId: SPACE_ID })

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
  const { idStore, log, didDocument } = memoryIdStore({ spaceId: SPACE_ID })
  const updateKeys = mintClientWebvhUpdateKeys()
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
  const { idStore, log, didDocument } = memoryIdStore({ spaceId: SPACE_ID })
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
      signer: { kind: 'enrolled', updateKeys },
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
    const stranger = mintClientWebvhUpdateKeys()

    await expect(
      signAccountEntry({
        idStore,
        signer: { kind: 'enrolled', updateKeys: stranger },
        expectedDid: did,
        verb: 'revoking a client',
        build: () => ({})
      })
    ).rejects.toThrow(/finalize the pending rotation before revoking a client/)
    // The authorized signer still works, so nothing about the log is broken.
    const outcome = await signAccountEntry({
      idStore,
      signer: { kind: 'enrolled', updateKeys },
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
    const outcome = await signAccountEntry({
      idStore,
      signer: { kind: 'ladder', ladderSeed },
      expectedDid: did,
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
    // The pin advanced to what this entry published. The pin now rides the
    // store seam, so the ceremony takes no pin options of its own.
    expect((await idStore.pin.store.read({ logId: LOG_ID }))!.head).toMatch(
      /^2-/
    )
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
      signer: { kind: 'enrolled', updateKeys },
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
      signer: { kind: 'enrolled', updateKeys },
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
      signer: { kind: 'enrolled', updateKeys },
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

describe('a credential that approved an enrollment on the ladder arm', () => {
  /**
   * A client-anchored account whose enrolled client bound a passphrase-shaped
   * credential (rung 0 committed, never revealed), after which the credential
   * approved a second client's enrollment through its ladder: the commit
   * entry reveals rung 0 and commits the enrollee's two hashes, and the add
   * entry, signed by the same rung, authorizes the enrollee's update key.
   */
  async function approvedOnClientAnchoredAccount() {
    const account = await clientAnchoredAccount()
    const credential = await standingCredential(8)
    await publishUnlockKey({
      idStore: account.idStore,
      signer: { kind: 'enrolled', updateKeys: account.updateKeys },
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed,
      expectedDid: account.did
    })
    const enrollee = await mintedNewClient(1)
    await enrollWebvhClient({
      idStore: account.idStore,
      signer: { kind: 'ladder', ladderSeed: credential.ladderSeed },
      newClient: enrollee.keys,
      expectedDid: account.did
    })
    const enrolled = await resolved(account.log)
    const updateKeyHash = await deriveNextKeyHash(
      enrollee.keys.updateKeyMultibase
    )
    const stagedHash = await deriveNextKeyHash(
      enrollee.keys.stagedUpdateKeyMultibase
    )
    // The shape under test: the rung stands revealed beside the enrollee's
    // update key, and both of the enrollee's hashes stand committed.
    expect(enrolled.meta.updateKeys).toContain(credential.rung0.keyMultibase)
    expect(enrolled.meta.updateKeys).toContain(enrollee.keys.updateKeyMultibase)
    expect(enrolled.meta.nextKeyHashes).toContain(updateKeyHash)
    expect(enrolled.meta.nextKeyHashes).toContain(stagedHash)
    const credentialVmId = unlockKeyVmId({
      did: account.did,
      keyAgreement: credential.unlockKeys.keyAgreement
    })
    return {
      ...account,
      credential,
      credentialVmId,
      enrollee,
      updateKeyHash,
      stagedHash,
      log: account.log
    }
  }

  /**
   * The assertions every reading of the approver's inventory must meet after
   * the approval: its own rung and commitment, and nothing of the enrollee's.
   */
  function expectOwnInventoryOnly(
    inventory: Awaited<ReturnType<typeof attributeLadderInventory>>,
    fixture: Awaited<ReturnType<typeof approvedOnClientAnchoredAccount>>
  ) {
    const rungHash = fixture.credential.rung0.keyMultibase
    expect(inventory.revealedKeys).toEqual([rungHash])
    expect(inventory.committedHashes).not.toContain(fixture.updateKeyHash)
    expect(inventory.committedHashes).not.toContain(fixture.stagedHash)
    expect(inventory.revealedKeys).not.toContain(
      fixture.enrollee.keys.updateKeyMultibase
    )
  }

  it('attributes the approver on the seeded, member-anchored, and registry-anchored readings', async () => {
    const fixture = await approvedOnClientAnchoredAccount()
    const log = readLogFromString(fixture.log()!)
    const { credential, credentialVmId } = fixture
    const rung0Hash = await deriveNextKeyHash(credential.rung0.keyMultibase)

    const seeded = await attributeLadderInventory({
      log,
      anchorHash: rung0Hash,
      ladderSeed: credential.ladderSeed,
      credentialVmId
    })
    expectOwnInventoryOnly(seeded, fixture)
    expect(seeded.committedHashes).toEqual([rung0Hash])

    // Seedless, anchored on the member's own `ladderCommitment`.
    const memberAnchored = await attributeLadderInventory({
      log,
      credentialVmId
    })
    expectOwnInventoryOnly(memberAnchored, fixture)
    expect(memberAnchored.committedHashes).toEqual([rung0Hash])

    // Seedless, anchored on the recorded bind-time rung.
    const registryAnchored = await attributeLadderInventory({
      log,
      anchorKeyMultibase: credential.unlockKeys.updateKeyMultibase,
      credentialVmId
    })
    expectOwnInventoryOnly(registryAnchored, fixture)
    expect(registryAnchored.committedHashes).toEqual([rung0Hash])

    // The enrollee is an ordinary enrolled client with an attributable
    // active key, so the surviving-client guard has something to protect.
    const rows = listEnrolledWebvhClients({ log })
    expect(
      rows.find(
        row =>
          row.signingKeyMultibase === fixture.enrollee.keys.signingKeyMultibase
      )?.updateKeyMultibase
    ).toBe(fixture.enrollee.keys.updateKeyMultibase)
  })

  it('passes the retirement pre-flight with and without the seed', async () => {
    const { idStore, did, credential } = await approvedOnClientAnchoredAccount()
    const seedless = await preflightUnlockCredentialRetirement({
      idStore,
      unlockKeys: credential.unlockKeys,
      expectedDid: did
    })
    const seeded = await preflightUnlockCredentialRetirement({
      idStore,
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed,
      expectedDid: did
    })
    const ladderVm = `${did}#${await ladderVmKeyMultibase({
      ladderSeed: credential.ladderSeed
    })}`
    expect(seedless.struck).toEqual([ladderVm])
    expect(seedless.unclaimed).toEqual([])
    expect(seeded.struck).toEqual([ladderVm])
    expect(seeded.unclaimed).toEqual([])
  })

  it('retires the approver on the enrolled arm, leaving the enrolled client whole', async () => {
    const fixture = await approvedOnClientAnchoredAccount()
    const { idStore, log, did, updateKeys, credential, enrollee } = fixture
    const rung0Hash = await deriveNextKeyHash(credential.rung0.keyMultibase)

    // Seedless: the enrolled client strikes the credential from its record
    // alone, the shape of a passphrase removal from another client.
    const strike = await removeUnlockKey({
      idStore,
      signer: { kind: 'enrolled', updateKeys },
      unlockKeys: credential.unlockKeys,
      expectedDid: did
    })

    const after = await resolved(log)
    expect(strike.ladderVm.unclaimed).toEqual([])
    expect(relationIds(after.doc?.keyAgreement)).not.toContain(
      fixture.credentialVmId
    )
    expect(ladderVmIds({ doc: after.doc! })).toEqual([])
    // The credential's rung and its commitment are gone.
    expect(after.meta.updateKeys).not.toContain(credential.rung0.keyMultibase)
    expect(after.meta.nextKeyHashes).not.toContain(rung0Hash)
    // The enrolled client's active key, carry-over hash, and staged hash
    // all stand, and the client is still listed with an attributed key.
    expect(after.meta.updateKeys).toContain(enrollee.keys.updateKeyMultibase)
    expect(after.meta.nextKeyHashes).toContain(fixture.updateKeyHash)
    expect(after.meta.nextKeyHashes).toContain(fixture.stagedHash)
    expect(
      listEnrolledWebvhClients({ log: readLogFromString(log()!) }).map(row => [
        row.signingKeyMultibase,
        row.updateKeyMultibase
      ])
    ).toEqual([
      [
        CANONICAL_CLIENT_KEYS[0]!.signingKeyMultibase,
        await updateKeyMultibase({ seed: updateKeys.updateSeed })
      ],
      [enrollee.keys.signingKeyMultibase, enrollee.keys.updateKeyMultibase]
    ])
  })

  it('retires the approver on the ladder arm, signed by a successor credential', async () => {
    // A ladder-anchored account whose credential approved an enrollment, then
    // bound a successor through its ladder: the passphrase-change shape on a
    // credential-only account.
    const account = await ladderAnchoredAccount(9)
    const enrollee = await mintedNewClient(1)
    await enrollWebvhClient({
      idStore: account.idStore,
      signer: { kind: 'ladder', ladderSeed: account.ladderSeed },
      newClient: enrollee.keys,
      expectedDid: account.did
    })
    const successor = await standingCredential(8)
    await publishUnlockKey({
      idStore: account.idStore,
      signer: { kind: 'ladder', ladderSeed: account.ladderSeed },
      unlockKeys: successor.unlockKeys,
      ladderSeed: successor.ladderSeed,
      expectedDid: account.did
    })
    const updateKeyHash = await deriveNextKeyHash(
      enrollee.keys.updateKeyMultibase
    )
    const stagedHash = await deriveNextKeyHash(
      enrollee.keys.stagedUpdateKeyMultibase
    )

    const strike = await removeUnlockKey({
      idStore: account.idStore,
      signer: { kind: 'ladder', ladderSeed: successor.ladderSeed },
      unlockKeys: account.unlockKeys,
      ladderSeed: account.ladderSeed,
      expectedDid: account.did
    })

    const after = await resolved(account.log)
    const retiredVm = `${account.did}#${await ladderVmKeyMultibase({
      ladderSeed: account.ladderSeed
    })}`
    const successorVm = `${account.did}#${await ladderVmKeyMultibase({
      ladderSeed: successor.ladderSeed
    })}`
    expect(strike.ladderVm.struck).toEqual([retiredVm])
    expect(strike.ladderVm.unclaimed).toEqual([successorVm])
    expect(ladderVmIds({ doc: after.doc! })).toEqual([successorVm])
    expect(after.meta.updateKeys).not.toContain(account.rung0.keyMultibase)
    expect(after.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(account.rung0.keyMultibase)
    )
    // The enrolled client survives the retirement whole.
    expect(after.meta.updateKeys).toContain(enrollee.keys.updateKeyMultibase)
    expect(after.meta.nextKeyHashes).toContain(updateKeyHash)
    expect(after.meta.nextKeyHashes).toContain(stagedHash)
    expect(
      listEnrolledWebvhClients({
        log: readLogFromString(account.log()!)
      }).map(row => [row.signingKeyMultibase, row.updateKeyMultibase])
    ).toEqual([
      [enrollee.keys.signingKeyMultibase, enrollee.keys.updateKeyMultibase]
    ])
    // And so does the successor's ladder.
    expect(after.meta.updateKeys).toContain(successor.rung0.keyMultibase)
  })

  it("keeps refusing a rung-signed entry that reveals the ladder's own next rung beside the standing one", async () => {
    // The transfer never releases a hash the ladder knows a priori, nor one
    // committed last among its entry's additions, where a ladder's own next
    // commitment sits. A rung-signed entry authorizing rung 1 while rung 0
    // stands and signs is no ceremony's shape, and every reading -- seeded,
    // member-anchored, registry-anchored -- still reads it as two reveals of
    // one ladder. The seedless readings rest on the position alone: their
    // a-priori set stops at the anchor, and `hash(rung 1)` reached the
    // claims through the genesis entry, which committed it last. The
    // continuation-born shape, where `hash(rung 1)` is handed over from the
    // middle of a spend's additions, is pinned in the recovery suite.
    const { idStore, log, did, ladderSeed, rung0, unlockKeys } =
      await ladderAnchoredAccount(9)
    const rung1 = await ladderRung({ ladderSeed, index: 1 })
    await signAccountEntry({
      idStore,
      signer: { kind: 'ladder', ladderSeed },
      expectedDid: did,
      build: ({ published }) => ({
        updateKeys: [...published.updateKeys, rung1.keyMultibase]
      })
    })
    const after = await resolved(log)
    expect(after.meta.updateKeys).toContain(rung0.keyMultibase)
    expect(after.meta.updateKeys).toContain(rung1.keyMultibase)

    const written = readLogFromString(log()!)
    const credentialVmId = unlockKeyVmId({
      did,
      keyAgreement: unlockKeys.keyAgreement
    })
    await expect(
      attributeLadderInventory({
        log: written,
        anchorHash: await deriveNextKeyHash(rung0.keyMultibase),
        ladderSeed,
        credentialVmId
      })
    ).rejects.toBeInstanceOf(LadderAttributionError)
    await expect(
      attributeLadderInventory({ log: written, credentialVmId })
    ).rejects.toBeInstanceOf(LadderAttributionError)
    await expect(
      attributeLadderInventory({
        log: written,
        anchorKeyMultibase: unlockKeys.updateKeyMultibase,
        credentialVmId
      })
    ).rejects.toBeInstanceOf(LadderAttributionError)
    // And the pre-flight, seedless, refuses rather than reporting a clean
    // retirement that would leave rung 1 standing.
    await expect(
      preflightUnlockCredentialRetirement({
        idStore,
        unlockKeys,
        expectedDid: did
      })
    ).rejects.toBeInstanceOf(LadderAttributionError)
  })

  /**
   * A client-anchored account with a bound standing credential, the shape
   * every resumed-approval test below starts from.
   */
  async function accountWithCredential() {
    const account = await clientAnchoredAccount()
    const credential = await standingCredential(8)
    await publishUnlockKey({
      idStore: account.idStore,
      signer: { kind: 'enrolled', updateKeys: account.updateKeys },
      unlockKeys: credential.unlockKeys,
      ladderSeed: credential.ladderSeed,
      expectedDid: account.did
    })
    const credentialVmId = unlockKeyVmId({
      did: account.did,
      keyAgreement: credential.unlockKeys.keyAgreement
    })
    return { ...account, credential, credentialVmId }
  }

  /**
   * An approval's commit entry alone, on the enrolled or the ladder arm: a
   * fresh enrollee's update-key and staged hashes, the shape a torn approval
   * leaves. Returns the enrollee.
   */
  async function commitOnly({
    account,
    arm
  }: {
    account: Awaited<ReturnType<typeof accountWithCredential>>
    arm: 'enrolled' | 'ladder'
  }) {
    const enrollee = await mintedNewClient(1)
    await signAccountEntry({
      idStore: account.idStore,
      signer:
        arm === 'enrolled'
          ? { kind: 'enrolled', updateKeys: account.updateKeys }
          : { kind: 'ladder', ladderSeed: account.credential.ladderSeed },
      expectedDid: account.did,
      build: async () => ({
        commitHashes: [
          await deriveNextKeyHash(enrollee.keys.updateKeyMultibase),
          await deriveNextKeyHash(enrollee.keys.stagedUpdateKeyMultibase)
        ]
      })
    })
    return enrollee
  }

  /**
   * The log's last two entries are a reveal of `rung` alone, then the add
   * entry authorizing the enrollee's update key.
   */
  function expectRevealThenAdd({
    account,
    rung,
    enrollee
  }: {
    account: Awaited<ReturnType<typeof accountWithCredential>>
    rung: string
    enrollee: Awaited<ReturnType<typeof mintedNewClient>>
  }) {
    const [revealed, added] = readLogFromString(account.log()!)
      .slice(-2)
      .map(entry => entry.parameters.updateKeys ?? [])
    expect(revealed).toContain(rung)
    expect(revealed).not.toContain(enrollee.keys.updateKeyMultibase)
    expect(added).toContain(enrollee.keys.updateKeyMultibase)
  }

  /**
   * The readings a resumed approval must leave usable: the enrollee listed
   * with its update key attributed, both ladder walks reading without
   * refusal, the approver retiring on the enrolled arm with the enrollee
   * whole, and the enrollee then disconnecting.
   */
  async function expectResumedApprovalReadable({
    account,
    enrollee
  }: {
    account: Awaited<ReturnType<typeof accountWithCredential>>
    enrollee: Awaited<ReturnType<typeof mintedNewClient>>
  }) {
    const { idStore, log, did, updateKeys, credential, credentialVmId } =
      account
    const written = readLogFromString(log()!)
    const row = listEnrolledWebvhClients({ log: written }).find(
      client => client.signingKeyMultibase === enrollee.keys.signingKeyMultibase
    )
    expect(row?.updateKeyMultibase).toBe(enrollee.keys.updateKeyMultibase)

    const updateKeyHash = await deriveNextKeyHash(
      enrollee.keys.updateKeyMultibase
    )
    const stagedHash = await deriveNextKeyHash(
      enrollee.keys.stagedUpdateKeyMultibase
    )
    for (const reading of [
      { ladderSeed: credential.ladderSeed, credentialVmId },
      { credentialVmId }
    ]) {
      const inventory = await attributeLadderInventory({
        log: written,
        ...reading
      })
      expect(inventory.revealedKeys).not.toContain(
        enrollee.keys.updateKeyMultibase
      )
      expect(inventory.committedHashes).not.toContain(updateKeyHash)
      expect(inventory.committedHashes).not.toContain(stagedHash)
    }

    const strike = await removeUnlockKey({
      idStore,
      signer: { kind: 'enrolled', updateKeys },
      unlockKeys: credential.unlockKeys,
      expectedDid: did
    })
    expect(strike.ladderVm.unclaimed).toEqual([])
    const retired = await resolved(log)
    expect(ladderVmIds({ doc: retired.doc! })).toEqual([])
    expect(retired.meta.updateKeys).toContain(enrollee.keys.updateKeyMultibase)
    expect(retired.meta.nextKeyHashes).toContain(updateKeyHash)
    expect(retired.meta.nextKeyHashes).toContain(stagedHash)

    await revokeWebvhClient({
      idStore,
      signer: { kind: 'enrolled', updateKeys },
      revokedClient: enrollee.keys,
      expectedDid: did
    })
    const revoked = await resolved(log)
    expect(revoked.meta.updateKeys).not.toContain(
      enrollee.keys.updateKeyMultibase
    )
    expect(revoked.meta.nextKeyHashes).not.toContain(stagedHash)
  }

  it('reveals the rung in an entry of its own when a ladder-arm add resumes a client-arm commit', async () => {
    const account = await accountWithCredential()
    const enrollee = await commitOnly({ account, arm: 'enrolled' })
    const before = readLogFromString(account.log()!).length

    await enrollWebvhClient({
      idStore: account.idStore,
      signer: { kind: 'ladder', ladderSeed: account.credential.ladderSeed },
      newClient: enrollee.keys,
      expectedDid: account.did
    })

    // Two entries: the reveal, then the add authorizing the enrollee's key
    // alone.
    expect(readLogFromString(account.log()!).length).toBe(before + 2)
    expectRevealThenAdd({
      account,
      rung: account.credential.rung0.keyMultibase,
      enrollee
    })
    await expectResumedApprovalReadable({ account, enrollee })
  })

  it('reads a ladder-arm commit resumed by an enrolled-arm add as a transfer to the enrollee', async () => {
    const account = await accountWithCredential()
    const enrollee = await commitOnly({ account, arm: 'ladder' })

    await enrollWebvhClient({
      idStore: account.idStore,
      signer: { kind: 'enrolled', updateKeys: account.updateKeys },
      newClient: enrollee.keys,
      expectedDid: account.did
    })

    await expectResumedApprovalReadable({ account, enrollee })
  })

  it("reads an approval resumed after the same credential's self-enrollment climbed the ladder", async () => {
    const account = await accountWithCredential()
    const enrollee = await commitOnly({ account, arm: 'ladder' })
    const selfEnrolled = await mintedNewClient(2)
    await selfEnrollWebvhClient({
      store: account.idStore,
      ladderSeed: account.credential.ladderSeed,
      newClientKeys: selfEnrolled.keys,
      newClientUpdateSeeds: selfEnrolled.seeds,
      onCommitted: async () => {},
      expectedDid: account.did
    })
    const rung1 = await ladderRung({
      ladderSeed: account.credential.ladderSeed,
      index: 1
    })
    const climbed = await resolved(account.log)
    expect(climbed.meta.updateKeys).not.toContain(rung1.keyMultibase)

    await enrollWebvhClient({
      idStore: account.idStore,
      signer: { kind: 'ladder', ladderSeed: account.credential.ladderSeed },
      newClient: enrollee.keys,
      expectedDid: account.did
    })

    // The resumed add entry is signed by rung 1, revealed ahead of it.
    expectRevealThenAdd({ account, rung: rung1.keyMultibase, enrollee })
    await expectResumedApprovalReadable({ account, enrollee })
    // The self-enrolled client comes through the whole run too.
    const after = await resolved(account.log)
    expect(after.meta.updateKeys).toContain(
      selfEnrolled.keys.updateKeyMultibase
    )
  })
})
