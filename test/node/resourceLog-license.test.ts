/**
 * Tests for the ceremony-tail license on ladder-signed resource-log appends
 * (`src/resourceLog/license.ts`, clause B of the ladder VM's authority
 * clauses): the two admitted shapes -- the log's first entry, and a rotation
 * that carries an inventory-changing controller-document version that no
 * verified entry already carries at or past -- and the refusals around them,
 * above all the silent-rekey shape (a ladder-signed rotation against an unchanged
 * document). The license is exercised at all three seams it lives on: the
 * predicate itself over a fake controller, the read path through
 * `verifyResourceLog` on real signed logs, and the write path's pre-append
 * admission check in the log-governed descriptor store. Plus the inventory view
 * the whole rule reads from -- the did:webvh adapter's `inventoryAt`, its
 * ladder recognition by relation asymmetry and its exclusion of enrolled
 * clients' key-agreement twins.
 */
import { describe, expect, it } from 'vitest'
import type { DIDLog } from '@interop/did-method-webvh'
import type { CollectionEncryption } from '@interop/was-client'
import { RESOURCE_LOG_METHOD } from '@interop/storage-core'
import {
  EPOCH_CONFIGURATION_STATE_TYPE,
  logGovernedDescriptorStore
} from '../../src/keys/rosterLogStore.js'
import { userKeyRosterPinId } from '../../src/keys/rosterStore.js'
import {
  buildResourceLogEntry,
  buildResourceLogGenesis,
  memoryResourceLogPinStore,
  ResourceLogIntegrityError,
  verifyResourceLog
} from '@interop/vh-resource-log'
import {
  assertLadderAppendLicensed,
  ResourceLogLicenseError,
  webvhResourceLogController,
  type WebvhResourceLogController
} from '../../src/resourceLog/index.js'
import { ownerRecipient } from '@interop/was-client/edv'
import { mintUserKey } from '../../src/keys/userKey.js'
import {
  ensureUserKeyRoster,
  replaceUserKeyRosterRecipients
} from '../../src/keys/userKeyRoster.js'
import { makeRosterClient, rosterDocumentFor } from './fixtures/rosterClient.js'
import { fakeController, memoryLogStore } from './fixtures/resourceLog.js'

const METHOD = 'resource-log:0.1'
const LOG_ID = userKeyRosterPinId({ spaceId: 'space-under-test' })

/**
 * Runs a call expected to refuse and hands back what it threw. Failing to
 * throw is itself a test failure, so a silently accepted append can never
 * pass as a refusal case.
 *
 * @param run {function}   `() => Promise<unknown>`
 * @returns {Promise<unknown>}
 */
async function caughtFrom(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run()
  } catch (err) {
    return err
  }
  throw new Error('expected a license refusal, but the call resolved')
}

/**
 * Asserts a caught value is a license refusal, by class AND by name (the two
 * ways a caller across a package boundary tells the classes apart).
 *
 * @param caught {unknown}
 */
function expectLicenseRefusal(caught: unknown): void {
  expect(caught).toBeInstanceOf(ResourceLogLicenseError)
  expect((caught as Error).name).toBe('ResourceLogLicenseError')
}

describe('assertLadderAppendLicensed', () => {
  it('licenses an append carrying a inventory-changing version', async () => {
    const controller = fakeController({
      versions: [
        { versionId: '1-v1', keys: ['zLadder'], inventoryKeys: ['credA'] },
        { versionId: '2-v2', keys: ['zLadder'], inventoryKeys: ['credB'] }
      ]
    })
    await expect(
      assertLadderAppendLicensed({
        controller,
        controllerVersionIndex: 1,
        headControllerVersionIndex: 0
      })
    ).resolves.toBeUndefined()
  })

  it('refuses a rotation against an unchanged inventory (the silent rekey)', async () => {
    // The document entry landed, but it changed no credential inventory: the
    // ladder cannot rotate the roster off the back of it.
    const controller = fakeController({
      versions: [
        { versionId: '1-v1', keys: ['zLadder'], inventoryKeys: ['credA'] },
        { versionId: '2-v2', keys: ['zLadder'], inventoryKeys: ['credA'] }
      ]
    })
    const caught = await caughtFrom(() =>
      assertLadderAppendLicensed({
        controller,
        controllerVersionIndex: 1,
        headControllerVersionIndex: 0
      })
    )
    expectLicenseRefusal(caught)
    expect((caught as Error).message).toContain('did not change')
  })

  it('is one-shot: refuses a head at or past the change', async () => {
    const controller = fakeController({
      versions: [
        { versionId: '1-v1', keys: ['zLadder'], inventoryKeys: ['credA'] },
        { versionId: '2-v2', keys: ['zLadder'], inventoryKeys: ['credB'] },
        { versionId: '3-v3', keys: ['zLadder'], inventoryKeys: ['credC'] }
      ]
    })
    const atTheChange = await caughtFrom(() =>
      assertLadderAppendLicensed({
        controller,
        controllerVersionIndex: 1,
        headControllerVersionIndex: 1
      })
    )
    expectLicenseRefusal(atTheChange)
    const pastTheChange = await caughtFrom(() =>
      assertLadderAppendLicensed({
        controller,
        controllerVersionIndex: 1,
        headControllerVersionIndex: 2
      })
    )
    expectLicenseRefusal(pastTheChange)
  })

  it('licenses the genesis version when its inventory is non-empty', async () => {
    // S(-1) is empty, so a first version carrying any inventory member is
    // itself inventory-changing.
    const controller = fakeController({
      versions: [
        { versionId: '1-v1', keys: ['zLadder'], inventoryKeys: ['credA'] }
      ]
    })
    await expect(
      assertLadderAppendLicensed({
        controller,
        controllerVersionIndex: 0,
        headControllerVersionIndex: null
      })
    ).resolves.toBeUndefined()
  })

  it('refuses an append with no controller version fail-closed', async () => {
    const controller = fakeController({
      versions: [],
      currentKeys: ['zLadder']
    })
    const caught = await caughtFrom(() =>
      assertLadderAppendLicensed({
        controller,
        controllerVersionIndex: null,
        headControllerVersionIndex: null
      })
    )
    expectLicenseRefusal(caught)
    expect((caught as Error).message).toContain('controller document version')
  })

  it('licenses an inventory change in the removal direction', async () => {
    // Retiring a credential is as much an inventory change as adding one; the
    // comparison is set inequality in either direction.
    const controller = fakeController({
      versions: [
        {
          versionId: '1-v1',
          keys: ['zLadder'],
          inventoryKeys: ['credA', 'credB']
        },
        { versionId: '2-v2', keys: ['zLadder'], inventoryKeys: ['credA'] }
      ]
    })
    await expect(
      assertLadderAppendLicensed({
        controller,
        controllerVersionIndex: 1,
        headControllerVersionIndex: 0
      })
    ).resolves.toBeUndefined()
  })
})

describe('verifyResourceLog (the ceremony-tail license end to end)', () => {
  /**
   * An account whose document backs one enrolled client (alice) and one
   * ladder VM, with the two controller views a ceremony sees: before the
   * inventory-changing document entry, and after it.
   */
  async function makeAccount() {
    const alice = await makeRosterClient()
    const ladder = await makeRosterClient()
    const firstVersion = {
      versionId: '1-v1',
      keys: [alice.signingKeyMultibase, ladder.signingKeyMultibase],
      ladderKeys: [ladder.signingKeyMultibase],
      inventoryKeys: ['credA']
    }
    const beforeEdit = fakeController({ versions: [firstVersion] })
    const afterEdit = fakeController({
      versions: [
        firstVersion,
        {
          versionId: '2-v2',
          keys: [alice.signingKeyMultibase, ladder.signingKeyMultibase],
          ladderKeys: [ladder.signingKeyMultibase],
          inventoryKeys: ['credB']
        }
      ]
    })
    const unchangedEdit = fakeController({
      versions: [
        firstVersion,
        {
          versionId: '2-v2',
          keys: [alice.signingKeyMultibase, ladder.signingKeyMultibase],
          ladderKeys: [ladder.signingKeyMultibase],
          inventoryKeys: ['credA']
        }
      ]
    })
    return { alice, ladder, beforeEdit, afterEdit, unchangedEdit }
  }

  it('verifies a ladder-signed genesis (the license first-entry shape)', async () => {
    const { ladder, beforeEdit } = await makeAccount()
    const genesis = await buildResourceLogGenesis({
      state: { type: 'TestState', value: 1 },
      method: METHOD,
      controller: beforeEdit,
      signer: ladder.logSigner
    })
    const verified = await verifyResourceLog({
      entries: [genesis],
      controller: beforeEdit,
      expectedMethod: METHOD
    })
    expect(verified.state).toEqual({ type: 'TestState', value: 1 })
    expect(verified.headControllerVersionIndex).toBe(0)
  })

  it('verifies a ladder-signed tail carrying a inventory-changing version', async () => {
    // The torn ceremony's late-arriving tail: the document entry landed, and
    // the roster append that should have followed it arrives afterwards.
    const { ladder, beforeEdit, afterEdit } = await makeAccount()
    const genesis = await buildResourceLogGenesis({
      state: { type: 'TestState', value: 1 },
      method: METHOD,
      controller: beforeEdit,
      signer: ladder.logSigner
    })
    const tail = await buildResourceLogEntry({
      head: genesis,
      state: { type: 'TestState', value: 2 },
      controller: afterEdit,
      signer: ladder.logSigner
    })
    const verified = await verifyResourceLog({
      entries: [genesis, tail],
      controller: afterEdit,
      expectedMethod: METHOD
    })
    expect(verified.state).toEqual({ type: 'TestState', value: 2 })
    expect(verified.headControllerVersionIndex).toBe(1)
  })

  it('refuses a ladder-signed append at a version the head already carries', async () => {
    const { ladder, beforeEdit } = await makeAccount()
    const genesis = await buildResourceLogGenesis({
      state: { type: 'TestState', value: 1 },
      method: METHOD,
      controller: beforeEdit,
      signer: ladder.logSigner
    })
    const rekey = await buildResourceLogEntry({
      head: genesis,
      state: { type: 'TestState', value: 2 },
      controller: beforeEdit,
      signer: ladder.logSigner
    })
    const caught = await caughtFrom(() =>
      verifyResourceLog({
        entries: [genesis, rekey],
        controller: beforeEdit,
        expectedMethod: METHOD
      })
    )
    expectLicenseRefusal(caught)
    // A license refusal is an admission class of its own: the log is not
    // corrupt, so it must never arrive wrapped as an integrity failure.
    expect(caught).not.toBeInstanceOf(ResourceLogIntegrityError)
  })

  it('leaves an ordinary client-signed append alone at an unchanged version', async () => {
    const { alice, beforeEdit, unchangedEdit } = await makeAccount()
    const genesis = await buildResourceLogGenesis({
      state: { type: 'TestState', value: 1 },
      method: METHOD,
      controller: beforeEdit,
      signer: alice.logSigner
    })
    const append = await buildResourceLogEntry({
      head: genesis,
      state: { type: 'TestState', value: 2 },
      controller: unchangedEdit,
      signer: alice.logSigner
    })
    const verified = await verifyResourceLog({
      entries: [genesis, append],
      controller: unchangedEdit,
      expectedMethod: METHOD
    })
    expect(verified.state).toEqual({ type: 'TestState', value: 2 })
    expect(verified.headControllerVersionIndex).toBe(1)
  })

  it('refuses a second ladder-signed append at an already-spent version', async () => {
    // The licensed rotation lands; a second one against the same document
    // version is exactly what the one-shot rule exists to refuse.
    const { ladder, beforeEdit, afterEdit } = await makeAccount()
    const genesis = await buildResourceLogGenesis({
      state: { type: 'TestState', value: 1 },
      method: METHOD,
      controller: beforeEdit,
      signer: ladder.logSigner
    })
    const licensed = await buildResourceLogEntry({
      head: genesis,
      state: { type: 'TestState', value: 2 },
      controller: afterEdit,
      signer: ladder.logSigner
    })
    const second = await buildResourceLogEntry({
      head: licensed,
      state: { type: 'TestState', value: 3 },
      controller: afterEdit,
      signer: ladder.logSigner
    })
    const caught = await caughtFrom(() =>
      verifyResourceLog({
        entries: [genesis, licensed, second],
        controller: afterEdit,
        expectedMethod: METHOD
      })
    )
    expectLicenseRefusal(caught)
    expect(caught).not.toBeInstanceOf(ResourceLogIntegrityError)
  })
})

describe('logGovernedDescriptorStore (the pre-append license check)', () => {
  /**
   * An epoch-configuration descriptor, the state type the governed store
   * writes into its log entries.
   *
   * @param currentEpoch {string}
   * @returns {CollectionEncryption}
   */
  function descriptorFor(currentEpoch: string): CollectionEncryption {
    return { scheme: 'edv', currentEpoch, epochs: [] }
  }

  /**
   * A ladder-signing store over an in-memory log, plus the controller views
   * before and after a inventory-changing document entry.
   */
  async function makeLadderStore() {
    const ladder = await makeRosterClient()
    const firstVersion = {
      versionId: '1-v1',
      keys: [ladder.signingKeyMultibase],
      ladderKeys: [ladder.signingKeyMultibase],
      inventoryKeys: ['credA']
    }
    const controllerRef: { current: WebvhResourceLogController } = {
      current: fakeController({ versions: [firstVersion] })
    }
    const afterEdit = fakeController({
      versions: [
        firstVersion,
        {
          versionId: '2-v2',
          keys: [ladder.signingKeyMultibase],
          ladderKeys: [ladder.signingKeyMultibase],
          inventoryKeys: ['credB']
        }
      ]
    })
    const log = memoryLogStore()
    const store = logGovernedDescriptorStore({
      log,
      resolveController: async () => controllerRef.current,
      pinStore: memoryResourceLogPinStore(),
      logId: LOG_ID,
      signer: ladder.logSigner
    })
    return { ladder, controllerRef, afterEdit, log, store }
  }

  it('creates the genesis with a ladder signer, no license involved', async () => {
    const { log, store } = await makeLadderStore()
    await store.create!(descriptorFor('did:key:z6LSepochOne'))
    const entries = log._getEntries()!
    expect(entries).toHaveLength(1)
    expect(entries[0]!.state.type).toBe(EPOCH_CONFIGURATION_STATE_TYPE)
    expect((entries[0]!.parameters as { method: string }).method).toBe(
      RESOURCE_LOG_METHOD
    )
  })

  it('refuses a ladder-signed replace against an unchanged document, writing nothing', async () => {
    const { log, store } = await makeLadderStore()
    await store.create!(descriptorFor('did:key:z6LSepochOne'))
    const current = await store.read()
    expect(current).not.toBeNull()
    const before = log._getEntries()!

    const caught = await caughtFrom(() =>
      store.replace(descriptorFor('did:key:z6LSepochTwo'), {
        ifMatch: current!.etag
      })
    )
    expectLicenseRefusal(caught)
    // The check runs BEFORE the append: nothing unlicensed ever reaches the
    // served log, where it would poison every other reader's verification.
    expect(log._getEntries()!).toEqual(before)
  })

  it('refuses a replace by a signer removed at the controller head, writing nothing', async () => {
    // The library's pre-write pass, not the license: an ordinary enrolled
    // client whose key the controller's head no longer lists. Read-back
    // would refuse the entry too, but only after it poisoned the served log.
    const alice = await makeRosterClient()
    const firstVersion = {
      versionId: '1-v1',
      keys: [alice.signingKeyMultibase]
    }
    const controllerRef: { current: WebvhResourceLogController } = {
      current: fakeController({ versions: [firstVersion] })
    }
    const log = memoryLogStore()
    const store = logGovernedDescriptorStore({
      log,
      resolveController: async () => controllerRef.current,
      pinStore: memoryResourceLogPinStore(),
      logId: LOG_ID,
      signer: alice.logSigner
    })
    await store.create!(descriptorFor('did:key:z6LSepochOne'))
    const current = await store.read()
    const before = log._getEntries()!

    controllerRef.current = fakeController({
      versions: [firstVersion, { versionId: '2-v2', keys: [] }]
    })
    const caught = await caughtFrom(() =>
      store.replace(descriptorFor('did:key:z6LSepochTwo'), {
        ifMatch: current!.etag
      })
    )
    expect(caught).toBeInstanceOf(ResourceLogIntegrityError)
    expect((caught as Error).name).toBe('ResourceLogIntegrityError')
    expect(log._getEntries()!).toEqual(before)
  })

  it('admits a ladder-signed replace after a inventory-changing document entry', async () => {
    const { controllerRef, afterEdit, log, store } = await makeLadderStore()
    await store.create!(descriptorFor('did:key:z6LSepochOne'))
    const current = await store.read()

    controllerRef.current = afterEdit
    await store.replace(descriptorFor('did:key:z6LSepochTwo'), {
      ifMatch: current!.etag
    })

    const entries = log._getEntries()!
    expect(entries).toHaveLength(2)
    expect(entries[1]!.proof[0]!.verificationMethod).toContain(
      '?versionId=2-v2'
    )
    const settled = await store.read()
    expect(settled!.descriptor.currentEpoch).toBe('did:key:z6LSepochTwo')
  })

  it('admits the one-write mandatory rotation as the single licensed ladder append', async () => {
    // The transient-recovery continuation's roster half: on a client-less
    // account the ladder VM holds exactly ONE licensed append at the
    // continuation's inventory-changing entry, so the spent-code retirement,
    // both incoming escrows, and the fresh epoch must land in that one
    // append -- `replaceUserKeyRosterRecipients` over the governed store.
    const { controllerRef, afterEdit, log, store } = await makeLadderStore()
    const spentCode = await makeRosterClient()
    const freshCredential = await makeRosterClient()
    const replacementCode = await makeRosterClient()
    const userKey = await mintUserKey()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: spentCode.kak
    })
    expect(log._getEntries()!).toHaveLength(1)

    controllerRef.current = afterEdit
    const rotationArgs = {
      store,
      document: rosterDocumentFor([freshCredential, replacementCode]),
      retireRecipientIds: [spentCode.kak.id],
      recipients: [
        ownerRecipient({ keyAgreementKey: freshCredential.kak }),
        ownerRecipient({ keyAgreementKey: replacementCode.kak })
      ],
      ownerKeyAgreementKey: spentCode.kak
    }
    const descriptor = await replaceUserKeyRosterRecipients(rotationArgs)

    // One licensed append, carrying the inventory-changing version; the
    // rotation append IS the sealing append.
    const entries = log._getEntries()!
    expect(entries).toHaveLength(2)
    expect(entries[1]!.proof[0]!.verificationMethod).toContain(
      '?versionId=2-v2'
    )
    const currentKids = descriptor
      .epochs!.find(epoch => epoch.id === descriptor.currentEpoch)!
      .recipients.map(entry => entry.header.kid)
    expect(currentKids).toContain(freshCredential.kak.id)
    expect(currentKids).toContain(replacementCode.kak.id)
    expect(currentKids).not.toContain(spentCode.kak.id)

    // A naive re-run converges without writing, so it never needs a second
    // license grant.
    const again = await replaceUserKeyRosterRecipients({
      ...rotationArgs,
      ownerKeyAgreementKey: freshCredential.kak
    })
    expect(log._getEntries()!).toHaveLength(2)
    expect(again.currentEpoch).toBe(descriptor.currentEpoch)

    // The one-shot refinement holds: a further ladder-signed write carrying
    // the same spent version refuses before anything reaches the log.
    const current = await store.read()
    const caught = await caughtFrom(() =>
      store.replace(descriptorFor('did:key:z6LSepochThree'), {
        ifMatch: current!.etag
      })
    )
    expectLicenseRefusal(caught)
    expect(log._getEntries()!).toHaveLength(2)
  })
})

describe('webvhResourceLogController.inventoryAt', () => {
  const DID = 'did:webvh:scid:example.com:space:abc:id'
  const CLIENT_SIGNING = 'z6MkClientSigning'
  const CLIENT_TWIN = 'z6LSClientTwin'
  const LADDER = 'z6MkLadder'
  const CREDENTIAL_KEY = 'z6LSPasskeyCredential'
  const CREDENTIAL_COMMITMENT = 'uEiCommitmentOfThePassphraseKey'

  /**
   * A minimal already-verified account log: one enrolled client (its signing
   * method under both invocation and delegation, its key-agreement twin
   * marked with the `did:key` controller), the ladder VM (delegation only),
   * and two credential inventory entries -- one verbatim key, one commitment.
   * The second version drops the commitment entry, so the two versions carry
   * different inventories.
   */
  function makeLog(): DIDLog {
    const verificationMethod = [
      {
        id: `${DID}#${CLIENT_SIGNING}`,
        controller: DID,
        publicKeyMultibase: CLIENT_SIGNING
      },
      {
        id: `${DID}#${CLIENT_TWIN}`,
        controller: `did:key:${CLIENT_SIGNING}`,
        publicKeyMultibase: CLIENT_TWIN
      },
      {
        id: `${DID}#${LADDER}`,
        controller: DID,
        publicKeyMultibase: LADDER
      },
      {
        id: `${DID}#${CREDENTIAL_KEY}`,
        controller: DID,
        publicKeyMultibase: CREDENTIAL_KEY
      },
      {
        id: `${DID}#commitment`,
        controller: DID,
        publicKeyCommitment: CREDENTIAL_COMMITMENT
      }
    ]
    return [
      {
        versionId: '1-v1',
        state: {
          id: DID,
          verificationMethod,
          assertionMethod: [`${DID}#${CLIENT_SIGNING}`, `${DID}#${LADDER}`],
          capabilityInvocation: [`${DID}#${CLIENT_SIGNING}`],
          // The ladder VM is the delegation member with no invocation twin.
          capabilityDelegation: [
            `${DID}#${CLIENT_SIGNING}`,
            `${DID}#${LADDER}`
          ],
          keyAgreement: [
            `${DID}#${CLIENT_TWIN}`,
            `${DID}#${CREDENTIAL_KEY}`,
            `${DID}#commitment`
          ]
        }
      },
      {
        versionId: '2-v2',
        state: {
          id: DID,
          verificationMethod,
          assertionMethod: [`${DID}#${CLIENT_SIGNING}`, `${DID}#${LADDER}`],
          capabilityInvocation: [`${DID}#${CLIENT_SIGNING}`],
          capabilityDelegation: [
            `${DID}#${CLIENT_SIGNING}`,
            `${DID}#${LADDER}`
          ],
          keyAgreement: [`${DID}#${CLIENT_TWIN}`, `${DID}#${CREDENTIAL_KEY}`]
        }
      }
    ] as unknown as DIDLog
  }

  it('recognizes the ladder VM by relation asymmetry', async () => {
    const controller = webvhResourceLogController({ did: DID, log: makeLog() })
    const inventory = await controller.inventoryAt('1-v1')
    expect([...inventory.ladderKeys]).toEqual([LADDER])
    // The enrolled client delegates AND invokes, so it is never a ladder key.
    expect(inventory.ladderKeys.has(CLIENT_SIGNING)).toBe(false)
  })

  it('collects S(V) from the account-controlled keyAgreement entries', async () => {
    const controller = webvhResourceLogController({ did: DID, log: makeLog() })
    const inventory = await controller.inventoryAt('1-v1')
    expect([...inventory.inventoryKeys].sort()).toEqual(
      [LADDER, CREDENTIAL_KEY, CREDENTIAL_COMMITMENT].sort()
    )
    // A client's key-agreement twin carries the did:key controller marker, so
    // enrollment and revocation never register as inventory changes.
    expect(inventory.inventoryKeys.has(CLIENT_TWIN)).toBe(false)
  })

  it('answers from the head version, and refuses an unknown one', async () => {
    const controller = webvhResourceLogController({ did: DID, log: makeLog() })
    const head = await controller.inventoryAt()
    expect([...head.inventoryKeys].sort()).toEqual(
      [LADDER, CREDENTIAL_KEY].sort()
    )
    let caught: unknown = null
    try {
      await controller.inventoryAt('3-v3')
    } catch (err) {
      caught = err
    }
    expect(caught).toBeInstanceOf(ResourceLogIntegrityError)
    expect((caught as Error).name).toBe('ResourceLogIntegrityError')
  })

  // The adapter is what supplies the library's admitAppend hook: the license
  // lives here, not in the library's verifier (a hook-less controller admits
  // every membership-backed append -- the library's own suite pins that).
  describe('the admitAppend hook', () => {
    it('admits an ordinary client-signed append untouched', async () => {
      const controller = webvhResourceLogController({
        did: DID,
        log: makeLog()
      })
      await controller.admitAppend({
        ordinal: 2,
        keyMultibase: CLIENT_SIGNING,
        controllerVersionId: '2-v2',
        controllerVersionIndex: 1,
        headControllerVersionIndex: 1
      })
    })

    it('licenses a ladder-signed append at the inventory-changing version', async () => {
      // makeLog()'s second version drops the commitment entry, so carrying
      // it with the head still behind it is the licensed one-shot.
      const controller = webvhResourceLogController({
        did: DID,
        log: makeLog()
      })
      await controller.admitAppend({
        ordinal: 2,
        keyMultibase: LADDER,
        controllerVersionId: '2-v2',
        controllerVersionIndex: 1,
        headControllerVersionIndex: 0
      })
    })

    it('refuses an unlicensed ladder-signed append with the license class intact', async () => {
      const controller = webvhResourceLogController({
        did: DID,
        log: makeLog()
      })
      const caught = await caughtFrom(() =>
        controller.admitAppend({
          ordinal: 3,
          keyMultibase: LADDER,
          controllerVersionId: '2-v2',
          controllerVersionIndex: 1,
          // The head already carries the change: the one-shot is spent.
          headControllerVersionIndex: 1
        })
      )
      expectLicenseRefusal(caught)
    })
  })
})
