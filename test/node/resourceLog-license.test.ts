/**
 * Tests for the ceremony-tail license on ladder-signed resource-log appends
 * (`src/resourceLog/license.ts`, clause B of the ladder VM's authority
 * clauses): the two admitted shapes -- the log's first entry, and a rotation
 * anchored at a posture-changing controller-document version that no verified
 * entry already anchors at or past -- and the refusals around them, above all
 * the silent-rekey shape (a ladder-signed rotation against an unchanged
 * document). The license is exercised at all three seams it lives on: the
 * predicate itself over a fake controller, the read path through
 * `verifyResourceLog` on real signed logs, and the write path's pre-append
 * admission check in the log-governed descriptor store. Plus the posture view
 * the whole rule reads from -- the did:webvh adapter's `postureAt`, its
 * ladder recognition by relation asymmetry and its exclusion of enrolled
 * clients' key-agreement twins.
 */
import { describe, expect, it } from 'vitest'
import type { DIDLog } from '@interop/did-method-webvh'
import type { CollectionEncryption } from '@interop/was-client'
import { RESOURCE_LOG_METHOD } from '@interop/was-client/log'
import {
  EPOCH_CONFIGURATION_STATE_TYPE,
  logGovernedDescriptorStore
} from '../../src/keys/rosterLogStore.js'
import { userKeyRosterPinId } from '../../src/keys/rosterStore.js'
import {
  assertLadderAppendLicensed,
  buildResourceLogEntry,
  buildResourceLogGenesis,
  memoryResourceLogPinStore,
  ResourceLogIntegrityError,
  ResourceLogLicenseError,
  verifyResourceLog,
  webvhResourceLogController,
  type ResourceLogController
} from '../../src/resourceLog/index.js'
import { makeRosterClient } from './fixtures/rosterClient.js'
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
  it('licenses an append anchored at a posture-changing version', async () => {
    const controller = fakeController({
      versions: [
        { versionId: '1-v1', keys: ['zLadder'], postureKeys: ['credA'] },
        { versionId: '2-v2', keys: ['zLadder'], postureKeys: ['credB'] }
      ]
    })
    await expect(
      assertLadderAppendLicensed({
        controller,
        anchorIndex: 1,
        headAnchorIndex: 0
      })
    ).resolves.toBeUndefined()
  })

  it('refuses a rotation against an unchanged posture (the silent rekey)', async () => {
    // The document entry landed, but it changed no credential posture: the
    // ladder cannot rotate the roster off the back of it.
    const controller = fakeController({
      versions: [
        { versionId: '1-v1', keys: ['zLadder'], postureKeys: ['credA'] },
        { versionId: '2-v2', keys: ['zLadder'], postureKeys: ['credA'] }
      ]
    })
    const caught = await caughtFrom(() =>
      assertLadderAppendLicensed({
        controller,
        anchorIndex: 1,
        headAnchorIndex: 0
      })
    )
    expectLicenseRefusal(caught)
    expect((caught as Error).message).toContain('did not change')
  })

  it('is one-shot: refuses a head anchored at or past the change', async () => {
    const controller = fakeController({
      versions: [
        { versionId: '1-v1', keys: ['zLadder'], postureKeys: ['credA'] },
        { versionId: '2-v2', keys: ['zLadder'], postureKeys: ['credB'] },
        { versionId: '3-v3', keys: ['zLadder'], postureKeys: ['credC'] }
      ]
    })
    const atTheChange = await caughtFrom(() =>
      assertLadderAppendLicensed({
        controller,
        anchorIndex: 1,
        headAnchorIndex: 1
      })
    )
    expectLicenseRefusal(atTheChange)
    const pastTheChange = await caughtFrom(() =>
      assertLadderAppendLicensed({
        controller,
        anchorIndex: 1,
        headAnchorIndex: 2
      })
    )
    expectLicenseRefusal(pastTheChange)
  })

  it('licenses the genesis version when its posture is non-empty', async () => {
    // S(-1) is empty, so a first version carrying any posture member is
    // itself posture-changing.
    const controller = fakeController({
      versions: [
        { versionId: '1-v1', keys: ['zLadder'], postureKeys: ['credA'] }
      ]
    })
    await expect(
      assertLadderAppendLicensed({
        controller,
        anchorIndex: 0,
        headAnchorIndex: null
      })
    ).resolves.toBeUndefined()
  })

  it('refuses an unanchored append fail-closed', async () => {
    const controller = fakeController({
      versions: [],
      currentKeys: ['zLadder']
    })
    const caught = await caughtFrom(() =>
      assertLadderAppendLicensed({
        controller,
        anchorIndex: null,
        headAnchorIndex: null
      })
    )
    expectLicenseRefusal(caught)
    expect((caught as Error).message).toContain('anchor')
  })

  it('licenses a posture change in the removal direction', async () => {
    // Retiring a credential is as much a posture change as adding one; the
    // comparison is set inequality in either direction.
    const controller = fakeController({
      versions: [
        {
          versionId: '1-v1',
          keys: ['zLadder'],
          postureKeys: ['credA', 'credB']
        },
        { versionId: '2-v2', keys: ['zLadder'], postureKeys: ['credA'] }
      ]
    })
    await expect(
      assertLadderAppendLicensed({
        controller,
        anchorIndex: 1,
        headAnchorIndex: 0
      })
    ).resolves.toBeUndefined()
  })
})

describe('verifyResourceLog (the ceremony-tail license end to end)', () => {
  /**
   * An account whose document backs one enrolled client (alice) and one
   * ladder VM, with the two controller views a ceremony sees: before the
   * posture-changing document entry, and after it.
   */
  async function makeAccount() {
    const alice = await makeRosterClient()
    const ladder = await makeRosterClient()
    const firstVersion = {
      versionId: '1-v1',
      keys: [alice.signingKeyMultibase, ladder.signingKeyMultibase],
      ladderKeys: [ladder.signingKeyMultibase],
      postureKeys: ['credA']
    }
    const beforeEdit = fakeController({ versions: [firstVersion] })
    const afterEdit = fakeController({
      versions: [
        firstVersion,
        {
          versionId: '2-v2',
          keys: [alice.signingKeyMultibase, ladder.signingKeyMultibase],
          ladderKeys: [ladder.signingKeyMultibase],
          postureKeys: ['credB']
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
          postureKeys: ['credA']
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
    expect(verified.headAnchorIndex).toBe(0)
  })

  it('verifies a ladder-signed tail anchored at a posture-changing version', async () => {
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
    expect(verified.headAnchorIndex).toBe(1)
  })

  it('refuses a ladder-signed append anchored where the head already anchors', async () => {
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
    expect(verified.headAnchorIndex).toBe(1)
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
   * before and after a posture-changing document entry.
   */
  async function makeLadderStore() {
    const ladder = await makeRosterClient()
    const firstVersion = {
      versionId: '1-v1',
      keys: [ladder.signingKeyMultibase],
      ladderKeys: [ladder.signingKeyMultibase],
      postureKeys: ['credA']
    }
    const controllerRef: { current: ResourceLogController } = {
      current: fakeController({ versions: [firstVersion] })
    }
    const afterEdit = fakeController({
      versions: [
        firstVersion,
        {
          versionId: '2-v2',
          keys: [ladder.signingKeyMultibase],
          ladderKeys: [ladder.signingKeyMultibase],
          postureKeys: ['credB']
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

  it('admits a ladder-signed replace after a posture-changing document entry', async () => {
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
})

describe('webvhResourceLogController.postureAt', () => {
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
   * and two credential posture entries -- one verbatim key, one commitment.
   * The second version drops the commitment entry, so the two versions carry
   * different postures.
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
    const posture = await controller.postureAt('1-v1')
    expect([...posture.ladderKeys]).toEqual([LADDER])
    // The enrolled client delegates AND invokes, so it is never a ladder key.
    expect(posture.ladderKeys.has(CLIENT_SIGNING)).toBe(false)
  })

  it('collects S(V) from the account-controlled keyAgreement entries', async () => {
    const controller = webvhResourceLogController({ did: DID, log: makeLog() })
    const posture = await controller.postureAt('1-v1')
    expect([...posture.postureKeys].sort()).toEqual(
      [LADDER, CREDENTIAL_KEY, CREDENTIAL_COMMITMENT].sort()
    )
    // A client's key-agreement twin carries the did:key controller marker, so
    // enrollment and revocation never register as posture changes.
    expect(posture.postureKeys.has(CLIENT_TWIN)).toBe(false)
  })

  it('answers from the head version, and refuses an unknown one', async () => {
    const controller = webvhResourceLogController({ did: DID, log: makeLog() })
    const head = await controller.postureAt()
    expect([...head.postureKeys].sort()).toEqual(
      [LADDER, CREDENTIAL_KEY].sort()
    )
    let caught: unknown = null
    try {
      await controller.postureAt('3-v3')
    } catch (err) {
      caught = err
    }
    expect(caught).toBeInstanceOf(ResourceLogIntegrityError)
    expect((caught as Error).name).toBe('ResourceLogIntegrityError')
  })
})
