/**
 * Tests for the sealing sweep (`src/resourceLog/seal.ts`): the membership-
 * change detection over the controller view, the unsealed-head detection via
 * the verifier's `headAnchorIndex`, the idempotent backstop append, the
 * closed-log refusal, and the shapes that must NOT register as removals (a
 * growth-only history -- the recovery-spend shape -- and an unversioned
 * controller).
 */
import { describe, expect, it } from 'vitest'
import {
  createResourceLog,
  latestAssertionRemovalIndex,
  memoryResourceLogPinStore,
  readResourceLog,
  ResourceLogClosedError,
  sealResourceLog,
  type ResourceLogController
} from '../../src/resourceLog/index.js'
import { makeRosterClient } from './fixtures/rosterClient.js'
import {
  buildTerminalEntry,
  fakeController,
  memoryLogStore
} from './fixtures/resourceLog.js'

const METHOD = 'was-resource-log-test'
const STATE = { type: 'TestState', value: 1 }

/**
 * One account under test: an enrolled writer (alice), a revocable second
 * client (bob), the pre-edit controller (bob still keyed), and the post-edit
 * controller (bob's assertion key removed at version 2-v2).
 */
async function makeAccount() {
  const alice = await makeRosterClient()
  const bob = await makeRosterClient()
  const preEdit = fakeController({
    versions: [
      {
        versionId: '1-v1',
        keys: [alice.signingKeyMultibase, bob.signingKeyMultibase]
      }
    ]
  })
  const postEdit = fakeController({
    versions: [
      {
        versionId: '1-v1',
        keys: [alice.signingKeyMultibase, bob.signingKeyMultibase]
      },
      { versionId: '2-v2', keys: [alice.signingKeyMultibase] }
    ]
  })
  return { alice, bob, preEdit, postEdit }
}

/**
 * Creates a log whose genesis is anchored at the given controller's head.
 */
async function makeLog({
  controller,
  signer
}: {
  controller: ResourceLogController
  signer: Awaited<ReturnType<typeof makeRosterClient>>['logSigner']
}) {
  const store = memoryLogStore()
  const pinStore = memoryResourceLogPinStore()
  await createResourceLog({
    store,
    controller,
    method: METHOD,
    pinStore,
    signer,
    state: STATE
  })
  return { store, pinStore }
}

describe('latestAssertionRemovalIndex', () => {
  it('resolves 0 when no version ever removed an assertion key', async () => {
    const { preEdit } = await makeAccount()
    expect(await latestAssertionRemovalIndex({ controller: preEdit })).toBe(0)
  })

  it('finds the version that lost a member', async () => {
    const { postEdit } = await makeAccount()
    expect(await latestAssertionRemovalIndex({ controller: postEdit })).toBe(1)
  })

  it('resolves the LATEST removal across several', async () => {
    const controller = fakeController({
      versions: [
        { versionId: '1-v1', keys: ['zA', 'zB', 'zC'] },
        { versionId: '2-v2', keys: ['zA', 'zC'] },
        { versionId: '3-v3', keys: ['zA', 'zC', 'zD'] },
        { versionId: '4-v4', keys: ['zA', 'zD'] }
      ]
    })
    expect(await latestAssertionRemovalIndex({ controller })).toBe(3)
  })

  it('registers no removal for a growth-only history (the recovery-spend shape)', async () => {
    // A spent recovery code's verification method was keyAgreement-only, so
    // the spend's add-and-retire entry only ever GROWS the assertionMethod
    // set (the new client in); its sealing is the mandatory rotation itself.
    const controller = fakeController({
      versions: [
        { versionId: '1-v1', keys: ['zA'] },
        { versionId: '2-v2', keys: ['zA', 'zNewClient'] }
      ]
    })
    expect(await latestAssertionRemovalIndex({ controller })).toBe(0)
  })

  it('resolves 0 on an unversioned controller', async () => {
    const controller = fakeController({ versions: [], currentKeys: ['zA'] })
    expect(await latestAssertionRemovalIndex({ controller })).toBe(0)
  })
})

describe('sealResourceLog', () => {
  it('detects an unsealed log and appends the backstop entry, verbatim state', async () => {
    const { alice, preEdit, postEdit } = await makeAccount()
    const { store, pinStore } = await makeLog({
      controller: preEdit,
      signer: alice.logSigner
    })

    const result = await sealResourceLog({
      store,
      controller: postEdit,
      expectedMethod: METHOD,
      pinStore,
      signer: alice.logSigner
    })

    expect(result.sealed).toBe(true)
    const entries = store._getEntries()!
    expect(entries).toHaveLength(2)
    // The backstop entry changes no resource state and anchors post-removal.
    expect(entries[1]!.state).toEqual(entries[0]!.state)
    expect(entries[1]!.proof[0]!.verificationMethod).toContain(
      '?versionId=2-v2'
    )
    expect(result.verified!.headAnchorIndex).toBe(1)
  })

  it('is idempotent: a second sweep writes nothing', async () => {
    const { alice, preEdit, postEdit } = await makeAccount()
    const { store, pinStore } = await makeLog({
      controller: preEdit,
      signer: alice.logSigner
    })
    await sealResourceLog({
      store,
      controller: postEdit,
      expectedMethod: METHOD,
      pinStore,
      signer: alice.logSigner
    })

    const again = await sealResourceLog({
      store,
      controller: postEdit,
      expectedMethod: METHOD,
      pinStore,
      signer: alice.logSigner
    })
    expect(again.sealed).toBe(false)
    expect(store._getEntries()!).toHaveLength(2)
  })

  it('no-ops when the head already anchors at the removal (an ordinary post-edit write sealed it)', async () => {
    const { alice, postEdit } = await makeAccount()
    // The log's only entry is already anchored at the post-edit head.
    const { store, pinStore } = await makeLog({
      controller: postEdit,
      signer: alice.logSigner
    })

    const result = await sealResourceLog({
      store,
      controller: postEdit,
      expectedMethod: METHOD,
      pinStore,
      signer: alice.logSigner
    })
    expect(result.sealed).toBe(false)
    expect(store._getEntries()!).toHaveLength(1)
  })

  it('no-ops without touching the log when the controller never removed a member', async () => {
    const { alice, preEdit } = await makeAccount()
    const { store, pinStore } = await makeLog({
      controller: preEdit,
      signer: alice.logSigner
    })

    const result = await sealResourceLog({
      store,
      controller: preEdit,
      expectedMethod: METHOD,
      pinStore,
      signer: alice.logSigner
    })
    expect(result).toEqual({ sealed: false, verified: null })
    expect(store._getEntries()!).toHaveLength(1)
  })

  it('no-ops on an unversioned controller (anchors do not exist there)', async () => {
    const alice = await makeRosterClient()
    const unversioned = fakeController({
      versions: [],
      currentKeys: [alice.signingKeyMultibase]
    })
    const { store, pinStore } = await makeLog({
      controller: unversioned,
      signer: alice.logSigner
    })

    const result = await sealResourceLog({
      store,
      controller: unversioned,
      expectedMethod: METHOD,
      pinStore,
      signer: alice.logSigner
    })
    expect(result).toEqual({ sealed: false, verified: null })
  })

  it('no-ops on an absent log (nothing exists to seal)', async () => {
    const { alice, postEdit } = await makeAccount()
    const result = await sealResourceLog({
      store: memoryLogStore(),
      controller: postEdit,
      expectedMethod: METHOD,
      pinStore: memoryResourceLogPinStore(),
      signer: alice.logSigner
    })
    expect(result).toEqual({ sealed: false, verified: null })
  })

  it('propagates ResourceLogClosedError on an unsealed closed log', async () => {
    const { alice, preEdit, postEdit } = await makeAccount()
    const { store, pinStore } = await makeLog({
      controller: preEdit,
      signer: alice.logSigner
    })
    // The log's authors close it (still anchored pre-edit), then the edit
    // removes a member: the seal cannot extend a closed history.
    const head = store._getEntries()![0]!
    const terminal = await buildTerminalEntry({
      head,
      nextLog: { method: METHOD, scid: 'QmSuccessor' },
      controller: preEdit,
      signer: alice.logSigner
    })
    store._setEntries([head, terminal])

    await expect(
      sealResourceLog({
        store,
        controller: postEdit,
        expectedMethod: METHOD,
        pinStore,
        signer: alice.logSigner
      })
    ).rejects.toThrow(ResourceLogClosedError)
  })
})

describe('VerifiedResourceLog.headAnchorIndex', () => {
  it('reports the head anchor as an index into the controller versions', async () => {
    const { alice, preEdit, postEdit } = await makeAccount()
    const { store, pinStore } = await makeLog({
      controller: preEdit,
      signer: alice.logSigner
    })
    const read = await readResourceLog({
      store,
      controller: postEdit,
      expectedMethod: METHOD,
      pinStore
    })
    expect(read!.verified.headAnchorIndex).toBe(0)
  })

  it('is null on an unversioned controller', async () => {
    const alice = await makeRosterClient()
    const unversioned = fakeController({
      versions: [],
      currentKeys: [alice.signingKeyMultibase]
    })
    const { store, pinStore } = await makeLog({
      controller: unversioned,
      signer: alice.logSigner
    })
    const read = await readResourceLog({
      store,
      controller: unversioned,
      expectedMethod: METHOD,
      pinStore
    })
    expect(read!.verified.headAnchorIndex).toBeNull()
  })
})
