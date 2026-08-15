/**
 * Unit tests for the resource-log read/append/create path
 * (`src/resourceLog/append.ts`) over the in-memory store fixture: pin advance
 * on read, the guarded genesis create with lost-race adoption, the append's
 * CAS rebase-and-retry loop (`buildState` re-invoked on the new head), the
 * `null` convergence signal, the closed-log refusal, and the fail-closed
 * refusals of a missing validator and an absent log. Plus the keyed pin seam
 * itself: the `resourceLogPinId` slot key and the per-log independence one
 * store instance must keep across the several logs a wallet holds.
 */
import { describe, expect, it } from 'vitest'
import {
  appendResourceLog,
  createResourceLog,
  memoryResourceLogPinStore,
  readResourceLog,
  resourceLogPinId,
  ResourceLogClosedError,
  type VerifiedResourceLog
} from '../../src/resourceLog/index.js'
import { makeRosterClient } from './fixtures/rosterClient.js'
import {
  buildTerminalEntry,
  fakeController,
  memoryLogStore
} from './fixtures/resourceLog.js'

const METHOD = 'resource-log:0.1'
const LOG_ID = resourceLogPinId({
  spaceId: 'space-under-test',
  collectionId: 'key-map',
  resourceId: 'test-log.jsonl'
})

/**
 * One enrolled client, its single-version controller view, a fresh store and
 * pin store -- the writer setup every case below starts from.
 */
async function makeWriter() {
  const alice = await makeRosterClient()
  const controller = fakeController({
    versions: [{ versionId: '1-v1', keys: [alice.signingKeyMultibase] }]
  })
  const store = memoryLogStore()
  const pinStore = memoryResourceLogPinStore()
  return { alice, controller, store, pinStore }
}

describe('resourceLogPinId', () => {
  it('builds the documented space/collection/resource slot key', () => {
    expect(
      resourceLogPinId({
        spaceId: 'urn:uuid:space',
        collectionId: 'key-map',
        resourceId: 'user-key.jsonl'
      })
    ).toBe('space/urn:uuid:space/key-map/user-key.jsonl')
  })

  it('never collides across two accounts holding the same log resource', () => {
    const slot = (spaceId: string) =>
      resourceLogPinId({
        spaceId,
        collectionId: 'id',
        resourceId: 'did.jsonl'
      })
    expect(slot('space-one')).not.toBe(slot('space-two'))
  })
})

describe('memoryResourceLogPinStore', () => {
  it('keeps the pins of one store instance independent per logId', async () => {
    const { alice, controller, store, pinStore } = await makeWriter()
    const otherLogId = resourceLogPinId({
      spaceId: 'space-under-test',
      collectionId: 'id',
      resourceId: 'did.jsonl'
    })

    const { verified } = await createResourceLog({
      store,
      controller,
      method: METHOD,
      pinStore,
      logId: LOG_ID,
      signer: alice.logSigner,
      state: { type: 'TestState', value: 1 }
    })

    // The written slot holds this log's pin; the sibling slot is untouched,
    // so a second log's first contact is still a first contact.
    expect(await pinStore.read({ logId: LOG_ID })).toEqual(verified.pin)
    expect(await pinStore.read({ logId: otherLogId })).toBeNull()

    // The second log, served through the SAME store, pins beside the first
    // rather than over it.
    const second = await makeWriter()
    const { verified: otherVerified } = await createResourceLog({
      store: second.store,
      controller: second.controller,
      method: METHOD,
      pinStore,
      logId: otherLogId,
      signer: second.alice.logSigner,
      state: { type: 'TestState', value: 2 }
    })
    expect(await pinStore.read({ logId: otherLogId })).toEqual(
      otherVerified.pin
    )
    expect(await pinStore.read({ logId: LOG_ID })).toEqual(verified.pin)
  })
})

describe('readResourceLog', () => {
  it('resolves null on an absent log (the pre-genesis state)', async () => {
    const { controller, store, pinStore } = await makeWriter()
    expect(
      await readResourceLog({
        store,
        controller,
        expectedMethod: METHOD,
        pinStore,
        logId: LOG_ID
      })
    ).toBeNull()
    expect(await pinStore.read({ logId: LOG_ID })).toBeNull()
  })

  it('verifies, returns the etag, and advances the pin', async () => {
    const { alice, controller, store, pinStore } = await makeWriter()
    const { verified: created } = await createResourceLog({
      store,
      controller,
      method: METHOD,
      pinStore,
      logId: LOG_ID,
      signer: alice.logSigner,
      state: { type: 'TestState', value: 1 }
    })
    const read = await readResourceLog({
      store,
      controller,
      expectedMethod: METHOD,
      pinStore,
      logId: LOG_ID
    })
    expect(read).not.toBeNull()
    expect(read!.verified.state).toEqual({ type: 'TestState', value: 1 })
    expect(read!.etag).toBeDefined()
    expect(await pinStore.read({ logId: LOG_ID })).toEqual(created.pin)
  })

  it('refuses a rollback on a later read (the pin never regresses)', async () => {
    const { alice, controller, store, pinStore } = await makeWriter()
    await createResourceLog({
      store,
      controller,
      method: METHOD,
      pinStore,
      logId: LOG_ID,
      signer: alice.logSigner,
      state: { type: 'TestState', value: 1 }
    })
    await appendResourceLog({
      store,
      controller,
      expectedMethod: METHOD,
      pinStore,
      logId: LOG_ID,
      signer: alice.logSigner,
      buildState: () => ({ type: 'TestState', value: 2 })
    })
    // The host replays the one-entry log from before the append.
    const genesisOnly = store._getEntries()!.slice(0, 1)
    store._setEntries(genesisOnly)
    await expect(
      readResourceLog({
        store,
        controller,
        expectedMethod: METHOD,
        pinStore,
        logId: LOG_ID
      })
    ).rejects.toMatchObject({
      name: 'ResourceLogContinuityError',
      reason: 'rollback'
    })
  })
})

describe('createResourceLog', () => {
  it('creates the genesis, confirms by read-back, and establishes the pin', async () => {
    const { alice, controller, store, pinStore } = await makeWriter()
    const { verified, created } = await createResourceLog({
      store,
      controller,
      method: METHOD,
      pinStore,
      logId: LOG_ID,
      signer: alice.logSigner,
      state: { type: 'TestState', value: 1 }
    })
    expect(created).toBe(true)
    expect(verified.entries).toHaveLength(1)
    expect(store._getEntries()).toEqual(verified.entries)
    expect(await pinStore.read({ logId: LOG_ID })).toEqual(verified.pin)
  })

  it('adopts the winner on a lost guarded-create race', async () => {
    const { controller, store, pinStore } = await makeWriter()
    const bob = await makeRosterClient()
    const bothController = fakeController({
      versions: [
        {
          versionId: '1-v1',
          keys: [
            ...(await controller.assertionKeysAt('1-v1')),
            bob.signingKeyMultibase
          ]
        }
      ]
    })
    // The winner (bob) creates first...
    const winner = await createResourceLog({
      store,
      controller: bothController,
      method: METHOD,
      pinStore: memoryResourceLogPinStore(),
      logId: LOG_ID,
      signer: bob.logSigner,
      state: { type: 'TestState', value: 42 }
    })
    // ...and the loser's create adopts the served log instead of clobbering.
    const alice = await makeRosterClient()
    const aliceController = fakeController({
      versions: [
        {
          versionId: '1-v1',
          keys: [alice.signingKeyMultibase, bob.signingKeyMultibase]
        }
      ]
    })
    const { verified, created } = await createResourceLog({
      store,
      controller: aliceController,
      method: METHOD,
      pinStore,
      logId: LOG_ID,
      signer: alice.logSigner,
      state: { type: 'TestState', value: 1 }
    })
    expect(created).toBe(false)
    expect(verified.scid).toBe(winner.verified.scid)
    expect(verified.state).toEqual({ type: 'TestState', value: 42 })
    expect(await pinStore.read({ logId: LOG_ID })).toEqual(verified.pin)
  })
})

describe('appendResourceLog', () => {
  it('appends against the verified head and confirms by read-back', async () => {
    const { alice, controller, store, pinStore } = await makeWriter()
    await createResourceLog({
      store,
      controller,
      method: METHOD,
      pinStore,
      logId: LOG_ID,
      signer: alice.logSigner,
      state: { type: 'TestState', value: 1 }
    })
    const heads: unknown[] = []
    const confirmed = await appendResourceLog({
      store,
      controller,
      expectedMethod: METHOD,
      pinStore,
      logId: LOG_ID,
      signer: alice.logSigner,
      buildState: verified => {
        heads.push(verified.state)
        return { type: 'TestState', value: 2 }
      }
    })
    expect(heads).toEqual([{ type: 'TestState', value: 1 }])
    expect(confirmed.entries).toHaveLength(2)
    expect(confirmed.state).toEqual({ type: 'TestState', value: 2 })
    expect(await pinStore.read({ logId: LOG_ID })).toEqual(confirmed.pin)
  })

  it('converges without a write when buildState resolves null', async () => {
    const { alice, controller, store, pinStore } = await makeWriter()
    await createResourceLog({
      store,
      controller,
      method: METHOD,
      pinStore,
      logId: LOG_ID,
      signer: alice.logSigner,
      state: { type: 'TestState', value: 1 }
    })
    const before = store._getEntries()
    const verified = await appendResourceLog({
      store,
      controller,
      expectedMethod: METHOD,
      pinStore,
      logId: LOG_ID,
      signer: alice.logSigner,
      buildState: () => null
    })
    expect(verified.entries).toHaveLength(1)
    expect(store._getEntries()).toEqual(before)
  })

  it('rebases and retries when a concurrent append wins the CAS', async () => {
    const { alice, store, pinStore } = await makeWriter()
    const bob = await makeRosterClient()
    const bothController = fakeController({
      versions: [
        {
          versionId: '1-v1',
          keys: [alice.signingKeyMultibase, bob.signingKeyMultibase]
        }
      ]
    })
    await createResourceLog({
      store,
      controller: bothController,
      method: METHOD,
      pinStore,
      logId: LOG_ID,
      signer: alice.logSigner,
      state: { type: 'TestState', value: 1 }
    })
    // Between alice's read and her append, bob lands an entry: her CAS loses
    // and the loop re-reads, rebases on bob's head, and retries.
    let raced = false
    const racingStore = {
      ...store,
      async append(
        entry: Parameters<typeof store.append>[0],
        options: Parameters<typeof store.append>[1]
      ) {
        if (!raced) {
          raced = true
          await appendResourceLog({
            store,
            controller: bothController,
            expectedMethod: METHOD,
            pinStore: memoryResourceLogPinStore(),
            logId: LOG_ID,
            signer: bob.logSigner,
            buildState: () => ({ type: 'TestState', value: 100 })
          })
        }
        return store.append(entry, options)
      }
    }
    const rebasedOn: unknown[] = []
    const confirmed = await appendResourceLog({
      store: racingStore,
      controller: bothController,
      expectedMethod: METHOD,
      pinStore,
      logId: LOG_ID,
      signer: alice.logSigner,
      buildState: (verified: VerifiedResourceLog) => {
        rebasedOn.push(verified.state)
        return {
          type: 'TestState',
          value: (verified.state.value as number) + 1
        }
      }
    })
    // First attempt built on value 1; the retry rebased on bob's value 100.
    expect(rebasedOn).toEqual([
      { type: 'TestState', value: 1 },
      { type: 'TestState', value: 100 }
    ])
    expect(confirmed.entries).toHaveLength(3)
    expect(confirmed.state).toEqual({ type: 'TestState', value: 101 })
  })

  it('gives up after maxAttempts lost races, with the conflict as cause', async () => {
    const { alice, controller, store, pinStore } = await makeWriter()
    await createResourceLog({
      store,
      controller,
      method: METHOD,
      pinStore,
      logId: LOG_ID,
      signer: alice.logSigner,
      state: { type: 'TestState', value: 1 }
    })
    // Every append attempt loses: another writer bumps the store version
    // between the read and the CAS, forever.
    const contestedStore = {
      ...store,
      async append() {
        const entries = store._getEntries()!
        store._setEntries(entries)
        return store.append(entries[0]!, { ifMatch: 'stale' })
      }
    }
    await expect(
      appendResourceLog({
        store: contestedStore,
        controller,
        expectedMethod: METHOD,
        pinStore,
        logId: LOG_ID,
        signer: alice.logSigner,
        buildState: () => ({ type: 'TestState', value: 2 }),
        maxAttempts: 2
      })
    ).rejects.toThrow(/lost the compare-and-swap race 2 times/)
  })

  it('refuses to append to an absent log', async () => {
    const { alice, controller, store, pinStore } = await makeWriter()
    await expect(
      appendResourceLog({
        store,
        controller,
        expectedMethod: METHOD,
        pinStore,
        logId: LOG_ID,
        signer: alice.logSigner,
        buildState: () => ({ type: 'TestState', value: 1 })
      })
    ).rejects.toThrow(/does not exist yet/)
  })

  it('refuses to append without a validator (no unconditional writes)', async () => {
    const { alice, controller, store, pinStore } = await makeWriter()
    await createResourceLog({
      store,
      controller,
      method: METHOD,
      pinStore,
      logId: LOG_ID,
      signer: alice.logSigner,
      state: { type: 'TestState', value: 1 }
    })
    store._withholdEtag(true)
    await expect(
      appendResourceLog({
        store,
        controller,
        expectedMethod: METHOD,
        pinStore,
        logId: LOG_ID,
        signer: alice.logSigner,
        buildState: () => ({ type: 'TestState', value: 2 })
      })
    ).rejects.toThrow(/no validator/)
  })

  it('refuses to extend a log closed by a terminal handover entry', async () => {
    const { alice, controller, store, pinStore } = await makeWriter()
    await createResourceLog({
      store,
      controller,
      method: METHOD,
      pinStore,
      logId: LOG_ID,
      signer: alice.logSigner,
      state: { type: 'TestState', value: 1 }
    })
    const entries = store._getEntries()!
    const terminal = await buildTerminalEntry({
      head: entries[entries.length - 1]!,
      nextLog: { method: METHOD, scid: 'QmSuccessorScid' },
      controller,
      signer: alice.logSigner
    })
    store._setEntries([...entries, terminal])
    let refusal: unknown
    try {
      await appendResourceLog({
        store,
        controller,
        expectedMethod: METHOD,
        pinStore,
        logId: LOG_ID,
        signer: alice.logSigner,
        buildState: () => ({ type: 'TestState', value: 2 })
      })
    } catch (err) {
      refusal = err
    }
    expect(refusal).toBeInstanceOf(ResourceLogClosedError)
    expect((refusal as ResourceLogClosedError).nextLog).toEqual({
      method: METHOD,
      scid: 'QmSuccessorScid'
    })
  })
})
