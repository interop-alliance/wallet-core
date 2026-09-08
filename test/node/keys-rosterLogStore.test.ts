/**
 * Integration tests for the log-governed descriptor store
 * (`src/keys/rosterLogStore.ts`): the roster's ensure/add/rotate/read flows
 * driven through was-client's recipient machinery over a resource log, with a
 * fake controller standing in for the verified did:webvh document. The WC-1
 * provenance properties are re-proven at this layer: a fabricated or spliced
 * served log is refused on read (there is no read path around the verifier),
 * a head state of a foreign `type` is refused as a descriptor, writes carry
 * the controller head resolved per operation, and a CAS conflict surfaces
 * as the `PreconditionFailedError` the edv rebase loops drive on. The log
 * class the store states at construction is exercised at the end: it decides
 * the admission rule every resolved view carries, the minimum a ceremony set
 * included.
 */
import { describe, expect, it, vi } from 'vitest'
import { PreconditionFailedError } from '@interop/was-client'
import { RESOURCE_LOG_METHOD } from '@interop/storage-core'
import {
  EPOCH_CONFIGURATION_STATE_TYPE,
  isSealableDescriptorStore,
  logGovernedDescriptorStore
} from '../../src/keys/rosterLogStore.js'
import { userKeyRosterPinId } from '../../src/keys/rosterStore.js'
import { mintUserKey } from '../../src/keys/userKey.js'
import {
  addUserKeyRosterRecipient,
  ensureUserKeyRoster,
  readUserKeyRoster,
  rotateUserKeyRoster
} from '../../src/keys/userKeyRoster.js'
import {
  buildResourceLogEntry,
  buildResourceLogGenesis,
  memoryResourceLogPinStore,
  ResourceLogContinuityError,
  ResourceLogIntegrityError
} from '@interop/vh-resource-log'
import type { WebvhResourceLogController } from '../../src/resourceLog/index.js'
import {
  makeRosterClient as makeClient,
  rosterDocumentFor as documentFor,
  type RosterTestClient
} from './fixtures/rosterClient.js'
import {
  descriptorFor,
  fakeController,
  ladderDescriptorStore,
  memoryLogStore
} from './fixtures/resourceLog.js'

const LOG_ID = userKeyRosterPinId({ spaceId: 'space-under-test' })

/**
 * One account: an enrolled writing client (alice), a mutable controller view
 * (grown by "document edits" mid-test), the in-memory log, and the governed
 * store built over them.
 */
async function makeAccount() {
  const alice = await makeClient()
  const controllerRef: { current: WebvhResourceLogController } = {
    current: fakeController({
      versions: [{ versionId: '1-v1', keys: [alice.signingKeyMultibase] }]
    })
  }
  const log = memoryLogStore()
  const pinStore = memoryResourceLogPinStore()
  const store = logGovernedDescriptorStore({
    log,
    resolveController: async () => controllerRef.current,
    pinStore,
    logId: LOG_ID,
    signer: alice.logSigner,
    logClass: 'user-key-roster'
  })
  return { alice, controllerRef, log, pinStore, store }
}

/**
 * Re-keys the account's controller view for a grown client set at a new
 * version (the fake stand-in for a did:webvh enrollment/revocation edit).
 */
function controllerAt(
  versions: Array<{ versionId: string; clients: RosterTestClient[] }>
): WebvhResourceLogController {
  return fakeController({
    versions: versions.map(({ versionId, clients }) => ({
      versionId,
      keys: clients.map(client => client.signingKeyMultibase)
    }))
  })
}

describe('userKeyRosterPinId', () => {
  it('names the roster log slot in the key-map collection', () => {
    expect(userKeyRosterPinId({ spaceId: 'urn:uuid:space' })).toBe(
      'space/urn:uuid:space/key-map/user-key.jsonl'
    )
  })

  it('gives two accounts distinct roster slots', () => {
    expect(userKeyRosterPinId({ spaceId: 'space-one' })).not.toBe(
      userKeyRosterPinId({ spaceId: 'space-two' })
    )
  })
})

describe('logGovernedDescriptorStore (roster flows over the log)', () => {
  it('walks the served log once per seeded rotation, and re-reads only after a lost compare-and-swap', async () => {
    const { alice, log, store } = await makeAccount()
    const bob = await makeClient()
    const userKey = await mintUserKey()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    await addUserKeyRosterRecipient({
      store,
      recipient: {
        id: bob.kak.id as string,
        publicKeyMultibase: bob.publicKeyMultibase
      },
      ownerKeyAgreementKey: alice.kak
    })

    // The deciding read, then the rotation seeded from it: the append lands
    // with no second walk of the served log before it.
    const readLog = vi.spyOn(log, 'read')
    const appendLog = vi.spyOn(log, 'append')
    const current = (await store.read())!
    const rotated = await rotateUserKeyRoster({
      store,
      document: documentFor([alice]),
      retireRecipientId: bob.kak.id as string,
      current
    })
    expect(rotated.currentEpoch).not.toBe(userKey.id)
    expect(log._getEntries()).toHaveLength(3)
    expect(appendLog).toHaveBeenCalledTimes(1)
    const readsBeforeAppend = readLog.mock.invocationCallOrder.filter(
      order => order < appendLog.mock.invocationCallOrder[0]!
    ).length
    expect(readsBeforeAppend).toBe(1)

    // A seed behind the served log loses the compare-and-swap; the loop
    // re-reads and the rotation lands on the winner's head.
    const carol = await makeClient()
    const dave = await makeClient()
    await addUserKeyRosterRecipient({
      store,
      recipient: {
        id: carol.kak.id as string,
        publicKeyMultibase: carol.publicKeyMultibase
      },
      ownerKeyAgreementKey: alice.kak
    })
    const stale = (await store.read())!
    await addUserKeyRosterRecipient({
      store,
      recipient: {
        id: dave.kak.id as string,
        publicKeyMultibase: dave.publicKeyMultibase
      },
      ownerKeyAgreementKey: alice.kak
    })
    const entriesBefore = log._getEntries()!.length
    appendLog.mockClear()
    const again = await rotateUserKeyRoster({
      store,
      document: documentFor([alice, dave]),
      retireRecipientId: carol.kak.id as string,
      current: stale
    })
    expect(appendLog).toHaveBeenCalledTimes(2)
    expect(log._getEntries()).toHaveLength(entriesBefore + 1)
    const head = again.epochs!.find(epoch => epoch.id === again.currentEpoch)!
    expect(head.recipients.map(entry => entry.header.kid).sort()).toEqual(
      [alice.kak.id, dave.kak.id].sort()
    )
  })

  it('governs ensure/add/rotate/read: every write is a signed log append', async () => {
    const { alice, log, store } = await makeAccount()
    const bob = await makeClient()
    const userKey = await mintUserKey()

    // ensure -> the genesis entry.
    const created = await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    expect(created.currentEpoch).toBe(userKey.id)
    let entries = log._getEntries()!
    expect(entries).toHaveLength(1)
    expect(entries[0]!.state.type).toBe(EPOCH_CONFIGURATION_STATE_TYPE)
    expect((entries[0]!.parameters as { method: string }).method).toBe(
      RESOURCE_LOG_METHOD
    )

    // The enrollment wrap -> one append.
    await addUserKeyRosterRecipient({
      store,
      recipient: {
        id: bob.kak.id as string,
        publicKeyMultibase: bob.publicKeyMultibase
      },
      ownerKeyAgreementKey: alice.kak
    })
    entries = log._getEntries()!
    expect(entries).toHaveLength(2)

    // The revocation rotation -> one append.
    const rotated = await rotateUserKeyRoster({
      store,
      document: documentFor([alice]),
      retireRecipientId: bob.kak.id as string
    })
    entries = log._getEntries()!
    expect(entries).toHaveLength(3)
    expect(rotated.currentEpoch).not.toBe(userKey.id)

    // The read path delivers the rotated key off the verified head.
    const delivered = await readUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      pinnedEpochId: userKey.id
    })
    expect(delivered!.rotated).toBe(true)
    expect(delivered!.userKey.id).toBe(rotated.currentEpoch)
  })

  it('refuses a fabricated served log on read (tampered state)', async () => {
    const { alice, log, store } = await makeAccount()
    const userKey = await mintUserKey()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })

    // The host mutates the head entry's state (an extra epoch smuggled in);
    // the entry's proof no longer verifies, so the read refuses the log.
    const entries = log._getEntries()!
    ;(entries[0]!.state as unknown as { epochs: unknown[] }).epochs.push({
      id: 'did:key:z6LSfabricatedEpoch',
      recipients: []
    })
    log._setEntries(entries)

    await expect(
      readUserKeyRoster({
        store,
        userKey,
        clientKeyAgreementKey: alice.kak
      })
    ).rejects.toThrow(ResourceLogIntegrityError)
  })

  it('refuses a spliced rotation: a forged entry atop the legitimate prefix', async () => {
    const { alice, log, store } = await makeAccount()
    const userKey = await mintUserKey()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })

    // The attacker holds real keys and hash-chains a rotation-shaped entry
    // correctly onto the served log -- but no controller version ever listed
    // its signing key.
    const attacker = await makeClient()
    const attackerView = controllerAt([
      { versionId: '1-v1', clients: [attacker] }
    ])
    const entries = log._getEntries()!
    const forged = await buildResourceLogEntry({
      head: entries[entries.length - 1]!,
      state: {
        ...entries[0]!.state,
        currentEpoch: 'did:key:z6LSattackerEpoch'
      },
      controller: attackerView,
      signer: attacker.logSigner
    })
    log._setEntries([...entries, forged])

    await expect(
      readUserKeyRoster({
        store,
        userKey,
        clientKeyAgreementKey: alice.kak
      })
    ).rejects.toThrow(ResourceLogIntegrityError)
  })

  it('refuses a served rollback behind the chain-head pin', async () => {
    const { alice, log, store } = await makeAccount()
    const bob = await makeClient()
    const userKey = await mintUserKey()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    await addUserKeyRosterRecipient({
      store,
      recipient: {
        id: bob.kak.id as string,
        publicKeyMultibase: bob.publicKeyMultibase
      },
      ownerKeyAgreementKey: alice.kak
    })

    // The host replays the pre-enrollment log: internally consistent, every
    // entry legitimately signed -- only the pin catches it.
    log._setEntries(log._getEntries()!.slice(0, 1))
    await expect(
      readUserKeyRoster({
        store,
        userKey,
        clientKeyAgreementKey: alice.kak
      })
    ).rejects.toThrow(ResourceLogContinuityError)
  })

  it('refuses a verified head whose state is not an epoch configuration', async () => {
    const { alice, controllerRef, log, store } = await makeAccount()
    // A log legitimately signed by an enrolled client, but carrying a foreign
    // state document: the store's `type` gate refuses to hand it out as a
    // descriptor.
    const genesis = await buildResourceLogGenesis({
      state: { type: 'SomethingElse', payload: 1 },
      method: RESOURCE_LOG_METHOD,
      controller: controllerRef.current,
      signer: alice.logSigner
    })
    log._setEntries([genesis])
    await expect(store.read()).rejects.toThrow(/carries state of type/)
  })

  it('carries the controller head resolved per operation on each write', async () => {
    const { alice, controllerRef, log, store } = await makeAccount()
    const bob = await makeClient()
    const userKey = await mintUserKey()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    const genesisVm = log._getEntries()![0]!.proof[0]!.verificationMethod
    expect(genesisVm).toContain('?versionId=1-v1')

    // The account document grows a version (an enrollment edit); the next
    // roster write -- resolved per operation -- carries the new head.
    controllerRef.current = controllerAt([
      { versionId: '1-v1', clients: [alice] },
      { versionId: '2-v2', clients: [alice, bob] }
    ])
    await addUserKeyRosterRecipient({
      store,
      recipient: {
        id: bob.kak.id as string,
        publicKeyMultibase: bob.publicKeyMultibase
      },
      ownerKeyAgreementKey: alice.kak
    })
    const entries = log._getEntries()!
    expect(entries[1]!.proof[0]!.verificationMethod).toContain(
      '?versionId=2-v2'
    )
  })

  it('rebases instead of verifying when the controller view regresses between read and replace', async () => {
    const { alice, controllerRef, log, store } = await makeAccount()
    const bob = await makeClient()
    const userKey = await mintUserKey()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    const grown = controllerAt([
      { versionId: '1-v1', clients: [alice] },
      { versionId: '2-v2', clients: [alice, bob] }
    ])
    const shrunk = controllerRef.current
    controllerRef.current = grown
    const current = await store.read()
    expect(current).not.toBeNull()
    const before = log._getEntries()!

    // The pre-write pass indexes the head's controller version into the
    // version list of the view the read verified under; a resolver that
    // hands the replace a view missing that head is out of the pass's
    // contract, so the store reports the CAS loop's rebase signal and
    // writes nothing.
    controllerRef.current = shrunk
    const caught = await store
      .replace(current!.descriptor, { ifMatch: current!.etag })
      .then(() => null)
      .catch((err: unknown) => err)
    expect(caught).toBeInstanceOf(PreconditionFailedError)
    expect((caught as Error).message).toMatch(/does not carry version "2-v2"/)
    expect(log._getEntries()!).toEqual(before)

    // Under the grown view again, the re-read write goes through.
    controllerRef.current = grown
    const reread = await store.read()
    await store.replace(reread!.descriptor, { ifMatch: reread!.etag })
    expect(log._getEntries()!).toHaveLength(2)
  })

  it('propagates PreconditionFailedError on a lost CAS (the edv rebase signal)', async () => {
    const { alice, log, store } = await makeAccount()
    const userKey = await mintUserKey()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    const current = await store.read()
    expect(current).not.toBeNull()

    // A concurrent writer advances the log between this store's read and its
    // replace: the store throws the library's ResourceLogConflictError, and
    // the descriptor store translates it back to the PreconditionFailedError
    // the roster machinery's compare-and-swap loops rebase on, keeping the
    // library conflict as the cause.
    log._setEntries(log._getEntries())
    const caught = await store
      .replace(current!.descriptor, { ifMatch: current!.etag })
      .then(() => null)
      .catch((err: unknown) => err)
    expect(caught).toBeInstanceOf(PreconditionFailedError)
    expect((caught as { cause?: Error }).cause?.name).toBe(
      'ResourceLogConflictError'
    )
  })

  it('passes an untranslated PreconditionFailedError through unchanged', async () => {
    // A store adapter that still throws was-client's class directly (the
    // pre-library contract) already satisfies the descriptor-store port; the
    // translation must not double-wrap or swallow it.
    const { alice, log, store, controllerRef } = await makeAccount()
    const userKey = await mintUserKey()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    const untranslated = logGovernedDescriptorStore({
      log: {
        read: () => log.read(),
        append: async () => {
          throw new PreconditionFailedError('stale log etag', { status: 412 })
        },
        create: () => log.create(null as never)
      },
      resolveController: async () => controllerRef.current,
      pinStore: memoryResourceLogPinStore(),
      logId: LOG_ID,
      signer: alice.logSigner,
      logClass: 'user-key-roster'
    })
    const current = await untranslated.read()
    const caught = await untranslated
      .replace(current!.descriptor, { ifMatch: current!.etag })
      .then(() => null)
      .catch((err: unknown) => err)
    expect(caught).toBeInstanceOf(PreconditionFailedError)
    expect((caught as Error).cause).toBeUndefined()
  })

  it('acquires the head itself for a replace no read on the instance precedes', async () => {
    const { alice, controllerRef, log, store } = await makeAccount()
    const userKey = await mintUserKey()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    // A second instance over the same log, seeded with the first's read:
    // the replace reads once for its head, then appends under the seed's
    // validator.
    const first = (await store.read())!
    const fresh = logGovernedDescriptorStore({
      log,
      resolveController: async () => controllerRef.current,
      pinStore: memoryResourceLogPinStore(),
      logId: LOG_ID,
      signer: alice.logSigner,
      logClass: 'user-key-roster'
    })
    const readLog = vi.spyOn(log, 'read')
    await fresh.replace(first.descriptor, { ifMatch: first.etag })
    expect(log._getEntries()).toHaveLength(2)
    expect(readLog.mock.calls.length).toBeGreaterThanOrEqual(1)

    // Behind the served log, the seed's validator loses the compare-and-swap
    // rather than landing on a head the seed never saw.
    const stale = logGovernedDescriptorStore({
      log,
      resolveController: async () => controllerRef.current,
      pinStore: memoryResourceLogPinStore(),
      logId: LOG_ID,
      signer: alice.logSigner,
      logClass: 'user-key-roster'
    })
    await expect(
      stale.replace(first.descriptor, { ifMatch: first.etag })
    ).rejects.toBeInstanceOf(PreconditionFailedError)
    expect(log._getEntries()).toHaveLength(2)
  })

  it('refuses a replace on an absent log', async () => {
    const { alice, controllerRef } = await makeAccount()
    const fresh = logGovernedDescriptorStore({
      log: memoryLogStore(),
      resolveController: async () => controllerRef.current,
      pinStore: memoryResourceLogPinStore(),
      logId: LOG_ID,
      signer: alice.logSigner,
      logClass: 'user-key-roster'
    })
    await expect(
      fresh.replace(
        { scheme: 'edv', currentEpoch: 'did:key:z6LSx', epochs: [] },
        { ifMatch: 'v1' }
      )
    ).rejects.toThrow(/the log is absent/)
  })

  it('resolves null on an absent log (the pre-genesis roster state)', async () => {
    const { store } = await makeAccount()
    expect(await store.read()).toBeNull()
  })

  describe('an absent log under a held pin (the host hides the roster log)', () => {
    /**
     * A provisioned-and-pinned roster the host then stops serving.
     */
    async function makeHiddenRoster() {
      const account = await makeAccount()
      const { alice, log, pinStore, store } = account
      const userKey = await mintUserKey()
      await ensureUserKeyRoster({
        store,
        userKey,
        clientKeyAgreementKey: alice.kak
      })
      const pinnedHead = (await pinStore.read({ logId: LOG_ID }))!.head
      log._setEntries(null)
      return { ...account, userKey, pinnedHead }
    }

    it('read() refuses it as a rollback, not as pre-genesis', async () => {
      const { store, pinStore, pinnedHead } = await makeHiddenRoster()
      await expect(store.read()).rejects.toMatchObject({
        name: 'ResourceLogContinuityError',
        reason: 'rollback',
        pinnedHead
      })
      expect((await pinStore.read({ logId: LOG_ID }))?.head).toBe(pinnedHead)
    })

    it('ensureUserKeyRoster surfaces the refusal instead of re-provisioning', async () => {
      const { alice, log, store, pinnedHead } = await makeHiddenRoster()
      await expect(
        ensureUserKeyRoster({
          store,
          userKey: await mintUserKey(),
          clientKeyAgreementKey: alice.kak
        })
      ).rejects.toMatchObject({
        name: 'ResourceLogContinuityError',
        reason: 'rollback',
        pinnedHead
      })
      expect(log._getEntries()).toBeNull()
    })

    it('create() refuses it as a rollback, creating nothing', async () => {
      const { log, store, pinnedHead } = await makeHiddenRoster()
      await expect(
        store.create!({
          scheme: 'edv',
          currentEpoch: 'did:key:z6LSx',
          epochs: []
        })
      ).rejects.toMatchObject({
        name: 'ResourceLogContinuityError',
        reason: 'rollback',
        pinnedHead
      })
      expect(log._getEntries()).toBeNull()
    })

    it('create() under a held pin with the log served is the lost race', async () => {
      const { alice, log, store } = await makeAccount()
      await ensureUserKeyRoster({
        store,
        userKey: await mintUserKey(),
        clientKeyAgreementKey: alice.kak
      })
      const before = log._getEntries()
      await expect(
        store.create!({
          scheme: 'edv',
          currentEpoch: 'did:key:z6LSx',
          epochs: []
        })
      ).rejects.toThrow(PreconditionFailedError)
      expect(log._getEntries()).toEqual(before)
    })
  })

  it('is sealable, unlike a plain descriptor store', async () => {
    const { store } = await makeAccount()
    expect(isSealableDescriptorStore(store)).toBe(true)
    expect(
      isSealableDescriptorStore({
        read: async () => null,
        replace: async () => {},
        create: async () => {}
      })
    ).toBe(false)
  })

  it('seal() closes the gap a no-op rotation leaves: the orphan-client revocation', async () => {
    const { alice, controllerRef, log, store } = await makeAccount()
    const bob = await makeClient()
    const userKey = await mintUserKey()
    // Bob is enrolled in the document but never received a roster wrap (a
    // torn enrollment, or a rotation re-run). The roster genesis carries
    // the pre-revocation head.
    controllerRef.current = controllerAt([
      { versionId: '1-v1', clients: [alice, bob] }
    ])
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })

    // The revocation edit removes bob; the roster rotation then no-ops (bob
    // holds no current-epoch wrap), appending nothing.
    controllerRef.current = controllerAt([
      { versionId: '1-v1', clients: [alice, bob] },
      { versionId: '2-v2', clients: [alice] }
    ])
    await rotateUserKeyRoster({
      store,
      document: documentFor([alice]),
      retireRecipientId: bob.kak.id as string
    })
    expect(log._getEntries()!).toHaveLength(1)

    // The seal backstop carries the head past the edit, changing nothing.
    expect(await store.seal()).toBe('sealed')
    const entries = log._getEntries()!
    expect(entries).toHaveLength(2)
    expect(entries[1]!.state).toEqual(entries[0]!.state)
    expect(entries[1]!.proof[0]!.verificationMethod).toContain(
      '?versionId=2-v2'
    )
    // Idempotent: the sweep converges.
    expect(await store.seal()).toBe('noop')
    expect(log._getEntries()!).toHaveLength(2)
  })

  it('seal() no-ops when the rotation itself was the sealing append', async () => {
    const { alice, controllerRef, log, store } = await makeAccount()
    const bob = await makeClient()
    const userKey = await mintUserKey()
    controllerRef.current = controllerAt([
      { versionId: '1-v1', clients: [alice, bob] }
    ])
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    await addUserKeyRosterRecipient({
      store,
      recipient: {
        id: bob.kak.id as string,
        publicKeyMultibase: bob.publicKeyMultibase
      },
      ownerKeyAgreementKey: alice.kak
    })

    // The ordinary cascade: the edit lands, then the rotation appends --
    // carrying the post-edit head, which IS the sealing append.
    controllerRef.current = controllerAt([
      { versionId: '1-v1', clients: [alice, bob] },
      { versionId: '2-v2', clients: [alice] }
    ])
    await rotateUserKeyRoster({
      store,
      document: documentFor([alice]),
      retireRecipientId: bob.kak.id as string
    })
    const before = log._getEntries()!.length

    expect(await store.seal()).toBe('noop')
    expect(log._getEntries()!).toHaveLength(before)
  })

  it('seal() reuses the view the preceding read or rotation verified: no extra log fetch', async () => {
    const { alice, controllerRef, log, store } = await makeAccount()
    const bob = await makeClient()
    const userKey = await mintUserKey()
    controllerRef.current = controllerAt([
      { versionId: '1-v1', clients: [alice, bob] }
    ])
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    await addUserKeyRosterRecipient({
      store,
      recipient: {
        id: bob.kak.id as string,
        publicKeyMultibase: bob.publicKeyMultibase
      },
      ownerKeyAgreementKey: alice.kak
    })
    controllerRef.current = controllerAt([
      { versionId: '1-v1', clients: [alice, bob] },
      { versionId: '2-v2', clients: [alice] }
    ])
    await rotateUserKeyRoster({
      store,
      document: documentFor([alice]),
      retireRecipientId: bob.kak.id as string
    })

    // The rotation settled its own verified view on this store instance, so
    // the sweep answers from it alone.
    const afterRotation = vi.spyOn(log, 'read')
    expect(await store.seal()).toBe('noop')
    expect(afterRotation).not.toHaveBeenCalled()
    afterRotation.mockRestore()

    // The same holds after an ordinary read.
    await store.read()
    const afterRead = vi.spyOn(log, 'read')
    expect(await store.seal()).toBe('noop')
    expect(afterRead).not.toHaveBeenCalled()
    afterRead.mockRestore()
  })

  it('seal() on a fresh store instance (nothing verified yet) reads the log and seals', async () => {
    const { alice, controllerRef, log, pinStore, store } = await makeAccount()
    const bob = await makeClient()
    const userKey = await mintUserKey()
    // The orphan-client shape again: the roster genesis carries the
    // pre-revocation head and nothing has rotated since.
    controllerRef.current = controllerAt([
      { versionId: '1-v1', clients: [alice, bob] }
    ])
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    controllerRef.current = controllerAt([
      { versionId: '1-v1', clients: [alice, bob] },
      { versionId: '2-v2', clients: [alice] }
    ])

    // A store built after the fact -- the login sweep in a fresh session --
    // holds no verified view, so it falls back to reading.
    const fresh = logGovernedDescriptorStore({
      log,
      resolveController: async () => controllerRef.current,
      pinStore,
      logId: LOG_ID,
      signer: alice.logSigner,
      logClass: 'user-key-roster'
    })
    const readSpy = vi.spyOn(log, 'read')
    expect(await fresh.seal()).toBe('sealed')
    expect(readSpy).toHaveBeenCalled()
    const entries = log._getEntries()!
    expect(entries).toHaveLength(2)
    expect(entries[1]!.proof[0]!.verificationMethod).toContain(
      '?versionId=2-v2'
    )
    readSpy.mockRestore()

    // And the sweep's own settled view makes the re-run free.
    const rerunSpy = vi.spyOn(log, 'read')
    expect(await fresh.seal()).toBe('noop')
    expect(rerunSpy).not.toHaveBeenCalled()
    rerunSpy.mockRestore()
  })

  it('seal() no-ops after a recovery-spend-shaped history (growth-only assertion set)', async () => {
    const { alice, controllerRef, log, store } = await makeAccount()
    const newClient = await makeClient()
    const code = await makeClient()
    const userKey = await mintUserKey()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    // The standing recovery code: a roster recipient (its wrap is maintained
    // for free by rotation fan-out), keyAgreement-only in the document.
    await addUserKeyRosterRecipient({
      store,
      recipient: {
        id: code.kak.id as string,
        publicKeyMultibase: code.publicKeyMultibase
      },
      ownerKeyAgreementKey: alice.kak
    })

    // A recovery spend: the add-and-retire entry brings the new client's
    // assertion key IN; the spent code's method was keyAgreement-only, so no
    // assertion key ever leaves. The mandatory post-spend rotation is the
    // spent code's sealing, and the sweep finds nothing else to do.
    controllerRef.current = controllerAt([
      { versionId: '1-v1', clients: [alice] },
      { versionId: '2-v2', clients: [alice, newClient] }
    ])
    await rotateUserKeyRoster({
      store,
      document: documentFor([alice, newClient]),
      retireRecipientId: code.kak.id as string
    })

    expect(await store.seal()).toBe('noop')
    // The rotation itself carried the post-spend head.
    const entries = log._getEntries()!
    expect(entries[entries.length - 1]!.proof[0]!.verificationMethod).toContain(
      '?versionId=2-v2'
    )
  })
})

describe('logGovernedDescriptorStore (the log class it states at construction)', () => {
  it('admits a ladder-signed replace the license would refuse, on a descriptor log', async () => {
    const { log, store } = await ladderDescriptorStore({
      logId: LOG_ID,
      logClass: 'collection-descriptor',
      editedInventoryKeys: ['credA']
    })
    await store.create!(descriptorFor('did:key:z6LSepochOne'))
    const current = await store.read()

    await store.replace(descriptorFor('did:key:z6LSepochTwo'), {
      ifMatch: current!.etag
    })

    expect(log._getEntries()!).toHaveLength(2)
    expect((await store.read())!.descriptor.currentEpoch).toBe(
      'did:key:z6LSepochTwo'
    )
  })

  it('refuses that same replace on the roster log, writing nothing', async () => {
    const { log, store } = await ladderDescriptorStore({
      logId: LOG_ID,
      logClass: 'user-key-roster',
      editedInventoryKeys: ['credA']
    })
    await store.create!(descriptorFor('did:key:z6LSepochOne'))
    const current = await store.read()
    const before = log._getEntries()!

    let caught: unknown = null
    try {
      await store.replace(descriptorFor('did:key:z6LSepochTwo'), {
        ifMatch: current!.etag
      })
    } catch (err) {
      caught = err
    }
    expect((caught as Error | null)?.name).toBe('ResourceLogLicenseError')
    expect(log._getEntries()!).toEqual(before)
  })

  it('applies the class to a minimum controller version a ceremony set', async () => {
    // The minimum supersedes a stale resolver, and it is narrowed by the
    // store's class on the way out: an unwrapped minimum view would carry the
    // license and refuse this append.
    const {
      controllerRef,
      afterEdit: unchangedEdit,
      log,
      store
    } = await ladderDescriptorStore({
      logId: LOG_ID,
      logClass: 'collection-descriptor',
      editedInventoryKeys: ['credA']
    })
    await store.create!(descriptorFor('did:key:z6LSepochOne'))

    store.setMinimumControllerVersion({ controller: unchangedEdit })
    // The resolver stays behind, still serving the pre-edit view.
    expect(controllerRef.current.versionIds).toEqual(['1-v1'])
    const current = await store.read()
    await store.replace(descriptorFor('did:key:z6LSepochTwo'), {
      ifMatch: current!.etag
    })

    const entries = log._getEntries()!
    expect(entries).toHaveLength(2)
    expect(entries[1]!.proof[0]!.verificationMethod).toContain(
      '?versionId=2-v2'
    )
  })
})
