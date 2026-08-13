/**
 * Integration tests for the log-governed descriptor store
 * (`src/keys/rosterLogStore.ts`): the roster's ensure/add/rotate/read flows
 * driven through was-client's recipient machinery over a resource log, with a
 * fake controller standing in for the verified did:webvh document. The WC-1
 * provenance properties are re-proven at this layer: a fabricated or spliced
 * served log is refused on read (there is no read path around the verifier),
 * a head state of a foreign `type` is refused as a descriptor, writes anchor
 * at the controller head resolved per operation, and a CAS conflict surfaces
 * as the `PreconditionFailedError` the edv rebase loops drive on.
 */
import { describe, expect, it } from 'vitest'
import { PreconditionFailedError } from '@interop/was-client'
import { RESOURCE_LOG_METHOD } from '@interop/was-client/log'
import {
  EPOCH_CONFIGURATION_STATE_TYPE,
  isSealableDescriptorStore,
  logGovernedDescriptorStore
} from '../../src/keys/rosterLogStore.js'
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
  ResourceLogIntegrityError,
  type ResourceLogController
} from '../../src/resourceLog/index.js'
import {
  makeRosterClient as makeClient,
  rosterDocumentFor as documentFor,
  type RosterTestClient
} from './fixtures/rosterClient.js'
import { fakeController, memoryLogStore } from './fixtures/resourceLog.js'

/**
 * One account: an enrolled writing client (alice), a mutable controller view
 * (grown by "document edits" mid-test), the in-memory log, and the governed
 * store built over them.
 */
async function makeAccount() {
  const alice = await makeClient()
  const controllerRef: { current: ResourceLogController } = {
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
    signer: alice.logSigner
  })
  return { alice, controllerRef, log, pinStore, store }
}

/**
 * Re-keys the account's controller view for a grown client set at a new
 * version (the fake stand-in for a did:webvh enrollment/revocation edit).
 */
function controllerAt(
  versions: Array<{ versionId: string; clients: RosterTestClient[] }>
): ResourceLogController {
  return fakeController({
    versions: versions.map(({ versionId, clients }) => ({
      versionId,
      keys: clients.map(client => client.signingKeyMultibase)
    }))
  })
}

describe('logGovernedDescriptorStore (roster flows over the log)', () => {
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

  it('anchors each write at the controller head resolved per operation', async () => {
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
    // roster write -- resolved per operation -- anchors at the new head.
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
    // replace: the stale validator must surface as the 412 the roster
    // machinery's compare-and-swap loops rebase on.
    log._setEntries(log._getEntries())
    await expect(
      store.replace(current!.descriptor, { ifMatch: current!.etag })
    ).rejects.toThrow(PreconditionFailedError)
  })

  it('refuses a replace that does not follow a read on the same instance', async () => {
    const { alice, controllerRef } = await makeAccount()
    const fresh = logGovernedDescriptorStore({
      log: memoryLogStore(),
      resolveController: async () => controllerRef.current,
      pinStore: memoryResourceLogPinStore(),
      signer: alice.logSigner
    })
    await expect(
      fresh.replace(
        { scheme: 'edv', currentEpoch: 'did:key:z6LSx', epochs: [] },
        { ifMatch: 'v1' }
      )
    ).rejects.toThrow(/must follow a read/)
  })

  it('resolves null on an absent log (the pre-genesis roster state)', async () => {
    const { store } = await makeAccount()
    expect(await store.read()).toBeNull()
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
    // torn enrollment, or a rotation re-run). The roster genesis anchors at
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

    // The seal backstop re-anchors the head past the edit, changing nothing.
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
    // anchored at the post-edit head, which IS the sealing append.
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
    // The rotation itself anchored at the post-spend head.
    const entries = log._getEntries()!
    expect(entries[entries.length - 1]!.proof[0]!.verificationMethod).toContain(
      '?versionId=2-v2'
    )
  })
})
