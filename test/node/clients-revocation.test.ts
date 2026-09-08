/**
 * Unit tests for the client-revocation cascade (`src/clients/revocation.ts`):
 * the up-front refusals, the graceful "no roster to rotate" completion on an
 * account whose collections are not encrypted yet, and the ordinary rotate-
 * and-adopt path. The document edit itself is stubbed -- it has its own tests
 * against a real log -- so what is exercised here is the cascade's own
 * ordering and outcome reporting.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { DIDLog } from '@interop/did-method-webvh'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import { revokeAccountClient } from '../../src/clients/revocation.js'
import {
  makeRosterClient,
  rosterDocumentFor,
  type RosterTestClient
} from './fixtures/rosterClient.js'
import {
  addUserKeyRosterRecipient,
  ensureUserKeyRoster,
  rosterRecipientKid
} from '../../src/keys/userKeyRoster.js'
import { logGovernedDescriptorStore } from '../../src/keys/rosterLogStore.js'
import { userKeyRosterPinId } from '../../src/keys/rosterStore.js'
import { mintUserKey } from '../../src/keys/userKey.js'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import type { WebvhResourceLogController } from '../../src/resourceLog/index.js'
import {
  ensureDidWebvh,
  enrollWebvhClient,
  keyAgreementTwinMultibase,
  revokeWebvhClient,
  updateKeyMultibase,
  type WebvhIdStore
} from '../../src/webvh/index.js'
import type { ClientWebvhUpdateKeys } from '../../src/webvh/index.js'
import { mintEnrollmentRequest } from '../../src/enrollment/enrollment.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'
import { truncatingLogStore } from './fixtures/truncatingLogStore.js'
import {
  CONTROLLER_DID,
  fakeController,
  memoryLogStore
} from './fixtures/resourceLog.js'

const ROSTER_LOG_ID = userKeyRosterPinId({ spaceId: 'urn:uuid:space' })
const ACCOUNT_SPACE_ID = 'space-revocation-pin'

vi.mock('../../src/webvh/index.js', async importOriginal => {
  const actual =
    await importOriginal<typeof import('../../src/webvh/index.js')>()
  return { ...actual, revokeWebvhClient: vi.fn() }
})

/**
 * An in-memory descriptor store.
 *
 * @returns {object}
 */
function memoryStore(): EncryptionDescriptorStore & {
  state: { descriptor?: CollectionEncryption }
  writes: number
} {
  const holder = {
    state: {} as { descriptor?: CollectionEncryption },
    writes: 0,
    async read() {
      return holder.state.descriptor
        ? { descriptor: holder.state.descriptor, etag: '"v"' }
        : null
    },
    async replace(descriptor: CollectionEncryption) {
      holder.state.descriptor = descriptor
      holder.writes += 1
    },
    async create(descriptor: CollectionEncryption) {
      holder.state.descriptor = descriptor
      holder.writes += 1
    }
  }
  return holder
}

/**
 * A wallet client's identity key-agreement key (a self-describing did:key).
 *
 * @returns {Promise<IKeyAgreementKey & { publicKeyMultibase: string }>}
 */
async function makeClientKak(): Promise<
  IKeyAgreementKey & { publicKeyMultibase: string }
> {
  const kak = await X25519KeyAgreementKey2020.generate()
  const did = `did:key:${kak.publicKeyMultibase}`
  kak.controller = did
  kak.id = `${did}#${kak.publicKeyMultibase}`
  return kak as IKeyAgreementKey & { publicKeyMultibase: string }
}

const idStore = {} as WebvhIdStore
const updateKeys = {} as ClientWebvhUpdateKeys
const collections = { collectionIds: [], storeFor: () => memoryStore() }

/**
 * A fake post-edit account log, one version per client set, carrying exactly
 * what `webvhResourceLogController` reads off a verified did:webvh log: each
 * entry's `versionId` and its resolved document (`state`) with the version's
 * `assertionMethod` keys. Version ids match `fakeController`'s
 * (`1-v1`, `2-v2`, ...), so a minimum controller version built from this log and a fake
 * resolved view describe the same history.
 *
 * @param versions {RosterTestClient[][]}
 * @returns {DIDLog}
 */
function accountLogFor(versions: RosterTestClient[][]): DIDLog {
  return versions.map((versionClients, index) => ({
    versionId: `${index + 1}-v${index + 1}`,
    state: {
      ...rosterDocumentFor(versionClients),
      assertionMethod: versionClients.map(
        client => `${CONTROLLER_DID}#${client.signingKeyMultibase}`
      )
    }
  })) as unknown as DIDLog
}

/**
 * The revoked client's public halves, and the key-agreement key its roster
 * entry is wrapped to.
 *
 * @returns {Promise<object>}
 */
async function makeRevokedClient() {
  const kak = await makeClientKak()
  const revokedClient = {
    signingKeyMultibase: 'z6MkRevokedSigningKey',
    keyAgreementKeyMultibase: kak.publicKeyMultibase,
    updateKeyMultibase: 'z6MkRevokedUpdateKey'
  }
  return { kak, revokedClient, kid: rosterRecipientKid(revokedClient) }
}

describe('revokeAccountClient', () => {
  beforeEach(() => {
    vi.mocked(revokeWebvhClient).mockReset()
  })

  it('completes with nothing rotated on an account with no roster', async () => {
    const own = await makeRosterClient()
    const ownKak = own.kak
    const { revokedClient } = await makeRevokedClient()
    const doc = { keyAgreement: [] }
    vi.mocked(revokeWebvhClient).mockResolvedValue({
      doc,
      log: accountLogFor([[own]])
    } as unknown as Awaited<ReturnType<typeof revokeWebvhClient>>)
    const rosterStore = memoryStore()

    const result = await revokeAccountClient({
      idStore,
      signer: { kind: 'client', updateKeys },
      revokedClient,
      rosterStore,
      clientKeyAgreementKey: ownKak,
      collections
    })

    // The document edit landed, so the client IS disconnected: a completed
    // cascade, not a failure, and no roster write was attempted.
    expect(result).toEqual({
      rotated: false,
      collections: { outcomes: {}, failed: [] },
      document: doc
    })
    expect(rosterStore.writes).toBe(0)
  })

  it('hands a supplied projection store to the document edit', async () => {
    const own = await makeRosterClient()
    const { revokedClient } = await makeRevokedClient()
    vi.mocked(revokeWebvhClient).mockResolvedValue({
      doc: { keyAgreement: [] },
      log: accountLogFor([[own]])
    } as unknown as Awaited<ReturnType<typeof revokeWebvhClient>>)
    const projectionStore = {} as WebvhIdStore

    await revokeAccountClient({
      idStore,
      signer: { kind: 'client', updateKeys },
      projectionStore,
      revokedClient,
      rosterStore: memoryStore(),
      clientKeyAgreementKey: own.kak,
      collections
    })

    // The edit is where the pre-entry projection PUT happens, so the cascade
    // owes it nothing but the pass-through.
    expect(vi.mocked(revokeWebvhClient).mock.calls[0]?.[0]).toMatchObject({
      projectionStore
    })

    // Omitted, the edit is called without the member at all, so its own
    // behavior is unchanged.
    vi.mocked(revokeWebvhClient).mockClear()
    await revokeAccountClient({
      idStore,
      signer: { kind: 'client', updateKeys },
      revokedClient,
      rosterStore: memoryStore(),
      clientKeyAgreementKey: own.kak,
      collections
    })
    expect(vi.mocked(revokeWebvhClient).mock.calls[0]?.[0]).not.toHaveProperty(
      'projectionStore'
    )
  })

  it('rotates the roster off the revoked client and adopts the fresh key', async () => {
    const own = await makeRosterClient()
    const ownKak = own.kak
    const { revokedClient, kak: revokedKak, kid } = await makeRevokedClient()
    const userKey = await mintUserKey()
    const rosterStore = memoryStore()
    await ensureUserKeyRoster({
      store: rosterStore,
      userKey,
      clientKeyAgreementKey: ownKak
    })
    await addUserKeyRosterRecipient({
      store: rosterStore,
      recipient: { id: kid, publicKeyMultibase: revokedKak.publicKeyMultibase },
      ownerKeyAgreementKey: ownKak
    })
    // The document as the edit left it: the revoked client's verification
    // methods are gone, and this client's signing key -- the one its roster
    // writes sign the epoch configuration with -- is still backed.
    const doc = rosterDocumentFor([own])
    vi.mocked(revokeWebvhClient).mockResolvedValue({
      doc,
      log: accountLogFor([[own]])
    } as unknown as Awaited<ReturnType<typeof revokeWebvhClient>>)
    const adopted: Array<{ userKey: { id: string } }> = []

    const result = await revokeAccountClient({
      idStore,
      signer: { kind: 'client', updateKeys },
      revokedClient,
      rosterStore,
      userKey,
      clientKeyAgreementKey: ownKak,
      onUserKeyAdopted: async entry => {
        adopted.push(entry)
      },
      collections
    })

    expect(result.rotated).toBe(true)
    expect(result.userKey!.id).not.toBe(userKey.id)
    expect(adopted).toHaveLength(1)
    const fresh = result.rosterDescriptor!.epochs!.find(
      epoch => epoch.id === result.rosterDescriptor!.currentEpoch
    )!
    expect(fresh.recipients.map(entry => entry.header.kid)).toEqual([ownKak.id])
  })

  it('retires the wrap without being told the revoked client key-agreement key', async () => {
    const own = await makeRosterClient()
    const ownKak = own.kak
    const { revokedClient, kak: revokedKak, kid } = await makeRevokedClient()
    const userKey = await mintUserKey()
    const rosterStore = memoryStore()
    await ensureUserKeyRoster({
      store: rosterStore,
      userKey,
      clientKeyAgreementKey: ownKak
    })
    await addUserKeyRosterRecipient({
      store: rosterStore,
      recipient: { id: kid, publicKeyMultibase: revokedKak.publicKeyMultibase },
      ownerKeyAgreementKey: ownKak
    })
    const doc = rosterDocumentFor([own])
    vi.mocked(revokeWebvhClient).mockResolvedValue({
      doc,
      log: accountLogFor([[own]])
    } as unknown as Awaited<ReturnType<typeof revokeWebvhClient>>)

    const result = await revokeAccountClient({
      idStore,
      signer: { kind: 'client', updateKeys },
      // No key-agreement key at all: the roster stage names no recipient, it
      // converges onto the post-edit document, which no longer keys the
      // revoked client's entry.
      revokedClient: {
        signingKeyMultibase: revokedClient.signingKeyMultibase,
        updateKeyMultibase: revokedClient.updateKeyMultibase
      },
      rosterStore,
      userKey,
      clientKeyAgreementKey: ownKak,
      collections
    })

    expect(result.rotated).toBe(true)
    expect(result.userKey!.id).not.toBe(userKey.id)
    const fresh = result.rosterDescriptor!.epochs!.find(
      epoch => epoch.id === result.rosterDescriptor!.currentEpoch
    )!
    expect(fresh.recipients.map(entry => entry.header.kid)).toEqual([ownKak.id])
  })

  it('seals the roster log when the rotation no-ops (orphan client), and reports it', async () => {
    const own = await makeRosterClient()
    const revoked = await makeRosterClient()
    const userKey = await mintUserKey()

    // A log-governed roster store over a real in-memory log, with a mutable
    // controller view the mocked document edit advances.
    const controllerFor = (clients: RosterTestClient[][]) =>
      fakeController({
        versions: clients.map((versionClients, index) => ({
          versionId: `${index + 1}-v${index + 1}`,
          keys: versionClients.map(client => client.signingKeyMultibase)
        }))
      })
    const controllerRef: { current: WebvhResourceLogController } = {
      current: controllerFor([[own, revoked]])
    }
    const log = memoryLogStore()
    const rosterStore = logGovernedDescriptorStore({
      log,
      resolveController: async () => controllerRef.current,
      pinStore: memoryResourceLogPinStore(),
      logId: ROSTER_LOG_ID,
      signer: own.logSigner,
      logClass: 'user-key-roster'
    })
    // The revoked client is in the document but was never wrapped into the
    // roster (a torn enrollment): the rotation will find nothing to retire.
    await ensureUserKeyRoster({
      store: rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak
    })
    expect(log._getEntries()!).toHaveLength(1)

    const doc = rosterDocumentFor([own])
    vi.mocked(revokeWebvhClient).mockImplementation(async () => {
      // The document edit: the revoked client's keys leave at version 2.
      controllerRef.current = controllerFor([[own, revoked], [own]])
      return {
        did: CONTROLLER_DID,
        doc,
        log: accountLogFor([[own, revoked], [own]])
      } as unknown as Awaited<ReturnType<typeof revokeWebvhClient>>
    })

    const result = await revokeAccountClient({
      idStore,
      signer: { kind: 'client', updateKeys },
      revokedClient: {
        signingKeyMultibase: revoked.signingKeyMultibase,
        updateKeyMultibase: 'z6MkRevokedUpdateKey'
      },
      rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak,
      collections
    })

    // Nothing rotated -- but the seal backstop re-anchored the roster log
    // past the document edit, and the cascade reports it.
    expect(result.rotated).toBe(false)
    expect(result.rosterSeal).toEqual({ outcome: 'sealed' })
    const entries = log._getEntries()!
    expect(entries).toHaveLength(2)
    expect(entries[1]!.state).toEqual(entries[0]!.state)
    expect(entries[1]!.proof[0]!.verificationMethod).toContain(
      '?versionId=2-v2'
    )

    // A naive full re-run converges: nothing left to rotate or seal.
    const rerun = await revokeAccountClient({
      idStore,
      signer: { kind: 'client', updateKeys },
      revokedClient: {
        signingKeyMultibase: revoked.signingKeyMultibase,
        updateKeyMultibase: 'z6MkRevokedUpdateKey'
      },
      rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak,
      collections
    })
    expect(rerun.rotated).toBe(false)
    expect(rerun.rosterSeal).toEqual({ outcome: 'noop' })
    expect(log._getEntries()!).toHaveLength(2)
  })

  it('reports the seal as a noop when the rotation itself sealed the log', async () => {
    const own = await makeRosterClient()
    const revoked = await makeRosterClient()
    const userKey = await mintUserKey()
    const controllerFor = (clients: RosterTestClient[][]) =>
      fakeController({
        versions: clients.map((versionClients, index) => ({
          versionId: `${index + 1}-v${index + 1}`,
          keys: versionClients.map(client => client.signingKeyMultibase)
        }))
      })
    const controllerRef: { current: WebvhResourceLogController } = {
      current: controllerFor([[own, revoked]])
    }
    const log = memoryLogStore()
    const rosterStore = logGovernedDescriptorStore({
      log,
      resolveController: async () => controllerRef.current,
      pinStore: memoryResourceLogPinStore(),
      logId: ROSTER_LOG_ID,
      signer: own.logSigner,
      logClass: 'user-key-roster'
    })
    await ensureUserKeyRoster({
      store: rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak
    })
    const revokedKid = rosterRecipientKid({
      signingKeyMultibase: revoked.signingKeyMultibase,
      keyAgreementKeyMultibase: revoked.publicKeyMultibase
    })
    await addUserKeyRosterRecipient({
      store: rosterStore,
      recipient: {
        id: revokedKid,
        publicKeyMultibase: revoked.publicKeyMultibase
      },
      ownerKeyAgreementKey: own.kak
    })

    const doc = rosterDocumentFor([own])
    vi.mocked(revokeWebvhClient).mockImplementation(async () => {
      controllerRef.current = controllerFor([[own, revoked], [own]])
      return {
        did: CONTROLLER_DID,
        doc,
        log: accountLogFor([[own, revoked], [own]])
      } as unknown as Awaited<ReturnType<typeof revokeWebvhClient>>
    })

    const result = await revokeAccountClient({
      idStore,
      signer: { kind: 'client', updateKeys },
      revokedClient: {
        signingKeyMultibase: revoked.signingKeyMultibase,
        updateKeyMultibase: 'z6MkRevokedUpdateKey'
      },
      rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak,
      collections
    })

    // The rotation appended post-edit -- the sealing append by construction
    // -- so the backstop had nothing to add.
    expect(result.rotated).toBe(true)
    expect(result.rosterSeal).toEqual({ outcome: 'noop' })
    const entries = log._getEntries()!
    expect(entries[entries.length - 1]!.proof[0]!.verificationMethod).toContain(
      '?versionId=2-v2'
    )
  })

  it('anchors post-edit even when the injected controller view is stale', async () => {
    // The store's injected `resolveController` keeps serving the cached
    // pre-edit view for the whole cascade -- an app that never invalidated
    // its session-verified log. The orchestrator's minimum controller version, built
    // from the document edit's own post-edit log, must supersede it: without
    // that, the rotation anchors at version 1 and the seal backstop sees no
    // removal ("noop") while the roster log stays unsealed.
    const own = await makeRosterClient()
    const revoked = await makeRosterClient()
    const userKey = await mintUserKey()
    const staleController = fakeController({
      versions: [
        {
          versionId: '1-v1',
          keys: [own.signingKeyMultibase, revoked.signingKeyMultibase]
        }
      ]
    })
    const log = memoryLogStore()
    const rosterStore = logGovernedDescriptorStore({
      log,
      resolveController: async () => staleController,
      pinStore: memoryResourceLogPinStore(),
      logId: ROSTER_LOG_ID,
      signer: own.logSigner,
      logClass: 'user-key-roster'
    })
    await ensureUserKeyRoster({
      store: rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak
    })
    const revokedKid = rosterRecipientKid({
      signingKeyMultibase: revoked.signingKeyMultibase,
      keyAgreementKeyMultibase: revoked.publicKeyMultibase
    })
    await addUserKeyRosterRecipient({
      store: rosterStore,
      recipient: {
        id: revokedKid,
        publicKeyMultibase: revoked.publicKeyMultibase
      },
      ownerKeyAgreementKey: own.kak
    })

    const doc = rosterDocumentFor([own])
    vi.mocked(revokeWebvhClient).mockResolvedValue({
      did: CONTROLLER_DID,
      doc,
      log: accountLogFor([[own, revoked], [own]])
    } as unknown as Awaited<ReturnType<typeof revokeWebvhClient>>)

    const result = await revokeAccountClient({
      idStore,
      signer: { kind: 'client', updateKeys },
      revokedClient: {
        signingKeyMultibase: revoked.signingKeyMultibase,
        updateKeyMultibase: 'z6MkRevokedUpdateKey'
      },
      rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak,
      collections
    })

    // The rotation itself is the sealing append, anchored at the post-edit
    // version the stale resolver never served.
    expect(result.rotated).toBe(true)
    expect(result.rosterSeal).toEqual({ outcome: 'noop' })
    const entries = log._getEntries()!
    expect(entries[entries.length - 1]!.proof[0]!.verificationMethod).toContain(
      '?versionId=2-v2'
    )
  })

  it("acquires the roster once per run: the deciding read seeds the rotation's compare-and-swap", async () => {
    const own = await makeRosterClient()
    const revoked = await makeRosterClient()
    const userKey = await mintUserKey()
    const controllerFor = (clients: RosterTestClient[][]) =>
      fakeController({
        versions: clients.map((versionClients, index) => ({
          versionId: `${index + 1}-v${index + 1}`,
          keys: versionClients.map(client => client.signingKeyMultibase)
        }))
      })
    const controllerRef: { current: WebvhResourceLogController } = {
      current: controllerFor([[own, revoked]])
    }
    const rosterStore = logGovernedDescriptorStore({
      log: memoryLogStore(),
      resolveController: async () => controllerRef.current,
      pinStore: memoryResourceLogPinStore(),
      logId: ROSTER_LOG_ID,
      signer: own.logSigner,
      logClass: 'user-key-roster'
    })
    await ensureUserKeyRoster({
      store: rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak
    })
    const revokedKid = rosterRecipientKid({
      signingKeyMultibase: revoked.signingKeyMultibase,
      keyAgreementKeyMultibase: revoked.publicKeyMultibase
    })
    await addUserKeyRosterRecipient({
      store: rosterStore,
      recipient: {
        id: revokedKid,
        publicKeyMultibase: revoked.publicKeyMultibase
      },
      ownerKeyAgreementKey: own.kak
    })

    const doc = rosterDocumentFor([own])
    vi.mocked(revokeWebvhClient).mockImplementation(async () => {
      controllerRef.current = controllerFor([[own, revoked], [own]])
      return {
        did: CONTROLLER_DID,
        doc,
        log: accountLogFor([[own, revoked], [own]])
      } as unknown as Awaited<ReturnType<typeof revokeWebvhClient>>
    })

    const readSpy = vi.spyOn(rosterStore, 'read')
    const result = await revokeAccountClient({
      idStore,
      signer: { kind: 'client', updateKeys },
      revokedClient: {
        signingKeyMultibase: revoked.signingKeyMultibase,
        updateKeyMultibase: 'z6MkRevokedUpdateKey'
      },
      rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak,
      collections
    })

    // One acquisition, not four: the convergence's deciding read seeds the
    // rotation's compare-and-swap, the adopting read is threaded the
    // rotation's own descriptor, and the seal reuses the view that rotation
    // settled.
    expect(readSpy).toHaveBeenCalledTimes(1)
    // The reduced run still reports the rotated epoch.
    expect(result.rotated).toBe(true)
    expect(result.rosterSeal).toEqual({ outcome: 'noop' })
    expect(result.userKey!.id).not.toBe(userKey.id)
    expect(result.rosterDescriptor!.currentEpoch).toBe(result.userKey!.id)
    const fresh = result.rosterDescriptor!.epochs!.find(
      epoch => epoch.id === result.rosterDescriptor!.currentEpoch
    )!
    expect(fresh.recipients.map(entry => entry.header.kid)).toEqual([
      own.kak.id
    ])
    readSpy.mockRestore()
  })

  it('runs the generation-delegation re-mint on the no-roster path too', async () => {
    const own = await makeRosterClient()
    const { revokedClient } = await makeRevokedClient()
    const doc = { keyAgreement: [] }
    vi.mocked(revokeWebvhClient).mockResolvedValue({
      doc,
      log: accountLogFor([[own]])
    } as unknown as Awaited<ReturnType<typeof revokeWebvhClient>>)

    const documents: object[] = []
    const result = await revokeAccountClient({
      idStore,
      signer: { kind: 'client', updateKeys },
      revokedClient,
      rosterStore: memoryStore(),
      clientKeyAgreementKey: own.kak,
      collections,
      remintGenerationDelegation: async ({ document }) => {
        documents.push(document)
        return { renewed: true }
      }
    })

    // The document edit alone is what rots the delegation, so the stage runs
    // even with no roster to rotate, against the post-edit document.
    expect(documents).toEqual([doc])
    expect(result.generation).toEqual({ renewed: true })
  })

  it('re-mints against the post-edit document, before the session adoption', async () => {
    const own = await makeRosterClient()
    const { revokedClient, kak: revokedKak, kid } = await makeRevokedClient()
    const userKey = await mintUserKey()
    const rosterStore = memoryStore()
    await ensureUserKeyRoster({
      store: rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak
    })
    await addUserKeyRosterRecipient({
      store: rosterStore,
      recipient: { id: kid, publicKeyMultibase: revokedKak.publicKeyMultibase },
      ownerKeyAgreementKey: own.kak
    })
    const doc = rosterDocumentFor([own])
    vi.mocked(revokeWebvhClient).mockResolvedValue({
      doc,
      log: accountLogFor([[own]])
    } as unknown as Awaited<ReturnType<typeof revokeWebvhClient>>)

    const calls: string[] = []
    const documents: object[] = []
    const result = await revokeAccountClient({
      idStore,
      signer: { kind: 'client', updateKeys },
      revokedClient,
      rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak,
      collections,
      remintGenerationDelegation: async ({ document }) => {
        documents.push(document)
        calls.push('generation')
        return { renewed: false, skipped: 'no-ladder-seed' }
      },
      onRotationAdopted: async () => {
        calls.push('session')
      }
    })

    expect(documents).toEqual([doc])
    expect(calls).toEqual(['generation', 'session'])
    expect(result.rotated).toBe(true)
    expect(result.generation).toEqual({
      renewed: false,
      skipped: 'no-ladder-seed'
    })
  })

  it('reports no generation member when no closure is injected', async () => {
    const own = await makeRosterClient()
    const { revokedClient, kak: revokedKak, kid } = await makeRevokedClient()
    const userKey = await mintUserKey()
    const rosterStore = memoryStore()
    await ensureUserKeyRoster({
      store: rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak
    })
    await addUserKeyRosterRecipient({
      store: rosterStore,
      recipient: { id: kid, publicKeyMultibase: revokedKak.publicKeyMultibase },
      ownerKeyAgreementKey: own.kak
    })
    vi.mocked(revokeWebvhClient).mockResolvedValue({
      doc: rosterDocumentFor([own]),
      log: accountLogFor([[own]])
    } as unknown as Awaited<ReturnType<typeof revokeWebvhClient>>)

    const result = await revokeAccountClient({
      idStore,
      signer: { kind: 'client', updateKeys },
      revokedClient,
      rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak,
      collections
    })
    expect(result.rotated).toBe(true)
    expect('generation' in result).toBe(false)
  })
})

describe('revokeAccountClient chain-head pin', () => {
  /**
   * A freshly minted client's public halves in the enrollment entry's shape,
   * plus the update-key seeds behind them.
   *
   * @returns {Promise<object>}
   */
  async function newClient() {
    const minted = await mintEnrollmentRequest()
    const signingKeyMultibase = minted.clientDid.slice('did:key:'.length)
    return {
      updateKeys: minted.webvhUpdateKeys,
      keys: {
        signingKeyMultibase,
        keyAgreementKeyMultibase: keyAgreementTwinMultibase({
          signingKeyMultibase
        }),
        updateKeyMultibase: await updateKeyMultibase({
          seed: minted.webvhUpdateKeys.updateSeed
        }),
        stagedUpdateKeyMultibase: await updateKeyMultibase({
          seed: minted.webvhUpdateKeys.stagedSeed
        })
      }
    }
  }

  it('refuses a served prefix of the pinned account log, publishing no entry', async () => {
    const own = await makeRosterClient()
    // The document edit runs for real here: what is under test is the read it
    // is built on, which the mock stands in for elsewhere in this suite.
    const actual = await vi.importActual<
      typeof import('../../src/webvh/index.js')
    >('../../src/webvh/index.js')
    vi.mocked(revokeWebvhClient).mockImplementation(actual.revokeWebvhClient)

    const { idStore, log } = memoryIdStore({ spaceId: ACCOUNT_SPACE_ID })
    const founder = await newClient()
    await ensureDidWebvh({
      idStore,
      wasServerUrl: 'http://localhost:8080',
      spaceId: ACCOUNT_SPACE_ID,
      clientKeys: {
        signingKeyMultibase: founder.keys.signingKeyMultibase,
        keyAgreementKeyMultibase: founder.keys.keyAgreementKeyMultibase
      },
      updateKeys: founder.updateKeys
    })
    // The client to disconnect, enrolled for real: its entries grow the log
    // past the genesis, and their publish advances the store's pin to it.
    const revoked = await newClient()
    await enrollWebvhClient({
      idStore,
      signer: { kind: 'client', updateKeys: founder.updateKeys },
      newClient: revoked.keys
    })
    const { store: truncated } = truncatingLogStore({ idStore, dropEntries: 1 })
    const logBefore = log()

    const caught = (await revokeAccountClient({
      idStore: truncated,
      signer: { kind: 'client', updateKeys: founder.updateKeys },
      revokedClient: revoked.keys,
      rosterStore: memoryStore(),
      clientKeyAgreementKey: own.kak,
      collections
    }).catch((err: unknown) => err)) as { name: string; reason: string }

    expect(caught.name).toBe('ResourceLogContinuityError')
    expect(caught.reason).toBe('rollback')
    // The truncation was refused on the read, so the edit published nothing.
    expect(log()).toBe(logBefore)
  })
})
