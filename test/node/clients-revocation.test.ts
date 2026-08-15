/**
 * Unit tests for the client-revocation cascade (`src/clients/revocation.ts`):
 * the up-front refusals, the graceful "no roster to rotate" completion on an
 * account whose collections are not encrypted yet, and the ordinary rotate-
 * and-adopt path. The document edit itself is stubbed -- it has its own tests
 * against a real log -- so what is exercised here is the cascade's own
 * ordering and outcome reporting.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
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
import { mintUserKey } from '../../src/keys/userKey.js'
import {
  memoryResourceLogPinStore,
  type ResourceLogController
} from '../../src/resourceLog/index.js'
import { revokeWebvhClient, type WebvhIdStore } from '../../src/webvh/index.js'
import type { ClientWebvhUpdateKeys } from '../../src/webvh/index.js'
import { fakeController, memoryLogStore } from './fixtures/resourceLog.js'

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
      doc
    } as unknown as Awaited<ReturnType<typeof revokeWebvhClient>>)
    const rosterStore = memoryStore()

    const result = await revokeAccountClient({
      idStore,
      updateKeys,
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
      doc
    } as unknown as Awaited<ReturnType<typeof revokeWebvhClient>>)
    const adopted: Array<{ userKey: { id: string } }> = []

    const result = await revokeAccountClient({
      idStore,
      updateKeys,
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
      doc
    } as unknown as Awaited<ReturnType<typeof revokeWebvhClient>>)

    const result = await revokeAccountClient({
      idStore,
      updateKeys,
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
    const controllerRef: { current: ResourceLogController } = {
      current: controllerFor([[own, revoked]])
    }
    const log = memoryLogStore()
    const rosterStore = logGovernedDescriptorStore({
      log,
      resolveController: async () => controllerRef.current,
      pinStore: memoryResourceLogPinStore(),
      signer: own.logSigner
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
      return { doc } as unknown as Awaited<ReturnType<typeof revokeWebvhClient>>
    })

    const result = await revokeAccountClient({
      idStore,
      updateKeys,
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
      updateKeys,
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
    const controllerRef: { current: ResourceLogController } = {
      current: controllerFor([[own, revoked]])
    }
    const log = memoryLogStore()
    const rosterStore = logGovernedDescriptorStore({
      log,
      resolveController: async () => controllerRef.current,
      pinStore: memoryResourceLogPinStore(),
      signer: own.logSigner
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
      return { doc } as unknown as Awaited<ReturnType<typeof revokeWebvhClient>>
    })

    const result = await revokeAccountClient({
      idStore,
      updateKeys,
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

  it('acquires the roster once per run: the existence probe plus the rotation CAS read', async () => {
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
    const controllerRef: { current: ResourceLogController } = {
      current: controllerFor([[own, revoked]])
    }
    const rosterStore = logGovernedDescriptorStore({
      log: memoryLogStore(),
      resolveController: async () => controllerRef.current,
      pinStore: memoryResourceLogPinStore(),
      signer: own.logSigner
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
      return { doc } as unknown as Awaited<ReturnType<typeof revokeWebvhClient>>
    })

    const readSpy = vi.spyOn(rosterStore, 'read')
    const result = await revokeAccountClient({
      idStore,
      updateKeys,
      revokedClient: {
        signingKeyMultibase: revoked.signingKeyMultibase,
        updateKeyMultibase: 'z6MkRevokedUpdateKey'
      },
      rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak,
      collections
    })

    // Two acquisitions, not four: the adopting read is threaded the
    // rotation's own descriptor, and the seal reuses the view that rotation
    // settled.
    expect(readSpy).toHaveBeenCalledTimes(2)
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

  it('refuses to disconnect the wallet running the cascade', async () => {
    const own = await makeRosterClient()
    const ownKak = own.kak
    const { revokedClient } = await makeRevokedClient()
    await expect(
      revokeAccountClient({
        idStore,
        updateKeys,
        revokedClient,
        ownSigningKeyMultibase: revokedClient.signingKeyMultibase,
        rosterStore: memoryStore(),
        clientKeyAgreementKey: ownKak,
        collections
      })
    ).rejects.toThrow(/cannot disconnect itself/)
    expect(revokeWebvhClient).not.toHaveBeenCalled()
  })
})
