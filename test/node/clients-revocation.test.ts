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
import { makeRosterClient, rosterDocumentFor } from './fixtures/rosterClient.js'
import {
  addUserKeyRosterRecipient,
  ensureUserKeyRoster,
  rosterRecipientKid
} from '../../src/keys/userKeyRoster.js'
import { mintUserKey } from '../../src/keys/userKey.js'
import { revokeWebvhClient, type WebvhIdStore } from '../../src/webvh/index.js'
import type { ClientWebvhUpdateKeys } from '../../src/webvh/index.js'

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
      signEpochs: own.signEpochs,
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
      clientKeyAgreementKey: ownKak,
      signEpochs: own.signEpochs
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
      signEpochs: own.signEpochs,
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
        signEpochs: own.signEpochs,
        collections
      })
    ).rejects.toThrow(/cannot disconnect itself/)
    expect(revokeWebvhClient).not.toHaveBeenCalled()
  })
})
