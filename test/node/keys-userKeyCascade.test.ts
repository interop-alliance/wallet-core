/**
 * Unit tests for the user key rotation cascade's per-collection half
 * (`src/keys/userKeyCascade.ts`) and the roster rotation helper
 * (`rotateUserKeyRoster`): generation recovery from the roster, the staleness
 * rule (a collection is stale exactly when its current epoch names a
 * non-current user key generation), the fail-closed refusal of an epoch-less
 * descriptor, convergence under a naive re-run, the collection fan-out driver
 * (`cascadeCollectionsToUserKey`), the doc-backed resolver riding the roster
 * rotation, and the escrow invariant that no epoch recipient wrapped to a
 * non-user-key kid ever receives a user-key generation secret. All over
 * in-memory descriptor stores with the real epoch crypto.
 */
import { describe, expect, it } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import {
  addRecipient,
  ensureFirstEpoch,
  epochKeyIdFor,
  initRecipients,
  resolveEpochKeys,
  unwrapEpochSecret,
  type EncryptionDescriptorStore
} from '@interop/was-client/edv'
import type { CollectionEncryption } from '@interop/was-client'
import { mintUserKey, userKeyVaultKeys } from '../../src/keys/userKey.js'
import {
  addUserKeyRosterRecipient,
  ensureUserKeyRoster,
  readUserKeyRoster,
  rotateUserKeyRoster
} from '../../src/keys/userKeyRoster.js'
import {
  cascadeCollectionsToUserKey,
  userKeyAsRecipient,
  rotateCollectionEpochsToUserKey,
  unwrapUserKeyGenerations
} from '../../src/keys/userKeyCascade.js'
import { makeRosterClient, rosterDocumentFor } from './fixtures/rosterClient.js'

/**
 * An in-memory descriptor store with a write counter and create-if-absent.
 *
 * @param [initial] {CollectionEncryption}
 * @returns {object}
 */
function memoryStore(
  initial?: CollectionEncryption
): EncryptionDescriptorStore & {
  state: { descriptor?: CollectionEncryption }
  writes: number
} {
  const holder = {
    state: { descriptor: initial },
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
 * A key-agreement key for a party that never signs a roster write -- an app's
 * collection recipient, a stranger, a server-planted entry. The return type
 * keeps `publicKeyMultibase` visible (the widened `IKeyAgreementKey` drops it)
 * so fixtures can mint recipient entries from it.
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

/**
 * A two-generation account: a roster whose first epoch is user key 1 (wrapped
 * to one enrolled client) rotated to user key 2 through the doc-backed
 * resolver.
 *
 * @returns {Promise<object>}
 */
async function rotatedRoster() {
  const client = await makeRosterClient()
  const clientKak = client.kak
  const userKey1 = await mintUserKey()
  const rosterStore = memoryStore()
  await ensureUserKeyRoster({
    store: rosterStore,
    userKey: userKey1,
    clientKeyAgreementKey: clientKak
  })
  // A second enrolled party joins the roster, is revoked (its VM leaves the
  // stub verified document), and the rotation retires its wrap.
  const revoked = await makeClientKak()
  await addUserKeyRosterRecipient({
    store: rosterStore,
    recipient: {
      id: revoked.id,
      publicKeyMultibase: revoked.publicKeyMultibase
    },
    ownerKeyAgreementKey: clientKak
  })
  const document = rosterDocumentFor([client])
  await rotateUserKeyRoster({
    store: rosterStore,
    document,
    retireRecipientId: revoked.id
  })
  const read = await readUserKeyRoster({
    store: rosterStore,
    clientKeyAgreementKey: clientKak
  })
  const userKey2 = read!.userKey
  expect(read!.rotated).toBe(true)
  expect(userKey2.id).not.toBe(userKey1.id)
  return {
    client,
    clientKak,
    document,
    userKey1,
    userKey2,
    rosterStore,
    rosterDescriptor: read!.descriptor
  }
}

describe('unwrapUserKeyGenerations', () => {
  it('recovers every generation from the roster in order', async () => {
    const { clientKak, userKey1, userKey2, rosterDescriptor } =
      await rotatedRoster()
    const generations = await unwrapUserKeyGenerations({
      descriptor: rosterDescriptor,
      clientKeyAgreementKey: clientKak
    })
    expect(generations.map(generation => generation.id)).toEqual([
      userKey1.id,
      userKey2.id
    ])
    expect(generations[0]!.secret).toEqual(userKey1.secret)
  })

  it('skips an epoch this client holds no wrap in', async () => {
    const { clientKak, userKey2, rosterStore } = await rotatedRoster()
    const stranger = await makeClientKak()
    // A later-enrolled party gets escrow wraps in every epoch; a stranger
    // with no wraps recovers nothing.
    await addUserKeyRosterRecipient({
      store: rosterStore,
      recipient: {
        id: stranger.id,
        publicKeyMultibase: stranger.publicKeyMultibase
      },
      ownerKeyAgreementKey: clientKak
    })
    const read = await readUserKeyRoster({
      store: rosterStore,
      userKey: userKey2,
      clientKeyAgreementKey: clientKak
    })
    const strangers = await unwrapUserKeyGenerations({
      descriptor: read!.descriptor,
      clientKeyAgreementKey: await makeClientKak()
    })
    expect(strangers).toEqual([])
  })
})

describe('rotateCollectionEpochsToUserKey', () => {
  it('rotates a stale collection: fresh epoch on the current user key, history escrowed, other readers ride through', async () => {
    const { clientKak, userKey1, userKey2, rosterDescriptor } =
      await rotatedRoster()
    const app = await makeClientKak()
    const collectionStore = memoryStore()
    await initRecipients({
      store: collectionStore,
      recipients: [
        userKeyAsRecipient({ userKey: userKey1 }),
        { id: app.id, publicKeyMultibase: app.publicKeyMultibase }
      ]
    })
    const generations = await unwrapUserKeyGenerations({
      descriptor: rosterDescriptor,
      clientKeyAgreementKey: clientKak
    })

    const outcome = await rotateCollectionEpochsToUserKey({
      store: collectionStore,
      userKey: userKey2,
      generations
    })
    expect(outcome).toBe('rotated')

    const descriptor = collectionStore.state.descriptor!
    expect(descriptor.epochs).toHaveLength(2)
    const current = descriptor.epochs!.find(
      epoch => epoch.id === descriptor.currentEpoch
    )!
    const kids = current.recipients.map(entry => entry.header.kid)
    expect(kids).toContain(epochKeyIdFor(userKey2.id))
    expect(kids).toContain(app.id)
    expect(kids).not.toContain(epochKeyIdFor(userKey1.id))
    // The current user key reads the whole history (escrow), and the app still
    // resolves every epoch.
    const userKey2Keys = await resolveEpochKeys({
      encryption: descriptor,
      keyAgreementKey: userKeyVaultKeys({ userKey: userKey2 }).keyAgreementKey
    })
    expect(userKey2Keys!.readKeys).toHaveLength(2)
    const appKeys = await resolveEpochKeys({
      encryption: descriptor,
      keyAgreementKey: app
    })
    expect(appKeys!.readKeys).toHaveLength(2)
  })

  it('is a no-op on a collection already on the current user key (naive re-run convergence)', async () => {
    const { clientKak, userKey2, rosterDescriptor } = await rotatedRoster()
    const collectionStore = memoryStore()
    await initRecipients({
      store: collectionStore,
      recipients: [userKeyAsRecipient({ userKey: userKey2 })]
    })
    const generations = await unwrapUserKeyGenerations({
      descriptor: rosterDescriptor,
      clientKeyAgreementKey: clientKak
    })
    const writesBefore = collectionStore.writes
    const outcome = await rotateCollectionEpochsToUserKey({
      store: collectionStore,
      userKey: userKey2,
      generations
    })
    expect(outcome).toBe('noop')
    expect(collectionStore.writes).toBe(writesBefore)
  })

  it('refuses an epoch-less descriptor fail-closed, without writing', async () => {
    // Provisioning installs every encrypted collection's epoch[0], so a
    // descriptor without epochs can only come from a tampering or
    // pre-provisioning host; the cascade never mints a first epoch.
    const userKey = await mintUserKey()
    const collectionStore = memoryStore({ scheme: 'edv' })
    await expect(
      rotateCollectionEpochsToUserKey({
        store: collectionStore,
        userKey,
        generations: [userKey]
      })
    ).rejects.toThrow('carries no key epochs')
    expect(collectionStore.writes).toBe(0)
  })

  it('retires several stranded generations at once', async () => {
    // Two crashes back to back: the collection's current epoch still names
    // user key 1 while the roster has moved through user key 2 to user key 3.
    const { clientKak, document, userKey1, userKey2, rosterStore } =
      await rotatedRoster()
    const another = await makeClientKak()
    await addUserKeyRosterRecipient({
      store: rosterStore,
      recipient: {
        id: another.id,
        publicKeyMultibase: another.publicKeyMultibase
      },
      ownerKeyAgreementKey: clientKak
    })
    await rotateUserKeyRoster({
      store: rosterStore,
      document,
      retireRecipientId: another.id
    })
    const read = await readUserKeyRoster({
      store: rosterStore,
      clientKeyAgreementKey: clientKak
    })
    const userKey3 = read!.userKey
    const generations = await unwrapUserKeyGenerations({
      descriptor: read!.descriptor,
      clientKeyAgreementKey: clientKak
    })
    expect(generations).toHaveLength(3)

    const collectionStore = memoryStore()
    await initRecipients({
      store: collectionStore,
      recipients: [userKeyAsRecipient({ userKey: userKey1 })]
    })
    // Simulate the crashed first cascade's escrow half: user key 2 escrowed into
    // the (still current) user key 1 epoch, no rotation.
    await addRecipient({
      store: collectionStore,
      recipient: userKeyAsRecipient({ userKey: userKey2 }),
      owner: {
        keyAgreementKey: userKeyVaultKeys({ userKey: userKey1 }).keyAgreementKey
      }
    })

    const outcome = await rotateCollectionEpochsToUserKey({
      store: collectionStore,
      userKey: userKey3,
      generations
    })
    expect(outcome).toBe('rotated')
    const descriptor = collectionStore.state.descriptor!
    const current = descriptor.epochs!.find(
      epoch => epoch.id === descriptor.currentEpoch
    )!
    const kids = current.recipients.map(entry => entry.header.kid)
    expect(kids).toEqual([epochKeyIdFor(userKey3.id)])
  })

  it('is a no-op over a freshly provisioned epoch[0] (no stale generation)', async () => {
    // The provision-time install wraps a fresh random epoch[0] to the current
    // user key; a cascade meeting it has nothing to retire and nothing to
    // escrow, so a naive full re-run stays write-free.
    const client = await makeRosterClient()
    const clientKak = client.kak
    const userKey = await mintUserKey()
    const rosterStore = memoryStore()
    const rosterDescriptor = await ensureUserKeyRoster({
      store: rosterStore,
      userKey,
      clientKeyAgreementKey: clientKak
    })
    const generations = await unwrapUserKeyGenerations({
      descriptor: rosterDescriptor,
      clientKeyAgreementKey: clientKak
    })
    const collectionStore = memoryStore()
    const { descriptor, installed } = await ensureFirstEpoch({
      store: collectionStore,
      recipients: [userKeyAsRecipient({ userKey })]
    })
    expect(installed).toBe(true)
    // epoch[0] is a fresh random epoch key, never the user key generation.
    expect(descriptor.currentEpoch).not.toBe(userKey.id)
    const writesBefore = collectionStore.writes
    const outcome = await rotateCollectionEpochsToUserKey({
      store: collectionStore,
      userKey,
      generations
    })
    expect(outcome).toBe('noop')
    expect(collectionStore.writes).toBe(writesBefore)
  })
})

describe('collection-epoch escrow of an external grantee', () => {
  it('never hands a non-user-key recipient a user-key generation secret', async () => {
    // The invariant that makes the cascade rotation-only: no collection epoch
    // ever IS a user-key generation, so escrowing an external grantee (an App
    // Connect app, a share recipient) into every epoch -- which is what
    // `addRecipient` does -- can never wrap the account's user key to it.
    const { clientKak, userKey1, userKey2, rosterDescriptor } =
      await rotatedRoster()
    // A collection provisioned epoch-from-birth under the first-generation
    // user key, then rotated by the cascade: the richest epoch history a
    // wallet collection accumulates.
    const collectionStore = memoryStore()
    await ensureFirstEpoch({
      store: collectionStore,
      recipients: [userKeyAsRecipient({ userKey: userKey1 })]
    })
    const generations = await unwrapUserKeyGenerations({
      descriptor: rosterDescriptor,
      clientKeyAgreementKey: clientKak
    })
    expect(
      await rotateCollectionEpochsToUserKey({
        store: collectionStore,
        userKey: userKey2,
        generations
      })
    ).toBe('rotated')

    // The external grantee is escrowed into EVERY epoch.
    const app = await makeClientKak()
    await addRecipient({
      store: collectionStore,
      recipient: { id: app.id, publicKeyMultibase: app.publicKeyMultibase },
      owner: {
        keyAgreementKey: userKeyVaultKeys({ userKey: userKey2 }).keyAgreementKey
      }
    })

    const descriptor = collectionStore.state.descriptor!
    const generationIds = generations.map(generation => generation.id)
    const generationSecrets = generations.map(generation =>
      Array.from(generation.secret)
    )
    expect(descriptor.epochs!.length).toBeGreaterThanOrEqual(2)
    for (const epoch of descriptor.epochs!) {
      // Structural half: no epoch IS a user-key generation.
      expect(generationIds).not.toContain(epoch.id)
      // Escrow half: the grantee's wrap in this epoch unwraps to that epoch's
      // own secret, never to any user-key generation's.
      const entry = epoch.recipients.find(
        recipient => recipient.header.kid === app.id
      )
      expect(entry).toBeDefined()
      const secret = await unwrapEpochSecret({
        entry: entry!,
        keyAgreementKey: app
      })
      expect(secret).not.toBeNull()
      expect(generationSecrets).not.toContainEqual(Array.from(secret!))
    }
  })
})

describe('cascadeCollectionsToUserKey', () => {
  it('fans out over the named collections, reporting each outcome', async () => {
    const { clientKak, userKey1, userKey2, rosterDescriptor } =
      await rotatedRoster()
    const stale = memoryStore()
    await initRecipients({
      store: stale,
      recipients: [userKeyAsRecipient({ userKey: userKey1 })]
    })
    const current = memoryStore()
    await initRecipients({
      store: current,
      recipients: [userKeyAsRecipient({ userKey: userKey2 })]
    })
    const stores: Record<string, EncryptionDescriptorStore> = {
      'private-credentials': stale,
      'wallet-activity': current
    }
    const result = await cascadeCollectionsToUserKey({
      collectionIds: Object.keys(stores),
      storeFor: collectionId => stores[collectionId]!,
      rosterDescriptor,
      clientKeyAgreementKey: clientKak,
      userKey: userKey2
    })
    expect(result.failed).toEqual([])
    expect(result.outcomes).toEqual({
      'private-credentials': 'rotated',
      'wallet-activity': 'noop'
    })
  })

  it('skips a collection the isEncrypted pre-filter rejects', async () => {
    const { clientKak, userKey2, rosterDescriptor } = await rotatedRoster()
    const collectionStore = memoryStore()
    await initRecipients({
      store: collectionStore,
      recipients: [userKeyAsRecipient({ userKey: userKey2 })]
    })
    const storeFor = (collectionId: string) => {
      if (collectionId !== 'private-credentials') {
        throw new Error('storeFor reached a filtered collection')
      }
      return collectionStore
    }
    const result = await cascadeCollectionsToUserKey({
      collectionIds: ['private-credentials', 'public-credentials'],
      storeFor,
      isEncrypted: async collectionId => collectionId === 'private-credentials',
      rosterDescriptor,
      clientKeyAgreementKey: clientKak,
      userKey: userKey2
    })
    expect(result.failed).toEqual([])
    expect(result.outcomes).toEqual({ 'private-credentials': 'noop' })
  })

  it('collects a failing collection without aborting the rest', async () => {
    const { clientKak, userKey1, userKey2, rosterDescriptor } =
      await rotatedRoster()
    const stale = memoryStore()
    await initRecipients({
      store: stale,
      recipients: [userKeyAsRecipient({ userKey: userKey1 })]
    })
    const broken: EncryptionDescriptorStore = {
      async read() {
        throw new Error('descriptor read refused')
      },
      async replace() {},
      async create() {}
    }
    const stores: Record<string, EncryptionDescriptorStore> = {
      'private-credentials': stale,
      contacts: broken
    }
    const result = await cascadeCollectionsToUserKey({
      collectionIds: Object.keys(stores),
      storeFor: collectionId => stores[collectionId]!,
      // A throwing pre-filter lands in `failed` too, not outside it.
      isEncrypted: async collectionId => {
        if (collectionId === 'contacts') {
          throw new Error('descriptor read refused')
        }
        return true
      },
      rosterDescriptor,
      clientKeyAgreementKey: clientKak,
      userKey: userKey2
    })
    expect(result.outcomes).toEqual({ 'private-credentials': 'rotated' })
    expect(result.failed).toHaveLength(1)
    expect(result.failed[0]!.collectionId).toBe('contacts')
    expect((result.failed[0]!.error as Error).message).toBe(
      'descriptor read refused'
    )
  })
})

describe('rotateUserKeyRoster', () => {
  it('drops a roster entry with no document VM and never re-wraps the retiree', async () => {
    const { clientKak, document, rosterStore } = await rotatedRoster()
    // Inject a server-planted entry with no document backing, then rotate:
    // the fresh epoch must carry only the document-backed client.
    const planted = await makeClientKak()
    const state = (
      rosterStore as unknown as {
        state: { descriptor?: CollectionEncryption }
      }
    ).state
    const descriptor = state.descriptor!
    const currentEpoch = descriptor.epochs!.find(
      epoch => epoch.id === descriptor.currentEpoch
    )!
    currentEpoch.recipients = [
      ...currentEpoch.recipients,
      {
        header: {
          kid: planted.id,
          alg: 'ECDH-ES+A256KW',
          epk: {},
          apu: '',
          apv: ''
        },
        encrypted_key: 'AAAA'
      } as unknown as (typeof currentEpoch.recipients)[number]
    ]
    const rotated = await rotateUserKeyRoster({
      store: rosterStore,
      document,
      retireRecipientId: planted.id
    })
    const fresh = rotated.epochs!.find(
      epoch => epoch.id === rotated.currentEpoch
    )!
    expect(fresh.recipients.map(entry => entry.header.kid)).toEqual([
      clientKak.id
    ])
  })
})
