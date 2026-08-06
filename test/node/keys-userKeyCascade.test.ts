/**
 * Unit tests for the user key rotation cascade's per-collection half
 * (`src/keys/userKeyCascade.ts`) and the roster rotation helper
 * (`rotateUserKeyRoster`): generation recovery from the roster, the staleness
 * rule (a collection is stale exactly when its current epoch names a
 * non-current user key generation), the pre-epoch install, convergence under a
 * naive re-run, the collection fan-out driver (`cascadeCollectionsToUserKey`),
 * and the doc-backed resolver riding the roster rotation. All over in-memory
 * descriptor stores with the real epoch crypto.
 */
import { describe, expect, it } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import {
  epochKeyIdFor,
  initRecipients,
  resolveEpochKeys,
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
    clientKeyAgreementKey: clientKak,
    signEpochs: client.signEpochs
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
    retireRecipientId: revoked.id,
    signEpochs: client.signEpochs
  })
  const read = await readUserKeyRoster({
    store: rosterStore,
    clientKeyAgreementKey: clientKak,
    document
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

  it('installs the prior generation as epoch one on a pre-epoch collection, then rotates', async () => {
    const { clientKak, userKey1, userKey2, rosterDescriptor } =
      await rotatedRoster()
    // Declared encrypted, no epochs yet: its envelopes are sealed to user key 1's
    // KAK (the era's vault key).
    const collectionStore = memoryStore({ scheme: 'edv' })
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
    // Epoch one IS the prior generation (pre-epoch envelopes are
    // epoch-of-that-generation envelopes), readable through the current user key.
    expect(descriptor.epochs![0]!.id).toBe(userKey1.id)
    const keys = await resolveEpochKeys({
      encryption: descriptor,
      keyAgreementKey: userKeyVaultKeys({ userKey: userKey2 }).keyAgreementKey
    })
    expect(keys!.writeEpoch).toBe(descriptor.currentEpoch)
    expect(keys!.readKeys.map(key => key.id)).toContain(
      epochKeyIdFor(userKey1.id)
    )
    // Writes no longer land under the compromised generation's key.
    expect(descriptor.currentEpoch).not.toBe(userKey1.id)
  })

  it('installs the current user key alone on a first-generation account', async () => {
    const client = await makeRosterClient()
    const clientKak = client.kak
    const userKey = await mintUserKey()
    const rosterStore = memoryStore()
    const rosterDescriptor = await ensureUserKeyRoster({
      store: rosterStore,
      userKey,
      clientKeyAgreementKey: clientKak,
      signEpochs: client.signEpochs
    })
    const generations = await unwrapUserKeyGenerations({
      descriptor: rosterDescriptor,
      clientKeyAgreementKey: clientKak
    })
    const collectionStore = memoryStore({ scheme: 'edv' })
    const outcome = await rotateCollectionEpochsToUserKey({
      store: collectionStore,
      userKey,
      generations
    })
    expect(outcome).toBe('installed')
    const descriptor = collectionStore.state.descriptor!
    expect(descriptor.epochs).toHaveLength(1)
    expect(descriptor.currentEpoch).toBe(userKey.id)
  })

  it('retires several stranded generations at once', async () => {
    // Two crashes back to back: the collection's current epoch still names
    // user key 1 while the roster has moved through user key 2 to user key 3.
    const { client, clientKak, document, userKey1, userKey2, rosterStore } =
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
      retireRecipientId: another.id,
      signEpochs: client.signEpochs
    })
    const read = await readUserKeyRoster({
      store: rosterStore,
      clientKeyAgreementKey: clientKak,
      document
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
    const { addRecipient } = await import('@interop/was-client/edv')
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

  it('converges when a concurrent cascade wins the first-epoch race', async () => {
    // A first-generation account: both cascades take the no-previous-
    // generation branch of the pre-epoch install.
    const client = await makeRosterClient()
    const clientKak = client.kak
    const userKey = await mintUserKey()
    const rosterStore = memoryStore()
    const rosterDescriptor = await ensureUserKeyRoster({
      store: rosterStore,
      userKey,
      clientKeyAgreementKey: clientKak,
      signEpochs: client.signEpochs
    })
    const generations = await unwrapUserKeyGenerations({
      descriptor: rosterDescriptor,
      clientKeyAgreementKey: clientKak
    })

    // The winner installs the first epoch.
    const winnerStore = memoryStore({ scheme: 'edv' })
    expect(
      await rotateCollectionEpochsToUserKey({
        store: winnerStore,
        userKey,
        generations
      })
    ).toBe('installed')
    const winner = winnerStore.state.descriptor!

    // The loser's first read finds an empty collection; every read after it
    // -- the install's own compare-and-swap read included -- finds what the
    // winner landed in between.
    const loser = memoryStore({ scheme: 'edv' })
    let reads = 0
    const raced: EncryptionDescriptorStore = {
      ...loser,
      async read() {
        reads += 1
        if (reads > 1) {
          loser.state.descriptor = winner
        }
        return loser.read()
      }
    }

    const outcome = await rotateCollectionEpochsToUserKey({
      store: raced,
      userKey,
      generations
    })
    expect(outcome).toBe('noop')
    expect(loser.writes).toBe(0)
    expect(loser.state.descriptor).toBe(winner)
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
    const { client, clientKak, document, rosterStore } = await rotatedRoster()
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
      retireRecipientId: planted.id,
      signEpochs: client.signEpochs
    })
    const fresh = rotated.epochs!.find(
      epoch => epoch.id === rotated.currentEpoch
    )!
    expect(fresh.recipients.map(entry => entry.header.kid)).toEqual([
      clientKak.id
    ])
  })
})
