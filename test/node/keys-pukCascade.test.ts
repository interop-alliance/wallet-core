/**
 * Unit tests for the PUK rotation cascade's per-collection half
 * (`src/keys/pukCascade.ts`) and the roster rotation helper
 * (`rotatePukRoster`): generation recovery from the roster, the staleness
 * rule (a collection is stale exactly when its current epoch names a
 * non-current PUK generation), the pre-epoch install, convergence under a
 * naive re-run, the collection fan-out driver (`cascadeCollectionsToPuk`),
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
import { mintPuk, pukVaultKeys } from '../../src/keys/puk.js'
import {
  addPukRosterRecipient,
  ensurePukRoster,
  readPukRoster,
  rotatePukRoster
} from '../../src/keys/pukRoster.js'
import {
  cascadeCollectionsToPuk,
  pukAsRecipient,
  rotateCollectionEpochsToPuk,
  unwrapPukGenerations
} from '../../src/keys/pukCascade.js'

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
 * A wallet client's identity key-agreement key (a self-describing did:key).
 * The return type keeps `publicKeyMultibase` visible (the widened
 * `IKeyAgreementKey` drops it) so fixtures can mint recipient entries and
 * document stubs from it.
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
 * A two-generation account: a roster whose first epoch is PUK1 (wrapped to
 * one enrolled client) rotated to PUK2 through the doc-backed resolver.
 *
 * @returns {Promise<object>}
 */
async function rotatedRoster() {
  const clientKak = await makeClientKak()
  const puk1 = await mintPuk()
  const rosterStore = memoryStore()
  await ensurePukRoster({
    store: rosterStore,
    puk: puk1,
    clientKeyAgreementKey: clientKak
  })
  // A second enrolled party joins the roster, is revoked (its VM leaves the
  // stub verified document), and the rotation retires its wrap.
  const revoked = await makeClientKak()
  await addPukRosterRecipient({
    store: rosterStore,
    recipient: {
      id: revoked.id,
      publicKeyMultibase: revoked.publicKeyMultibase
    },
    ownerKeyAgreementKey: clientKak
  })
  const document = {
    keyAgreement: [
      {
        id: `did:webvh:x#${clientKak.publicKeyMultibase}`,
        publicKeyMultibase: clientKak.publicKeyMultibase
      }
    ]
  }
  await rotatePukRoster({
    store: rosterStore,
    document,
    retireRecipientId: revoked.id
  })
  const read = await readPukRoster({
    store: rosterStore,
    clientKeyAgreementKey: clientKak
  })
  const puk2 = read!.puk
  expect(read!.rotated).toBe(true)
  expect(puk2.id).not.toBe(puk1.id)
  return {
    clientKak,
    puk1,
    puk2,
    rosterStore,
    rosterDescriptor: read!.descriptor
  }
}

describe('unwrapPukGenerations', () => {
  it('recovers every generation from the roster in order', async () => {
    const { clientKak, puk1, puk2, rosterDescriptor } = await rotatedRoster()
    const generations = await unwrapPukGenerations({
      descriptor: rosterDescriptor,
      clientKeyAgreementKey: clientKak
    })
    expect(generations.map(generation => generation.id)).toEqual([
      puk1.id,
      puk2.id
    ])
    expect(generations[0]!.secret).toEqual(puk1.secret)
  })

  it('skips an epoch this client holds no wrap in', async () => {
    const { clientKak, puk2, rosterStore } = await rotatedRoster()
    const stranger = await makeClientKak()
    // A later-enrolled party gets escrow wraps in every epoch; a stranger
    // with no wraps recovers nothing.
    await addPukRosterRecipient({
      store: rosterStore,
      recipient: {
        id: stranger.id,
        publicKeyMultibase: stranger.publicKeyMultibase
      },
      ownerKeyAgreementKey: clientKak
    })
    const read = await readPukRoster({
      store: rosterStore,
      puk: puk2,
      clientKeyAgreementKey: clientKak
    })
    const strangers = await unwrapPukGenerations({
      descriptor: read!.descriptor,
      clientKeyAgreementKey: await makeClientKak()
    })
    expect(strangers).toEqual([])
  })
})

describe('rotateCollectionEpochsToPuk', () => {
  it('rotates a stale collection: fresh epoch on the current PUK, history escrowed, other readers ride through', async () => {
    const { clientKak, puk1, puk2, rosterDescriptor } = await rotatedRoster()
    const app = await makeClientKak()
    const collectionStore = memoryStore()
    await initRecipients({
      store: collectionStore,
      recipients: [
        pukAsRecipient({ puk: puk1 }),
        { id: app.id, publicKeyMultibase: app.publicKeyMultibase }
      ]
    })
    const generations = await unwrapPukGenerations({
      descriptor: rosterDescriptor,
      clientKeyAgreementKey: clientKak
    })

    const outcome = await rotateCollectionEpochsToPuk({
      store: collectionStore,
      puk: puk2,
      generations
    })
    expect(outcome).toBe('rotated')

    const descriptor = collectionStore.state.descriptor!
    expect(descriptor.epochs).toHaveLength(2)
    const current = descriptor.epochs!.find(
      epoch => epoch.id === descriptor.currentEpoch
    )!
    const kids = current.recipients.map(entry => entry.header.kid)
    expect(kids).toContain(epochKeyIdFor(puk2.id))
    expect(kids).toContain(app.id)
    expect(kids).not.toContain(epochKeyIdFor(puk1.id))
    // The current PUK reads the whole history (escrow), and the app still
    // resolves every epoch.
    const puk2Keys = await resolveEpochKeys({
      encryption: descriptor,
      keyAgreementKey: pukVaultKeys({ puk: puk2 }).keyAgreementKey
    })
    expect(puk2Keys!.readKeys).toHaveLength(2)
    const appKeys = await resolveEpochKeys({
      encryption: descriptor,
      keyAgreementKey: app
    })
    expect(appKeys!.readKeys).toHaveLength(2)
  })

  it('is a no-op on a collection already on the current PUK (naive re-run convergence)', async () => {
    const { clientKak, puk2, rosterDescriptor } = await rotatedRoster()
    const collectionStore = memoryStore()
    await initRecipients({
      store: collectionStore,
      recipients: [pukAsRecipient({ puk: puk2 })]
    })
    const generations = await unwrapPukGenerations({
      descriptor: rosterDescriptor,
      clientKeyAgreementKey: clientKak
    })
    const writesBefore = collectionStore.writes
    const outcome = await rotateCollectionEpochsToPuk({
      store: collectionStore,
      puk: puk2,
      generations
    })
    expect(outcome).toBe('noop')
    expect(collectionStore.writes).toBe(writesBefore)
  })

  it('installs the prior generation as epoch one on a pre-epoch collection, then rotates', async () => {
    const { clientKak, puk1, puk2, rosterDescriptor } = await rotatedRoster()
    // Declared encrypted, no epochs yet: its envelopes are sealed to PUK1's
    // KAK (the era's vault key).
    const collectionStore = memoryStore({ scheme: 'edv' })
    const generations = await unwrapPukGenerations({
      descriptor: rosterDescriptor,
      clientKeyAgreementKey: clientKak
    })
    const outcome = await rotateCollectionEpochsToPuk({
      store: collectionStore,
      puk: puk2,
      generations
    })
    expect(outcome).toBe('rotated')
    const descriptor = collectionStore.state.descriptor!
    expect(descriptor.epochs).toHaveLength(2)
    // Epoch one IS the prior generation (pre-epoch envelopes are
    // epoch-of-that-generation envelopes), readable through the current PUK.
    expect(descriptor.epochs![0]!.id).toBe(puk1.id)
    const keys = await resolveEpochKeys({
      encryption: descriptor,
      keyAgreementKey: pukVaultKeys({ puk: puk2 }).keyAgreementKey
    })
    expect(keys!.writeEpoch).toBe(descriptor.currentEpoch)
    expect(keys!.readKeys.map(key => key.id)).toContain(epochKeyIdFor(puk1.id))
    // Writes no longer land under the compromised generation's key.
    expect(descriptor.currentEpoch).not.toBe(puk1.id)
  })

  it('installs the current PUK alone on a first-generation account', async () => {
    const clientKak = await makeClientKak()
    const puk = await mintPuk()
    const rosterStore = memoryStore()
    const rosterDescriptor = await ensurePukRoster({
      store: rosterStore,
      puk,
      clientKeyAgreementKey: clientKak
    })
    const generations = await unwrapPukGenerations({
      descriptor: rosterDescriptor,
      clientKeyAgreementKey: clientKak
    })
    const collectionStore = memoryStore({ scheme: 'edv' })
    const outcome = await rotateCollectionEpochsToPuk({
      store: collectionStore,
      puk,
      generations
    })
    expect(outcome).toBe('installed')
    const descriptor = collectionStore.state.descriptor!
    expect(descriptor.epochs).toHaveLength(1)
    expect(descriptor.currentEpoch).toBe(puk.id)
  })

  it('retires several stranded generations at once', async () => {
    // Two crashes back to back: the collection's current epoch still names
    // PUK1 while the roster has moved through PUK2 to PUK3.
    const { clientKak, puk1, puk2, rosterStore } = await rotatedRoster()
    const another = await makeClientKak()
    await addPukRosterRecipient({
      store: rosterStore,
      recipient: {
        id: another.id,
        publicKeyMultibase: another.publicKeyMultibase
      },
      ownerKeyAgreementKey: clientKak
    })
    const document = {
      keyAgreement: [
        {
          id: `did:webvh:x#${clientKak.publicKeyMultibase}`,
          publicKeyMultibase: clientKak.publicKeyMultibase
        }
      ]
    }
    await rotatePukRoster({
      store: rosterStore,
      document,
      retireRecipientId: another.id
    })
    const read = await readPukRoster({
      store: rosterStore,
      clientKeyAgreementKey: clientKak
    })
    const puk3 = read!.puk
    const generations = await unwrapPukGenerations({
      descriptor: read!.descriptor,
      clientKeyAgreementKey: clientKak
    })
    expect(generations).toHaveLength(3)

    const collectionStore = memoryStore()
    await initRecipients({
      store: collectionStore,
      recipients: [pukAsRecipient({ puk: puk1 })]
    })
    // Simulate the crashed first cascade's escrow half: PUK2 escrowed into
    // the (still current) PUK1 epoch, no rotation.
    const { addRecipient } = await import('@interop/was-client/edv')
    await addRecipient({
      store: collectionStore,
      recipient: pukAsRecipient({ puk: puk2 }),
      owner: { keyAgreementKey: pukVaultKeys({ puk: puk1 }).keyAgreementKey }
    })

    const outcome = await rotateCollectionEpochsToPuk({
      store: collectionStore,
      puk: puk3,
      generations
    })
    expect(outcome).toBe('rotated')
    const descriptor = collectionStore.state.descriptor!
    const current = descriptor.epochs!.find(
      epoch => epoch.id === descriptor.currentEpoch
    )!
    const kids = current.recipients.map(entry => entry.header.kid)
    expect(kids).toEqual([epochKeyIdFor(puk3.id)])
  })

  it('converges when a concurrent cascade wins the first-epoch race', async () => {
    // A first-generation account: both cascades take the no-previous-
    // generation branch of the pre-epoch install.
    const clientKak = await makeClientKak()
    const puk = await mintPuk()
    const rosterStore = memoryStore()
    const rosterDescriptor = await ensurePukRoster({
      store: rosterStore,
      puk,
      clientKeyAgreementKey: clientKak
    })
    const generations = await unwrapPukGenerations({
      descriptor: rosterDescriptor,
      clientKeyAgreementKey: clientKak
    })

    // The winner installs the first epoch.
    const winnerStore = memoryStore({ scheme: 'edv' })
    expect(
      await rotateCollectionEpochsToPuk({
        store: winnerStore,
        puk,
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

    const outcome = await rotateCollectionEpochsToPuk({
      store: raced,
      puk,
      generations
    })
    expect(outcome).toBe('noop')
    expect(loser.writes).toBe(0)
    expect(loser.state.descriptor).toBe(winner)
  })
})

describe('cascadeCollectionsToPuk', () => {
  it('fans out over the named collections, reporting each outcome', async () => {
    const { clientKak, puk1, puk2, rosterDescriptor } = await rotatedRoster()
    const stale = memoryStore()
    await initRecipients({
      store: stale,
      recipients: [pukAsRecipient({ puk: puk1 })]
    })
    const current = memoryStore()
    await initRecipients({
      store: current,
      recipients: [pukAsRecipient({ puk: puk2 })]
    })
    const stores: Record<string, EncryptionDescriptorStore> = {
      'private-credentials': stale,
      'wallet-activity': current
    }
    const result = await cascadeCollectionsToPuk({
      collectionIds: Object.keys(stores),
      storeFor: collectionId => stores[collectionId]!,
      rosterDescriptor,
      clientKeyAgreementKey: clientKak,
      puk: puk2
    })
    expect(result.failed).toEqual([])
    expect(result.outcomes).toEqual({
      'private-credentials': 'rotated',
      'wallet-activity': 'noop'
    })
  })

  it('skips a collection the isEncrypted pre-filter rejects', async () => {
    const { clientKak, puk2, rosterDescriptor } = await rotatedRoster()
    const collectionStore = memoryStore()
    await initRecipients({
      store: collectionStore,
      recipients: [pukAsRecipient({ puk: puk2 })]
    })
    const storeFor = (collectionId: string) => {
      if (collectionId !== 'private-credentials') {
        throw new Error('storeFor reached a filtered collection')
      }
      return collectionStore
    }
    const result = await cascadeCollectionsToPuk({
      collectionIds: ['private-credentials', 'public-credentials'],
      storeFor,
      isEncrypted: async collectionId => collectionId === 'private-credentials',
      rosterDescriptor,
      clientKeyAgreementKey: clientKak,
      puk: puk2
    })
    expect(result.failed).toEqual([])
    expect(result.outcomes).toEqual({ 'private-credentials': 'noop' })
  })

  it('collects a failing collection without aborting the rest', async () => {
    const { clientKak, puk1, puk2, rosterDescriptor } = await rotatedRoster()
    const stale = memoryStore()
    await initRecipients({
      store: stale,
      recipients: [pukAsRecipient({ puk: puk1 })]
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
    const result = await cascadeCollectionsToPuk({
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
      puk: puk2
    })
    expect(result.outcomes).toEqual({ 'private-credentials': 'rotated' })
    expect(result.failed).toHaveLength(1)
    expect(result.failed[0]!.collectionId).toBe('contacts')
    expect((result.failed[0]!.error as Error).message).toBe(
      'descriptor read refused'
    )
  })
})

describe('rotatePukRoster', () => {
  it('drops a roster entry with no document VM and never re-wraps the retiree', async () => {
    const { clientKak, rosterStore } = await rotatedRoster()
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
    const document = {
      keyAgreement: [
        {
          id: `did:webvh:x#${clientKak.publicKeyMultibase}`,
          publicKeyMultibase: clientKak.publicKeyMultibase
        }
      ]
    }
    const rotated = await rotatePukRoster({
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
