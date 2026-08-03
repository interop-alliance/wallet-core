/**
 * Unit tests for the PUK wrap-set roster (`src/keys/pukRoster.ts`): init /
 * read / rotate round-trips driven through the real was-client recipient
 * primitives over an in-memory descriptor store, the document-backed recipient
 * resolver's skip contract (a server-injected roster entry with no matching
 * did:webvh `keyAgreement` verification method receives no wrap on the next
 * rotation), the latest-seen-epoch pin tripping on a rolled-back roster, and
 * `epochsMac` rejecting a fabricated epoch configuration.
 */
import { describe, expect, it } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { PreconditionFailedError } from '@interop/was-client'
import type { CollectionEncryption } from '@interop/was-client'
import {
  addRecipient,
  ownerRecipient,
  removeRecipient,
  type EncryptionDescriptorStore
} from '@interop/was-client/edv'
import { mintPuk } from '../../src/keys/puk.js'
import {
  addPukRosterRecipient,
  convergePukRosterToDocument,
  ensurePukRoster,
  PukRosterContinuityError,
  PukRosterIntegrityError,
  PukRosterUnwrapError,
  pukRosterRecipientResolver,
  readPukRoster,
  rosterRecipientKid,
  type RosterRecipientDocument
} from '../../src/keys/pukRoster.js'

/**
 * An in-memory `EncryptionDescriptorStore` with a monotonic version counter
 * as the compare-and-swap etag, plus a `_setDescriptor` control seam so tests
 * can simulate a tampering/replaying host (the resource host enforces no
 * descriptor invariants, which is exactly the property under test).
 */
function memoryDescriptorStore(): EncryptionDescriptorStore & {
  _getDescriptor(): CollectionEncryption | null
  _setDescriptor(descriptor: CollectionEncryption | null): void
} {
  let descriptor: CollectionEncryption | null = null
  let version = 0
  return {
    async read() {
      return descriptor
        ? { descriptor: structuredClone(descriptor), etag: `v${version}` }
        : null
    },
    async replace(next, { ifMatch }: { ifMatch?: string }) {
      if (ifMatch !== `v${version}`) {
        throw new PreconditionFailedError('stale descriptor etag')
      }
      descriptor = next
      version++
    },
    async create(next) {
      if (descriptor) {
        throw new PreconditionFailedError('descriptor already exists')
      }
      descriptor = next
      version++
    },
    _getDescriptor() {
      return descriptor ? structuredClone(descriptor) : null
    },
    _setDescriptor(next) {
      descriptor = next
      version++
    }
  }
}

/**
 * A wallet client for the tests: its identity key-agreement key (the roster
 * recipient, id'd in the self-describing did:key form the wallet's client
 * KAK uses) and its public multibase, for building document verification
 * methods.
 */
async function makeClient(): Promise<{
  kak: IKeyAgreementKey
  publicKeyMultibase: string
}> {
  const kak = await X25519KeyAgreementKey2020.generate()
  const publicKeyMultibase = kak.publicKeyMultibase as string
  const did = `did:key:${publicKeyMultibase}`
  kak.controller = did
  kak.id = `${did}#${publicKeyMultibase}`
  return { kak: kak as IKeyAgreementKey, publicKeyMultibase }
}

/**
 * The locally verified did:webvh document for a set of enrolled clients: one
 * `keyAgreement` verification method per client, in the
 * `<did:webvh>#<multibase>` id form the enrollment ceremony publishes.
 */
function documentFor(
  clients: Array<{ publicKeyMultibase: string }>
): RosterRecipientDocument {
  const did = 'did:webvh:QmScid:example.com:space:abc:id'
  return {
    verificationMethod: clients.map(client => ({
      id: `${did}#${client.publicKeyMultibase}`,
      publicKeyMultibase: client.publicKeyMultibase
    })),
    keyAgreement: clients.map(client => `${did}#${client.publicKeyMultibase}`)
  }
}

describe('ensurePukRoster', () => {
  it('creates an absent roster with the PUK installed as its first epoch', async () => {
    const alice = await makeClient()
    const puk = await mintPuk()
    const store = memoryDescriptorStore()

    const descriptor = await ensurePukRoster({
      store,
      puk,
      clientKeyAgreementKey: alice.kak
    })
    // The roster's current epoch IS the PUK: the epoch id is the PUK's
    // did:key, the wrapped secret is the PUK's raw key.
    expect(descriptor.currentEpoch).toBe(puk.id)
    expect(descriptor.epochs).toHaveLength(1)
    expect(descriptor.epochs![0]!.recipients.map(r => r.header.kid)).toEqual([
      alice.kak.id
    ])
    expect(descriptor.epochsMac).toBeDefined()
    // The stored roster body is the descriptor verbatim.
    expect(store._getDescriptor()).toEqual(descriptor)
  })

  it('leaves an existing roster untouched (idempotent)', async () => {
    const alice = await makeClient()
    const puk = await mintPuk()
    const store = memoryDescriptorStore()
    const created = await ensurePukRoster({
      store,
      puk,
      clientKeyAgreementKey: alice.kak
    })

    const again = await ensurePukRoster({
      store,
      puk: await mintPuk(),
      clientKeyAgreementKey: (await makeClient()).kak
    })
    expect(again).toEqual(created)
    expect(store._getDescriptor()).toEqual(created)
  })
})

describe('addPukRosterRecipient (the enrollment wrap)', () => {
  it('escrows every epoch to the new client, who then reads the PUK with no cached copy', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const carol = await makeClient()
    const puk = await mintPuk()
    const store = memoryDescriptorStore()
    await ensurePukRoster({ store, puk, clientKeyAgreementKey: alice.kak })

    // Rotate once (revoking a temporary reader) so the roster holds history:
    // the escrow assertion below needs a pre-enrollment epoch.
    await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: carol.kak }),
      owner: { keyAgreementKey: alice.kak }
    })
    await removeRecipient({
      store,
      recipientId: carol.kak.id,
      pull: async () => {},
      resolveRecipientKey: pukRosterRecipientResolver({
        document: documentFor([alice])
      })
    })

    // The enrollment wrap: the recipient arrives as public halves (the
    // connect-code shape), not a key object.
    const descriptor = await addPukRosterRecipient({
      store,
      recipient: {
        id: bob.kak.id as string,
        publicKeyMultibase: bob.publicKeyMultibase
      },
      ownerKeyAgreementKey: alice.kak
    })
    // Escrow: bob holds a wrap in EVERY epoch, pre-enrollment ones included.
    expect(descriptor.epochs).toHaveLength(2)
    for (const epoch of descriptor.epochs!) {
      expect(epoch.recipients.map(r => r.header.kid)).toContain(bob.kak.id)
    }

    // The enrollee's first read: no cached PUK at all (the puk-less path),
    // authenticated end to end, delivering the current epoch's key.
    const read = await readPukRoster({
      store,
      clientKeyAgreementKey: bob.kak
    })
    expect(read).not.toBeNull()
    expect(read!.rotated).toBe(true)
    expect(read!.puk.id).toBe(descriptor.currentEpoch)
    expect(read!.puk.secret).toHaveLength(32)
  })

  it('is idempotent: a standing wrap is returned without a write', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const puk = await mintPuk()
    const store = memoryDescriptorStore()
    await ensurePukRoster({ store, puk, clientKeyAgreementKey: alice.kak })

    const recipient = {
      id: bob.kak.id as string,
      publicKeyMultibase: bob.publicKeyMultibase
    }
    const first = await addPukRosterRecipient({
      store,
      recipient,
      ownerKeyAgreementKey: alice.kak
    })
    const again = await addPukRosterRecipient({
      store,
      recipient,
      ownerKeyAgreementKey: alice.kak
    })
    expect(again).toEqual(first)
    expect(store._getDescriptor()).toEqual(first)
  })

  it('refuses to enroll into an absent roster', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    await expect(
      addPukRosterRecipient({
        store: memoryDescriptorStore(),
        recipient: {
          id: bob.kak.id as string,
          publicKeyMultibase: bob.publicKeyMultibase
        },
        ownerKeyAgreementKey: alice.kak
      })
    ).rejects.toThrow('roster does not exist')
  })
})

describe('roster init / read / rotate round-trip through the seam', () => {
  it('confirms a current cached PUK, delivers a rotation, and refuses a revoked client', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const carol = await makeClient()
    const puk = await mintPuk()
    const store = memoryDescriptorStore()

    await ensurePukRoster({ store, puk, clientKeyAgreementKey: alice.kak })
    // Enrollment escrow: bob and carol join every epoch.
    await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: bob.kak }),
      owner: { keyAgreementKey: alice.kak }
    })
    await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: carol.kak }),
      owner: { keyAgreementKey: alice.kak }
    })

    // A read with the current cached PUK confirms it, no rotation.
    const current = await readPukRoster({
      store,
      puk,
      clientKeyAgreementKey: bob.kak
    })
    expect(current).not.toBeNull()
    expect(current!.rotated).toBe(false)
    expect(current!.puk).toBe(puk)
    expect(current!.latestEpochId).toBe(puk.id)

    // Revoking carol rotates the roster: the pull axis is a caller-supplied
    // action (the consumer's real pull axis is a did:webvh document edit),
    // and remaining recipients resolve from the verified document.
    const rotated = await removeRecipient({
      store,
      recipientId: carol.kak.id,
      pull: async () => {},
      resolveRecipientKey: pukRosterRecipientResolver({
        document: documentFor([alice, bob])
      })
    })
    expect(rotated.currentEpoch).not.toBe(puk.id)

    // Rotation delivery: bob's next read (cached PUK now stale, its epoch
    // pinned from before) unwraps the fresh PUK with his own key. The
    // roster wraps the key-agreement secret alone, so no signing seed rides
    // along.
    const delivered = await readPukRoster({
      store,
      puk,
      clientKeyAgreementKey: bob.kak,
      pinnedEpochId: puk.id
    })
    expect(delivered!.rotated).toBe(true)
    expect(delivered!.puk.id).toBe(rotated.currentEpoch)
    expect(delivered!.puk.secret).toHaveLength(32)
    expect(delivered!.puk.secret).not.toEqual(puk.secret)
    expect(delivered!.puk.signingSeed).toBeUndefined()
    expect(delivered!.latestEpochId).toBe(rotated.currentEpoch)

    // Alice unwraps the same fresh PUK -- one rotated key, delivered to all
    // remaining clients.
    const deliveredToAlice = await readPukRoster({
      store,
      puk,
      clientKeyAgreementKey: alice.kak,
      pinnedEpochId: puk.id
    })
    expect(Array.from(deliveredToAlice!.puk.secret)).toEqual(
      Array.from(delivered!.puk.secret)
    )

    // The revoked client holds no wrap in the current epoch.
    await expect(
      readPukRoster({
        store,
        puk,
        clientKeyAgreementKey: carol.kak,
        pinnedEpochId: puk.id
      })
    ).rejects.toThrow(PukRosterUnwrapError)
  })

  it('resolves null on an absent roster (an account not yet provisioned)', async () => {
    const alice = await makeClient()
    expect(
      await readPukRoster({
        store: memoryDescriptorStore(),
        puk: await mintPuk(),
        clientKeyAgreementKey: alice.kak
      })
    ).toBeNull()
  })
})

describe('the document-backed recipient resolver (delivers, never sources)', () => {
  it('resolves a kid only through a matching keyAgreement verification method', async () => {
    const alice = await makeClient()
    const resolve = pukRosterRecipientResolver({
      document: documentFor([alice])
    })
    // The did:key-form kid matches its <did:webvh>#<multibase> VM on the
    // public-key material.
    expect(await resolve(alice.kak.id!)).toEqual({
      id: alice.kak.id,
      publicKeyMultibase: alice.publicKeyMultibase
    })
    const stranger = await makeClient()
    expect(await resolve(stranger.kak.id!)).toBeNull()
    expect(await resolve('not-a-key-id')).toBeNull()
  })

  it('drops a server-injected roster entry: no document VM, no wrap on the next rotation', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const attacker = await makeClient()
    const puk = await mintPuk()
    const store = memoryDescriptorStore()

    await ensurePukRoster({ store, puk, clientKeyAgreementKey: alice.kak })
    const enrolled = await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: bob.kak }),
      owner: { keyAgreementKey: alice.kak }
    })

    // The host injects a recipient entry for a key of its choosing. The MAC
    // deliberately does not cover recipient entries (an entry cannot be
    // forged into something that UNWRAPS without the epoch secret), so the
    // injected entry sits in the roster undetected...
    const tampered = structuredClone(enrolled)
    tampered.epochs![0]!.recipients.push({
      encrypted_key: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      header: {
        kid: attacker.kak.id!,
        alg: 'ECDH-ES+A256KW',
        epk: {
          kty: 'OKP',
          crv: 'X25519',
          x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        },
        apu: '',
        apv: ''
      }
    } as never)
    store._setDescriptor(tampered)

    // ...but it never receives a wrap: the rotation resolves remaining
    // recipients from the verified document, where the attacker has no
    // keyAgreement VM -- the skip contract drops the entry.
    const rotated = await removeRecipient({
      store,
      recipientId: bob.kak.id!,
      pull: async () => {},
      resolveRecipientKey: pukRosterRecipientResolver({
        document: documentFor([alice, bob])
      })
    })
    const currentEpoch = rotated.epochs!.find(
      epoch => epoch.id === rotated.currentEpoch
    )!
    expect(currentEpoch.recipients.map(r => r.header.kid)).toEqual([
      alice.kak.id
    ])
  })
})

describe('roster continuity (the latest-seen-epoch pin)', () => {
  it('trips on a rolled-back roster served by the store', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const puk = await mintPuk()
    const store = memoryDescriptorStore()

    await ensurePukRoster({ store, puk, clientKeyAgreementKey: alice.kak })
    await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: bob.kak }),
      owner: { keyAgreementKey: alice.kak }
    })
    // Snapshot the pre-rotation configuration -- internally consistent, its
    // MAC valid under the old epoch's secret.
    const preRotation = store._getDescriptor()!

    const rotated = await removeRecipient({
      store,
      recipientId: bob.kak.id!,
      pull: async () => {},
      resolveRecipientKey: pukRosterRecipientResolver({
        document: documentFor([alice])
      })
    })

    // The host replays the entire old configuration. The MAC alone cannot
    // catch a whole-configuration replay (its documented limitation); the
    // pinned latest-seen epoch does.
    store._setDescriptor(preRotation)
    await expect(
      readPukRoster({
        store,
        puk,
        clientKeyAgreementKey: alice.kak,
        pinnedEpochId: rotated.currentEpoch
      })
    ).rejects.toThrow(PukRosterContinuityError)
  })
})

describe('epochsMac (authenticated epoch configuration)', () => {
  it('rejects a fabricated epoch list', async () => {
    const alice = await makeClient()
    const puk = await mintPuk()
    const store = memoryDescriptorStore()
    await ensurePukRoster({ store, puk, clientKeyAgreementKey: alice.kak })

    // The host fabricates an epoch configuration (an extra epoch id smuggled
    // into the list) without holding any epoch secret to re-key the MAC.
    const tampered = store._getDescriptor()!
    tampered.epochs = [
      ...tampered.epochs!,
      { id: 'did:key:z6LSfabricatedEpoch', recipients: [] }
    ]
    store._setDescriptor(tampered)

    await expect(
      readPukRoster({ store, puk, clientKeyAgreementKey: alice.kak })
    ).rejects.toThrow(PukRosterIntegrityError)
  })

  it('rejects a roster whose MAC was stripped', async () => {
    const alice = await makeClient()
    const puk = await mintPuk()
    const store = memoryDescriptorStore()
    await ensurePukRoster({ store, puk, clientKeyAgreementKey: alice.kak })

    const tampered = store._getDescriptor()!
    delete tampered.epochsMac
    store._setDescriptor(tampered)

    await expect(
      readPukRoster({ store, puk, clientKeyAgreementKey: alice.kak })
    ).rejects.toThrow(PukRosterIntegrityError)
  })

  it('rejects a roster whose current epoch is not in its own list', async () => {
    const alice = await makeClient()
    const puk = await mintPuk()
    const store = memoryDescriptorStore()
    await ensurePukRoster({ store, puk, clientKeyAgreementKey: alice.kak })

    const tampered = store._getDescriptor()!
    tampered.currentEpoch = 'did:key:z6LSelsewhere'
    store._setDescriptor(tampered)

    await expect(
      readPukRoster({ store, puk, clientKeyAgreementKey: alice.kak })
    ).rejects.toThrow(PukRosterIntegrityError)
  })
})

describe('rosterRecipientKid', () => {
  it('builds the did:key-form kid a client reads its own wrap under', () => {
    expect(
      rosterRecipientKid({
        signingKeyMultibase: 'z6MkSigning',
        keyAgreementKeyMultibase: 'z6LSAgreement'
      })
    ).toBe('did:key:z6MkSigning#z6LSAgreement')
  })
})

describe('convergePukRosterToDocument (the torn-cascade detector)', () => {
  it('writes nothing when every roster recipient is keyed by the document', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const puk = await mintPuk()
    const store = memoryDescriptorStore()
    await ensurePukRoster({ store, puk, clientKeyAgreementKey: alice.kak })
    const enrolled = await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: bob.kak }),
      owner: { keyAgreementKey: alice.kak }
    })

    const result = await convergePukRosterToDocument({
      store,
      document: documentFor([alice, bob])
    })
    expect(result.rotated).toBe(false)
    expect(result.staleRecipientIds).toEqual([])
    expect(result.descriptor).toEqual(enrolled)
    expect(store._getDescriptor()).toEqual(enrolled)
  })

  it('rotates away from a recipient the document no longer keys', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const puk = await mintPuk()
    const store = memoryDescriptorStore()
    await ensurePukRoster({ store, puk, clientKeyAgreementKey: alice.kak })
    await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: bob.kak }),
      owner: { keyAgreementKey: alice.kak }
    })

    // The state a cascade torn between its halves leaves behind: bob's
    // verification methods are out of the document, but the roster still
    // wraps the current per-user key to him.
    const document = documentFor([alice])
    const result = await convergePukRosterToDocument({ store, document })

    expect(result.rotated).toBe(true)
    expect(result.staleRecipientIds).toEqual([bob.kak.id])
    expect(result.descriptor!.currentEpoch).not.toBe(puk.id)
    const current = result.descriptor!.epochs!.find(
      epoch => epoch.id === result.descriptor!.currentEpoch
    )!
    expect(current.recipients.map(entry => entry.header.kid)).toEqual([
      alice.kak.id
    ])

    // Alice adopts the fresh key by an ordinary read; bob cannot.
    const read = await readPukRoster({
      store,
      puk,
      clientKeyAgreementKey: alice.kak,
      pinnedEpochId: puk.id
    })
    expect(read!.rotated).toBe(true)
    expect(read!.puk.id).toBe(result.descriptor!.currentEpoch)
    await expect(
      readPukRoster({ store, puk, clientKeyAgreementKey: bob.kak })
    ).rejects.toThrow(PukRosterUnwrapError)

    // A second run over the converged pair is a no-op.
    const again = await convergePukRosterToDocument({ store, document })
    expect(again.rotated).toBe(false)
    expect(again.staleRecipientIds).toEqual([])
  })

  it('retires every stale recipient in one rotation', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const carol = await makeClient()
    const puk = await mintPuk()
    const store = memoryDescriptorStore()
    await ensurePukRoster({ store, puk, clientKeyAgreementKey: alice.kak })
    for (const client of [bob, carol]) {
      await addRecipient({
        store,
        recipient: ownerRecipient({ keyAgreementKey: client.kak }),
        owner: { keyAgreementKey: alice.kak }
      })
    }

    const result = await convergePukRosterToDocument({
      store,
      document: documentFor([alice])
    })
    expect(result.rotated).toBe(true)
    expect(result.staleRecipientIds.sort()).toEqual(
      [bob.kak.id, carol.kak.id].sort()
    )
    // One fresh epoch, wrapped to the one remaining recipient.
    expect(result.descriptor!.epochs).toHaveLength(2)
    const current = result.descriptor!.epochs!.find(
      epoch => epoch.id === result.descriptor!.currentEpoch
    )!
    expect(current.recipients.map(entry => entry.header.kid)).toEqual([
      alice.kak.id
    ])
  })

  it('accepts a descriptor the caller has already read', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const puk = await mintPuk()
    const store = memoryDescriptorStore()
    await ensurePukRoster({ store, puk, clientKeyAgreementKey: alice.kak })
    const descriptor = await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: bob.kak }),
      owner: { keyAgreementKey: alice.kak }
    })

    const result = await convergePukRosterToDocument({
      store,
      document: documentFor([alice]),
      descriptor
    })
    expect(result.rotated).toBe(true)
    expect(result.staleRecipientIds).toEqual([bob.kak.id])
  })

  it('refuses to rotate a roster no recipient of which the document keys', async () => {
    const alice = await makeClient()
    const stranger = await makeClient()
    const puk = await mintPuk()
    const store = memoryDescriptorStore()
    const created = await ensurePukRoster({
      store,
      puk,
      clientKeyAgreementKey: alice.kak
    })

    await expect(
      convergePukRosterToDocument({
        store,
        document: documentFor([stranger])
      })
    ).rejects.toThrow(PukRosterIntegrityError)
    expect(store._getDescriptor()).toEqual(created)
  })

  it('resolves on an absent roster without writing one', async () => {
    const alice = await makeClient()
    const store = memoryDescriptorStore()
    const result = await convergePukRosterToDocument({
      store,
      document: documentFor([alice])
    })
    expect(result).toEqual({
      rotated: false,
      staleRecipientIds: [],
      descriptor: null
    })
    expect(store._getDescriptor()).toBeNull()
  })
})
