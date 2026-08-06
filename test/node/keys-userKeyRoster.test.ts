/**
 * Unit tests for the user key wrap-set roster (`src/keys/userKeyRoster.ts`):
 * init / read / rotate round-trips driven through the real was-client recipient
 * primitives over an in-memory descriptor store, the document-backed recipient
 * resolver's skip contract (a server-injected roster entry with no matching
 * did:webvh `keyAgreement` verification method receives no wrap on the next
 * rotation), the latest-seen-epoch pin tripping on a rolled-back roster,
 * `epochsMac` rejecting a fabricated epoch configuration, and `epochsSig`
 * refusing a server-minted epoch on the adopt (rotated/first-read) path -- the
 * one place the MAC alone proves nothing against the host.
 */
import { describe, expect, it } from 'vitest'
import { PreconditionFailedError } from '@interop/was-client'
import type { CollectionEncryption } from '@interop/was-client'
import {
  addRecipient,
  computeEpochsMac,
  mintEpoch,
  ownerRecipient,
  removeRecipient,
  wrapEpochSecret,
  type EncryptionDescriptorStore
} from '@interop/was-client/edv'
import { mintUserKey } from '../../src/keys/userKey.js'
import {
  addUserKeyRosterRecipient,
  convergeUserKeyRosterToDocument,
  ensureUserKeyRoster,
  UserKeyRosterContinuityError,
  UserKeyRosterIntegrityError,
  UserKeyRosterUnwrapError,
  userKeyRosterRecipientResolver,
  readUserKeyRoster,
  rosterRecipientKid
} from '../../src/keys/userKeyRoster.js'
import {
  makeRosterClient as makeClient,
  rosterDocumentFor as documentFor
} from './fixtures/rosterClient.js'

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

describe('ensureUserKeyRoster', () => {
  it('creates an absent roster with the user key installed as its first epoch', async () => {
    const alice = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()

    const descriptor = await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })
    // The roster's current epoch IS the user key: the epoch id is the user key's
    // did:key, the wrapped secret is the user key's raw key.
    expect(descriptor.currentEpoch).toBe(userKey.id)
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
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    const created = await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })

    const other = await makeClient()
    const again = await ensureUserKeyRoster({
      store,
      userKey: await mintUserKey(),
      clientKeyAgreementKey: other.kak,
      signEpochs: other.signEpochs
    })
    expect(again).toEqual(created)
    expect(store._getDescriptor()).toEqual(created)
  })
})

describe('addUserKeyRosterRecipient (the enrollment wrap)', () => {
  it('escrows every epoch to the new client, who then reads the user key with no cached copy', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const carol = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })

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
      resolveRecipientKey: userKeyRosterRecipientResolver({
        document: documentFor([alice])
      }),
      signEpochs: alice.signEpochs
    })

    // The enrollment wrap: the recipient arrives as public halves (the
    // connect-code shape), not a key object.
    const descriptor = await addUserKeyRosterRecipient({
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

    // The enrollee's first read: no cached user key at all (the userKey-less path),
    // authenticated end to end -- the epoch configuration signature checked
    // against the document that now backs bob too -- delivering the current
    // epoch's key.
    const read = await readUserKeyRoster({
      store,
      clientKeyAgreementKey: bob.kak,
      document: documentFor([alice, bob])
    })
    expect(read).not.toBeNull()
    expect(read!.rotated).toBe(true)
    expect(read!.userKey.id).toBe(descriptor.currentEpoch)
    expect(read!.userKey.secret).toHaveLength(32)
  })

  it('is idempotent: a standing wrap is returned without a write', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })

    const recipient = {
      id: bob.kak.id as string,
      publicKeyMultibase: bob.publicKeyMultibase
    }
    const first = await addUserKeyRosterRecipient({
      store,
      recipient,
      ownerKeyAgreementKey: alice.kak
    })
    const again = await addUserKeyRosterRecipient({
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
      addUserKeyRosterRecipient({
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
  it('confirms a current cached user key, delivers a rotation, and refuses a revoked client', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const carol = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()

    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })
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

    // A read with the current cached user key confirms it, no rotation.
    const current = await readUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: bob.kak
    })
    expect(current).not.toBeNull()
    expect(current!.rotated).toBe(false)
    expect(current!.userKey).toBe(userKey)
    expect(current!.latestEpochId).toBe(userKey.id)

    // Revoking carol rotates the roster: the pull axis is a caller-supplied
    // action (the consumer's real pull axis is a did:webvh document edit),
    // and remaining recipients resolve from the verified document.
    const rotated = await removeRecipient({
      store,
      recipientId: carol.kak.id,
      pull: async () => {},
      resolveRecipientKey: userKeyRosterRecipientResolver({
        document: documentFor([alice, bob])
      }),
      signEpochs: alice.signEpochs
    })
    expect(rotated.currentEpoch).not.toBe(userKey.id)

    // Rotation delivery: bob's next read (cached user key now stale, its epoch
    // pinned from before) unwraps the fresh user key with his own key, after the
    // rotated configuration's signature checks out against the document. The
    // roster wraps the key-agreement secret alone, so no signing seed rides
    // along.
    const delivered = await readUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: bob.kak,
      pinnedEpochId: userKey.id,
      document: documentFor([alice, bob])
    })
    expect(delivered!.rotated).toBe(true)
    expect(delivered!.userKey.id).toBe(rotated.currentEpoch)
    expect(delivered!.userKey.secret).toHaveLength(32)
    expect(delivered!.userKey.secret).not.toEqual(userKey.secret)
    expect(delivered!.userKey.signingSeed).toBeUndefined()
    expect(delivered!.latestEpochId).toBe(rotated.currentEpoch)

    // Alice unwraps the same fresh user key -- one rotated key, delivered to all
    // remaining clients.
    const deliveredToAlice = await readUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      pinnedEpochId: userKey.id,
      document: documentFor([alice, bob])
    })
    expect(Array.from(deliveredToAlice!.userKey.secret)).toEqual(
      Array.from(delivered!.userKey.secret)
    )

    // The revoked client holds no wrap in the current epoch.
    await expect(
      readUserKeyRoster({
        store,
        userKey,
        clientKeyAgreementKey: carol.kak,
        pinnedEpochId: userKey.id,
        document: documentFor([alice, bob])
      })
    ).rejects.toThrow(UserKeyRosterUnwrapError)
  })

  it('resolves null on an absent roster (an account not yet provisioned)', async () => {
    const alice = await makeClient()
    expect(
      await readUserKeyRoster({
        store: memoryDescriptorStore(),
        userKey: await mintUserKey(),
        clientKeyAgreementKey: alice.kak
      })
    ).toBeNull()
  })
})

describe('the document-backed recipient resolver (delivers, never sources)', () => {
  it('resolves a kid only through a matching keyAgreement verification method', async () => {
    const alice = await makeClient()
    const resolve = userKeyRosterRecipientResolver({
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
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()

    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })
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
      resolveRecipientKey: userKeyRosterRecipientResolver({
        document: documentFor([alice, bob])
      }),
      signEpochs: alice.signEpochs
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
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()

    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })
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
      resolveRecipientKey: userKeyRosterRecipientResolver({
        document: documentFor([alice])
      }),
      signEpochs: alice.signEpochs
    })

    // The host replays the entire old configuration. The MAC alone cannot
    // catch a whole-configuration replay (its documented limitation); the
    // pinned latest-seen epoch does.
    store._setDescriptor(preRotation)
    await expect(
      readUserKeyRoster({
        store,
        userKey,
        clientKeyAgreementKey: alice.kak,
        pinnedEpochId: rotated.currentEpoch
      })
    ).rejects.toThrow(UserKeyRosterContinuityError)
  })
})

describe('epochsMac (authenticated epoch configuration)', () => {
  it('rejects a fabricated epoch list', async () => {
    const alice = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })

    // The host fabricates an epoch configuration (an extra epoch id smuggled
    // into the list) without holding any epoch secret to re-key the MAC.
    const tampered = store._getDescriptor()!
    tampered.epochs = [
      ...tampered.epochs!,
      { id: 'did:key:z6LSfabricatedEpoch', recipients: [] }
    ]
    store._setDescriptor(tampered)

    await expect(
      readUserKeyRoster({ store, userKey, clientKeyAgreementKey: alice.kak })
    ).rejects.toThrow(UserKeyRosterIntegrityError)
  })

  it('rejects a roster whose MAC was stripped', async () => {
    const alice = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })

    const tampered = store._getDescriptor()!
    delete tampered.epochsMac
    store._setDescriptor(tampered)

    await expect(
      readUserKeyRoster({ store, userKey, clientKeyAgreementKey: alice.kak })
    ).rejects.toThrow(UserKeyRosterIntegrityError)
  })

  it('rejects a roster whose current epoch is not in its own list', async () => {
    const alice = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })

    const tampered = store._getDescriptor()!
    tampered.currentEpoch = 'did:key:z6LSelsewhere'
    store._setDescriptor(tampered)

    await expect(
      readUserKeyRoster({ store, userKey, clientKeyAgreementKey: alice.kak })
    ).rejects.toThrow(UserKeyRosterIntegrityError)
  })
})

describe('epochsSig (roster provenance on the adopt path)', () => {
  /**
   * What a compromised host can build all by itself: a fresh epoch minted
   * server-side, wrapped to the victim's world-readable key-agreement key,
   * with the `epochsMac` computed under that same minted secret -- an
   * internally consistent configuration the MAC check accepts. Only the
   * missing (or unbacked) signature gives it away.
   *
   * @param options {object}
   * @param options.victim {{ kak: IKeyAgreementKey, publicKeyMultibase: string }}
   * @param [options.priorEpochs] {CollectionEncryption['epochs']}   legit
   *   epochs to keep in the list (a fabricated rotation atop a real roster)
   * @returns {Promise<CollectionEncryption>}
   */
  async function fabricateRoster({
    victim,
    priorEpochs = []
  }: {
    victim: { kak: { id?: string }; publicKeyMultibase: string }
    priorEpochs?: CollectionEncryption['epochs']
  }): Promise<CollectionEncryption> {
    const { epochId, secret } = await mintEpoch()
    const fabricated: CollectionEncryption = {
      scheme: 'edv',
      version: 1,
      epochs: [
        ...priorEpochs!,
        {
          id: epochId,
          recipients: [
            await wrapEpochSecret({
              epochSecret: secret,
              recipient: {
                id: victim.kak.id!,
                publicKeyMultibase: victim.publicKeyMultibase
              }
            })
          ]
        }
      ],
      currentEpoch: epochId
    }
    fabricated.epochsMac = await computeEpochsMac({
      descriptor: fabricated,
      epochSecret: secret
    })
    return fabricated
  }

  it("refuses a fabricated roster on a fresh client's first read (WC-1)", async () => {
    const alice = await makeClient()
    const victim = await makeClient()
    const store = memoryDescriptorStore()

    // The server serves a wholly fabricated roster: fresh epoch wrapped to
    // the victim's public key-agreement key, epochsMac keyed under the same
    // minted secret. The self-referential MAC verifies; the signature check
    // must be what refuses it.
    store._setDescriptor(await fabricateRoster({ victim }))
    await expect(
      readUserKeyRoster({
        store,
        clientKeyAgreementKey: victim.kak,
        document: documentFor([alice, victim])
      })
    ).rejects.toThrow(UserKeyRosterIntegrityError)

    // Copying a stale-but-genuine signature from an earlier legit roster
    // does not help: it does not cover the fabricated configuration.
    const legit = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store: legit,
      userKey: await mintUserKey(),
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })
    const staleSig = legit._getDescriptor()!.epochsSig!
    const withStaleSig = await fabricateRoster({ victim })
    withStaleSig.epochsSig = staleSig
    store._setDescriptor(withStaleSig)
    await expect(
      readUserKeyRoster({
        store,
        clientKeyAgreementKey: victim.kak,
        document: documentFor([alice, victim])
      })
    ).rejects.toThrow(UserKeyRosterIntegrityError)
  })

  it('refuses a fabricated rotation spliced atop the legit roster', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })
    await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: bob.kak }),
      owner: { keyAgreementKey: alice.kak }
    })

    // The host splices a minted epoch on top of the genuine list (so bob's
    // pinned epoch still appears -- continuity passes) and re-MACs under the
    // minted secret, keeping the genuine-but-stale signature in place.
    const legit = store._getDescriptor()!
    const spliced = await fabricateRoster({
      victim: bob,
      priorEpochs: legit.epochs
    })
    spliced.epochsSig = legit.epochsSig
    store._setDescriptor(spliced)

    await expect(
      readUserKeyRoster({
        store,
        userKey,
        clientKeyAgreementKey: bob.kak,
        pinnedEpochId: userKey.id,
        document: documentFor([alice, bob])
      })
    ).rejects.toThrow(UserKeyRosterIntegrityError)
  })

  it('refuses a rotation signed by a key the document does not back', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })
    await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: bob.kak }),
      owner: { keyAgreementKey: alice.kak }
    })
    await removeRecipient({
      store,
      recipientId: bob.kak.id!,
      pull: async () => {},
      resolveRecipientKey: userKeyRosterRecipientResolver({
        document: documentFor([alice])
      }),
      signEpochs: alice.signEpochs
    })

    // The rotation is genuine, but the reader's verified document no longer
    // carries the signer (e.g. the signer was revoked without a re-rotation):
    // fail closed rather than adopt an epoch nobody current vouches for.
    await expect(
      readUserKeyRoster({
        store,
        userKey,
        clientKeyAgreementKey: alice.kak,
        pinnedEpochId: userKey.id,
        document: documentFor([bob])
      })
    ).rejects.toThrow(UserKeyRosterIntegrityError)
  })

  it('requires the account document on the adopt path', async () => {
    const alice = await makeClient()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey: await mintUserKey(),
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })
    await expect(
      readUserKeyRoster({ store, clientKeyAgreementKey: alice.kak })
    ).rejects.toThrow('needs the account document')
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

describe('convergeUserKeyRosterToDocument (the torn-cascade detector)', () => {
  it('writes nothing when every roster recipient is keyed by the document', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })
    const enrolled = await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: bob.kak }),
      owner: { keyAgreementKey: alice.kak }
    })

    const result = await convergeUserKeyRosterToDocument({
      store,
      document: documentFor([alice, bob]),
      signEpochs: alice.signEpochs
    })
    expect(result.rotated).toBe(false)
    expect(result.staleRecipientIds).toEqual([])
    expect(result.descriptor).toEqual(enrolled)
    expect(store._getDescriptor()).toEqual(enrolled)
  })

  it('rotates away from a recipient the document no longer keys', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })
    await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: bob.kak }),
      owner: { keyAgreementKey: alice.kak }
    })

    // The state a cascade torn between its halves leaves behind: bob's
    // verification methods are out of the document, but the roster still
    // wraps the current user key to him.
    const document = documentFor([alice])
    const result = await convergeUserKeyRosterToDocument({
      store,
      document,
      signEpochs: alice.signEpochs
    })

    expect(result.rotated).toBe(true)
    expect(result.staleRecipientIds).toEqual([bob.kak.id])
    expect(result.descriptor!.currentEpoch).not.toBe(userKey.id)
    const current = result.descriptor!.epochs!.find(
      epoch => epoch.id === result.descriptor!.currentEpoch
    )!
    expect(current.recipients.map(entry => entry.header.kid)).toEqual([
      alice.kak.id
    ])

    // Alice adopts the fresh key by an ordinary read; bob cannot.
    const read = await readUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      pinnedEpochId: userKey.id,
      document
    })
    expect(read!.rotated).toBe(true)
    expect(read!.userKey.id).toBe(result.descriptor!.currentEpoch)
    await expect(
      readUserKeyRoster({
        store,
        userKey,
        clientKeyAgreementKey: bob.kak,
        document
      })
    ).rejects.toThrow(UserKeyRosterUnwrapError)

    // A second run over the converged pair is a no-op.
    const again = await convergeUserKeyRosterToDocument({
      store,
      document,
      signEpochs: alice.signEpochs
    })
    expect(again.rotated).toBe(false)
    expect(again.staleRecipientIds).toEqual([])
  })

  it('retires every stale recipient in one rotation', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const carol = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })
    for (const client of [bob, carol]) {
      await addRecipient({
        store,
        recipient: ownerRecipient({ keyAgreementKey: client.kak }),
        owner: { keyAgreementKey: alice.kak }
      })
    }

    const result = await convergeUserKeyRosterToDocument({
      store,
      document: documentFor([alice]),
      signEpochs: alice.signEpochs
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
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })
    const descriptor = await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: bob.kak }),
      owner: { keyAgreementKey: alice.kak }
    })

    const result = await convergeUserKeyRosterToDocument({
      store,
      document: documentFor([alice]),
      descriptor,
      signEpochs: alice.signEpochs
    })
    expect(result.rotated).toBe(true)
    expect(result.staleRecipientIds).toEqual([bob.kak.id])
  })

  it('refuses to rotate a roster no recipient of which the document keys', async () => {
    const alice = await makeClient()
    const stranger = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    const created = await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      signEpochs: alice.signEpochs
    })

    await expect(
      convergeUserKeyRosterToDocument({
        store,
        document: documentFor([stranger]),
        signEpochs: alice.signEpochs
      })
    ).rejects.toThrow(UserKeyRosterIntegrityError)
    expect(store._getDescriptor()).toEqual(created)
  })

  it('resolves on an absent roster without writing one', async () => {
    const alice = await makeClient()
    const store = memoryDescriptorStore()
    const result = await convergeUserKeyRosterToDocument({
      store,
      document: documentFor([alice]),
      signEpochs: alice.signEpochs
    })
    expect(result).toEqual({
      rotated: false,
      staleRecipientIds: [],
      descriptor: null
    })
    expect(store._getDescriptor()).toBeNull()
  })
})
