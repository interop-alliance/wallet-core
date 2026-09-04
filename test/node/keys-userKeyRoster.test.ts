/**
 * Unit tests for the user key wrap-set roster (`src/keys/userKeyRoster.ts`):
 * init / read / rotate round-trips driven through the real was-client recipient
 * primitives over an in-memory descriptor store, the document-backed recipient
 * resolver's skip contract (a server-injected roster entry with no matching
 * did:webvh `keyAgreement` verification method receives no wrap on the next
 * rotation), the latest-seen-epoch pin tripping on a rolled-back roster, and
 * the descriptor consistency refusal (a current epoch the epoch list does not
 * carry), and the threaded-descriptor read (a caller reusing the descriptor a
 * verified operation on the same store just resolved, which skips the fetch
 * but keeps every check).
 */
import { describe, expect, it } from 'vitest'
import {
  createMultihash,
  MultihashAlgorithm
} from '@interop/data-integrity-core/multihash'
import { PreconditionFailedError } from '@interop/was-client'
import type { CollectionEncryption } from '@interop/was-client'
import {
  addRecipient,
  ownerRecipient,
  removeRecipient,
  type EncryptionDescriptorStore
} from '@interop/was-client/edv'
import { sha384 } from '@noble/hashes/sha2.js'
import { base58, base64urlnopad } from '@scure/base'
import { mintUserKey } from '../../src/keys/userKey.js'
import {
  keyAgreementCommitment,
  MULTIKEY_COMMITMENT_VM_TYPE,
  MULTIKEY_VM_TYPE
} from '../../src/webvh/didWebvh.js'
import {
  addUserKeyRosterRecipient,
  convergeUserKeyRosterToDocument,
  currentEpochOf,
  ensureUserKeyRoster,
  UserKeyRosterContinuityError,
  UserKeyRosterIntegrityError,
  UserKeyRosterUnwrapError,
  userKeyRosterRecipientResolver,
  readUserKeyRoster,
  replaceUserKeyRosterRecipients,
  rosterRecipientsToRetire,
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
  _writes(): number
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
    },
    // How many writes the store has taken: what a "one append" assertion
    // counts, the version counter doubling as the etag.
    _writes() {
      return version
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
      clientKeyAgreementKey: alice.kak
    })
    // The roster's current epoch IS the user key: the epoch id is the user key's
    // did:key, the wrapped secret is the user key's raw key.
    expect(descriptor.currentEpoch).toBe(userKey.id)
    expect(descriptor.epochs).toHaveLength(1)
    expect(descriptor.epochs![0]!.recipients.map(r => r.header.kid)).toEqual([
      alice.kak.id
    ])
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
      clientKeyAgreementKey: alice.kak
    })

    const other = await makeClient()
    const again = await ensureUserKeyRoster({
      store,
      userKey: await mintUserKey(),
      clientKeyAgreementKey: other.kak
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
      clientKeyAgreementKey: alice.kak
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
      })
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
      clientKeyAgreementKey: bob.kak
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
      clientKeyAgreementKey: alice.kak
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

  it('refuses a currentEpoch naming no epoch in its own list, without writing', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    const created = await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    store._setDescriptor({
      ...created,
      currentEpoch: 'did:key:zBogusEpochNobodyMinted'
    })
    const writesBefore = store._writes()

    let caught: unknown
    try {
      await addUserKeyRosterRecipient({
        store,
        recipient: {
          id: bob.kak.id as string,
          publicKeyMultibase: bob.publicKeyMultibase
        },
        ownerKeyAgreementKey: alice.kak
      })
    } catch (err) {
      caught = err
    }
    expect((caught as Error)?.name).toBe('UserKeyRosterIntegrityError')
    // The refusal happened before was-client's own `addRecipient` write path
    // ever ran.
    expect(store._writes()).toBe(writesBefore)
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
      clientKeyAgreementKey: alice.kak
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
      })
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
      pinnedEpochId: userKey.id
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
      pinnedEpochId: userKey.id
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
        pinnedEpochId: userKey.id
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

  it('backs a roster entry through a published hash commitment', async () => {
    // A low-entropy-derived standing unlock credential publishes only
    // `publicKeyCommitment`; the roster entry carries the real key, and the
    // resolver answers iff the key hashes to the published commitment.
    const alice = await makeClient()
    const credential = await makeClient()
    const did = 'did:webvh:QmScid:example.com:space:abc:id'
    const commitment = await keyAgreementCommitment({
      keyAgreementKeyMultibase: credential.publicKeyMultibase
    })
    const base = documentFor([alice])
    const document = {
      verificationMethod: [
        ...base.verificationMethod!,
        {
          id: `${did}#${commitment}`,
          type: MULTIKEY_COMMITMENT_VM_TYPE,
          publicKeyCommitment: commitment
        }
      ],
      keyAgreement: [...base.keyAgreement!, `${did}#${commitment}`]
    }
    const resolve = userKeyRosterRecipientResolver({ document })
    // The credential's kid resolves to its real key, vouched for by the
    // commitment; a stranger's key hashes to no published commitment.
    expect(await resolve(credential.kak.id!)).toEqual({
      id: credential.kak.id,
      publicKeyMultibase: credential.publicKeyMultibase
    })
    expect(await resolve(alice.kak.id!)).toEqual({
      id: alice.kak.id,
      publicKeyMultibase: alice.publicKeyMultibase
    })
    const stranger = await makeClient()
    expect(await resolve(stranger.kak.id!)).toBeNull()
  })

  it('backs a hybrid verification method on the branch its type declares, never both', async () => {
    // A method carrying BOTH `publicKeyMultibase` and `publicKeyCommitment`
    // (a drifted or buggy sibling implementation) must not authorize two
    // recipients: the `type` selects exactly one branch.
    const alice = await makeClient()
    const other = await makeClient()
    const did = 'did:webvh:QmScid:example.com:space:abc:id'
    const commitment = await keyAgreementCommitment({
      keyAgreementKeyMultibase: other.publicKeyMultibase
    })
    // A `Multikey` hybrid backs its verbatim key; the smuggled commitment
    // backs nothing.
    const asMultikey = userKeyRosterRecipientResolver({
      document: {
        verificationMethod: [
          {
            id: `${did}#${alice.publicKeyMultibase}`,
            type: MULTIKEY_VM_TYPE,
            publicKeyMultibase: alice.publicKeyMultibase,
            publicKeyCommitment: commitment
          }
        ],
        keyAgreement: [`${did}#${alice.publicKeyMultibase}`]
      }
    })
    expect(await asMultikey(alice.kak.id!)).toEqual({
      id: alice.kak.id,
      publicKeyMultibase: alice.publicKeyMultibase
    })
    expect(await asMultikey(other.kak.id!)).toBeNull()
    // A `MultikeyCommitment` hybrid backs its committed key; the smuggled
    // verbatim key backs nothing.
    const asCommitment = userKeyRosterRecipientResolver({
      document: {
        verificationMethod: [
          {
            id: `${did}#${commitment}`,
            type: MULTIKEY_COMMITMENT_VM_TYPE,
            publicKeyMultibase: alice.publicKeyMultibase,
            publicKeyCommitment: commitment
          }
        ],
        keyAgreement: [`${did}#${commitment}`]
      }
    })
    expect(await asCommitment(other.kak.id!)).toEqual({
      id: other.kak.id,
      publicKeyMultibase: other.publicKeyMultibase
    })
    expect(await asCommitment(alice.kak.id!)).toBeNull()
  })

  it('tolerates a malformed or unsupported commitment as a non-match', async () => {
    // Verification decodes the commitment, so a published entry that is not
    // a decodable multihash -- or names an algorithm with no implementation
    // -- backs nothing. It is dropped like any other unbacked entry rather
    // than failing the resolution.
    const alice = await makeClient()
    const credential = await makeClient()
    const did = 'did:webvh:QmScid:example.com:space:abc:id'
    const unsupported = base64urlnopad.encode(
      createMultihash(
        sha384(base58.decode(credential.publicKeyMultibase.slice(1))),
        MultihashAlgorithm.SHA2_384
      )
    )
    const base = documentFor([alice])
    for (const commitment of ['not-a-multihash!!', '', unsupported]) {
      const document = {
        verificationMethod: [
          ...base.verificationMethod!,
          {
            id: `${did}#${commitment}`,
            type: MULTIKEY_COMMITMENT_VM_TYPE,
            publicKeyCommitment: commitment
          }
        ],
        keyAgreement: [...base.keyAgreement!, `${did}#${commitment}`]
      }
      const resolve = userKeyRosterRecipientResolver({ document })
      expect(await resolve(credential.kak.id!)).toBeNull()
      // The healthy entries beside it still resolve.
      expect(await resolve(alice.kak.id!)).toEqual({
        id: alice.kak.id,
        publicKeyMultibase: alice.publicKeyMultibase
      })
    }
  })

  it('keeps a commitment-backed wrap across a rotation', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const credential = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: bob.kak }),
      owner: { keyAgreementKey: alice.kak }
    })
    await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: credential.kak }),
      owner: { keyAgreementKey: alice.kak }
    })

    // Revoke bob; the commitment-backed credential must keep its wrap, like
    // any verbatim-published recovery key would.
    const did = 'did:webvh:QmScid:example.com:space:abc:id'
    const commitment = await keyAgreementCommitment({
      keyAgreementKeyMultibase: credential.publicKeyMultibase
    })
    const base = documentFor([alice])
    const rotated = await removeRecipient({
      store,
      recipientId: bob.kak.id!,
      pull: async () => {},
      resolveRecipientKey: userKeyRosterRecipientResolver({
        document: {
          verificationMethod: [
            ...base.verificationMethod!,
            {
              id: `${did}#${commitment}`,
              type: MULTIKEY_COMMITMENT_VM_TYPE,
              publicKeyCommitment: commitment
            }
          ],
          keyAgreement: [...base.keyAgreement!, `${did}#${commitment}`]
        }
      })
    })
    const currentEpoch = rotated.epochs!.find(
      epoch => epoch.id === rotated.currentEpoch
    )!
    expect(currentEpoch.recipients.map(r => r.header.kid).sort()).toEqual(
      [alice.kak.id, credential.kak.id].sort()
    )
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
      clientKeyAgreementKey: alice.kak
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
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()

    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
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
      })
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

describe('currentEpochOf', () => {
  it('resolves the descriptor current epoch', async () => {
    const alice = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    const descriptor = await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })

    const currentEpoch = currentEpochOf({
      descriptor,
      label: 'The user key roster'
    })
    expect(currentEpoch.id).toBe(userKey.id)
    expect(currentEpoch.recipients.map(entry => entry.header.kid)).toEqual([
      alice.kak.id
    ])
  })

  it('refuses a currentEpoch naming no epoch in its own list, naming the label', async () => {
    const alice = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    const descriptor = await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })

    expect(() =>
      currentEpochOf({
        descriptor: { ...descriptor, currentEpoch: 'did:key:zNoSuchEpoch' },
        label: 'The collection descriptor'
      })
    ).toThrow(
      'The collection descriptor names no current epoch in its own epoch list.'
    )
  })
})

describe('descriptor consistency', () => {
  it('rejects a roster whose current epoch is not in its own list', async () => {
    const alice = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })

    const tampered = store._getDescriptor()!
    tampered.currentEpoch = 'did:key:z6LSelsewhere'
    store._setDescriptor(tampered)

    await expect(
      readUserKeyRoster({ store, userKey, clientKeyAgreementKey: alice.kak })
    ).rejects.toThrow(UserKeyRosterIntegrityError)
  })
})

// The detached `epochsSig` provenance suite that lived here (fabricated
// roster, spliced rotation, unbacked signer, document-required adopt path)
// was retired with the signature itself: the roster is now log-governed, and
// those properties are re-proven against the resource-log design in
// `resourceLog-verify.test.ts` and `keys-rosterLogStore.test.ts`.

describe('readUserKeyRoster with a threaded descriptor', () => {
  /**
   * A store that refuses to be read: any acquisition at all fails the test,
   * which is how "the threaded descriptor is used verbatim" is asserted.
   */
  function refusingStore(): EncryptionDescriptorStore {
    return {
      async read() {
        throw new Error('store.read must not be called')
      },
      async replace() {},
      async create() {}
    }
  }

  it('reads nothing and confirms a current cached user key', async () => {
    const alice = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    const descriptor = await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })

    const read = await readUserKeyRoster({
      store: refusingStore(),
      descriptor,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    expect(read.rotated).toBe(false)
    expect(read.userKey).toBe(userKey)
    expect(read.descriptor).toBe(descriptor)
    expect(read.latestEpochId).toBe(userKey.id)
  })

  it('delivers a rotated epoch exactly as the store-read path does', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: bob.kak }),
      owner: { keyAgreementKey: alice.kak }
    })
    const rotated = await removeRecipient({
      store,
      recipientId: bob.kak.id!,
      pull: async () => {},
      resolveRecipientKey: userKeyRosterRecipientResolver({
        document: documentFor([alice])
      })
    })

    const threaded = await readUserKeyRoster({
      store: refusingStore(),
      descriptor: rotated,
      userKey,
      clientKeyAgreementKey: alice.kak,
      pinnedEpochId: userKey.id
    })
    expect(threaded.rotated).toBe(true)
    expect(threaded.userKey.id).toBe(rotated.currentEpoch)
    expect(threaded.latestEpochId).toBe(rotated.currentEpoch)

    // The same key the ordinary read path resolves off the store.
    const viaStore = await readUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak,
      pinnedEpochId: userKey.id
    })
    expect(Array.from(threaded.userKey.secret)).toEqual(
      Array.from(viaStore!.userKey.secret)
    )
  })

  it('still trips the latest-seen-epoch pin on a rolled-back threaded descriptor', async () => {
    const alice = await makeClient()
    const bob = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: bob.kak }),
      owner: { keyAgreementKey: alice.kak }
    })
    const preRotation = store._getDescriptor()!
    const rotated = await removeRecipient({
      store,
      recipientId: bob.kak.id!,
      pull: async () => {},
      resolveRecipientKey: userKeyRosterRecipientResolver({
        document: documentFor([alice])
      })
    })

    // Continuity is this function's own check, not the store's: a threaded
    // descriptor gets it in full.
    await expect(
      readUserKeyRoster({
        store: refusingStore(),
        descriptor: preRotation,
        userKey,
        clientKeyAgreementKey: alice.kak,
        pinnedEpochId: rotated.currentEpoch
      })
    ).rejects.toThrow(UserKeyRosterContinuityError)
  })

  it('still refuses a threaded descriptor naming no current epoch', async () => {
    const alice = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    const descriptor = await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })

    await expect(
      readUserKeyRoster({
        store: refusingStore(),
        descriptor: { ...descriptor, currentEpoch: 'did:key:z6LSelsewhere' },
        userKey,
        clientKeyAgreementKey: alice.kak
      })
    ).rejects.toThrow(UserKeyRosterIntegrityError)
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

describe('rosterRecipientsToRetire', () => {
  it("names the current epoch's other kids, and refuses a roster with no current epoch", async () => {
    const keeper = await makeClient()
    const retiree = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    let descriptor = await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: keeper.kak
    })
    descriptor = await addUserKeyRosterRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: retiree.kak }),
      ownerKeyAgreementKey: keeper.kak
    })

    expect(
      rosterRecipientsToRetire({
        descriptor,
        keepRecipientIds: [keeper.kak.id]
      })
    ).toEqual([retiree.kak.id])
    expect(
      rosterRecipientsToRetire({
        descriptor,
        keepRecipientIds: [keeper.kak.id, retiree.kak.id]
      })
    ).toEqual([])
    expect(() =>
      rosterRecipientsToRetire({
        descriptor: { ...descriptor, currentEpoch: 'did:key:zNoSuchEpoch' },
        keepRecipientIds: []
      })
    ).toThrow(UserKeyRosterIntegrityError)
  })
})

describe('replaceUserKeyRosterRecipients (the one-write mandatory rotation)', () => {
  it('retires the spent wrap and escrows every incoming recipient in one call', async () => {
    const spentCode = await makeClient()
    const freshCredential = await makeClient()
    const replacementCode = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: spentCode.kak
    })

    // The document AFTER the continuation's add-and-retire entry: the spent
    // code is out, the fresh credential's and the replacement code's
    // key-agreement inventories are in.
    const descriptor = await replaceUserKeyRosterRecipients({
      store,
      document: documentFor([freshCredential, replacementCode]),
      retireRecipientIds: [spentCode.kak.id],
      recipients: [
        ownerRecipient({ keyAgreementKey: freshCredential.kak }),
        ownerRecipient({ keyAgreementKey: replacementCode.kak })
      ],
      ownerKeyAgreementKey: spentCode.kak
    })

    // A fresh epoch rotated off the spent code, wrapped to both incoming
    // recipients.
    expect(descriptor.currentEpoch).not.toBe(userKey.id)
    expect(descriptor.epochs).toHaveLength(2)
    const current = descriptor.epochs!.find(
      epoch => epoch.id === descriptor.currentEpoch
    )!
    const currentKids = current.recipients.map(entry => entry.header.kid)
    expect(currentKids).toContain(freshCredential.kak.id)
    expect(currentKids).toContain(replacementCode.kak.id)
    expect(currentKids).not.toContain(spentCode.kak.id)
    // The escrow reached history: both incoming recipients decrypt the
    // pre-rotation epoch too.
    const historic = descriptor.epochs!.find(epoch => epoch.id === userKey.id)!
    const historicKids = historic.recipients.map(entry => entry.header.kid)
    expect(historicKids).toContain(freshCredential.kak.id)
    expect(historicKids).toContain(replacementCode.kak.id)

    // Both incoming recipients adopt the fresh key by an ordinary read; the
    // spent code cannot.
    for (const incoming of [freshCredential, replacementCode]) {
      const read = await readUserKeyRoster({
        store,
        userKey,
        clientKeyAgreementKey: incoming.kak,
        pinnedEpochId: userKey.id
      })
      expect(read!.rotated).toBe(true)
      expect(read!.userKey.id).toBe(descriptor.currentEpoch)
      expect(read!.userKey.secret).toHaveLength(32)
    }
    await expect(
      readUserKeyRoster({
        store,
        userKey,
        clientKeyAgreementKey: spentCode.kak
      })
    ).rejects.toThrow(UserKeyRosterUnwrapError)
  })

  it('drops a surviving recipient the post-entry document no longer keys', async () => {
    const spentCode = await makeClient()
    const ghost = await makeClient()
    const freshCredential = await makeClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: spentCode.kak
    })
    await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: ghost.kak }),
      owner: { keyAgreementKey: spentCode.kak }
    })

    // The ghost sits in the roster but the document backs only the fresh
    // credential, so the document-backed resolver answers null for it and the
    // fresh epoch never wraps to it.
    const descriptor = await replaceUserKeyRosterRecipients({
      store,
      document: documentFor([freshCredential]),
      retireRecipientIds: [spentCode.kak.id],
      recipients: [ownerRecipient({ keyAgreementKey: freshCredential.kak })],
      ownerKeyAgreementKey: spentCode.kak
    })
    const current = descriptor.epochs!.find(
      epoch => epoch.id === descriptor.currentEpoch
    )!
    expect(current.recipients.map(entry => entry.header.kid)).toEqual([
      freshCredential.kak.id
    ])
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
      clientKeyAgreementKey: alice.kak
    })
    const enrolled = await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: bob.kak }),
      owner: { keyAgreementKey: alice.kak }
    })

    const result = await convergeUserKeyRosterToDocument({
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
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
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
      document
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
      pinnedEpochId: userKey.id
    })
    expect(read!.rotated).toBe(true)
    expect(read!.userKey.id).toBe(result.descriptor!.currentEpoch)
    await expect(
      readUserKeyRoster({
        store,
        userKey,
        clientKeyAgreementKey: bob.kak
      })
    ).rejects.toThrow(UserKeyRosterUnwrapError)

    // A second run over the converged pair is a no-op.
    const again = await convergeUserKeyRosterToDocument({
      store,
      document
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
      clientKeyAgreementKey: alice.kak
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
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    const descriptor = await addRecipient({
      store,
      recipient: ownerRecipient({ keyAgreementKey: bob.kak }),
      owner: { keyAgreementKey: alice.kak }
    })

    const result = await convergeUserKeyRosterToDocument({
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
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    const created = await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })

    await expect(
      convergeUserKeyRosterToDocument({
        store,
        document: documentFor([stranger])
      })
    ).rejects.toThrow(UserKeyRosterIntegrityError)
    expect(store._getDescriptor()).toEqual(created)
  })

  it('resolves on an absent roster without writing one', async () => {
    const alice = await makeClient()
    const store = memoryDescriptorStore()
    const result = await convergeUserKeyRosterToDocument({
      store,
      document: documentFor([alice])
    })
    expect(result).toEqual({
      rotated: false,
      staleRecipientIds: [],
      escrowedRecipientIds: [],
      descriptor: null
    })
    expect(store._getDescriptor()).toBeNull()
  })
})

describe('convergeUserKeyRosterToDocument (the escrow direction)', () => {
  const DID = 'did:webvh:QmScid:example.com:space:abc:id'

  /**
   * A test client whose roster kid is the production one -- the pair a
   * document's controller marker and key-agreement method carry between them
   * ({@link rosterRecipientKid}), which is what the escrow direction rebuilds.
   *
   * @returns {Promise<RosterTestClient>}
   */
  async function markedClient() {
    const client = await makeClient()
    ;(client.kak as { id: string }).id = rosterRecipientKid({
      signingKeyMultibase: client.signingKeyMultibase,
      keyAgreementKeyMultibase: client.publicKeyMultibase
    })
    return client
  }

  /**
   * A document keying enrolled clients (their key-agreement twins carrying
   * the `did:key` controller marker) beside standing credentials (unmarked,
   * account-controlled, verbatim or commitment).
   *
   * @param options {object}
   * @param options.clients {Array<{ publicKeyMultibase: string,
   *   signingKeyMultibase: string }>}
   * @param [options.credentials] {string[]}   verbatim credential keys
   * @param [options.commitments] {string[]}   credential key commitments
   * @returns {KeyAgreementDocument}
   */
  function markedDocumentFor({
    clients,
    credentials = [],
    commitments = []
  }: {
    clients: Array<{ publicKeyMultibase: string; signingKeyMultibase: string }>
    credentials?: string[]
    commitments?: string[]
  }) {
    const methods = [
      ...clients.map(client => ({
        id: `${DID}#${client.publicKeyMultibase}`,
        type: MULTIKEY_VM_TYPE,
        controller: `did:key:${client.signingKeyMultibase}`,
        publicKeyMultibase: client.publicKeyMultibase
      })),
      ...credentials.map(key => ({
        id: `${DID}#${key}`,
        type: MULTIKEY_VM_TYPE,
        controller: DID,
        publicKeyMultibase: key
      })),
      ...commitments.map((commitment, index) => ({
        id: `${DID}#commitment-${index}`,
        type: MULTIKEY_COMMITMENT_VM_TYPE,
        controller: DID,
        publicKeyCommitment: commitment
      }))
    ]
    return {
      verificationMethod: methods,
      keyAgreement: methods.map(method => method.id)
    }
  }

  it('escrows a document-keyed client that holds no wrap, without rotating', async () => {
    const alice = await markedClient()
    const bob = await markedClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    const initial = await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })

    // The window a ladder-signed enrollment approval leaves: bob's document
    // entry landed, the append that was to wrap the user key to him did not.
    const result = await convergeUserKeyRosterToDocument({
      store,
      document: markedDocumentFor({ clients: [alice, bob] }),
      ownerKeyAgreementKey: alice.kak
    })
    expect(result.staleRecipientIds).toEqual([])
    expect(result.escrowedRecipientIds).toEqual([bob.kak.id])
    // An escrow-only convergence adds wraps rather than minting an epoch.
    expect(result.rotated).toBe(false)
    expect(result.descriptor?.currentEpoch).toBe(initial.currentEpoch)
    const epoch = (result.descriptor?.epochs ?? []).find(
      candidate => candidate.id === result.descriptor?.currentEpoch
    )
    expect(epoch?.recipients.map(entry => entry.header.kid).sort()).toEqual(
      [alice.kak.id, bob.kak.id].sort()
    )
  })

  it('escrows two missing recipients in ONE append', async () => {
    const alice = await markedClient()
    const bob = await markedClient()
    const carol = await markedClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    const initial = await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    const writesBefore = store._writes()

    // Two clients the document keys and the roster does not. On a
    // ladder-signed store only the first append is licensed, so a write per
    // recipient would refuse the second after the caller's pivot.
    const result = await convergeUserKeyRosterToDocument({
      store,
      document: markedDocumentFor({ clients: [alice, bob, carol] }),
      ownerKeyAgreementKey: alice.kak
    })
    expect(store._writes() - writesBefore).toBe(1)
    expect(result.rotated).toBe(false)
    expect(result.escrowedRecipientIds.sort()).toEqual(
      [bob.kak.id, carol.kak.id].sort()
    )
    expect(result.descriptor?.currentEpoch).toBe(initial.currentEpoch)
    // Escrow means every epoch, for both of them.
    for (const epoch of result.descriptor?.epochs ?? []) {
      expect(epoch.recipients.map(entry => entry.header.kid).sort()).toEqual(
        [alice.kak.id, bob.kak.id, carol.kak.id].sort()
      )
    }
  })

  it('escrows and retires in one append, and reads the same afterwards', async () => {
    const alice = await markedClient()
    const bob = await markedClient()
    const carol = await markedClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    await addRecipient({
      store,
      recipient: { id: bob.kak.id, publicKeyMultibase: bob.publicKeyMultibase },
      owner: { keyAgreementKey: alice.kak }
    })
    const writesBefore = store._writes()

    // bob left the document, carol arrived, and neither half of the roster
    // caught up.
    const result = await convergeUserKeyRosterToDocument({
      store,
      document: markedDocumentFor({ clients: [alice, carol] }),
      ownerKeyAgreementKey: alice.kak
    })
    expect(result.rotated).toBe(true)
    expect(result.staleRecipientIds).toEqual([bob.kak.id])
    expect(result.escrowedRecipientIds).toEqual([carol.kak.id])
    expect(store._writes() - writesBefore).toBe(1)
    const current = (result.descriptor?.epochs ?? []).find(
      candidate => candidate.id === result.descriptor?.currentEpoch
    )
    expect(current?.recipients.map(entry => entry.header.kid).sort()).toEqual(
      [alice.kak.id, carol.kak.id].sort()
    )
    // Escrow means every epoch, so carol reads the account's history too.
    for (const epoch of result.descriptor?.epochs ?? []) {
      expect(epoch.recipients.map(entry => entry.header.kid)).toContain(
        carol.kak.id
      )
    }
  })

  it('does not escrow a standing credential the document publishes', async () => {
    // A passkey's or a recovery code's key-agreement key stands in the
    // document verbatim, but its roster kid names its standing client's
    // SIGNING key, which no document publishes. A commitment-only passphrase
    // entry withholds even the key. Both are mended by the ceremony holding
    // the credential, never here.
    const alice = await markedClient()
    const credential = await markedClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    const initial = await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    const writesBefore = store._writes()
    const result = await convergeUserKeyRosterToDocument({
      store,
      document: markedDocumentFor({
        clients: [alice],
        credentials: [credential.publicKeyMultibase],
        commitments: ['uCommitmentOfAPassphraseKey']
      }),
      ownerKeyAgreementKey: alice.kak
    })
    expect(result.escrowedRecipientIds).toEqual([])
    expect(result.rotated).toBe(false)
    expect(result.descriptor).toEqual(initial)
    expect(store._writes()).toBe(writesBefore)
  })

  it('writes nothing when neither direction is stale', async () => {
    const alice = await markedClient()
    const bob = await markedClient()
    const userKey = await mintUserKey()
    const store = memoryDescriptorStore()
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: alice.kak
    })
    const enrolled = await addRecipient({
      store,
      recipient: { id: bob.kak.id, publicKeyMultibase: bob.publicKeyMultibase },
      owner: { keyAgreementKey: alice.kak }
    })
    const writesBefore = store._writes()
    const result = await convergeUserKeyRosterToDocument({
      store,
      document: markedDocumentFor({ clients: [alice, bob] }),
      ownerKeyAgreementKey: alice.kak
    })
    expect(result).toEqual({
      rotated: false,
      staleRecipientIds: [],
      escrowedRecipientIds: [],
      descriptor: enrolled
    })
    expect(store._writes()).toBe(writesBefore)
  })
})
