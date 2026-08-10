/**
 * Unit tests for the login-time roster policy
 * (`src/clients/rosterPolicy.ts`): which roster failures refuse a session and
 * which keep the cached key for an offline start, that an absent roster is
 * not a failure, and that the completion sweep's convergence never reports a
 * rotation it performed as `unchanged`.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import {
  checkUserKeyRosterAtLogin,
  convergeUserKeyRosterToAccount
} from '../../src/clients/rosterPolicy.js'
import {
  addUserKeyRosterRecipient,
  ensureUserKeyRoster,
  UserKeyRosterContinuityError,
  UserKeyRosterIntegrityError,
  UserKeyRosterUnwrapError
} from '../../src/keys/userKeyRoster.js'
import { mintUserKey } from '../../src/keys/userKey.js'
import { verifyAccountLog } from '../../src/webvh/index.js'
import { makeRosterClient, rosterDocumentFor } from './fixtures/rosterClient.js'

vi.mock('../../src/webvh/index.js', async importOriginal => {
  const actual =
    await importOriginal<typeof import('../../src/webvh/index.js')>()
  return { ...actual, verifyAccountLog: vi.fn() }
})

/**
 * A descriptor store whose read behaves as instructed.
 *
 * @param read {Function}
 * @returns {EncryptionDescriptorStore}
 */
function storeReading(read: () => unknown): EncryptionDescriptorStore {
  return { read } as unknown as EncryptionDescriptorStore
}

const clientKeyAgreementKey = { id: 'did:key:zSelf#z6LSTwin' } as never

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

/**
 * A torn revocation: a roster whose current epoch still wraps the per-user
 * key to a client the account document no longer keys -- exactly what the
 * completion sweep exists to finish.
 *
 * @returns {Promise<object>}
 */
async function tornRoster() {
  const own = await makeRosterClient()
  const ownKak = own.kak
  const strandedKak = await makeClientKak()
  const userKey = await mintUserKey()
  const store = memoryStore()
  await ensureUserKeyRoster({
    store,
    userKey,
    clientKeyAgreementKey: ownKak
  })
  await addUserKeyRosterRecipient({
    store,
    recipient: {
      id: strandedKak.id,
      publicKeyMultibase: strandedKak.publicKeyMultibase
    },
    ownerKeyAgreementKey: ownKak
  })
  // The document as the (never re-run) revocation edit left it: only this
  // client is keyed -- and its signing key is the verification method the
  // roster's epoch-configuration signature resolves against.
  const doc = rosterDocumentFor([own])
  const descriptor = (await store.read())!.descriptor
  // The fixture's own setup writes do not count: `writes` below means "the
  // convergence has rotated".
  store.writes = 0
  return { own, ownKak, strandedKak, userKey, store, doc, descriptor }
}

const pointer = { did: 'did:webvh:x', spaceId: 'urn:uuid:space', host: 'h' }

describe('convergeUserKeyRosterToAccount', () => {
  beforeEach(() => {
    vi.mocked(verifyAccountLog).mockReset()
  })

  it('adopts the fresh key it rotated to', async () => {
    const { ownKak, userKey, store, doc, descriptor } = await tornRoster()
    vi.mocked(verifyAccountLog).mockResolvedValue({
      doc
    } as unknown as Awaited<ReturnType<typeof verifyAccountLog>>)
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const adopted: Array<{ userKey: { id: string } }> = []

    const result = await convergeUserKeyRosterToAccount({
      pointer,
      store,
      userKey,
      descriptor,
      clientKeyAgreementKey: ownKak,
      onUserKeyAdopted: async entry => {
        adopted.push(entry)
      }
    })

    expect(result.rotated).toBe(true)
    expect(result.userKey.id).not.toBe(userKey.id)
    expect(result.descriptor.currentEpoch).toBe(result.userKey.id)
    expect(adopted).toHaveLength(1)
    expect(adopted[0]!.userKey.id).toBe(result.userKey.id)
    warn.mockRestore()
  })

  it('refuses to report a rotation it performed as unchanged', async () => {
    const { ownKak, userKey, store, doc, descriptor } = await tornRoster()
    vi.mocked(verifyAccountLog).mockResolvedValue({
      doc
    } as unknown as Awaited<ReturnType<typeof verifyAccountLog>>)
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const onUserKeyAdopted = vi.fn()

    // The adopting read fails after the rotation has already landed.
    const failing: EncryptionDescriptorStore = {
      ...store,
      async read() {
        if (store.writes > 0) {
          throw new TypeError('Failed to fetch')
        }
        return store.read()
      }
    }

    await expect(
      convergeUserKeyRosterToAccount({
        pointer,
        store: failing,
        userKey,
        descriptor,
        clientKeyAgreementKey: ownKak,
        onUserKeyAdopted
      })
    ).rejects.toThrow(/must not continue under the retired key/)
    expect(onUserKeyAdopted).not.toHaveBeenCalled()
    warn.mockRestore()
  })

  it('rethrows a roster refusal raised by the adopting read', async () => {
    const { ownKak, userKey, store, doc, descriptor } = await tornRoster()
    vi.mocked(verifyAccountLog).mockResolvedValue({
      doc
    } as unknown as Awaited<ReturnType<typeof verifyAccountLog>>)
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    // The rotation lands, then this client's own wrap goes missing from the
    // fresh epoch: the same continuity class the login read refuses on.
    const stripped: EncryptionDescriptorStore = {
      ...store,
      async read() {
        const current = await store.read()
        if (current && store.writes > 0) {
          const epoch = current.descriptor.epochs!.find(
            entry => entry.id === current.descriptor.currentEpoch
          )!
          epoch.recipients = epoch.recipients.filter(
            entry => entry.header.kid !== ownKak.id
          )
        }
        return current
      }
    }

    await expect(
      convergeUserKeyRosterToAccount({
        pointer,
        store: stripped,
        userKey,
        descriptor,
        clientKeyAgreementKey: ownKak
      })
    ).rejects.toBeInstanceOf(UserKeyRosterUnwrapError)
    warn.mockRestore()
  })

  it('rethrows a roster refusal raised by the convergence itself', async () => {
    const { ownKak, userKey, store, descriptor } = await tornRoster()
    // A document that keys nobody on the roster: rotating onto no one is
    // refused rather than swallowed into an unchanged result.
    vi.mocked(verifyAccountLog).mockResolvedValue({
      doc: { keyAgreement: [] }
    } as unknown as Awaited<ReturnType<typeof verifyAccountLog>>)

    await expect(
      convergeUserKeyRosterToAccount({
        pointer,
        store,
        userKey,
        descriptor,
        clientKeyAgreementKey: ownKak
      })
    ).rejects.toBeInstanceOf(UserKeyRosterIntegrityError)
    expect(store.writes).toBe(0)
  })

  it('keeps the unchanged input when the log cannot be verified', async () => {
    const { ownKak, userKey, store, descriptor } = await tornRoster()
    vi.mocked(verifyAccountLog).mockRejectedValue(
      new TypeError('Failed to fetch')
    )
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    const result = await convergeUserKeyRosterToAccount({
      pointer,
      store,
      userKey,
      descriptor,
      clientKeyAgreementKey: ownKak
    })
    expect(result).toEqual({
      rotated: false,
      staleRecipientIds: [],
      userKey,
      descriptor
    })
    expect(warn).toHaveBeenCalled()
    warn.mockRestore()
  })
})

describe('checkUserKeyRosterAtLogin', () => {
  it('resolves null when the account has no roster yet', async () => {
    const onRosterRead = vi.fn()
    const read = await checkUserKeyRosterAtLogin({
      store: storeReading(() => null),
      clientKeyAgreementKey,
      onRosterRead
    })
    expect(read).toBeNull()
    expect(onRosterRead).not.toHaveBeenCalled()
  })

  it('keeps the cached key for an offline start', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const read = await checkUserKeyRosterAtLogin({
      store: storeReading(() => {
        throw new TypeError('Failed to fetch')
      }),
      clientKeyAgreementKey
    })
    expect(read).toBeNull()
    expect(warn).toHaveBeenCalled()
    warn.mockRestore()
  })

  it('refuses the session on each of the three roster errors', async () => {
    const errors = [
      new UserKeyRosterContinuityError({ pinnedEpochId: 'did:key:zOld' }),
      new UserKeyRosterIntegrityError('fabricated'),
      new UserKeyRosterUnwrapError('no wrap')
    ]
    for (const error of errors) {
      await expect(
        checkUserKeyRosterAtLogin({
          store: storeReading(() => {
            throw error
          }),
          clientKeyAgreementKey
        })
      ).rejects.toBe(error)
    }
  })
})
