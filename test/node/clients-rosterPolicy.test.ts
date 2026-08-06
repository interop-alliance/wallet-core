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
  checkPukRosterAtLogin,
  convergePukRosterToAccount
} from '../../src/clients/rosterPolicy.js'
import {
  addPukRosterRecipient,
  ensurePukRoster,
  PukRosterContinuityError,
  PukRosterIntegrityError,
  PukRosterUnwrapError
} from '../../src/keys/pukRoster.js'
import { mintPuk } from '../../src/keys/puk.js'
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
  const puk = await mintPuk()
  const store = memoryStore()
  await ensurePukRoster({
    store,
    puk,
    clientKeyAgreementKey: ownKak,
    signEpochs: own.signEpochs
  })
  await addPukRosterRecipient({
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
  return { own, ownKak, strandedKak, puk, store, doc, descriptor }
}

const pointer = { did: 'did:webvh:x', spaceId: 'urn:uuid:space', host: 'h' }

describe('convergePukRosterToAccount', () => {
  beforeEach(() => {
    vi.mocked(verifyAccountLog).mockReset()
  })

  it('adopts the fresh key it rotated to', async () => {
    const { own, ownKak, puk, store, doc, descriptor } = await tornRoster()
    vi.mocked(verifyAccountLog).mockResolvedValue({
      doc
    } as unknown as Awaited<ReturnType<typeof verifyAccountLog>>)
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const adopted: Array<{ puk: { id: string } }> = []

    const result = await convergePukRosterToAccount({
      pointer,
      store,
      puk,
      descriptor,
      clientKeyAgreementKey: ownKak,
      signEpochs: own.signEpochs,
      onPukAdopted: async entry => {
        adopted.push(entry)
      }
    })

    expect(result.rotated).toBe(true)
    expect(result.puk.id).not.toBe(puk.id)
    expect(result.descriptor.currentEpoch).toBe(result.puk.id)
    expect(adopted).toHaveLength(1)
    expect(adopted[0]!.puk.id).toBe(result.puk.id)
    warn.mockRestore()
  })

  it('refuses to report a rotation it performed as unchanged', async () => {
    const { own, ownKak, puk, store, doc, descriptor } = await tornRoster()
    vi.mocked(verifyAccountLog).mockResolvedValue({
      doc
    } as unknown as Awaited<ReturnType<typeof verifyAccountLog>>)
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const onPukAdopted = vi.fn()

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
      convergePukRosterToAccount({
        pointer,
        store: failing,
        puk,
        descriptor,
        clientKeyAgreementKey: ownKak,
        signEpochs: own.signEpochs,
        onPukAdopted
      })
    ).rejects.toThrow(/must not continue under the retired key/)
    expect(onPukAdopted).not.toHaveBeenCalled()
    warn.mockRestore()
  })

  it('rethrows a roster refusal raised by the adopting read', async () => {
    const { own, ownKak, puk, store, doc, descriptor } = await tornRoster()
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
      convergePukRosterToAccount({
        pointer,
        store: stripped,
        puk,
        descriptor,
        clientKeyAgreementKey: ownKak,
        signEpochs: own.signEpochs
      })
    ).rejects.toBeInstanceOf(PukRosterUnwrapError)
    warn.mockRestore()
  })

  it('rethrows a roster refusal raised by the convergence itself', async () => {
    const { own, ownKak, puk, store, descriptor } = await tornRoster()
    // A document that keys nobody on the roster: rotating onto no one is
    // refused rather than swallowed into an unchanged result.
    vi.mocked(verifyAccountLog).mockResolvedValue({
      doc: { keyAgreement: [] }
    } as unknown as Awaited<ReturnType<typeof verifyAccountLog>>)

    await expect(
      convergePukRosterToAccount({
        pointer,
        store,
        puk,
        descriptor,
        clientKeyAgreementKey: ownKak,
        signEpochs: own.signEpochs
      })
    ).rejects.toBeInstanceOf(PukRosterIntegrityError)
    expect(store.writes).toBe(0)
  })

  it('keeps the unchanged input when the log cannot be verified', async () => {
    const { own, ownKak, puk, store, descriptor } = await tornRoster()
    vi.mocked(verifyAccountLog).mockRejectedValue(
      new TypeError('Failed to fetch')
    )
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    const result = await convergePukRosterToAccount({
      pointer,
      store,
      puk,
      descriptor,
      clientKeyAgreementKey: ownKak,
      signEpochs: own.signEpochs
    })
    expect(result).toEqual({
      rotated: false,
      staleRecipientIds: [],
      puk,
      descriptor
    })
    expect(warn).toHaveBeenCalled()
    warn.mockRestore()
  })
})

describe('checkPukRosterAtLogin', () => {
  it('resolves null when the account has no roster yet', async () => {
    const onRosterRead = vi.fn()
    const read = await checkPukRosterAtLogin({
      store: storeReading(() => null),
      pointer,
      clientKeyAgreementKey,
      onRosterRead
    })
    expect(read).toBeNull()
    expect(onRosterRead).not.toHaveBeenCalled()
  })

  it('keeps the cached key for an offline start', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const read = await checkPukRosterAtLogin({
      store: storeReading(() => {
        throw new TypeError('Failed to fetch')
      }),
      pointer,
      clientKeyAgreementKey
    })
    expect(read).toBeNull()
    expect(warn).toHaveBeenCalled()
    warn.mockRestore()
  })

  it('refuses the session on each of the three roster errors', async () => {
    const errors = [
      new PukRosterContinuityError({ pinnedEpochId: 'did:key:zOld' }),
      new PukRosterIntegrityError('fabricated'),
      new PukRosterUnwrapError('no wrap')
    ]
    for (const error of errors) {
      await expect(
        checkPukRosterAtLogin({
          store: storeReading(() => {
            throw error
          }),
          pointer,
          clientKeyAgreementKey
        })
      ).rejects.toBe(error)
    }
  })
})
