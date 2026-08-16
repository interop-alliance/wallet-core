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
import { logGovernedDescriptorStore } from '../../src/keys/rosterLogStore.js'
import { userKeyRosterPinId } from '../../src/keys/rosterStore.js'
import { mintUserKey } from '../../src/keys/userKey.js'
import {
  memoryResourceLogPinStore,
  ResourceLogContinuityError,
  type ResourceLogController
} from '../../src/resourceLog/index.js'
import { verifyAccountLog } from '../../src/webvh/index.js'
import { makeRosterClient, rosterDocumentFor } from './fixtures/rosterClient.js'
import { fakeController, memoryLogStore } from './fixtures/resourceLog.js'

const ROSTER_LOG_ID = userKeyRosterPinId({ spaceId: 'urn:uuid:space' })

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

  it('seals a converged roster whose log still anchors before the membership change', async () => {
    // The torn revocation whose rotation no-op'd: the roster only ever
    // wrapped this client, so the recipient convergence finds nothing stale
    // -- but the roster log's head still anchors before the document edit
    // that removed the other client. The sweep detects and closes exactly
    // that.
    const own = await makeRosterClient()
    const revoked = await makeRosterClient()
    const userKey = await mintUserKey()
    const controllerFor = (versions: Array<{ id: string; keys: string[] }>) =>
      fakeController({
        versions: versions.map(version => ({
          versionId: version.id,
          keys: version.keys
        }))
      })
    const controllerRef: { current: ResourceLogController } = {
      current: controllerFor([
        {
          id: '1-v1',
          keys: [own.signingKeyMultibase, revoked.signingKeyMultibase]
        }
      ])
    }
    const log = memoryLogStore()
    const store = logGovernedDescriptorStore({
      log,
      resolveController: async () => controllerRef.current,
      pinStore: memoryResourceLogPinStore(),
      logId: ROSTER_LOG_ID,
      signer: own.logSigner
    })
    await ensureUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey: own.kak
    })
    const descriptor = (await store.read())!.descriptor
    // The revocation edit landed (version 2), but its roster rotation
    // no-op'd and appended nothing.
    controllerRef.current = controllerFor([
      {
        id: '1-v1',
        keys: [own.signingKeyMultibase, revoked.signingKeyMultibase]
      },
      { id: '2-v2', keys: [own.signingKeyMultibase] }
    ])
    vi.mocked(verifyAccountLog).mockResolvedValue({
      doc: rosterDocumentFor([own])
    } as unknown as Awaited<ReturnType<typeof verifyAccountLog>>)

    const result = await convergeUserKeyRosterToAccount({
      pointer,
      store,
      userKey,
      descriptor,
      clientKeyAgreementKey: own.kak
    })

    expect(result.rotated).toBe(false)
    expect(result.sealed).toBe(true)
    expect(result.userKey).toBe(userKey)
    const entries = log._getEntries()!
    expect(entries).toHaveLength(2)
    expect(entries[1]!.state).toEqual(entries[0]!.state)
    expect(entries[1]!.proof[0]!.verificationMethod).toContain(
      '?versionId=2-v2'
    )

    // Idempotent across starts: the next sweep finds a sealed log.
    const again = await convergeUserKeyRosterToAccount({
      pointer,
      store,
      userKey,
      descriptor,
      clientKeyAgreementKey: own.kak
    })
    expect(again.sealed).toBe(false)
    expect(log._getEntries()!).toHaveLength(2)
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
      sealed: false,
      staleRecipientIds: [],
      userKey,
      descriptor
    })
    expect(warn).toHaveBeenCalled()
    warn.mockRestore()
  })

  it('keeps the unchanged input on an account-log rollback', async () => {
    // The rollback carve-out applies to the sweep too: a lagging replica
    // serving the account log behind the chain-head pin leaves this start
    // on the key it already has, and the next start converges.
    const { ownKak, userKey, store, descriptor } = await tornRoster()
    vi.mocked(verifyAccountLog).mockRejectedValue(
      new ResourceLogContinuityError({ reason: 'rollback', pinnedHead: '3-a' })
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
      sealed: false,
      staleRecipientIds: [],
      userKey,
      descriptor
    })
    expect(warn).toHaveBeenCalled()
    warn.mockRestore()
  })

  it('rethrows an account-log fork', async () => {
    const { ownKak, userKey, store, descriptor } = await tornRoster()
    const fork = new ResourceLogContinuityError({
      reason: 'fork',
      pinnedHead: '3-a'
    })
    vi.mocked(verifyAccountLog).mockRejectedValue(fork)

    await expect(
      convergeUserKeyRosterToAccount({
        pointer,
        store,
        userKey,
        descriptor,
        clientKeyAgreementKey: ownKak
      })
    ).rejects.toBe(fork)
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

  it('refuses the session on each of the roster refusals', async () => {
    const errors = [
      new UserKeyRosterContinuityError({ pinnedEpochId: 'did:key:zOld' }),
      new UserKeyRosterIntegrityError('fabricated'),
      new UserKeyRosterUnwrapError('no wrap'),
      new ResourceLogContinuityError({ reason: 'fork', pinnedHead: '3-a' }),
      new ResourceLogContinuityError({
        reason: 'scid-switch',
        pinnedHead: '3-a'
      }),
      new ResourceLogContinuityError({
        reason: 'method-switch',
        pinnedHead: '3-a'
      })
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

  it('degrades a chain-head rollback to the cached key', async () => {
    // The rollback carve-out: a lagging replica serving a head behind the
    // chain-head pin is reconcilable divergence, not a session refusal --
    // nothing rolled back is adopted (the read resolves null) and the pin
    // never regressed inside the store, so the start carries on under the
    // cached key exactly as it does offline.
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const read = await checkUserKeyRosterAtLogin({
      store: storeReading(() => {
        throw new ResourceLogContinuityError({
          reason: 'rollback',
          pinnedHead: '3-a'
        })
      }),
      clientKeyAgreementKey
    })
    expect(read).toBeNull()
    expect(warn).toHaveBeenCalled()
    warn.mockRestore()
  })

  it('degrades a rollback raised by a second copy of the package', async () => {
    // The carve-out must match on `err.name` + `err.reason`, never
    // `instanceof`, for the same duplicated-package reason as the refusals.
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const foreign = new Error('not a continuation (rollback)')
    foreign.name = 'ResourceLogContinuityError'
    ;(foreign as { reason?: string }).reason = 'rollback'
    const read = await checkUserKeyRosterAtLogin({
      store: storeReading(() => {
        throw foreign
      }),
      clientKeyAgreementKey
    })
    expect(read).toBeNull()
    expect(warn).toHaveBeenCalled()
    warn.mockRestore()
  })

  it('refuses refusal errors raised by a second copy of the package', async () => {
    // The refusal classes are raised inside the app-injected descriptor
    // store, which can resolve to a different copy of this package (linked,
    // or duplicated through a dependency tree). Those instances fail every
    // `instanceof` check against this copy's classes, so the refusal match
    // must key on `err.name` -- a foreign refusal falling into the transport
    // branch would warn and proceed on the cached key.
    const refusalNames = [
      'ResourceLogContinuityError',
      'ResourceLogIntegrityError',
      'UserKeyRosterContinuityError',
      'UserKeyRosterIntegrityError',
      'UserKeyRosterUnwrapError'
    ]
    for (const refusalName of refusalNames) {
      const foreign = new Error(`refused (${refusalName})`)
      foreign.name = refusalName
      if (refusalName === 'ResourceLogContinuityError') {
        ;(foreign as { reason?: string }).reason = 'fork'
      }
      await expect(
        checkUserKeyRosterAtLogin({
          store: storeReading(() => {
            throw foreign
          }),
          clientKeyAgreementKey
        })
      ).rejects.toBe(foreign)
    }
  })

  it('propagates a persist failure from onRosterRead on a rotated read', async () => {
    // The adoption callback throwing is neither a transport hiccup nor a
    // roster refusal: the read succeeded and adopted a rotated key, but the
    // app failed to persist it and the epoch pin. Swallowing that into the
    // warn-and-null path would let the session proceed on the retired cached
    // key with the pin never advanced.
    const own = await makeRosterClient()
    const rosterKey = await mintUserKey()
    const cachedKey = await mintUserKey()
    const store = memoryStore()
    await ensureUserKeyRoster({
      store,
      userKey: rosterKey,
      clientKeyAgreementKey: own.kak
    })
    const persistFailure = new Error('IndexedDB write failed')
    const onRosterRead = vi.fn(async (adopted: { latestEpochId: string }) => {
      expect(adopted.latestEpochId).toBe(rosterKey.id)
      throw persistFailure
    })
    await expect(
      checkUserKeyRosterAtLogin({
        store,
        userKey: cachedKey,
        clientKeyAgreementKey: own.kak,
        onRosterRead
      })
    ).rejects.toBe(persistFailure)
    expect(onRosterRead).toHaveBeenCalledOnce()
  })
})
