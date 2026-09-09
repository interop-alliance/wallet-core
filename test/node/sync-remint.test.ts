/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The create-loss re-mint (`src/sync/remint.ts`): after an eager minter
 * adopts a published descriptor another provisioner won, every pending
 * (pre-feed) envelope sealed under the losing epoch is re-minted under the
 * adopted descriptor's current epoch -- and nothing else is touched: rows the
 * adopted cipher can route, acked rows (feed existence), and tombstones stay
 * as they are. Ciphers are seam-level fakes: an envelope is `{ epoch,
 * payload }` and an unknown epoch throws the real `UnknownEpochError` the
 * helper matches on.
 */
import { describe, it, expect } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { PreconditionFailedError } from '@interop/was-client'
import type { CollectionEncryption } from '@interop/was-client'
import {
  createEdvDocCipher,
  createRefreshingEdvDocCipher,
  initRecipients,
  ownerRecipient,
  type EncryptionDescriptorStore
} from '@interop/was-client/edv'
import { singleKeyResolver } from '@interop/was-client/identity'

import { remintPendingEnvelopes } from '../../src/sync/remint.js'
import { UnknownEpochError } from '../../src/sync/types.js'
import type {
  DocCipher,
  Json,
  SyncStore,
  SyncedRow
} from '../../src/sync/types.js'

type FakeEnvelope = { epoch: string; payload: Json }

/**
 * A seam-level DocCipher over `{ epoch, payload }` envelopes: decrypt routes
 * only the known epochs (an unknown one throws `UnknownEpochError`), encrypt
 * seals under `mintEpoch` and mints a fresh id from the payload + epoch (a
 * re-mint therefore re-keys, like a real ciphertext-hashed content id).
 */
function fakeCipher({
  knownEpochs,
  mintEpoch
}: {
  knownEpochs: string[]
  mintEpoch: string
}): DocCipher {
  return {
    async encrypt({ data }) {
      const envelope: FakeEnvelope = { epoch: mintEpoch, payload: data }
      return {
        id: `id-${mintEpoch}-${JSON.stringify(data)}`,
        envelope: envelope as unknown as Json,
        epoch: mintEpoch
      }
    },
    async decrypt({ envelope }) {
      const { epoch, payload } = envelope as unknown as FakeEnvelope
      if (!knownEpochs.includes(epoch)) {
        throw new UnknownEpochError({
          collectionId: 'test-collection',
          kids: [epoch]
        })
      }
      return payload
    }
  }
}

function envelopeUnder(epoch: string, payload: Json): Json {
  return { epoch, payload } as unknown as Json
}

function pendingRow(
  id: string,
  data: Json | null,
  overrides: Partial<SyncedRow> = {}
): SyncedRow {
  return { id, version: 0, updatedAt: '', deleted: false, data, ...overrides }
}

type ReplaceCall = {
  id: string
  newId: string
  envelope: Json
  revision?: string | number
}

type RemintStore = SyncStore & {
  replacePending: NonNullable<SyncStore['replacePending']>
}

/**
 * A store double exposing only what the helper drives: the dirty rows and a
 * recording `replacePending`. `onReplace` decides each replace's outcome (and
 * may mutate `rows` the way a concurrent local write would); omitted, every
 * replace applies. `getDirtyRows` re-reads `rows` on every call, so a retry
 * pass sees whatever the previous one left behind.
 */
function fakeStore({
  rows,
  onReplace
}: {
  rows: SyncedRow[]
  onReplace?: (options: ReplaceCall) => boolean
}): { store: RemintStore; replaced: ReplaceCall[] } {
  const replaced: ReplaceCall[] = []
  const store = {
    getDirtyRows: async () => [...rows],
    replacePending: async (options: ReplaceCall) => {
      replaced.push(options)
      return { applied: onReplace ? onReplace(options) : true }
    }
  } as unknown as RemintStore
  return { store, replaced }
}

async function decryptStale({
  envelope
}: {
  id: string
  envelope: Json
}): Promise<Json> {
  return (envelope as unknown as FakeEnvelope).payload
}

describe('remintPendingEnvelopes', () => {
  it('re-mints a pending envelope sealed under an epoch the adopted descriptor does not carry', async () => {
    const payload: Json = { name: 'cred-1' }
    const { store, replaced } = fakeStore({
      rows: [
        pendingRow('old-id', envelopeUnder('loser', payload), {
          revision: 7
        })
      ]
    })
    const cipher = fakeCipher({ knownEpochs: ['winner'], mintEpoch: 'winner' })

    const result = await remintPendingEnvelopes({ store, cipher, decryptStale })

    expect(result).toEqual({ pending: 1, reminted: 1 })
    expect(replaced).toHaveLength(1)
    const [entry] = replaced
    expect(entry?.id).toBe('old-id')
    expect(entry?.newId).not.toBe('old-id')
    expect((entry?.envelope as unknown as FakeEnvelope).epoch).toBe('winner')
    expect((entry?.envelope as unknown as FakeEnvelope).payload).toEqual(
      payload
    )
    // The store's conditional-replace token rides along.
    expect(entry?.revision).toBe(7)
  })

  it('leaves routable pending rows untouched', async () => {
    const { store, replaced } = fakeStore({
      rows: [pendingRow('a', envelopeUnder('winner', { name: 'ok' }))]
    })
    const cipher = fakeCipher({ knownEpochs: ['winner'], mintEpoch: 'winner' })

    const result = await remintPendingEnvelopes({ store, cipher, decryptStale })

    expect(result).toEqual({ pending: 1, reminted: 0 })
    expect(replaced).toHaveLength(0)
  })

  it('never touches acked rows or tombstones (feed existence / nothing to re-mint)', async () => {
    const { store, replaced } = fakeStore({
      rows: [
        // Acked: on the feed under version 1; immutable there, never probed.
        pendingRow('acked', envelopeUnder('loser', { name: 'on-feed' }), {
          version: 1
        }),
        // Pending tombstone: no body to re-mint.
        pendingRow('gone', null, { deleted: true })
      ]
    })
    const cipher = fakeCipher({ knownEpochs: ['winner'], mintEpoch: 'winner' })

    const result = await remintPendingEnvelopes({ store, cipher, decryptStale })

    expect(result).toEqual({ pending: 0, reminted: 0 })
    expect(replaced).toHaveLength(0)
  })

  it('propagates a decrypt failure that is not an unknown epoch', async () => {
    const { store } = fakeStore({
      rows: [pendingRow('a', envelopeUnder('winner', { name: 'x' }))]
    })
    const cipher: DocCipher = {
      encrypt: async () => {
        throw new Error('unreachable')
      },
      decrypt: async () => {
        throw new Error('corrupt envelope')
      }
    }

    await expect(
      remintPendingEnvelopes({ store, cipher, decryptStale })
    ).rejects.toThrow('corrupt envelope')
  })

  it('re-probes and settles a row the store skipped on a revision mismatch', async () => {
    // A concurrent local write lands between the snapshot and the replace:
    // the store skips, and the retry pass re-probes the rewritten row (still
    // sealed under the loser epoch) and re-mints it under its fresh revision.
    const rows = [
      pendingRow('old-id', envelopeUnder('loser', { name: 'v1' }), {
        revision: 1
      })
    ]
    const { store, replaced } = fakeStore({
      rows,
      onReplace: ({ revision }) => {
        if (revision === 1) {
          // The concurrent write: a newer body, still minted eagerly under
          // the losing epoch, under a bumped revision token.
          rows[0] = pendingRow(
            'old-id',
            envelopeUnder('loser', { name: 'v2' }),
            {
              revision: 2
            }
          )
          return false
        }
        return true
      }
    })
    const cipher = fakeCipher({ knownEpochs: ['winner'], mintEpoch: 'winner' })

    const result = await remintPendingEnvelopes({ store, cipher, decryptStale })

    // The skipped attempt is NOT counted; the settled retry is.
    expect(result).toEqual({ pending: 1, reminted: 1 })
    expect(replaced.map(entry => entry.revision)).toEqual([1, 2])
    const settled = replaced[1]
    expect((settled?.envelope as unknown as FakeEnvelope).epoch).toBe('winner')
    // The re-mint carries the concurrent write's newer payload, not the stale
    // snapshot's.
    expect((settled?.envelope as unknown as FakeEnvelope).payload).toEqual({
      name: 'v2'
    })
  })

  it('throws rather than returning when a hot-writing row never settles', async () => {
    // Every replace is skipped: the row is still sealed under the losing
    // epoch, and must not be reported as re-minted (pushing it would land a
    // permanently unroutable feed entry).
    const { store, replaced } = fakeStore({
      rows: [
        pendingRow('hot', envelopeUnder('loser', { name: 'x' }), {
          revision: 1
        })
      ],
      onReplace: () => false
    })
    const cipher = fakeCipher({ knownEpochs: ['winner'], mintEpoch: 'winner' })

    await expect(
      remintPendingEnvelopes({ store, cipher, decryptStale })
    ).rejects.toThrow(/hot/)
    // Bounded: the pass gives up instead of livelocking.
    expect(replaced).toHaveLength(5)
  })

  it('stops between rows when the signal aborts', async () => {
    const controller = new AbortController()
    const { store, replaced } = fakeStore({
      rows: [
        pendingRow('first', envelopeUnder('loser', { name: 'one' })),
        pendingRow('second', envelopeUnder('loser', { name: 'two' }))
      ]
    })
    const cipher = fakeCipher({ knownEpochs: ['winner'], mintEpoch: 'winner' })
    const abortingDecryptStale = async (options: {
      id: string
      envelope: Json
    }): Promise<Json> => {
      controller.abort()
      return decryptStale(options)
    }

    const result = await remintPendingEnvelopes({
      store,
      cipher,
      decryptStale: abortingDecryptStale,
      signal: controller.signal
    })

    // The in-flight first row settles; the second is never started.
    expect(result).toEqual({ pending: 2, reminted: 1 })
    expect(replaced.map(entry => entry.id)).toEqual(['first'])
  })

  it('is idempotent: a re-run finds the re-minted envelope routable', async () => {
    const rows = [pendingRow('old-id', envelopeUnder('loser', { name: 'a' }))]
    const { store, replaced } = fakeStore({ rows })
    const cipher = fakeCipher({ knownEpochs: ['winner'], mintEpoch: 'winner' })

    await remintPendingEnvelopes({ store, cipher, decryptStale })
    // Apply the replace the way a real store would, then run again.
    const [entry] = replaced
    if (!entry) {
      throw new Error('expected the first run to re-mint')
    }
    rows[0] = pendingRow(entry.newId, entry.envelope)
    const second = await remintPendingEnvelopes({ store, cipher, decryptStale })

    expect(second).toEqual({ pending: 1, reminted: 0 })
    expect(replaced).toHaveLength(1)
  })
})

/**
 * The same sweep over the real self-refreshing cipher
 * (`createRefreshingEdvDocCipher`, `@interop/was-client/edv`), which the
 * engine hands the re-mint: a refresh that fails must surface the original
 * `UnknownEpochError`, not the build failure, or the sweep aborts on the first
 * row it exists to repair.
 */
describe('remintPendingEnvelopes over the self-refreshing EDV cipher', () => {
  const COLLECTION_ID = 'private-credentials'

  /** A reader: an X25519 key-agreement key in did:key form, plus its resolver. */
  async function makeReader(): Promise<{
    keyAgreementKey: IKeyAgreementKey
    keyResolver: ReturnType<typeof singleKeyResolver>
  }> {
    const kak = await X25519KeyAgreementKey2020.generate()
    const publicKeyMultibase = kak.publicKeyMultibase as string
    const did = `did:key:${publicKeyMultibase}`
    kak.controller = did
    kak.id = `${did}#${publicKeyMultibase}`
    const keyAgreementKey = kak as IKeyAgreementKey
    return {
      keyAgreementKey,
      keyResolver: singleKeyResolver({ keyAgreementKey })
    }
  }

  /** A one-epoch roster minted for one reader through the real create path. */
  async function mintDescriptor(reader: {
    keyAgreementKey: IKeyAgreementKey
  }): Promise<CollectionEncryption> {
    let descriptor: CollectionEncryption | null = null
    const store: EncryptionDescriptorStore = {
      async read() {
        return descriptor ? { descriptor, etag: 'v1' } : null
      },
      async replace() {
        throw new PreconditionFailedError('never replaced here')
      },
      async create(next) {
        descriptor = next
      }
    }
    return initRecipients({
      store,
      recipients: [ownerRecipient({ keyAgreementKey: reader.keyAgreementKey })]
    })
  }

  it('keeps a failed refresh classifiable by the create-loss re-mint', async () => {
    // The re-mint classifies on the error's `UnknownEpochError` name to find
    // the pending rows it exists to repair; a build failure surfacing instead
    // would abort the whole sweep on the first such row.
    const owner = await makeReader()
    const adopted = await mintDescriptor(owner)
    let fetches = 0
    const cipher = await createRefreshingEdvDocCipher({
      ...owner,
      collectionId: COLLECTION_ID,
      source: {
        async collectionEncryption() {
          fetches++
          if (fetches > 1) {
            throw new Error('network down')
          }
          return adopted
        }
      },
      cache: {
        async readDescriptor() {
          throw new Error('descriptor cache unreadable')
        },
        async writeDescriptor() {}
      }
    })
    // A pending envelope minted under a descriptor the adopted one does not
    // carry (the lost create), plus the stale cipher that can still open it.
    const loser = await makeReader()
    const loserCipher = await createEdvDocCipher({
      ...loser,
      collectionId: COLLECTION_ID,
      encryption: await mintDescriptor(loser)
    })
    const pending = await loserCipher.encrypt({ data: { name: 'cred-1' } })

    const replaced: Array<{ id: string; newId: string }> = []
    const store = {
      getDirtyRows: async () => [
        {
          id: pending.id,
          version: 0,
          updatedAt: '',
          deleted: false,
          data: pending.envelope as unknown as Json
        }
      ],
      replacePending: async (options: { id: string; newId: string }) => {
        replaced.push({ id: options.id, newId: options.newId })
        return { applied: true }
      }
    } as unknown as SyncStore & {
      replacePending: NonNullable<SyncStore['replacePending']>
    }

    const result = await remintPendingEnvelopes({
      store,
      cipher,
      decryptStale: async ({ envelope }) =>
        (await loserCipher.decrypt({ envelope })) as Json
    })
    expect(result).toEqual({ pending: 1, reminted: 1 })
    expect(replaced).toHaveLength(1)
    // The refresh was attempted (and failed) before the re-mint took over.
    expect(fetches).toBe(2)
  })
})
