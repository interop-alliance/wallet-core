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

/**
 * A store double exposing only what the helper drives: the dirty rows and
 * (unless `withReplace: false`) a recording `replacePending`.
 */
function fakeStore({
  rows,
  withReplace = true
}: {
  rows: SyncedRow[]
  withReplace?: boolean
}): {
  store: SyncStore
  replaced: Array<{
    id: string
    newId: string
    envelope: Json
    revision?: string | number
  }>
} {
  const replaced: Array<{
    id: string
    newId: string
    envelope: Json
    revision?: string | number
  }> = []
  const store = {
    getDirtyRows: async () => rows,
    ...(withReplace && {
      replacePending: async (options: {
        id: string
        newId: string
        envelope: Json
        revision?: string | number
      }) => {
        replaced.push(options)
      }
    })
  } as unknown as SyncStore
  return { store, replaced }
}

const decryptStale = async ({
  envelope
}: {
  id: string
  envelope: Json
}): Promise<Json> => (envelope as unknown as FakeEnvelope).payload

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

  it('leaves routable pending rows untouched -- and needs no replacePending for them', async () => {
    const { store, replaced } = fakeStore({
      rows: [pendingRow('a', envelopeUnder('winner', { name: 'ok' }))],
      withReplace: false
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

  it('throws when a re-mint is needed but the store lacks replacePending', async () => {
    const { store } = fakeStore({
      rows: [pendingRow('a', envelopeUnder('loser', { name: 'x' }))],
      withReplace: false
    })
    const cipher = fakeCipher({ knownEpochs: ['winner'], mintEpoch: 'winner' })

    await expect(
      remintPendingEnvelopes({ store, cipher, decryptStale })
    ).rejects.toThrow(/replacePending/)
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
