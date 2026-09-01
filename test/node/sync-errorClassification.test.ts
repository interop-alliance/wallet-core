/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The sync layer's error classification (`isSyncConflictError` /
 * `isSyncNotFoundError` / `isUnknownEpochError`, `src/sync/types.ts`).
 *
 * All three signals are raised inside app-injected seams -- the `WasSyncPort`
 * for the two wire signals, the caller's `DocCipher` for the unknown epoch --
 * and those seams can resolve to a second copy of `@interop/was-client` (a
 * `link:` dev setup, a dedupe miss through a dependency tree). So every test
 * here raises the FOREIGN-REALM shape: a hand-built error carrying only the
 * `name` string, which no `instanceof` against this package's copy of the
 * class can ever match. Each case pins the branch the loop takes, since the
 * cost of the miss is silent and expensive: every push 412 becomes a fatal
 * cycle error, and the create-loss re-mint rethrows instead of re-minting,
 * leaving permanently unroutable envelopes to be pushed onto a shared feed.
 */
import { describe, it, expect } from 'vitest'

import { runPush } from '../../src/sync/push.js'
import { remintPendingEnvelopes } from '../../src/sync/remint.js'
import {
  isSyncConflictError,
  isSyncNotFoundError,
  isUnknownEpochError,
  UnknownEpochError,
  WasSyncConflictError,
  WasSyncNotFoundError,
  type Json,
  type MasterState,
  type SyncStore,
  type SyncedRow,
  type WasSyncPort
} from '../../src/sync/types.js'

/**
 * An error as it arrives from a SECOND copy of `@interop/was-client`: the same
 * `name` contract, an unrelated constructor.
 */
function foreignRealmError(name: string): Error {
  const err = new Error(`${name} raised by another copy of the package.`)
  err.name = name
  return err
}

/**
 * A `SyncStore` recording every settlement call, over a fixed dirty-row set.
 */
function recordingStore(rows: SyncedRow[]): SyncStore & {
  calls: string[]
  adopted: { id: string; latest: MasterState | null }[]
} {
  const calls: string[] = []
  const adopted: { id: string; latest: MasterState | null }[] = []
  return {
    calls,
    adopted,
    getCheckpoint: async () => undefined,
    getDirtyRows: async () => rows,
    applyPulledPage: async () => {},
    markPushed: async ({ id }) => {
      calls.push(`markPushed:${id}`)
    },
    markDeletedPushed: async ({ id }) => {
      calls.push(`markDeletedPushed:${id}`)
    },
    adoptLatest: async ({ id, latest }) => {
      calls.push(`adoptLatest:${id}`)
      adopted.push({ id, latest })
    }
  }
}

function liveRow(id: string, version = 0): SyncedRow {
  return {
    id,
    version,
    updatedAt: '1',
    deleted: false,
    data: { id } as unknown as Json
  }
}

describe('sync error classification', () => {
  describe('the predicates', () => {
    it("matches this package's own classes", () => {
      expect(isSyncConflictError(new WasSyncConflictError())).toBe(true)
      expect(isSyncNotFoundError(new WasSyncNotFoundError())).toBe(true)
      expect(
        isUnknownEpochError(
          new UnknownEpochError({ collectionId: 'c', kids: ['k'] })
        )
      ).toBe(true)
    })

    it("matches a foreign realm's errors, which instanceof cannot", () => {
      const conflict = foreignRealmError('WasSyncConflictError')
      const notFound = foreignRealmError('WasSyncNotFoundError')
      const unknownEpoch = foreignRealmError('UnknownEpochError')

      expect(conflict instanceof WasSyncConflictError).toBe(false)
      expect(notFound instanceof WasSyncNotFoundError).toBe(false)
      expect(unknownEpoch instanceof UnknownEpochError).toBe(false)

      expect(isSyncConflictError(conflict)).toBe(true)
      expect(isSyncNotFoundError(notFound)).toBe(true)
      expect(isUnknownEpochError(unknownEpoch)).toBe(true)
    })

    it('keeps the three signals apart, and rejects everything else', () => {
      const conflict = foreignRealmError('WasSyncConflictError')
      expect(isSyncNotFoundError(conflict)).toBe(false)
      expect(isUnknownEpochError(conflict)).toBe(false)

      for (const predicate of [
        isSyncConflictError,
        isSyncNotFoundError,
        isUnknownEpochError
      ]) {
        expect(predicate(new Error('plain'))).toBe(false)
        expect(predicate(foreignRealmError('KeyUnwrapError'))).toBe(false)
        // A nullish or non-object rejection reads as "not this signal" rather
        // than raising a TypeError of its own.
        expect(predicate(undefined)).toBe(false)
        expect(predicate(null)).toBe(false)
        expect(predicate('WasSyncConflictError')).toBe(false)
      }
    })
  })

  describe('runPush', () => {
    it('settles a foreign-realm 412 on an upsert instead of aborting the cycle', async () => {
      const store = recordingStore([liveRow('doc-1')])
      const master: MasterState = {
        version: 7,
        updatedAt: '2',
        data: { id: 'doc-1' } as unknown as Json
      }
      const port = {
        query: async () => ({ documents: [], checkpoint: null }),
        putContent: async () => {
          throw foreignRealmError('WasSyncConflictError')
        },
        deleteContent: async () => 0,
        get: async () => master
      } as unknown as WasSyncPort

      const result = await runPush({ port, store })

      expect(result).toEqual({ pushed: 1, conflictsResolved: 0 })
      expect(store.calls).toEqual(['adoptLatest:doc-1'])
      expect(store.adopted[0]?.latest).toBe(master)
    })

    it('runs the injected resolver on a foreign-realm 412', async () => {
      const store = recordingStore([liveRow('doc-1')])
      const resolved: string[] = []
      const port = {
        query: async () => ({ documents: [], checkpoint: null }),
        putContent: async () => {
          throw foreignRealmError('WasSyncConflictError')
        },
        deleteContent: async () => 0,
        get: async () => null
      } as unknown as WasSyncPort

      const result = await runPush({
        port,
        store,
        resolveConflict: async ({ id }) => {
          resolved.push(id)
        }
      })

      expect(resolved).toEqual(['doc-1'])
      expect(result.conflictsResolved).toBe(1)
      expect(store.calls).toEqual([])
    })

    it('settles a delete on a foreign-realm 404', async () => {
      const store = recordingStore([{ ...liveRow('doc-1', 3), deleted: true }])
      const port = {
        query: async () => ({ documents: [], checkpoint: null }),
        putContent: async () => 1,
        deleteContent: async () => {
          throw foreignRealmError('WasSyncNotFoundError')
        },
        get: async () => null
      } as unknown as WasSyncPort

      await runPush({ port, store })

      expect(store.calls).toEqual(['markDeletedPushed:doc-1'])
    })

    it('re-reads and retries a delete on a foreign-realm 412', async () => {
      const store = recordingStore([{ ...liveRow('doc-1', 3), deleted: true }])
      const ifMatches: (string | undefined)[] = []
      const port = {
        query: async () => ({ documents: [], checkpoint: null }),
        putContent: async () => 1,
        deleteContent: async ({ ifMatch }: { ifMatch?: string }) => {
          ifMatches.push(ifMatch)
          if (ifMatches.length === 1) {
            throw foreignRealmError('WasSyncConflictError')
          }
          return 9
        },
        get: async () => ({ version: 8, updatedAt: '2' }) as MasterState
      } as unknown as WasSyncPort

      await runPush({ port, store })

      // The 412 sent the loop back for a fresh If-Match rather than out to the
      // engine's backoff.
      expect(ifMatches).toEqual(['"3"', '"8"'])
      expect(store.calls).toEqual(['markDeletedPushed:doc-1'])
    })

    it('still propagates an unrelated write failure', async () => {
      const store = recordingStore([liveRow('doc-1')])
      const port = {
        query: async () => ({ documents: [], checkpoint: null }),
        putContent: async () => {
          throw new Error('socket hang up')
        },
        deleteContent: async () => 0,
        get: async () => null
      } as unknown as WasSyncPort

      await expect(runPush({ port, store })).rejects.toThrow('socket hang up')
      expect(store.calls).toEqual([])
    })
  })

  describe('remintPendingEnvelopes', () => {
    it('re-mints a row whose cipher raised a foreign-realm unknown epoch', async () => {
      const replaced: { id: string; newId: string }[] = []
      const store = {
        ...recordingStore([liveRow('doc-1')]),
        replacePending: async ({
          id,
          newId
        }: {
          id: string
          newId: string
        }) => {
          replaced.push({ id, newId })
          return { applied: true }
        }
      } as unknown as SyncStore & {
        replacePending: NonNullable<SyncStore['replacePending']>
      }

      const result = await remintPendingEnvelopes({
        store,
        cipher: {
          encrypt: async ({ data }) => ({
            id: 'doc-1-reminted',
            envelope: data,
            epoch: 'epoch-2'
          }),
          decrypt: async () => {
            throw foreignRealmError('UnknownEpochError')
          }
        },
        decryptStale: async ({ envelope }) => envelope
      })

      expect(result).toEqual({ pending: 1, reminted: 1 })
      expect(replaced).toEqual([{ id: 'doc-1', newId: 'doc-1-reminted' }])
    })

    it('still propagates a decrypt failure that is not an unknown epoch', async () => {
      const store = {
        ...recordingStore([liveRow('doc-1')]),
        replacePending: async () => ({ applied: true })
      } as unknown as SyncStore & {
        replacePending: NonNullable<SyncStore['replacePending']>
      }

      await expect(
        remintPendingEnvelopes({
          store,
          cipher: {
            encrypt: async ({ data }) => ({
              id: 'doc-1-reminted',
              envelope: data,
              epoch: 'epoch-2'
            }),
            decrypt: async () => {
              throw foreignRealmError('KeyUnwrapError')
            }
          },
          decryptStale: async ({ envelope }) => envelope
        })
      ).rejects.toThrow(/KeyUnwrapError/)
    })
  })
})
