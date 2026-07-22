/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Protocol suite for the WAS replication engine core (`src/sync/`). Drives the
 * real `runPull` / `runPush` / `SyncEngine` against a stateful in-memory fake
 * WAS server and an in-memory `SyncStore` whose reconciliation mirrors a
 * concrete replica store, plus an identity `DocCipher` (decrypt = identity).
 *
 * Covers: pull checkpoint iteration + empty/short-page rules, the push conflict
 * table (from both the content-addressed and the tombstone-wins perspectives),
 * the pull-apply-vs-local-dirty table, echo convergence, and the engine's
 * migrate-once ordering / single-flight / backoff behavior. These invariants are
 * exactly what both wallet replicas depend on to converge on identical bytes.
 */
import { describe, it, expect } from 'vitest'

import { runPull } from '../../src/sync/pull.js'
import { runPush, formatEtag } from '../../src/sync/push.js'
import { SyncEngine } from '../../src/sync/engine.js'
import {
  WasSyncConflictError,
  WasSyncNotFoundError,
  type Json,
  type MasterState,
  type ProjectionAction,
  type SyncCheckpoint,
  type SyncStore,
  type SyncedRow,
  type WasSyncPort,
  type WireDoc
} from '../../src/sync/types.js'

// --------------------------------------------------------------------------
// Test doubles
// --------------------------------------------------------------------------

type Cred = { '@context': string[]; id: string; type: string[] }

/** A tiny credential stand-in; the "envelope" IS this JSON (decrypt = identity). */
function makeCred(id: string): Cred {
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    id,
    type: ['VerifiableCredential']
  }
}
const decryptDoc = async (env: Json): Promise<Json> => env
const envelopeFor = (id: string): Json => makeCred(id) as unknown as Json

/**
 * Stateful in-memory WAS server exposing the {@link WasSyncPort}
 * (putContent/deleteContent return the acked version). Documents order by a
 * monotonic tick used as `updatedAt`, mirroring the real change feed.
 */
class FakeWasServer {
  private docs = new Map<
    string,
    { version: number; updatedAt: string; deleted: boolean; data?: Json }
  >()
  private tick = 0

  private nextUpdatedAt(): string {
    this.tick += 1
    return String(this.tick).padStart(12, '0')
  }

  seed(id: string, data: Json): void {
    this.docs.set(id, {
      version: 1,
      updatedAt: this.nextUpdatedAt(),
      deleted: false,
      data
    })
  }

  seedTombstone(id: string): void {
    this.docs.set(id, {
      version: 2,
      updatedAt: this.nextUpdatedAt(),
      deleted: true
    })
  }

  has(id: string): boolean {
    const doc = this.docs.get(id)
    return doc !== undefined && !doc.deleted
  }
  isTombstone(id: string): boolean {
    return this.docs.get(id)?.deleted === true
  }
  dataFor(id: string): Json | undefined {
    return this.docs.get(id)?.data
  }
  versionOf(id: string): number | undefined {
    return this.docs.get(id)?.version
  }

  port(): WasSyncPort {
    return {
      query: async ({ checkpoint, limit }) => {
        const ordered = [...this.docs.entries()]
          .map(([id, doc]) => ({ id, ...doc }))
          .sort((left, right) =>
            left.updatedAt === right.updatedAt
              ? left.id.localeCompare(right.id)
              : left.updatedAt.localeCompare(right.updatedAt)
          )
        const after = checkpoint
          ? ordered.filter(
              doc =>
                doc.updatedAt > checkpoint.updatedAt ||
                (doc.updatedAt === checkpoint.updatedAt &&
                  doc.id > checkpoint.id)
            )
          : ordered
        const page = after.slice(0, limit)
        const documents: WireDoc[] = page.map(doc => ({
          id: doc.id,
          _deleted: doc.deleted,
          updatedAt: doc.updatedAt,
          version: doc.version,
          ...(doc.data !== undefined && !doc.deleted && { data: doc.data })
        }))
        const last = page[page.length - 1]
        const nextCheckpoint: SyncCheckpoint | null = last
          ? { id: last.id, updatedAt: last.updatedAt }
          : null
        return { documents, checkpoint: nextCheckpoint }
      },

      putContent: async ({ id, data, ifMatch, ifNoneMatch }) => {
        const existing = this.docs.get(id)
        // If-None-Match: * fails if the resource exists in ANY form (a tombstone
        // still occupies the id), so a create over a tombstone -> 412.
        if (ifNoneMatch && existing) {
          throw new WasSyncConflictError()
        }
        if (
          ifMatch !== undefined &&
          (!existing || formatEtag(existing.version) !== ifMatch)
        ) {
          throw new WasSyncConflictError()
        }
        const version = (existing?.version ?? 0) + 1
        this.docs.set(id, {
          version,
          updatedAt: this.nextUpdatedAt(),
          deleted: false,
          data
        })
        return version
      },

      deleteContent: async ({ id, ifMatch }) => {
        const existing = this.docs.get(id)
        if (!existing || existing.deleted) {
          // Never existed / already a tombstone -> 404 (settled for a delete).
          throw new WasSyncNotFoundError()
        }
        if (ifMatch !== undefined && formatEtag(existing.version) !== ifMatch) {
          throw new WasSyncConflictError()
        }
        const version = existing.version + 1
        this.docs.set(id, {
          version,
          updatedAt: this.nextUpdatedAt(),
          deleted: true
        })
        return version
      },

      get: async ({ id }) => {
        const doc = this.docs.get(id)
        if (!doc || doc.deleted) {
          return null // tombstone and absent are indistinguishable via GET
        }
        return {
          version: doc.version,
          updatedAt: doc.updatedAt,
          deleted: false,
          data: doc.data
        } satisfies MasterState
      }
    }
  }
}

/** Local row shape (mirrors a concrete `synced_docs` row). */
interface Row {
  id: string
  version: number
  updatedAt: string
  deleted: boolean
  data: Json | null
  dirty: boolean
}

/**
 * In-memory {@link SyncStore} whose `applyPulledPage` / `adoptMaster`
 * reconciliation is byte-for-byte the intended concrete-store behavior, plus a
 * `projection` map standing in for the decrypted read-model.
 */
class InMemoryStore implements SyncStore {
  rows = new Map<string, Row>()
  projection = new Map<string, Cred>()
  checkpoint: SyncCheckpoint | undefined

  /** Test helper: seed a dirty local create (never-acked). */
  localCreate(id: string): void {
    this.rows.set(id, {
      id,
      version: 0,
      updatedAt: '',
      deleted: false,
      data: envelopeFor(id),
      dirty: true
    })
    this.projection.set(id, makeCred(id))
  }
  /** Test helper: mark an existing local row deleted+dirty (a pending delete). */
  localDelete(id: string): void {
    const row = this.rows.get(id)
    if (!row) {
      throw new Error('no such row')
    }
    this.rows.set(id, { ...row, deleted: true, data: null, dirty: true })
    this.projection.delete(id)
  }

  async getCheckpoint(): Promise<SyncCheckpoint | undefined> {
    return this.checkpoint
  }

  async getDirtyRows(): Promise<SyncedRow[]> {
    return [...this.rows.values()]
      .filter(r => r.dirty)
      .map(({ id, version, updatedAt, deleted, data }) => ({
        id,
        version,
        updatedAt,
        deleted,
        data
      }))
  }

  private applyProjection(
    id: string,
    action: ProjectionAction | undefined
  ): void {
    if (!action) {
      return
    }
    if (action.kind === 'upsert') {
      this.projection.set(id, action.payload as unknown as Cred)
    } else if (action.kind === 'delete') {
      this.projection.delete(id)
    }
  }

  async applyPulledPage({
    documents,
    checkpoint,
    projections
  }: {
    documents: WireDoc[]
    checkpoint: SyncCheckpoint
    projections: Map<string, ProjectionAction>
  }): Promise<void> {
    for (const doc of documents) {
      const existing = this.rows.get(doc.id)
      if (doc._deleted) {
        // Tombstone wins.
        this.rows.set(doc.id, {
          id: doc.id,
          version: doc.version,
          updatedAt: doc.updatedAt,
          deleted: true,
          data: null,
          dirty: false
        })
        this.projection.delete(doc.id)
        continue
      }
      if (existing?.dirty && existing.deleted) {
        // Our unacked delete vs a live pull: keep the tombstone dirty, but
        // refresh version/updatedAt so the eventual DELETE's If-Match is current.
        this.rows.set(doc.id, {
          ...existing,
          version: doc.version,
          updatedAt: doc.updatedAt
        })
        continue
      }
      if (existing?.dirty && !existing.deleted) {
        // A pending LIVE local write (mutable head document, local-wins re-push):
        // keep the dirty envelope + projection, only refresh version/updatedAt so
        // the re-push's If-Match is current. Content-addressed feeds never reach
        // here (their pushes settle to clean before the pull).
        this.rows.set(doc.id, {
          ...existing,
          version: doc.version,
          updatedAt: doc.updatedAt
        })
        continue
      }
      // Absent/clean, or our unacked create echoing back (idempotent): upsert and
      // clear dirty. Same bytes by construction on a content-addressed collection.
      this.rows.set(doc.id, {
        id: doc.id,
        version: doc.version,
        updatedAt: doc.updatedAt,
        deleted: false,
        data: (doc.data as Json | undefined) ?? null,
        dirty: false
      })
      this.applyProjection(doc.id, projections.get(doc.id))
    }
    this.checkpoint = checkpoint
  }

  async markPushed({
    id,
    version
  }: {
    id: string
    version?: number
  }): Promise<void> {
    const row = this.rows.get(id)
    if (!row) {
      return
    }
    this.rows.set(id, {
      ...row,
      dirty: false,
      ...(version !== undefined && { version })
    })
  }

  async markDeletedPushed({
    id,
    version
  }: {
    id: string
    version?: number
  }): Promise<void> {
    const row = this.rows.get(id)
    if (!row) {
      return
    }
    this.rows.set(id, {
      ...row,
      deleted: true,
      data: null,
      dirty: false,
      ...(version !== undefined && { version })
    })
  }

  async adoptMaster({
    id,
    master,
    projection
  }: {
    id: string
    master: MasterState | null
    projection: ProjectionAction
  }): Promise<void> {
    const row = this.rows.get(id)
    if (master === null) {
      this.rows.set(id, {
        id,
        version: row?.version ?? 0,
        updatedAt: row?.updatedAt ?? '',
        deleted: true,
        data: null,
        dirty: false
      })
    } else {
      this.rows.set(id, {
        id,
        version: master.version,
        updatedAt: master.updatedAt,
        deleted: master.deleted,
        data: master.data ?? row?.data ?? null,
        dirty: false
      })
    }
    this.applyProjection(id, projection)
  }
}

// --------------------------------------------------------------------------
// runPull
// --------------------------------------------------------------------------

describe('runPull', () => {
  it('pulls remote docs into rows + projection', async () => {
    const server = new FakeWasServer()
    server.seed('a', envelopeFor('a'))
    server.seed('b', envelopeFor('b'))
    const store = new InMemoryStore()

    const { applied } = await runPull({
      port: server.port(),
      store,
      batchSize: 100,
      decryptDoc
    })

    expect(applied).toBe(2)
    expect(store.rows.get('a')?.dirty).toBe(false)
    expect(store.projection.get('a')?.id).toBe('a')
    expect(store.projection.get('b')?.id).toBe('b')
    expect(store.checkpoint).toBeTruthy()
  })

  it('iterates checkpoints across multiple pages', async () => {
    const server = new FakeWasServer()
    for (let i = 0; i < 5; i++) {
      server.seed(`c${i}`, envelopeFor(`c${i}`))
    }
    const store = new InMemoryStore()

    const { applied } = await runPull({
      port: server.port(),
      store,
      batchSize: 2, // 5 docs over pages of 2 -> 3 pages
      decryptDoc
    })

    expect(applied).toBe(5)
    expect(store.projection.size).toBe(5)
  })

  it('skips an undecryptable document instead of wedging the feed', async () => {
    const server = new FakeWasServer()
    server.seed('good1', envelopeFor('good1'))
    server.seed('poison', envelopeFor('poison'))
    server.seed('good2', envelopeFor('good2'))
    const store = new InMemoryStore()

    const failing = async (env: Json): Promise<Json> => {
      if ((env as { id?: string }).id === 'poison') {
        throw new Error('cannot decrypt')
      }
      return env
    }

    const { applied } = await runPull({
      port: server.port(),
      store,
      batchSize: 100,
      decryptDoc: failing
    })

    // Every doc's row + checkpoint advance (the feed is not stuck); only the
    // poison doc lacks a plaintext projection.
    expect(applied).toBe(3)
    expect(store.projection.has('good1')).toBe(true)
    expect(store.projection.has('good2')).toBe(true)
    expect(store.projection.has('poison')).toBe(false)
    expect(store.checkpoint).toBeTruthy()
  })

  it('keeps the prior checkpoint on an empty page', async () => {
    const server = new FakeWasServer()
    server.seed('a', envelopeFor('a'))
    const store = new InMemoryStore()

    await runPull({ port: server.port(), store, batchSize: 100, decryptDoc })
    const first = store.checkpoint
    expect(first).toBeTruthy()

    // No new server changes -> next pull is an empty page; checkpoint unchanged.
    await runPull({ port: server.port(), store, batchSize: 100, decryptDoc })
    expect(store.checkpoint).toEqual(first)
  })

  it('applies a tombstone: deletes the projection', async () => {
    const server = new FakeWasServer()
    server.seed('a', envelopeFor('a'))
    const store = new InMemoryStore()
    await runPull({ port: server.port(), store, batchSize: 100, decryptDoc })
    expect(store.projection.has('a')).toBe(true)

    server.seedTombstone('a')
    await runPull({ port: server.port(), store, batchSize: 100, decryptDoc })

    expect(store.projection.has('a')).toBe(false)
    expect(store.rows.get('a')?.deleted).toBe(true)
    expect(store.rows.get('a')?.dirty).toBe(false)
  })

  it('pull-apply vs our unacked delete: keeps tombstone dirty, refreshes version', async () => {
    const store = new InMemoryStore()
    store.localCreate('a')
    // pretend it was acked at version 1
    await store.markPushed({ id: 'a', version: 1 })
    store.localDelete('a')

    const server = new FakeWasServer()
    server.seed('a', envelopeFor('a')) // remote is live at some version

    await runPull({ port: server.port(), store, batchSize: 100, decryptDoc })

    const row = store.rows.get('a')!
    expect(row.deleted).toBe(true)
    expect(row.dirty).toBe(true)
    expect(row.version).toBe(server.versionOf('a'))
    expect(store.projection.has('a')).toBe(false)
  })
})

// --------------------------------------------------------------------------
// runPush -- create
// --------------------------------------------------------------------------

describe('runPush (create)', () => {
  it('pushes a create: server has it, row clean + acked', async () => {
    const server = new FakeWasServer()
    const store = new InMemoryStore()
    store.localCreate('a')

    await runPush({ port: server.port(), store })

    expect(server.has('a')).toBe(true)
    expect(server.dataFor('a')).toEqual(envelopeFor('a'))
    const row = store.rows.get('a')!
    expect(row.dirty).toBe(false)
    expect(row.version).toBe(server.versionOf('a'))
  })

  it('create 412 + live master: adopts master, projection untouched', async () => {
    const server = new FakeWasServer()
    server.seed('a', envelopeFor('a')) // identical envelope already on server
    const store = new InMemoryStore()
    store.localCreate('a') // credential already in projection locally

    await runPush({ port: server.port(), store })

    const row = store.rows.get('a')!
    expect(row.dirty).toBe(false)
    expect(row.version).toBe(server.versionOf('a'))
    expect(store.projection.has('a')).toBe(true)
  })

  it('create 412 + tombstone master: deletion wins, projection deleted', async () => {
    const server = new FakeWasServer()
    server.seedTombstone('a') // id exists only as a tombstone
    const store = new InMemoryStore()
    store.localCreate('a')

    await runPush({ port: server.port(), store })

    const row = store.rows.get('a')!
    expect(row.deleted).toBe(true)
    expect(row.dirty).toBe(false)
    expect(store.projection.has('a')).toBe(false)
  })
})

// --------------------------------------------------------------------------
// runPush -- delete
// --------------------------------------------------------------------------

describe('runPush (delete)', () => {
  async function seedAckedLocal(
    server: FakeWasServer,
    store: InMemoryStore,
    id: string
  ) {
    store.localCreate(id)
    await runPush({ port: server.port(), store }) // create -> acked at v1
  }

  it('deletes an acked row with If-Match: server tombstone, row clean', async () => {
    const server = new FakeWasServer()
    const store = new InMemoryStore()
    await seedAckedLocal(server, store, 'a')
    store.localDelete('a')

    await runPush({ port: server.port(), store })

    expect(server.isTombstone('a')).toBe(true)
    expect(store.rows.get('a')?.dirty).toBe(false)
    expect(store.rows.get('a')?.deleted).toBe(true)
  })

  it('delete of a never-acked row (unconditional) settles', async () => {
    // Local create+delete before the create ever reached the server: version 0,
    // no remote resource -> DELETE 404 -> settled.
    const server = new FakeWasServer()
    const store = new InMemoryStore()
    store.localCreate('a')
    store.localDelete('a')

    await runPush({ port: server.port(), store })

    expect(store.rows.get('a')?.dirty).toBe(false)
    expect(server.has('a')).toBe(false)
  })

  it('delete 412 then live master: retries with fresh If-Match and settles', async () => {
    const server = new FakeWasServer()
    const store = new InMemoryStore()
    await seedAckedLocal(server, store, 'a') // acked at v1 locally

    // Someone else bumps the server version to 2, so our stale If-Match "1" 412s.
    await server
      .port()
      .putContent({ id: 'a', data: envelopeFor('a'), ifMatch: formatEtag(1) })
    expect(server.versionOf('a')).toBe(2)

    store.localDelete('a') // local row still thinks version is 1

    await runPush({ port: server.port(), store })

    expect(server.isTombstone('a')).toBe(true)
    expect(store.rows.get('a')?.dirty).toBe(false)
  })
})

// --------------------------------------------------------------------------
// Echo convergence
// --------------------------------------------------------------------------

describe('echo convergence', () => {
  it('create -> push -> pull echoes the same doc idempotently (no duplicate)', async () => {
    const server = new FakeWasServer()
    const store = new InMemoryStore()
    store.localCreate('a')

    await runPush({ port: server.port(), store })
    await runPull({ port: server.port(), store, batchSize: 100, decryptDoc })

    // One row, clean, projection stable.
    expect(store.rows.size).toBe(1)
    expect(store.rows.get('a')?.dirty).toBe(false)
    expect(store.projection.size).toBe(1)
    expect(store.projection.get('a')?.id).toBe('a')
  })
})

// --------------------------------------------------------------------------
// Mutable (last-write-wins) conflict settlement, from the resolver perspective
// --------------------------------------------------------------------------

describe('runPush (mutable LWW resolver)', () => {
  it('invokes the resolver on a 412 and reports conflictsResolved', async () => {
    // A mutable head document already acked at v1 locally; the server has moved
    // to v2, so our If-Match "1" update 412s and the resolver settles it.
    const server = new FakeWasServer()
    const store = new InMemoryStore()
    store.localCreate('head')
    await runPush({ port: server.port(), store }) // acked v1
    // Server-side change bumps to v2.
    await server.port().putContent({
      id: 'head',
      data: envelopeFor('head'),
      ifMatch: formatEtag(1)
    })
    // Make the local row a dirty in-place update at the stale version 1.
    const row = store.rows.get('head')!
    store.rows.set('head', { ...row, version: 1, dirty: true })

    let seen = 0
    const resolveConflict = async ({ id }: { id: string }) => {
      seen += 1
      const master = await server.port().get({ id })
      await store.adoptMaster({
        id,
        master,
        projection: { kind: 'none' }
      })
    }

    const { conflictsResolved } = await runPush({
      port: server.port(),
      store,
      resolveConflict
    })

    expect(seen).toBe(1)
    expect(conflictsResolved).toBe(1)
    expect(store.rows.get('head')?.version).toBe(server.versionOf('head'))
  })
})

// --------------------------------------------------------------------------
// SyncEngine
// --------------------------------------------------------------------------

function engineDeps(
  server: FakeWasServer,
  store: InMemoryStore,
  overrides: Record<string, unknown> = {}
) {
  const migratedFlag = { value: false }
  const calls = {
    provision: 0,
    lazyMigration: 0,
    stampMigrated: 0,
    stampLastSynced: 0,
    pullApplied: 0
  }
  const deps = {
    port: server.port(),
    store,
    decryptDoc,
    ensureProvisioned: async () => {
      calls.provision++
    },
    isMigrated: async () => migratedFlag.value,
    runLazyMigration: async () => {
      calls.lazyMigration++
    },
    stampMigrated: async () => {
      migratedFlag.value = true
      calls.stampMigrated++
    },
    stampLastSynced: async () => {
      calls.stampLastSynced++
    },
    onPullApplied: () => {
      calls.pullApplied++
    },
    random: () => 0,
    ...overrides
  }
  return { deps, calls, migratedFlag }
}

describe('SyncEngine', () => {
  it('first cycle: pull, then migrate, then push, then pull; flips migrated', async () => {
    const server = new FakeWasServer()
    server.seed('remote', envelopeFor('remote'))
    const store = new InMemoryStore()
    store.localCreate('local')
    const { deps, calls, migratedFlag } = engineDeps(server, store)

    const engine = new SyncEngine(deps)
    await engine.sync()

    expect(migratedFlag.value).toBe(true)
    expect(calls.lazyMigration).toBe(1)
    expect(calls.stampMigrated).toBe(1)
    expect(calls.stampLastSynced).toBe(1)
    // Local create pushed to server, remote pulled into projection.
    expect(server.has('local')).toBe(true)
    expect(store.projection.has('remote')).toBe(true)
    expect(engine.status).toBe('synced')
  })

  it('stamps migrated only once but sweeps unlinked rows every cycle', async () => {
    const server = new FakeWasServer()
    const store = new InMemoryStore()
    const { deps, calls } = engineDeps(server, store)
    const engine = new SyncEngine(deps)

    await engine.sync()
    await engine.sync()

    expect(calls.stampMigrated).toBe(1)
    expect(calls.lazyMigration).toBe(2)
  })

  it('single-flight: concurrent sync() coalesces and reruns once', async () => {
    const server = new FakeWasServer()
    const store = new InMemoryStore()

    // Gate the first ensureProvisioned so a second sync() lands mid-cycle.
    let release: () => void = () => {}
    const gate = new Promise<void>(resolve => {
      release = resolve
    })
    let provisionCalls = 0
    const { deps } = engineDeps(server, store, {
      ensureProvisioned: async () => {
        provisionCalls++
        if (provisionCalls === 1) {
          await gate
        }
      }
    })
    const engine = new SyncEngine(deps)

    const first = engine.sync()
    const second = engine.sync() // lands while first is gated -> sets rerun
    expect(second).toBe(first)

    release()
    await first

    expect(provisionCalls).toBe(2)
    expect(engine.status).toBe('synced')
  })

  it('on error: status error + schedules a backoff retry; recovers on retry', async () => {
    const server = new FakeWasServer()
    const store = new InMemoryStore()

    let scheduled: (() => void) | null = null
    let lastDelay = 0
    let fail = true
    const { deps } = engineDeps(server, store, {
      ensureProvisioned: async () => {
        if (fail) {
          throw new Error('boom')
        }
      },
      schedule: (fn: () => void, delayMs: number) => {
        scheduled = fn
        lastDelay = delayMs
        return () => {}
      },
      backoff: { baseDelayMs: 1000, maxDelayMs: 60000 }
    })
    const engine = new SyncEngine(deps)

    await engine.sync()
    expect(engine.status).toBe('error')
    expect(scheduled).toBeTruthy()
    expect(lastDelay).toBe(1000)

    // Fire the retry; this time it succeeds.
    fail = false
    await new Promise<void>(resolve => {
      const fn = scheduled!
      scheduled = null
      fn()
      setTimeout(resolve, 0)
    })
    expect(engine.status).toBe('synced')
  })

  it('onPullApplied fires only when a pull applied documents', async () => {
    const server = new FakeWasServer()
    const store = new InMemoryStore()
    const { deps, calls } = engineDeps(server, store)
    // pre-migrate so only the steady-state push+pull runs
    ;(deps as { isMigrated: () => Promise<boolean> }).isMigrated = async () =>
      true

    const engine = new SyncEngine(deps)
    await engine.sync()
    expect(calls.pullApplied).toBe(0)

    server.seed('x', envelopeFor('x'))
    await engine.sync()
    expect(calls.pullApplied).toBe(1)
  })

  it('stop() sets idle and prevents further syncs', async () => {
    const server = new FakeWasServer()
    const store = new InMemoryStore()
    const { deps } = engineDeps(server, store)
    const engine = new SyncEngine(deps)

    engine.stop()
    expect(engine.status).toBe('idle')
    await engine.sync() // no-op after stop
    expect(engine.status).toBe('idle')
  })
})
