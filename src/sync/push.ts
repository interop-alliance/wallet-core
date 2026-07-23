/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The push side of the WAS replication engine core: fan each dirty local row out
 * to a conditional WAS write, then reconcile per the content-addressed conflict
 * table.
 *
 * On a content-addressed collection an id's `data` never mutates, so a live row
 * only ever pushes as a create (`If-None-Match: *`) and a tombstone as a delete;
 * there is no update path. A mutable (last-write-wins) collection pushes a live
 * row as a create while never-acked (`version 0`) and as an in-place update
 * (`If-Match`) once acked, and settles a `412` through its injected
 * {@link ResolveConflict} policy.
 *
 * This loop covers the CONTENT sub-resource only (`data` / `version`, at
 * `PUT/DELETE /:id`). It does not drive the independently-versioned METADATA
 * sub-resource (`custom` / `metaVersion`, at `PUT /:id/meta`): a replica that
 * syncs user-writable metadata (the web wallet's RxDB driver, via
 * `WasSyncPort.putMeta`) keeps that half in its own push handler. It is left out
 * of this core deliberately -- none of the wallet Space collections
 * (`private-credentials`, `public-credentials`, `wallet-activity`, `contacts`,
 * `contacts-history`) versions its metadata independently of its content, so
 * folding a `putMeta` diff into this loop would add an untested code path with
 * no collection to exercise it. The `WasSyncPort.putMeta` capability stays
 * optional on the port for the driver that needs it.
 */
import { formatEtag } from '@interop/was-client/sync'
import type { Json, ResolveConflict, SyncStore, WasSyncPort } from './types.js'
import { WasSyncConflictError, WasSyncNotFoundError } from './types.js'

// Formats a master revision as the quoted strong ETag the server compares
// `If-Match` against (revision `3` becomes `"3"`). Re-exported so callers keep
// importing it from here.
export { formatEtag }

/**
 * Pushes a dirty live row. A never-acked row (`version 0`) is a create
 * (`PUT /:id` with `If-None-Match: *`); an acked row (`version > 0`) is an
 * in-place update (`If-Match` over its version) -- reachable only on a mutable
 * collection, since a content-addressed row never mutates in place. On success
 * the acked version is recorded and the row goes clean.
 *
 * A `412` is settled by the collection's policy:
 * - A mutable collection defers to its {@link ResolveConflict} (re-read master,
 *   pick the deterministic winner, apply-remote or re-encrypt-local).
 * - An insert-only content-addressed collection (no resolver) applies the
 *   built-in settlement: master live -> the identical envelope already exists
 *   (same content hash), adopt its version, projection untouched; master
 *   absent/tombstone -> deletion wins, adopt the tombstone and delete the
 *   projection (a later re-add re-encrypts to a fresh id, so nothing is blocked).
 */
async function pushUpsert({
  port,
  store,
  row,
  resolveConflict
}: {
  port: WasSyncPort
  store: SyncStore
  row: { id: string; version: number; data: Json | null }
  resolveConflict?: ResolveConflict
}): Promise<{ conflictResolved: boolean }> {
  try {
    const version = await port.putContent({
      id: row.id,
      data: row.data ?? null,
      ...(row.version > 0
        ? { ifMatch: formatEtag(row.version) }
        : { ifNoneMatch: true })
    })
    await store.markPushed({ id: row.id, version })
    return { conflictResolved: false }
  } catch (err) {
    if (!(err instanceof WasSyncConflictError)) {
      throw err
    }
    if (resolveConflict) {
      await resolveConflict({
        id: row.id,
        version: row.version,
        data: row.data
      })
      // The resolver may have left the row dirty (local-wins re-encrypt); the
      // caller reruns so the re-push settles within the same sync run.
      return { conflictResolved: true }
    }
    const master = await port.get({ id: row.id })
    if (master === null || master.deleted) {
      await store.adoptLatest({
        id: row.id,
        latest: null,
        projection: { kind: 'delete' }
      })
    } else {
      await store.adoptLatest({
        id: row.id,
        latest: master,
        projection: { kind: 'none' }
      })
    }
    return { conflictResolved: false }
  }
}

/**
 * Attempts one conditional delete. Returns `true` when the delete is settled
 * (`204` acked, or `404` -- already gone / never reached the server), `false`
 * on a `412` so the caller can re-read and retry. Any other error propagates to
 * the engine's backoff.
 */
async function tryDelete({
  port,
  store,
  id,
  ifMatch
}: {
  port: WasSyncPort
  store: SyncStore
  id: string
  ifMatch?: string
}): Promise<boolean> {
  try {
    const version = await port.deleteContent({
      id,
      ...(ifMatch !== undefined && { ifMatch })
    })
    await store.markDeletedPushed({ id, version })
    return true
  } catch (err) {
    if (err instanceof WasSyncNotFoundError) {
      await store.markDeletedPushed({ id })
      return true
    }
    if (err instanceof WasSyncConflictError) {
      return false
    }
    throw err
  }
}

/**
 * Pushes a dirty tombstone. `DELETE /:id` with `If-Match` when the row was ever
 * acked (`version > 0`), unconditional otherwise:
 * - `204` / `404` -> settled (clean).
 * - `412` then master absent/tombstone -> delete/delete race, settled.
 * - `412` then master live -> retry once with a fresh `If-Match`; a second
 *   `412` leaves the row dirty for the next cycle (the next pull refreshes its
 *   `version` via the dirty-deleted-vs-live rule, so the retry's `If-Match`
 *   becomes current).
 */
async function pushDelete({
  port,
  store,
  row
}: {
  port: WasSyncPort
  store: SyncStore
  row: { id: string; version: number }
}): Promise<void> {
  const firstIfMatch = row.version > 0 ? formatEtag(row.version) : undefined
  if (await tryDelete({ port, store, id: row.id, ifMatch: firstIfMatch })) {
    return
  }

  const master = await port.get({ id: row.id })
  if (master === null || master.deleted) {
    // delete/delete race -- the resource is already a tombstone / absent.
    await store.markDeletedPushed({ id: row.id })
    return
  }

  // Second attempt with the current master version. If it too hits 412 we simply
  // leave the row dirty (tryDelete returned false and made no store write).
  await tryDelete({
    port,
    store,
    id: row.id,
    ifMatch: formatEtag(master.version)
  })
}

/**
 * Pushes every dirty row for one feed, sequentially (bounds sockets/CPU, and
 * keeps conflict reconciliation deterministic). Honors `signal` between rows.
 * A non-conflict error from any row propagates so the engine aborts the cycle
 * and backs off; already-pushed rows in the batch stay settled.
 *
 * @param options {object}
 * @param options.port {WasSyncPort}
 * @param options.store {SyncStore}
 * @param [options.resolveConflict] {ResolveConflict}   mutable-collection policy
 * @param [options.signal] {AbortSignal}
 * @returns {Promise<{ pushed: number; conflictsResolved: number }>}   dirty rows
 *   processed this cycle, and how many invoked the LWW resolver (a positive
 *   count means the caller should rerun so a local-wins re-push settles)
 */
export async function runPush({
  port,
  store,
  resolveConflict,
  signal
}: {
  port: WasSyncPort
  store: SyncStore
  resolveConflict?: ResolveConflict
  signal?: AbortSignal
}): Promise<{ pushed: number; conflictsResolved: number }> {
  const rows = await store.getDirtyRows()
  let pushed = 0
  let conflictsResolved = 0
  for (const row of rows) {
    if (signal?.aborted) {
      break
    }
    if (row.deleted) {
      await pushDelete({ port, store, row })
    } else {
      const { conflictResolved } = await pushUpsert({
        port,
        store,
        row,
        resolveConflict
      })
      if (conflictResolved) {
        conflictsResolved += 1
      }
    }
    pushed += 1
  }
  return { pushed, conflictsResolved }
}
