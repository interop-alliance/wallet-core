/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The push side of the WAS replication engine core: fan each dirty local
 * resource replica out to a conditional WAS write, then reconcile per the
 * content-addressed conflict table.
 *
 * On a content-addressed collection an id's `data` never mutates, so a live
 * resource replica only ever pushes as a create (`If-None-Match: *`) and a
 * tombstone as a delete; there is no update path. A mutable (last-write-wins)
 * collection pushes a live resource replica as a create while never-acked
 * and as an in-place update (`If-Match`) once acked, and settles
 * a `412` through its injected {@link ResolveConflict} policy.
 *
 * This loop covers the CONTENT sub-resource only (`data`, at
 * `PUT/DELETE /:id`). It does not drive the independently-validated METADATA
 * sub-resource (`custom` / `metaEtag`, at `PUT /:id/meta`): a replica that
 * syncs user-writable metadata (the web wallet's RxDB driver, via
 * `WasSyncPort.putMeta`) keeps that half in its own push handler. It is left
 * out of this core deliberately -- none of the wallet Space collections
 * (`private-credentials`, `public-credentials`, `wallet-activity`, `contacts`,
 * `contacts-history`) versions its metadata independently of its content, so
 * folding a `putMeta` diff into this loop would add an untested code path with
 * no collection to exercise it. The `WasSyncPort.putMeta` capability stays
 * optional on the port for the driver that needs it.
 *
 * Every content write and delete carries the engine's injected `writerId`, when
 * one was injected, as the `Writer-Id` header (the WAS writer-attribution
 * label). The label is minted app-side; this loop never mints, persists, or
 * derives one. The server's declare-or-clear rule means a write without it
 * clears the stored label, so an engine run without a `writerId` attributes
 * nothing rather than leaving a previous writer's label in place.
 */
import {
  isSyncConflictError,
  isSyncNotFoundError
} from '@interop/was-client/sync'
import type { Json, ResolveConflict, SyncStore, WasSyncPort } from './types.js'

/**
 * Pushes a dirty live resource replica. A never-acked resource replica is a
 * create (`PUT /:id` with `If-None-Match: *`); an acked one is an in-place
 * update (`If-Match` over its stored `etag`, echoed back verbatim -- absent
 * only where the server never exposed one) -- reachable only on a mutable
 * collection, since a content-addressed resource replica never mutates in
 * place. On success `acked` and the `etag` are recorded and the resource
 * replica goes clean --
 * unless a local write landed while the write was in flight, which the resource
 * replica's `revision` token detects (see {@link SyncStore.markPushed}) so the
 * newer write stays dirty for the rerun cycle.
 *
 * A `412` is settled by the collection's policy:
 * - A mutable collection defers to its {@link ResolveConflict} (re-read master,
 *   pick the deterministic winner, apply-remote or re-encrypt-local).
 * - An insert-only content-addressed collection (no resolver) applies the
 *   built-in settlement: master live -> the identical envelope already exists
 *   (same content hash), adopt its state, projection untouched; master
 *   absent/tombstone -> deletion wins, adopt the tombstone and delete the
 *   projection (a later re-add re-encrypts to a fresh id, so nothing is blocked).
 */
async function pushUpsert({
  port,
  store,
  replica,
  resolveConflict,
  writerId
}: {
  port: WasSyncPort
  store: SyncStore
  replica: {
    id: string
    acked: boolean
    etag?: string
    data: Json | null
    revision?: string | number
  }
  resolveConflict?: ResolveConflict
  writerId?: string
}): Promise<{ conflictResolved: boolean }> {
  try {
    const ack = await port.putContent({
      id: replica.id,
      data: replica.data ?? null,
      ...(replica.acked ? { ifMatch: replica.etag } : { ifNoneMatch: true }),
      ...(writerId !== undefined && { writerId })
    })
    await store.markPushed({
      id: replica.id,
      etag: ack.etag,
      ...(replica.revision !== undefined && { revision: replica.revision })
    })
    return { conflictResolved: false }
  } catch (err) {
    if (!isSyncConflictError(err)) {
      throw err
    }
    if (resolveConflict) {
      await resolveConflict({ id: replica.id, data: replica.data })
      // The resolver may have left the resource replica dirty (local-wins
      // re-encrypt); the caller reruns so the re-push settles within the same
      // sync run.
      return { conflictResolved: true }
    }
    const master = await port.get({ id: replica.id })
    // An absent or tombstoned resource surfaces as `get` resolving null.
    if (master === null) {
      await store.adoptLatest({
        id: replica.id,
        latest: null,
        projection: { kind: 'delete' }
      })
    } else {
      await store.adoptLatest({
        id: replica.id,
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
  ifMatch,
  revision,
  writerId
}: {
  port: WasSyncPort
  store: SyncStore
  id: string
  ifMatch?: string
  revision?: string | number
  writerId?: string
}): Promise<boolean> {
  const revisionAck = revision !== undefined ? { revision } : {}
  try {
    const ack = await port.deleteContent({
      id,
      ...(ifMatch !== undefined && { ifMatch }),
      ...(writerId !== undefined && { writerId })
    })
    await store.markDeletedPushed({
      id,
      etag: ack?.etag,
      ...revisionAck
    })
    return true
  } catch (err) {
    if (isSyncNotFoundError(err)) {
      await store.markDeletedPushed({ id, ...revisionAck })
      return true
    }
    if (isSyncConflictError(err)) {
      return false
    }
    throw err
  }
}

/**
 * Pushes a dirty tombstone. `DELETE /:id` with `If-Match` over the resource
 * replica's stored `etag` when the resource replica was ever acked (`acked`,
 * 0`), unconditional otherwise:
 * - `204` / `404` -> settled (clean).
 * - `412` then master absent/tombstone -> delete/delete race, settled.
 * - `412` then master live -> retry once with the master's fresh `etag`; a
 *   second `412` leaves the resource replica dirty for the next cycle (the next
 *   pull refreshes its `etag` via the dirty-deleted-vs-live rule,
 *   so the retry's `If-Match` becomes current).
 */
async function pushDelete({
  port,
  store,
  replica,
  writerId
}: {
  port: WasSyncPort
  store: SyncStore
  replica: {
    id: string
    acked: boolean
    etag?: string
    revision?: string | number
  }
  writerId?: string
}): Promise<void> {
  const revisionAck =
    replica.revision !== undefined ? { revision: replica.revision } : {}
  const firstIfMatch = replica.acked ? replica.etag : undefined
  if (
    await tryDelete({
      port,
      store,
      id: replica.id,
      ifMatch: firstIfMatch,
      writerId,
      ...revisionAck
    })
  ) {
    return
  }

  const master = await port.get({ id: replica.id })
  if (master === null) {
    // delete/delete race -- the resource is already a tombstone / absent.
    await store.markDeletedPushed({ id: replica.id, ...revisionAck })
    return
  }

  // Second attempt with the master's current etag. If it too hits 412 we simply
  // leave the resource replica dirty (tryDelete returned false and made no
  // store write).
  await tryDelete({
    port,
    store,
    id: replica.id,
    ifMatch: master.etag,
    writerId,
    ...revisionAck
  })
}

/**
 * Pushes every dirty resource replica for one feed, sequentially (bounds
 * sockets/CPU, and keeps conflict reconciliation deterministic). Honors
 * `signal` between resource replicas. A non-conflict error from any resource
 * replica propagates so the engine aborts the cycle and backs off;
 * already-pushed resource replicas in the batch stay settled.
 *
 * @param options {object}
 * @param options.port {WasSyncPort}
 * @param options.store {SyncStore}
 * @param [options.resolveConflict] {ResolveConflict}   mutable-collection policy
 * @param [options.writerId] {string}   this writer's attribution label, sent
 *   as `Writer-Id` on every write and delete; absent sends none
 * @param [options.signal] {AbortSignal}
 * @returns {Promise<{ pushed: number; conflictsResolved: number }>}   dirty
 *   resource replicas processed this cycle, and how many invoked the LWW resolver (a positive
 *   count means the caller should rerun so a local-wins re-push settles)
 */
export async function runPush({
  port,
  store,
  resolveConflict,
  writerId,
  signal
}: {
  port: WasSyncPort
  store: SyncStore
  resolveConflict?: ResolveConflict
  writerId?: string
  signal?: AbortSignal
}): Promise<{ pushed: number; conflictsResolved: number }> {
  const replicas = await store.getDirtyResourceReplicas()
  let pushed = 0
  let conflictsResolved = 0
  for (const replica of replicas) {
    if (signal?.aborted) {
      break
    }
    if (replica.deleted) {
      await pushDelete({ port, store, replica, writerId })
    } else {
      const { conflictResolved } = await pushUpsert({
        port,
        store,
        replica,
        resolveConflict,
        writerId
      })
      if (conflictResolved) {
        conflictsResolved += 1
      }
    }
    pushed += 1
  }
  return { pushed, conflictsResolved }
}
