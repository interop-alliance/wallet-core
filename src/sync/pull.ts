/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The pull side of the WAS replication engine core: iterate the `changes` feed
 * from the stored checkpoint, decrypt each document to a projection action
 * OUTSIDE the store transaction, and hand each page to the store to apply
 * atomically.
 *
 * All I/O is through the injected {@link WasSyncPort} and {@link SyncStore};
 * decryption is the injected `decryptDoc`. No environment-specific imports, so
 * the loop runs identically in the browser, Node, and React Native.
 *
 * Cross-replica invariants this loop and the RxDB `createPullHandler` in the web
 * wallet's driver both hold, so the two replicas resume the same feed the same
 * way:
 * - Omit `checkpoint` entirely on the first pull (never send `null`).
 * - Empty page (`checkpoint: null`, "no change") keeps the PRIOR checkpoint --
 *   never overwrite it with `null`, or the feed restarts from the beginning.
 * - A tombstone deletes the projected row; a live document decrypts its `data`
 *   body to the payload to upsert.
 *
 * Echo suppression is an optimization on top of that and must not change what
 * converges. A live feed document whose `writerId` equals the engine's own
 * injected label, and whose revision the store confirms it already holds
 * ({@link SyncStore.heldRevisions}), skips the decrypt and applies with a
 * `none` projection: the local projection already reflects that revision,
 * since this replica wrote it. Every other document -- no `writerId`, a
 * foreign one, or one the store does not confirm -- is decrypted exactly as
 * before. The label is advisory plaintext a host can rewrite, which is why the
 * store's revision check, not the label, is what licenses the skip: a forged
 * label on a revision this replica does not hold still decrypts.
 */
import { isIntegrityError } from '@interop/was-client/sync'

import { log } from '../log.js'
import type {
  Json,
  ProjectionAction,
  SyncCheckpoint,
  SyncStore,
  WasSyncPort,
  WireDoc
} from './types.js'

/**
 * Maps one pulled wire document to the projection action for the decrypted
 * read-model. A tombstone deletes the projected row; a live document decrypts
 * its `data` body to the payload to upsert. A live document with no body (should
 * not occur on an encrypted collection) is a no-op.
 *
 * Decryption runs here, outside the store transaction, so a slow/failing decrypt
 * never holds the store's write lock. A document whose body cannot be decrypted
 * (legacy plaintext row, corrupt/foreign envelope, key mismatch) is skipped with
 * a `none` projection rather than throwing: the body is still stored and the
 * checkpoint advances past it, so one poison document can never permanently
 * wedge the feed for the whole replica. A document that decrypts but fails the
 * collection's `validatePayload` guard (written by the other replica --
 * possibly a buggy or schema-incompatible writer) is skipped the same way:
 * stored, checkpoint advanced, never projected.
 *
 * The decrypt is addressed: the feed row's own `id` goes to `decryptDoc`, and
 * the cipher refuses an envelope sealed for some other resource with was-
 * client's `IntegrityError`. That refusal has two causes and the reader
 * cannot tell them apart: a host that moved one resource's stored envelope
 * under another resource's id, and a row minted by a writer that predates
 * addressed sealing (the legacy contacts rows
 * `docs/cross-replica-sync-compatibility.md` records as a stated loss, which
 * every fresh replica bootstrap re-reads). It is logged apart from the
 * ordinary undecryptable skip so a caller can count it, but the benign cause
 * is the common one and an alert on it needs a rate rather than a single
 * event. The projection outcome is the same `none`: the row is not applied,
 * the body is still stored, and the checkpoint advances past it.
 *
 * @param doc {WireDoc}
 * @param decryptDoc {(options: { id: string, envelope: Json }) =>
 *   Promise<Json>}
 * @param [validatePayload] {(payload: Json) => boolean}
 * @returns {Promise<ProjectionAction>}
 */
export async function projectionForDoc(
  doc: WireDoc,
  decryptDoc: (options: { id: string; envelope: Json }) => Promise<Json>,
  validatePayload?: (payload: Json) => boolean
): Promise<ProjectionAction> {
  if (doc._deleted) {
    return { kind: 'delete' }
  }
  if (doc.data === undefined || doc.data === null) {
    return { kind: 'none' }
  }
  try {
    const payload = await decryptDoc({ id: doc.id, envelope: doc.data as Json })
    if (validatePayload !== undefined && !validatePayload(payload)) {
      log.warn('Skipping malformed synced document (no projection)', {
        id: doc.id
      })
      return { kind: 'none' }
    }
    return { kind: 'upsert', payload }
  } catch (err) {
    if (isIntegrityError(err)) {
      log.warn(
        'Skipping synced document sealed for another resource id (no ' +
          'projection)',
        {
          id: doc.id,
          err
        }
      )
      return { kind: 'none' }
    }
    log.warn('Skipping undecryptable synced document (no projection)', {
      id: doc.id,
      err
    })
    return { kind: 'none' }
  }
}

/**
 * Are two feed positions the same point? Used as the pull loop's
 * no-progress guard: a page whose resume checkpoint equals the one it was
 * fetched with would be refetched forever.
 *
 * @param left {SyncCheckpoint | undefined}
 * @param right {SyncCheckpoint | null}
 * @returns {boolean}
 */
function sameCheckpoint(
  left: SyncCheckpoint | undefined,
  right: SyncCheckpoint | null
): boolean {
  if (left === undefined || right === null) {
    return false
  }
  return left.id === right.id && left.updatedAt === right.updatedAt
}

/**
 * The ids of a page's own-writer echoes the store already holds. A document
 * qualifies as a candidate when it is live, carries an `etag`, and names
 * `writerId`; the store then confirms which of those revisions it holds.
 * Suppression is off (an empty set) when no `writerId` was injected or the
 * store does not implement {@link SyncStore.heldRevisions}.
 *
 * @param options {object}
 * @param options.store {SyncStore}
 * @param options.documents {WireDoc[]}
 * @param [options.writerId] {string}
 * @returns {Promise<Set<string>>}
 */
async function heldEchoes({
  store,
  documents,
  writerId
}: {
  store: SyncStore
  documents: WireDoc[]
  writerId?: string
}): Promise<Set<string>> {
  if (writerId === undefined || store.heldRevisions === undefined) {
    return new Set()
  }
  const candidates: { id: string; etag: string }[] = []
  for (const doc of documents) {
    if (!doc._deleted && doc.etag !== undefined && doc.writerId === writerId) {
      candidates.push({ id: doc.id, etag: doc.etag })
    }
  }
  if (candidates.length === 0) {
    return new Set()
  }
  const confirmed = await store.heldRevisions({ documents: candidates })
  // Only a candidate can be suppressed, whatever else the store answers.
  return new Set(candidates.map(({ id }) => id).filter(id => confirmed.has(id)))
}

/**
 * Runs the pull loop to exhaustion for one feed. Fetches a page from the current
 * checkpoint, decrypts it to projections, and applies it (upserts + projection +
 * checkpoint advance) in one exclusive store transaction. Terminates on an empty
 * page (caught up / no change -- the prior checkpoint is kept, never overwritten
 * with `null`), or on a checkpoint that did not advance. Page size is never used
 * as the caught-up signal: the server may clamp `limit` below the requested
 * `batchSize`. Honors `signal` between pages so a lock drops
 * the loop promptly; a mid-loop abort leaves each already-applied page intact
 * and the feed resumable.
 *
 * @param options {object}
 * @param options.port {WasSyncPort}
 * @param options.store {SyncStore}
 * @param options.batchSize {number}     pull `limit` (server clamps at 1000)
 * @param options.decryptDoc {(options: { id: string, envelope: Json }) =>
 *   Promise<Json>}
 * @param [options.validatePayload] {(payload: Json) => boolean}   collection
 *   payload guard; a decrypted document failing it is stored but not projected
 * @param [options.writerId] {string}   this writer's attribution label; turns
 *   on echo suppression when the store implements `heldRevisions`
 * @param [options.signal] {AbortSignal}
 * @returns {Promise<{ applied: number; suppressed: number }>}   documents
 *   applied across all pages, and how many of them skipped the decrypt as a
 *   held own-writer echo
 */
export async function runPull({
  port,
  store,
  batchSize,
  decryptDoc,
  validatePayload,
  writerId,
  signal
}: {
  port: WasSyncPort
  store: SyncStore
  batchSize: number
  decryptDoc: (options: { id: string; envelope: Json }) => Promise<Json>
  validatePayload?: (payload: Json) => boolean
  writerId?: string
  signal?: AbortSignal
}): Promise<{ applied: number; suppressed: number }> {
  let applied = 0
  let suppressed = 0
  for (;;) {
    if (signal?.aborted) {
      break
    }

    const checkpoint = await store.getCheckpoint()
    const { documents, checkpoint: next } = await port.query({
      // Omit `checkpoint` entirely on the first pull.
      ...(checkpoint !== undefined && { checkpoint }),
      limit: batchSize
    })

    // Empty page ("no change") -- or a defensively-guarded null checkpoint on a
    // non-empty page: keep the prior checkpoint so the feed does not restart.
    if (documents.length === 0 || next === null) {
      break
    }

    // Decrypt the whole page concurrently -- each document is independent, and
    // decryption dominates the page's cost. The entries are collected in
    // document order, so `projections` is keyed identically to a sequential run.
    // A held own-writer echo skips the decrypt with a `none` projection.
    const held = await heldEchoes({ store, documents, writerId })
    const actions = await Promise.all(
      documents.map(doc =>
        held.has(doc.id)
          ? Promise.resolve<ProjectionAction>({ kind: 'none' })
          : projectionForDoc(doc, decryptDoc, validatePayload)
      )
    )
    const projections = new Map<string, ProjectionAction>(
      documents.map((doc, index) => [doc.id, actions[index]!])
    )

    // A lock/stop between decrypt and apply drops this page (checkpoint not
    // advanced), leaving it to a clean re-pull -- cheaper than holding the write
    // lock across the abort check.
    if (signal?.aborted) {
      break
    }

    await store.applyPulledPage({
      documents,
      checkpoint: next as SyncCheckpoint,
      projections
    })
    applied += documents.length
    suppressed += held.size

    // Caught-up is decided by the SERVER, not by page size: a server free to
    // clamp `limit` returns full-but-short pages forever, so a
    // `documents.length < batchSize` test would stop the loop one page into the
    // backlog. We loop until the server itself says there is nothing left --
    // an empty page (checked at the top of the next iteration), at the cost of
    // one extra round trip at the tail. The checkpoint is the same page's
    // resume position; if it somehow did not advance, stop rather than refetch
    // the same page forever.
    if (sameCheckpoint(checkpoint, next)) {
      break
    }
  }
  return { applied, suppressed }
}
