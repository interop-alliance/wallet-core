/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Types for the WAS replication engine core.
 *
 * The wire contract and port seam (`Json`, `SyncCheckpoint`, `WireDoc`,
 * `MasterState`, `WasSyncPort`, `DocCipher`, and the `WasSyncConflictError` /
 * `WasSyncNotFoundError` / `UnknownEpochError` signals) come from
 * `@interop/was-client/sync` and are re-exported here so a single import gives
 * a consumer both the wire types and the replica-side seams. Beside the three
 * signal classes sit the three predicates that CLASSIFY them
 * ({@link isSyncConflictError}, {@link isSyncNotFoundError},
 * {@link isUnknownEpochError}): each is raised inside an app-injected seam --
 * the port for the two wire signals, the caller's `DocCipher` for the third --
 * which can resolve to a second copy of `@interop/was-client` (a `link:` dev
 * setup, a dedupe miss through a dependency tree), so they are matched on
 * `err.name` and never with `instanceof`. The same rule the resource-log
 * refusal classes follow, and for the same reason: an `instanceof` miss here
 * turns every push 412 into a fatal cycle error and makes the create-loss
 * re-mint rethrow instead of re-minting. Every one of the three classes
 * assigns its `name` explicitly, which is what makes the string a contract.
 *
 * The local-persistence seam (`SyncStore`, `SyncedRow`, `ProjectionAction`,
 * `ResolveConflict`) is the replica's side of the contract: it stands in for a
 * concrete store (an RxDB collection, a SQLite `synced_docs` / `sync_checkpoints`
 * table pair, or an in-memory test double). The engine owns the `DocCipher` and
 * decrypts OUTSIDE the store transaction, so these methods never see key
 * material.
 *
 * This module (and `pull.ts` / `push.ts` / `engine.ts`) has no runtime imports
 * beyond the wire contract, so the engine runs anywhere: browser, Node, or React
 * Native, against a fake port and an in-memory store.
 */
export {
  UnknownEpochError,
  WasSyncConflictError,
  WasSyncNotFoundError
} from '@interop/was-client/sync'
export type {
  Json,
  SyncCheckpoint,
  WireDoc,
  MasterState,
  WasSyncPort,
  DocCipher
} from '@interop/was-client/sync'

import type {
  Json,
  MasterState,
  SyncCheckpoint,
  WireDoc
} from '@interop/was-client/sync'

/**
 * Whether an error is the replication port's rejected-conditional-write signal
 * (`WasSyncConflictError`, HTTP 412): a lost-update `If-Match` mismatch, or a
 * create-if-absent whose target already exists. The push loop's one settle-and-
 * reconcile branch; everything else propagates to the engine's backoff.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
export function isSyncConflictError(err: unknown): boolean {
  return (err as { name?: unknown } | null)?.name === 'WasSyncConflictError'
}

/**
 * Whether an error is the replication port's absent-target signal
 * (`WasSyncNotFoundError`, HTTP 404). On a delete that is a settled outcome
 * -- already gone, or the write never reached the server -- not a conflict.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
export function isSyncNotFoundError(err: unknown): boolean {
  return (err as { name?: unknown } | null)?.name === 'WasSyncNotFoundError'
}

/**
 * Whether an error is the cipher's unknown-epoch signal (`UnknownEpochError`):
 * an envelope naming recipient key ids whose epoch the descriptor this reader
 * holds does not list at all. Distinct from a key the reader simply does not
 * have (`KeyUnwrapError`), which re-reading the descriptor cannot fix.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
export function isUnknownEpochError(err: unknown): boolean {
  return (err as { name?: unknown } | null)?.name === 'UnknownEpochError'
}

/**
 * A dirty local synced-docs row awaiting push. `data` is the stored body (the
 * EDV envelope on an encrypted collection, or the plaintext JSON on a plaintext
 * one), `null` for a tombstone. `version` is the last server-acked content
 * revision (`0` = never acked, so a create).
 *
 * `revision` is the store's own local revision token for the row: any opaque
 * value the store bumps on EVERY local write (a counter, a hash of the stored
 * body, an RxDB `_rev`). The push loop carries it back through
 * {@link SyncStore.markPushed} / {@link SyncStore.markDeletedPushed} so the ack
 * can be made conditional -- a local write that lands while the HTTP write is
 * in flight leaves a different token behind and keeps the row dirty. A store
 * that omits it opts out of that protection and is acked unconditionally.
 */
export interface SyncedRow {
  id: string
  version: number
  updatedAt: string
  deleted: boolean
  data: Json | null
  revision?: string | number
}

/**
 * What a pulled / reconciled document does to the decrypted read-model (the
 * plaintext projection for the collection). Computed by the engine (which owns
 * the DocCipher) and handed to the store to apply inside the same transaction as
 * the envelope write. The collection-specific meaning of "upsert" / "delete" is
 * supplied to the store as transactional writer functions, so this action stays
 * collection-agnostic: `payload` is the decrypted document body. `none` = leave
 * the projection untouched (e.g. adopting a live master for a document already
 * present locally).
 */
export type ProjectionAction =
  { kind: 'upsert'; payload: Json } | { kind: 'delete' } | { kind: 'none' }

/**
 * The per-row 412-conflict policy for a mutable (last-write-wins) collection,
 * injected into the push loop. Insert-only content-addressed collections leave
 * it undefined: their settlement rules -- identical-envelope adoption and
 * tombstone-wins -- already cover every 412. For a mutable head document the
 * resolver re-reads the master, decides the winner deterministically, and either
 * applies the remote payload or re-encrypts the local one for the next push.
 * Bound to a profile's cipher + store by the caller; opaque to the push loop.
 */
export type ResolveConflict = (row: {
  id: string
  version: number
  data: Json | null
}) => Promise<void>

/**
 * The local-persistence seam, pre-bound to one `(replica, collection)` feed. A
 * concrete store implements it; the engine and the pull/push loops depend only
 * on this interface. Every method that mutates more than one table does so in
 * ONE exclusive transaction (see the per-method notes). Decryption happens in
 * the engine, outside these calls.
 */
export interface SyncStore {
  /**
   * The last persisted pull checkpoint, or `undefined` before the first pull.
   */
  getCheckpoint(): Promise<SyncCheckpoint | undefined>

  /**
   * All rows awaiting push (dirty).
   */
  getDirtyRows(): Promise<SyncedRow[]>

  /**
   * Applies one pulled page in a single exclusive transaction: reconcile each
   * document against the local row (per the pull-apply conflict table), write
   * the matching projection action, and advance the checkpoint. `projections`
   * is keyed by document id.
   */
  applyPulledPage(options: {
    documents: WireDoc[]
    checkpoint: SyncCheckpoint
    projections: Map<string, ProjectionAction>
  }): Promise<void>

  /**
   * Marks a pushed create/update as acked: record the server `version` when
   * provided (the `204` ETag), and clear dirty -- but ONLY if the row's current
   * {@link SyncedRow.revision} still equals the `revision` that was pushed. A
   * local write that landed while the write was in flight leaves a newer token,
   * and that row MUST stay dirty (with the acked `version` still recorded, so
   * the re-push's `If-Match` is current) so the rerun cycle pushes it. When
   * `revision` is `undefined` -- a store that does not track a revision token --
   * dirty is cleared unconditionally.
   */
  markPushed(options: {
    id: string
    version?: number
    revision?: string | number
  }): Promise<void>

  /**
   * Marks a pushed delete as settled: keep the tombstone, record the server
   * `version` when provided, and clear dirty under the same revision condition
   * as {@link SyncStore.markPushed} -- a row rewritten locally mid-flight stays
   * dirty and keeps its local state rather than being forced to a clean
   * tombstone.
   */
  markDeletedPushed(options: {
    id: string
    version?: number
    revision?: string | number
  }): Promise<void>

  /**
   * Adopts the server's latest state (its {@link MasterState}, in the wire
   * contract's RxDB-derived naming) for a row whose push hit a `412`, applying
   * `projection` in the same transaction. `latest === null` means the server
   * has a tombstone (or the resource is absent): record the tombstone and
   * delete the projection.
   */
  adoptLatest(options: {
    id: string
    latest: MasterState | null
    projection: ProjectionAction
  }): Promise<void>

  /**
   * Replaces the body of a pending row (dirty, never-acked, live -- no feed
   * existence) with a re-minted envelope, re-keying the row from `id` to
   * `newId` when the fresh encryption minted a different resource id, all in
   * ONE transaction: the row keeps `version 0` and stays dirty, and whatever
   * links the plaintext projection / app row to the synced row moves to
   * `newId` with it. Under the same revision condition as
   * {@link SyncStore.markPushed}: when `revision` is provided and the row's
   * current token differs (a local write landed mid-re-mint), the replace is
   * skipped -- the newer state stays as-is for the next pass.
   *
   * The outcome MUST be reported: resolve with `{ applied: true }` when the
   * row's body was replaced, and `{ applied: false }` when the revision
   * condition skipped it. A skip is not a failure, but it leaves a row still
   * sealed under an epoch the published descriptor does not carry, and the
   * caller (`remintPendingEnvelopes`) re-probes and retries it rather than
   * counting it as re-minted -- a silently skipped row would otherwise be
   * pushed to the feed as a permanently unroutable entry. A store that does
   * not track a revision token replaces unconditionally and always reports
   * `{ applied: true }`.
   *
   * Optional: only an eager-minting replica (one that mints envelopes at
   * local write time against a cached descriptor) needs it, for the
   * create-loss re-mint (`remintPendingEnvelopes`). A replica that mints
   * lazily in the engine's migration sweep never re-mints and may omit it.
   */
  replacePending?(options: {
    id: string
    newId: string
    envelope: Json
    revision?: string | number
  }): Promise<{ applied: boolean }>
}
