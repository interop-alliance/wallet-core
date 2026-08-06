/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Types for the WAS replication engine core.
 *
 * The wire contract and port seam (`Json`, `SyncCheckpoint`, `WireDoc`,
 * `MasterState`, `WasSyncPort`, `DocCipher`, and the `WasSyncConflictError` /
 * `WasSyncNotFoundError` signals) come from `@interop/was-client/sync` and are
 * re-exported here so a single import gives a consumer both the wire types and
 * the replica-side seams.
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
}
