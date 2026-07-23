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
 */
export interface SyncedRow {
  id: string
  version: number
  updatedAt: string
  deleted: boolean
  data: Json | null
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
  /** The last persisted pull checkpoint, or `undefined` before the first pull. */
  getCheckpoint(): Promise<SyncCheckpoint | undefined>

  /** All rows awaiting push (dirty). */
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
   * Marks a pushed create as acked: clear dirty, and record the server `version`
   * when provided (the `204` ETag).
   */
  markPushed(options: { id: string; version?: number }): Promise<void>

  /**
   * Marks a pushed delete as settled: keep the tombstone, clear dirty, and
   * record the server `version` when provided.
   */
  markDeletedPushed(options: { id: string; version?: number }): Promise<void>

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
