/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The generic per-collection spec SHAPE the replication engine + store drive one
 * feed with. It bundles everything a feed needs: its id and id-derivation model,
 * its plaintext-projection transactional writers, its lazy-migration sweep, the
 * read-model refresh to fire after a pull, and (for a mutable collection) its
 * 412 last-write-wins policy.
 *
 * Only the SHAPE lives here. The concrete registry -- which collections a given
 * app replicates and how each writer touches the app's own store -- stays
 * app-side, because the writers bind to the app's transaction handle and its
 * read-model refresh mechanism. The spec is parameterized over those two so a
 * SQLite-backed replica and a future RxDB adapter can both implement it without
 * this module importing either store:
 *
 * - `Tx` is the store's transaction handle passed to `applyUpsertTx` /
 *   `applyDeleteTx` (a SQLite database instance in the mobile store; whatever an
 *   RxDB writer needs in the browser store). It replaces the mobile store's
 *   concrete `SQLiteDatabase` leak with a type parameter.
 * - `RefreshContext` is whatever `onPullApplied` needs to trigger a read-model
 *   refresh (a Redux dispatch in one app, a store handle or `void` in another).
 */
import type {
  DocCipher,
  Json,
  ResolveConflict,
  SyncStore,
  WasSyncPort
} from './types.js'

/**
 * One synced collection's full behavior. `applyUpsertTx` / `applyDeleteTx` are
 * the store's plaintext-projection writers, invoked inside the store's pull
 * transaction with the decrypted payload; `migrate` is the unlinked-row sweep;
 * `makeResolveConflict` is present only for a mutable (LWW) collection, absent
 * for insert-only content-addressed collections whose push settlement covers
 * every 412.
 *
 * `encryption` selects the doc cipher and the server-side collection marker:
 * `'edv'` (the default) envelopes every doc, `'plaintext'` ships it verbatim;
 * `isPublic` grants collection-level world read on the server. Both replicas
 * MUST agree on `collectionId` / `idDerivation` / `encryption` / `isPublic` for
 * a collection, or their writes land in separate or differently-shaped
 * collections and never converge.
 */
export interface SyncedCollectionSpec<Tx = unknown, RefreshContext = void> {
  collectionId: string
  idDerivation: 'content' | 'random'
  encryption?: 'edv' | 'plaintext'
  isPublic?: boolean
  /**
   * Structural guard for this collection's decrypted payloads (they were
   * written by the other replica). A pulled document that decrypts but fails
   * it is stored without being projected. Absent = project without checking.
   */
  validatePayload?: (payload: Json) => boolean
  applyUpsertTx: (
    tx: Tx,
    profileRecordId: string,
    syncId: string,
    payload: Json
  ) => Promise<void>
  applyDeleteTx: (
    tx: Tx,
    profileRecordId: string,
    syncId: string
  ) => Promise<void>
  onPullApplied: (context: RefreshContext) => void
  migrate: (options: {
    profileRecordId: string
    cipher: DocCipher
    signal?: AbortSignal
  }) => Promise<void>
  makeResolveConflict?: (options: {
    profileRecordId: string
    cipher: DocCipher
    port: WasSyncPort
    store: SyncStore
  }) => ResolveConflict
}
