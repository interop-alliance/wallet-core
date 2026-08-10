/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/sync` subpath: the WAS replication engine core --
 * the correctness-critical, cross-replica byte-compatibility surface two
 * WAS-enabled wallet apps share.
 *
 * - The wire contract and port seam (`WasSyncPort`, `SyncCheckpoint`, `WireDoc`,
 *   `Json`, `DocCipher`, `MasterState`, and the `WasSyncConflictError` /
 *   `WasSyncNotFoundError` / `UnknownEpochError` signals) come from
 *   `@interop/was-client/sync` and are re-exported here so an engine consumer
 *   imports one package.
 * - `SyncStore` / `SyncedRow` / `ProjectionAction` / `ResolveConflict` are the
 *   replica-side persistence seam.
 * - `runPull` / `projectionForDoc`, `runPush`, and `SyncEngine` are the pull,
 *   push, and orchestration algorithms.
 * - `remintPendingEnvelopes` is the create-loss re-mint for an eager-minting
 *   replica: the descriptor-before-first-content-push invariant's remedy when
 *   another provisioner's descriptor create won (see `remint.ts`).
 * - `SyncedCollectionSpec` is the generic per-collection spec shape a concrete
 *   registry implements.
 * - `resolveContactHeadConflict` / `contactHeadPayloadOf` are the
 *   last-write-wins rule for the one mutable collection (`contacts`), which
 *   needs a `DocCipher` to reach the fields it compares.
 *
 * The RxDB adapter (the web wallet's driver) is intentionally not part of this
 * subpath in v0: that app keeps its own `replicateRxCollection` driver, and its
 * metadata (`putMeta` / `metaVersion`) push half stays driver-side. See
 * `push.ts` for why the metadata half is left out of the shared core.
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

export type {
  SyncStore,
  SyncedRow,
  ProjectionAction,
  ResolveConflict
} from './types.js'

export { runPull, projectionForDoc } from './pull.js'
export { runPush, formatEtag } from './push.js'
export { remintPendingEnvelopes } from './remint.js'
export { SyncEngine } from './engine.js'
export type { SyncEngineDeps, SyncStatus } from './engine.js'
export type { SyncedCollectionSpec } from './collections.js'

export {
  contactHeadPayloadOf,
  resolveContactHeadConflict
} from './contactsConflict.js'
export type { ContactConflictWinner } from './contactsConflict.js'
