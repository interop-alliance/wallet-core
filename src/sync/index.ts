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
 *   `WasSyncNotFoundError` signals) come from `@interop/was-client/sync` and are
 *   re-exported here so an engine consumer imports one package.
 * - `SyncStore` / `SyncedRow` / `ProjectionAction` / `ResolveConflict` are the
 *   replica-side persistence seam.
 * - `runPull` / `projectionForDoc`, `runPush`, and `SyncEngine` are the pull,
 *   push, and orchestration algorithms.
 * - `SyncedCollectionSpec` is the generic per-collection spec shape a concrete
 *   registry implements.
 *
 * The RxDB adapter (the web wallet's driver) is intentionally not part of this
 * subpath in v0: that app keeps its own `replicateRxCollection` driver, and its
 * metadata (`putMeta` / `metaVersion`) push half stays driver-side. See
 * `push.ts` for why the metadata half is left out of the shared core.
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

export type {
  SyncStore,
  SyncedRow,
  ProjectionAction,
  ResolveConflict
} from './types.js'

export { runPull, projectionForDoc } from './pull.js'
export { runPush, formatEtag } from './push.js'
export { SyncEngine } from './engine.js'
export type { SyncEngineDeps, SyncStatus } from './engine.js'
export type { SyncedCollectionSpec } from './collections.js'
