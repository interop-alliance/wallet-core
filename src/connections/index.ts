/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/connections` subpath: the `connections`
 * directory, one encrypted entry per party the wallet has dealt with (an app,
 * an agent, a wallet client, a contact). The wallet writes every entry, and
 * no party ever writes one.
 *
 * - The entry codec (`parseConnectionEntry`), the `kind` and `grantKind`
 *   vocabularies, and the writer policy (`CONNECTION_WRITER_POLICY`).
 * - `connectionResourceId`, the two-arm resource id keyed by the
 *   collection's blinded-index key.
 * - The store seam and its WAS adapter (`wasConnectionsStore`), and the one
 *   listing read (`readConnections`) every lookup by DID resolves against.
 * - The grant index the revocation orchestrators share
 *   (`connectionGrants`, `grantTargets`, `splitGrantsByExpiry`,
 *   `grantRecipientKid`), with the reader checks every reader applies.
 * - The upsert helpers (`recordGrants`, `removeGrants`, `retireConnection`,
 *   `unretireConnection`, `setConnectionLabel`) and their kind refusal
 *   (`ConnectionKindMismatchError`).
 * - The writer arm: lazy registration (`registerConnectionWriter`), the
 *   pull-path touch (`touchConnectionWriter`), the per-entry sweep
 *   (`sweepConnectionWriters`), and `resolveWriter` for history views.
 * - `signingKeyMultibaseOfDid`, the one join between a wallet client's entry
 *   and the account document, and `normalizeDisplayName`, the one name rule
 *   every producer writes `name` through.
 */
export {
  CONNECTION_ENTRY_VERSION,
  CONNECTION_KINDS,
  CONNECTION_WRITER_POLICY,
  GRANT_KINDS,
  connectionKindOf,
  connectionWriterPolicy,
  grantKindOf,
  isWritableConnectionEntry,
  parseConnectionEntry
} from './entry.js'
export type {
  ConnectionEntry,
  ConnectionGrantRecord,
  ConnectionKind,
  ConnectionWriter,
  ConnectionWriterPolicy,
  ConnectionZcap,
  GrantKind
} from './entry.js'
export { CONNECTIONS_ID_PREFIX, connectionResourceId } from './resourceId.js'
export type { ConnectionIdKey } from './resourceId.js'
export { wasConnectionsStore } from './store.js'
export type { ConnectionsStore, StoredConnection } from './store.js'
export { findConnection, readConnections } from './read.js'
export type { ConnectionsListing, ReadConnection } from './read.js'
export {
  collectionIdInSpace,
  connectionGrants,
  grantRecipientKid,
  grantTargets,
  isTargetInSpace,
  splitGrantsByExpiry
} from './grants.js'
export type { ConnectionGrant } from './grants.js'
export { connectionRecipientKid, signingKeyMultibaseOfDid } from './didKey.js'
export { ConnectionKindMismatchError } from './errors.js'
export {
  recordGrants,
  removeGrants,
  retireConnection,
  setConnectionLabel,
  unretireConnection
} from './upsert.js'
export type { ConnectionWriteOutcome, ConnectionWriteResult } from './upsert.js'
export {
  registerConnectionWriter,
  resolveWriter,
  sweepConnectionWriters,
  touchConnectionWriter
} from './writers.js'
export type {
  ConnectionWritersSweep,
  ResolvedWriter,
  WriterFirstSeenRecord,
  WriterFirstSeenStore,
  WriterRegistrationOutcome,
  WriterTouchOutcome
} from './writers.js'
export { normalizeDisplayName } from '../labelText.js'
export { CONNECTIONS_COLLECTION } from '../space/collections.js'
