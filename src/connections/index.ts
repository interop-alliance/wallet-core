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
 * - The agent-connection readers: the received list (`receivedGrants`,
 *   `receivedGrantLapsed`, `liveInboxChannel`), the latest grant per scope
 *   (`latestGrantsPerScope`), a consent's renewal scope
 *   (`renewalScopeGrants`), the renewal predicate (`agentGrantDue`,
 *   `AGENT_GRANT_RENEWAL_WINDOW_MS`), and `agentConnectionsSignedBy`.
 * - The upsert helpers (`recordGrants`, `removeGrants`, `retireConnection`,
 *   `unretireConnection`, `setConnectionLabel`) and their kind refusal
 *   (`ConnectionKindMismatchError`), and the agent-connection helpers
 *   (`recordReceivedGrants`, `recordRenewedGrants`, `settleOutboxItem`,
 *   `pruneSupersededGrants`, `dropReceivedGrant`, `clearReceivedGrants`,
 *   `markDeclined`).
 * - The proof check a renewal runs over a recorded grant
 *   (`verifyRecordedGrantProof`), which verifies the delegation signature
 *   under a key the current document lists, and the action-set readers
 *   (`allowsAction`, `normalizedActions`).
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
  CONNECTION_SEED_BYTES,
  CONNECTION_WRITER_POLICY,
  GRANT_KINDS,
  RECEIVED_GRANT_KINDS,
  connectionKindOf,
  decodeConnectionSeed,
  connectionWriterPolicy,
  grantKindOf,
  isWritableConnectionEntry,
  parseConnectionEntry
} from './entry.js'
export type {
  ConnectionEntry,
  ConnectionGrantRecord,
  ConnectionKind,
  ConnectionOutboxItem,
  ConnectionReceivedGrantRecord,
  ConnectionWriter,
  ConnectionWriterPolicy,
  ConnectionZcap,
  GrantKind,
  ReceivedGrantKind
} from './entry.js'
export {
  CONNECTIONS_ID_PREFIX,
  connectionResourceId,
  connectionSeedTag,
  verifyConnectionSeedTag
} from './resourceId.js'
export type { ConnectionIdKey } from './resourceId.js'
export { wasConnectionsStore } from './store.js'
export type { ConnectionsStore, StoredConnection } from './store.js'
export { findConnection, readConnections } from './read.js'
export type { ConnectionsListing, ReadConnection } from './read.js'
export {
  AGENT_GRANT_RENEWAL_WINDOW_MS,
  agentConnectionsSignedBy,
  agentGrantDue,
  allowsAction,
  collectionIdInSpace,
  connectionGrants,
  grantRecipientKid,
  grantTargets,
  isTargetInSpace,
  grantScopeKey,
  latestGrantsPerScope,
  latestIndexPerScope,
  liveInboxChannel,
  normalizedActions,
  receivedGrantLapsed,
  receivedGrants,
  renewalScopeGrants,
  splitGrantsByExpiry
} from './grants.js'
export type { ConnectionGrant, ConnectionReceivedGrant } from './grants.js'
export { verifyRecordedGrantProof } from './grantProof.js'
export type { GrantProofRefusal, GrantProofResult } from './grantProof.js'
export {
  connectionDidKey,
  connectionRecipientKid,
  signingKeyMultibaseOfDid
} from './didKey.js'
export { ConnectionKindMismatchError } from './errors.js'
export {
  clearReceivedGrants,
  dropReceivedGrant,
  markDeclined,
  pruneSupersededGrants,
  recordGrants,
  recordReceivedGrants,
  recordRenewedGrants,
  removeGrants,
  retireConnection,
  setConnectionLabel,
  settleOutboxItem,
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
