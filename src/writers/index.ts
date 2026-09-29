/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The writer roster: the `registered-writers` collection's entry shape, its
 * resource id, the storage seam and WAS adapter, lazy registration with the
 * throttled liveness touch, the sweep-on-read with two-phase expiry, and the
 * join a history view resolves a revision's `writerId` through. Every field
 * is advisory display data, and none is an input to any decision.
 */
export {
  REGISTERED_WRITER_ID_LABEL,
  REGISTERED_WRITER_POLICY,
  parseRegisteredWriterEntry,
  registeredWriterPolicy,
  registeredWriterResourceId
} from './entry.js'
export type { RegisteredWriterEntry, RegisteredWriterPolicy } from './entry.js'
export { wasRegisteredWritersStore } from './store.js'
export type { RegisteredWritersStore, StoredRegisteredWriter } from './store.js'
export {
  registerWriterOnSecondSession,
  renameRegisteredWriter,
  resolveRegisteredWriter,
  sweepRegisteredWriters
} from './roster.js'
export type {
  RegisteredWritersSweep,
  ResolvedWriter,
  WriterRegistrationOutcome,
  WriterFirstSeenRecord,
  WriterFirstSeenStore
} from './roster.js'
