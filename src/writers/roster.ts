/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The writer roster's logic: lazy registration with its throttled liveness
 * touch, the user's rename, the sweep-on-read with two-phase expiry, and the
 * join a history view renders a revision's `writerId` through.
 *
 * Orphaning is the normal lifecycle of a writer: a cleared browser profile
 * cannot deregister. So no cleanup here depends on the dying writer. Any
 * replica that reads the roster sweeps it, every sweep write is conditional
 * on the ETag it read, and a lost race is skipped, so concurrent sweepers
 * converge. Registration waits until the writer is encountered in a second
 * session under the same account, which keeps one-shot writers (an incognito
 * window, a cleared profile) out of the roster altogether.
 */
import { NotSupportedError } from '@interop/was-client'
import {
  parseRegisteredWriterEntry,
  registeredWriterPolicy,
  registeredWriterResourceId
} from './entry.js'
import type { RegisteredWriterEntry, RegisteredWriterPolicy } from './entry.js'
import type { RegisteredWritersStore, StoredRegisteredWriter } from './store.js'

/**
 * The writer first-seen record, kept client-local: the account and
 * `writerId` this client's writer first appeared under, and when it last
 * touched its roster entry. One slot, so a writer that moves to another
 * account starts over.
 */
export interface WriterFirstSeenRecord {
  accountDid: string
  writerId: string
  /**
   * ISO 8601 UTC start of the session the record was written in.
   */
  firstSessionAt: string
  /**
   * ISO 8601 UTC time of the latest successful registration or touch.
   */
  lastTouchedAt?: string
}

/**
 * The client-local seam for the writer first-seen record. Where it lives is
 * the wallet's choice. A forget of this client's local state clears it along with
 * the `writerId`.
 */
export interface WriterFirstSeenStore {
  get(): Promise<unknown>
  put(record: WriterFirstSeenRecord): Promise<void>
}

/**
 * What {@link registerWriterOnSecondSession} did.
 *
 * - `deferred` -- the writer has not yet been encountered in a second session
 *   under this account; the first-seen record is (re)written and the roster
 *   is untouched.
 * - `fresh` -- the latest touch is within the touch interval; no I/O.
 * - `registered` -- a new entry was written (or a malformed one replaced).
 * - `touched` -- the existing entry's `lastSeen` was advanced.
 * - `raced` -- every attempt lost a conditional write; the next call retries.
 */
export type WriterRegistrationOutcome =
  'deferred' | 'fresh' | 'registered' | 'touched' | 'raced'

const PRECONDITION_FAILED_ERROR_NAME = 'PreconditionFailedError'
const NOT_FOUND_ERROR_NAME = 'NotFoundError'
const REGISTRATION_ATTEMPTS = 3

/**
 * Whether a store write lost a race: a conditional write refused, or (for a
 * delete) the resource already gone. A put that meets `NotFoundError` has
 * not raced. It is refused, so it propagates. Matched by name, since the
 * store is an injected seam that may raise from a second copy of was-client.
 *
 * @param err {unknown}
 * @param [options] {object}
 * @param [options.deleting] {boolean}
 * @returns {boolean}
 */
function isLostRace(
  err: unknown,
  { deleting = false }: { deleting?: boolean } = {}
): boolean {
  const name = (err as { name?: unknown } | null)?.name
  return (
    name === PRECONDITION_FAILED_ERROR_NAME ||
    (deleting && name === NOT_FOUND_ERROR_NAME)
  )
}

/**
 * The ETag a guarded write over an existing resource pins to. A read that
 * carried none would send the write unconditionally and could overwrite a
 * newer touch or rename, so it is refused instead.
 *
 * @param options {object}
 * @param options.resourceId {string}
 * @param [options.etag] {string}
 * @returns {string}
 */
function requireEtag({
  resourceId,
  etag
}: {
  resourceId: string
  etag?: string
}): string {
  if (etag === undefined) {
    throw new NotSupportedError(
      `Cannot update registered writer "${resourceId}": its read returned ` +
        'no ETag, so the write would go out unconditionally. A browser ' +
        "client needs `ETag` in the server's `Access-Control-Expose-Headers`."
    )
  }
  return etag
}

/**
 * An entry's `lastSeen` as a time no later than `now`. A writer's clock
 * that runs fast would otherwise keep its entry newest, ahead of every
 * eviction.
 *
 * @param options {object}
 * @param options.entry {RegisteredWriterEntry}
 * @param options.now {Date}
 * @returns {number}
 */
function effectiveLastSeen({
  entry,
  now
}: {
  entry: RegisteredWriterEntry
  now: Date
}): number {
  return Math.min(Date.parse(entry.lastSeen), now.getTime())
}

/**
 * Reads the writer first-seen record, or `undefined` when it is missing or
 * malformed.
 *
 * @param body {unknown}
 * @returns {WriterFirstSeenRecord | undefined}
 */
function parseFirstSeenRecord(
  body: unknown
): WriterFirstSeenRecord | undefined {
  if (body === null || typeof body !== 'object') {
    return undefined
  }
  const { accountDid, writerId, firstSessionAt, lastTouchedAt } =
    body as Record<string, unknown>
  if (
    typeof accountDid !== 'string' ||
    typeof writerId !== 'string' ||
    typeof firstSessionAt !== 'string' ||
    Number.isNaN(Date.parse(firstSessionAt)) ||
    (lastTouchedAt !== undefined &&
      (typeof lastTouchedAt !== 'string' ||
        Number.isNaN(Date.parse(lastTouchedAt))))
  ) {
    return undefined
  }
  return {
    accountDid,
    writerId,
    firstSessionAt,
    ...(lastTouchedAt !== undefined && { lastTouchedAt })
  }
}

/**
 * One stored resource read as an entry of this account's roster: a
 * well-formed entry stored at its own resource id. An entry stored under any
 * other id is skipped, so a copied or misplaced entry labels nothing.
 *
 * @param options {object}
 * @param options.accountDid {string}
 * @param options.stored {StoredRegisteredWriter}
 * @returns {RegisteredWriterEntry | undefined}
 */
function boundEntry({
  accountDid,
  stored
}: {
  accountDid: string
  stored: StoredRegisteredWriter
}): RegisteredWriterEntry | undefined {
  const entry = parseRegisteredWriterEntry(stored.body)
  if (
    entry === undefined ||
    registeredWriterResourceId({ accountDid, writerId: entry.writerId }) !==
      stored.resourceId
  ) {
    return undefined
  }
  return entry
}

/**
 * Registers this client's writer in the roster once it is encountered in a
 * second session under the account, and touches its `lastSeen` at most once
 * per touch interval after that. Call it on the wallet's connect or sync path;
 * calls within the interval cost no I/O.
 *
 * A new entry takes `label`. A touch keeps the stored label, so a rename
 * stands, and refreshes `signingKeyMultibase` when one is given. Registering
 * a new entry first makes room under the entry cap, deleting the
 * oldest-`lastSeen` entries.
 *
 * @param options {object}
 * @param options.store {RegisteredWritersStore}
 * @param options.local {WriterFirstSeenStore}
 * @param options.accountDid {string}   the account whose Space holds the roster
 * @param options.writerId {string}   this client's writer
 * @param options.label {string}   the coarse platform self-description a new
 *   entry takes
 * @param options.sessionStartedAt {Date}   when the current session began; a
 *   first-seen record written at or after it is this session's own
 * @param [options.signingKeyMultibase] {string}   an enrolled wallet client's
 *   own signing-key multibase
 * @param [options.now] {Date}
 * @param [options.policy] {Partial<RegisteredWriterPolicy>}
 * @returns {Promise<WriterRegistrationOutcome>}
 */
export async function registerWriterOnSecondSession({
  store,
  local,
  accountDid,
  writerId,
  label,
  sessionStartedAt,
  signingKeyMultibase,
  now = new Date(),
  policy
}: {
  store: RegisteredWritersStore
  local: WriterFirstSeenStore
  accountDid: string
  writerId: string
  label: string
  sessionStartedAt: Date
  signingKeyMultibase?: string
  now?: Date
  policy?: Partial<RegisteredWriterPolicy>
}): Promise<WriterRegistrationOutcome> {
  const resolved = registeredWriterPolicy(policy)
  const firstSeen = parseFirstSeenRecord(await local.get())
  if (
    firstSeen === undefined ||
    firstSeen.accountDid !== accountDid ||
    firstSeen.writerId !== writerId
  ) {
    await local.put({
      accountDid,
      writerId,
      firstSessionAt: sessionStartedAt.toISOString()
    })
    return 'deferred'
  }
  if (Date.parse(firstSeen.firstSessionAt) >= sessionStartedAt.getTime()) {
    return 'deferred'
  }
  if (
    firstSeen.lastTouchedAt !== undefined &&
    now.getTime() - Date.parse(firstSeen.lastTouchedAt) <
      resolved.touchIntervalMs
  ) {
    return 'fresh'
  }

  const resourceId = registeredWriterResourceId({ accountDid, writerId })
  const lastSeen = now.toISOString()
  for (let attempt = 0; attempt < REGISTRATION_ATTEMPTS; attempt++) {
    const stored = await store.get({ resourceId })
    const existing =
      stored === undefined
        ? undefined
        : boundEntry({ accountDid, stored: { resourceId, ...stored } })
    const entry: RegisteredWriterEntry = {
      version: 1,
      writerId,
      ...(signingKeyMultibase !== undefined
        ? { signingKeyMultibase }
        : existing?.signingKeyMultibase !== undefined && {
            signingKeyMultibase: existing.signingKeyMultibase
          }),
      label: existing?.label ?? label,
      lastSeen,
      active: true
    }
    try {
      if (stored === undefined) {
        await sweepStored({
          store,
          accountDid,
          stored: await store.list(),
          now,
          policy: resolved,
          capacity: resolved.maxEntries - 1
        })
        await store.put({ resourceId, entry, ifNoneMatch: true })
      } else {
        await store.put({
          resourceId,
          entry,
          ifMatch: requireEtag({ resourceId, etag: stored.etag })
        })
      }
    } catch (err) {
      if (isLostRace(err)) {
        continue
      }
      throw err
    }
    await local.put({ ...firstSeen, lastTouchedAt: lastSeen })
    return existing === undefined ? 'registered' : 'touched'
  }
  return 'raced'
}

/**
 * Renames this client's writer. The rename lands only on a registered entry;
 * before registration there is nothing to rename, and the call returns
 * `false`.
 *
 * @param options {object}
 * @param options.store {RegisteredWritersStore}
 * @param options.accountDid {string}
 * @param options.writerId {string}
 * @param options.label {string}   the new label; blank is refused
 * @returns {Promise<boolean>}   whether an entry was renamed
 */
export async function renameRegisteredWriter({
  store,
  accountDid,
  writerId,
  label
}: {
  store: RegisteredWritersStore
  accountDid: string
  writerId: string
  label: string
}): Promise<boolean> {
  const trimmed = label.trim()
  if (!trimmed) {
    throw new TypeError('A writer label must not be blank.')
  }
  const resourceId = registeredWriterResourceId({ accountDid, writerId })
  const stored = await store.get({ resourceId })
  if (stored === undefined) {
    return false
  }
  const existing = boundEntry({ accountDid, stored: { resourceId, ...stored } })
  if (existing === undefined) {
    return false
  }
  await store.put({
    resourceId,
    entry: { ...existing, label: trimmed },
    ifMatch: requireEtag({ resourceId, etag: stored.etag })
  })
  return true
}

/**
 * The outcome of a sweep: the entries left standing, and what it changed.
 */
export interface RegisteredWritersSweep {
  entries: RegisteredWriterEntry[]
  markedInactive: string[]
  deleted: string[]
}

/**
 * The two-phase expiry over a listing already read. An active entry past the
 * inactivity TTL is marked inactive. Past `capacity` entries, the
 * oldest-`lastSeen` ones are deleted (ties broken by resource id, so every
 * sweeper picks the same ones). A resource that is not a bound entry is left
 * alone and not counted: it may be an entry sealed under an epoch this reader
 * does not hold yet.
 *
 * @param options {object}
 * @param options.store {RegisteredWritersStore}
 * @param options.accountDid {string}
 * @param options.stored {StoredRegisteredWriter[]}
 * @param options.now {Date}
 * @param options.policy {RegisteredWriterPolicy}
 * @param options.capacity {number}   the most entries to leave standing
 * @returns {Promise<RegisteredWritersSweep>}
 */
async function sweepStored({
  store,
  accountDid,
  stored,
  now,
  policy,
  capacity
}: {
  store: RegisteredWritersStore
  accountDid: string
  stored: StoredRegisteredWriter[]
  now: Date
  policy: RegisteredWriterPolicy
  capacity: number
}): Promise<RegisteredWritersSweep> {
  const bound: Array<{
    stored: StoredRegisteredWriter
    entry: RegisteredWriterEntry
  }> = []
  for (const item of stored) {
    const entry = boundEntry({ accountDid, stored: item })
    if (entry !== undefined) {
      bound.push({ stored: item, entry })
    }
  }
  bound.sort(
    (left, right) =>
      effectiveLastSeen({ entry: right.entry, now }) -
        effectiveLastSeen({ entry: left.entry, now }) ||
      (left.stored.resourceId < right.stored.resourceId ? -1 : 1)
  )

  const markedInactive: string[] = []
  const deleted: string[] = []
  const entries: RegisteredWriterEntry[] = []
  for (const [index, { stored: item, entry }] of bound.entries()) {
    // A resource read without an ETag is never written: an unconditional
    // write could clobber a newer touch.
    if (index >= Math.max(capacity, 0)) {
      if (item.etag === undefined) {
        continue
      }
      try {
        await store.delete({ resourceId: item.resourceId, ifMatch: item.etag })
        deleted.push(entry.writerId)
      } catch (err) {
        if (!isLostRace(err, { deleting: true })) {
          throw err
        }
      }
      continue
    }
    const expired =
      now.getTime() - effectiveLastSeen({ entry, now }) > policy.inactiveAfterMs
    if (entry.active && expired && item.etag !== undefined) {
      const inactive: RegisteredWriterEntry = { ...entry, active: false }
      try {
        await store.put({
          resourceId: item.resourceId,
          entry: inactive,
          ifMatch: item.etag
        })
        markedInactive.push(entry.writerId)
        entries.push(inactive)
      } catch (err) {
        if (!isLostRace(err)) {
          throw err
        }
        // A newer write won; the entry as read still labels its revisions.
        entries.push(entry)
      }
      continue
    }
    entries.push(entry)
  }
  return { entries, markedInactive, deleted }
}

/**
 * Reads the roster and sweeps it: the sweep-on-read every history view runs.
 * Safe to run from any replica, and concurrently.
 *
 * @param options {object}
 * @param options.store {RegisteredWritersStore}
 * @param options.accountDid {string}   the account whose Space holds the roster
 * @param [options.now] {Date}
 * @param [options.policy] {Partial<RegisteredWriterPolicy>}
 * @returns {Promise<RegisteredWritersSweep>}
 */
export async function sweepRegisteredWriters({
  store,
  accountDid,
  now = new Date(),
  policy
}: {
  store: RegisteredWritersStore
  accountDid: string
  now?: Date
  policy?: Partial<RegisteredWriterPolicy>
}): Promise<RegisteredWritersSweep> {
  const resolved = registeredWriterPolicy(policy)
  return sweepStored({
    store,
    accountDid,
    stored: await store.list(),
    now,
    policy: resolved,
    capacity: resolved.maxEntries
  })
}

/**
 * How a history view renders one revision's writer. `undefined` from
 * {@link resolveRegisteredWriter} means no entry: the view renders its
 * fallback label ("another session").
 */
export interface ResolvedWriter {
  label: string
  active: boolean
  /**
   * Present only when the entry's `signingKeyMultibase` is an enrolled
   * client's key in the verified account document. The view may then link
   * the revision to that client's row. Absent, the label stands unlinked.
   */
  clientSigningKeyMultibase?: string
}

/**
 * Resolves a revision's `writerId` against the swept roster.
 *
 * @param options {object}
 * @param options.writerId {string}
 * @param options.entries {RegisteredWriterEntry[]}   a sweep's `entries`
 * @param options.enrolledSigningKeys {ReadonlySet<string>}   the signing-key
 *   multibases of the enrolled clients in the verified account document
 * @returns {ResolvedWriter | undefined}
 */
export function resolveRegisteredWriter({
  writerId,
  entries,
  enrolledSigningKeys
}: {
  writerId: string
  entries: RegisteredWriterEntry[]
  enrolledSigningKeys: ReadonlySet<string>
}): ResolvedWriter | undefined {
  const entry = entries.find(candidate => candidate.writerId === writerId)
  if (entry === undefined) {
    return undefined
  }
  const linked =
    entry.signingKeyMultibase !== undefined &&
    enrolledSigningKeys.has(entry.signingKeyMultibase)
  return {
    label: entry.label,
    active: entry.active,
    ...(linked && { clientSigningKeyMultibase: entry.signingKeyMultibase })
  }
}
