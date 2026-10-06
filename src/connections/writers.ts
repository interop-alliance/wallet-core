/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The directory's writer arm: the `writers` list on a wallet client's entry,
 * one member per `writerId` the client has written under. Lazy registration
 * with its throttled liveness touch, the pull-path touch, the per-entry sweep
 * with its two-phase expiry, and the join a history view resolves a
 * revision's `writerId` through.
 *
 * Orphaning is a writer's normal end: a cleared browser profile cannot
 * deregister. So no cleanup here depends on the dying writer. Any replica
 * that reads the directory sweeps it, every sweep write is conditional on the
 * ETag it read, and a lost race is skipped, so concurrent sweepers converge.
 * Registration waits until the writer is encountered in a second session
 * under the same account, which keeps one-shot writers (an incognito window,
 * a cleared profile) off the entry altogether.
 *
 * Every field is advisory display data. A pulled revision's `writerId` is
 * not verified, so a host can replay a registered one and keep its member
 * active. Nothing here is an input to an authorization decision.
 */
import { isJsonObject } from '../jsonObject.js'
import { normalizeDisplayName } from '../labelText.js'
import { signingKeyMultibaseOfDid } from './didKey.js'
import {
  connectionWriterPolicy,
  isWritableConnectionEntry,
  newConnectionEntry
} from './entry.js'
import type {
  ConnectionEntry,
  ConnectionWriter,
  ConnectionWriterPolicy
} from './entry.js'
import type { ConnectionsListing, ReadConnection } from './read.js'
import { connectionResourceId } from './resourceId.js'
import type { ConnectionIdKey } from './resourceId.js'
import type { ConnectionsStore } from './store.js'
import { isLostConnectionRace, writeConnection } from './upsert.js'
import type { ConnectionChange, WritableConnection } from './upsert.js'

/**
 * The writer first-seen record, kept by the client: the account and
 * `writerId` this client's writer first appeared under, and when it last
 * touched its member. One slot, so a writer that moves to another account
 * starts over.
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
 * The seam for the writer first-seen record. Where it lives is the wallet's
 * choice: it rides the session's persistence, and a forget of this client's
 * local state clears it along with the `writerId`.
 */
export interface WriterFirstSeenStore {
  get(): Promise<unknown>
  put(record: WriterFirstSeenRecord): Promise<void>
}

/**
 * What {@link registerConnectionWriter} did.
 *
 * - `deferred` -- the writer has not yet been encountered in a second session
 *   under this account; the first-seen record is (re)written and the
 *   directory is untouched.
 * - `fresh` -- the latest touch is within the touch interval; no I/O.
 * - `registered` -- the writer member was added (the entry created if it was
 *   absent).
 * - `touched` -- the writer member's `lastSeen` was advanced.
 * - `raced` -- every attempt lost a conditional write; the next call retries.
 * - `unlisted` -- no entry stands and the verified document does not list
 *   this client, so none is created.
 * - `retired` -- the entry is retired and the verified document no longer
 *   lists this client; nothing is written.
 * - `kind-mismatch` -- the entry at this client's id is not a
 *   `wallet-client` entry; nothing is written, and the caller logs it.
 * - `refused` -- the entry cannot be parsed, or comes from a newer build;
 *   nothing is written.
 */
export type WriterRegistrationOutcome =
  | 'deferred'
  | 'fresh'
  | 'registered'
  | 'touched'
  | 'raced'
  | 'unlisted'
  | 'retired'
  | 'kind-mismatch'
  | 'refused'

/**
 * A writer member's `lastSeen` as a time no later than `now`. A writer whose
 * clock runs fast would otherwise keep its member newest, ahead of every
 * eviction.
 *
 * @param options {object}
 * @param options.writer {ConnectionWriter}
 * @param options.now {Date}
 * @returns {number}
 */
function effectiveLastSeen({
  writer,
  now
}: {
  writer: ConnectionWriter
  now: Date
}): number {
  return Math.min(Date.parse(writer.lastSeen), now.getTime())
}

/**
 * Writer members ordered newest-`lastSeen` first, ties broken by `writerId`,
 * so every sweeper drops the same ones.
 *
 * @param options {object}
 * @param options.writers {ConnectionWriter[]}
 * @param options.now {Date}
 * @returns {ConnectionWriter[]}
 */
function newestFirst({
  writers,
  now
}: {
  writers: ConnectionWriter[]
  now: Date
}): ConnectionWriter[] {
  return [...writers].sort(
    (left, right) =>
      effectiveLastSeen({ writer: right, now }) -
        effectiveLastSeen({ writer: left, now }) ||
      (left.writerId < right.writerId ? -1 : 1)
  )
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
  if (!isJsonObject(body)) {
    return undefined
  }
  const { accountDid, writerId, firstSessionAt, lastTouchedAt } = body
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
 * The entry's writers with one member's `lastSeen` moved to `now` and the
 * member marked active.
 *
 * @param options {object}
 * @param options.writers {ConnectionWriter[]}
 * @param options.member {ConnectionWriter}   one of `writers`
 * @param options.now {Date}
 * @returns {ConnectionWriter[]}
 */
function touchedWriters({
  writers,
  member,
  now
}: {
  writers: ConnectionWriter[]
  member: ConnectionWriter
  now: Date
}): ConnectionWriter[] {
  const lastSeen = now.toISOString()
  return writers.map(writer =>
    writer === member ? { ...writer, lastSeen, active: true } : writer
  )
}

/**
 * The change {@link registerConnectionWriter} applies: create the entry, or
 * add or touch this client's member, or stop with the outcome that forbids
 * the write. A new member first makes room under the cap, dropping the
 * oldest-`lastSeen` members. `added` says whether the body carries a new
 * member rather than a touched one.
 *
 * @param options {object}
 * @param [options.current] {WritableConnection}
 * @param options.did {string}
 * @param options.writerId {string}
 * @param options.label {string}
 * @param options.listedInDocument {boolean}
 * @param options.now {Date}
 * @param options.policy {ConnectionWriterPolicy}
 * @returns {object}
 */
function withOwnWriter({
  current,
  did,
  writerId,
  label,
  listedInDocument,
  now,
  policy
}: {
  current: WritableConnection | undefined
  did: string
  writerId: string
  label: string
  listedInDocument: boolean
  now: Date
  policy: ConnectionWriterPolicy
}): ConnectionChange<WriterRegistrationOutcome> & { added?: boolean } {
  const lastSeen = now.toISOString()
  const ownMember = { writerId, label, lastSeen, active: true }
  if (current === undefined) {
    if (!listedInDocument) {
      return { stop: 'unlisted' }
    }
    return {
      body: {
        ...newConnectionEntry({ kind: 'wallet-client', did, now }),
        name: label,
        writers: [ownMember]
      },
      added: true
    }
  }
  const { entry } = current
  if (entry.kind !== 'wallet-client') {
    return { stop: 'kind-mismatch' }
  }
  if (entry.retired !== undefined && !listedInDocument) {
    return { stop: 'retired' }
  }
  const existing = entry.writers.find(writer => writer.writerId === writerId)
  let writers: ConnectionWriter[]
  if (existing !== undefined) {
    writers = touchedWriters({ writers: entry.writers, member: existing, now })
  } else {
    const kept = newestFirst({ writers: entry.writers, now }).slice(
      0,
      Math.max(policy.maxWriters - 1, 0)
    )
    writers = [
      ...entry.writers.filter(writer => kept.includes(writer)),
      ownMember
    ]
  }
  const body: Record<string, unknown> = {
    ...current.body,
    lastSeen,
    writers
  }
  // A retired entry this client still stands in the document for is a
  // forget torn after its retirement: un-retire it.
  delete body.retired
  return { body, added: existing === undefined }
}

/**
 * Registers this client's writer on its own `wallet-client` entry once the
 * writer is encountered in a second session under the account, and touches
 * the member's `lastSeen` at most once per touch interval after that. Call it
 * on the wallet's connect or sync path; calls within the interval cost no
 * I/O. The interval runs from the last settled call, whatever its outcome,
 * so an entry this client cannot write (`unlisted`, `retired`,
 * `kind-mismatch`, `refused`) is re-read once per interval and not on every
 * call. Only `raced` leaves the next call to try again at once.
 *
 * An absent entry is created (`kind: 'wallet-client'`, `id` this client's
 * did:key, `name` the platform label), which converges a lost
 * enrollment-time write, but only while the verified account document lists
 * this client. A retired entry is un-retired while the document lists this
 * client (a forget torn after its retirement) and left alone otherwise. A
 * new member first makes room under the per-entry writer cap.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}   the collection's blinded-index
 *   key
 * @param options.local {WriterFirstSeenStore}
 * @param options.accountDid {string}   the account the first-seen record is
 *   kept under
 * @param options.did {string}   this client's did:key
 * @param options.writerId {string}   this client's writer
 * @param options.label {string}   the coarse platform self-description a new
 *   member (and a new entry's `name`) takes; held to the display-name rule,
 *   and refused with a `TypeError` outside it
 * @param options.listedInDocument {boolean}   whether the verified account
 *   document lists this client
 * @param options.sessionStartedAt {Date}   when the current session began; a
 *   first-seen record written at or after it is this session's own
 * @param [options.now] {Date}
 * @param [options.policy] {Partial<ConnectionWriterPolicy>}
 * @returns {Promise<WriterRegistrationOutcome>}
 */
export async function registerConnectionWriter({
  store,
  hmacKey,
  local,
  accountDid,
  did,
  writerId,
  label,
  listedInDocument,
  sessionStartedAt,
  now = new Date(),
  policy
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  local: WriterFirstSeenStore
  accountDid: string
  did: string
  writerId: string
  label: string
  listedInDocument: boolean
  sessionStartedAt: Date
  now?: Date
  policy?: Partial<ConnectionWriterPolicy>
}): Promise<WriterRegistrationOutcome> {
  const resolved = connectionWriterPolicy(policy)
  const name = normalizeDisplayName({ value: label })
  if (name === undefined) {
    throw new TypeError(
      'A writer label is 1 to 64 code points once control and bidi ' +
        'characters are stripped.'
    )
  }
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

  let written: WriterRegistrationOutcome = 'touched'
  const outcome = await racedAs('raced', async () =>
    writeConnection<WriterRegistrationOutcome>({
      store,
      hmacKey,
      resourceId: await connectionResourceId({ hmacKey, did }),
      unwritable: 'refused',
      change(current) {
        const next = withOwnWriter({
          current,
          did,
          writerId,
          label: name,
          listedInDocument,
          now,
          policy: resolved
        })
        written = next.added === true ? 'registered' : 'touched'
        return next
      }
    })
  )
  if (outcome !== 'raced') {
    await local.put({ ...firstSeen, lastTouchedAt: now.toISOString() })
  }
  return outcome === 'created' || outcome === 'updated' ? written : outcome
}

/**
 * Runs one {@link writeConnection} and turns the lost race it throws after
 * its last attempt into `raced`. Every other throw propagates.
 *
 * @param raced {Raced}   the outcome a lost race resolves to
 * @param write {Function}
 * @returns {Promise<object>}   the write's outcome, or `raced`
 */
async function racedAs<Outcome, Raced extends string>(
  raced: Raced,
  write: () => Promise<{ outcome: Outcome }>
): Promise<Outcome | Raced> {
  try {
    return (await write()).outcome
  } catch (err) {
    if (isLostConnectionRace(err)) {
      return raced
    }
    throw err
  }
}

/**
 * What {@link touchConnectionWriter} did.
 *
 * - `unregistered` -- no listed entry carries the writer; nothing is written.
 * - `retired` -- the writer's entry is retired; nothing is written.
 * - `fresh` -- the member was touched within the touch interval.
 * - `touched` -- the member's `lastSeen` was advanced.
 * - `refused` -- the entry cannot be written by this build.
 * - `raced` -- every attempt lost a conditional write.
 */
export type WriterTouchOutcome =
  'unregistered' | 'retired' | 'fresh' | 'touched' | 'refused' | 'raced'

/**
 * Touches a registered writer's member from a pulled revision's `writerId`:
 * the remembered session's pull path, throttled like the client's own touch.
 * The writer is found in a listing already read, so the call costs no extra
 * listing read, and a member the listing shows as fresh costs no I/O at all.
 * An unregistered `writerId` is ignored, and so is a writer on a retired
 * entry, so a replayed revision cannot keep a departed client's writer
 * alive.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.listing {ConnectionsListing}   the latest listing read
 * @param options.writerId {string}   the pulled revision's `writerId`
 * @param [options.now] {Date}
 * @param [options.policy] {Partial<ConnectionWriterPolicy>}
 * @returns {Promise<WriterTouchOutcome>}
 */
export async function touchConnectionWriter({
  store,
  hmacKey,
  listing,
  writerId,
  now = new Date(),
  policy
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  listing: ConnectionsListing
  writerId: string
  now?: Date
  policy?: Partial<ConnectionWriterPolicy>
}): Promise<WriterTouchOutcome> {
  const resolved = connectionWriterPolicy(policy)
  const found = listing.entries.find(item =>
    item.entry.writers.some(writer => writer.writerId === writerId)
  )
  if (found === undefined) {
    return 'unregistered'
  }
  // Decided from the listing first, so the common fresh member costs no read.
  const listed = memberToTouch({
    entry: found.entry,
    writerId,
    now,
    policy: resolved
  })
  if ('stop' in listed) {
    return listed.stop
  }
  const outcome = await racedAs('raced', () =>
    writeConnection<WriterTouchOutcome>({
      store,
      hmacKey,
      resourceId: found.resourceId,
      unwritable: 'refused',
      change(current) {
        if (current === undefined) {
          return { stop: 'unregistered' }
        }
        const next = memberToTouch({
          entry: current.entry,
          writerId,
          now,
          policy: resolved
        })
        if ('stop' in next) {
          return next
        }
        return {
          body: {
            ...current.body,
            writers: touchedWriters({
              writers: current.entry.writers,
              member: next.member,
              now
            })
          }
        }
      }
    })
  )
  return outcome === 'created' || outcome === 'updated' ? 'touched' : outcome
}

/**
 * The member a touch advances on an entry, or the outcome that stops the
 * touch: a retired entry, a `writerId` the entry does not carry, or a member
 * touched within the interval.
 *
 * @param options {object}
 * @param options.entry {ConnectionEntry}
 * @param options.writerId {string}
 * @param options.now {Date}
 * @param options.policy {ConnectionWriterPolicy}
 * @returns {object}
 */
function memberToTouch({
  entry,
  writerId,
  now,
  policy
}: {
  entry: ConnectionEntry
  writerId: string
  now: Date
  policy: ConnectionWriterPolicy
}): { member: ConnectionWriter } | { stop: WriterTouchOutcome } {
  if (entry.retired !== undefined) {
    return { stop: 'retired' }
  }
  const member = entry.writers.find(writer => writer.writerId === writerId)
  if (member === undefined) {
    return { stop: 'unregistered' }
  }
  if (
    now.getTime() - effectiveLastSeen({ writer: member, now }) <
    policy.touchIntervalMs
  ) {
    return { stop: 'fresh' }
  }
  return { member }
}

/**
 * The outcome of a sweep: the listing with each written entry replaced by
 * what was written, the writers it changed, and the entries whose write
 * failed for a reason other than a lost race, each with the error the store
 * raised, for the caller's log.
 */
export interface ConnectionWritersSweep {
  listing: ConnectionsListing
  markedInactive: string[]
  dropped: string[]
  failed: Array<{ resourceId: string; err: unknown }>
}

/**
 * The two-phase expiry over one entry's writers, or `undefined` when it
 * changes nothing. Past the cap, the oldest-`lastSeen` members are dropped.
 * Among the members kept, an active one past the inactivity window is marked
 * inactive.
 *
 * @param options {object}
 * @param options.entry {ConnectionEntry}
 * @param options.now {Date}
 * @param options.policy {ConnectionWriterPolicy}
 * @returns {object | undefined}
 */
function sweptWriters({
  entry,
  now,
  policy
}: {
  entry: ConnectionEntry
  now: Date
  policy: ConnectionWriterPolicy
}):
  | { writers: ConnectionWriter[]; markedInactive: string[]; dropped: string[] }
  | undefined {
  const kept = new Set(
    newestFirst({ writers: entry.writers, now }).slice(
      0,
      Math.max(policy.maxWriters, 0)
    )
  )
  const markedInactive: string[] = []
  const dropped: string[] = []
  const writers: ConnectionWriter[] = []
  for (const writer of entry.writers) {
    if (!kept.has(writer)) {
      dropped.push(writer.writerId)
      continue
    }
    const expired =
      now.getTime() - effectiveLastSeen({ writer, now }) >
      policy.inactiveAfterMs
    if (writer.active && expired) {
      markedInactive.push(writer.writerId)
      writers.push({ ...writer, active: false })
      continue
    }
    writers.push(writer)
  }
  if (markedInactive.length === 0 && dropped.length === 0) {
    return undefined
  }
  return { writers, markedInactive, dropped }
}

/**
 * Sweeps every entry of a listing already read: the per-entry two-phase
 * expiry of `writers`, run at the directory listing read on both session
 * kinds. Safe to run from any replica, and concurrently. Every write is
 * conditional on the ETag the listing read, and a lost race is skipped: the
 * entry as read still labels its revisions. Any other failed write is skipped
 * the same way and reported in `failed`, so one unreachable entry does not
 * fail the listing read the sweep rides on; the next sweep converges it. An
 * entry this build cannot write (a newer `version`), or one read without an
 * ETag, is left alone.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.listing {ConnectionsListing}
 * @param [options.now] {Date}
 * @param [options.policy] {Partial<ConnectionWriterPolicy>}
 * @returns {Promise<ConnectionWritersSweep>}
 */
export async function sweepConnectionWriters({
  store,
  listing,
  now = new Date(),
  policy
}: {
  store: ConnectionsStore
  listing: ConnectionsListing
  now?: Date
  policy?: Partial<ConnectionWriterPolicy>
}): Promise<ConnectionWritersSweep> {
  const resolved = connectionWriterPolicy(policy)
  const markedInactive: string[] = []
  const dropped: string[] = []
  const failed: Array<{ resourceId: string; err: unknown }> = []
  const entries: ReadConnection[] = []
  for (const item of listing.entries) {
    const swept = isWritableConnectionEntry(item.entry)
      ? sweptWriters({ entry: item.entry, now, policy: resolved })
      : undefined
    if (swept === undefined || item.etag === undefined) {
      entries.push(item)
      continue
    }
    const body = { ...item.body, writers: swept.writers }
    try {
      const { etag } = await store.put({
        resourceId: item.resourceId,
        body,
        ifMatch: item.etag
      })
      markedInactive.push(...swept.markedInactive)
      dropped.push(...swept.dropped)
      entries.push({
        resourceId: item.resourceId,
        ...(etag !== undefined && { etag }),
        entry: { ...item.entry, writers: swept.writers },
        body
      })
    } catch (err) {
      if (!isLostConnectionRace(err)) {
        failed.push({ resourceId: item.resourceId, err })
      }
      entries.push(item)
    }
  }
  return {
    listing: { ...listing, entries },
    markedInactive,
    dropped,
    failed
  }
}

/**
 * How a history view renders one revision's writer. `undefined` from
 * {@link resolveWriter} means no entry carries the writer: the view renders
 * its fallback label ("another session").
 */
export interface ResolvedWriter {
  /**
   * The entry's display name: the user's `label`, else its `name`, else the
   * writer member's platform label.
   */
  label: string
  active: boolean
  /**
   * Whether the writer's entry is retired.
   */
  retired: boolean
  /**
   * Present only when the entry's did:key carries a signing key the verified
   * account document lists. The view may then link the revision to that
   * client's row.
   */
  clientSigningKeyMultibase?: string
}

/**
 * Resolves a revision's `writerId` against the directory's entries.
 *
 * @param options {object}
 * @param options.writerId {string}
 * @param options.entries {ConnectionEntry[]}   the listed entries
 * @param options.enrolledSigningKeys {ReadonlySet<string>}   the signing-key
 *   multibases of the enrolled clients in the verified account document
 * @returns {ResolvedWriter | undefined}
 */
export function resolveWriter({
  writerId,
  entries,
  enrolledSigningKeys
}: {
  writerId: string
  entries: ConnectionEntry[]
  enrolledSigningKeys: ReadonlySet<string>
}): ResolvedWriter | undefined {
  for (const entry of entries) {
    const member = entry.writers.find(writer => writer.writerId === writerId)
    if (member === undefined) {
      continue
    }
    const multibase =
      entry.id === undefined
        ? undefined
        : signingKeyMultibaseOfDid({ did: entry.id })
    const linked = multibase !== undefined && enrolledSigningKeys.has(multibase)
    return {
      label: entry.label ?? entry.name ?? member.label,
      active: member.active,
      retired: entry.retired !== undefined,
      ...(linked && { clientSigningKeyMultibase: multibase })
    }
  }
  return undefined
}
