/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `connections` directory entry: its version-1 members, the `kind` and
 * `grantKind` vocabularies, the writer policy every sweeper shares, and the
 * codec every reader runs.
 *
 * The codec reads leniently. It checks the shape of every member this build
 * knows, and a body that fails that check is unparseable and skipped by
 * every listing. It ignores members it does not know, at the top level and
 * on a grant wrapper. A well-formed body whose `version` is above this
 * build's is still read, for display, from the members this build knows. The
 * writers in `upsert.ts` and `writers.ts` work on the stored body itself, so
 * every member they do not own, known or not, is written back verbatim, and
 * they refuse a body this build cannot write.
 *
 * Nothing here authenticates a body. An EDV envelope does not authenticate
 * its writer, so the storage host can plant one. The grant checks in
 * `grants.ts` bound what a planted grant can steer.
 */
import { normalizeDisplayName } from '../labelText.js'

/**
 * The entry version this build reads for writing and writes.
 */
export const CONNECTION_ENTRY_VERSION = 1

/**
 * The `kind` vocabulary: what the party says it is. An entry carrying any
 * other value reads as an unclassified party.
 */
export const CONNECTION_KINDS = [
  'app',
  'agent',
  'wallet-client',
  'contact'
] as const

/**
 * One value of {@link CONNECTION_KINDS}.
 */
export type ConnectionKind = (typeof CONNECTION_KINDS)[number]

/**
 * The `grantKind` vocabulary: `'share'` marks a grant the
 * shared-wallet-collection flow wrote, and `'grant'` is every other delegated
 * capability. A reader treats any other stored value as a plain grant.
 */
export const GRANT_KINDS = ['grant', 'share'] as const

/**
 * One value of {@link GRANT_KINDS}.
 */
export type GrantKind = (typeof GRANT_KINDS)[number]

/**
 * The delegated capability a grant wrapper stores verbatim. Only the members
 * the directory's readers take are typed. The rest of the document (its
 * proof and chain) rides along untouched, since revocation POSTs it as it
 * stands.
 */
export type ConnectionZcap = {
  id: string
  controller: string
  invocationTarget: string
  allowedAction?: string | string[]
  expires?: string
  [member: string]: unknown
}

/**
 * One member of an entry's `grants`: the capability, the kind of grant it
 * is, and when the consent that wrote it ran. `grantKind` is kept as stored,
 * so a value from a later build survives; {@link grantKindOf} reads it.
 */
export type ConnectionGrantRecord = {
  zcap: ConnectionZcap
  grantKind: string
  /**
   * ISO 8601 UTC time of the consent that wrote the grant.
   */
  grantedAt: string
  [member: string]: unknown
}

/**
 * One member of an entry's `writers`: a `writerId` the party has written
 * under, with the platform label it registered with and its liveness state.
 */
export type ConnectionWriter = {
  writerId: string
  label: string
  /**
   * ISO 8601 UTC time of the writer's latest liveness touch.
   */
  lastSeen: string
  /**
   * `false` once a sweep found `lastSeen` past the inactivity window. The
   * writer's next touch sets it back to `true`.
   */
  active: boolean
  [member: string]: unknown
}

/**
 * A directory entry as the codec reads it: the members this build knows.
 * `version` is any positive integer the body carried; only
 * {@link CONNECTION_ENTRY_VERSION} is writable here
 * ({@link isWritableConnectionEntry}). `kind` is kept as stored;
 * {@link connectionKindOf} reads it. `name` is the normalized form of the
 * stored member.
 */
export type ConnectionEntry = {
  version: number
  kind: string
  /**
   * The party's DID. Absent only on a keyless writer entry, which then
   * carries exactly one member in `writers`.
   */
  id?: string
  /**
   * The party's latest self-declared name.
   */
  name?: string
  /**
   * The user's own name for the party.
   */
  label?: string
  /**
   * The attested Web origin, for an App Connect app.
   */
  origin?: string
  /**
   * The canonical app URL, for an App Connect app.
   */
  url?: string
  /**
   * The app-key Resource id in the app-key collection, present only while
   * the wallet holds the key it minted.
   */
  appKey?: string
  firstSeen: string
  lastSeen: string
  /**
   * ISO 8601 UTC time the relationship ended. Present once retired.
   */
  retired?: string
  grants: ConnectionGrantRecord[]
  writers: ConnectionWriter[]
}

const DAY_MS = 24 * 60 * 60 * 1000

/**
 * The writer policy every wallet that sweeps must share, or two sweepers
 * disagree about which writer members are inactive or over the cap.
 */
export interface ConnectionWriterPolicy {
  /**
   * How long a writer member may go untouched before a sweep marks it
   * inactive.
   */
  inactiveAfterMs: number
  /**
   * The most writer members one entry holds. A sweep, or a registration
   * making room, drops the oldest-`lastSeen` members beyond it.
   */
  maxWriters: number
  /**
   * The least time between two liveness touches of the same writer member.
   */
  touchIntervalMs: number
}

/**
 * The writer policy: inactive after 90 days, at most 8 writers per entry,
 * touched at most once a day.
 */
export const CONNECTION_WRITER_POLICY: ConnectionWriterPolicy = {
  inactiveAfterMs: 90 * DAY_MS,
  maxWriters: 8,
  touchIntervalMs: DAY_MS
}

/**
 * Resolves a partial policy override against the defaults. A test may
 * override; every replica sweeping one account must use the same values.
 *
 * @param [policy] {Partial<ConnectionWriterPolicy>}
 * @returns {ConnectionWriterPolicy}
 */
export function connectionWriterPolicy(
  policy?: Partial<ConnectionWriterPolicy>
): ConnectionWriterPolicy {
  return { ...CONNECTION_WRITER_POLICY, ...policy }
}

/**
 * An entry's `kind` as one of {@link CONNECTION_KINDS}, or `undefined` for an
 * unclassified party.
 *
 * @param entry {ConnectionEntry}
 * @returns {ConnectionKind | undefined}
 */
export function connectionKindOf(
  entry: ConnectionEntry
): ConnectionKind | undefined {
  return (CONNECTION_KINDS as readonly string[]).includes(entry.kind)
    ? (entry.kind as ConnectionKind)
    : undefined
}

/**
 * A grant's `grantKind` as one of {@link GRANT_KINDS}: `'share'` only when
 * stored so, and `'grant'` for every other value.
 *
 * @param grant {ConnectionGrantRecord}
 * @returns {GrantKind}
 */
export function grantKindOf(grant: ConnectionGrantRecord): GrantKind {
  return grant.grantKind === 'share' ? 'share' : 'grant'
}

/**
 * A fresh entry's body as this build creates it: this build's `version`, the
 * party's `kind` and DID, both timestamps at `now`, and no grants or writers.
 * Every create spreads its own members over this, so the entry shape has one
 * write site beside the codec.
 *
 * @param options {object}
 * @param options.kind {ConnectionKind}
 * @param options.did {string}
 * @param options.now {Date}
 * @returns {Record<string, unknown>}
 */
export function newConnectionEntry({
  kind,
  did,
  now
}: {
  kind: ConnectionKind
  did: string
  now: Date
}): Record<string, unknown> {
  const stamp = now.toISOString()
  return {
    version: CONNECTION_ENTRY_VERSION,
    kind,
    id: did,
    firstSeen: stamp,
    lastSeen: stamp,
    grants: [],
    writers: []
  }
}

/**
 * Whether this build may write over the entry: its `version` is this
 * build's. A body from a newer build is read for display only.
 *
 * @param entry {ConnectionEntry}
 * @returns {boolean}
 */
export function isWritableConnectionEntry(entry: ConnectionEntry): boolean {
  return entry.version === CONNECTION_ENTRY_VERSION
}

/**
 * Whether a value is a plain JSON object (not null, not an array).
 *
 * @param value {unknown}
 * @returns {boolean}
 */
export function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/**
 * Whether a value is a string `Date.parse` reads as a time.
 *
 * @param value {unknown}
 * @returns {boolean}
 */
function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value))
}

/**
 * Whether a value is absent or a string.
 *
 * @param value {unknown}
 * @returns {boolean}
 */
function isOptionalString(value: unknown): value is string | undefined {
  return value === undefined || typeof value === 'string'
}

/**
 * Reads a stored capability's known members, or `undefined` when one of them
 * has the wrong shape. The capability itself is returned verbatim.
 *
 * @param value {unknown}
 * @returns {ConnectionZcap | undefined}
 */
export function parseConnectionZcap(
  value: unknown
): ConnectionZcap | undefined {
  if (!isJsonObject(value)) {
    return undefined
  }
  const { id, controller, invocationTarget, allowedAction, expires } = value
  if (
    typeof id !== 'string' ||
    id === '' ||
    typeof controller !== 'string' ||
    typeof invocationTarget !== 'string' ||
    (allowedAction !== undefined &&
      typeof allowedAction !== 'string' &&
      !(
        Array.isArray(allowedAction) &&
        allowedAction.every(action => typeof action === 'string')
      )) ||
    (expires !== undefined && !isTimestamp(expires))
  ) {
    return undefined
  }
  return value as ConnectionZcap
}

/**
 * Reads one stored grant wrapper, or `undefined` when a known member has the
 * wrong shape. The wrapper is returned verbatim, unknown members included.
 *
 * @param value {unknown}
 * @returns {ConnectionGrantRecord | undefined}
 */
function parseGrantRecord(value: unknown): ConnectionGrantRecord | undefined {
  if (!isJsonObject(value)) {
    return undefined
  }
  if (
    parseConnectionZcap(value.zcap) === undefined ||
    typeof value.grantKind !== 'string' ||
    !isTimestamp(value.grantedAt)
  ) {
    return undefined
  }
  return value as ConnectionGrantRecord
}

/**
 * Reads one stored writer member, or `undefined` when a known member has the
 * wrong shape. The member is returned verbatim, unknown members included.
 *
 * @param value {unknown}
 * @returns {ConnectionWriter | undefined}
 */
function parseWriter(value: unknown): ConnectionWriter | undefined {
  if (!isJsonObject(value)) {
    return undefined
  }
  if (
    typeof value.writerId !== 'string' ||
    value.writerId === '' ||
    typeof value.label !== 'string' ||
    !isTimestamp(value.lastSeen) ||
    typeof value.active !== 'boolean'
  ) {
    return undefined
  }
  const label = normalizeDisplayName({ value: value.label })
  if (label === undefined) {
    return undefined
  }
  return { ...value, label } as ConnectionWriter
}

/**
 * Reads a stored body as a directory entry, or `undefined` when it is not
 * one. A body fails when any member this build knows has the wrong shape:
 * a `version` that is not a positive integer, an empty `kind`, an `id` that
 * is not a DID, a `name`, `label`, or writer `label` outside the display-name
 * rule (1 to 64 code points once the control and bidi characters are stripped
 * and the result trimmed), a timestamp `Date.parse` cannot read, a malformed
 * grant wrapper or writer member, or no `id` beside anything but exactly one
 * writer. Every display string a view renders is held to that one rule.
 * Unknown members are ignored. A body with a `version` above this build's
 * that passes every check is returned for display;
 * {@link isWritableConnectionEntry} says it cannot be written.
 *
 * Where the body sits is not checked here. A reader also checks that the
 * body sits at the resource id its own `id` (or its one writer) derives to
 * (`read.ts`).
 *
 * @param body {unknown}
 * @returns {ConnectionEntry | undefined}
 */
export function parseConnectionEntry(
  body: unknown
): ConnectionEntry | undefined {
  if (!isJsonObject(body)) {
    return undefined
  }
  const {
    version,
    kind,
    id,
    name,
    label,
    origin,
    url,
    appKey,
    firstSeen,
    lastSeen,
    retired,
    grants,
    writers
  } = body
  if (
    typeof version !== 'number' ||
    !Number.isInteger(version) ||
    version < 1 ||
    typeof kind !== 'string' ||
    kind === '' ||
    (id !== undefined && (typeof id !== 'string' || !id.startsWith('did:'))) ||
    !isOptionalString(name) ||
    !isOptionalString(label) ||
    !isOptionalString(origin) ||
    !isOptionalString(url) ||
    (appKey !== undefined && (typeof appKey !== 'string' || appKey === '')) ||
    !isTimestamp(firstSeen) ||
    !isTimestamp(lastSeen) ||
    (retired !== undefined && !isTimestamp(retired)) ||
    !Array.isArray(grants) ||
    !Array.isArray(writers)
  ) {
    return undefined
  }
  const normalizedName =
    name === undefined ? undefined : normalizeDisplayName({ value: name })
  const normalizedLabel =
    label === undefined ? undefined : normalizeDisplayName({ value: label })
  if (
    (name !== undefined && normalizedName === undefined) ||
    (label !== undefined && normalizedLabel === undefined)
  ) {
    return undefined
  }
  const parsedGrants = grants.map(parseGrantRecord)
  const parsedWriters = writers.map(parseWriter)
  if (
    parsedGrants.some(grant => grant === undefined) ||
    parsedWriters.some(writer => writer === undefined)
  ) {
    return undefined
  }
  if (id === undefined && parsedWriters.length !== 1) {
    return undefined
  }
  return {
    version,
    kind,
    ...(id !== undefined && { id }),
    ...(normalizedName !== undefined && { name: normalizedName }),
    ...(normalizedLabel !== undefined && { label: normalizedLabel }),
    ...(origin !== undefined && { origin }),
    ...(url !== undefined && { url }),
    ...(appKey !== undefined && { appKey }),
    firstSeen,
    lastSeen,
    ...(retired !== undefined && { retired }),
    grants: parsedGrants as ConnectionGrantRecord[],
    writers: parsedWriters as ConnectionWriter[]
  }
}
