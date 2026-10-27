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
import { base64urlnopad } from '@scure/base'
import { isJsonObject } from '../jsonObject.js'
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
  'contact',
  'replica-server'
] as const

/**
 * The one kind whose entry carries a non-empty `replicas` list.
 */
export const REPLICA_SERVER_KIND = 'replica-server' as const

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
 * The `grantKind` vocabulary of `grantsReceived`, the capabilities a party
 * handed the wallet: `'inbox'` is the party's POST capability on its own
 * inbox, the channel a push goes through. An unknown stored value is kept as
 * stored.
 */
export const RECEIVED_GRANT_KINDS = ['inbox'] as const

/**
 * One value of {@link RECEIVED_GRANT_KINDS}.
 */
export type ReceivedGrantKind = (typeof RECEIVED_GRANT_KINDS)[number]

/**
 * The byte length of the pairwise seed, and the length of its base64url
 * no-pad text.
 */
export const CONNECTION_SEED_BYTES = 32
const CONNECTION_SEED_TEXT_LENGTH = 43

/**
 * The delegated capability a grant wrapper stores verbatim. Only the members
 * the directory's readers take are typed. The rest of the document (its
 * proof and chain) rides along untouched, since revocation POSTs it as it
 * stands. `expires` is required: a capability with no expiry is not a grant
 * the directory records.
 */
export type ConnectionZcap = {
  id: string
  controller: string
  invocationTarget: string
  allowedAction?: string | string[]
  expires: string
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
   * ISO 8601 UTC time of the consent that wrote the grant. A renewed record
   * keeps the consent's time.
   */
  grantedAt: string
  /**
   * ISO 8601 UTC time of the renewal that minted this record, present on a
   * record `recordRenewedGrants` wrote.
   */
  renewedAt?: string
  [member: string]: unknown
}

/**
 * One member of an entry's `grantsReceived`: a capability the party handed
 * the wallet, verbatim, the kind of grant it is, and when it was stored.
 * `grantKind` is kept as stored.
 */
export type ConnectionReceivedGrantRecord = {
  zcap: ConnectionZcap
  grantKind: string
  /**
   * ISO 8601 UTC time the record was stored.
   */
  receivedAt: string
  [member: string]: unknown
}

/**
 * One member of an entry's `outbox`: a pending envelope to the party,
 * verbatim, and the time it was queued. The item names no channel; a push
 * resolves the channel from `grantsReceived` at push time.
 */
export type ConnectionOutboxItem = {
  message: Record<string, unknown>
  /**
   * ISO 8601 UTC time the item was queued.
   */
  createdAt: string
  [member: string]: unknown
}

/**
 * One member of a `replica-server` entry's `replicas`: one replica Space on
 * that replica server, with its source Space, its registration ids, and the
 * user's outstanding intents toward it. Each marker is written by one intent
 * and cleared by its completion; no unset marker reads as an intent.
 */
export type ConnectionReplica = {
  /**
   * The source Space's container URL, with its trailing slash, as the
   * registration body carries it.
   */
  fromSpace: string
  /**
   * The replica Space's id on the replica server: 32 random bytes, base64url
   * with no padding, distinct from the source Space's id.
   */
  spaceId: string
  /**
   * The id of the item's registration, present once its first registration
   * landed. An in-place replacement of the registration's capability keeps
   * it.
   */
  registrationId?: string
  /**
   * A first registration's id, present between its mint and the landing of
   * its POST, then moved to `registrationId`.
   */
  pendingRegistrationId?: string
  /**
   * The registration's collection list, not empty when present. Absent when
   * the replica server copies every live Collection.
   */
  collections?: string[]
  /**
   * ISO 8601 UTC time of the user's Stop. Marks a stopped snapshot until a
   * completed re-start clears it.
   */
  stoppedAt?: string
  /**
   * ISO 8601 UTC time of the user's re-start, written first and cleared
   * last.
   */
  restartedAt?: string
  /**
   * ISO 8601 UTC time the replica Space read absent under the account's own
   * authority.
   */
  lostAt?: string
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
   * The canonical app URL, for an App Connect app, or the base URL of a
   * replica server.
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
  /**
   * ISO 8601 UTC time the owner declined this party's offer. Present while
   * the decline stands; a fresh consent clears it.
   */
  declined?: string
  /**
   * The wallet's pairwise seed toward this party: 32 random bytes, base64url
   * with no padding. Written once, and always beside `seedTag`.
   */
  seed?: string
  /**
   * The tag over `seed` under the directory's blinded-index key
   * (`connectionSeedTag`), base64url with no padding. A site that turns the
   * seed into a key verifies it first.
   */
  seedTag?: string
  grants: ConnectionGrantRecord[]
  /**
   * The capabilities the party handed the wallet. Absent on a body an older
   * build wrote, which reads as empty.
   */
  grantsReceived: ConnectionReceivedGrantRecord[]
  /**
   * The pending envelopes to the party. Absent on a body an older build
   * wrote, which reads as empty.
   */
  outbox: ConnectionOutboxItem[]
  writers: ConnectionWriter[]
  /**
   * The replica Spaces on a `replica-server` entry's server. Empty on every
   * other kind, where a non-empty list fails the codec, and absent on a body
   * an older build wrote, which reads as empty.
   */
  replicas: ConnectionReplica[]
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
    grantsReceived: [],
    outbox: [],
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
 * has the wrong shape or `expires` is absent. The capability itself is
 * returned verbatim.
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
    !isTimestamp(expires)
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
    !isTimestamp(value.grantedAt) ||
    (value.renewedAt !== undefined && !isTimestamp(value.renewedAt))
  ) {
    return undefined
  }
  return value as ConnectionGrantRecord
}

/**
 * Reads one stored received-grant wrapper, or `undefined` when a known
 * member has the wrong shape. The wrapper is returned verbatim, unknown
 * members included.
 *
 * @param value {unknown}
 * @returns {ConnectionReceivedGrantRecord | undefined}
 */
function parseReceivedGrantRecord(
  value: unknown
): ConnectionReceivedGrantRecord | undefined {
  if (!isJsonObject(value)) {
    return undefined
  }
  if (
    parseConnectionZcap(value.zcap) === undefined ||
    typeof value.grantKind !== 'string' ||
    !isTimestamp(value.receivedAt)
  ) {
    return undefined
  }
  return value as ConnectionReceivedGrantRecord
}

/**
 * Reads one stored outbox item, or `undefined` when a known member has the
 * wrong shape: `message` must be a JSON object and `createdAt` a timestamp.
 * The item is returned verbatim.
 *
 * @param value {unknown}
 * @returns {ConnectionOutboxItem | undefined}
 */
function parseOutboxItem(value: unknown): ConnectionOutboxItem | undefined {
  if (!isJsonObject(value)) {
    return undefined
  }
  if (!isJsonObject(value.message) || !isTimestamp(value.createdAt)) {
    return undefined
  }
  return value as ConnectionOutboxItem
}

/**
 * The seed bytes a stored `seed` member decodes to, or `undefined` when it
 * is not 43 characters of base64url with no padding decoding to 32 bytes.
 * The same rule reads a stored `seedTag`, which has the same length.
 *
 * @param value {unknown}
 * @returns {Uint8Array | undefined}
 */
export function decodeConnectionSeed(value: unknown): Uint8Array | undefined {
  if (
    typeof value !== 'string' ||
    value.length !== CONNECTION_SEED_TEXT_LENGTH
  ) {
    return undefined
  }
  let bytes: Uint8Array
  try {
    bytes = base64urlnopad.decode(value)
  } catch {
    return undefined
  }
  return bytes.length === CONNECTION_SEED_BYTES ? bytes : undefined
}

/**
 * Whether a value is a Space's container URL: an absolute URL ending with a
 * slash. The one rule the codec, the replica-server helpers, and the grant
 * target check share.
 *
 * @param value {unknown}
 * @returns {boolean}
 */
export function isSpaceContainerUrl(value: unknown): value is string {
  if (typeof value !== 'string' || !value.endsWith('/')) {
    return false
  }
  try {
    new URL(value)
    return true
  } catch {
    return false
  }
}

/**
 * A Space's container URL in the one form the directory stores and compares
 * it in: URL-parsed and re-serialized, so a default port or an upper-case
 * host names the same Space as its plain form. Refuses a value that is not
 * a container URL ({@link isSpaceContainerUrl}) with a `TypeError`.
 *
 * @param value {string}
 * @returns {string}
 */
export function spaceContainerUrl(value: string): string {
  if (!isSpaceContainerUrl(value)) {
    throw new TypeError(
      `A Space container URL is an absolute URL ending with a slash; got ` +
        `"${value}".`
    )
  }
  return new URL(value).href
}

/**
 * Whether a value is a fresh id as the directory stores one: 43 characters
 * of base64url with no padding decoding to 32 bytes (a replica Space id, a
 * registration id).
 *
 * @param value {unknown}
 * @returns {boolean}
 */
export function isConnectionFreshId(value: unknown): value is string {
  return decodeConnectionSeed(value) !== undefined
}

/**
 * Reads one stored replica item, or `undefined` when a known member has the
 * wrong shape: `fromSpace` must be a container URL, `spaceId` and each
 * registration id a fresh id, `collections` a non-empty list of non-empty
 * strings (an absent list means every live Collection, so an empty one has
 * no reading), and each marker a timestamp. The item is returned verbatim, unknown members
 * included.
 *
 * @param value {unknown}
 * @returns {ConnectionReplica | undefined}
 */
function parseReplica(value: unknown): ConnectionReplica | undefined {
  if (!isJsonObject(value)) {
    return undefined
  }
  const {
    fromSpace,
    spaceId,
    registrationId,
    pendingRegistrationId,
    collections,
    stoppedAt,
    restartedAt,
    lostAt
  } = value
  if (
    !isSpaceContainerUrl(fromSpace) ||
    !isConnectionFreshId(spaceId) ||
    (registrationId !== undefined && !isConnectionFreshId(registrationId)) ||
    (pendingRegistrationId !== undefined &&
      !isConnectionFreshId(pendingRegistrationId)) ||
    (collections !== undefined &&
      !(
        Array.isArray(collections) &&
        collections.length > 0 &&
        collections.every(
          collection => typeof collection === 'string' && collection !== ''
        )
      )) ||
    (stoppedAt !== undefined && !isTimestamp(stoppedAt)) ||
    (restartedAt !== undefined && !isTimestamp(restartedAt)) ||
    (lostAt !== undefined && !isTimestamp(lostAt))
  ) {
    return undefined
  }
  return value as ConnectionReplica
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
 * grant wrapper, received-grant wrapper, outbox item, replica item, or writer
 * member, a non-empty `replicas` list on an entry whose `kind` is not
 * `'replica-server'`, a `seed` or `seedTag` that is not 43 characters of
 * base64url decoding to 32 bytes, a `seed` with no `seedTag` (or the
 * reverse), or no `id` beside anything but exactly one writer. Every display string a view renders is
 * held to that one rule. An absent `grantsReceived`, `outbox`, or `replicas`
 * (a body an older build wrote, or an entry of a kind that carries none)
 * reads as empty. Unknown members are ignored. A body with a `version` above
 * this build's that passes every check is returned for display;
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
    declined,
    seed,
    seedTag,
    grants,
    grantsReceived,
    outbox,
    writers,
    replicas
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
    (declined !== undefined && !isTimestamp(declined)) ||
    (seed !== undefined && decodeConnectionSeed(seed) === undefined) ||
    (seedTag !== undefined && decodeConnectionSeed(seedTag) === undefined) ||
    (seed === undefined) !== (seedTag === undefined) ||
    !Array.isArray(grants) ||
    (grantsReceived !== undefined && !Array.isArray(grantsReceived)) ||
    (outbox !== undefined && !Array.isArray(outbox)) ||
    !Array.isArray(writers) ||
    (replicas !== undefined &&
      (!Array.isArray(replicas) ||
        (replicas.length > 0 && kind !== REPLICA_SERVER_KIND)))
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
  const parsedReceived = (grantsReceived ?? []).map(parseReceivedGrantRecord)
  const parsedOutbox = (outbox ?? []).map(parseOutboxItem)
  const parsedWriters = writers.map(parseWriter)
  const parsedReplicas = (replicas ?? []).map(parseReplica)
  if (
    parsedGrants.some(grant => grant === undefined) ||
    parsedReceived.some(grant => grant === undefined) ||
    parsedOutbox.some(item => item === undefined) ||
    parsedWriters.some(writer => writer === undefined) ||
    parsedReplicas.some(item => item === undefined)
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
    ...(declined !== undefined && { declined }),
    ...(seed !== undefined && { seed: seed as string }),
    ...(seedTag !== undefined && { seedTag: seedTag as string }),
    grants: parsedGrants as ConnectionGrantRecord[],
    grantsReceived: parsedReceived as ConnectionReceivedGrantRecord[],
    outbox: parsedOutbox as ConnectionOutboxItem[],
    writers: parsedWriters as ConnectionWriter[],
    replicas: parsedReplicas as ConnectionReplica[]
  }
}
