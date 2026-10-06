/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */

/**
 * A capability to record, read by the codec, or a `TypeError` naming the
 * write when it lacks an id, a controller, or an invocation target.
 *
 * @param options {object}
 * @param options.value {object}
 * @param options.what {string}   the write's name, for the message
 * @returns {ConnectionZcap}
 */
function requiredConnectionZcap({
  value,
  what
}: {
  value: object
  what: string
}): ConnectionZcap {
  const zcap = parseConnectionZcap(value)
  if (zcap === undefined) {
    throw new TypeError(
      `A ${what} must carry a capability with an id, a controller, and an ` +
        'invocation target.'
    )
  }
  return zcap
}
/**
 * The upsert helpers every flow writes a party's entry through:
 * `recordGrants` at consent, `removeGrants` at an unshare or a torn
 * consent's rollback, `retireConnection` when a relationship ends,
 * `unretireConnection` when one resumes without a consent,
 * `setConnectionLabel` for the user's rename and the enrollment-time name,
 * and the agent-connection helpers over `grantsReceived` and `outbox`:
 * `recordReceivedGrants`, `recordRenewedGrants` (the renewal's one write),
 * `settleOutboxItem`, `pruneSupersededGrants`, `clearReceivedGrants`, and
 * `markDeclined`.
 *
 * Each runs `writeConnection`, the one bounded compare-and-swap loop at a
 * party's resource id, which the writer arm (`writers.ts`) runs too. It reads
 * the entry, applies its change to the stored body, and writes under
 * `ifMatch` (or creates under `ifNoneMatch`). A lost race re-reads and
 * re-applies, up to three attempts, after which the last
 * `PreconditionFailedError` is thrown. A helper changes only the members it
 * owns, so a member a newer build added, on the entry or on a grant wrapper,
 * is written back verbatim. A helper that finds a body it cannot parse, one
 * whose `version` is above this build's, or one that does not belong at the
 * id refuses to write, rather than treating the body as absent: overwriting
 * it would wipe a newer build's grants.
 */
import { NotSupportedError } from '@interop/was-client'
import { errorNameOf } from '../errorName.js'
import { normalizeDisplayName } from '../labelText.js'
import { REVOCATION_CLOCK_SKEW_MS } from '../webvh/index.js'
import { signingKeyMultibaseOfDid } from './didKey.js'
import {
  CONNECTION_ENTRY_VERSION,
  GRANT_KINDS,
  RECEIVED_GRANT_KINDS,
  isJsonObject,
  isWritableConnectionEntry,
  newConnectionEntry,
  parseConnectionEntry,
  parseConnectionZcap
} from './entry.js'
import type {
  ConnectionEntry,
  ConnectionGrantRecord,
  ConnectionKind,
  ConnectionOutboxItem,
  ConnectionReceivedGrantRecord,
  ConnectionZcap,
  GrantKind,
  ReceivedGrantKind
} from './entry.js'
import { ConnectionKindMismatchError } from './errors.js'
import {
  allowsAction,
  connectionGrants,
  grantScopeKey,
  latestIndexPerScope,
  isTargetInSpace,
  liveInboxChannel,
  receivedGrantLapsed,
  receivedGrants
} from './grants.js'
import { claimedResourceId } from './read.js'
import { connectionResourceId, verifyConnectionSeedTag } from './resourceId.js'
import type { ConnectionIdKey } from './resourceId.js'
import type { ConnectionsStore } from './store.js'

const PRECONDITION_FAILED_ERROR_NAME = 'PreconditionFailedError'
const WRITE_ATTEMPTS = 3
const STRICT_ISO_8601 =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/

/**
 * What one helper call did at the party's id.
 *
 * - `created` -- no entry stood there, and one was written.
 * - `updated` -- the entry was rewritten.
 * - `unchanged` -- the entry already said what the helper would write.
 * - `absent` -- no entry stood there, and the helper creates none.
 */
export type ConnectionWriteOutcome =
  'created' | 'updated' | 'unchanged' | 'absent'

/**
 * A helper's result: where it wrote, and what it did there.
 */
export interface ConnectionWriteResult {
  resourceId: string
  outcome: ConnectionWriteOutcome
}

/**
 * An entry a helper may write over: the members the codec read, and the
 * stored body the write starts from.
 */
export interface WritableConnection {
  entry: ConnectionEntry
  body: Record<string, unknown>
  etag?: string
}

/**
 * Whether a store write lost a race. Matched by name, since the store is an
 * injected seam that may raise from a second copy of was-client.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
export function isLostConnectionRace(err: unknown): boolean {
  return errorNameOf(err) === PRECONDITION_FAILED_ERROR_NAME
}

/**
 * The ETag a write over an existing resource pins to. A read that carried
 * none would send the write unconditionally, so it is refused instead.
 *
 * @param options {object}
 * @param options.resourceId {string}
 * @param [options.etag] {string}
 * @returns {string}
 */
function requireConnectionEtag({
  resourceId,
  etag
}: {
  resourceId: string
  etag?: string
}): string {
  if (etag === undefined) {
    throw new NotSupportedError(
      `Cannot update connections entry "${resourceId}": its read returned ` +
        'no ETag, so the write would go out unconditionally. A browser ' +
        "client needs `ETag` in the server's `Access-Control-Expose-Headers`."
    )
  }
  return etag
}

/**
 * Reads a stored body as an entry this build may write over, or throws. The
 * body must sit at the id its own members derive to, parse, and carry this
 * build's `version`.
 *
 * @param options {object}
 * @param options.resourceId {string}
 * @param options.stored {object}   the store's `get` result
 * @param options.hmacKey {ConnectionIdKey}
 * @returns {Promise<WritableConnection>}
 */
async function writableConnection({
  resourceId,
  stored,
  hmacKey
}: {
  resourceId: string
  stored: { body: unknown; etag?: string }
  hmacKey: ConnectionIdKey
}): Promise<WritableConnection> {
  const claimed = await claimedResourceId({ body: stored.body, hmacKey })
  const entry = parseConnectionEntry(stored.body)
  if (claimed !== resourceId || entry === undefined) {
    throw new Error(
      `The connections entry at "${resourceId}" cannot be parsed as the ` +
        'entry for this id; this build refuses to write over it.'
    )
  }
  if (!isWritableConnectionEntry(entry)) {
    throw new Error(
      `The connections entry at "${resourceId}" carries version ` +
        `${entry.version}, newer than this build's ` +
        `${CONNECTION_ENTRY_VERSION}; this build refuses to write over it.`
    )
  }
  return {
    entry,
    body: stored.body as Record<string, unknown>,
    ...(stored.etag !== undefined && { etag: stored.etag })
  }
}

/**
 * What a `change` callback asks {@link writeConnection} to do on one
 * attempt: write `body` at the id, or stop with the given outcome and write
 * nothing.
 */
export type ConnectionChange<Stop> =
  { body: Record<string, unknown> } | { stop: Stop }

/**
 * The bounded compare-and-swap loop every directory write runs at one
 * resource id: the upsert helpers here and the writer arm in `writers.ts`.
 * Each attempt reads the resource, hands `change` the writable entry (or
 * `undefined` when none stands), and writes the body it returns under
 * `ifMatch` (or creates it under `ifNoneMatch`). A `stop` ends the loop with
 * that outcome and no write. A lost race re-reads and re-applies, and after
 * the last attempt the last `PreconditionFailedError` is thrown. `change`
 * may throw a refusal, which ends the loop the same way.
 *
 * A stored body this build cannot write over (unparseable, misplaced, or
 * from a newer build) throws, unless `unwritable` names the outcome to
 * resolve with instead.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.resourceId {string}
 * @param options.change {Function}
 * @param [options.unwritable] {Stop}   the outcome for a body this build
 *   cannot write over; omitted, such a body throws
 * @returns {Promise<object>}   the id and the outcome: `created`, `updated`,
 *   or the `stop` the callback returned
 */
export async function writeConnection<Stop>({
  store,
  hmacKey,
  resourceId,
  change,
  unwritable
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  resourceId: string
  change: (current: WritableConnection | undefined) => ConnectionChange<Stop>
  unwritable?: Stop
}): Promise<{ resourceId: string; outcome: 'created' | 'updated' | Stop }> {
  let lastRace: unknown
  for (let attempt = 0; attempt < WRITE_ATTEMPTS; attempt++) {
    const stored = await store.get({ resourceId })
    let current: WritableConnection | undefined
    if (stored !== undefined) {
      try {
        current = await writableConnection({ resourceId, stored, hmacKey })
      } catch (err) {
        if (unwritable === undefined) {
          throw err
        }
        return { resourceId, outcome: unwritable }
      }
    }
    const next = change(current)
    if ('stop' in next) {
      return { resourceId, outcome: next.stop }
    }
    try {
      if (current === undefined) {
        await store.put({ resourceId, body: next.body, ifNoneMatch: true })
        return { resourceId, outcome: 'created' }
      }
      await store.put({
        resourceId,
        body: next.body,
        ifMatch: requireConnectionEtag({ resourceId, etag: current.etag })
      })
      return { resourceId, outcome: 'updated' }
    } catch (err) {
      if (!isLostConnectionRace(err)) {
        throw err
      }
      lastRace = err
    }
  }
  throw lastRace
}

/**
 * {@link writeConnection} for the helpers here, keyed by the party's DID. A
 * helper with nothing to write stops with `absent` (no entry at the id) or
 * `unchanged`.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the party's DID
 * @param options.change {Function}
 * @returns {Promise<ConnectionWriteResult>}
 */
async function writePartyConnection({
  store,
  hmacKey,
  did,
  change
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  change: (
    current: WritableConnection | undefined
  ) => ConnectionChange<'absent' | 'unchanged'>
}): Promise<ConnectionWriteResult> {
  return writeConnection({
    store,
    hmacKey,
    resourceId: await connectionResourceId({ hmacKey, did }),
    change
  })
}

/**
 * Refuses a stored entry of another kind than the writing flow's.
 *
 * @param options {object}
 * @param options.entry {ConnectionEntry}
 * @param options.kind {string}
 */
function assertKind({
  entry,
  kind
}: {
  entry: ConnectionEntry
  kind: string
}): void {
  if (entry.kind !== kind) {
    throw new ConnectionKindMismatchError({
      expectedKind: kind,
      foundKind: entry.kind
    })
  }
}

/**
 * A capability the wallet delegated, checked strictly: its known members
 * well-formed, its `controller` the party's DID, its `invocationTarget`
 * under this Space. The target check is the same one every reader applies,
 * so a grant that is stored is a grant the revocation index will see.
 *
 * @param options {object}
 * @param options.did {string}
 * @param options.spaceUrl {string}
 * @param options.zcap {object}
 * @returns {ConnectionZcap}
 */
function checkedDelegatedZcap({
  did,
  spaceUrl,
  zcap: value
}: {
  did: string
  spaceUrl: string
  zcap: object
}): ConnectionZcap {
  const zcap = requiredConnectionZcap({ value, what: 'grant to record' })
  if (zcap.controller !== did) {
    throw new TypeError(
      `A grant to record must be delegated to the party "${did}"; its ` +
        `controller is "${zcap.controller}".`
    )
  }
  if (!isTargetInSpace({ target: zcap.invocationTarget, spaceUrl })) {
    throw new TypeError(
      'A grant to record must target this Space; its invocation target is ' +
        `"${zcap.invocationTarget}".`
    )
  }
  return zcap
}

/**
 * The capability of one grant to record: {@link checkedDelegatedZcap}, and
 * its kind one this build writes.
 *
 * @param options {object}
 * @param options.did {string}
 * @param options.spaceUrl {string}
 * @param options.grant {object}
 * @returns {ConnectionZcap}
 */
function checkedGrant({
  did,
  spaceUrl,
  grant
}: {
  did: string
  spaceUrl: string
  grant: { zcap: object; grantKind: GrantKind }
}): ConnectionZcap {
  const zcap = checkedDelegatedZcap({ did, spaceUrl, zcap: grant.zcap })
  if (!(GRANT_KINDS as readonly string[]).includes(grant.grantKind)) {
    throw new TypeError(`Unknown grant kind "${grant.grantKind}".`)
  }
  return zcap
}

/**
 * A capability's `expires` as epoch milliseconds. The codec has already
 * checked the member is present and parses.
 *
 * @param zcap {ConnectionZcap}
 * @returns {number}
 */
function expiresAtOf(zcap: ConnectionZcap): number {
  return Date.parse(zcap.expires)
}

/**
 * Whether a capability's `expires` is past by more than the revocation clock
 * skew.
 *
 * @param options {object}
 * @param options.zcap {ConnectionZcap}
 * @param options.now {Date}
 * @returns {boolean}
 */
function expiredBeyondSkew({
  zcap,
  now
}: {
  zcap: ConnectionZcap
  now: Date
}): boolean {
  return expiresAtOf(zcap) + REVOCATION_CLOCK_SKEW_MS <= now.getTime()
}

/**
 * The index of the latest record in each scope of a list of grant records
 * ({@link latestIndexPerScope} over their capabilities).
 *
 * @param options {object}
 * @param options.grants {ConnectionGrantRecord[]}
 * @returns {Map<string, number>}   scope key to the latest record's index
 */
function latestPerScope({
  grants
}: {
  grants: ConnectionGrantRecord[]
}): Map<string, number> {
  return latestIndexPerScope({ zcaps: grants.map(grant => grant.zcap) })
}

/**
 * The capabilities an envelope carries (`message.object.zcaps`), or
 * `undefined` when it carries no such list.
 *
 * @param message {object}   the envelope, verbatim
 * @returns {unknown[] | undefined}
 */
function envelopeZcaps(
  message: Record<string, unknown>
): unknown[] | undefined {
  const { object } = message
  if (!isJsonObject(object) || !Array.isArray(object.zcaps)) {
    return undefined
  }
  return object.zcaps
}

/**
 * Checks an envelope a write queues beside the records it carries: its
 * `object.zcaps` must be a non-empty list whose zcap ids are exactly
 * `zcapIds`, so a reused message cannot queue a capability the write does
 * not record. Refuses with a `TypeError`.
 *
 * @param options {object}
 * @param options.message {object}   the envelope, verbatim
 * @param options.zcapIds {Iterable<string>}   the ids the write records
 * @param options.what {string}   the write's name, for the message
 */
function assertEnvelopeCarries({
  message,
  zcapIds,
  what
}: {
  message: Record<string, unknown>
  zcapIds: Iterable<string>
  what: string
}): void {
  const zcaps = envelopeZcaps(message)
  if (zcaps === undefined || zcaps.length === 0) {
    throw new TypeError(
      `A ${what} message must carry a non-empty \`object.zcaps\` list.`
    )
  }
  const messageIds = new Set(zcaps.map(value => parseConnectionZcap(value)?.id))
  const recordedIds = new Set(zcapIds)
  if (
    messageIds.size !== recordedIds.size ||
    [...messageIds].some(id => id === undefined || !recordedIds.has(id))
  ) {
    throw new TypeError(
      `A ${what} message's zcaps must be exactly the recorded zcaps.`
    )
  }
}

/**
 * Records a consent on the party's entry: creates the entry, or merges into
 * it. Each new grant is added by its capability id (one already recorded is
 * left as stored), `name` is set when it passes the display-name rule (left
 * as it was otherwise), `origin`, `url`, and `appKey` are set when given,
 * `retired` and `declined` are cleared, and `lastSeen` moves to `now`.
 * `firstSeen` is set only on create, and `label` is never touched. Every
 * grant of one call carries the same `grantedAt`. A zero-grant consent
 * writes too, so an App Connect app with no grants is indexed by its key.
 *
 * A `message` (an envelope carrying exactly the grants of this call) is
 * queued on `outbox` in the same write, stamped `now`, so a restore that
 * records fresh grants and owes the party their envelope has no tear between
 * the two. Pending items stay; a consent replaces no envelope.
 *
 * A `seed` and its `seedTag` (both or neither) are written when the entry
 * carries no seed, and left as stored when it carries the same one. An entry
 * carrying a different seed is refused with an `Error`, since the seed is
 * written once. A tag that does not verify under `hmacKey` is refused with a
 * `TypeError` before anything is read.
 *
 * Refuses an entry of another kind with {@link ConnectionKindMismatchError},
 * and a grant delegated to another party or targeting another Space with a
 * `TypeError`, before anything is written. Without `spaceUrl` (a session with
 * no Space, which delegates nothing) only a zero-grant write proceeds, and a
 * call carrying any grant throws a `TypeError`.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the party's DID, every grant's controller
 * @param options.kind {ConnectionKind}   the kind this flow writes
 * @param [options.spaceUrl] {string}   this Space's container URL, every
 *   grant's target prefix; absent on a session with no Space
 * @param options.grants {Array<object>}   `{ zcap, grantKind }` per grant
 * @param [options.name] {string}   the party's self-declared name
 * @param [options.origin] {string}   the attested Web origin (App Connect)
 * @param [options.url] {string}   the canonical app URL (App Connect)
 * @param [options.appKey] {string}   the app-key Resource id (App Connect)
 * @param [options.seed] {string}   the wallet's pairwise seed toward the
 *   party, base64url with no padding
 * @param [options.seedTag] {string}   the seed's tag (`connectionSeedTag`)
 * @param [options.message] {object}   an envelope to queue on `outbox` with
 *   the consent, carrying exactly the grants of this call
 * @param [options.now] {Date}
 * @returns {Promise<ConnectionWriteResult>}
 */
export async function recordGrants({
  store,
  hmacKey,
  did,
  kind,
  spaceUrl,
  grants,
  name,
  origin,
  url,
  appKey,
  seed,
  seedTag,
  message,
  now = new Date()
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  kind: ConnectionKind
  spaceUrl?: string
  grants: Array<{ zcap: object; grantKind: GrantKind }>
  name?: string
  origin?: string
  url?: string
  appKey?: string
  seed?: string
  seedTag?: string
  message?: Record<string, unknown>
  now?: Date
}): Promise<ConnectionWriteResult> {
  if ((seed === undefined) !== (seedTag === undefined)) {
    throw new TypeError('A connection seed is written with its tag, or not.')
  }
  const seeded = seed !== undefined && seedTag !== undefined
  if (seeded && !(await verifyConnectionSeedTag({ hmacKey, seed, seedTag }))) {
    throw new TypeError(
      "The connection seed's tag does not verify under this directory's key."
    )
  }
  const stamp = now.toISOString()
  const recorded: ConnectionGrantRecord[] = []
  const seen = new Set<string>()
  for (const grant of grants) {
    if (spaceUrl === undefined) {
      throw new TypeError(
        "A grant to record needs this Space's container URL; a write with " +
          'no Space records no grants.'
      )
    }
    const zcap = checkedGrant({ did, spaceUrl, grant })
    if (!seen.has(zcap.id)) {
      seen.add(zcap.id)
      recorded.push({ zcap, grantKind: grant.grantKind, grantedAt: stamp })
    }
  }
  if (message !== undefined) {
    assertEnvelopeCarries({
      message,
      zcapIds: recorded.map(grant => grant.zcap.id),
      what: 'consent'
    })
  }
  const queued: ConnectionOutboxItem[] =
    message === undefined ? [] : [{ message, createdAt: stamp }]
  const normalizedName =
    name === undefined ? undefined : normalizeDisplayName({ value: name })
  const declared = {
    ...(normalizedName !== undefined && { name: normalizedName }),
    ...(origin !== undefined && { origin }),
    ...(url !== undefined && { url }),
    ...(appKey !== undefined && { appKey })
  }
  return writePartyConnection({
    store,
    hmacKey,
    did,
    change(current) {
      if (current === undefined) {
        return {
          body: {
            ...newConnectionEntry({ kind, did, now }),
            ...declared,
            ...(seeded && { seed, seedTag }),
            grants: recorded,
            outbox: queued
          }
        }
      }
      assertKind({ entry: current.entry, kind })
      if (
        seeded &&
        current.entry.seed !== undefined &&
        current.entry.seed !== seed
      ) {
        throw new Error(
          'The connections entry already carries a different pairwise seed; ' +
            'a seed is written once.'
        )
      }
      const held = new Set(current.entry.grants.map(grant => grant.zcap.id))
      const body: Record<string, unknown> = {
        ...current.body,
        ...declared,
        lastSeen: stamp,
        grants: [
          ...current.entry.grants,
          ...recorded.filter(grant => !held.has(grant.zcap.id))
        ]
      }
      if (seeded && current.entry.seed === undefined) {
        body.seed = seed
        body.seedTag = seedTag
      }
      if (queued.length > 0) {
        body.outbox = [...current.entry.outbox, ...queued]
      }
      delete body.retired
      delete body.declined
      return { body }
    }
  })
}

/**
 * Removes grants from the party's entry by capability id, whatever the
 * entry's kind. Used by an unshare after its revocation, and by a torn
 * consent's rollback. An absent entry, or one holding none of the ids,
 * writes nothing.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the party's DID
 * @param options.zcapIds {Iterable<string>}   the capability ids to remove
 * @returns {Promise<ConnectionWriteResult>}
 */
export async function removeGrants({
  store,
  hmacKey,
  did,
  zcapIds
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  zcapIds: Iterable<string>
}): Promise<ConnectionWriteResult> {
  const removing = new Set(zcapIds)
  return writePartyConnection({
    store,
    hmacKey,
    did,
    change(current) {
      if (current === undefined) {
        return { stop: 'absent' }
      }
      const kept = current.entry.grants.filter(
        grant => !removing.has(grant.zcap.id)
      )
      if (kept.length === current.entry.grants.length) {
        return { stop: 'unchanged' }
      }
      return { body: { ...current.body, grants: kept } }
    }
  })
}

/**
 * Retires the party's entry, of any kind, once a revocation has handled its
 * grants: empties `grants`, `grantsReceived`, and `outbox`, drops `appKey`,
 * and stamps `retired`. `name`, `label`, `origin`, `url`, `firstSeen`,
 * `lastSeen`, `writers`, `seed`, `seedTag`, and `declined` stay, so a
 * departed party keeps resolving. An entry already retired with nothing left
 * to empty writes nothing, and an absent entry writes nothing.
 *
 * Throws when a read finds a grant that passes the reader checks and is not
 * among `handledZcapIds`: a concurrent consent merged it, and the revocation
 * must run again before the entry may retire. A grant that fails the reader
 * checks (another party's controller, a target outside this Space) is not
 * the party's, and the retirement empties it with the rest. Without
 * `spaceUrl` (a session with no Space, which delegates nothing) no grant can
 * be the party's, so none counts as unhandled and the retirement empties
 * them all.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the party's DID
 * @param options.handledZcapIds {Iterable<string>}   the capability ids the
 *   revocation POSTed
 * @param [options.spaceUrl] {string}   this Space's container URL, every
 *   session with a Space passes it
 * @param [options.now] {Date}
 * @returns {Promise<ConnectionWriteResult>}
 */
export async function retireConnection({
  store,
  hmacKey,
  did,
  handledZcapIds,
  spaceUrl,
  now = new Date()
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  handledZcapIds: Iterable<string>
  spaceUrl?: string
  now?: Date
}): Promise<ConnectionWriteResult> {
  const handled = new Set(handledZcapIds)
  return writePartyConnection({
    store,
    hmacKey,
    did,
    change(current) {
      if (current === undefined) {
        return { stop: 'absent' }
      }
      const partyGrants =
        spaceUrl === undefined
          ? []
          : connectionGrants({ entry: current.entry, spaceUrl })
      const unhandled = partyGrants.filter(grant => !handled.has(grant.zcapId))
      if (unhandled.length > 0) {
        throw new Error(
          `The connections entry carries ${unhandled.length} grant(s) this ` +
            'revocation did not handle (a consent merged them since); the ' +
            'revocation must run again before the entry retires.'
        )
      }
      const { entry } = current
      if (
        entry.retired !== undefined &&
        entry.grants.length === 0 &&
        entry.grantsReceived.length === 0 &&
        entry.outbox.length === 0 &&
        entry.appKey === undefined
      ) {
        return { stop: 'unchanged' }
      }
      const body: Record<string, unknown> = {
        ...current.body,
        grants: [],
        grantsReceived: [],
        outbox: [],
        retired: entry.retired ?? now.toISOString()
      }
      delete body.appKey
      return { body }
    }
  })
}

/**
 * Un-retires the party's entry, the inverse of {@link retireConnection} for a
 * party whose relationship resumed without a consent: clears `retired` and
 * moves `lastSeen` to `now`. Every other member stays as stored, so `grants`
 * stays empty and the names and `writers` are written back verbatim. An
 * entry with no `retired` writes nothing, and an absent entry writes nothing.
 *
 * Refuses an entry of another kind with {@link ConnectionKindMismatchError}.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the party's DID
 * @param options.kind {ConnectionKind}   the kind the calling flow writes
 * @param [options.now] {Date}
 * @returns {Promise<ConnectionWriteResult>}
 */
export async function unretireConnection({
  store,
  hmacKey,
  did,
  kind,
  now = new Date()
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  kind: ConnectionKind
  now?: Date
}): Promise<ConnectionWriteResult> {
  return writePartyConnection({
    store,
    hmacKey,
    did,
    change(current) {
      if (current === undefined) {
        return { stop: 'absent' }
      }
      assertKind({ entry: current.entry, kind })
      if (current.entry.retired === undefined) {
        return { stop: 'unchanged' }
      }
      const body: Record<string, unknown> = {
        ...current.body,
        lastSeen: now.toISOString()
      }
      delete body.retired
      return { body }
    }
  })
}

/**
 * Sets the user's `label` on the party's entry, and its `name` when given.
 * A blank `label` removes the member; an omitted one leaves it, and one
 * outside the display-name rule is refused with a `TypeError`, since the
 * user typed it and can shorten it. A `name` outside the rule is ignored. The enrollment approval writes
 * the code's suggested label as `name` and passes `label` only when the
 * approver edited it.
 *
 * Creates an absent entry only for a wallet client the verified account
 * document lists (`kind: 'wallet-client'`, its did:key's signing-key
 * multibase in `enrolledSigningKeys`), and throws for any other absent
 * party. Refuses an entry of another kind with
 * {@link ConnectionKindMismatchError}.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the party's DID
 * @param options.kind {ConnectionKind}   the kind the calling surface lists
 *   the party as
 * @param [options.label] {string}   the user's name for the party
 * @param [options.name] {string}   the party's name (a client's default
 *   platform label, or an enrollee's suggested label)
 * @param [options.enrolledSigningKeys] {ReadonlySet<string>}   the enrolled
 *   clients' signing-key multibases in the verified account document; needed
 *   to create a wallet client's entry
 * @param [options.now] {Date}
 * @returns {Promise<ConnectionWriteResult>}
 */
export async function setConnectionLabel({
  store,
  hmacKey,
  did,
  kind,
  label,
  name,
  enrolledSigningKeys,
  now = new Date()
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  kind: ConnectionKind
  label?: string
  name?: string
  enrolledSigningKeys?: ReadonlySet<string>
  now?: Date
}): Promise<ConnectionWriteResult> {
  const trimmedLabel = label?.trim()
  const normalizedLabel = trimmedLabel
    ? normalizeDisplayName({ value: trimmedLabel })
    : undefined
  if (trimmedLabel && normalizedLabel === undefined) {
    throw new TypeError(
      'A label is 1 to 64 code points once control and bidi characters are ' +
        'stripped.'
    )
  }
  const normalizedName =
    name === undefined ? undefined : normalizeDisplayName({ value: name })
  return writePartyConnection({
    store,
    hmacKey,
    did,
    change(current) {
      if (current === undefined) {
        const multibase = signingKeyMultibaseOfDid({ did })
        if (
          kind !== 'wallet-client' ||
          multibase === undefined ||
          enrolledSigningKeys?.has(multibase) !== true
        ) {
          throw new Error(
            'No connections entry stands for this party, and one is created ' +
              'here only for a wallet client the verified account document ' +
              'lists.'
          )
        }
        return {
          body: {
            ...newConnectionEntry({ kind, did, now }),
            ...(normalizedName !== undefined && { name: normalizedName }),
            ...(normalizedLabel !== undefined && { label: normalizedLabel })
          }
        }
      }
      assertKind({ entry: current.entry, kind })
      const body: Record<string, unknown> = { ...current.body }
      if (trimmedLabel !== undefined) {
        if (normalizedLabel !== undefined) {
          body.label = normalizedLabel
        } else {
          delete body.label
        }
      }
      if (normalizedName !== undefined) {
        body.name = normalizedName
      }
      if (
        body.label === current.body.label &&
        body.name === current.body.name
      ) {
        return { stop: 'unchanged' }
      }
      return { body }
    }
  })
}

/**
 * Records the capabilities a party handed the wallet on its entry's
 * `grantsReceived`. Each new record is merged in turn: one whose capability
 * id is already held is left as stored; one with the `grantKind` and
 * `invocationTarget` of a held record replaces it when its `expires` is
 * strictly later or when the held
 * record has lapsed as of `now` (at the earlier of its `expires` and
 * `receivedAt` plus `channelMaxLifetimeMs`), and leaves the held record
 * otherwise; any other is appended. Every record whose `expires`
 * is past by more than the revocation clock skew is then dropped. A new
 * record carries `receivedAt: now`.
 *
 * Each grant is checked strictly before anything is read, refused with a
 * `TypeError`: its known members well-formed, its `controller` the wallet's
 * pairwise DID toward the party, its `invocationTarget` outside this Space,
 * its kind one of `RECEIVED_GRANT_KINDS`, an `'inbox'` grant allowing POST,
 * and an `expires` in strict ISO 8601 form, with any number of fractional
 * second digits (a format one engine's `Date.parse` accepts and another's
 * refuses would make the entry unparseable there). A retired entry is refused
 * with an `Error`, and an absent entry writes nothing.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the party's DID
 * @param options.pairwiseDid {string}   the wallet's pairwise did:key toward
 *   the party, every received grant's controller
 * @param options.spaceUrl {string}   this Space's container URL, which no
 *   received grant may target
 * @param options.grants {Array<object>}   `{ zcap, grantKind }` per grant
 * @param options.channelMaxLifetimeMs {number}   how long after `receivedAt`
 *   a received record lapses at the latest
 * @param [options.now] {Date}
 * @returns {Promise<ConnectionWriteResult>}
 */
export async function recordReceivedGrants({
  store,
  hmacKey,
  did,
  pairwiseDid,
  spaceUrl,
  grants,
  channelMaxLifetimeMs,
  now = new Date()
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  pairwiseDid: string
  spaceUrl: string
  grants: Array<{ zcap: object; grantKind: ReceivedGrantKind }>
  channelMaxLifetimeMs: number
  now?: Date
}): Promise<ConnectionWriteResult> {
  const stamp = now.toISOString()
  const incoming: ConnectionReceivedGrantRecord[] = []
  for (const grant of grants) {
    const zcap = requiredConnectionZcap({
      value: grant.zcap,
      what: 'received grant'
    })
    if (zcap.controller !== pairwiseDid) {
      throw new TypeError(
        `A received grant must be delegated to the pairwise DID ` +
          `"${pairwiseDid}"; its controller is "${zcap.controller}".`
      )
    }
    if (isTargetInSpace({ target: zcap.invocationTarget, spaceUrl })) {
      throw new TypeError(
        'A received grant must target the party, not this Space; its ' +
          `invocation target is "${zcap.invocationTarget}".`
      )
    }
    if (
      !(RECEIVED_GRANT_KINDS as readonly string[]).includes(grant.grantKind)
    ) {
      throw new TypeError(`Unknown received grant kind "${grant.grantKind}".`)
    }
    if (
      grant.grantKind === 'inbox' &&
      !allowsAction({ allowedAction: zcap.allowedAction, action: 'POST' })
    ) {
      throw new TypeError('An inbox grant must allow POST.')
    }
    if (!STRICT_ISO_8601.test(zcap.expires)) {
      throw new TypeError(
        "A received grant's `expires` must be an ISO 8601 date-time; got " +
          `"${zcap.expires}".`
      )
    }
    incoming.push({ zcap, grantKind: grant.grantKind, receivedAt: stamp })
  }
  return writePartyConnection({
    store,
    hmacKey,
    did,
    change(current) {
      if (current === undefined) {
        return { stop: 'absent' }
      }
      if (current.entry.retired !== undefined) {
        throw new Error(
          'The connections entry is retired; it records no received grants.'
        )
      }
      const merged = [...current.entry.grantsReceived]
      for (const record of incoming) {
        if (merged.some(held => held.zcap.id === record.zcap.id)) {
          continue
        }
        const sameChannel = merged.findIndex(
          held =>
            held.grantKind === record.grantKind &&
            held.zcap.invocationTarget === record.zcap.invocationTarget
        )
        if (sameChannel === -1) {
          merged.push(record)
        } else if (
          expiresAtOf(record.zcap) > expiresAtOf(merged[sameChannel]!.zcap) ||
          receivedGrantLapsed({
            grant: {
              expires: merged[sameChannel]!.zcap.expires,
              receivedAt: merged[sameChannel]!.receivedAt
            },
            now,
            maxLifetimeMs: channelMaxLifetimeMs
          })
        ) {
          merged[sameChannel] = record
        }
      }
      const kept = merged.filter(
        record => !expiredBeyondSkew({ zcap: record.zcap, now })
      )
      if (
        kept.length === current.entry.grantsReceived.length &&
        kept.every(
          (record, index) => record === current.entry.grantsReceived[index]
        )
      ) {
        return { stop: 'unchanged' }
      }
      return { body: { ...current.body, grantsReceived: kept } }
    }
  })
}

/**
 * The renewal's pivot: appends the renewed grant records and queues the
 * envelope that carries them to the party, in one compare-and-swap. Each
 * renewed record keeps its source's `grantKind` and `grantedAt` and carries
 * `renewedAt: now`; the source record stays as stored. On `outbox`, every
 * zcap sharing a renewed zcap's scope is removed from the envelopes already
 * pending, an envelope left with none is dropped, and `message` is appended
 * with `createdAt: now`.
 *
 * A renewed zcap must copy its source's `invocationTarget` as stored, since
 * the scope compares it verbatim (a trailing `*` marker included).
 *
 * Refuses with an `Error`, writing nothing: a retired entry (whose `retired`
 * stays), an entry with no live inbox channel (`receivedGrants`, then
 * `liveInboxChannel`), a renewal whose source record is gone, a renewal
 * whose source is no longer the latest record of its scope (a concurrent
 * renewal ran), and a renewal whose `expires` is not strictly later than its
 * source's. The last is what keeps a renewal minted under a short-lived parent from
 * being appended at every login. A renewed zcap not delegated to the party,
 * not targeting this Space, or of another scope than its source, and a
 * `message` whose zcap ids are not exactly the renewed zcap ids, are refused
 * with a `TypeError`. An absent entry writes nothing.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the party's DID, every renewed grant's
 *   controller
 * @param options.pairwiseDid {string}   the wallet's pairwise did:key toward
 *   the party, the inbox channel's controller
 * @param options.spaceUrl {string}   this Space's container URL
 * @param options.renewals {Array<object>}   `{ zcap, sourceZcapId }` per
 *   renewed grant: the new capability and the id of the record it renews
 * @param options.message {object}   the envelope to queue, verbatim
 * @param options.channelMaxLifetimeMs {number}   how long after `receivedAt`
 *   an inbox record lapses at the latest
 * @param [options.now] {Date}
 * @returns {Promise<ConnectionWriteResult>}
 */
export async function recordRenewedGrants({
  store,
  hmacKey,
  did,
  pairwiseDid,
  spaceUrl,
  renewals,
  message,
  channelMaxLifetimeMs,
  now = new Date()
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  pairwiseDid: string
  spaceUrl: string
  renewals: Array<{ zcap: object; sourceZcapId: string }>
  message: Record<string, unknown>
  channelMaxLifetimeMs: number
  now?: Date
}): Promise<ConnectionWriteResult> {
  if (renewals.length === 0) {
    throw new TypeError('A renewal write needs at least one renewed grant.')
  }
  const renewed = renewals.map(renewal => ({
    zcap: checkedDelegatedZcap({ did, spaceUrl, zcap: renewal.zcap }),
    sourceZcapId: renewal.sourceZcapId
  }))
  if (
    new Set(renewed.map(renewal => renewal.sourceZcapId)).size !==
    renewed.length
  ) {
    throw new TypeError('Each renewed grant must renew a different record.')
  }
  assertEnvelopeCarries({
    message,
    zcapIds: renewed.map(renewal => renewal.zcap.id),
    what: 'renewal'
  })
  const renewedScopes = new Set(
    renewed.map(renewal => grantScopeKey({ zcap: renewal.zcap }))
  )
  const stamp = now.toISOString()
  return writePartyConnection({
    store,
    hmacKey,
    did,
    change(current) {
      if (current === undefined) {
        return { stop: 'absent' }
      }
      const { entry } = current
      if (entry.retired !== undefined) {
        throw new Error(
          'The connections entry is retired; its grants are not renewed.'
        )
      }
      const channel = liveInboxChannel({
        grants: receivedGrants({ entry, pairwiseDid, spaceUrl }),
        now,
        maxLifetimeMs: channelMaxLifetimeMs
      })
      if (channel === undefined) {
        throw new Error(
          'The connections entry holds no live inbox channel to deliver a ' +
            'renewal through.'
        )
      }
      const latest = latestPerScope({ grants: entry.grants })
      const appended: ConnectionGrantRecord[] = []
      for (const { zcap, sourceZcapId } of renewed) {
        const sourceIndex = entry.grants.findIndex(
          grant => grant.zcap.id === sourceZcapId
        )
        const source = entry.grants[sourceIndex]
        if (source === undefined) {
          throw new Error(
            `The grant "${sourceZcapId}" a renewal renews is no longer on ` +
              'the connections entry.'
          )
        }
        const scope = grantScopeKey({ zcap: source.zcap })
        if (grantScopeKey({ zcap }) !== scope) {
          throw new TypeError(
            `A renewal of "${sourceZcapId}" must keep its controller, ` +
              'invocation target, and allowed actions.'
          )
        }
        if (latest.get(scope) !== sourceIndex) {
          throw new Error(
            `The grant "${sourceZcapId}" is no longer the latest of its ` +
              'scope; a concurrent renewal superseded it.'
          )
        }
        if (expiresAtOf(zcap) <= expiresAtOf(source.zcap)) {
          throw new Error(
            `A renewal of "${sourceZcapId}" must expire strictly later than ` +
              'the record it renews.'
          )
        }
        appended.push({
          zcap,
          grantKind: source.grantKind,
          grantedAt: source.grantedAt,
          renewedAt: stamp
        })
      }
      const outbox: ConnectionOutboxItem[] = []
      for (const item of entry.outbox) {
        const zcaps = envelopeZcaps(item.message)
        if (zcaps === undefined) {
          outbox.push(item)
          continue
        }
        const kept = zcaps.filter(value => {
          const zcap = parseConnectionZcap(value)
          return (
            zcap === undefined || !renewedScopes.has(grantScopeKey({ zcap }))
          )
        })
        if (kept.length === zcaps.length) {
          outbox.push(item)
        } else if (kept.length > 0) {
          const itemObject = item.message.object as Record<string, unknown>
          outbox.push({
            ...item,
            message: {
              ...item.message,
              object: { ...itemObject, zcaps: kept }
            }
          })
        }
      }
      outbox.push({ message, createdAt: stamp })
      return {
        body: {
          ...current.body,
          grants: [...entry.grants, ...appended],
          outbox
        }
      }
    }
  })
}

/**
 * Removes the outbox item(s) queued at `createdAt`, once a push delivered
 * them. None queued then writes nothing, and an absent entry writes nothing.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the party's DID
 * @param options.createdAt {string}   the delivered item's `createdAt`
 * @returns {Promise<ConnectionWriteResult>}
 */
export async function settleOutboxItem({
  store,
  hmacKey,
  did,
  createdAt
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  createdAt: string
}): Promise<ConnectionWriteResult> {
  return writePartyConnection({
    store,
    hmacKey,
    did,
    change(current) {
      if (current === undefined) {
        return { stop: 'absent' }
      }
      const kept = current.entry.outbox.filter(
        item => item.createdAt !== createdAt
      )
      if (kept.length === current.entry.outbox.length) {
        return { stop: 'unchanged' }
      }
      return { body: { ...current.body, outbox: kept } }
    }
  })
}

/**
 * Drops the grant records renewal superseded, and the outbox items no push
 * can still deliver. In each scope holding more than one record, every
 * record but the latest is dropped when its `expires` is past by more than
 * the revocation clock skew, or when its capability id is among
 * `deadChainZcapIds`. The latest record of a scope always stays. An outbox
 * item is discarded when every zcap its envelope carries is past `expires` by
 * more than the skew; an item carrying a zcap this build cannot read stays.
 * Nothing to drop writes nothing, and an absent
 * entry writes nothing.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the party's DID
 * @param [options.deadChainZcapIds] {Iterable<string>}   ids of superseded
 *   records whose chain revocation reads as dead (the signer gone from the
 *   account document, or the parent naming another annex generation) and
 *   whose successor's outbox item was settled. A grant `agentGrantDue` reads
 *   as due by replacement does not qualify on that alone: a grant under an
 *   in-place-renewed delegation stays live until that delegation expires.
 * @param [options.now] {Date}
 * @returns {Promise<ConnectionWriteResult>}
 */
export async function pruneSupersededGrants({
  store,
  hmacKey,
  did,
  deadChainZcapIds = [],
  now = new Date()
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  deadChainZcapIds?: Iterable<string>
  now?: Date
}): Promise<ConnectionWriteResult> {
  const deadChains = new Set(deadChainZcapIds)
  return writePartyConnection({
    store,
    hmacKey,
    did,
    change(current) {
      if (current === undefined) {
        return { stop: 'absent' }
      }
      const { entry } = current
      const kept = new Set(latestPerScope({ grants: entry.grants }).values())
      const grants = entry.grants.filter(
        (grant, index) =>
          kept.has(index) ||
          !(
            expiredBeyondSkew({ zcap: grant.zcap, now }) ||
            deadChains.has(grant.zcap.id)
          )
      )
      const outbox = entry.outbox.filter(item => {
        const zcaps = envelopeZcaps(item.message)?.map(parseConnectionZcap)
        return (
          zcaps === undefined ||
          zcaps.length === 0 ||
          !zcaps.every(
            zcap => zcap !== undefined && expiredBeyondSkew({ zcap, now })
          )
        )
      })
      if (
        grants.length === entry.grants.length &&
        outbox.length === entry.outbox.length
      ) {
        return { stop: 'unchanged' }
      }
      return { body: { ...current.body, grants, outbox } }
    }
  })
}

/**
 * Empties the party's `grantsReceived` and `outbox`: the agent revoke's
 * first write, so no client pushes to the party once it starts. Both already
 * empty writes nothing, and an absent entry writes nothing.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the party's DID
 * @returns {Promise<ConnectionWriteResult>}
 */
export async function clearReceivedGrants({
  store,
  hmacKey,
  did
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
}): Promise<ConnectionWriteResult> {
  return writePartyConnection({
    store,
    hmacKey,
    did,
    change(current) {
      if (current === undefined) {
        return { stop: 'absent' }
      }
      if (
        current.entry.grantsReceived.length === 0 &&
        current.entry.outbox.length === 0
      ) {
        return { stop: 'unchanged' }
      }
      return { body: { ...current.body, grantsReceived: [], outbox: [] } }
    }
  })
}

/**
 * Records the owner's decline of the party's offer: sets `declined` to
 * `now`. An entry already declined keeps its time and writes nothing, and an
 * absent entry writes nothing. A later consent (`recordGrants`) clears it.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the party's DID
 * @param [options.now] {Date}
 * @returns {Promise<ConnectionWriteResult>}
 */
export async function markDeclined({
  store,
  hmacKey,
  did,
  now = new Date()
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  now?: Date
}): Promise<ConnectionWriteResult> {
  return writePartyConnection({
    store,
    hmacKey,
    did,
    change(current) {
      if (current === undefined) {
        return { stop: 'absent' }
      }
      if (current.entry.declined !== undefined) {
        return { stop: 'unchanged' }
      }
      return { body: { ...current.body, declined: now.toISOString() } }
    }
  })
}
