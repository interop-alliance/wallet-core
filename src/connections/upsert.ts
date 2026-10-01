/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The upsert helpers every flow writes a party's entry through:
 * `recordGrants` at consent, `removeGrants` at an unshare or a torn
 * consent's rollback, `retireConnection` when a relationship ends, and
 * `setConnectionLabel` for the user's rename and the enrollment-time name.
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
import { signingKeyMultibaseOfDid } from './didKey.js'
import {
  CONNECTION_ENTRY_VERSION,
  GRANT_KINDS,
  isWritableConnectionEntry,
  newConnectionEntry,
  parseConnectionEntry,
  parseConnectionZcap
} from './entry.js'
import type {
  ConnectionEntry,
  ConnectionGrantRecord,
  ConnectionKind,
  ConnectionZcap,
  GrantKind
} from './entry.js'
import { ConnectionKindMismatchError } from './errors.js'
import { connectionGrants, isTargetInSpace } from './grants.js'
import { claimedResourceId } from './read.js'
import { connectionResourceId } from './resourceId.js'
import type { ConnectionIdKey } from './resourceId.js'
import type { ConnectionsStore } from './store.js'

const PRECONDITION_FAILED_ERROR_NAME = 'PreconditionFailedError'
const WRITE_ATTEMPTS = 3

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
 * The capability of one grant to record, checked strictly: its known members
 * well-formed, its `controller` the party's DID, its `invocationTarget` under
 * this Space, its kind one this build writes. The target check is the same
 * one every reader applies, so a grant that is stored is a grant the
 * revocation index will see.
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
  const zcap = parseConnectionZcap(grant.zcap)
  if (zcap === undefined) {
    throw new TypeError(
      'A grant to record must carry a capability with an id, a controller, ' +
        'and an invocation target.'
    )
  }
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
  if (!(GRANT_KINDS as readonly string[]).includes(grant.grantKind)) {
    throw new TypeError(`Unknown grant kind "${grant.grantKind}".`)
  }
  return zcap
}

/**
 * Records a consent on the party's entry: creates the entry, or merges into
 * it. Each new grant is added by its capability id (one already recorded is
 * left as stored), `name` is set when it passes the display-name rule (left
 * as it was otherwise), `origin`, `url`, and `appKey` are set when given,
 * `retired` is cleared, and `lastSeen` moves to `now`. `firstSeen` is set
 * only on create, and `label` is never touched. A zero-grant consent writes
 * too, so an App Connect app with no grants is indexed by its key.
 *
 * Refuses an entry of another kind with {@link ConnectionKindMismatchError},
 * and a grant delegated to another party or targeting another Space with a
 * `TypeError`, before anything is written.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the party's DID, every grant's controller
 * @param options.kind {ConnectionKind}   the kind this flow writes
 * @param options.spaceUrl {string}   this Space's container URL, every
 *   grant's target prefix
 * @param options.grants {Array<object>}   `{ zcap, grantKind }` per grant
 * @param [options.name] {string}   the party's self-declared name
 * @param [options.origin] {string}   the attested Web origin (App Connect)
 * @param [options.url] {string}   the canonical app URL (App Connect)
 * @param [options.appKey] {string}   the app-key Resource id (App Connect)
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
  now = new Date()
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  kind: ConnectionKind
  spaceUrl: string
  grants: Array<{ zcap: object; grantKind: GrantKind }>
  name?: string
  origin?: string
  url?: string
  appKey?: string
  now?: Date
}): Promise<ConnectionWriteResult> {
  const stamp = now.toISOString()
  const recorded: ConnectionGrantRecord[] = []
  const seen = new Set<string>()
  for (const grant of grants) {
    const zcap = checkedGrant({ did, spaceUrl, grant })
    if (!seen.has(zcap.id)) {
      seen.add(zcap.id)
      recorded.push({ zcap, grantKind: grant.grantKind, grantedAt: stamp })
    }
  }
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
            grants: recorded
          }
        }
      }
      assertKind({ entry: current.entry, kind })
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
      delete body.retired
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
 * grants: empties `grants`, drops `appKey`, and stamps `retired`. `name`,
 * `label`, `origin`, `url`, `firstSeen`, `lastSeen`, and `writers` stay, so a
 * departed party keeps resolving. An entry already retired with nothing left
 * to empty writes nothing, and an absent entry writes nothing.
 *
 * Throws when a read finds a grant that passes the reader checks and is not
 * among `handledZcapIds`: a concurrent consent merged it, and the revocation
 * must run again before the entry may retire. A grant that fails the reader
 * checks (another party's controller, a target outside this Space) is not
 * the party's, and the retirement empties it with the rest.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the party's DID
 * @param options.handledZcapIds {Iterable<string>}   the capability ids the
 *   revocation POSTed
 * @param options.spaceUrl {string}   this Space's container URL
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
  spaceUrl: string
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
      const unhandled = connectionGrants({
        entry: current.entry,
        spaceUrl
      }).filter(grant => !handled.has(grant.zcapId))
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
        entry.appKey === undefined
      ) {
        return { stop: 'unchanged' }
      }
      const body: Record<string, unknown> = {
        ...current.body,
        grants: [],
        retired: entry.retired ?? now.toISOString()
      }
      delete body.appKey
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
