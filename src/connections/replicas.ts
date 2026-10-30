/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The upsert helpers a replica registration and its maintenance write a
 * `replica-server` entry through: `recordReplicas` (the registration's entry
 * write, before anything touches the replica server), `recordReplicaGrant`
 * (a pull grant, with a first registration's pending id in the same write),
 * `settleReplicaRegistration` (the landed id), `setReplicaMarker` and
 * `clearReplicaMarker` over `stoppedAt`, `restartedAt`, and `lostAt`, and
 * `removeReplica`. Beside them, `restatedReplicaServerDids` is the restate
 * predicate a fresh client-annex generation's replica pointers are read
 * under.
 *
 * Each runs `writeConnection` (`upsert.ts`), the one bounded compare-and-swap
 * loop at the party's resource id, and refuses an entry of another kind with
 * `ConnectionKindMismatchError` before writing. Each changes only the
 * members it owns, so every other member, on the entry or on an item, is
 * written back verbatim. Every `fromSpace` is stored and matched in its
 * URL-normalized form (`spaceContainerUrl`). The members and their rules are
 * decision 0031's.
 */
import { normalizeDisplayName } from '../labelText.js'
import {
  REPLICA_SERVER_KIND,
  isConnectionFreshId,
  newConnectionEntry,
  spaceContainerUrl
} from './entry.js'
import type { ConnectionEntry, ConnectionReplica } from './entry.js'
import { verifyRecordedGrantProof } from './grantProof.js'
import type { AnnexDocumentResolver } from './grantProof.js'
import { isTargetInSpace } from './grants.js'
import type { ConnectionIdKey } from './resourceId.js'
import type { ConnectionsStore } from './store.js'
import type { PublishedKeyDocument } from '../webvh/index.js'
import {
  assertKind,
  assertPullGrantActions,
  assertTargetInSpaces,
  checkedDelegatedZcap,
  renewedGrantRecord,
  writePartyConnection
} from './upsert.js'
import type { ConnectionWriteResult } from './upsert.js'

/**
 * The intent markers a replica item carries.
 */
export const REPLICA_MARKERS = ['stoppedAt', 'restartedAt', 'lostAt'] as const

/**
 * One value of {@link REPLICA_MARKERS}.
 */
export type ReplicaMarker = (typeof REPLICA_MARKERS)[number]

/**
 * The named source Spaces of a marker write, normalized, or `undefined`
 * when none are named (every item). Refuses an empty list with a
 * `TypeError`, since a write naming no item would mark nothing while its
 * side effects (the re-start's decline clearing) still ran.
 *
 * @param fromSpaces {Iterable<string> | undefined}
 * @returns {Set<string> | undefined}
 */
function namedSourceSpaces(
  fromSpaces: Iterable<string> | undefined
): Set<string> | undefined {
  if (fromSpaces === undefined) {
    return undefined
  }
  const named = new Set([...fromSpaces].map(spaceContainerUrl))
  if (named.size === 0) {
    throw new TypeError(
      'A marker write names at least one source Space, or omits the list ' +
        'to name every item.'
    )
  }
  return named
}

/**
 * Refuses a value that is not a fresh id (32 bytes, base64url with no
 * padding) with a `TypeError`.
 *
 * @param options {object}
 * @param options.value {string}
 * @param options.what {string}   the id's name, for the message
 */
function assertFreshId({ value, what }: { value: string; what: string }): void {
  if (!isConnectionFreshId(value)) {
    throw new TypeError(
      `A ${what} is 32 random bytes as base64url with no padding; got ` +
        `"${value}".`
    )
  }
}

/**
 * The index of the item whose `fromSpace` is `fromSpace`, or a thrown
 * `Error` when the entry lists none.
 *
 * @param options {object}
 * @param options.entry {ConnectionEntry}
 * @param options.fromSpace {string}
 * @returns {number}
 */
function replicaIndex({
  entry,
  fromSpace
}: {
  entry: ConnectionEntry
  fromSpace: string
}): number {
  const index = entry.replicas.findIndex(item => item.fromSpace === fromSpace)
  if (index === -1) {
    throw new Error(
      `The connections entry lists no replica of the Space "${fromSpace}".`
    )
  }
  return index
}

/**
 * The stored `replicas` list with the item at `index` replaced.
 *
 * @param options {object}
 * @param options.entry {ConnectionEntry}
 * @param options.index {number}
 * @param options.item {ConnectionReplica}
 * @returns {ConnectionReplica[]}
 */
function withReplica({
  entry,
  index,
  item
}: {
  entry: ConnectionEntry
  index: number
  item: ConnectionReplica
}): ConnectionReplica[] {
  return entry.replicas.map((held, heldIndex) =>
    heldIndex === index ? item : held
  )
}

/**
 * The registration ceremony's entry write, before anything touches the
 * replica server: creates the `replica-server` entry, or merges into it.
 * `url` is set, `name` when it passes the display-name rule, and `lastSeen`
 * moves to `now`. Each item of `replicas` is added by its `fromSpace` (stored
 * URL-normalized) with its freshly minted replica Space id; an item already
 * listed for that source Space is left as stored, so a re-run adopts the ids
 * an earlier run persisted. An item already listed that carries `lostAt` is
 * refused with an `Error`: its replica Space is gone, so adopting its id
 * would register under a lost Space while the item kept reading as lost.
 * Delete removes the item (`removeReplica`) before the Space is registered
 * again. `retired` and `declined` are cleared, since the user's registration
 * is a fresh consent toward the server. `firstSeen` is set only on create,
 * and `label` is never touched.
 *
 * A `seed` and its `seedTag` (both or neither) are written when the entry
 * carries no seed, and left as stored when it carries the same one. An entry
 * carrying a different seed is refused with an `Error`, since the seed is
 * written once and a retired entry keeps it.
 *
 * Refuses an entry of another kind with {@link ConnectionKindMismatchError},
 * and a `fromSpace` that is not a container URL, a `spaceId` that is not a
 * fresh id, two items naming one source Space, or a `seed` without its tag
 * (or the reverse) with a `TypeError`, before anything is written. The tag
 * is not verified here; the caller minted both under the directory's key.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the replica server's `serverDid`
 * @param options.url {string}   the replica server's base URL
 * @param options.replicas {Array<object>}   `{ fromSpace, spaceId }` per
 *   replica Space to record
 * @param [options.name] {string}   the replica server's host name
 * @param [options.seed] {string}   the bootstrap seed, base64url with no
 *   padding
 * @param [options.seedTag] {string}   the seed's tag (`connectionSeedTag`)
 * @param [options.now] {Date}
 * @returns {Promise<ConnectionWriteResult>}
 */
export async function recordReplicas({
  store,
  hmacKey,
  did,
  url,
  replicas,
  name,
  seed,
  seedTag,
  now = new Date()
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  url: string
  replicas: Array<{ fromSpace: string; spaceId: string }>
  name?: string
  seed?: string
  seedTag?: string
  now?: Date
}): Promise<ConnectionWriteResult> {
  if ((seed === undefined) !== (seedTag === undefined)) {
    throw new TypeError('A connection seed is written with its tag, or not.')
  }
  const incoming: ConnectionReplica[] = []
  for (const { fromSpace: value, spaceId } of replicas) {
    const fromSpace = spaceContainerUrl(value)
    assertFreshId({ value: spaceId, what: 'replica Space id' })
    if (incoming.some(item => item.fromSpace === fromSpace)) {
      throw new TypeError(
        `A replica-server entry lists one replica per source Space; ` +
          `"${fromSpace}" is named twice.`
      )
    }
    incoming.push({ fromSpace, spaceId })
  }
  const named = new Set(incoming.map(item => item.fromSpace))
  const stamp = now.toISOString()
  const normalizedName =
    name === undefined ? undefined : normalizeDisplayName({ value: name })
  const declared = {
    ...(normalizedName !== undefined && { name: normalizedName }),
    url
  }
  return writePartyConnection({
    store,
    hmacKey,
    did,
    change(current) {
      if (current === undefined) {
        return {
          body: {
            ...newConnectionEntry({ kind: REPLICA_SERVER_KIND, did, now }),
            ...declared,
            ...(seed !== undefined && { seed, seedTag }),
            replicas: incoming
          }
        }
      }
      const { entry } = current
      assertKind({ entry, kind: REPLICA_SERVER_KIND })
      if (
        seed !== undefined &&
        entry.seed !== undefined &&
        entry.seed !== seed
      ) {
        throw new Error(
          'The connections entry already carries a different pairwise seed; ' +
            'a seed is written once.'
        )
      }
      const held = new Set(entry.replicas.map(item => item.fromSpace))
      const lost = entry.replicas.find(
        item => item.lostAt !== undefined && named.has(item.fromSpace)
      )
      if (lost !== undefined) {
        throw new Error(
          `The replica of "${lost.fromSpace}" is marked lost; it is removed ` +
            'before the Space is registered again.'
        )
      }
      const body: Record<string, unknown> = {
        ...current.body,
        ...declared,
        lastSeen: stamp,
        ...(seed !== undefined &&
          entry.seed === undefined && { seed, seedTag }),
        replicas: [
          ...entry.replicas,
          ...incoming.filter(item => !held.has(item.fromSpace))
        ]
      }
      delete body.retired
      delete body.declined
      return { body }
    }
  })
}

/**
 * Records one pull grant on the entry, and with it a first registration's
 * pending id, in one write. The grant is appended as a `'grant'` record
 * stamped `grantedAt: now`; one already recorded by its capability id is
 * left as stored. With `pendingRegistrationId`, the item for `fromSpace`
 * gains it, unless its first registration already landed (`registrationId`
 * present) or it is pending under another id, each refused with an `Error`:
 * the pending id is recorded before its POST, so a second id would orphan a
 * registration that may have landed under the first.
 *
 * With `renews`, the id of the recorded grant the capability renews, the
 * record is a renewal under `renewedGrantRecord`, the rule
 * `recordRenewedGrants` applies: it keeps the source's `grantKind` and
 * `grantedAt` and carries `renewedAt: now`, the source stays as stored, and
 * the capability must share the source's scope (controller, invocation
 * target, allowed actions) and expire strictly later. A source no longer on
 * the entry, no longer the latest record of its scope, or a capability not
 * expiring strictly later, is refused with an `Error`. The login pass records a renewal this
 * way, with no pending id; the two together are refused with a `TypeError`.
 *
 * This write touches neither `declined` nor `retired`: the pass records a
 * renewal through it, and a declined entry must stay declined until the
 * owner's re-start (`setReplicaMarker` with `restartedAt`) clears it.
 *
 * Refuses an entry of another kind with {@link ConnectionKindMismatchError},
 * a retired entry with an `Error`, and a capability not delegated to the
 * server's DID (`checkedDelegatedZcap`) or not targeting `fromSpace`
 * (`assertTargetInSpaces`), one
 * allowing any action but `GET` (a pull grant reads and nothing else), or a
 * `pendingRegistrationId` that is not a fresh id, with a `TypeError`. An entry listing no item for
 * `fromSpace` is refused with an `Error`. An absent entry writes nothing.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the replica server's `serverDid`, the
 *   grant's controller
 * @param options.fromSpace {string}   the source Space the grant reads from
 * @param options.zcap {object}   the pull capability
 * @param [options.pendingRegistrationId] {string}   a first registration's
 *   id, recorded before its POST
 * @param [options.renews] {string}   the capability id of the recorded grant
 *   this one renews
 * @param [options.now] {Date}
 * @returns {Promise<ConnectionWriteResult>}
 */
export async function recordReplicaGrant({
  store,
  hmacKey,
  did,
  fromSpace: spaceValue,
  zcap: zcapValue,
  pendingRegistrationId,
  renews,
  now = new Date()
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  fromSpace: string
  zcap: object
  pendingRegistrationId?: string
  renews?: string
  now?: Date
}): Promise<ConnectionWriteResult> {
  const fromSpace = spaceContainerUrl(spaceValue)
  if (pendingRegistrationId !== undefined && renews !== undefined) {
    throw new TypeError(
      'A first registration has no recorded grant to renew; pass a pending ' +
        'registration id or a renewed grant, not both.'
    )
  }
  const zcap = checkedDelegatedZcap({ did, zcap: zcapValue })
  assertTargetInSpaces({ zcap, spaceUrls: [fromSpace] })
  assertPullGrantActions({ zcap })
  if (pendingRegistrationId !== undefined) {
    assertFreshId({ value: pendingRegistrationId, what: 'registration id' })
  }
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
      assertKind({ entry, kind: REPLICA_SERVER_KIND })
      if (entry.retired !== undefined) {
        throw new Error(
          'The connections entry is retired; it records no pull grants.'
        )
      }
      const index = replicaIndex({ entry, fromSpace })
      const item = entry.replicas[index]!
      const grantHeld = entry.grants.some(grant => grant.zcap.id === zcap.id)
      const record =
        renews === undefined
          ? { zcap, grantKind: 'grant', grantedAt: stamp }
          : renewedGrantRecord({ entry, zcap, sourceZcapId: renews, stamp })
      let replicas = entry.replicas
      if (pendingRegistrationId !== undefined) {
        if (item.registrationId !== undefined) {
          throw new Error(
            `The replica of "${fromSpace}" is registered already; a ` +
              'replacement mints no new registration id.'
          )
        }
        if (
          item.pendingRegistrationId !== undefined &&
          item.pendingRegistrationId !== pendingRegistrationId
        ) {
          throw new Error(
            `The replica of "${fromSpace}" has a registration pending under ` +
              `"${item.pendingRegistrationId}"; it settles or is removed ` +
              'before another id is recorded.'
          )
        }
        if (item.pendingRegistrationId !== pendingRegistrationId) {
          replicas = withReplica({
            entry,
            index,
            item: { ...item, pendingRegistrationId }
          })
        }
      }
      if (grantHeld && replicas === entry.replicas) {
        return { stop: 'unchanged' }
      }
      return {
        body: {
          ...current.body,
          ...(!grantHeld && { grants: [...entry.grants, record] }),
          replicas
        }
      }
    }
  })
}

/**
 * Moves a landed first registration's id from `pendingRegistrationId` to
 * `registrationId` on the item for `fromSpace`. An item already settled on
 * `registrationId` with no pending id writes nothing. An item whose pending
 * id is another, or that carries neither, is refused with an `Error`.
 *
 * Refuses an entry of another kind with {@link ConnectionKindMismatchError},
 * and an entry listing no item for `fromSpace` with an `Error`. An absent
 * entry writes nothing.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the replica server's `serverDid`
 * @param options.fromSpace {string}   the item's source Space
 * @param options.registrationId {string}   the id that landed
 * @returns {Promise<ConnectionWriteResult>}
 */
export async function settleReplicaRegistration({
  store,
  hmacKey,
  did,
  fromSpace: value,
  registrationId
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  fromSpace: string
  registrationId: string
}): Promise<ConnectionWriteResult> {
  const fromSpace = spaceContainerUrl(value)
  assertFreshId({ value: registrationId, what: 'registration id' })
  return writePartyConnection({
    store,
    hmacKey,
    did,
    change(current) {
      if (current === undefined) {
        return { stop: 'absent' }
      }
      const { entry } = current
      assertKind({ entry, kind: REPLICA_SERVER_KIND })
      const index = replicaIndex({ entry, fromSpace })
      const item = entry.replicas[index]!
      if (
        item.registrationId === registrationId &&
        item.pendingRegistrationId === undefined
      ) {
        return { stop: 'unchanged' }
      }
      if (item.pendingRegistrationId !== registrationId) {
        throw new Error(
          `The replica of "${fromSpace}" has no pending registration ` +
            `"${registrationId}" to settle.`
        )
      }
      const settled: ConnectionReplica = { ...item, registrationId }
      delete settled.pendingRegistrationId
      return {
        body: {
          ...current.body,
          replicas: withReplica({ entry, index, item: settled })
        }
      }
    }
  })
}

/**
 * One marker write over the named items, or every item when `fromSpaces` is
 * omitted: `apply` returns the item's replacement, or `undefined` to leave it
 * as stored. `finish` edits the body beside `replicas` and says whether it
 * changed anything, so a write that touches no item may still land. Nothing
 * changed writes nothing.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}
 * @param [options.fromSpaces] {Iterable<string>}
 * @param options.apply {Function}
 * @param [options.finish] {Function}
 * @returns {Promise<ConnectionWriteResult>}
 */
async function writeReplicaMarkers({
  store,
  hmacKey,
  did,
  fromSpaces,
  apply,
  finish = () => false
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  fromSpaces?: Iterable<string>
  apply: (item: ConnectionReplica) => ConnectionReplica | undefined
  finish?: (options: {
    entry: ConnectionEntry
    body: Record<string, unknown>
  }) => boolean
}): Promise<ConnectionWriteResult> {
  const named = namedSourceSpaces(fromSpaces)
  return writePartyConnection({
    store,
    hmacKey,
    did,
    change(current) {
      if (current === undefined) {
        return { stop: 'absent' }
      }
      const { entry } = current
      assertKind({ entry, kind: REPLICA_SERVER_KIND })
      for (const fromSpace of named ?? []) {
        replicaIndex({ entry, fromSpace })
      }
      let changed = false
      const replicas = entry.replicas.map(item => {
        const applied =
          named !== undefined && !named.has(item.fromSpace)
            ? undefined
            : apply(item)
        if (applied === undefined) {
          return item
        }
        changed = true
        return applied
      })
      const body: Record<string, unknown> = { ...current.body, replicas }
      if (!finish({ entry, body }) && !changed) {
        return { stop: 'unchanged' }
      }
      return { body }
    }
  })
}

/**
 * Sets one intent marker to `now` on each named item, or on every item when
 * `fromSpaces` is omitted: `stoppedAt` is the user's Stop, `restartedAt` the
 * re-start, and `lostAt` the replica Space reading absent under the account's
 * own authority. An item already carrying the marker keeps its time. Setting
 * `restartedAt` also clears the entry's `declined`, in the same write, since
 * the re-start is the owner's consent. Nothing to set writes nothing.
 *
 * Refuses an entry of another kind with {@link ConnectionKindMismatchError},
 * a named source Space the entry lists no item for with an `Error`, and an
 * empty `fromSpaces` with a `TypeError`, since it would mark nothing while
 * the re-start's decline clearing still ran. An absent entry writes nothing.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the replica server's `serverDid`
 * @param options.marker {ReplicaMarker}
 * @param [options.fromSpaces] {Iterable<string>}   the items to mark, by
 *   source Space; omitted, every item
 * @param [options.now] {Date}
 * @returns {Promise<ConnectionWriteResult>}
 */
export async function setReplicaMarker({
  store,
  hmacKey,
  did,
  marker,
  fromSpaces,
  now = new Date()
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  marker: ReplicaMarker
  fromSpaces?: Iterable<string>
  now?: Date
}): Promise<ConnectionWriteResult> {
  const stamp = now.toISOString()
  return writeReplicaMarkers({
    store,
    hmacKey,
    did,
    fromSpaces,
    apply: item =>
      item[marker] === undefined ? { ...item, [marker]: stamp } : undefined,
    finish({ entry, body }) {
      if (marker !== 'restartedAt') {
        return false
      }
      delete body.declined
      return entry.declined !== undefined
    }
  })
}

/**
 * Clears one intent marker on each named item, or on every item when
 * `fromSpaces` is omitted: a completed re-start clears `stoppedAt` and then
 * `restartedAt`. An item without the marker is left as stored, and nothing
 * to clear writes nothing.
 *
 * Refuses an entry of another kind with {@link ConnectionKindMismatchError},
 * a named source Space the entry lists no item for with an `Error`, and an
 * empty `fromSpaces` with a `TypeError`. An absent entry writes nothing.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the replica server's `serverDid`
 * @param options.marker {ReplicaMarker}
 * @param [options.fromSpaces] {Iterable<string>}   the items to clear, by
 *   source Space; omitted, every item
 * @returns {Promise<ConnectionWriteResult>}
 */
export async function clearReplicaMarker({
  store,
  hmacKey,
  did,
  marker,
  fromSpaces
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  marker: ReplicaMarker
  fromSpaces?: Iterable<string>
}): Promise<ConnectionWriteResult> {
  return writeReplicaMarkers({
    store,
    hmacKey,
    did,
    fromSpaces,
    apply(item) {
      if (item[marker] === undefined) {
        return undefined
      }
      const cleared: ConnectionReplica = { ...item }
      delete cleared[marker]
      return cleared
    }
  })
}

/**
 * Removes the item for `fromSpace`, once its replica Space is gone. An
 * entry listing no such item writes nothing. The entry is not retired here:
 * `retireConnection` runs once the list is empty.
 *
 * Refuses an entry of another kind with {@link ConnectionKindMismatchError},
 * and an item whose source Space a recorded grant still targets with an
 * `Error`: Stop revokes and removes the pull grants first, so a grant left
 * recorded means a Stop torn before its last step, and the removal would
 * hide it from the readers that finish it. An absent entry writes nothing.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.did {string}   the replica server's `serverDid`
 * @param options.fromSpace {string}   the item's source Space
 * @returns {Promise<ConnectionWriteResult>}
 */
export async function removeReplica({
  store,
  hmacKey,
  did,
  fromSpace: value
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
  did: string
  fromSpace: string
}): Promise<ConnectionWriteResult> {
  const fromSpace = spaceContainerUrl(value)
  return writePartyConnection({
    store,
    hmacKey,
    did,
    change(current) {
      if (current === undefined) {
        return { stop: 'absent' }
      }
      const { entry } = current
      assertKind({ entry, kind: REPLICA_SERVER_KIND })
      const kept = entry.replicas.filter(item => item.fromSpace !== fromSpace)
      if (kept.length === entry.replicas.length) {
        return { stop: 'unchanged' }
      }
      const standing = entry.grants.filter(grant =>
        isTargetInSpace({
          target: grant.zcap.invocationTarget,
          spaceUrl: fromSpace
        })
      )
      if (standing.length > 0) {
        throw new Error(
          `The connections entry still records ${standing.length} pull ` +
            `grant(s) on "${fromSpace}"; Stop removes them before the ` +
            'replica is removed.'
        )
      }
      return { body: { ...current.body, replicas: kept } }
    }
  })
}

/**
 * THE RESTATE PREDICATE (app-connect-spec decision 0001): the replica
 * servers whose pointer a fresh client-annex generation restates, read off
 * the connections directory. A server is selected when its `replica-server`
 * entry is not declined and lists at least one replica Space that is not
 * stopped (`stoppedAt` unset) and has a recorded pull grant
 * (`recordReplicaGrant`: controller the server's DID, target under that
 * source Space) whose delegation proof verifies as this account's
 * (`verifyRecordedGrantProof`). A registration torn before its pull grant
 * was recorded is therefore not restated, and neither is a planted entry
 * carrying no wallet-signed grant. Entries of another kind are skipped.
 *
 * The one selector both wallets hand to the swap and GC entry points as
 * `replicaServerDids`, so the two replicas of an account restate the same
 * pointer set. Order is the entries' order, each server once. What the
 * proof check throws (an annex read that fails) propagates, so a caller
 * whose directory cannot be verified restates nothing rather than a subset.
 *
 * @param options {object}
 * @param options.entries {ConnectionEntry[]}   the directory's entries, or
 *   the `replica-server` ones
 * @param options.signerCheck {object}   what each grant is verified against
 *   (`verifyRecordedGrantProof`'s `signerCheck`)
 * @param options.signerCheck.doc {PublishedKeyDocument}   the locally
 *   verified account document
 * @param [options.signerCheck.clientAnnexDid] {string}   the annex DID the
 *   document's delegated-clients pointer currently names
 * @param options.signerCheck.annexDocument {AnnexDocumentResolver}
 * @returns {Promise<string[]>}   the selected servers' DIDs
 */
export async function restatedReplicaServerDids({
  entries,
  signerCheck
}: {
  entries: ConnectionEntry[]
  signerCheck: {
    doc: PublishedKeyDocument
    clientAnnexDid?: string
    annexDocument: AnnexDocumentResolver
  }
}): Promise<string[]> {
  const selected = new Set<string>()
  for (const entry of entries) {
    if (
      entry.kind !== REPLICA_SERVER_KIND ||
      entry.id === undefined ||
      entry.declined !== undefined ||
      selected.has(entry.id)
    ) {
      continue
    }
    if (
      await hasVerifiedPullGrant({ entry, serverDid: entry.id, signerCheck })
    ) {
      selected.add(entry.id)
    }
  }
  return [...selected]
}

/**
 * Whether a `replica-server` entry records a pull grant for one of its live
 * replica Spaces whose delegation proof verifies as this account's: the
 * per-entry half of {@link restatedReplicaServerDids}. Verification stops at
 * the first grant that verifies.
 *
 * @param options {object}
 * @param options.entry {ConnectionEntry}
 * @param options.serverDid {string}   the entry's id, the server's DID
 * @param options.signerCheck {object}   `verifyRecordedGrantProof`'s
 *   `signerCheck`
 * @returns {Promise<boolean>}
 */
async function hasVerifiedPullGrant({
  entry,
  serverDid,
  signerCheck
}: {
  entry: ConnectionEntry
  serverDid: string
  signerCheck: {
    doc: PublishedKeyDocument
    clientAnnexDid?: string
    annexDocument: AnnexDocumentResolver
  }
}): Promise<boolean> {
  const live = entry.replicas.filter(item => item.stoppedAt === undefined)
  const pullGrants = entry.grants.filter(
    grant =>
      grant.zcap.controller === serverDid &&
      live.some(item =>
        isTargetInSpace({
          target: grant.zcap.invocationTarget,
          spaceUrl: item.fromSpace
        })
      )
  )
  for (const grant of pullGrants) {
    const result = await verifyRecordedGrantProof({
      zcap: grant.zcap,
      signerCheck
    })
    if (result.verified) {
      return true
    }
  }
  return false
}
