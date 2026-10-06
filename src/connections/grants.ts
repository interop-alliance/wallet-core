/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The grant index the revocation orchestrators share: the grants of one
 * entry that pass the reader checks, their targets, the live and expired
 * split, and the recipient kid a grant's controller derives.
 *
 * Every reader applies the same two checks, since the storage host can plant
 * an entry and also holds every capability a party ever invoked. A grant
 * whose `zcap.controller` is not the entry's `id` is dropped, so an entry at
 * one party's id cannot steer a revocation at another party's capabilities.
 * A grant whose `zcap.invocationTarget` is not under this Space's container
 * URL is dropped, so no reader acts on a capability over another Space.
 *
 * The agent-connection readers sit beside them: the received list (the
 * capabilities an agent handed the wallet, over targets outside this Space),
 * the live inbox channel, the latest grant per scope, the grants one
 * connection request's consent produced, the agent grant renewal predicate,
 * and the agent entries one key signed grants for.
 */
import { vmFragmentOf } from '@interop/vh-resource-log'
import type { IZcap } from '@interop/data-integrity-core'
import { connectionRecipientKid } from './didKey.js'
import { grantKindOf } from './entry.js'
import type { ConnectionEntry, ConnectionZcap, GrantKind } from './entry.js'
import { INBOX_COLLECTION } from '../space/collections.js'
import {
  delegationProofKeyId,
  delegationSignerGone,
  embeddedParentCapability,
  zcapExpiring
} from '../webvh/index.js'
import type { PublishedKeyDocument } from '../webvh/index.js'

/**
 * The agent grant renewal window: ninety days before its `expires`, a grant
 * to an agent is due for renewal. Distinct from the thirty-day window the
 * standing recorded zcaps share, since an agent cannot ask the owner for a
 * fresh grant on its own.
 */
export const AGENT_GRANT_RENEWAL_WINDOW_MS = 90 * 24 * 60 * 60 * 1000

/**
 * One grant that passed the reader checks, with the members a decision
 * reads taken off its capability.
 */
export interface ConnectionGrant {
  /**
   * The capability's `id`, the key every merge and removal matches on.
   */
  zcapId: string
  /**
   * The capability's `controller`, equal to the entry's `id`.
   */
  controller: string
  /**
   * The capability's `invocationTarget`, under this Space's container URL.
   */
  target: string
  allowedAction?: string | string[]
  expires: string
  grantKind: GrantKind
  grantedAt: string
  /**
   * The stored capability, verbatim: what a revocation POSTs.
   */
  zcap: ConnectionZcap
}

/**
 * Whether a capability target sits under a Space's container URL. The target
 * is normalized by URL parsing first, so a dot segment cannot climb out of
 * the Space.
 *
 * @param options {object}
 * @param options.target {string}
 * @param options.spaceUrl {string}   the Space's container URL, with its
 *   trailing slash
 * @returns {boolean}
 */
export function isTargetInSpace({
  target,
  spaceUrl
}: {
  target: string
  spaceUrl: string
}): boolean {
  if (!spaceUrl.endsWith('/')) {
    throw new TypeError(
      `A Space container URL ends with a slash; got "${spaceUrl}".`
    )
  }
  let normalized: string
  try {
    normalized = new URL(target).href
  } catch {
    return false
  }
  return normalized.startsWith(new URL(spaceUrl).href)
}

/**
 * The grants of one entry that pass the reader checks, in stored order. An
 * entry with no `id` (a keyless writer entry) has no grant a controller can
 * match, so none pass.
 *
 * @param options {object}
 * @param options.entry {ConnectionEntry}
 * @param options.spaceUrl {string}   this Space's container URL
 * @returns {ConnectionGrant[]}
 */
export function connectionGrants({
  entry,
  spaceUrl
}: {
  entry: ConnectionEntry
  spaceUrl: string
}): ConnectionGrant[] {
  const grants: ConnectionGrant[] = []
  for (const grant of entry.grants) {
    const { zcap } = grant
    if (
      entry.id === undefined ||
      zcap.controller !== entry.id ||
      !isTargetInSpace({ target: zcap.invocationTarget, spaceUrl })
    ) {
      continue
    }
    grants.push({
      zcapId: zcap.id,
      controller: zcap.controller,
      target: zcap.invocationTarget,
      allowedAction: zcap.allowedAction,
      expires: zcap.expires,
      grantKind: grantKindOf(grant),
      grantedAt: grant.grantedAt,
      zcap
    })
  }
  return grants
}

/**
 * The Collection a capability target addresses when it is exactly a
 * Collection container URL of the given Space (`<spaceUrl><collectionId>/`),
 * else `undefined`: a Resource, a sub-resource, the Space itself, and a
 * target outside the Space all read as none. The target is normalized by URL
 * parsing first, as `isTargetInSpace` does, and the segment is
 * percent-decoded.
 *
 * @param options {object}
 * @param options.target {string}
 * @param options.spaceUrl {string}   the Space's container URL, with its
 *   trailing slash
 * @returns {string | undefined}
 */
export function collectionIdInSpace({
  target,
  spaceUrl
}: {
  target: string
  spaceUrl: string
}): string | undefined {
  if (!isTargetInSpace({ target, spaceUrl })) {
    return undefined
  }
  const rest = new URL(target).href.slice(new URL(spaceUrl).href.length)
  const segment = /^([^/?#]+)\/$/.exec(rest)?.[1]
  if (segment === undefined) {
    return undefined
  }
  try {
    return decodeURIComponent(segment)
  } catch {
    return undefined
  }
}

/**
 * The distinct targets of a set of grants, in first-seen order.
 *
 * @param options {object}
 * @param options.grants {ConnectionGrant[]}
 * @returns {string[]}
 */
export function grantTargets({
  grants
}: {
  grants: ConnectionGrant[]
}): string[] {
  return [...new Set(grants.map(grant => grant.target))]
}

/**
 * Splits grants into the live and the expired. A grant whose `expires` is at
 * or before `now` is expired.
 *
 * @param options {object}
 * @param options.grants {ConnectionGrant[]}
 * @param [options.now] {Date}
 * @returns {{ live: ConnectionGrant[], expired: ConnectionGrant[] }}
 */
export function splitGrantsByExpiry({
  grants,
  now = new Date()
}: {
  grants: ConnectionGrant[]
  now?: Date
}): { live: ConnectionGrant[]; expired: ConnectionGrant[] } {
  const live: ConnectionGrant[] = []
  const expired: ConnectionGrant[] = []
  for (const grant of grants) {
    if (Date.parse(grant.expires) <= now.getTime()) {
      expired.push(grant)
    } else {
      live.push(grant)
    }
  }
  return { live, expired }
}

/**
 * The key-epoch recipient kid a grant's controller derives, or `undefined`
 * when the controller is not an Ed25519 did:key.
 *
 * @param options {object}
 * @param options.grant {ConnectionGrant}
 * @returns {string | undefined}
 */
export function grantRecipientKid({
  grant
}: {
  grant: ConnectionGrant
}): string | undefined {
  return connectionRecipientKid({ did: grant.controller })
}

/**
 * One received grant that passed the received-list checks, with the members
 * a decision reads taken off its capability.
 */
export interface ConnectionReceivedGrant {
  /**
   * The capability's `id`.
   */
  zcapId: string
  /**
   * The capability's `controller`, equal to the wallet's pairwise DID toward
   * the party.
   */
  controller: string
  /**
   * The capability's `invocationTarget`, outside this Space.
   */
  target: string
  allowedAction?: string | string[]
  expires: string
  /**
   * The record's `grantKind`, as stored.
   */
  grantKind: string
  receivedAt: string
  /**
   * The stored capability, verbatim: what an invocation presents.
   */
  zcap: ConnectionZcap
}

/**
 * Whether a capability's action set names a verb. A string action is a
 * one-member set.
 *
 * @param options {object}
 * @param [options.allowedAction] {string | string[]}
 * @param options.action {string}
 * @returns {boolean}
 */
export function allowsAction({
  allowedAction,
  action
}: {
  allowedAction?: string | string[]
  action: string
}): boolean {
  return normalizedActions({ allowedAction }).includes(action)
}

/**
 * A capability's action set as a sorted array: a string is a one-member
 * set, and an absent member is the empty set.
 *
 * @param options {object}
 * @param [options.allowedAction] {string | string[]}
 * @returns {string[]}
 */
export function normalizedActions({
  allowedAction
}: {
  allowedAction?: string | string[]
}): string[] {
  if (allowedAction === undefined) {
    return []
  }
  if (typeof allowedAction === 'string') {
    return [allowedAction]
  }
  return [...allowedAction].sort()
}

/**
 * The scope key two capabilities share when one renews the other: the
 * `controller`, the `invocationTarget` compared verbatim (a trailing `*`
 * marker counts), and the normalized `allowedAction`. The renewal pivot and
 * {@link latestGrantsPerScope} key on the same string.
 *
 * @param options {object}
 * @param options.zcap {ConnectionZcap}
 * @returns {string}
 */
export function grantScopeKey({ zcap }: { zcap: ConnectionZcap }): string {
  return JSON.stringify([
    zcap.controller,
    zcap.invocationTarget,
    normalizedActions({ allowedAction: zcap.allowedAction })
  ])
}

/**
 * The received grants of one entry that pass the received-list checks, in
 * stored order: the opposite rule to {@link connectionGrants}. A record is
 * kept only when its `zcap.controller` is the wallet's pairwise DID toward
 * the party and its `invocationTarget` is outside this Space. An `'inbox'`
 * record must also allow `POST`. A retired entry yields none, since readers
 * ignore the received list on a retired entry.
 *
 * @param options {object}
 * @param options.entry {ConnectionEntry}
 * @param options.pairwiseDid {string}   the wallet's pairwise DID toward the
 *   party
 * @param options.spaceUrl {string}   this Space's container URL
 * @returns {ConnectionReceivedGrant[]}
 */
export function receivedGrants({
  entry,
  pairwiseDid,
  spaceUrl
}: {
  entry: ConnectionEntry
  pairwiseDid: string
  spaceUrl: string
}): ConnectionReceivedGrant[] {
  if (entry.retired !== undefined) {
    return []
  }
  const grants: ConnectionReceivedGrant[] = []
  for (const record of entry.grantsReceived) {
    const { zcap } = record
    if (
      zcap.controller !== pairwiseDid ||
      isTargetInSpace({ target: zcap.invocationTarget, spaceUrl })
    ) {
      continue
    }
    if (
      record.grantKind === 'inbox' &&
      !allowsAction({ allowedAction: zcap.allowedAction, action: 'POST' })
    ) {
      continue
    }
    grants.push({
      zcapId: zcap.id,
      controller: zcap.controller,
      target: zcap.invocationTarget,
      allowedAction: zcap.allowedAction,
      expires: zcap.expires,
      grantKind: record.grantKind,
      receivedAt: record.receivedAt,
      zcap
    })
  }
  return grants
}

/**
 * Whether a received grant has lapsed as of `now`: it lapses at the earlier
 * of its `expires` and `receivedAt + maxLifetimeMs`. A record with an
 * unparseable `receivedAt` reads as lapsed.
 *
 * @param options {object}
 * @param options.grant {object}   the grant's `expires` and `receivedAt`: a
 *   `ConnectionReceivedGrant`, or a stored record's members
 * @param options.now {Date}
 * @param options.maxLifetimeMs {number}   the longest a received grant is
 *   used after it was stored
 * @returns {boolean}
 */
export function receivedGrantLapsed({
  grant,
  now,
  maxLifetimeMs
}: {
  grant: Pick<ConnectionReceivedGrant, 'expires' | 'receivedAt'>
  now: Date
  maxLifetimeMs: number
}): boolean {
  const receivedAt = Date.parse(grant.receivedAt)
  if (Number.isNaN(receivedAt)) {
    return true
  }
  const lapsesAt = Math.min(
    receivedAt + maxLifetimeMs,
    Date.parse(grant.expires)
  )
  return lapsesAt <= now.getTime()
}

/**
 * The live inbox channel: of the `'inbox'` received grants not lapsed
 * ({@link receivedGrantLapsed}), the one with the greatest `expires`. A tie
 * keeps the later record in stored order.
 *
 * @param options {object}
 * @param options.grants {ConnectionReceivedGrant[]}   the received list, as
 *   {@link receivedGrants} returns it
 * @param options.now {Date}
 * @param options.maxLifetimeMs {number}
 * @returns {ConnectionReceivedGrant | undefined}
 */
export function liveInboxChannel({
  grants,
  now,
  maxLifetimeMs
}: {
  grants: ConnectionReceivedGrant[]
  now: Date
  maxLifetimeMs: number
}): ConnectionReceivedGrant | undefined {
  let best: ConnectionReceivedGrant | undefined
  let bestExpires = Number.NEGATIVE_INFINITY
  for (const grant of grants) {
    if (
      grant.grantKind !== 'inbox' ||
      receivedGrantLapsed({ grant, now, maxLifetimeMs })
    ) {
      continue
    }
    const expiresAt = Date.parse(grant.expires)
    if (best === undefined || expiresAt >= bestExpires) {
      best = grant
      bestExpires = expiresAt
    }
  }
  return best
}

/**
 * The latest grant per scope. A scope is the grant's `controller`, its
 * `target` compared verbatim (a trailing `*` marker included), and its
 * action set (a string is a one-member set, and order does not matter). The
 * latest is the one with the greatest `expires`, and a tie keeps the later
 * record in stored order. One grant per scope, in first-seen scope order.
 *
 * @param options {object}
 * @param options.grants {ConnectionGrant[]}
 * @returns {ConnectionGrant[]}
 */
export function latestGrantsPerScope({
  grants
}: {
  grants: ConnectionGrant[]
}): ConnectionGrant[] {
  const latest = latestIndexPerScope({ zcaps: grants.map(grant => grant.zcap) })
  return [...latest.values()].map(index => grants[index]!)
}

/**
 * The index of the latest capability in each scope ({@link grantScopeKey})
 * of a list: the greatest `expires`, a tie going to the later one. Scopes
 * come out in first-seen order.
 *
 * @param options {object}
 * @param options.zcaps {ConnectionZcap[]}
 * @returns {Map<string, number>}   scope key to the latest capability's index
 */
export function latestIndexPerScope({
  zcaps
}: {
  zcaps: ConnectionZcap[]
}): Map<string, number> {
  const latest = new Map<string, number>()
  zcaps.forEach((zcap, index) => {
    const scope = grantScopeKey({ zcap })
    const held = latest.get(scope)
    if (
      held === undefined ||
      Date.parse(zcap.expires) >= Date.parse(zcaps[held]!.expires)
    ) {
      // Map.set on an existing key keeps the key's first-seen position.
      latest.set(scope, index)
    }
  })
  return latest
}

/**
 * The grants one connection request's consent produced: those sharing their
 * `grantedAt` with an inbox grant on the same list (one targeting exactly
 * this Space's inbox collection container and allowing `POST`), whose action
 * set is exactly `GET` and `HEAD` on a Collection container, or exactly
 * `POST` on the inbox. A write grant, and a read grant from another consent,
 * are out of scope.
 *
 * @param options {object}
 * @param options.grants {ConnectionGrant[]}
 * @param options.spaceUrl {string}   this Space's container URL
 * @returns {ConnectionGrant[]}
 */
export function renewalScopeGrants({
  grants,
  spaceUrl
}: {
  grants: ConnectionGrant[]
  spaceUrl: string
}): ConnectionGrant[] {
  const actionsOf = (grant: ConnectionGrant): string =>
    normalizedActions({ allowedAction: grant.allowedAction }).join(' ')
  const isInboxPostTarget = (grant: ConnectionGrant): boolean =>
    collectionIdInSpace({ target: grant.target, spaceUrl }) === INBOX_COLLECTION
  const consentStamps = new Set(
    grants
      .filter(
        grant =>
          isInboxPostTarget(grant) &&
          allowsAction({ allowedAction: grant.allowedAction, action: 'POST' })
      )
      .map(grant => grant.grantedAt)
  )
  return grants.filter(grant => {
    if (!consentStamps.has(grant.grantedAt)) {
      return false
    }
    const actions = actionsOf(grant)
    if (actions === 'GET HEAD') {
      return (
        collectionIdInSpace({ target: grant.target, spaceUrl }) !== undefined
      )
    }
    return actions === 'POST' && isInboxPostTarget(grant)
  })
}

/**
 * Whether a grant to an agent is due for renewal. A grant already past its
 * `expires` is not due: it is gone, and a fresh consent replaces it. One
 * inside the renewal window is due (`zcapExpiring`'s polarity). Past that, a
 * grant whose embedded parent is
 * not the generation delegation the account currently points at is dead by
 * replacement and due, while its parent's own signer still stands under
 * `capabilityDelegation`. When that signer has left the document the grant
 * fails its proof check instead and is not due here. A root-anchored grant
 * (no embedded parent) is not due on this axis. The document is consulted
 * for the parent's signer only, since an annex VM that signs the leaf never
 * appears in the account document.
 *
 * @param options {object}
 * @param options.zcap {ConnectionZcap}
 * @param [options.pointedDelegationId] {string}   the current generation
 *   delegation's id, read from the account pointer's generation log head;
 *   undefined when the document points at no generation
 * @param options.doc {PublishedKeyDocument}   the locally verified account
 *   document
 * @param [options.renewalWindowMs] {number}
 * @param [options.now] {number}   epoch milliseconds
 * @returns {boolean}
 */
export function agentGrantDue({
  zcap,
  pointedDelegationId,
  doc,
  renewalWindowMs = AGENT_GRANT_RENEWAL_WINDOW_MS,
  now = Date.now()
}: {
  zcap: ConnectionZcap
  pointedDelegationId?: string
  doc: PublishedKeyDocument
  renewalWindowMs?: number
  now?: number
}): boolean {
  if (Date.parse(zcap.expires) <= now) {
    return false
  }
  if (zcapExpiring({ expires: zcap.expires, windowMs: renewalWindowMs, now })) {
    return true
  }
  const parent = embeddedParentCapability(zcap as unknown as IZcap)
  if (parent === undefined) {
    return false
  }
  return (
    parent.id !== pointedDelegationId &&
    !delegationSignerGone({ zcap: parent, doc })
  )
}

/**
 * The unretired agent entries holding at least one grant (through
 * {@link connectionGrants}) a key signed. A root-anchored grant (no embedded
 * parent) counts when its own proof names the key. A grant with an embedded
 * parent counts when the parent's proof names the key, the parent's minter.
 *
 * @param options {object}
 * @param options.entries {ConnectionEntry[]}
 * @param options.keyId {string}   a verification-method id in either DID
 *   form, or a bare multibase
 * @param options.spaceUrl {string}   this Space's container URL
 * @returns {ConnectionEntry[]}
 */
export function agentConnectionsSignedBy({
  entries,
  keyId,
  spaceUrl
}: {
  entries: ConnectionEntry[]
  keyId: string
  spaceUrl: string
}): ConnectionEntry[] {
  const key = vmFragmentOf(keyId) ?? keyId
  const signedBy = (zcap: IZcap): boolean => {
    const proofKeyId = delegationProofKeyId(zcap)
    return (
      proofKeyId !== undefined &&
      (vmFragmentOf(proofKeyId) ?? proofKeyId) === key
    )
  }
  return entries.filter(
    entry =>
      entry.kind === 'agent' &&
      entry.retired === undefined &&
      connectionGrants({ entry, spaceUrl }).some(grant => {
        const zcap = grant.zcap as unknown as IZcap
        const parent = embeddedParentCapability(zcap)
        return signedBy(parent ?? zcap)
      })
  )
}
