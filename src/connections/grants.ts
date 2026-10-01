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
 */
import { connectionRecipientKid } from './didKey.js'
import { grantKindOf } from './entry.js'
import type { ConnectionEntry, ConnectionZcap, GrantKind } from './entry.js'

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
  expires?: string
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
      ...(zcap.allowedAction !== undefined && {
        allowedAction: zcap.allowedAction
      }),
      ...(zcap.expires !== undefined && { expires: zcap.expires }),
      grantKind: grantKindOf(grant),
      grantedAt: grant.grantedAt,
      zcap
    })
  }
  return grants
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
 * Splits grants into the live and the expired. A grant with no `expires` is
 * live. One whose `expires` is at or before `now` is expired.
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
    if (
      grant.expires !== undefined &&
      Date.parse(grant.expires) <= now.getTime()
    ) {
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
