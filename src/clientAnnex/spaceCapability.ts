/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Single-verb Space capabilities: the short-lived children a transient
 * session mints so it can destroy (or probe) a Space it has no root
 * invocation over. Two shapes, one mint, both target-exact:
 *
 * - Three links, over a stored parent. The parent is the management zcap an
 *   unlock identity delegated to the account at bind time. The child's
 *   `invocationTarget` is the parent's own, copied verbatim from the parent's
 *   bytes rather than rebuilt, so a deployment whose stored parent carries a
 *   target this client would build differently still lands on the bytes the
 *   server checks.
 * - Two links, over a Space's synthesized root. The child's
 *   `invocationTarget` is the bare Space URL, built with was-client's path
 *   builders so a sub-path deployment keeps its prefix.
 *
 * `allowedAction` is exactly one HTTP verb -- `DELETE` for the deletion
 * child, `GET` for the probe child -- which is what a storage server's
 * admission predicate keys on. The delegatee is the caller's: the ladder
 * VM's bare did:key on a transient session (it re-derives from the ladder
 * seed and resolves from its own bytes, so it outlives the account log it
 * was minted beside), the account did:webvh on a remembered one.
 *
 * Nothing here is stored. A child is minted immediately before its own
 * request and dropped; on a torn run it lapses by its short TTL, so no
 * revocation is owed.
 *
 * Two checks stay with the caller rather than here: that the parent's
 * `controller` is the delegator this client signs as, and that the parent's
 * target names the Space the caller means on the deployment it is talking
 * to. The caller holds the deployment URL and the delegator DID; this module
 * holds neither, and guessing either would rebuild the very bytes the
 * verbatim copy exists to preserve.
 */
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { rootCapabilityId, spacePath, toUrl } from '@interop/was-client/paths'

/**
 * The single-verb Space capability's lifetime: ten minutes, long enough for
 * the request it is minted for and twice `@interop/zcap`'s 300-second clock
 * skew allowance. A child's `expires` is the earlier of this and its
 * parent's, since the library refuses a child less restrictive than its
 * parent with no skew allowance.
 */
export const DELETION_ZCAP_TTL_MS = 10 * 60 * 1000

/**
 * The two verbs a single-verb Space capability may carry: the deletion
 * child's `DELETE` and the probe child's `GET`.
 */
export type SpaceCapabilityVerb = 'DELETE' | 'GET'

/**
 * The typed refusal of a mint over a parent capability whose own `expires`
 * has already passed: the child would verify nowhere, so nothing is minted
 * and nothing is sent. Matched on `name` -- error classes do not survive
 * crossing package copies. The parent's `expires` and `id` ride the error so
 * a caller can name the lapsed capability in its own copy without re-reading
 * the parent.
 */
export class ExpiredParentCapabilityError extends Error {
  readonly parentExpires: string
  readonly parentId: string | undefined

  constructor({
    message,
    parentExpires,
    parentId
  }: {
    message: string
    parentExpires: string
    parentId: string | undefined
  }) {
    super(message)
    this.name = 'ExpiredParentCapabilityError'
    this.parentExpires = parentExpires
    this.parentId = parentId
  }
}

/**
 * The child's expiry: `min(now + ttlMs, parent.expires)`. A parent already
 * expired is refused rather than minted from, since the child would verify
 * nowhere.
 *
 * @param options {object}
 * @param options.ttlMs {number}
 * @param [options.parent] {IZcap}   the stored parent capability, absent on
 *   the root-parented shape (a synthesized root has no expiry)
 * @param options.now {number}   epoch milliseconds
 * @returns {Date}
 */
function childExpires({
  ttlMs,
  parent,
  now
}: {
  ttlMs: number
  parent?: IZcap
  now: number
}): Date {
  const requested = now + ttlMs
  const parentExpires = Date.parse(
    (parent as { expires?: string })?.expires ?? ''
  )
  if (Number.isNaN(parentExpires)) {
    return new Date(requested)
  }
  if (parentExpires <= now) {
    const expiresIso = new Date(parentExpires).toISOString()
    throw new ExpiredParentCapabilityError({
      message:
        'single-verb Space capability: the parent capability expired at ' +
        `${expiresIso}; refusing to mint a child that verifies nowhere.`,
      parentExpires: expiresIso,
      parentId: (parent as { id?: string })?.id
    })
  }
  return new Date(Math.min(requested, parentExpires))
}

/**
 * Refuses a child the parent cannot authorize. A parent's `allowedAction` may
 * be a single string, a list, or absent (which delegates every action), so
 * the check normalizes before asking. Refusing locally is what keeps the
 * failure legible: an unauthorized invocation comes back from the storage
 * server as a 404, indistinguishable from a Space that is simply gone, so a
 * child that verifies nowhere must never be minted and sent.
 *
 * @param options {object}
 * @param options.parent {IZcap}
 * @param options.verb {SpaceCapabilityVerb}
 * @returns {void}
 */
function assertParentAllows({
  parent,
  verb
}: {
  parent: IZcap
  verb: SpaceCapabilityVerb
}): void {
  const allowed = (parent as { allowedAction?: string | string[] })
    .allowedAction
  if (allowed === undefined) {
    return
  }
  const actions = Array.isArray(allowed) ? allowed : [allowed]
  if (actions.length === 0 || actions.includes(verb)) {
    return
  }
  throw new Error(
    `single-verb Space capability: the parent capability allows ` +
      `${actions.join(', ')} and not ${verb}; refusing to mint a child that ` +
      'verifies nowhere.'
  )
}

/**
 * Mints a single-verb child of a STORED parent capability -- the three-link
 * shape, used on an unlock Space whose management zcap the account already
 * holds. The child's `invocationTarget` is the parent's unchanged.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the delegating signer (the ladder
 *   VM's client on a transient session, an enrolled client's on a remembered
 *   one)
 * @param options.parent {IZcap}   the stored parent capability
 * @param options.verb {SpaceCapabilityVerb}   the child's one allowed action
 * @param options.controller {string}   the delegatee DID
 * @param [options.ttlMs] {number}   the child's requested lifetime
 * @param [options.now] {number}   the clock the child is minted against
 *   (epoch milliseconds); a caller holding server-relative time passes it
 *   so the proof's `created` and the child's `expires` come off one clock
 * @returns {Promise<IZcap>}
 */
export async function mintSpaceVerbCapability({
  zcapClient,
  parent,
  verb,
  controller,
  ttlMs = DELETION_ZCAP_TTL_MS,
  now = Date.now()
}: {
  zcapClient: ZcapClient
  parent: IZcap
  verb: SpaceCapabilityVerb
  controller: string
  ttlMs?: number
  now?: number
}): Promise<IZcap> {
  const invocationTarget = (parent as { invocationTarget?: string })
    .invocationTarget
  if (invocationTarget === undefined) {
    throw new Error(
      'single-verb Space capability: the parent capability names no ' +
        '`invocationTarget`.'
    )
  }
  assertParentAllows({ parent, verb })
  return (await zcapClient.delegate({
    capability: parent,
    invocationTarget,
    controller,
    allowedActions: [verb],
    expires: childExpires({ ttlMs, parent, now }),
    now
  })) as IZcap
}

/**
 * Mints a single-verb child of a Space's SYNTHESIZED ROOT -- the two-link
 * shape, used on the account Space and an auxiliary annex Space, where the
 * session holds no stored parent. The child's `invocationTarget` is the bare
 * Space URL, with no trailing slash, so the deletion child covers the Space
 * itself rather than its items subtree.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the delegating signer
 * @param options.storageServerUrl {string}   the Space's storage server
 * @param options.spaceId {string}
 * @param options.verb {SpaceCapabilityVerb}   the child's one allowed action
 * @param options.controller {string}   the delegatee DID
 * @param [options.ttlMs] {number}   the child's requested lifetime
 * @param [options.now] {number}   the clock the child is minted against
 *   (epoch milliseconds); a caller holding server-relative time passes it
 *   so the proof's `created` and the child's `expires` come off one clock
 * @returns {Promise<IZcap>}
 */
export async function mintSpaceRootVerbCapability({
  zcapClient,
  storageServerUrl,
  spaceId,
  verb,
  controller,
  ttlMs = DELETION_ZCAP_TTL_MS,
  now = Date.now()
}: {
  zcapClient: ZcapClient
  storageServerUrl: string
  spaceId: string
  verb: SpaceCapabilityVerb
  controller: string
  ttlMs?: number
  now?: number
}): Promise<IZcap> {
  const spaceUrl = toUrl({
    serverUrl: storageServerUrl,
    path: spacePath(spaceId)
  })
  return (await zcapClient.delegate({
    capability: rootCapabilityId(spaceUrl),
    invocationTarget: spaceUrl,
    controller,
    allowedActions: [verb],
    expires: childExpires({ ttlMs, now }),
    now
  })) as IZcap
}
