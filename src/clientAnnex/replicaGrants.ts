/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The two grants a wallet signs around a replica server: the standing pull
 * delegation a replica server copies a Space under, and the short-lived
 * maintenance grant a credential-anchored account manages a promoted replica
 * Space through. Both shapes are permanent wire artifacts; the
 * wire-constants list records them and the spec text that owns them.
 *
 * - The pull delegation ({@link mintReplicaPullDelegation}) is the same shape
 *   on every session kind. Who signs it is the caller's choice: an enrolled
 *   client's promoted signer (`webvhZcapClient`), which the ladder clause does
 *   not bound, or the acting credential's ladder VM (`ladderVmZcapClient`),
 *   which the source server admits under predicate 6 only while the pointed
 *   annex document carries a replica pointer naming the grantee. The mint
 *   writes no pointer and checks for none; a ladder-signed pull minted before
 *   its pointer is refused by the source server, so the registration
 *   ceremony installs the pointer first.
 * - The maintenance grant ({@link mintReplicasMaintenanceGrant}) targets a
 *   replica Space's replicas route on the replica server. It lives minutes
 *   and is not stored, so a torn run owes no revocation.
 *
 * Both targets are the bare container URL under today's attenuation. When the
 * authorization profile ships the explicit subtree marker, each flips to its
 * `*` form (the one known gap on the marker in the wire-constants doc).
 *
 * Whether a recorded pull grant is due for renewal is read by the shared
 * predicates in `webvh/standingZcap.ts` (`zcapExpiring`, `standingZcapStale`);
 * this module adds no reading of its own.
 */
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { isEd25519DidKey } from '@interop/pws-client/edv/cipher'
import {
  rootCapabilityId,
  spaceReplicasUrl,
  spaceUrlById
} from '@interop/pws-client/paths'
import { STANDING_ZCAP_TTL_MS } from '../webvh/standingZcap.js'
import { assertReplicaServerDid } from './log.js'
import { DELETION_ZCAP_TTL_MS } from './spaceCapability.js'

/**
 * The pull delegation's action set: the read-only GET form of the `changes`
 * query is all a replica server's pull loop invokes. Permanent wire shape;
 * the source server's predicate admits a set within {GET, HEAD}, and the
 * wallet mints the narrower one.
 */
export const REPLICA_PULL_ACTIONS = ['GET'] as const

/**
 * The pull delegation's lifetime: the house standing-zcap value (one year),
 * renewed by the replica pass inside `ZCAP_RENEWAL_WINDOW_MS`, with the
 * replacement installed in place on the replica server's registration.
 */
export const REPLICA_PULL_TTL_MS = STANDING_ZCAP_TTL_MS

/**
 * Mints one replica pull delegation: the standing GET-only zcap a replica
 * server copies a Space under. The shape is the same for the account Space
 * and for the auxiliary annex Space, and on every session kind:
 *
 * - `invocationTarget` is the Space's canonical container URL (the
 *   trailing-slash form), built with pws-client's paths helpers so the bytes
 *   match the server's target check on a sub-path deployment. That URL
 *   covers the Space's changes feed.
 * - `controller` is the replica server's DID, a did:webvh whose path is
 *   `space:server:id`; any other string is refused before signing, since the
 *   source server's predicate bounds the grantee's shape the same way.
 * - `allowedAction` is {@link REPLICA_PULL_ACTIONS}.
 * - The chain is rooted directly in the Space's root zcap.
 * - `expires` is {@link REPLICA_PULL_TTL_MS} out.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the delegating signer
 * @param options.baseServerUrl {string}   the pulled Space's storage server
 * @param options.spaceId {string}   the pulled Space's id (the account Space
 *   or the auxiliary annex Space)
 * @param options.serverDid {string}   the replica server's DID, the grantee
 * @param [options.now] {number}   the clock the delegation is minted against
 *   (epoch milliseconds); a caller holding server-relative time passes it
 *   so the proof's `created` and `expires` come off one clock
 * @returns {Promise<IZcap>}
 */
export async function mintReplicaPullDelegation({
  zcapClient,
  baseServerUrl,
  spaceId,
  serverDid,
  now = Date.now()
}: {
  zcapClient: ZcapClient
  baseServerUrl: string
  spaceId: string
  serverDid: string
  now?: number
}): Promise<IZcap> {
  assertReplicaServerDid({ serverDid })
  const spaceUrl = spaceUrlById({ baseServerUrl, spaceId })
  return (await zcapClient.delegate({
    capability: rootCapabilityId(spaceUrl),
    invocationTarget: spaceUrl,
    controller: serverDid,
    allowedActions: [...REPLICA_PULL_ACTIONS],
    expires: new Date(now + REPLICA_PULL_TTL_MS),
    now
  })) as IZcap
}

/**
 * The maintenance grant's action set, the full vocabulary the replica
 * server's replicas-route predicate admits: GET lists and reads a
 * registration, POST re-registers against a source the Space already has,
 * PUT replaces a registration's pull capability in place and pauses or
 * clears a pause, and DELETE removes a registration. Permanent wire shape.
 */
export const REPLICAS_MAINTENANCE_ACTIONS = [
  'GET',
  'POST',
  'PUT',
  'DELETE'
] as const

/**
 * The maintenance grant's lifetime, and its upper bound: the single-verb
 * Space capability's ten minutes, long enough for the one request or short
 * run of requests it is minted before. It is minted per use and never
 * recorded, so expiry is its only end of life, and the mint refuses a caller
 * lifetime past this value.
 */
export const REPLICAS_MAINTENANCE_TTL_MS = DELETION_ZCAP_TTL_MS

/**
 * Whether a DID is a bare Ed25519 did:key: the Ed25519 multicodec prefix
 * followed by base58btc alone, so an empty method-specific id or a path,
 * query, or fragment after it is refused.
 *
 * @param did {string}
 * @returns {boolean}
 */
function isBareEd25519DidKey(did: string): boolean {
  return isEd25519DidKey(did) && /^did:key:z[1-9A-HJ-NP-Za-km-z]+$/.test(did)
}

/**
 * Mints the maintenance grant on a replica Space's replicas route, for an
 * account that holds no key able to root-invoke there (a promoted replica
 * Space's controller is the account did:webvh, and a credential-anchored
 * account has no `capabilityInvocation` key). The ladder VM delegates to
 * its own bare did:key, and the caller invokes as that did:key, the pattern
 * the single-verb Space capabilities already run.
 *
 * - `invocationTarget` is the replica Space's replicas container URL on the
 *   replica server (`spaceReplicasUrl`, no trailing slash); the registration
 *   and status URLs beneath it are reached through that one target.
 * - `controller` is the caller's delegatee, the ladder VM's bare did:key.
 * - `allowedAction` is {@link REPLICAS_MAINTENANCE_ACTIONS}.
 * - The chain is rooted directly in the replica Space's root zcap.
 * - `expires` is `ttlMs` out, {@link REPLICAS_MAINTENANCE_TTL_MS} by default.
 *
 * Two refusals stand before signing. A `controller` that is not a bare
 * did:key (the account did:webvh, an account-document method id with a
 * fragment, any other DID method) is refused, since the grant is minted for
 * the wallet to invoke as that did:key and nothing else. A `ttlMs` that is
 * not positive or exceeds {@link REPLICAS_MAINTENANCE_TTL_MS} is refused,
 * since a longer-lived grant is recorded nowhere and could not be revoked.
 *
 * The replica server applies no pointer gate to this shape; what the grant
 * reaches is bounded by the route (a delegated POST admits only a
 * registration whose source is already registered, and the mapping
 * registration cannot be removed). An enrolled client root-invokes the route
 * instead and mints nothing here.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the delegating signer, the ladder
 *   VM under its account-document method id
 * @param options.baseServerUrl {string}   the REPLICA server's base URL
 * @param options.spaceId {string}   the replica Space's id on that server
 * @param options.controller {string}   the delegatee DID, the ladder VM's
 *   bare did:key
 * @param [options.ttlMs] {number}   the grant's requested lifetime, at most
 *   {@link REPLICAS_MAINTENANCE_TTL_MS}
 * @param [options.now] {number}   the clock the grant is minted against
 *   (epoch milliseconds)
 * @returns {Promise<IZcap>}
 */
export async function mintReplicasMaintenanceGrant({
  zcapClient,
  baseServerUrl,
  spaceId,
  controller,
  ttlMs = REPLICAS_MAINTENANCE_TTL_MS,
  now = Date.now()
}: {
  zcapClient: ZcapClient
  baseServerUrl: string
  spaceId: string
  controller: string
  ttlMs?: number
  now?: number
}): Promise<IZcap> {
  if (!isBareEd25519DidKey(controller)) {
    throw new Error(
      'replicas maintenance grant: `controller` must be a bare did:key, ' +
        `got ${JSON.stringify(controller)}.`
    )
  }
  // Negated range so a NaN lifetime is refused too.
  if (!(ttlMs > 0 && ttlMs <= REPLICAS_MAINTENANCE_TTL_MS)) {
    throw new Error(
      'replicas maintenance grant: `ttlMs` must be positive and at most ' +
        `${REPLICAS_MAINTENANCE_TTL_MS} ms, got ${ttlMs}.`
    )
  }
  const spaceUrl = spaceUrlById({ baseServerUrl, spaceId })
  return (await zcapClient.delegate({
    capability: rootCapabilityId(spaceUrl),
    invocationTarget: spaceReplicasUrl({ spaceUrl }),
    controller,
    allowedActions: [...REPLICAS_MAINTENANCE_ACTIONS],
    expires: new Date(now + ttlMs),
    now
  })) as IZcap
}
