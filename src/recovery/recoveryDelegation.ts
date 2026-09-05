/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The recovery code's authorization bridge: the pre-minted PUT-on-`did.jsonl`
 * delegation. The delegation is a wire artifact both apps must mint
 * byte-identically (issuance and every re-bind produce the record another
 * replica later recovers with), so its builder lives here: PUT on the one
 * `did.jsonl` resource, one-year TTL, delegated to the code-derived signing
 * DID. Its narrow scope is what keeps recovery loud -- a stolen code must
 * extend the world-readable log before it can read anything.
 *
 * No ceremony re-mints another credential's bridge. A record's bridge and
 * `delegatedClients` sibling are signed by that record's own credential's
 * ladder VM, and its frame proof by that credential's own unlock identity
 * key (`decisions/0019`), so the only thing that can rot a bridge is
 * retiring the credential it belongs to -- which deletes the record with it.
 * A bridge that ages out, or one a pre-rule bind left signed by a foreign
 * key, is refreshed by that credential's own login on the house staleness
 * axes ({@link zcapExpiring}, `recordedZcapStale`), and the registry fields
 * a refresh records are built here ({@link recordedDelegationFields}).
 */
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { resourcePath, toUrl } from '@interop/was-client/paths'
import { DID_LOG_RESOURCE, ID_COLLECTION } from '../space/collections.js'
import type { AccountPointer } from '../keyring/record.js'
import {
  delegationProofKeyId,
  STANDING_ZCAP_TTL_MS
} from '../webvh/standingZcap.js'

/**
 * The recovery delegation's lifetime: the house standing-zcap value
 * ({@link STANDING_ZCAP_TTL_MS} -- one year, per NIST SP 800-57's
 * cryptoperiod guidance; see `webvh/standingZcap.ts`, the policy's one
 * home). The delegation's scope stays narrow (PUT on the one world-readable
 * DID log resource, whose worst-case abuse is a log write that still has to
 * verify against the published hash chain and prerotation commitments to
 * resolve). A code must keep working past the year, so expiry is watched
 * rather than terminal: the registry entry records the delegation's
 * `expires`, {@link zcapExpiring} treats the renewal window before it as
 * stale, the re-mint refreshes a stale delegation, and the login-time
 * recovery health check flags one the same way it flags rot (the signing
 * client's verification method leaving the document).
 */
export const RECOVERY_DELEGATION_TTL_MS = STANDING_ZCAP_TTL_MS

// Re-exported from their shared home (`webvh/standingZcap.ts`), so this
// module's public surface predating the move is unchanged.
export { ZCAP_RENEWAL_WINDOW_MS, zcapExpiring } from '../webvh/standingZcap.js'

/**
 * The absolute URL of the account's `did.jsonl` log resource -- the
 * invocation target of the pre-minted recovery delegation. Built with
 * was-client's path builders, the one owner of the WAS path grammar, so the
 * path is joined onto the pointer host's base path (a sub-path deployment
 * keeps its prefix) and the minted target matches the URL the server checks
 * it against byte for byte.
 *
 * @param options {object}
 * @param options.pointer {AccountPointer}
 * @returns {string}
 */
function didLogUrl({ pointer }: { pointer: AccountPointer }): string {
  return toUrl({
    serverUrl: pointer.host,
    path: resourcePath(pointer.spaceId, ID_COLLECTION.id, DID_LOG_RESOURCE)
  })
}

/**
 * Delegates the narrow log-write bridge to a code-derived client: PUT on the
 * one `did.jsonl` resource, {@link RECOVERY_DELEGATION_TTL_MS} lifetime. The
 * delegation is what lets a latent-authority code write its self-enrolling
 * continuation without any standing invocation presence.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the delegating client (an enrolled
 *   client's promoted signer)
 * @param options.pointer {AccountPointer}
 * @param options.recoveryClientDid {string}
 * @param [options.now] {number}   epoch milliseconds the lifetime is measured
 *   from, for tests
 * @returns {Promise<IZcap>}
 */
export async function delegateLogWrite({
  zcapClient,
  pointer,
  recoveryClientDid,
  now = Date.now()
}: {
  zcapClient: ZcapClient
  pointer: AccountPointer
  recoveryClientDid: string
  now?: number
}): Promise<IZcap> {
  return zcapClient.delegate({
    invocationTarget: didLogUrl({ pointer }),
    controller: recoveryClientDid,
    allowedActions: ['PUT'],
    expires: new Date(now + RECOVERY_DELEGATION_TTL_MS)
  })
}

// Re-exported from its shared home (`webvh/standingZcap.ts`), so this
// module's public surface is unchanged.
export { delegationProofKeyId }

/**
 * The registry fields a record's delegations stand for -- which key signed
 * the bridge and the `delegatedClients` sibling, and when each expires --
 * built once here for the re-mint and for the credential-anchored
 * establishment's standing fields. A member is present iff its source is:
 * an absent delegation, a proof with no key id, or a caveat-less zcap
 * contributes nothing.
 *
 * @param options {object}
 * @param [options.delegation] {IZcap}   the record's bridge delegation
 * @param [options.delegatedClients] {IZcap}   the record's sibling
 * @returns {{ delegationKeyId?: string, delegationExpires?: string,
 *   delegatedClientsKeyId?: string, delegatedClientsExpires?: string }}
 */
export function recordedDelegationFields({
  delegation,
  delegatedClients
}: {
  delegation?: IZcap
  delegatedClients?: IZcap
}): {
  delegationKeyId?: string
  delegationExpires?: string
  delegatedClientsKeyId?: string
  delegatedClientsExpires?: string
} {
  const delegationKeyId = delegation
    ? delegationProofKeyId(delegation)
    : undefined
  const delegationExpires = delegation ? zcapExpires(delegation) : undefined
  const delegatedClientsKeyId = delegatedClients
    ? delegationProofKeyId(delegatedClients)
    : undefined
  const delegatedClientsExpires = delegatedClients
    ? zcapExpires(delegatedClients)
    : undefined
  return {
    ...(delegationKeyId ? { delegationKeyId } : {}),
    ...(delegationExpires ? { delegationExpires } : {}),
    ...(delegatedClientsKeyId ? { delegatedClientsKeyId } : {}),
    ...(delegatedClientsExpires ? { delegatedClientsExpires } : {})
  }
}

/**
 * A delegation's `expires` caveat, when it carries one.
 *
 * @param zcap {IZcap}
 * @returns {string | undefined}
 */
function zcapExpires(zcap: IZcap): string | undefined {
  return (zcap as { expires?: string }).expires
}
