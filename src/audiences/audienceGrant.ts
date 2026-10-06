/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The audience collection and its member grant. An audience is a plaintext
 * collection in the owner's Space whose posts are its Resources. Nothing
 * marks a collection as an audience on the wire.
 */
import type { IDelegatedZcap, IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import type { SpaceProvisionSpec } from '../space/collections.js'

/**
 * The provisioning attributes every audience collection carries: it is
 * plaintext, since its members read posts without a key epoch. The rest of
 * the spec is the caller's. `isPublic` is the caller's choice (a public
 * audience is one under world read), and the collection id follows the
 * existing collection name grammar and is chosen by the caller.
 */
export const AUDIENCE_PROVISION_ATTRIBUTES = {
  encryption: 'plaintext'
} as const satisfies Pick<SpaceProvisionSpec, 'encryption'>

/**
 * Delegates an audience member's read grant over the audience collection.
 * The shape is the read-only share grant a wallet mints for a collection
 * reader: GET and HEAD on the collection's container. No key epoch is
 * escrowed, since the audience is plaintext.
 *
 * The authorization profile is adding an explicit subtree marker (`*`
 * appended to the target), and this mint site will write it once the
 * profile and the server ship it. Until then the target is the bare
 * container URL, which the current server reads as covering the subtree.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the delegating signer
 * @param options.parentCapability {string | IZcap}   the parent: a root zcap
 *   id string, or the embedded generation delegation
 * @param options.collectionUrl {string}   the collection's canonical
 *   container URL (trailing slash)
 * @param options.controller {string}   the member's DID
 * @param options.expires {Date}   the grant's expiry
 * @returns {Promise<IDelegatedZcap>}
 */
export async function delegateAudienceGrant({
  zcapClient,
  parentCapability,
  collectionUrl,
  controller,
  expires
}: {
  zcapClient: ZcapClient
  parentCapability: string | IZcap
  collectionUrl: string
  controller: string
  expires: Date
}): Promise<IDelegatedZcap> {
  if (!collectionUrl.endsWith('/')) {
    throw new TypeError(
      'audience grant: `collectionUrl` must be the canonical container URL ' +
        '(with a trailing slash).'
    )
  }
  return (await zcapClient.delegate({
    capability: parentCapability,
    // Subtree marker: pending the profile change; flip this target to `${collectionUrl}*` when it ships.
    invocationTarget: collectionUrl,
    controller,
    allowedActions: ['GET', 'HEAD'],
    expires
  })) as IDelegatedZcap
}
