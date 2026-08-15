/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Public-credential URL derivation. Sharing a credential writes a plaintext copy
 * into the profile's `public-credentials` collection, keyed by the credential's
 * content cid; once replication mirrors it to the profile's WAS Space it
 * resolves at the URL below. Both wallet replicas build the identical URL for a
 * given `(serverUrl, spaceId, cid)`, so a link handed out by one resolves the
 * copy replicated by the other.
 *
 * The URL is assembled by was-client's path builders, the one owner of the WAS
 * path grammar: segments are percent-encoded (and reserved or dot segments
 * refused), and the path is joined onto the server URL's base path, so a
 * sub-path deployment keeps its prefix and the link addresses the same URL the
 * client wrote to.
 */
import { resourcePath, toUrl } from '@interop/was-client/paths'
import { PUBLIC_CREDENTIALS_COLLECTION } from './collections.js'

/**
 * The absolute, world-readable URL of a credential's shared copy:
 * `{serverUrl}/space/{spaceId}/public-credentials/{cid}`. Takes the server URL,
 * Space id, and credential cid as arguments, with no dependency on app config.
 * The path is joined onto the server URL's base path (a sub-path deployment
 * keeps its prefix), and each segment is percent-encoded by the builder.
 *
 * @param options {object}
 * @param options.serverUrl {string}   the WAS storage server base URL
 * @param options.spaceId {string}   the profile's WAS Space id
 * @param options.cid {string}   the credential's content cid
 * @returns {string}
 */
export function publicCredentialUrl({
  serverUrl,
  spaceId,
  cid
}: {
  serverUrl: string
  spaceId: string
  cid: string
}): string {
  return toUrl({
    serverUrl,
    path: resourcePath(spaceId, PUBLIC_CREDENTIALS_COLLECTION, cid)
  })
}
