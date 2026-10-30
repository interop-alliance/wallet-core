/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Where a wallet's did:webvh log lives, in both directions: the controller
 * template a log is created under, which encodes the base server URL (host
 * and path prefix) and the Space and collection holding `did.jsonl`, and its
 * inverse, which reads the log URL, the Space URL and the base server URL
 * back off an identifier. The server layout fixes a Space at
 * `{base}space/{spaceId}/`, so the base is the parent of the DID's `space`
 * segment, and a wallet holding the DID stores no host and no base.
 *
 * A leaf beside `didWebvh.ts` (which re-exports it) and `verifyLog.ts`, over
 * the library's address normalization, was-client's path rules and the
 * collection ids alone, so the ceremonies and the readers share one
 * definition without a file-level cycle between them.
 */
import {
  getBaseUrl,
  getFileUrl,
  normalizeCreateDidAddress,
  SCID_PLACEHOLDER
} from '@interop/did-method-webvh'
import {
  baseServerUrlOf,
  resourceUrl,
  spaceIdOfUrl,
  splitCollectionUrl
} from '@interop/was-client/paths'
import { DID_LOG_RESOURCE, ID_COLLECTION } from '../space/collections.js'

/**
 * The `did:webvh:{SCID}:<host>:<prefix...>:space:<spaceId>:<collectionId>`
 * controller template, with the literal `{SCID}` placeholder the library
 * replaces at creation. The host segment percent-encodes a port
 * (`localhost:8080` becomes `localhost%3A8080`), and the prefix segments are
 * the base server URL's path, one colon segment each and absent for an
 * origin-root base, both exactly as the library's own address normalization
 * produces them, so the DID is self-locating under any mount
 * ({@link didWebvhLogLocation} is the inverse). The collection defaults to
 * the account log's `id` collection; a client-annex generation's log passes
 * its own `gen-` generation id.
 *
 * @param options {object}
 * @param options.baseServerUrl {string}   the server's base server URL
 * @param options.spaceId {string}
 * @param [options.collectionId] {string}   the collection holding `did.jsonl`
 *   (defaults to the `id` collection)
 * @returns {string}
 */
export function didWebvhControllerTemplate({
  baseServerUrl,
  spaceId,
  collectionId = ID_COLLECTION.id
}: {
  baseServerUrl: string
  spaceId: string
  collectionId?: string
}): string {
  return normalizeCreateDidAddress({
    address: baseServerUrl,
    scid: SCID_PLACEHOLDER,
    paths: didWebvhLogPaths({ spaceId, collectionId }),
    context: 'did:webvh controller template'
  }).controller
}

/**
 * The path segments beneath the base server URL a log's did:webvh encodes:
 * `space/<spaceId>/<collectionId>`, the Space and the collection holding
 * `did.jsonl`. One definition serves the template and every `createDID`
 * call, so a log is always created at the location its DID names.
 *
 * @param options {object}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @returns {string[]}
 */
export function didWebvhLogPaths({
  spaceId,
  collectionId
}: {
  spaceId: string
  collectionId: string
}): string[] {
  return ['space', spaceId, collectionId]
}

/**
 * Where a did:webvh minted by {@link didWebvhControllerTemplate} publishes
 * its log, read off the identifier alone: the log URL (`.../did.jsonl`), the
 * Space URL, the Space id, and the base server URL the Space sits under (the
 * parent of the `space` segment, as the server layout fixes it). A wallet
 * holding the DID therefore holds the server, and stores neither a host nor
 * a base. Refuses, with the library's or was-client's own error, a DID whose
 * path does not have the `space/<spaceId>/<collectionId>` shape.
 *
 * @param options {object}
 * @param options.did {string}   a did:webvh with a real SCID (not a template)
 * @returns {{ logUrl: string, spaceUrl: string, spaceId: string,
 *   baseServerUrl: string, collectionId: string }}
 */
export function didWebvhLogLocation({ did }: { did: string }): {
  logUrl: string
  spaceUrl: string
  spaceId: string
  baseServerUrl: string
  collectionId: string
} {
  const { spaceUrl, collectionId } = splitCollectionUrl(`${getBaseUrl(did)}/`)
  return {
    logUrl: getFileUrl(did),
    spaceUrl,
    spaceId: spaceIdOfUrl(spaceUrl),
    baseServerUrl: baseServerUrlOf(spaceUrl),
    collectionId
  }
}

/**
 * The URL of the account log beneath a Space URL: `id/did.jsonl`. The
 * Space-URL twin of {@link didWebvhLogLocation}'s `logUrl`, for a reader
 * holding the Space URL and no DID yet.
 *
 * @param options {object}
 * @param options.spaceUrl {string}
 * @returns {string}
 */
export function accountLogUrl({ spaceUrl }: { spaceUrl: string }): string {
  return resourceUrl({
    spaceUrl,
    collectionId: ID_COLLECTION.id,
    resourceId: DID_LOG_RESOURCE
  })
}
