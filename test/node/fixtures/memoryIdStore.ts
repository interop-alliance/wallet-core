/**
 * The in-memory `WebvhIdStore` the did:webvh ceremony tests run against: the
 * world-readable `id` collection (`did.jsonl` and `did.json`) plus the private
 * `key-map` collection's `keys.json`, all held in closure variables. Shared by
 * every suite that drives a real ceremony (provisioning, enrollment,
 * revocation, recovery, log verification) so the fake's behavior -- notably
 * which resource ids it serves and stores -- is stated once.
 *
 * It also fakes the backend's conditional-write feature: every resource
 * carries an integer version served as its ETag, and `putIdResource` enforces
 * `ifMatch` / `ifNoneMatch`, throwing was-client's real
 * `PreconditionFailedError` on a stale or unexpected-present validator, and
 * answering a successful write with the resource's NEW validator (what
 * was-client's `Resource.put` returns). Pass `etags: false` for the
 * no-conditional-writes backend, which serves no ETag and ignores the
 * preconditions.
 */
import { PreconditionFailedError } from '@interop/was-client'
import {
  DID_DOCUMENT_RESOURCE,
  DID_KEYS_RESOURCE,
  DID_LOG_RESOURCE
} from '../../../src/space/collections.js'
import type { WebvhIdStore } from '../../../src/webvh/didWebvh.js'

/**
 * A fresh in-memory store, plus readers for what the ceremonies wrote.
 *
 * @param [options] {object}
 * @param [options.keys] {object}   the initial `keys.json` body (defaults to
 *   an empty map, as a Space that has never been provisioned would read)
 * @param [options.etags] {boolean}   whether the fake backend versions
 *   resources and enforces conditional writes (default `true`)
 * @returns {object}   `idStore` and the `log` / `didDocument` / `keys` readers
 */
export function memoryIdStore({
  keys = {},
  etags = true
}: { keys?: object; etags?: boolean } = {}): {
  idStore: WebvhIdStore & { getKeyMap(): Promise<object> }
  log: () => string | undefined
  didDocument: () => object | undefined
  keys: () => object
} {
  let currentLog: string | undefined
  let currentDidDoc: object | undefined
  let currentKeys: object = keys
  // Per-resource version counters, the fake's ETag source.
  const versions = new Map<string, number>()
  const etagOf = (resourceId: string): string | undefined => {
    const version = versions.get(resourceId)
    return etags && version !== undefined ? `"${version}"` : undefined
  }
  const checkPreconditions = ({
    resourceId,
    exists,
    ifMatch,
    ifNoneMatch
  }: {
    resourceId: string
    exists: boolean
    ifMatch?: string
    ifNoneMatch?: boolean
  }) => {
    if (!etags) {
      return
    }
    if (ifNoneMatch && exists) {
      throw new PreconditionFailedError(
        `${resourceId} already exists (If-None-Match: *).`
      )
    }
    if (ifMatch !== undefined && ifMatch !== etagOf(resourceId)) {
      throw new PreconditionFailedError(
        `${resourceId} has moved on (stale If-Match).`
      )
    }
  }
  const idStore = {
    async getKeyMap() {
      return currentKeys
    },
    async putKeyMap({ content }: { content: object }) {
      currentKeys = content
    },
    async getIdResource({ resourceId }: { resourceId: string }) {
      return resourceId === DID_DOCUMENT_RESOURCE ? currentDidDoc : undefined
    },
    async getIdResourceRaw({ resourceId }: { resourceId: string }) {
      if (resourceId !== DID_LOG_RESOURCE || currentLog === undefined) {
        return undefined
      }
      return { text: currentLog, etag: etagOf(resourceId) }
    },
    async putIdResource({
      resourceId,
      content,
      ifMatch,
      ifNoneMatch
    }: {
      resourceId: string
      content: object | string
      contentType?: string
      ifMatch?: string
      ifNoneMatch?: boolean
    }) {
      const exists =
        resourceId === DID_LOG_RESOURCE
          ? currentLog !== undefined
          : versions.has(resourceId)
      checkPreconditions({ resourceId, exists, ifMatch, ifNoneMatch })
      if (resourceId === DID_LOG_RESOURCE && typeof content === 'string') {
        currentLog = content
      }
      if (resourceId === DID_DOCUMENT_RESOURCE && typeof content === 'object') {
        currentDidDoc = content
      }
      if (resourceId === DID_KEYS_RESOURCE && typeof content === 'object') {
        currentKeys = content
      }
      versions.set(resourceId, (versions.get(resourceId) ?? 0) + 1)
      // The new validator, as the server answers a PUT: a ceremony that just
      // published can condition its next entry on it.
      const etag = etagOf(resourceId)
      return etag !== undefined ? { etag } : {}
    }
  }
  return {
    idStore,
    log: () => currentLog,
    didDocument: () => currentDidDoc,
    keys: () => currentKeys
  }
}
