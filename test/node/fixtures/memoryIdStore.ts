/**
 * The in-memory `WebvhIdStore` the did:webvh ceremony tests run against: the
 * world-readable `id` collection (`did.jsonl` and `did.json`) plus the private
 * `key-map` collection's `keys.json`, all held in closure variables. Shared by
 * every suite that drives a real ceremony (provisioning, enrollment,
 * revocation, recovery, log verification) so the fake's behavior -- notably
 * which resource ids it serves and stores -- is stated once.
 */
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
 * @returns {object}   `idStore` and the `log` / `didDocument` / `keys` readers
 */
export function memoryIdStore({ keys = {} }: { keys?: object } = {}): {
  idStore: WebvhIdStore & { getKeyMap(): Promise<object> }
  log: () => string | undefined
  didDocument: () => object | undefined
  keys: () => object
} {
  let currentLog: string | undefined
  let currentDidDoc: object | undefined
  let currentKeys: object = keys
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
      return resourceId === DID_LOG_RESOURCE ? currentLog : undefined
    },
    async putIdResource({
      resourceId,
      content
    }: {
      resourceId: string
      content: object | string
      contentType?: string
    }) {
      if (resourceId === DID_LOG_RESOURCE && typeof content === 'string') {
        currentLog = content
      }
      if (resourceId === DID_DOCUMENT_RESOURCE && typeof content === 'object') {
        currentDidDoc = content
      }
      if (resourceId === DID_KEYS_RESOURCE && typeof content === 'object') {
        currentKeys = content
      }
    }
  }
  return {
    idStore,
    log: () => currentLog,
    didDocument: () => currentDidDoc,
    keys: () => currentKeys
  }
}
