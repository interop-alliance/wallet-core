/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The WAS-backed adapter for the did:webvh module's narrow store seam: the
 * account's identity collections as a {@link WebvhIdStore}, so every wallet
 * app drives the log ceremonies through one implementation instead of its own
 * copy.
 *
 * Both collections are addressed as plaintext: `id` holds published documents
 * (world-readable by policy) and `key-map` holds plain JSON, so neither goes
 * through the encryption codec.
 *
 * Bodies are written as raw bytes under the content type the caller states --
 * load-bearing, since the log is JSON Lines (`text/jsonl`), not JSON, and the
 * DID document is served as `application/did+json`.
 */
import type { WasClient } from '@interop/was-client'
import {
  DID_KEYS_RESOURCE,
  ID_COLLECTION,
  KEY_MAP_COLLECTION
} from '../space/collections.js'
import type { WebvhIdStore } from './didWebvh.js'

/**
 * Builds the `id`-collection store the did:webvh ceremonies read and write
 * through.
 *
 * @param options {object}
 * @param options.was {WasClient}   the account's storage client, signing as an
 *   enrolled client
 * @param options.spaceId {string}   the data Space id
 * @returns {WebvhIdStore}
 */
export function wasWebvhIdStore({
  was,
  spaceId
}: {
  was: WasClient
  spaceId: string
}): WebvhIdStore {
  const idResource = (resourceId: string) =>
    was
      .space(spaceId)
      .collection(ID_COLLECTION.id, { encryption: 'plaintext' })
      .resource(resourceId)

  return {
    getIdResourceRaw: async ({ resourceId }) => {
      const text = await idResource(resourceId).getText()
      return text === null ? undefined : text
    },
    getIdResource: async ({ resourceId }) => {
      const data = await idResource(resourceId).get()
      return data === null ? undefined : data
    },
    putIdResource: async ({
      resourceId,
      content,
      contentType = 'application/json'
    }) => {
      const serialized =
        typeof content === 'string' ? content : JSON.stringify(content)
      await idResource(resourceId).put(new TextEncoder().encode(serialized), {
        contentType
      })
    },
    putKeyMap: async ({ content }) => {
      await was
        .space(spaceId)
        .collection(KEY_MAP_COLLECTION.id, { encryption: 'plaintext' })
        .resource(DID_KEYS_RESOURCE)
        .put(new TextEncoder().encode(JSON.stringify(content)), {
          contentType: 'application/json'
        })
    }
  }
}
