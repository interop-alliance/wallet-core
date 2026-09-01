/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The WAS-backed adapter for the did:webvh module's narrow store seam: the
 * account's identity collections as a {@link WebvhIdStore}, so every wallet
 * app drives the log ceremonies through one implementation instead of its own
 * copy. The log-resource half is parameterized over the collection holding
 * `did.jsonl` ({@link wasWebvhLogStore}), so a client-annex generation's log --
 * a `gen-` collection in the auxiliary annex Space -- is served by the
 * same implementation without touching the account-log paths.
 *
 * Collections here are addressed through {@link plaintextCollection}: `id`
 * holds published documents (world-readable by policy), an annex generation's
 * collection holds only its `did.jsonl` (capability-gated, but never
 * encrypted -- the server resolves it out of its own storage), and `key-map`
 * holds plain JSON, so none of them goes through the encryption codec.
 *
 * Bodies are written as raw bytes under the content type the caller states --
 * load-bearing, since the log is JSON Lines (`text/jsonl`), not JSON, and the
 * DID document is served as `application/did+json`.
 *
 * Reads carry the resource's ETag and writes forward the ceremonies'
 * conditional-write preconditions, so a did:webvh ceremony's `did.jsonl`
 * publish is a compare-and-swap. A backend that does not advertise
 * `conditional-writes` serves no ETag, and the publish degrades to an
 * unconditional write.
 */
import type { IZcap } from '@interop/data-integrity-core'
import type { WasClient } from '@interop/was-client'
import {
  DID_KEYS_RESOURCE,
  ID_COLLECTION,
  KEY_MAP_COLLECTION
} from '../space/collections.js'
import { plaintextCollection } from '../space/plaintextCollection.js'
import type { WebvhIdStore } from './didWebvh.js'

/**
 * The log-resource subset of the seam: what a ceremony that only reads and
 * publishes a `did.jsonl` (and its sibling resources in the same collection)
 * needs. The account store and the annex store both serve it.
 */
export type WebvhLogResourceStore = Pick<
  WebvhIdStore,
  'getIdResourceRaw' | 'getIdResource' | 'putIdResource'
>

/**
 * Builds the parameterized log-resource store over one collection of one
 * Space: the shared implementation behind {@link wasWebvhIdStore} (the
 * account's `id` collection) and an annex generation's log store (its
 * `gen-` collection in the auxiliary Space). Signing is whatever the wrapped
 * client signs as -- controller-tier for the account paths, an enrolled
 * client's key for the annex.
 *
 * @param options {object}
 * @param options.was {WasClient}   the storage client to sign with
 * @param options.spaceId {string}   the Space holding the collection
 * @param options.collectionId {string}   the collection holding the log
 * @param [options.capability] {IZcap}   an invocation capability every request
 *   rides (a delegated writer -- e.g. the transient-recovery continuation over
 *   the credential's sibling delegation); absent, requests invoke the root
 *   capability as before
 * @returns {WebvhLogResourceStore}
 */
export function wasWebvhLogStore({
  was,
  spaceId,
  collectionId,
  capability
}: {
  was: WasClient
  spaceId: string
  collectionId: string
  capability?: IZcap
}): WebvhLogResourceStore {
  const resource = (resourceId: string) =>
    plaintextCollection({ was, spaceId, collectionId, capability }).resource(
      resourceId
    )

  return {
    getIdResourceRaw: async ({ resourceId }) => {
      const read = await resource(resourceId).getWithEtag()
      if (read === null) {
        return undefined
      }
      // The log is served as `text/jsonl`, so the body decodes to a Blob; the
      // string and stringify arms are defensive fallbacks for a backend that
      // served (and the codec parsed) a JSON content type instead.
      const { data, etag } = read
      const text =
        data instanceof Blob
          ? await data.text()
          : typeof data === 'string'
            ? data
            : JSON.stringify(data)
      return { text, etag }
    },
    getIdResource: async ({ resourceId }) => {
      const data = await resource(resourceId).get()
      return data === null ? undefined : data
    },
    putIdResource: async ({
      resourceId,
      content,
      contentType = 'application/json',
      ifMatch,
      ifNoneMatch
    }) => {
      const serialized =
        typeof content === 'string' ? content : JSON.stringify(content)
      // was-client's own PreconditionFailedError propagates as-is: its `name`
      // is exactly what the seam contract names.
      await resource(resourceId).put(new TextEncoder().encode(serialized), {
        contentType,
        ifMatch,
        ifNoneMatch
      })
    }
  }
}

/**
 * Builds the `id`-collection store the account's did:webvh ceremonies read
 * and write through.
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
  return {
    ...wasWebvhLogStore({ was, spaceId, collectionId: ID_COLLECTION.id }),
    putKeyMap: async ({ content }) => {
      await plaintextCollection({
        was,
        spaceId,
        collectionId: KEY_MAP_COLLECTION.id
      })
        .resource(DID_KEYS_RESOURCE)
        .put(new TextEncoder().encode(JSON.stringify(content)), {
          contentType: 'application/json'
        })
    }
  }
}
