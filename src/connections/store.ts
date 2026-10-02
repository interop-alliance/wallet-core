/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The directory's storage seam, and its WAS-backed adapter over the
 * `connections` collection.
 *
 * One resource per party keeps every write off any shared document. Every
 * write the directory logic makes is conditional: a read-modify-write under
 * `ifMatch`, or a create under `ifNoneMatch`. A lost race surfaces as an error
 * named `PreconditionFailedError`, which the logic matches by name, since the
 * seam may raise from a second copy of was-client.
 *
 * The seam reports what it could not read instead of hiding it. A listing
 * names a resource it could not decrypt, an unknown epoch included, and a
 * `get` that cannot decrypt throws. A reader that turned either into an
 * absent body could evict a party at the next rotation or write over a body
 * it never saw.
 */
import type { Collection, Json, JsonObject } from '@interop/was-client'
import type { DocCipher } from '@interop/was-client/edv/cipher'

/**
 * One resource as a listing read it: its body when it opened, or the error
 * that kept it from opening, and its ETag.
 */
export interface StoredConnection {
  resourceId: string
  etag?: string
  /**
   * The decrypted body. Absent when `readError` is set.
   */
  body?: unknown
  /**
   * Why the body could not be read or opened (an unknown epoch, a key this
   * reader does not hold, an envelope bound to another id). Set only when
   * `body` is absent.
   */
  readError?: unknown
}

/**
 * The Space-side seam of the directory.
 */
export interface ConnectionsStore {
  /**
   * Every resource in the collection, or `null` when the collection is
   * absent or not visible under this authority. A resource that fails to
   * open is listed with its `readError` rather than failing the list.
   */
  list(): Promise<StoredConnection[] | null>
  /**
   * One resource, or `undefined` when it does not exist. A resource that
   * exists and cannot be opened throws.
   */
  get(options: {
    resourceId: string
  }): Promise<{ body: unknown; etag?: string } | undefined>
  /**
   * Writes one body: conditional on `ifMatch`, or create-only under
   * `ifNoneMatch`.
   */
  put(options: {
    resourceId: string
    body: Record<string, unknown>
    ifMatch?: string
    ifNoneMatch?: boolean
  }): Promise<{ etag?: string }>
}

/**
 * Builds the directory store over the `connections` collection handle.
 *
 * A listing reads the collection's documents feed, bodies and ETags, one
 * request per page, and opens each envelope with `cipher` under the resource
 * id the feed served it at. A `get` and a `put` go through the handle, whose
 * encryption provider opens a read and seals a write. A `put` at an id with
 * no resource yet creates the resource there, sealed under the collection's
 * current epoch. The seam has no delete: an entry is retired and never
 * deleted while the account stands.
 *
 * @param options {object}
 * @param options.collection {Collection}   the account data Space's
 *   `connections` collection, opened through a storage client whose
 *   encryption provider seals and opens it like any other encrypted wallet
 *   collection (and carrying the invocation capability, if any)
 * @param options.cipher {object}   the collection's document cipher; only its
 *   `decrypt` is used, to open the envelopes the documents feed serves
 * @returns {ConnectionsStore}
 */
export function wasConnectionsStore({
  collection,
  cipher
}: {
  collection: Collection
  cipher: Pick<DocCipher, 'decrypt'>
}): ConnectionsStore {
  return {
    async list() {
      const documents = await collection.documents()
      if (documents === null) {
        return null
      }
      const context = collection.codecContext()
      return Promise.all(
        documents.map(async doc => {
          const etag = doc.etag !== undefined ? { etag: doc.etag } : {}
          try {
            const body = await cipher.decrypt({
              id: doc.id,
              envelope: doc.data as Json,
              context
            })
            return { resourceId: doc.id, ...etag, body }
          } catch (err) {
            return { resourceId: doc.id, ...etag, readError: err }
          }
        })
      )
    },
    async get({ resourceId }) {
      const result = await collection.resource(resourceId).getWithEtag()
      if (result === null) {
        return undefined
      }
      return {
        body: result.data,
        ...(result.etag !== undefined && { etag: result.etag })
      }
    },
    async put({ resourceId, body, ifMatch, ifNoneMatch }) {
      return collection.put(resourceId, body as JsonObject, {
        contentType: 'application/json',
        ...(ifMatch !== undefined && { ifMatch }),
        ...(ifNoneMatch === true && { ifNoneMatch })
      })
    }
  }
}
