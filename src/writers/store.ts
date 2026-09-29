/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The writer roster's storage seam, and its WAS-backed adapter over the
 * `registered-writers` collection.
 *
 * One resource per writer keeps registration, liveness touches, and sweeps
 * off any shared document. Every write the roster logic makes is conditional
 * on the ETag it read, so two sweepers, or a sweeper and a touching writer,
 * cannot overwrite each other's newer write. A lost race surfaces as an error
 * named `PreconditionFailedError`, which the roster logic matches by name.
 */
import type { Collection } from '@interop/was-client'
import type { RegisteredWriterEntry } from './entry.js'

/**
 * One stored resource: its body as read (`undefined` when it could not be
 * read or opened) and its ETag.
 */
export interface StoredRegisteredWriter {
  resourceId: string
  body: unknown
  etag?: string
}

/**
 * The Space-side seam of the roster.
 */
export interface RegisteredWritersStore {
  /**
   * Every resource in the collection. A resource that fails to read or
   * decrypt is listed with an `undefined` body rather than failing the list.
   */
  list(): Promise<StoredRegisteredWriter[]>
  /**
   * One resource, or `undefined` when it does not exist.
   */
  get(options: {
    resourceId: string
  }): Promise<Omit<StoredRegisteredWriter, 'resourceId'> | undefined>
  /**
   * Writes one entry: conditional on `ifMatch`, or create-only under
   * `ifNoneMatch`.
   */
  put(options: {
    resourceId: string
    entry: RegisteredWriterEntry
    ifMatch?: string
    ifNoneMatch?: boolean
  }): Promise<void>
  /**
   * Deletes one resource, conditional on `ifMatch` when given.
   */
  delete(options: { resourceId: string; ifMatch?: string }): Promise<void>
}

/**
 * Builds the roster store over the `registered-writers` collection handle.
 *
 * @param options {object}
 * @param options.collection {Collection}   the account data Space's
 *   `registered-writers` collection, opened through a storage client whose
 *   encryption provider seals and opens it like any other encrypted wallet
 *   collection (and carrying the invocation capability, if any)
 * @returns {RegisteredWritersStore}
 */
export function wasRegisteredWritersStore({
  collection
}: {
  collection: Collection
}): RegisteredWritersStore {
  async function read(
    resourceId: string
  ): Promise<Omit<StoredRegisteredWriter, 'resourceId'> | undefined> {
    const result = await collection.resource(resourceId).getWithEtag()
    if (result === null) {
      return undefined
    }
    return {
      body: result.data,
      ...(result.etag !== undefined && { etag: result.etag })
    }
  }

  return {
    async list() {
      const ids: string[] = []
      for await (const item of collection.listItems()) {
        ids.push(item.id)
      }
      return Promise.all(
        ids.map(async resourceId => {
          try {
            const stored = await read(resourceId)
            return { resourceId, body: stored?.body, etag: stored?.etag }
          } catch {
            return { resourceId, body: undefined }
          }
        })
      )
    },
    async get({ resourceId }) {
      return read(resourceId)
    },
    async put({ resourceId, entry, ifMatch, ifNoneMatch }) {
      await collection.put(resourceId, entry, {
        contentType: 'application/json',
        ...(ifMatch !== undefined && { ifMatch }),
        ...(ifNoneMatch === true && { ifNoneMatch })
      })
    },
    async delete({ resourceId, ifMatch }) {
      await collection
        .resource(resourceId)
        .delete(ifMatch !== undefined ? { ifMatch } : {})
    }
  }
}
