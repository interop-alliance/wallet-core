/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * An in-memory `connections` store with ETags, honoring `ifMatch` and
 * `ifNoneMatch` the way the WAS server does, plus the entry builders the
 * directory tests share.
 */
import type {
  ConnectionsStore,
  StoredConnection
} from '../../../src/connections/index.js'

/**
 * A named error, the shape the directory logic matches on.
 *
 * @param name {string}
 * @returns {Error}
 */
export function namedError(name: string): Error {
  const err = new Error(name)
  err.name = name
  return err
}

/**
 * One stored row: its body (or the error a read of it raises) and its ETag.
 */
export interface MemoryRow {
  body?: unknown
  readError?: Error
  etag: string
}

/**
 * Builds the store.
 *
 * @returns {object}
 */
export function memoryConnectionsStore() {
  const rows = new Map<string, MemoryRow>()
  let revision = 0
  const writes: string[] = []
  let missing = false
  const store: ConnectionsStore = {
    async list() {
      if (missing) {
        return null
      }
      return [...rows].map(([resourceId, row]): StoredConnection => {
        if (row.readError !== undefined) {
          return { resourceId, etag: row.etag, readError: row.readError }
        }
        return { resourceId, etag: row.etag, body: structuredClone(row.body) }
      })
    },
    async get({ resourceId }) {
      const row = rows.get(resourceId)
      if (row === undefined) {
        return undefined
      }
      if (row.readError !== undefined) {
        throw row.readError
      }
      return { body: structuredClone(row.body), etag: row.etag }
    },
    async put({ resourceId, body, ifMatch, ifNoneMatch }) {
      const row = rows.get(resourceId)
      if (ifNoneMatch && row !== undefined) {
        throw namedError('PreconditionFailedError')
      }
      if (ifMatch !== undefined && row?.etag !== ifMatch) {
        throw namedError('PreconditionFailedError')
      }
      writes.push(`put:${resourceId}`)
      const etag = `e${++revision}`
      rows.set(resourceId, { body: structuredClone(body), etag })
      return { etag }
    },
    async delete({ resourceId, ifMatch }) {
      const row = rows.get(resourceId)
      if (row === undefined) {
        throw namedError('NotFoundError')
      }
      if (ifMatch !== undefined && row.etag !== ifMatch) {
        throw namedError('PreconditionFailedError')
      }
      writes.push(`delete:${resourceId}`)
      rows.delete(resourceId)
    }
  }
  return {
    store,
    rows,
    writes,
    setMissing(value: boolean) {
      missing = value
    },
    seed(resourceId: string, body: unknown) {
      rows.set(resourceId, {
        body: structuredClone(body),
        etag: `s${++revision}`
      })
    }
  }
}

/**
 * A fixed 32-byte blinded-index key.
 */
export const HMAC_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1)

/**
 * A second account's blinded-index key.
 */
export const OTHER_HMAC_KEY = Uint8Array.from(
  { length: 32 },
  (_, index) => 0xff - index
)

/**
 * This Space's container URL.
 */
export const SPACE_URL = 'https://was.example/space/SPACE/'

/**
 * A delegated capability to `controller` over one collection of this Space.
 *
 * @param options {object}
 * @param options.id {string}
 * @param options.controller {string}
 * @param [options.collection] {string}
 * @param [options.expires] {string}
 * @param [options.target] {string}
 * @returns {object}
 */
export function zcap({
  id,
  controller,
  collection = 'private-credentials',
  expires = '2027-01-01T00:00:00.000Z',
  target
}: {
  id: string
  controller: string
  collection?: string
  expires?: string
  target?: string
}) {
  return {
    '@context': ['https://w3id.org/zcap/v1'],
    id,
    controller,
    parentCapability:
      'urn:zcap:root:https%3A%2F%2Fwas.example%2Fspace%2FSPACE%2F',
    invocationTarget: target ?? `${SPACE_URL}${collection}/`,
    allowedAction: ['GET'],
    expires,
    proof: { type: 'DataIntegrityProof', capabilityChain: [] }
  }
}
