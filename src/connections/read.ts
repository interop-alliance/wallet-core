/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The directory listing read: one pass over the store, each body parsed and
 * checked against the resource id it sits at.
 *
 * Every lookup by DID outside consent resolves against this one read,
 * matching on the decrypted `id` in memory. A wallet does not GET the id a DID
 * derives to just to look the party up, since the host would then learn which
 * id belongs to which DID and whether that DID has an entry.
 */
import { isJsonObject, parseConnectionEntry } from './entry.js'
import type { ConnectionEntry } from './entry.js'
import { connectionResourceId } from './resourceId.js'
import type { ConnectionIdKey } from './resourceId.js'
import type { ConnectionsStore } from './store.js'

/**
 * One entry a listing found at its own resource id.
 */
export interface ReadConnection {
  resourceId: string
  etag?: string
  /**
   * The members this build knows, as the codec read them.
   */
  entry: ConnectionEntry
  /**
   * The stored body verbatim, every member included. A writer starts from
   * this so the members it does not own survive.
   */
  body: Record<string, unknown>
}

/**
 * What one listing read found. A resource that sits at an id its own `id`
 * (or its one writer) does not derive to is ignored and reported nowhere: it
 * is a copy, a misplaced write, or a planted body, and labels nothing.
 */
export interface ConnectionsListing {
  /**
   * The parseable entries at their own ids, newer-version ones included.
   */
  entries: ReadConnection[]
  /**
   * Resources the store could not open (an unknown epoch, a key this reader
   * does not hold).
   */
  unreadable: string[]
  /**
   * Resources at their own id whose body the codec refuses. Such a body may
   * still vouch for a party this build cannot see.
   */
  unparseable: string[]
}

/**
 * The resource id a stored body claims by its own members: its `id`, or its
 * one writer's `writerId` when it carries no `id`. `undefined` when the body
 * names neither.
 *
 * @param options {object}
 * @param options.body {unknown}
 * @param options.hmacKey {ConnectionIdKey}
 * @returns {Promise<string | undefined>}
 */
export async function claimedResourceId({
  body,
  hmacKey
}: {
  body: unknown
  hmacKey: ConnectionIdKey
}): Promise<string | undefined> {
  if (!isJsonObject(body)) {
    return undefined
  }
  if (typeof body.id === 'string') {
    return connectionResourceId({ hmacKey, did: body.id })
  }
  const writers = body.writers
  if (Array.isArray(writers) && writers.length === 1) {
    const [writer] = writers as unknown[]
    if (isJsonObject(writer) && typeof writer.writerId === 'string') {
      return connectionResourceId({ hmacKey, writerId: writer.writerId })
    }
  }
  return undefined
}

/**
 * Reads the whole directory once. Returns `null` when the collection is
 * absent or not visible, which a caller deciding anything about a party
 * treats as a failure rather than as an empty directory.
 *
 * @param options {object}
 * @param options.store {ConnectionsStore}
 * @param options.hmacKey {ConnectionIdKey}   the collection's blinded-index
 *   key
 * @returns {Promise<ConnectionsListing | null>}
 */
export async function readConnections({
  store,
  hmacKey
}: {
  store: ConnectionsStore
  hmacKey: ConnectionIdKey
}): Promise<ConnectionsListing | null> {
  const stored = await store.list()
  if (stored === null) {
    return null
  }
  const listing: ConnectionsListing = {
    entries: [],
    unreadable: [],
    unparseable: []
  }
  // The claimed ids are independent HMACs, derived together rather than one
  // awaited at a time when the key is the async `sign` form.
  const claims = await Promise.all(
    stored.map(item =>
      item.readError !== undefined || item.body === undefined
        ? undefined
        : claimedResourceId({ body: item.body, hmacKey })
    )
  )
  for (const [index, item] of stored.entries()) {
    if (item.readError !== undefined || item.body === undefined) {
      listing.unreadable.push(item.resourceId)
      continue
    }
    if (claims[index] !== item.resourceId) {
      continue
    }
    const entry = parseConnectionEntry(item.body)
    if (entry === undefined) {
      listing.unparseable.push(item.resourceId)
      continue
    }
    listing.entries.push({
      resourceId: item.resourceId,
      ...(item.etag !== undefined && { etag: item.etag }),
      entry,
      body: item.body as Record<string, unknown>
    })
  }
  return listing
}

/**
 * The listed entry whose `id` is the given DID, matched in memory.
 *
 * @param options {object}
 * @param options.listing {ConnectionsListing}
 * @param options.did {string}
 * @returns {ReadConnection | undefined}
 */
export function findConnection({
  listing,
  did
}: {
  listing: ConnectionsListing
  did: string
}): ReadConnection | undefined {
  return listing.entries.find(item => item.entry.id === did)
}
