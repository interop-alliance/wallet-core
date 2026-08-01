/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Collection-encryption marker acquisition: reading a collection's
 * `CollectionEncryption` marker (its key-epoch roster) from the Collection
 * Description, caching each success, and falling back to the cached copy when
 * the description cannot be fetched -- offline, a previously-shared collection
 * must keep encrypting under its current epoch. A successful fetch that
 * returns no marker (an unshared collection) yields `undefined`: the
 * single-key path.
 *
 * The two seams are deliberately narrow, so a wallet app's own classes satisfy
 * them structurally -- no adapter needed. A {@link MarkerSource} is one signed
 * describe; a {@link MarkerCache} is a durable get/put the host has already
 * scoped to one account's Space (a web wallet: a localStorage pair keyed by
 * Space id; a mobile wallet: a per-(profile, collection) table column), so no
 * scope key appears in the interface.
 */
import type { CollectionEncryption, WasClient } from '@interop/was-client'

/**
 * Where markers come from: one signed read of the collection's Description.
 * Resolves `undefined` for a collection that is plaintext or has no marker;
 * network errors throw through (callers treat the fetch as best-effort and
 * fall back to a cached copy).
 */
export interface MarkerSource {
  collectionEncryption(options: {
    collectionId: string
  }): Promise<CollectionEncryption | undefined>
}

/**
 * Where fetched markers survive offline: a durable get/put pre-scoped by the
 * host to one account's Space. `readMarker` resolves `undefined` when nothing
 * is cached (never throws for absence).
 */
export interface MarkerCache {
  readMarker(options: {
    collectionId: string
  }): Promise<CollectionEncryption | undefined>
  writeMarker(options: {
    collectionId: string
    marker: CollectionEncryption
  }): Promise<void>
}

/**
 * The {@link MarkerSource} over a was-client handle: reads the collection's
 * Description in the given Space and returns its `encryption` marker.
 *
 * @param options {object}
 * @param options.was {WasClient}   a client whose signer can read the Space
 * @param options.spaceId {string}
 * @returns {MarkerSource}
 */
export function wasMarkerSource({
  was,
  spaceId
}: {
  was: WasClient
  spaceId: string
}): MarkerSource {
  return {
    async collectionEncryption({ collectionId }) {
      const description = await was
        .space(spaceId)
        .collection(collectionId)
        .describe()
      return description?.encryption ?? undefined
    }
  }
}

/**
 * Acquires one collection's marker: fetches it from the source, caching a
 * success; falls back to the cached copy when the fetch fails; and with no
 * source at all (a purely local code path) reads the cache alone. A
 * successful fetch that returns no marker resolves `undefined` -- an unshared
 * collection stays on the single-key path -- and deliberately leaves any
 * cached copy in place, mirroring the fetch-failure fallback.
 *
 * @param options {object}
 * @param [options.source] {MarkerSource}   omit for cache-only acquisition
 * @param options.cache {MarkerCache}
 * @param options.collectionId {string}
 * @param [options.onFetchError] {function}   observes a swallowed fetch
 *   failure (the cached-fallback branch); errors from the cache itself throw
 *   through
 * @returns {Promise<CollectionEncryption | undefined>}
 */
export async function acquireMarker({
  source,
  cache,
  collectionId,
  onFetchError
}: {
  source?: MarkerSource
  cache: MarkerCache
  collectionId: string
  onFetchError?: (err: unknown, info: { collectionId: string }) => void
}): Promise<CollectionEncryption | undefined> {
  if (!source) {
    return cache.readMarker({ collectionId })
  }
  try {
    const fetched = await source.collectionEncryption({ collectionId })
    if (fetched) {
      await cache.writeMarker({ collectionId, marker: fetched })
      return fetched
    }
    return undefined
  } catch (err) {
    onFetchError?.(err, { collectionId })
    return cache.readMarker({ collectionId })
  }
}

/**
 * Acquires markers for a set of collections concurrently (each fetch is an
 * independent signed round trip, so a session start is not gated on a serial
 * chain of describes). Collections that resolve no marker are simply absent
 * from the result.
 *
 * @param options {object}
 * @param [options.source] {MarkerSource}   omit for cache-only acquisition
 * @param options.cache {MarkerCache}
 * @param options.collectionIds {string[]}
 * @param [options.onFetchError] {function}   observes each swallowed fetch
 *   failure
 * @returns {Promise<Record<string, CollectionEncryption>>}   keyed by
 *   collection id
 */
export async function acquireMarkers({
  source,
  cache,
  collectionIds,
  onFetchError
}: {
  source?: MarkerSource
  cache: MarkerCache
  collectionIds: string[]
  onFetchError?: (err: unknown, info: { collectionId: string }) => void
}): Promise<Record<string, CollectionEncryption>> {
  const resolved = await Promise.all(
    collectionIds.map(
      async collectionId =>
        [
          collectionId,
          await acquireMarker({ source, cache, collectionId, onFetchError })
        ] as const
    )
  )
  const markers: Record<string, CollectionEncryption> = {}
  for (const [collectionId, marker] of resolved) {
    if (marker) {
      markers[collectionId] = marker
    }
  }
  return markers
}
