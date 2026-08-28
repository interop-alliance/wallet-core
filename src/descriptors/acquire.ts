/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Collection encryption-descriptor acquisition: reading a collection's
 * `CollectionEncryption` descriptor (its key-epoch roster) from the Collection
 * Description, caching each success, and falling back to the cached copy
 * whenever the description yields no descriptor -- whether it could not be
 * fetched at all (offline, a collection must keep encrypting under its current
 * epoch) or came back empty (WAS masks an unauthorized read as an absent one,
 * so an empty description is ambiguous, never an authoritative "no
 * encryption"). `undefined` therefore means only this: nothing, fetched or
 * cached, describes this collection's encryption -- a plaintext collection, or
 * an encrypted one whose epoch[0] install has not landed. A caller that has
 * declared the collection encrypted must refuse fail-closed rather than
 * encrypt without a roster.
 *
 * The two seams are deliberately narrow, so a wallet app's own classes satisfy
 * them structurally -- no adapter needed. An {@link EncryptionDescriptorSource}
 * is one signed describe; an {@link EncryptionDescriptorCache} is a
 * client-local get/put the host has already scoped to one account's Space (a
 * web wallet: a localStorage pair keyed by Space id; a mobile wallet: a
 * per-(profile, collection) table column), so no scope key appears in the
 * interface.
 */
import type { CollectionEncryption, WasClient } from '@interop/was-client'

/**
 * Whether a thrown fetch failure is a resource-log refusal the cache must NOT
 * paper over: a fabricated log (`ResourceLogIntegrityError`), or a log that
 * is not the continuation of the pinned history
 * (`ResourceLogContinuityError`) -- EXCEPT continuity reason `rollback`,
 * which is reconcilable divergence (possibly replication lag): the pin is
 * never regressed and nothing rolled-back is adopted, so serving the cached
 * copy in the meantime is exactly the offline case. Matched on `err.name`
 * rather than `instanceof`, which keeps this file dependency-light and
 * survives a linked or duplicated copy of the package.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
function isLogRefusal(err: unknown): boolean {
  const name = (err as { name?: unknown } | null)?.name
  if (name === 'ResourceLogIntegrityError') {
    return true
  }
  return (
    name === 'ResourceLogContinuityError' &&
    (err as { reason?: unknown }).reason !== 'rollback'
  )
}

/**
 * Where descriptors come from: one signed read of the collection's
 * Description. Resolves `undefined` when the description carries no encryption
 * member -- which a WAS host also serves for a read this client is not
 * authorized to make, so the absence is ambiguous and callers fall back to a
 * cached copy just as they do for a thrown fetch. Network errors throw through
 * (callers treat the fetch as best-effort).
 */
export interface EncryptionDescriptorSource {
  collectionEncryption(options: {
    collectionId: string
  }): Promise<CollectionEncryption | undefined>
}

/**
 * Where fetched descriptors survive offline: a client-local get/put
 * pre-scoped by the host to one account's Space. `readDescriptor` resolves
 * `undefined` when nothing is cached (never throws for absence).
 */
export interface EncryptionDescriptorCache {
  readDescriptor(options: {
    collectionId: string
  }): Promise<CollectionEncryption | undefined>
  writeDescriptor(options: {
    collectionId: string
    descriptor: CollectionEncryption
  }): Promise<void>
}

/**
 * The {@link EncryptionDescriptorSource} over a was-client handle: reads the
 * collection's Description in the given Space and returns its `encryption`
 * descriptor.
 *
 * @param options {object}
 * @param options.was {WasClient}   a client whose signer can read the Space
 * @param options.spaceId {string}
 * @returns {EncryptionDescriptorSource}
 */
export function wasDescriptorSource({
  was,
  spaceId
}: {
  was: WasClient
  spaceId: string
}): EncryptionDescriptorSource {
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
 * Acquires one collection's descriptor: fetches it from the source, caching a
 * success; falls back to the cached copy whenever the fetch yields no
 * descriptor (it threw, or it came back empty -- a masked 404 for an
 * unauthorized read looks exactly like an unencrypted collection); and with no
 * source at all (a purely local code path) reads the cache alone. Any cached
 * copy is deliberately left in place, never cleared by an empty fetch.
 * `undefined` means no descriptor exists anywhere for this collection.
 *
 * @param options {object}
 * @param [options.source] {EncryptionDescriptorSource}   omit for cache-only
 *   acquisition
 * @param options.cache {EncryptionDescriptorCache}
 * @param options.collectionId {string}
 * @param [options.onFetchError] {function}   observes a swallowed fetch
 *   failure (the thrown-fetch branch only; an empty description is not an
 *   error). Errors from the cache itself throw through, as do a log-governed
 *   source's refusal classes (a fabricated or discontinuous log is a security
 *   signal, not an outage the cache should paper over) -- except a continuity
 *   `rollback`, which falls back to the cache like any transport hiccup
 * @returns {Promise<CollectionEncryption | undefined>}
 */
export async function acquireDescriptor({
  source,
  cache,
  collectionId,
  onFetchError
}: {
  source?: EncryptionDescriptorSource
  cache: EncryptionDescriptorCache
  collectionId: string
  onFetchError?: (err: unknown, info: { collectionId: string }) => void
}): Promise<CollectionEncryption | undefined> {
  if (!source) {
    return cache.readDescriptor({ collectionId })
  }
  try {
    const fetched = await source.collectionEncryption({ collectionId })
    if (fetched) {
      await cache.writeDescriptor({ collectionId, descriptor: fetched })
      return fetched
    }
    // Empty description: not authoritative (an unauthorized read is masked as
    // an absent one), so a warm cache still serves the collection.
    return cache.readDescriptor({ collectionId })
  } catch (err) {
    if (isLogRefusal(err)) {
      throw err
    }
    onFetchError?.(err, { collectionId })
    return cache.readDescriptor({ collectionId })
  }
}

/**
 * Acquires descriptors for a set of collections concurrently (each fetch is an
 * independent signed round trip, so a session start is not gated on a serial
 * chain of describes). Collections that resolve no descriptor are simply
 * absent from the result.
 *
 * @param options {object}
 * @param [options.source] {EncryptionDescriptorSource}   omit for cache-only
 *   acquisition
 * @param options.cache {EncryptionDescriptorCache}
 * @param options.collectionIds {string[]}
 * @param [options.onFetchError] {function}   observes each swallowed fetch
 *   failure
 * @returns {Promise<Record<string, CollectionEncryption>>}   keyed by
 *   collection id
 */
export async function acquireDescriptors({
  source,
  cache,
  collectionIds,
  onFetchError
}: {
  source?: EncryptionDescriptorSource
  cache: EncryptionDescriptorCache
  collectionIds: string[]
  onFetchError?: (err: unknown, info: { collectionId: string }) => void
}): Promise<Record<string, CollectionEncryption>> {
  const resolved = await Promise.all(
    collectionIds.map(
      async collectionId =>
        [
          collectionId,
          await acquireDescriptor({ source, cache, collectionId, onFetchError })
        ] as const
    )
  )
  const descriptors: Record<string, CollectionEncryption> = {}
  for (const [collectionId, descriptor] of resolved) {
    if (descriptor) {
      descriptors[collectionId] = descriptor
    }
  }
  return descriptors
}
