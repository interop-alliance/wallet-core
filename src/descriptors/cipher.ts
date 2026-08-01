/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A self-refreshing EDV document cipher: `createEdvDocCipher` bound to
 * descriptor acquisition and the once-per-session refresh rule, for a host
 * whose decrypt seam is the cipher itself (a sync engine's `decryptDoc`, a
 * conflict resolver) rather than a row-scanning store.
 *
 * Built, the cipher acquires the collection's descriptor (fetch, cache the
 * success, cached fallback on failure -- see `acquire.ts`) and constructs the
 * underlying EDV cipher from it; with no descriptor, or a descriptor with no
 * epochs, that is the single-key path, unchanged. When a decrypt throws
 * `UnknownEpochError`, the cipher re-acquires the descriptor, rebuilds itself,
 * and retries that decrypt exactly once -- and only once per cipher instance,
 * which the host scopes to one `(profile, collection)` session by dropping
 * its cipher cache when the session ends. A second failure (or any unknown
 * epoch after the one refresh is spent) propagates.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import {
  createEdvDocCipher,
  UnknownEpochError,
  type DocCipher
} from '@interop/was-client/edv'
import {
  acquireDescriptor,
  type EncryptionDescriptorCache,
  type EncryptionDescriptorSource
} from './acquire.js'

/**
 * Builds a {@link DocCipher} whose descriptor is acquired through the
 * source/cache seams and refreshed (once per instance) on an unknown-epoch
 * decrypt.
 *
 * With no `source` the descriptor is served from the cache alone and the
 * refresh path is inert (an unknown-epoch decrypt propagates immediately) --
 * the shape for a purely local code path that must never touch the network.
 *
 * @param options {object}
 * @param options.keyAgreementKey {IKeyAgreementKey}   the vault key pair this
 *   collection's envelopes are sealed to
 * @param options.keyResolver {IKeyResolver}
 * @param options.collectionId {string}
 * @param [options.idDerivation] {'content' | 'random'}   defaults to
 *   `'content'`
 * @param [options.source] {EncryptionDescriptorSource}
 * @param options.cache {EncryptionDescriptorCache}
 * @param [options.onFetchError] {function}   observes swallowed
 *   descriptor-fetch failures
 * @returns {Promise<DocCipher>}
 */
export async function createRefreshingEdvDocCipher({
  keyAgreementKey,
  keyResolver,
  collectionId,
  idDerivation,
  source,
  cache,
  onFetchError
}: {
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  collectionId: string
  idDerivation?: 'content' | 'random'
  source?: EncryptionDescriptorSource
  cache: EncryptionDescriptorCache
  onFetchError?: (err: unknown, info: { collectionId: string }) => void
}): Promise<DocCipher> {
  const build = async (): Promise<DocCipher> =>
    createEdvDocCipher({
      keyAgreementKey,
      keyResolver,
      collectionId,
      idDerivation,
      encryption: await acquireDescriptor({
        source,
        cache,
        collectionId,
        onFetchError
      })
    })

  let inner = await build()
  // The one descriptor refresh this cipher instance (= this collection this
  // session) may spend, shared so concurrent unknown-epoch decrypts ride a
  // single re-read instead of each spending one.
  let refreshed: Promise<void> | null = null

  return {
    encrypt: options => inner.encrypt(options),

    encryptUpdate: options => {
      if (!inner.encryptUpdate) {
        throw new Error(
          `Collection "${collectionId}" cipher has no in-place update.`
        )
      }
      return inner.encryptUpdate(options)
    },

    async decrypt({ envelope }) {
      try {
        return await inner.decrypt({ envelope })
      } catch (err) {
        if (!(err instanceof UnknownEpochError) || !source) {
          throw err
        }
        refreshed ??= build().then(cipher => {
          inner = cipher
        })
        await refreshed
        // One retry under the swapped cipher. If the refresh was already
        // spent before this decrypt began, this re-attempt is a local
        // no-network decrypt that fails the same way -- so a genuinely
        // foreign envelope still surfaces UnknownEpochError, and never a
        // second description read.
        return inner.decrypt({ envelope })
      }
    }
  }
}
