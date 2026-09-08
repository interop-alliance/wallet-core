/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * In-memory `EncryptionDescriptorStore`s keyed by collection id -- the
 * `storeFor` lookup the epoch install and the collection fan-out take, with
 * real create-if-absent and compare-and-swap etag semantics and the injected
 * failures the partial-outcome contracts are about.
 *
 * State lives in one map rather than inside a store closure, so a caller that
 * builds a fresh store per collection (as the real builders do) still sees
 * what an earlier store wrote.
 */
import { PreconditionFailedError } from '@interop/was-client'
import type { CollectionEncryption } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import type { WebvhResourceLogController } from '../../../src/resourceLog/index.js'
import type { SealableEncryptionDescriptorStore } from '../../../src/keys/rosterLogStore.js'

/**
 * What {@link memoryDescriptorStores} hands back: the lookup itself, a reader
 * over the settled descriptors, and the write/anchor records the assertions
 * read.
 */
export interface MemoryDescriptorStores {
  storeFor(collectionId: string): EncryptionDescriptorStore
  descriptorOf(collectionId: string): CollectionEncryption | undefined
  /**
   * Every write, in order, as `<collectionId>` -- one entry per landed
   * `create` or `replace`.
   */
  writes: string[]
  /**
   * Every `setMinimumControllerVersion` a sealable store took, in order --
   * the post-edit anchoring the cascade owes each collection.
   */
  anchors: Array<{
    collectionId: string
    controller: WebvhResourceLogController
  }>
  /**
   * Drops a collection's whole governed state, so its store reads absent
   * again -- the state a collection is in when an earlier run's epoch
   * fan-out never reached it (no governing log, so no descriptor).
   */
  strip(collectionId: string): void
}

/**
 * Builds the lookup.
 *
 * @param [options] {object}
 * @param [options.failFor] {function}   `(collectionId) => boolean` -- every
 *   read for a matching collection throws (a transient server failure)
 * @param [options.rejectNullishFor] {function}   `(collectionId) => boolean`
 *   -- every read for a matching collection rejects with no reason at all
 * @param [options.uncreatableFor] {function}   `(collectionId) => boolean` --
 *   the store carries no `create`, so an absent descriptor cannot be seeded
 *   (a plaintext collection, which has no descriptor to install onto)
 * @param [options.sealable] {boolean}   the stores are
 *   {@link SealableEncryptionDescriptorStore}s, recording every anchoring in
 *   `anchors` (a log-governed collection store)
 * @returns {MemoryDescriptorStores}
 */
export function memoryDescriptorStores({
  failFor,
  rejectNullishFor,
  uncreatableFor,
  sealable = false
}: {
  failFor?: (collectionId: string) => boolean
  rejectNullishFor?: (collectionId: string) => boolean
  uncreatableFor?: (collectionId: string) => boolean
  sealable?: boolean
} = {}): MemoryDescriptorStores {
  const stored = new Map<
    string,
    { descriptor: CollectionEncryption; version: number }
  >()
  const writes: string[] = []
  const anchors: MemoryDescriptorStores['anchors'] = []

  function storeFor(collectionId: string): EncryptionDescriptorStore {
    const base: EncryptionDescriptorStore = {
      async read() {
        if (failFor?.(collectionId)) {
          throw new Error(`Service unavailable for "${collectionId}".`)
        }
        if (rejectNullishFor?.(collectionId)) {
          return Promise.reject()
        }
        const entry = stored.get(collectionId)
        return entry
          ? {
              descriptor: structuredClone(entry.descriptor),
              etag: `v${entry.version}`
            }
          : null
      },
      async replace(next, { ifMatch }: { ifMatch?: string }) {
        const entry = stored.get(collectionId)
        if (!entry || ifMatch !== `v${entry.version}`) {
          throw new PreconditionFailedError('stale descriptor etag')
        }
        entry.descriptor = structuredClone(next)
        entry.version++
        writes.push(collectionId)
      },
      ...(uncreatableFor?.(collectionId)
        ? {}
        : {
            async create(next: CollectionEncryption) {
              if (stored.has(collectionId)) {
                throw new PreconditionFailedError(
                  'the governing log already exists'
                )
              }
              stored.set(collectionId, {
                descriptor: structuredClone(next),
                version: 0
              })
              writes.push(collectionId)
            }
          })
    }
    if (!sealable) {
      return base
    }
    const sealableStore: SealableEncryptionDescriptorStore = {
      ...base,
      async seal() {
        return 'noop'
      },
      setMinimumControllerVersion({ controller }) {
        anchors.push({ collectionId, controller })
      }
    }
    return sealableStore
  }

  return {
    storeFor,
    descriptorOf: collectionId => stored.get(collectionId)?.descriptor,
    writes,
    anchors,
    strip: collectionId => {
      stored.delete(collectionId)
    }
  }
}

/**
 * The sealable decoration a log-governed collection store carries, over any
 * in-memory store: it records the anchoring the cascade owes it and the order
 * of that anchoring against the store's own writes.
 *
 * @param backing {EncryptionDescriptorStore}   an in-memory store carrying
 *   `create`
 * @returns {object}
 */
export function sealableOver(backing: EncryptionDescriptorStore) {
  const anchors: WebvhResourceLogController[] = []
  const events: string[] = []
  return {
    anchors,
    events,
    store: {
      read: () => backing.read(),
      replace: async (descriptor: CollectionEncryption) => {
        events.push('write')
        await backing.replace(descriptor, {})
      },
      create: async (descriptor: CollectionEncryption) => {
        events.push('write')
        await backing.create!(descriptor)
      },
      async seal() {
        return 'noop' as const
      },
      setMinimumControllerVersion({
        controller
      }: {
        controller: WebvhResourceLogController
      }) {
        events.push('anchor')
        anchors.push(controller)
      }
    }
  }
}
