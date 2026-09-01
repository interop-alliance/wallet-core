/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The WAS-backed adapter for the enrolled-client display labels
 * (`key-map/client-labels.json`): the {@link ClientLabelsStore} seam the label
 * helpers read and write through, over the same private, plaintext `key-map`
 * collection the wrap-set roster lives in. Every wallet app on the account
 * shares this one implementation, so they share one record.
 */
import type { WasClient } from '@interop/was-client'
import {
  CLIENT_LABELS_RESOURCE,
  KEY_MAP_COLLECTION
} from '../space/collections.js'
import { plaintextCollection } from '../space/plaintextCollection.js'
import type { ClientLabelsStore } from './clientLabels.js'

/**
 * Builds the labels store over `key-map/client-labels.json` in a data Space.
 *
 * @param options {object}
 * @param options.was {WasClient}   the account's storage client, signing as an
 *   enrolled client
 * @param options.spaceId {string}   the data Space id
 * @returns {ClientLabelsStore}
 */
export function wasClientLabelsStore({
  was,
  spaceId
}: {
  was: WasClient
  spaceId: string
}): ClientLabelsStore {
  const resource = plaintextCollection({
    was,
    spaceId,
    collectionId: KEY_MAP_COLLECTION.id
  }).resource(CLIENT_LABELS_RESOURCE)
  return {
    async get() {
      const result = await resource.get()
      return result === null ? undefined : result
    },
    async put({ content }: { content: object }) {
      const body = new TextEncoder().encode(JSON.stringify(content))
      await resource.put(body, { contentType: 'application/json' })
    }
  }
}
