/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The one plaintext-collection handle builder for the wallet's system
 * collections (`id`, `key-map`, `keyring`, and a client-annex generation's
 * `gen-` collection). Every resource in them is either already ciphertext or
 * plain JSON, so none of them goes through the encryption codec.
 *
 * Stating `{ encryption: 'plaintext' }` at every one of those handles is
 * load-bearing twice over, which is why the sites share a builder rather than
 * each remembering the override:
 *
 * - Without it the client decides plaintext vs encrypted by describing the
 *   collection first, and a 404 -- from a Space or collection that does not
 *   exist yet, as on every keyring lookup for a fresh unlock secret -- makes
 *   the client refuse to guess and throw an `EncryptionError`, instead of
 *   surfacing the miss as a 404-shaped `null`.
 * - On a collection the client took as encrypted, the EDV codec computes its
 *   own write preconditions, so a conditional write's compare-and-swap
 *   precondition is not the one that reaches the server -- silently defeating
 *   the CAS guard the resource-log append path and the `did.jsonl` publish
 *   depend on.
 */
import type { Collection, IZcap, WasClient } from '@interop/was-client'

/**
 * A lazy handle to one of the wallet's plaintext system collections. No I/O.
 *
 * @param options {object}
 * @param options.was {WasClient}   the storage client to address it through
 * @param options.spaceId {string}   the Space holding the collection
 * @param options.collectionId {string}
 * @param [options.capability] {IZcap}   an invocation capability every request
 *   through the handle rides; absent, requests invoke the root capability
 * @returns {Collection}
 */
export function plaintextCollection({
  was,
  spaceId,
  collectionId,
  capability
}: {
  was: WasClient
  spaceId: string
  collectionId: string
  capability?: IZcap
}): Collection {
  return was
    .space(spaceId)
    .collection(collectionId, { capability, encryption: 'plaintext' })
}
