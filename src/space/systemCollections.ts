/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The system collection ids and the keyring resource name -- an import-free
 * leaf, so a consumer that only needs to name the `id` / `key-map` /
 * `unlock-methods` / `keyring` collections (or the keyring record's resource
 * name) loads neither the Space layout module nor `@interop/social-core`.
 * `collections.ts` re-exports these names, so every existing importer keeps
 * working unchanged.
 */

/**
 * The system collections and resource names that carry an account's identity
 * and key material. They sit deliberately OUTSIDE the synced collection specs
 * in `collections.ts`: none of them gets a local replica or background replication, and each
 * is read and written directly.
 *
 * - `id` -- world-readable (a collection-level public-read policy): the
 *   published DID document (`did.json`) and the did:webvh history log
 *   (`did.jsonl`). The path segments name the collection that holds the
 *   document, so the did:web id is `did:web:<host>:space:<spaceId>:id` and
 *   resolves to `https://<host>/space/<spaceId>/id/did.json`.
 * - `key-map` -- private and capability-gated: the key-id map (`keys.json`)
 *   and the user key wrap-set roster log (`user-key.jsonl`). Kept separate from
 *   `id` exactly so `id` can be made world-readable without ever exposing key
 *   material. No capability to it should be delegated to a third party: the
 *   roster names a passphrase credential by its passphrase-derived key, beside
 *   a wrap of the user key, so a reader can test passphrase guesses offline.
 * - `unlock-methods` -- private and capability-gated: the account's
 *   unlock-method registry (`methods.json`), the records describing how the
 *   account can be unlocked (passphrase, passkeys). The record is sealed to
 *   the user key and signed by the key the user key derives, since its
 *   entries carry each method's management capability. It lives in the
 *   wallet data Space, not the unlock Space.
 * - `keyring` -- the unlock Space's single collection, holding the one
 *   keyring record (`keyring.json`). It lives in the minimal unlock Space
 *   controlled by an unlock identity, never in the wallet data Space.
 */
export const ID_COLLECTION = { id: 'id', name: 'Identity' }
export const KEY_MAP_COLLECTION = { id: 'key-map', name: 'Key Map' }
export const UNLOCK_METHODS_COLLECTION = {
  id: 'unlock-methods',
  name: 'Unlock Methods'
}
export const KEYRING_COLLECTION = { id: 'keyring', name: 'Keyring' }

/**
 * The keyring record: the encrypted account pointer, in the unlock Space.
 */
export const KEYRING_RESOURCE = 'keyring.json'
