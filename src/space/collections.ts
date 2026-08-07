/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The shared wallet Space layout: the collection ids and descriptive specs both
 * wallet replicas provision, so a credential written by one is found and read by
 * the other. Both replicas MUST agree on every field here -- `collectionId`
 * decides where a document lands on the server, `idDerivation` and `mutable`
 * decide whether it is overwritten in place or only appended, and `encryption` /
 * `isPublic` decide how it is stored and who can read it. A disagreement splits
 * the feed into separate or incompatibly-shaped collections that never converge.
 *
 * The contacts collections (`contacts`, `contacts-history`) are NOT declared
 * here: their ids and specs live in `@interop/social-core`
 * (`CONTACTS_COLLECTION_SPEC` / `CONTACTS_HISTORY_COLLECTION_SPEC`), which apps
 * import directly. The field vocabulary below mirrors that spec.
 */

/**
 * The app-neutral display name every wallet passes when provisioning the
 * shared Space (`space.configure({ name })` re-runs on provisioning, so a
 * per-app name would flip to whichever wallet provisioned last).
 */
export const WALLET_SPACE_NAME = 'Wallet Space'

/**
 * The immutable, content-addressed, EDV-encrypted credential replica.
 */
export const PRIVATE_CREDENTIALS_COLLECTION = 'private-credentials'
/**
 * The plaintext, world-readable copies of publicly shared credentials.
 */
export const PUBLIC_CREDENTIALS_COLLECTION = 'public-credentials'
/**
 * The append-only, EDV-encrypted wallet activity log.
 */
export const WALLET_ACTIVITY_COLLECTION = 'wallet-activity'

/**
 * A declarative descriptor of a synced wallet Space collection, aligned with
 * `@interop/social-core`'s `CONTACTS_COLLECTION_SPEC` vocabulary and extended
 * with the storage attributes the wallet Space needs:
 *
 * - `idDerivation` -- `'content'` for an append-only, content-addressed log (the
 *   id IS the hash of the stored body) or `'random'` for a mutable head (a
 *   stable id whose body is overwritten).
 * - `mutable` -- whether a document is overwritten in place (`true`) or only
 *   ever appended (`false`).
 * - `encryption` -- `'edv'` stores each document as an EDV envelope; `'plaintext'`
 *   stores it verbatim.
 * - `isPublic` -- whether the collection is granted collection-level world read
 *   on the server.
 */
export interface SpaceCollectionSpec {
  collectionId: string
  idDerivation: 'content' | 'random'
  mutable: boolean
  encryption: 'edv' | 'plaintext'
  isPublic: boolean
}

/**
 * The immutable credential replica: each credential stored as an EDV envelope,
 * addressed by the envelope's content hash, never overwritten, never public.
 */
export const PRIVATE_CREDENTIALS_COLLECTION_SPEC: SpaceCollectionSpec = {
  collectionId: PRIVATE_CREDENTIALS_COLLECTION,
  idDerivation: 'content',
  mutable: false,
  encryption: 'edv',
  isPublic: false
}

/**
 * The plaintext, world-readable copies of shared credentials, keyed by the
 * credential's content cid (the same id every replica mints, so a share
 * converges), granted collection-level world read on the server.
 */
export const PUBLIC_CREDENTIALS_COLLECTION_SPEC: SpaceCollectionSpec = {
  collectionId: PUBLIC_CREDENTIALS_COLLECTION,
  idDerivation: 'content',
  mutable: false,
  encryption: 'plaintext',
  isPublic: true
}

/**
 * The append-only activity log: each entry stored as an EDV envelope, addressed
 * by content hash, never overwritten, never public. Shared with the web wallet's
 * `wallet-activity` collection, so each replica reads the other's entries.
 */
export const WALLET_ACTIVITY_COLLECTION_SPEC: SpaceCollectionSpec = {
  collectionId: WALLET_ACTIVITY_COLLECTION,
  idDerivation: 'content',
  mutable: false,
  encryption: 'edv',
  isPublic: false
}

/**
 * The wallet Space's own (non-contacts) collection specs, in provision order.
 */
export const WALLET_SPACE_COLLECTION_SPECS: SpaceCollectionSpec[] = [
  PRIVATE_CREDENTIALS_COLLECTION_SPEC,
  PUBLIC_CREDENTIALS_COLLECTION_SPEC,
  WALLET_ACTIVITY_COLLECTION_SPEC
]

/**
 * The system collections and resource names that carry an account's identity
 * and key material. They sit deliberately OUTSIDE the synced collection specs
 * above: none of them gets a local replica or background replication, and each
 * is read and written directly.
 *
 * - `id` -- world-readable (a collection-level public-read policy): the
 *   published DID document (`did.json`) and the did:webvh history log
 *   (`did.jsonl`). The path segments name the collection that holds the
 *   document, so the did:web id is `did:web:<host>:space:<spaceId>:id` and
 *   resolves to `https://<host>/space/<spaceId>/id/did.json`.
 * - `key-map` -- private and capability-gated: the key-id map (`keys.json`)
 *   and the user key wrap-set roster (`user-key.json`). Kept separate from `id` exactly
 *   so `id` can be made world-readable without ever exposing key material.
 * - `keyring` -- the unlock Space's single collection, holding the one
 *   keyring record (`keyring.json`). It lives in the minimal unlock Space
 *   controlled by an unlock identity, never in the wallet data Space.
 */
export const ID_COLLECTION = { id: 'id', name: 'Identity' }
export const KEY_MAP_COLLECTION = { id: 'key-map', name: 'Key Map' }
export const KEYRING_COLLECTION = { id: 'keyring', name: 'Keyring' }

/**
 * The world-readable DID document, served as `application/did+json`.
 */
export const DID_DOCUMENT_RESOURCE = 'did.json'
/**
 * The world-readable did:webvh history log, a raw JSON-Lines string served as
 * `text/jsonl`: one log entry per line, each a full DID-document snapshot in a
 * hash chain. Sibling of `did.json` in the same `id` collection;
 * `did:webvh:<scid>:<host>:space:<spaceId>:id` resolves to
 * `https://<host>/space/<spaceId>/id/did.jsonl`.
 */
export const DID_LOG_RESOURCE = 'did.jsonl'
/**
 * The (non-public) key-id map: verification method to KMS key id. Lives in the
 * `key-map` collection. The recovery anchor -- written before `did.json` so a
 * torn provisioning resumes from it.
 */
export const DID_KEYS_RESOURCE = 'keys.json'
/**
 * The per-user-key (user key) wrap-set roster, sibling of `keys.json` in the
 * same private `key-map` collection: a `CollectionEncryption` descriptor stored
 * verbatim as the resource body, whose current epoch IS the current user key
 * (the epoch id is the user key's did:key; the wrapped secret is the user key's
 * raw key, wrapped to each enrolled client's key-agreement key). Read directly
 * with a compare-and-swap etag -- never replicated.
 */
export const USER_KEY_ROSTER_RESOURCE = 'user-key.json'
/**
 * The enrolled-client display labels, sibling of `keys.json` and
 * `user-key.json` in the same private `key-map` collection: a plain-JSON map
 * from a client's signing-key multibase to its human-chosen label. Display
 * metadata only -- the did:webvh document carries key material, never labels --
 * and plaintext by the collection's convention: the storage host can read the
 * labels, but it already serves the world-readable log that names every client
 * key, so a label adds only the display name.
 */
export const CLIENT_LABELS_RESOURCE = 'client-labels.json'
/**
 * The keyring record: the encrypted account pointer, in the unlock Space.
 */
export const KEYRING_RESOURCE = 'keyring.json'
