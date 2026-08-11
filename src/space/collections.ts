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
 * The contacts collections (`contacts`, `contacts-history`) keep their identity
 * contract (`collectionId`, `idDerivation`, `mutable`) in `@interop/social-core`
 * (`CONTACTS_COLLECTION_SPEC` / `CONTACTS_HISTORY_COLLECTION_SPEC`) -- the field
 * vocabulary below mirrors that spec. This module does not redeclare those
 * fields; the wallet-Space rosters spread them in and add only the storage
 * attributes that are wallet-Space layout (display name, `encryption`,
 * `isPublic`).
 */
import {
  CONTACTS_COLLECTION_SPEC,
  CONTACTS_HISTORY_COLLECTION_SPEC
} from '@interop/social-core'

/**
 * The app-neutral display name every wallet passes when provisioning the
 * shared Space (the name is set by whichever wallet happens to create the
 * Space, so a per-app name would brand the account with that one app).
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
 * What provisioning a wallet Space collection needs: the collection id, the
 * friendly display name both wallets pass as the server-side collection name,
 * and the storage attributes --
 *
 * - `encryption` -- `'edv'` stores each document as an EDV envelope; `'plaintext'`
 *   stores it verbatim.
 * - `isPublic` -- whether the collection is granted collection-level world read
 *   on the server.
 */
export interface SpaceProvisionSpec {
  collectionId: string
  name: string
  encryption: 'edv' | 'plaintext'
  isPublic: boolean
}

/**
 * A declarative descriptor of a synced wallet Space collection: the
 * provisioning attributes plus the document-identity contract the replication
 * engines need, aligned with `@interop/social-core`'s
 * `CONTACTS_COLLECTION_SPEC` vocabulary --
 *
 * - `idDerivation` -- `'content'` for an append-only, content-addressed log (the
 *   id IS the hash of the stored body) or `'random'` for a mutable head (a
 *   stable id whose body is overwritten).
 * - `mutable` -- whether a document is overwritten in place (`true`) or only
 *   ever appended (`false`).
 */
export interface SpaceCollectionSpec extends SpaceProvisionSpec {
  idDerivation: 'content' | 'random'
  mutable: boolean
}

/**
 * The immutable credential replica: each credential stored as an EDV envelope,
 * addressed by the envelope's content hash, never overwritten, never public.
 */
export const PRIVATE_CREDENTIALS_COLLECTION_SPEC: SpaceCollectionSpec = {
  collectionId: PRIVATE_CREDENTIALS_COLLECTION,
  name: 'Verifiable Credentials',
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
  name: 'Verifiable Credentials (Publicly Shared)',
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
  name: 'Wallet Activity Log',
  idDerivation: 'content',
  mutable: false,
  encryption: 'edv',
  isPublic: false
}

/**
 * The contacts head collection as it sits in the wallet Space: the identity
 * contract (`collectionId`, `idDerivation`, `mutable`) spread from
 * `@interop/social-core`'s `CONTACTS_COLLECTION_SPEC` (which stays its owner),
 * plus the storage attributes that are wallet-Space layout -- each contact a
 * mutable EDV envelope, never public.
 */
export const CONTACTS_SPACE_COLLECTION_SPEC: SpaceCollectionSpec = {
  ...CONTACTS_COLLECTION_SPEC,
  name: 'Contacts',
  encryption: 'edv',
  isPublic: false
}

/**
 * The contacts history log in the wallet Space: identity contract spread from
 * `@interop/social-core`'s `CONTACTS_HISTORY_COLLECTION_SPEC`, stored as
 * append-only, content-addressed EDV envelopes, never public.
 */
export const CONTACTS_HISTORY_SPACE_COLLECTION_SPEC: SpaceCollectionSpec = {
  ...CONTACTS_HISTORY_COLLECTION_SPEC,
  name: 'Contacts History',
  encryption: 'edv',
  isPublic: false
}

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
 *   and the user key wrap-set roster log (`user-key.jsonl`). Kept separate from
 *   `id` exactly so `id` can be made world-readable without ever exposing key
 *   material.
 * - `keyring` -- the unlock Space's single collection, holding the one
 *   keyring record (`keyring.json`). It lives in the minimal unlock Space
 *   controlled by an unlock identity, never in the wallet data Space.
 */
export const ID_COLLECTION = { id: 'id', name: 'Identity' }
export const KEY_MAP_COLLECTION = { id: 'key-map', name: 'Key Map' }
export const KEYRING_COLLECTION = { id: 'keyring', name: 'Keyring' }

/**
 * The `id` collection's provisioning attributes: plaintext (it holds only
 * world-readable DID artifacts) with a collection-level public-read grant.
 */
export const ID_COLLECTION_SPEC: SpaceProvisionSpec = {
  collectionId: ID_COLLECTION.id,
  name: ID_COLLECTION.name,
  encryption: 'plaintext',
  isPublic: true
}

/**
 * The `key-map` collection's provisioning attributes: plaintext (its resources
 * are wrap-sets and key-id maps, protected by capability, not by an EDV
 * envelope) and capability-only -- never public, exactly so `id` can be
 * world-readable without exposing key material.
 */
export const KEY_MAP_COLLECTION_SPEC: SpaceProvisionSpec = {
  collectionId: KEY_MAP_COLLECTION.id,
  name: KEY_MAP_COLLECTION.name,
  encryption: 'plaintext',
  isPublic: false
}

/**
 * The synced wallet Space collections, in provision order: the feeds a wallet
 * both provisions and replicates (each gets a local replica and a sync engine).
 */
export const WALLET_SPACE_SYNCED_SPECS: SpaceCollectionSpec[] = [
  PRIVATE_CREDENTIALS_COLLECTION_SPEC,
  PUBLIC_CREDENTIALS_COLLECTION_SPEC,
  WALLET_ACTIVITY_COLLECTION_SPEC,
  CONTACTS_SPACE_COLLECTION_SPEC,
  CONTACTS_HISTORY_SPACE_COLLECTION_SPEC
]

/**
 * The provisioned-but-not-synced system collections: part of every wallet
 * Space's layout, but no wallet mints a replication feed for them -- their
 * resources (`did.json`, `keys.json`, `user-key.jsonl`, ...) are read and
 * written directly. `keyring` is deliberately absent: it lives in the separate
 * unlock Space, never in the wallet data Space this roster lays out.
 */
export const WALLET_SPACE_SYSTEM_SPECS: SpaceProvisionSpec[] = [
  ID_COLLECTION_SPEC,
  KEY_MAP_COLLECTION_SPEC
]

/**
 * The full wallet Space layout -- every collection the provisioning wallet
 * ensures, synced feeds first. A Space provisioned from this roster is
 * identical no matter which wallet app created it.
 */
export const WALLET_SPACE_PROVISION_ROSTER: SpaceProvisionSpec[] = [
  ...WALLET_SPACE_SYNCED_SPECS,
  ...WALLET_SPACE_SYSTEM_SPECS
]

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
 * The resource log governing the user key wrap-set roster, sibling of
 * `keys.json` in the same private `key-map` collection: the hash-linked
 * history of the roster descriptor (the Resource Log Profile), JSON Lines,
 * one signed entry per line. The verified head entry's state is the roster --
 * a `CollectionEncryption` descriptor whose current epoch IS the current user
 * key (the epoch id is the user key's did:key; the wrapped secret is the user
 * key's raw key, wrapped to each enrolled client's key-agreement key). Read
 * directly with a compare-and-swap etag -- never replicated.
 */
export const USER_KEY_ROSTER_LOG_RESOURCE = 'user-key.jsonl'
/**
 * The enrolled-client display labels, sibling of `keys.json` and
 * `user-key.jsonl` in the same private `key-map` collection: a plain-JSON map
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
