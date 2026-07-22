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

/** The immutable, content-addressed, EDV-encrypted credential replica. */
export const PRIVATE_CREDENTIALS_COLLECTION = 'private-credentials'
/** The plaintext, world-readable copies of publicly shared credentials. */
export const PUBLIC_CREDENTIALS_COLLECTION = 'public-credentials'
/** The append-only, EDV-encrypted wallet activity log. */
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

/** The wallet Space's own (non-contacts) collection specs, in provision order. */
export const WALLET_SPACE_COLLECTION_SPECS: SpaceCollectionSpec[] = [
  PRIVATE_CREDENTIALS_COLLECTION_SPEC,
  PUBLIC_CREDENTIALS_COLLECTION_SPEC,
  WALLET_ACTIVITY_COLLECTION_SPEC
]
