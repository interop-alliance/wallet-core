/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The unlock Space: a minimal second Space, controlled by an unlock identity
 * and separate from the wallet data Space, holding the one keyring record.
 * These are standalone functions rather than methods on a wallet's remote-store
 * class (that store is bound to the data identity): each builds its own
 * `WasClient` over the caller's `zcapClient`. By default that is the unlock
 * agent's, whose invocation signer is the unlock root key (root invocation,
 * no capability attached -- the same invocation shape the data Space uses).
 * Each read/write/delete also takes an optional `capability`: an enrolled
 * client's `zcapClient` then invokes the management zcap the unlock identity
 * delegated at bind time, which is how a ceremony reaches an unlock Space
 * without holding its secret (the revocation cascade's re-mint reading and
 * re-PUTting a recovery code's standing record, or a lost unlock method's
 * Space being retired).
 *
 * The one resource is a plaintext JSON document (its keyring payload is
 * already ciphertext), so no encryption provider is wired in and every
 * read/write handle is built by {@link plaintextCollection} -- load-bearing
 * here for the absent Space a fresh unlock secret's keyring lookup meets.
 */
import { WasClient } from '@interop/was-client'
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { KEYRING_COLLECTION, KEYRING_RESOURCE } from '../space/collections.js'
import { plaintextCollection } from '../space/plaintextCollection.js'

/**
 * The default Space Description name an unlock Space is configured with.
 * Wire-visible (it is the Space's stored name), so it stays stable across
 * apps unless a caller deliberately overrides it.
 */
export const UNLOCK_SPACE_NAME = 'Freewallet Keyring'

/**
 * The bare WAS client for an unlock Space (see the module doc for why it wires
 * in no encryption provider).
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}   built on the unlock agent's signer
 * @returns {WasClient}
 */
function unlockSpaceClient({
  storageServerUrl,
  zcapClient
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
}): WasClient {
  return new WasClient({
    serverUrl: storageServerUrl,
    zcapClient
  })
}

/**
 * Ensures a plaintext collection exists in a Space (upsert -- idempotent),
 * running with the invoking client's root capability so `force` lets the upsert
 * treat a 404 from the pre-merge describe as genuinely absent rather than
 * unreadable.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param options.name {string}
 * @returns {Promise<void>}
 */
async function ensurePlaintextCollection({
  storageServerUrl,
  zcapClient,
  spaceId,
  collectionId,
  name
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  collectionId: string
  name: string
}): Promise<void> {
  const was = unlockSpaceClient({ storageServerUrl, zcapClient })
  await was
    .space(spaceId)
    .collection(collectionId)
    .configure({ name, force: true })
}

/**
 * Reads a single plaintext JSON record from a Space collection, or `null` when
 * it does not exist yet (a missing Space, collection, or resource all surface
 * as a 404-shaped `null` from `resource.get()`). A network / unreachable error
 * propagates, so callers can distinguish "no record" from "could not check".
 * The explicit `plaintext` override is load-bearing (see the module doc).
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param options.resourceId {string}
 * @param [options.capability] {IZcap}   an invocation capability the GET
 *   rides; absent, the request invokes the root capability
 * @returns {Promise<unknown | null>}
 */
async function getPlaintextRecord({
  storageServerUrl,
  zcapClient,
  spaceId,
  collectionId,
  resourceId,
  capability
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  collectionId: string
  resourceId: string
  capability?: IZcap
}): Promise<unknown | null> {
  const was = unlockSpaceClient({ storageServerUrl, zcapClient })
  const result = await plaintextCollection({
    was,
    spaceId,
    collectionId,
    capability
  })
    .resource(resourceId)
    .get()
  return result === null ? null : result
}

/**
 * Writes (upserts) a single plaintext JSON record into a Space collection.
 * Serialized to bytes with an explicit `application/json` content-type.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param options.resourceId {string}
 * @param options.record {object}
 * @param [options.capability] {IZcap}   an invocation capability the PUT
 *   rides; absent, the request invokes the root capability
 * @returns {Promise<void>}
 */
async function putPlaintextRecord({
  storageServerUrl,
  zcapClient,
  spaceId,
  collectionId,
  resourceId,
  record,
  capability
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  collectionId: string
  resourceId: string
  record: object
  capability?: IZcap
}): Promise<void> {
  const was = unlockSpaceClient({ storageServerUrl, zcapClient })
  const body = new TextEncoder().encode(JSON.stringify(record))
  await plaintextCollection({ was, spaceId, collectionId, capability })
    .resource(resourceId)
    .put(body, { contentType: 'application/json' })
}

/**
 * Ensures the unlock Space and its single `keyring` collection exist
 * (upsert -- idempotent). Runs with the unlock root capability, so `force`
 * lets the collection upsert treat a 404 from the pre-merge describe as
 * genuinely absent rather than unreadable.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}
 * @param options.spaceId {string}   the unlock Space id
 * @param options.controller {string}   the unlock did:key
 * @param [options.name] {string}   the Space Description name
 * @returns {Promise<void>}
 */
export async function ensureUnlockSpace({
  storageServerUrl,
  zcapClient,
  spaceId,
  controller,
  name = UNLOCK_SPACE_NAME
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  controller: string
  name?: string
}): Promise<void> {
  const was = unlockSpaceClient({ storageServerUrl, zcapClient })
  await was.space(spaceId).configure({ name, controller })
  await ensurePlaintextCollection({
    storageServerUrl,
    zcapClient,
    spaceId,
    collectionId: KEYRING_COLLECTION.id,
    name: KEYRING_COLLECTION.name
  })
}

/**
 * Reads the keyring record from the unlock Space, or returns `null` when it
 * does not exist yet. A network / unreachable error propagates, so callers can
 * distinguish "no keyring" from "could not check".
 *
 * With a `capability`, the `zcapClient` is an enrolled client's rather than
 * the unlock identity's, and the attached management zcap (delegated by the
 * unlock identity at bind time; it must allow GET) authorizes the read. This
 * is what lets the revocation cascade's re-mint read a recovery code's
 * standing record without holding the code: the record's code-authenticated
 * binding rides the frame in the clear, so carrying it forward verbatim needs
 * no decryption.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}
 * @param options.spaceId {string}   the unlock Space id
 * @param [options.capability] {IZcap}   the delegated management zcap;
 *   absent, the read is a root invocation
 * @returns {Promise<unknown | null>}
 */
export async function getUnlockKeyring({
  storageServerUrl,
  zcapClient,
  spaceId,
  capability
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  capability?: IZcap
}): Promise<unknown | null> {
  return getPlaintextRecord({
    storageServerUrl,
    zcapClient,
    spaceId,
    collectionId: KEYRING_COLLECTION.id,
    resourceId: KEYRING_RESOURCE,
    capability
  })
}

/**
 * Writes (upserts) the keyring record into the unlock Space as a JSON document.
 *
 * With a `capability`, the `zcapClient` is an enrolled client's rather than
 * the unlock identity's, and the attached management zcap (delegated by the
 * unlock identity at bind time; it must allow PUT) authorizes the write. This
 * is what lets the revocation cascade re-PUT a recovery code's unlock record
 * (a fresh `did.jsonl` delegation inside a re-wrapped record) without holding
 * the code: the record's JWE recipient is the code's unlock KAK, whose PUBLIC
 * half the issuing client recorded, so re-encryption needs no secret.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}
 * @param options.spaceId {string}   the unlock Space id
 * @param options.record {object}   the keyring record
 * @param [options.capability] {IZcap}   the delegated management zcap;
 *   absent, the write is a root invocation
 * @returns {Promise<void>}
 */
export async function putUnlockKeyring({
  storageServerUrl,
  zcapClient,
  spaceId,
  record,
  capability
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  record: object
  capability?: IZcap
}): Promise<void> {
  await putPlaintextRecord({
    storageServerUrl,
    zcapClient,
    spaceId,
    collectionId: KEYRING_COLLECTION.id,
    resourceId: KEYRING_RESOURCE,
    record,
    capability
  })
}

/**
 * Deletes the whole unlock Space (what retires an old passphrase on a
 * passphrase change, or a lost unlock method). The server's answer is
 * reported rather than decided here: an already-absent Space comes back as
 * `not-found`, and only a non-404 error propagates, so a caller that treats
 * the delete as idempotent ignores the outcome.
 *
 * With a `capability`, the `zcapClient` is an enrolled client's rather than
 * the unlock identity's, and the attached management zcap (delegated by the
 * unlock identity to the data identity at bind time; it must allow DELETE on
 * the Space's own URL) authorizes the delete -- retiring a lost unlock method
 * without re-deriving its identity from the (possibly lost) secret. The
 * server answers 404 both for an absent Space and for a refused capability,
 * so `not-found` is not a statement of absence on its own.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}
 * @param options.spaceId {string}   the unlock Space id
 * @param [options.capability] {IZcap}   the delegated management zcap;
 *   absent, the delete is a root invocation
 * @returns {Promise<{ outcome: 'deleted' | 'not-found' }>}   `not-found`
 *   when the server answered 404 (absent, or unauthorized under a
 *   capability); every other error propagates unchanged
 */
export async function deleteUnlockSpace({
  storageServerUrl,
  zcapClient,
  spaceId,
  capability
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  capability?: IZcap
}): Promise<{ outcome: 'deleted' | 'not-found' }> {
  const was = unlockSpaceClient({ storageServerUrl, zcapClient })
  return was.space(spaceId, { capability }).deleteWithOutcome()
}
