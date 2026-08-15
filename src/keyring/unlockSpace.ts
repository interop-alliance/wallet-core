/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The unlock Space: a minimal second Space, controlled by an unlock identity
 * and separate from the wallet data Space, holding the one keyring record.
 * These are standalone functions rather than methods on a wallet's remote-store
 * class (that store is bound to the data identity): each builds its own
 * `WasClient` over the unlock agent's `zcapClient`, whose invocation signer is
 * the unlock root key (root invocation, no capability attached -- the same
 * posture the data Space uses).
 *
 * The one resource is a plaintext JSON document (its keyring payload is
 * already ciphertext), so no encryption provider is wired in -- and the
 * read/write handles pass the explicit `{ encryption: 'plaintext' }` override.
 * The override is load-bearing: without it, the client decides plaintext vs
 * encrypted by reading the collection description, and when the unlock Space
 * does not exist yet (every keyring lookup for a fresh unlock secret) that read
 * 404s and the client refuses to guess, throwing an EncryptionError instead of
 * surfacing the miss as a 404-shaped `null`.
 */
import { WasClient } from '@interop/was-client'
import { resourcePath, spacePath } from '@interop/was-client/paths'
import { errorStatus } from '@interop/was-client/sync'
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { KEYRING_COLLECTION, KEYRING_RESOURCE } from '../space/collections.js'

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
 * @returns {Promise<unknown | null>}
 */
async function getPlaintextRecord({
  storageServerUrl,
  zcapClient,
  spaceId,
  collectionId,
  resourceId
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  collectionId: string
  resourceId: string
}): Promise<unknown | null> {
  const was = unlockSpaceClient({ storageServerUrl, zcapClient })
  const result = await was
    .space(spaceId)
    .collection(collectionId, { encryption: 'plaintext' })
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
 * @returns {Promise<void>}
 */
async function putPlaintextRecord({
  storageServerUrl,
  zcapClient,
  spaceId,
  collectionId,
  resourceId,
  record
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  collectionId: string
  resourceId: string
  record: object
}): Promise<void> {
  const was = unlockSpaceClient({ storageServerUrl, zcapClient })
  const body = new TextEncoder().encode(JSON.stringify(record))
  await was
    .space(spaceId)
    .collection(collectionId, { encryption: 'plaintext' })
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
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}
 * @param options.spaceId {string}   the unlock Space id
 * @returns {Promise<unknown | null>}
 */
export async function getUnlockKeyring({
  storageServerUrl,
  zcapClient,
  spaceId
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
}): Promise<unknown | null> {
  return getPlaintextRecord({
    storageServerUrl,
    zcapClient,
    spaceId,
    collectionId: KEYRING_COLLECTION.id,
    resourceId: KEYRING_RESOURCE
  })
}

/**
 * Writes (upserts) the keyring record into the unlock Space as a JSON document.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}
 * @param options.spaceId {string}   the unlock Space id
 * @param options.record {object}   the keyring record
 * @returns {Promise<void>}
 */
export async function putUnlockKeyring({
  storageServerUrl,
  zcapClient,
  spaceId,
  record
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  record: object
}): Promise<void> {
  await putPlaintextRecord({
    storageServerUrl,
    zcapClient,
    spaceId,
    collectionId: KEYRING_COLLECTION.id,
    resourceId: KEYRING_RESOURCE,
    record
  })
}

/**
 * Reads the keyring record with an explicitly attached management capability,
 * rather than by root invocation, or returns `null` when it does not exist.
 * The `zcapClient` here is an enrolled client's (not the unlock identity's);
 * the attached `capability` -- the management zcap the unlock identity
 * delegated at bind time, provided it allows GET -- authorizes the read
 * against the unlock Space. This is what lets the revocation cascade's
 * re-mint read a recovery code's standing record without holding the code:
 * the record's code-authenticated binding rides the frame in the clear, so
 * carrying it forward verbatim needs no decryption.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}   an enrolled client's zcap client
 * @param options.spaceId {string}   the unlock Space id
 * @param options.capability {IZcap}   the delegated management zcap (must
 *   allow GET)
 * @returns {Promise<unknown | null>}
 */
export async function getUnlockKeyringWithCapability({
  storageServerUrl,
  zcapClient,
  spaceId,
  capability
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  capability: IZcap
}): Promise<unknown | null> {
  const was = unlockSpaceClient({ storageServerUrl, zcapClient })
  const result = await was
    .space(spaceId)
    .collection(KEYRING_COLLECTION.id, { capability, encryption: 'plaintext' })
    .resource(KEYRING_RESOURCE)
    .get()
  return result === null ? null : result
}

/**
 * Writes (upserts) the keyring record with an explicitly attached management
 * capability, rather than by root invocation. The `zcapClient` here is an
 * enrolled client's (not the unlock identity's); the attached `capability` --
 * the management zcap the unlock identity delegated at bind time, provided it
 * allows PUT -- authorizes the write against the unlock Space. This is what
 * lets the revocation cascade re-PUT a recovery code's unlock record (a fresh
 * `did.jsonl` delegation inside a re-wrapped record) without holding the
 * code: the record's JWE recipient is the code's unlock KAK, whose PUBLIC
 * half the issuing client recorded, so re-encryption needs no secret.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}   an enrolled client's zcap client
 * @param options.spaceId {string}   the unlock Space id
 * @param options.record {object}   the keyring record
 * @param options.capability {IZcap}   the delegated management zcap (must
 *   allow PUT)
 * @returns {Promise<void>}
 */
export async function putUnlockKeyringWithCapability({
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
  capability: IZcap
}): Promise<void> {
  const was = unlockSpaceClient({ storageServerUrl, zcapClient })
  const body = new TextEncoder().encode(JSON.stringify(record))
  await was.request({
    capability,
    path: resourcePath(spaceId, KEYRING_COLLECTION.id, KEYRING_RESOURCE),
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body
  })
}

/**
 * Deletes the whole unlock Space (what retires an old passphrase on a
 * passphrase change). `space.delete()` is idempotent, so an already-absent
 * Space is a success.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}
 * @param options.spaceId {string}   the unlock Space id
 * @returns {Promise<void>}
 */
export async function deleteUnlockSpace({
  storageServerUrl,
  zcapClient,
  spaceId
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
}): Promise<void> {
  const was = unlockSpaceClient({ storageServerUrl, zcapClient })
  await was.space(spaceId).delete()
}

/**
 * Deletes an unlock Space with an explicitly attached management capability,
 * rather than by root invocation. The `zcapClient` here is the DATA identity's
 * (not the unlock identity's); the attached `capability` -- the management zcap
 * the unlock identity delegated to the data identity at bind time -- is what
 * authorizes the DELETE against the unlock Space. This is the tap-free
 * revocation path for a lost unlock method: the data identity can retire it
 * without re-deriving the unlock identity from the (possibly lost) secret. A
 * 404 is treated as success (idempotent -- the Space is already gone).
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}   the data identity's client
 * @param options.spaceId {string}   the unlock Space id
 * @param options.capability {IZcap}   the delegated management zcap
 * @returns {Promise<void>}
 */
export async function deleteUnlockSpaceWithCapability({
  storageServerUrl,
  zcapClient,
  spaceId,
  capability
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  capability: IZcap
}): Promise<void> {
  const was = unlockSpaceClient({ storageServerUrl, zcapClient })
  try {
    await was.request({
      capability,
      path: spacePath(spaceId),
      method: 'DELETE'
    })
  } catch (err) {
    if (errorStatus(err) === 404) {
      return
    }
    throw err
  }
}
