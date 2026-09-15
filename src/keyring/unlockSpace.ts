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
import { WasClient, type ServiceDescription } from '@interop/was-client'
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
 * The Space Description `type` array every unlock Space is created with,
 * passphrase, passkey, and recovery-code alike (the keyring record inside
 * names the credential kind). Wire-level and permanent: the server treats a
 * Space's `type` as immutable after creation, and it is what recognizes an
 * unlock Space from its Space Metadata object alone. `AuxiliarySpace` marks a
 * bookkeeping Space holding no user data; `UnlockSpace` names the role.
 * Sorted lexically, as the WAS spec recommends for a stable serialization.
 */
export const UNLOCK_SPACE_TYPE = ['AuxiliarySpace', 'Space', 'UnlockSpace']

/**
 * The bare WAS client for an unlock Space (see the module doc for why it wires
 * in no encryption provider). Each exported function builds one and hands it
 * to the helpers it composes, so a call discovers the service at most once.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}   built on the unlock agent's signer
 * @param [options.serviceDescription] {ServiceDescription}   the server's
 *   service description a client the caller already holds discovered
 *   (`(await was.service()).description`), so this one skips discovery
 * @returns {WasClient}
 */
function unlockSpaceClient({
  storageServerUrl,
  zcapClient,
  serviceDescription
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  serviceDescription?: ServiceDescription
}): WasClient {
  return new WasClient({
    serverUrl: storageServerUrl,
    zcapClient,
    serviceDescription
  })
}

/**
 * Ensures a plaintext collection exists in a Space (upsert -- idempotent),
 * running with the invoking client's root capability so `force` lets the upsert
 * treat a 404 from the pre-merge describe as genuinely absent rather than
 * unreadable.
 *
 * @param options {object}
 * @param options.was {WasClient}   the unlock Space client
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param options.name {string}
 * @returns {Promise<void>}
 */
async function ensurePlaintextCollection({
  was,
  spaceId,
  collectionId,
  name
}: {
  was: WasClient
  spaceId: string
  collectionId: string
  name: string
}): Promise<void> {
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
 * @param options.was {WasClient}   the unlock Space client
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param options.resourceId {string}
 * @param [options.capability] {IZcap}   an invocation capability the GET
 *   rides; absent, the request invokes the root capability
 * @returns {Promise<unknown | null>}
 */
async function getPlaintextRecord({
  was,
  spaceId,
  collectionId,
  resourceId,
  capability
}: {
  was: WasClient
  spaceId: string
  collectionId: string
  resourceId: string
  capability?: IZcap
}): Promise<unknown | null> {
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
 * @param options.was {WasClient}   the unlock Space client
 * @param options.spaceId {string}
 * @param options.collectionId {string}
 * @param options.resourceId {string}
 * @param options.record {object}
 * @param [options.capability] {IZcap}   an invocation capability the PUT
 *   rides; absent, the request invokes the root capability
 * @returns {Promise<void>}
 */
async function putPlaintextRecord({
  was,
  spaceId,
  collectionId,
  resourceId,
  record,
  capability
}: {
  was: WasClient
  spaceId: string
  collectionId: string
  resourceId: string
  record: object
  capability?: IZcap
}): Promise<void> {
  const body = new TextEncoder().encode(JSON.stringify(record))
  await plaintextCollection({ was, spaceId, collectionId, capability })
    .resource(resourceId)
    .put(body, { contentType: 'application/json' })
}

/**
 * Ensures the unlock Space and its single `keyring` collection exist
 * (upsert -- idempotent). The Space is configured with
 * {@link UNLOCK_SPACE_TYPE}. Runs with the unlock root capability, so `force`
 * lets the collection upsert treat a 404 from the pre-merge describe as
 * genuinely absent rather than unreadable.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}
 * @param [options.serviceDescription] {ServiceDescription}   the server's
 *   service description a client the caller already holds discovered
 *   (`(await was.service()).description`), so this one skips discovery
 * @param options.spaceId {string}   the unlock Space id
 * @param options.controller {string}   the unlock did:key
 * @param [options.name] {string}   the Space Description name
 * @returns {Promise<void>}
 */
export async function ensureUnlockSpace({
  storageServerUrl,
  zcapClient,
  serviceDescription,
  spaceId,
  controller,
  name = UNLOCK_SPACE_NAME
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  serviceDescription?: ServiceDescription
  spaceId: string
  controller: string
  name?: string
}): Promise<void> {
  const was = unlockSpaceClient({
    storageServerUrl,
    zcapClient,
    serviceDescription
  })
  await was
    .space(spaceId)
    .configure({ name, controller, type: UNLOCK_SPACE_TYPE })
  await ensurePlaintextCollection({
    was,
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
 * @param [options.serviceDescription] {ServiceDescription}   the server's
 *   service description a client the caller already holds discovered
 *   (`(await was.service()).description`), so this one skips discovery
 * @param options.spaceId {string}   the unlock Space id
 * @param [options.capability] {IZcap}   the delegated management zcap;
 *   absent, the read is a root invocation
 * @returns {Promise<unknown | null>}
 */
export async function getUnlockKeyring({
  storageServerUrl,
  zcapClient,
  serviceDescription,
  spaceId,
  capability
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  serviceDescription?: ServiceDescription
  spaceId: string
  capability?: IZcap
}): Promise<unknown | null> {
  return getPlaintextRecord({
    was: unlockSpaceClient({
      storageServerUrl,
      zcapClient,
      serviceDescription
    }),
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
 * @param [options.serviceDescription] {ServiceDescription}   the server's
 *   service description a client the caller already holds discovered
 *   (`(await was.service()).description`), so this one skips discovery
 * @param options.spaceId {string}   the unlock Space id
 * @param options.record {object}   the keyring record
 * @param [options.capability] {IZcap}   the delegated management zcap;
 *   absent, the write is a root invocation
 * @returns {Promise<void>}
 */
export async function putUnlockKeyring({
  storageServerUrl,
  zcapClient,
  serviceDescription,
  spaceId,
  record,
  capability
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  serviceDescription?: ServiceDescription
  spaceId: string
  record: object
  capability?: IZcap
}): Promise<void> {
  await putPlaintextRecord({
    was: unlockSpaceClient({
      storageServerUrl,
      zcapClient,
      serviceDescription
    }),
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
 * @param [options.serviceDescription] {ServiceDescription}   the server's
 *   service description a client the caller already holds discovered
 *   (`(await was.service()).description`), so this one skips discovery
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
  serviceDescription,
  spaceId,
  capability
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  serviceDescription?: ServiceDescription
  spaceId: string
  capability?: IZcap
}): Promise<{ outcome: 'deleted' | 'not-found' }> {
  const was = unlockSpaceClient({
    storageServerUrl,
    zcapClient,
    serviceDescription
  })
  return was.space(spaceId, { capability }).deleteWithOutcome()
}
