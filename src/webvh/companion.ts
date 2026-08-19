/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The companion did:webvh: the disposable sidecar log holding transient
 * per-visit verification methods, one generation per flat `gen-` collection
 * inside the account's stable auxiliary companion Space -- so per-visit facts
 * stay out of the account's identity log entirely. This module is the
 * generation's identity and genesis machinery: the `gen-<random>` segment
 * convention, the typed auxiliary Space ensure, the genesis parameters, and
 * the pin-slot key for companion continuity.
 *
 * The companion's posture differs from the account log's on purpose:
 *
 * - Update authority is each standing credential's static companion rung 0
 *   (chain length one, no rung advancement, no attribution scan). Genesis
 *   states the minting credential's rung-0 key in `updateKeys` and commits
 *   every standing credential's rung-0 hash in `nextKeyHashes` -- the minting
 *   key's own carry-over hash included, or no later entry could re-state it.
 * - Prerotation stays on (the rung-0 hashes are the commitment chain),
 *   witnesses stay off, and portability is off: a companion is
 *   generation-scoped and host-bound, and replacement is a GC swap, never a
 *   portability move.
 * - The genesis document is bare -- no verification methods, no service
 *   entries, the DID core context only. Transient verification methods are
 *   published per visit by later entries, and the generation delegation's
 *   service entry is installed by the entry publishing the generation's first
 *   transient method, never by genesis (its bytes would have to name the SCID
 *   the genesis hash derives from).
 * - No `did:web` projection exists: the generation collection holds only its
 *   `did.jsonl`, capability-gated rather than world-readable.
 *
 * Ordering rule: the companion log publishes FIRST; only then does the
 * caller re-point the account document's `#DelegatedClients` service entry at
 * the new companion DID. A companion nobody points at is authorization-inert
 * (no delegation ever names it), so a tear or a double-genesis race leaks
 * storage, never authority -- and the standing orphan discovery is a plain
 * `gen-` prefix match over the auxiliary Space's collection listing, with no
 * registry of generations anywhere.
 *
 * Generation identity is random, never a counter: a reused segment would
 * re-derive the same rung-0 update key for a new generation, and no counter
 * carrier survives GC deleting the old collection. The segment is also the
 * generation-identifying half of the companion rung HKDF labels
 * (`<segment>/rung/<k>` under the unlock ladder's one salt), so there is
 * exactly one spelling of a generation's identity -- the one the companion
 * DID string already embeds.
 */
import { createDID, deriveNextKeyHash } from '@interop/did-method-webvh'
import type { DIDDoc, DIDLog, Signer } from '@interop/did-method-webvh'
import type { WasClient } from '@interop/was-client'
import { base64urlnopad } from '@scure/base'
import { DID_LOG_RESOURCE } from '../space/collections.js'
import { resourceLogPinId } from '../resourceLog/pin.js'
import { didWebvhControllerTemplate, putLogResource } from './didWebvh.js'
import { wasWebvhLogStore } from './wasIdStore.js'
import type { WebvhLogResourceStore } from './wasIdStore.js'

/**
 * The Space Description `type` array of the auxiliary companion Space, set at
 * creation (the server treats a Space's `type` as immutable afterwards).
 * Wire-level and permanent: the server's inspector clause recognizes the
 * `DelegatedClientsSpace` member, and user-data surfaces exclude auxiliary
 * Spaces by it.
 */
export const COMPANION_SPACE_TYPE = [
  'Space',
  'AuxiliarySpace',
  'DelegatedClientsSpace'
]

/**
 * The `type` member that marks a Space as the delegated-clients auxiliary
 * Space (the last entry of {@link COMPANION_SPACE_TYPE}).
 */
const DELEGATED_CLIENTS_SPACE_TYPE = 'DelegatedClientsSpace'

/**
 * The literal prefix of every generation collection's name. Wire-level and
 * permanent: orphan discovery is a plain prefix match over the auxiliary
 * Space's collection listing, and the segment embeds in every companion DID
 * string ever published.
 */
export const GENERATION_SEGMENT_PREFIX = 'gen-'

/**
 * The random suffix: 12 bytes, base64url-no-pad (16 characters), for 20
 * characters total. Every character is inside the server's `[A-Za-z0-9._~-]+`
 * id allowlist, so `encodeURIComponent` is the identity on the segment and
 * the DID path encoding round-trips it.
 */
const GENERATION_SEGMENT_SUFFIX_BYTES = 12

/**
 * The full segment shape: the literal prefix plus 16 base64url characters.
 */
const GENERATION_SEGMENT_PATTERN = /^gen-[A-Za-z0-9_-]{16}$/

/**
 * Mints a fresh generation segment -- the generation collection's name, e.g.
 * `gen-Ux3v0kQf9aPmB2hZ`. Random rather than a counter on purpose: never-reuse
 * is structural (nothing durable survives GC to carry a counter), at the same
 * probabilistic order as every other random-id convention in the system.
 *
 * @returns {string}
 */
export function mintGenerationSegment(): string {
  return (
    GENERATION_SEGMENT_PREFIX +
    base64urlnopad.encode(
      crypto.getRandomValues(new Uint8Array(GENERATION_SEGMENT_SUFFIX_BYTES))
    )
  )
}

/**
 * Refuses anything that is not a well-formed generation segment. Run by every
 * companion builder that takes a segment, so a malformed one is refused
 * before it can reach a DID string, an HKDF label, or a collection id.
 *
 * @param segment {string}
 */
export function assertGenerationSegment(segment: string): void {
  if (!GENERATION_SEGMENT_PATTERN.test(segment)) {
    throw new Error(
      `Not a generation segment: "${segment}" (expected "gen-" plus 16 ` +
        'base64url characters).'
    )
  }
}

/**
 * The pin-slot key for one companion generation's log -- host-free like every
 * pin-slot key, keyed by the auxiliary Space id and the generation segment.
 * A transient session keeps this slot in an in-memory pin store (a durable
 * pin is the wrong lifetime for a disposable log, and a transient session
 * must not durably create the pin store on a read); a durable client's store
 * clears companion slots when the generation is collected.
 *
 * @param options {object}
 * @param options.spaceId {string}   the auxiliary companion Space's id
 * @param options.segment {string}   the generation collection's name
 * @returns {string}
 */
export function companionLogPinId({
  spaceId,
  segment
}: {
  spaceId: string
  segment: string
}): string {
  return resourceLogPinId({
    spaceId,
    collectionId: segment,
    resourceId: DID_LOG_RESOURCE
  })
}

/**
 * The WAS-backed store a companion generation's ceremonies read and publish
 * through with controller-tier signing (an enrolled client). A transient
 * session writes through the delegated store instead
 * (`delegatedWebvhLogStore`, invoking the credential's sibling delegation);
 * both carry the same CAS/ETag conditional-publish discipline.
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.spaceId {string}   the auxiliary companion Space's id
 * @param options.segment {string}   the generation collection's name
 * @returns {WebvhLogResourceStore}
 */
export function companionLogStore({
  was,
  spaceId,
  segment
}: {
  was: WasClient
  spaceId: string
  segment: string
}): WebvhLogResourceStore {
  assertGenerationSegment(segment)
  return wasWebvhLogStore({ was, spaceId, collectionId: segment })
}

/**
 * The DID core context -- the companion genesis document's whole `@context`.
 * The document carries no verification methods and no service entries at
 * genesis, so no other vocabulary is in scope; the entry that first publishes
 * a typed member extends the context then (a did:webvh entry replaces the
 * document wholesale).
 */
const DID_CORE_CONTEXT = 'https://www.w3.org/ns/did/v1'

/**
 * Creates the one-entry companion generation log. The genesis parameters are
 * the companion posture (see the module doc): prerotation on via the rung-0
 * hash commitments, no witnesses, portability off (the library's default,
 * stated explicitly in the emitted entry), and a bare document -- id and the
 * DID core context, nothing else.
 *
 * The caller supplies the update authority: the minting credential's
 * companion rung-0 key as the sole `updateKeys` member, `nextKeyHashes` as
 * every standing credential's rung-0 hash (restated explicitly on every later
 * entry, never inherited), and rung 0's signer. The minting key's own
 * carry-over hash MUST be among the commitments -- every companion entry
 * re-states `updateKeys` containing the revealed rung-0 keys, and the
 * resolver checks the re-statement against the previous entry's commitments
 * -- so a `nextKeyHashes` that omits it is refused here rather than
 * publishing a generation no one can ever extend.
 *
 * @param options {object}
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}   the auxiliary companion Space's id
 * @param options.segment {string}   the generation collection's name
 * @param options.updateKeyPublicKeyMultibase {string}   the minting
 *   credential's companion rung-0 key
 * @param options.nextKeyHashes {string[]}   every standing credential's
 *   rung-0 hash, the minting credential's included
 * @param options.signer {Signer}   the minting credential's rung-0 signer
 * @returns {Promise<{ log: DIDLog; did: string; doc: DIDDoc }>}
 */
export async function createCompanionLog({
  wasServerUrl,
  spaceId,
  segment,
  updateKeyPublicKeyMultibase,
  nextKeyHashes,
  signer
}: {
  wasServerUrl: string
  spaceId: string
  segment: string
  updateKeyPublicKeyMultibase: string
  nextKeyHashes: string[]
  signer: Signer
}): Promise<{ log: DIDLog; did: string; doc: DIDDoc }> {
  assertGenerationSegment(segment)
  const carryOverHash = await deriveNextKeyHash(updateKeyPublicKeyMultibase)
  if (!nextKeyHashes.includes(carryOverHash)) {
    throw new Error(
      'companion genesis: `nextKeyHashes` must include the minting ' +
        "credential's own rung-0 hash (the carry-over commitment), or no " +
        'later entry could ever re-state the revealed key.'
    )
  }
  const { host } = new URL(wasServerUrl)
  const controllerTemplate = didWebvhControllerTemplate({
    wasServerUrl,
    spaceId,
    collectionId: segment
  })
  const result = await createDID({
    address: host,
    paths: ['space', spaceId, segment],
    signer,
    updateKeys: [updateKeyPublicKeyMultibase],
    nextKeyHashes,
    didDocument: { '@context': [DID_CORE_CONTEXT], id: controllerTemplate }
  })
  if (!result.did || !result.doc) {
    throw new Error('companion genesis: createDID returned no DID document.')
  }
  return { log: result.log, did: result.did, doc: result.doc }
}

/**
 * Ensures the auxiliary companion Space exists: created with the typed
 * Description ({@link COMPANION_SPACE_TYPE}) under the given controller when
 * absent, verified when present. The `type` array must ride the create -- the
 * server accepts it at creation only and treats it as immutable afterwards --
 * which is also why an existing Space at this id that is NOT typed as the
 * delegated-clients Space is refused loudly: it can never become one.
 *
 * The Space id is minted by the caller at credential bind time with the
 * account Space's `mintSpaceId` convention (32 random bytes, base64url
 * no-pad): the sibling delegation's `invocationTarget` embeds the id and is
 * sealed into the unlock record before the account DID exists, so no
 * derivation over the account identity is possible -- and hash-derived
 * addressing would import the unlock Spaces' existence-oracle posture,
 * unwanted here.
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.spaceId {string}   the auxiliary companion Space's id
 * @param options.controller {string}   the Space controller (the account
 *   did:webvh where it exists; a bootstrap did:key on a client-less signup,
 *   promoted the same way the account Space's controller is)
 * @returns {Promise<void>}
 */
export async function ensureCompanionSpace({
  was,
  spaceId,
  controller
}: {
  was: WasClient
  spaceId: string
  controller: string
}): Promise<void> {
  const space = was.space(spaceId)
  const current = await space.describe()
  if (current === null) {
    await space.configure({
      controller,
      type: COMPANION_SPACE_TYPE,
      force: true
    })
    return
  }
  if (!current.type?.includes(DELEGATED_CLIENTS_SPACE_TYPE)) {
    throw new Error(
      `The Space "${spaceId}" exists but is not typed as the ` +
        'delegated-clients auxiliary Space; its type is immutable, so it ' +
        'cannot hold companion generations.'
    )
  }
}

/**
 * Mints a fresh companion generation with controller-tier signing: ensures
 * the typed auxiliary Space, mints a fresh random segment, creates the
 * generation collection, and publishes the genesis `did.jsonl` as a
 * create-if-absent -- the same conditional-publish discipline as every log
 * write, though a fresh random segment makes a create collision negligible.
 *
 * The account document's `#DelegatedClients` service entry is deliberately
 * NOT written here: the companion log publishes first, and the caller
 * re-points the account document at the returned DID afterwards. A run torn
 * between the two leaves an unpointed generation -- authorization-inert (no
 * delegation names it), collected by the standing `gen-` prefix orphan
 * discovery at the next durable login.
 *
 * A re-run after a tear mints a FRESH generation rather than resuming: the
 * genesis entry is timestamped, so a re-created log has a different SCID and
 * a resume could never land its create-if-absent PUT; the torn generation is
 * an inert orphan like any other.
 *
 * @param options {object}
 * @param options.was {WasClient}   the storage client, signing as an enrolled
 *   client (or the bootstrap controller on a client-less signup)
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}   the auxiliary companion Space's id
 * @param options.controller {string}   the auxiliary Space's controller, used
 *   only when the Space does not exist yet
 * @param options.updateKeyPublicKeyMultibase {string}   the minting
 *   credential's companion rung-0 key
 * @param options.nextKeyHashes {string[]}   every standing credential's
 *   rung-0 hash, the minting credential's included
 * @param options.signer {Signer}   the minting credential's rung-0 signer
 * @returns {Promise<{ did: string; segment: string; log: DIDLog;
 *   doc: DIDDoc }>}
 */
export async function mintCompanionGeneration({
  was,
  wasServerUrl,
  spaceId,
  controller,
  updateKeyPublicKeyMultibase,
  nextKeyHashes,
  signer
}: {
  was: WasClient
  wasServerUrl: string
  spaceId: string
  controller: string
  updateKeyPublicKeyMultibase: string
  nextKeyHashes: string[]
  signer: Signer
}): Promise<{ did: string; segment: string; log: DIDLog; doc: DIDDoc }> {
  await ensureCompanionSpace({ was, spaceId, controller })
  const segment = mintGenerationSegment()
  // The generation collection must exist before its first resource PUT; a
  // fresh random segment means this is always a create. Plaintext on purpose:
  // the server resolves the companion DID out of its own storage, and the
  // collection is capability-gated rather than encrypted.
  await was
    .space(spaceId)
    .collection(segment, { encryption: 'plaintext' })
    .configure({ name: segment, force: true })
  const created = await createCompanionLog({
    wasServerUrl,
    spaceId,
    segment,
    updateKeyPublicKeyMultibase,
    nextKeyHashes,
    signer
  })
  await putLogResource({
    store: companionLogStore({ was, spaceId, segment }),
    log: created.log,
    ifNoneMatch: true
  })
  return { ...created, segment }
}
