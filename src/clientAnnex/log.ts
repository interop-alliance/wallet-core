/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The client annex did:webvh: the disposable sidecar log holding transient
 * per-visit verification methods, one generation per flat `gen-` collection
 * inside the account's stable auxiliary annex Space -- so per-visit facts
 * stay out of the account's identity log entirely. This module is the
 * generation's identity, genesis, and enrollment machinery: the
 * `gen-<random>` generation id convention, the typed auxiliary Space ensure,
 * the genesis parameters, the pin-slot key for annex continuity, the atomic
 * transient-enrollment entry, and the account document's delegated-clients
 * service entry (the pointer at the current generation).
 *
 * The annex's posture differs from the account log's on purpose:
 *
 * - Update authority is each standing credential's static annex rung 0
 *   (chain length one, no rung advancement, no attribution scan). Genesis
 *   states the minting credential's rung-0 key in `updateKeys` and commits
 *   every standing credential's rung-0 hash in `nextKeyHashes` -- the minting
 *   key's own carry-over hash included, or no later entry could re-state it.
 * - Prerotation stays on (the rung-0 hashes are the commitment chain),
 *   witnesses stay off, and portability is off: an annex is
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
 * Ordering rule: the annex log publishes FIRST; only then does the
 * caller re-point the account document's `#DelegatedClients` service entry at
 * the new annex DID. An annex nobody points at is authorization-inert
 * (no delegation ever names it), so a tear or a double-genesis race leaks
 * storage, never authority -- and the standing orphan discovery is a plain
 * `gen-` prefix match over the auxiliary Space's collection listing, with no
 * registry of generations anywhere.
 *
 * Generation identity is random, never a counter: a reused generation id would
 * re-derive the same rung-0 update key for a new generation, and no counter
 * carrier survives GC deleting the old collection. The generation id is also
 * the generation-identifying half of the annex rung HKDF labels
 * (`<generationId>/rung/<k>` under the unlock ladder's one salt), so there is
 * exactly one spelling of a generation's identity -- the one the annex
 * DID string already embeds.
 */
import {
  createDID,
  deriveNextKeyHash,
  updateDID
} from '@interop/did-method-webvh'
import type {
  DIDDoc,
  DIDLog,
  ServiceEndpoint,
  Signer,
  VerificationMethod
} from '@interop/did-method-webvh'
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import type { IDelegatedZcap, WasClient } from '@interop/was-client'
import {
  rootCapabilityId,
  spaceItems,
  spacePath,
  toUrl
} from '@interop/was-client/paths'
import { base64urlnopad } from '@scure/base'
import { DID_LOG_RESOURCE } from '../space/collections.js'
import { resourceLogPinId } from '../resourceLog/pin.js'
import type { ResourceLogPinStore } from '../resourceLog/pin.js'
import { clientAnnexRung } from './ladder.js'
import {
  assertCarryOverCommitments,
  concludeWithPublishedLog,
  didWebvhControllerTemplate,
  MULTIKEY_VM_TYPE,
  publishUpdatedLog,
  putLogResource,
  readPublishedLog,
  relationIds,
  updateKeyMultibase,
  updateKeySigner,
  withLogConflictRetry
} from '../webvh/didWebvh.js'
import type {
  ClientWebvhUpdateKeys,
  PublishedWebvhLog,
  WebvhIdStore
} from '../webvh/didWebvh.js'
import { delegationKeyInDocument } from '../webvh/listClients.js'
import type { PublishedKeyDocument } from '../webvh/listClients.js'
import {
  delegationProofKeyId,
  STANDING_ZCAP_TTL_MS,
  zcapExpiring
} from '../webvh/standingZcap.js'
import { wasWebvhLogStore } from '../webvh/wasIdStore.js'
import type { WebvhLogResourceStore } from '../webvh/wasIdStore.js'

/**
 * The Space Description `type` array of the auxiliary annex Space, set at
 * creation (the server treats a Space's `type` as immutable afterwards).
 * Wire-level and permanent: the server's inspector clause recognizes the
 * `DelegatedClientsSpace` member, and user-data surfaces exclude auxiliary
 * Spaces by it.
 */
export const CLIENT_ANNEX_SPACE_TYPE = [
  'Space',
  'AuxiliarySpace',
  'DelegatedClientsSpace'
]

/**
 * The `type` member that marks a Space as the delegated-clients auxiliary
 * Space (the last entry of {@link CLIENT_ANNEX_SPACE_TYPE}).
 */
const DELEGATED_CLIENTS_SPACE_TYPE = 'DelegatedClientsSpace'

/**
 * The literal prefix of every generation collection's name. Wire-level and
 * permanent: orphan discovery is a plain prefix match over the auxiliary
 * Space's collection listing, and the generation id embeds in every annex
 * DID string ever published.
 */
export const GENERATION_ID_PREFIX = 'gen-'

/**
 * The random suffix: 12 bytes, base64url-no-pad (16 characters), for 20
 * characters total. Every character is inside the server's `[A-Za-z0-9._~-]+`
 * id allowlist, so `encodeURIComponent` is the identity on the generation id
 * and the DID path encoding round-trips it.
 */
const GENERATION_ID_SUFFIX_BYTES = 12

/**
 * The full generation id shape: the literal prefix plus 16 base64url
 * characters.
 */
const GENERATION_ID_PATTERN = /^gen-[A-Za-z0-9_-]{16}$/

/**
 * Mints a fresh generation id -- the generation collection's name, e.g.
 * `gen-Ux3v0kQf9aPmB2hZ`. Random rather than a counter on purpose: never-reuse
 * is structural (nothing durable survives GC to carry a counter), at the same
 * probabilistic order as every other random-id convention in the system.
 *
 * @returns {string}
 */
export function mintGenerationId(): string {
  return (
    GENERATION_ID_PREFIX +
    base64urlnopad.encode(
      crypto.getRandomValues(new Uint8Array(GENERATION_ID_SUFFIX_BYTES))
    )
  )
}

/**
 * Refuses anything that is not a well-formed generation id. Run by every
 * annex builder that takes a generation id, so a malformed one is refused
 * before it can reach a DID string, an HKDF label, or a collection id.
 *
 * @param generationId {string}
 */
export function assertGenerationId(generationId: string): void {
  if (!GENERATION_ID_PATTERN.test(generationId)) {
    throw new Error(
      `Not a generation id: "${generationId}" (expected "gen-" plus 16 ` +
        'base64url characters).'
    )
  }
}

/**
 * The pin-slot key for one annex generation's log -- host-free like every
 * pin-slot key, keyed by the auxiliary Space id and the generation id.
 * A transient session keeps this slot in an in-memory pin store (a durable
 * pin is the wrong lifetime for a disposable log, and a transient session
 * must not durably create the pin store on a read); a durable client's store
 * clears annex slots when the generation is collected.
 *
 * @param options {object}
 * @param options.spaceId {string}   the auxiliary annex Space's id
 * @param options.generationId {string}   the generation collection's name
 * @returns {string}
 */
export function clientAnnexLogPinId({
  spaceId,
  generationId
}: {
  spaceId: string
  generationId: string
}): string {
  return resourceLogPinId({
    spaceId,
    collectionId: generationId,
    resourceId: DID_LOG_RESOURCE
  })
}

/**
 * The WAS-backed store an annex generation's ceremonies read and publish
 * through with controller-tier signing (an enrolled client). A transient
 * session writes through the delegated store instead
 * (`delegatedWebvhLogStore`, invoking the credential's sibling delegation);
 * both carry the same CAS/ETag conditional-publish discipline.
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.spaceId {string}   the auxiliary annex Space's id
 * @param options.generationId {string}   the generation collection's name
 * @param [options.capability] {IZcap}   an invocation capability every request
 *   rides (the sibling delegation, where the caller is not an enrolled
 *   invoker); absent, requests invoke the root capability
 * @returns {WebvhLogResourceStore}
 */
export function clientAnnexLogStore({
  was,
  spaceId,
  generationId,
  capability
}: {
  was: WasClient
  spaceId: string
  generationId: string
  capability?: IZcap
}): WebvhLogResourceStore {
  assertGenerationId(generationId)
  return wasWebvhLogStore({
    was,
    spaceId,
    collectionId: generationId,
    ...(capability !== undefined ? { capability } : {})
  })
}

/**
 * The DID core context -- the annex genesis document's whole `@context`.
 * The document carries no verification methods and no service entries at
 * genesis, so no other vocabulary is in scope; the entry that first publishes
 * a typed member extends the context then (a did:webvh entry replaces the
 * document wholesale).
 */
const DID_CORE_CONTEXT = 'https://www.w3.org/ns/did/v1'

/**
 * The Multikey context, appended to the annex document's `@context` by
 * the entry that first publishes a transient verification method (genesis
 * carries the DID core context only, having no typed members to define).
 */
const MULTIKEY_CONTEXT_URL = 'https://w3id.org/security/multikey/v1'

/**
 * Creates the one-entry annex generation log. The genesis parameters are
 * the annex posture (see the module doc): prerotation on via the rung-0
 * hash commitments, no witnesses, portability off (the library's default,
 * stated explicitly in the emitted entry), and a bare document -- id and the
 * DID core context, nothing else.
 *
 * The caller supplies the update authority: the minting credential's
 * annex rung-0 key as the sole `updateKeys` member, `nextKeyHashes` as
 * every standing credential's rung-0 hash (restated explicitly on every later
 * entry, never inherited), and rung 0's signer. The minting key's own
 * carry-over hash MUST be among the commitments -- every annex entry
 * re-states `updateKeys` containing the revealed rung-0 keys, and the
 * resolver checks the re-statement against the previous entry's commitments
 * -- so a `nextKeyHashes` that omits it is refused here rather than
 * publishing a generation no one can ever extend.
 *
 * @param options {object}
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}   the auxiliary annex Space's id
 * @param options.generationId {string}   the generation collection's name
 * @param options.updateKeyPublicKeyMultibase {string}   the minting
 *   credential's annex rung-0 key
 * @param options.nextKeyHashes {string[]}   every standing credential's
 *   rung-0 hash, the minting credential's included
 * @param options.signer {Signer}   the minting credential's rung-0 signer
 * @returns {Promise<{ log: DIDLog; did: string; doc: DIDDoc }>}
 */
export async function createClientAnnexLog({
  wasServerUrl,
  spaceId,
  generationId,
  updateKeyPublicKeyMultibase,
  nextKeyHashes,
  signer
}: {
  wasServerUrl: string
  spaceId: string
  generationId: string
  updateKeyPublicKeyMultibase: string
  nextKeyHashes: string[]
  signer: Signer
}): Promise<{ log: DIDLog; did: string; doc: DIDDoc }> {
  assertGenerationId(generationId)
  const carryOverHash = await deriveNextKeyHash(updateKeyPublicKeyMultibase)
  if (!nextKeyHashes.includes(carryOverHash)) {
    throw new Error(
      'client annex genesis: `nextKeyHashes` must include the minting ' +
        "credential's own rung-0 hash (the carry-over commitment), or no " +
        'later entry could ever re-state the revealed key.'
    )
  }
  const { host } = new URL(wasServerUrl)
  const controllerTemplate = didWebvhControllerTemplate({
    wasServerUrl,
    spaceId,
    collectionId: generationId
  })
  const result = await createDID({
    address: host,
    paths: ['space', spaceId, generationId],
    signer,
    updateKeys: [updateKeyPublicKeyMultibase],
    nextKeyHashes,
    didDocument: { '@context': [DID_CORE_CONTEXT], id: controllerTemplate }
  })
  if (!result.did || !result.doc) {
    throw new Error('client annex genesis: createDID returned no DID document.')
  }
  return { log: result.log, did: result.did, doc: result.doc }
}

/**
 * Ensures the auxiliary annex Space exists: created with the typed
 * Description ({@link CLIENT_ANNEX_SPACE_TYPE}) under the given controller when
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
 * @param options.spaceId {string}   the auxiliary annex Space's id
 * @param options.controller {string}   the Space controller (the account
 *   did:webvh where it exists; a bootstrap did:key on a ladder-anchored signup,
 *   promoted the same way the account Space's controller is)
 * @returns {Promise<void>}
 */
export async function ensureClientAnnexSpace({
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
      type: CLIENT_ANNEX_SPACE_TYPE,
      force: true
    })
    return
  }
  if (!current.type?.includes(DELEGATED_CLIENTS_SPACE_TYPE)) {
    throw new Error(
      `The Space "${spaceId}" exists but is not typed as the ` +
        'delegated-clients auxiliary Space; its type is immutable, so it ' +
        'cannot hold client-annex generations.'
    )
  }
}

/**
 * Mints a fresh annex generation with controller-tier signing: ensures
 * the typed auxiliary Space, mints a fresh random generation id, creates the
 * generation collection, and publishes the genesis `did.jsonl` as a
 * create-if-absent -- the same conditional-publish discipline as every log
 * write, though a fresh random generation id makes a create collision
 * negligible.
 *
 * The account document's `#DelegatedClients` service entry is deliberately
 * NOT written here: the annex log publishes first, and the caller
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
 *   client (or the bootstrap controller on a ladder-anchored signup)
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}   the auxiliary annex Space's id
 * @param options.controller {string}   the auxiliary Space's controller, used
 *   only when the Space does not exist yet
 * @param options.updateKeyPublicKeyMultibase {string}   the minting
 *   credential's annex rung-0 key
 * @param options.nextKeyHashes {string[]}   every standing credential's
 *   rung-0 hash, the minting credential's included
 * @param options.signer {Signer}   the minting credential's rung-0 signer
 * @returns {Promise<{ did: string; generationId: string; log: DIDLog;
 *   doc: DIDDoc }>}
 */
export async function mintClientAnnexGeneration({
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
}): Promise<{ did: string; generationId: string; log: DIDLog; doc: DIDDoc }> {
  await ensureClientAnnexSpace({ was, spaceId, controller })
  const generationId = mintGenerationId()
  return publishClientAnnexGenesis({
    was,
    wasServerUrl,
    spaceId,
    generationId,
    updateKeyPublicKeyMultibase,
    nextKeyHashes,
    signer
  })
}

/**
 * The shared genesis-publish tail of both generation minters: creates the
 * generation collection and publishes the one-entry log as a
 * create-if-absent.
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}   the auxiliary annex Space's id
 * @param options.generationId {string}   the freshly minted generation id
 * @param options.updateKeyPublicKeyMultibase {string}
 * @param options.nextKeyHashes {string[]}
 * @param options.signer {Signer}
 * @param [options.capability] {IZcap}   an invocation capability the
 *   collection create and the genesis publish ride (a delegated minter)
 * @returns {Promise<{ did: string; generationId: string; log: DIDLog;
 *   doc: DIDDoc }>}
 */
async function publishClientAnnexGenesis({
  was,
  wasServerUrl,
  spaceId,
  generationId,
  updateKeyPublicKeyMultibase,
  nextKeyHashes,
  signer,
  capability
}: {
  was: WasClient
  wasServerUrl: string
  spaceId: string
  generationId: string
  updateKeyPublicKeyMultibase: string
  nextKeyHashes: string[]
  signer: Signer
  capability?: IZcap
}): Promise<{ did: string; generationId: string; log: DIDLog; doc: DIDDoc }> {
  // The generation collection must exist before its first resource PUT; a
  // fresh random generation id means this is always a create. Plaintext on
  // purpose:
  // the server resolves the annex DID out of its own storage, and the
  // collection is capability-gated rather than encrypted.
  await was
    .space(spaceId, capability !== undefined ? { capability } : {})
    .collection(generationId, { encryption: 'plaintext' })
    .configure({ name: generationId, force: true })
  const created = await createClientAnnexLog({
    wasServerUrl,
    spaceId,
    generationId,
    updateKeyPublicKeyMultibase,
    nextKeyHashes,
    signer
  })
  await putLogResource({
    store: clientAnnexLogStore({
      was,
      spaceId,
      generationId,
      ...(capability !== undefined ? { capability } : {})
    }),
    log: created.log,
    ifNoneMatch: true
  })
  return { ...created, generationId }
}

/**
 * Mints a fresh annex generation signed by a standing CREDENTIAL's
 * annex rung 0 -- the mint a ladder-seed holder runs (a credential-in-hand
 * login, or a test harness standing in for one). The generation id must exist
 * before the update authority can: the rung-0 key derives from the ladder
 * seed AND the generation id (`clientAnnexRung`), so this helper mints the
 * generation id
 * first, derives the rung, and states its own carry-over hash in
 * `nextKeyHashes` -- {@link mintClientAnnexGeneration}'s caller-supplied-key
 * shape cannot express that ordering. Everything else matches it: the typed
 * Space ensure, the collection create, the create-if-absent genesis publish,
 * and the pointer deliberately left to the caller.
 *
 * @param options {object}
 * @param options.was {WasClient}   the storage client, signing as an enrolled
 *   client (or the bootstrap controller on a ladder-anchored signup)
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}   the auxiliary annex Space's id
 * @param options.controller {string}   the auxiliary Space's controller, used
 *   only when the Space does not exist yet
 * @param options.ladderSeed {Uint8Array}   the minting credential's ladder
 *   seed, from its unlock record
 * @param [options.extraNextKeyHashes] {string[]}   the OTHER standing
 *   credentials' rung-0 hashes for this generation id, when the account has
 *   more
 *   than one; the minting credential's own carry-over hash is always included
 * @param [options.capability] {IZcap}   an invocation capability the mint
 *   rides -- the transient-recovery continuation minting its fresh generation
 *   through the credential's sibling delegation (the auxiliary Space's items
 *   subtree). The typed-Space ensure is then skipped: the delegation's target
 *   covers the collections beneath the Space, never the Space Description,
 *   and a standing sibling delegation presupposes the auxiliary Space
 * @returns {Promise<{ did: string; generationId: string; log: DIDLog;
 *   doc: DIDDoc }>}
 */
export async function mintCredentialClientAnnexGeneration({
  was,
  wasServerUrl,
  spaceId,
  controller,
  ladderSeed,
  extraNextKeyHashes = [],
  capability
}: {
  was: WasClient
  wasServerUrl: string
  spaceId: string
  controller: string
  ladderSeed: Uint8Array
  extraNextKeyHashes?: string[]
  capability?: IZcap
}): Promise<{ did: string; generationId: string; log: DIDLog; doc: DIDDoc }> {
  if (capability === undefined) {
    await ensureClientAnnexSpace({ was, spaceId, controller })
  }
  const generationId = mintGenerationId()
  const rung = await clientAnnexRung({ ladderSeed, generationId })
  return publishClientAnnexGenesis({
    was,
    wasServerUrl,
    spaceId,
    generationId,
    updateKeyPublicKeyMultibase: rung.keyMultibase,
    nextKeyHashes: [
      await deriveNextKeyHash(rung.keyMultibase),
      ...extraNextKeyHashes
    ],
    signer: await updateKeySigner({ seed: rung.seed }),
    ...(capability !== undefined ? { capability } : {})
  })
}

/**
 * The type IRI of the account document's delegated-clients service entry --
 * the pointer at the current annex generation's DID. Wire-level and
 * permanent: readers (this module's {@link delegatedClientsPointer}, the
 * server's annex-chain inspector clause) dispatch on this IRI, never on
 * the entry's fragment id, which is non-semantic by convention.
 */
export const DELEGATED_CLIENTS_SERVICE_TYPE =
  'https://w3id.org/byoe#DelegatedClients'

/**
 * The fragment id the wallet mints for a fresh delegated-clients service
 * entry. Non-semantic by the byoe service-entry convention -- readers MUST
 * dispatch on {@link DELEGATED_CLIENTS_SERVICE_TYPE} -- and stable: the GC
 * re-point preserves an existing entry's id verbatim, whatever it is.
 */
const DELEGATED_CLIENTS_SERVICE_FRAGMENT = 'delegated-clients'

/**
 * Builds a fresh delegated-clients service entry for the account document.
 * The `serviceEndpoint` is the annex DID STRING, deliberately not a URL:
 * the DID is self-certifying and host-independent, and the account pointer
 * already carries the host.
 *
 * @param options {object}
 * @param options.accountDid {string}   the account did:webvh
 * @param options.clientAnnexDid {string}   the current generation's annex
 *   DID
 * @returns {ServiceEndpoint}
 */
export function delegatedClientsServiceEntry({
  accountDid,
  clientAnnexDid
}: {
  accountDid: string
  clientAnnexDid: string
}): ServiceEndpoint {
  return {
    id: `${accountDid}#${DELEGATED_CLIENTS_SERVICE_FRAGMENT}`,
    type: DELEGATED_CLIENTS_SERVICE_TYPE,
    serviceEndpoint: clientAnnexDid
  }
}

/**
 * The annex DID the account document currently points at: the
 * `serviceEndpoint` of the service entry whose `type` names (or includes)
 * {@link DELEGATED_CLIENTS_SERVICE_TYPE}. Only a bare DID-string endpoint
 * counts -- the same predicate the server's inspector clause evaluates, so
 * wallet and server can never disagree on which generation is pointed.
 *
 * @param options {object}
 * @param options.doc {DIDDoc}   the resolved (and verified) account document
 * @returns {string | undefined}
 */
export function delegatedClientsPointer({
  doc
}: {
  doc: DIDDoc
}): string | undefined {
  for (const entry of doc.service ?? []) {
    const types = Array.isArray(entry.type) ? entry.type : [entry.type]
    if (
      types.includes(DELEGATED_CLIENTS_SERVICE_TYPE) &&
      typeof entry.serviceEndpoint === 'string'
    ) {
      return entry.serviceEndpoint
    }
  }
  return undefined
}

/**
 * The account document's `service` array with the delegated-clients pointer
 * set to `clientAnnexDid`. An existing pointer entry is re-pointed in place,
 * its fragment id preserved verbatim (the id is non-semantic and stable);
 * absent one, a fresh entry is appended. Every other service entry is carried
 * through untouched.
 *
 * Shared by the two writers of the pointer: the standalone
 * {@link setDelegatedClientsPointer} entry, and the transient-recovery
 * continuation, which folds the pointer into its own add-and-retire entry so
 * the pointer can never lag the entry that retires the standing ladder VMs.
 *
 * @param options {object}
 * @param options.doc {DIDDoc}   the current account document
 * @param options.accountDid {string}   the account did:webvh
 * @param options.clientAnnexDid {string}   the generation to point at
 * @returns {ServiceEndpoint[]}
 */
export function servicesPointedAtClientAnnex({
  doc,
  accountDid,
  clientAnnexDid
}: {
  doc: DIDDoc
  accountDid: string
  clientAnnexDid: string
}): ServiceEndpoint[] {
  const existing = (doc.service ?? []) as ServiceEndpoint[]
  const isPointerEntry = (entry: ServiceEndpoint) => {
    const types = Array.isArray(entry.type) ? entry.type : [entry.type]
    return types.includes(DELEGATED_CLIENTS_SERVICE_TYPE)
  }
  return existing.some(isPointerEntry)
    ? existing.map(entry =>
        isPointerEntry(entry)
          ? { ...entry, serviceEndpoint: clientAnnexDid }
          : entry
      )
    : [
        ...existing,
        delegatedClientsServiceEntry({ accountDid, clientAnnexDid })
      ]
}

/**
 * The unlock-record sibling delegation's `allowedAction` set: GET beside PUT,
 * so an enrolling transient client can read the annex head it appends to.
 * Wire-level and permanent (wallet-core decision 0005): the server's
 * inspector clause admits a delegated-clients delegation with `allowedAction`
 * a subset of exactly this pair.
 */
export const DELEGATED_CLIENTS_DELEGATION_ACTIONS = ['GET', 'PUT']

/**
 * The sibling delegation's lifetime: the house standing-zcap value (one
 * year; see `standingZcap.ts`). It rots on exactly the account bridge's axis
 * -- same signer, same current-key-set rule, same renewal window -- so the
 * re-mint pass that refreshes the bridge refreshes it too.
 */
export const DELEGATED_CLIENTS_DELEGATION_TTL_MS = STANDING_ZCAP_TTL_MS

/**
 * Mints one delegated-clients (annex Space) delegation: the pre-minted
 * zcap sealed into a standing credential's unlock record beside the account
 * bridge, which is what lets a transient login reach the annex log with
 * nothing but the credential. The shape is a permanent wire artifact
 * (wallet-core decision 0005):
 *
 * - `invocationTarget` is the AUXILIARY annex Space's items subtree --
 *   the Space URL with a trailing slash, built with was-client's paths
 *   helpers so the bytes match the server's target check on a sub-path
 *   deployment. Generation coverage comes from generation-id-bounded
 *   attenuation
 *   over the flat `gen-` collection names, so no GC cycle rewrites the
 *   record or the registry.
 * - `controller` is the credential-derived signing DID (the same grantee
 *   the account bridge names).
 * - `allowedActions` is {@link DELEGATED_CLIENTS_DELEGATION_ACTIONS}.
 * - The chain is rooted directly in the auxiliary Space's root zcap.
 * - `expires` is {@link DELEGATED_CLIENTS_DELEGATION_TTL_MS} out.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the delegating signer (an
 *   enrolled client's promoted signer, or the account ladder VM)
 * @param options.wasServerUrl {string}   the auxiliary Space's storage
 *   server (the account pointer's host)
 * @param options.clientAnnexSpaceId {string}   the auxiliary annex
 *   Space's id
 * @param options.controller {string}   the credential-derived signing DID
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {Promise<IZcap>}
 */
export async function mintDelegatedClientsDelegation({
  zcapClient,
  wasServerUrl,
  clientAnnexSpaceId,
  controller,
  now = Date.now()
}: {
  zcapClient: ZcapClient
  wasServerUrl: string
  clientAnnexSpaceId: string
  controller: string
  now?: number
}): Promise<IZcap> {
  const spaceUrl = toUrl({
    serverUrl: wasServerUrl,
    path: spacePath(clientAnnexSpaceId)
  })
  return (await zcapClient.delegate({
    capability: rootCapabilityId(spaceUrl),
    invocationTarget: toUrl({
      serverUrl: wasServerUrl,
      path: spaceItems(clientAnnexSpaceId)
    }),
    controller,
    allowedActions: [...DELEGATED_CLIENTS_DELEGATION_ACTIONS],
    expires: new Date(now + DELEGATED_CLIENTS_DELEGATION_TTL_MS)
  })) as IZcap
}

/**
 * Builds the annex-side sibling-delegation minter the durable record re-mint
 * orchestrator (`recovery/remintRecoveryDelegations`) takes as an injected
 * closure -- the boundary keeping that base orchestrator free of annex
 * imports. The returned closure reads the auxiliary annex Space id off the
 * verified document's delegated-clients service entry (the annex DID string
 * embeds it) and mints a fresh {@link mintDelegatedClientsDelegation} to the
 * named controller; it resolves `undefined` while the document points at no
 * generation, which the orchestrator reads as "carry the old sealed member
 * verbatim".
 *
 * @param options {object}
 * @param options.doc {object}   the locally verified account document
 * @param options.zcapClient {ZcapClient}   the acting client's promoted
 *   signer, which mints the fresh delegations
 * @param options.wasServerUrl {string}   the auxiliary Space's storage
 *   server (the account pointer's host)
 * @returns {Function}   `({ controller }) => Promise<IZcap | undefined>`
 */
export function delegatedClientsDelegationMinter({
  doc,
  zcapClient,
  wasServerUrl
}: {
  doc: object
  zcapClient: ZcapClient
  wasServerUrl: string
}): (options: { controller: string }) => Promise<IZcap | undefined> {
  return async ({ controller }: { controller: string }) => {
    const clientAnnexDid = delegatedClientsPointer({
      doc: doc as Parameters<typeof delegatedClientsPointer>[0]['doc']
    })
    if (!clientAnnexDid) {
      return undefined
    }
    let clientAnnexSpaceId: string
    try {
      clientAnnexSpaceId = clientAnnexDidParts({ did: clientAnnexDid }).spaceId
    } catch {
      return undefined
    }
    return mintDelegatedClientsDelegation({
      zcapClient,
      wasServerUrl,
      clientAnnexSpaceId,
      controller
    })
  }
}

/**
 * The auxiliary annex Space id a delegated-clients delegation targets,
 * read out of its `invocationTarget` (the items-subtree URL,
 * `.../space/<clientAnnexSpaceId>/`). The id has no other home -- a transient
 * login learns the Space from the delegation it unwraps, and a refresh pass
 * that holds the old delegation rebuilds the target from it -- so this parse
 * is the one reader. Returns `undefined` on anything that is not an
 * items-subtree Space URL.
 *
 * @param options {object}
 * @param options.delegation {IZcap}   a delegated-clients delegation
 * @returns {string | undefined}
 */
export function delegatedClientsDelegationSpaceId({
  delegation
}: {
  delegation: IZcap
}): string | undefined {
  const target = (delegation as { invocationTarget?: unknown }).invocationTarget
  if (typeof target !== 'string') {
    return undefined
  }
  let path: string
  try {
    path = new URL(target).pathname
  } catch {
    return undefined
  }
  // The items-subtree URL ends "/space/<id>/" -- the load-bearing trailing
  // slash leaves one empty final segment.
  const segments = path.split('/')
  if (
    segments.length < 4 ||
    segments[segments.length - 1] !== '' ||
    segments[segments.length - 3] !== 'space'
  ) {
    return undefined
  }
  const spaceId = segments[segments.length - 2]
  return spaceId ? decodeURIComponent(spaceId) : undefined
}

/**
 * The type IRI of the annex document's generation-delegation service
 * entry -- the generation's standing Space-scoped zcap, embedded where an
 * enrolling transient client can reach it before it holds any other
 * authority. Wire-level and permanent: readers (this module's
 * {@link embeddedGenerationDelegation}, the app-side loader) dispatch on this
 * IRI, never on the entry's fragment id, which is non-semantic by the byoe
 * service-entry convention.
 */
export const GENERATION_DELEGATION_SERVICE_TYPE =
  'https://w3id.org/byoe#GenerationDelegation'

/**
 * The fragment id the wallet mints for a fresh generation-delegation service
 * entry. Non-semantic by the byoe service-entry convention -- readers MUST
 * dispatch on {@link GENERATION_DELEGATION_SERVICE_TYPE} -- and stable: a
 * renewal replaces an existing entry's endpoint in place, its id preserved
 * verbatim, whatever it is.
 */
const GENERATION_DELEGATION_SERVICE_FRAGMENT = 'generation-delegation'

/**
 * The generation delegation's `allowedAction` set: the full closed WAS
 * action vocabulary. Wire-level and permanent (the app-connect-spec
 * generation-delegation record): attenuation is structural, not enumerated
 * -- child-within-parent is enforced on both actions and targets, so any
 * verb missing here would cap every transient-visit App Connect grant below
 * its durable-client shape. What stays outside the delegation is carried by
 * the TARGET instead: the items subtree excludes the bare Space URL, and
 * with it the Space Description PUT (a controller rewrite) and the Space
 * DELETE.
 */
export const GENERATION_DELEGATION_ACTIONS = [
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'DELETE'
]

/**
 * The generation delegation's lifetime: the house standing-zcap value (one
 * year; see `standingZcap.ts`). GC's explicit revoke is the intended
 * end-of-life; expiry is the backstop, deliberately not matched to the
 * quarterly GC cadence -- a 90-day-class TTL would begin renewal churn
 * exactly when GC is merely due.
 */
export const GENERATION_DELEGATION_TTL_MS = STANDING_ZCAP_TTL_MS

/**
 * Mints one generation delegation: the standing Space-scoped zcap a
 * generation's transient clients invoke under. The shape is a permanent wire
 * artifact (the app-connect-spec generation-delegation record):
 *
 * - `invocationTarget` is the ACCOUNT Space's items subtree -- the Space URL
 *   with a trailing slash, built with was-client's paths helpers so the
 *   bytes match the server's target check on a sub-path deployment. The
 *   bare Space URL sits outside the capability bytes (see
 *   {@link GENERATION_DELEGATION_ACTIONS} for what that excludes).
 * - `controller` is the bare annex DID string. Transient keys invoke as
 *   `<clientAnnexDid>#<vm>`, and the server's inspector clause compares this
 *   string against the account document's delegated-clients pointer.
 * - The chain is rooted directly in the account Space's root zcap, so an
 *   App Connect grant delegated under it forms the depth-3 chain
 *   `[root id string, this delegation embedded]`.
 * - `expires` is {@link GENERATION_DELEGATION_TTL_MS} out.
 *
 * The delegation signer is the caller's choice of licensed authority: the
 * account ladder VM (`ladderVmZcapClient`) or an enrolled durable client's
 * promoted signer (`webvhZcapClient`).
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the delegating signer (ladder VM
 *   or a durable client's promoted signer)
 * @param options.wasServerUrl {string}   the ACCOUNT Space's storage server
 * @param options.spaceId {string}   the ACCOUNT Space's id
 * @param options.clientAnnexDid {string}   the generation's annex DID
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {Promise<IZcap>}
 */
export async function mintGenerationDelegation({
  zcapClient,
  wasServerUrl,
  spaceId,
  clientAnnexDid,
  now = Date.now()
}: {
  zcapClient: ZcapClient
  wasServerUrl: string
  spaceId: string
  clientAnnexDid: string
  now?: number
}): Promise<IZcap> {
  clientAnnexDidParts({ did: clientAnnexDid })
  const spaceUrl = toUrl({ serverUrl: wasServerUrl, path: spacePath(spaceId) })
  return (await zcapClient.delegate({
    capability: rootCapabilityId(spaceUrl),
    invocationTarget: toUrl({
      serverUrl: wasServerUrl,
      path: spaceItems(spaceId)
    }),
    controller: clientAnnexDid,
    allowedActions: [...GENERATION_DELEGATION_ACTIONS],
    expires: new Date(now + GENERATION_DELEGATION_TTL_MS)
  })) as IZcap
}

/**
 * A child grant's `expires` under the generation delegation: the requested
 * TTL, clamped to the delegation's own expiry -- the library's per-hop
 * monotonicity rule IS the TTL clamp, so a grant minted past the parent's
 * `expires` would verify nowhere. By construction the bounded grants (30-day
 * read, 7-day write) always receive their full TTL; only 365-day-class
 * grants ever meet the clamp, at 30 or more days remaining (the
 * renew-precedes-mint stage keeps the delegation outside its renewal window
 * whenever a grant is minted).
 *
 * @param options {object}
 * @param options.ttlMs {number}   the grant's requested TTL
 * @param options.delegation {IZcap}   the generation delegation
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {Date}
 */
export function clampGrantExpires({
  ttlMs,
  delegation,
  now = Date.now()
}: {
  ttlMs: number
  delegation: IZcap
  now?: number
}): Date {
  const parentExpires = Date.parse(
    (delegation as { expires?: string }).expires ?? ''
  )
  if (Number.isNaN(parentExpires)) {
    throw new Error(
      'generation delegation: no parseable `expires`; refusing to mint a ' +
        'grant under an unbounded parent.'
    )
  }
  return new Date(Math.min(now + ttlMs, parentExpires))
}

/**
 * Builds a fresh generation-delegation service entry for an annex
 * document. The `serviceEndpoint` is the full delegated-zcap JSON as a
 * single map, byte-identical to what `zcapClient.delegate` produced -- the
 * annex entry proof (JCS canonicalization) then covers it byte for byte,
 * so host tampering with the stored delegation is client-visible.
 *
 * @param options {object}
 * @param options.clientAnnexDid {string}   the generation's annex DID
 * @param options.delegation {IZcap}   the minted generation delegation
 * @returns {ServiceEndpoint}
 */
export function generationDelegationServiceEntry({
  clientAnnexDid,
  delegation
}: {
  clientAnnexDid: string
  delegation: IZcap
}): ServiceEndpoint {
  return {
    id: `${clientAnnexDid}#${GENERATION_DELEGATION_SERVICE_FRAGMENT}`,
    type: GENERATION_DELEGATION_SERVICE_TYPE,
    serviceEndpoint: delegation as unknown as ServiceEndpoint['serviceEndpoint']
  }
}

/**
 * The generation delegation an annex document carries: the
 * `serviceEndpoint` map of the service entry whose `type` names (or
 * includes) {@link GENERATION_DELEGATION_SERVICE_TYPE}. Only a map-form
 * endpoint counts (the delegation is embedded as the zcap JSON itself,
 * never as a URL or an encoded string).
 *
 * @param options {object}
 * @param options.doc {DIDDoc}   the resolved (and verified) annex
 *   document
 * @returns {IZcap | undefined}
 */
export function embeddedGenerationDelegation({
  doc
}: {
  doc: DIDDoc
}): IZcap | undefined {
  for (const entry of doc.service ?? []) {
    const types = Array.isArray(entry.type) ? entry.type : [entry.type]
    if (types.includes(GENERATION_DELEGATION_SERVICE_TYPE)) {
      const endpoint = entry.serviceEndpoint
      if (
        endpoint !== null &&
        typeof endpoint === 'object' &&
        !Array.isArray(endpoint)
      ) {
        return endpoint as unknown as IZcap
      }
    }
  }
  return undefined
}

/**
 * Every generation delegation a generation's log has ever embedded, in log
 * order and deduplicated by zcap id -- the annex-log HISTORY WALK the
 * last-durable-client forget revokes from (decision 0004's 2026-08-19
 * amendment): a renewal replaces the head service entry's endpoint in place,
 * so a superseded delegation's bytes survive only in earlier entries'
 * re-stated full state, and a renewal inside the 30-day window can leave TWO
 * still-unexpired ladder-signed delegations. The caller filters (signer,
 * expiry) and revokes; this walk only recovers the bytes.
 *
 * @param options {object}
 * @param options.log {DIDLog}   the generation's VERIFIED log
 * @returns {IZcap[]}
 */
export function generationDelegationHistory({ log }: { log: DIDLog }): IZcap[] {
  const seen = new Set<string>()
  const delegations: IZcap[] = []
  for (const entry of log) {
    const embedded = embeddedGenerationDelegation({
      doc: entry.state as DIDDoc
    })
    if (embedded === undefined) {
      continue
    }
    const id = (embedded as { id?: string }).id
    if (typeof id !== 'string' || seen.has(id)) {
      continue
    }
    seen.add(id)
    delegations.push(embedded)
  }
  return delegations
}

/**
 * Submits the revocation of a generation delegation, reading the server's
 * 400 answer as success: an already-revoked chain (a resumed ceremony's
 * blind re-POST) and an expired delegation (which no longer needs revoking)
 * both land there, and the revocation protocol exposes no read endpoint to
 * distinguish them beforehand. Matched on `err.name` -- error classes do not
 * survive crossing package copies. The `revoke` seam is was-client's
 * `WasClient#revoke`, bound by the caller.
 *
 * @param options {object}
 * @param options.revoke {Function}   `(delegation) => Promise<void>` --
 *   POSTs the revocation (`was.revoke`)
 * @param options.delegation {IZcap}
 * @returns {Promise<void>}
 */
export async function revokeTreatingAlreadyRevokedAsSuccess({
  revoke,
  delegation
}: {
  revoke: (delegation: IDelegatedZcap) => Promise<void>
  delegation: IZcap
}): Promise<void> {
  try {
    await revoke(delegation as unknown as IDelegatedZcap)
  } catch (err) {
    if ((err as { name?: string }).name === 'ValidationError') {
      return
    }
    throw err
  }
}

/**
 * The annex document's service list with the generation delegation
 * installed: an existing entry's endpoint is replaced in place, its fragment
 * id preserved verbatim (the id is non-semantic and stable); absent one, a
 * fresh entry is appended. Every other service entry is preserved untouched.
 *
 * @param options {object}
 * @param options.doc {DIDDoc}   the annex document as published
 * @param options.clientAnnexDid {string}
 * @param options.delegation {IZcap}
 * @returns {ServiceEndpoint[]}
 */
function withGenerationDelegationEntry({
  doc,
  clientAnnexDid,
  delegation
}: {
  doc: DIDDoc
  clientAnnexDid: string
  delegation: IZcap
}): ServiceEndpoint[] {
  const existing = (doc.service ?? []) as ServiceEndpoint[]
  const isDelegationEntry = (entry: ServiceEndpoint) => {
    const types = Array.isArray(entry.type) ? entry.type : [entry.type]
    return types.includes(GENERATION_DELEGATION_SERVICE_TYPE)
  }
  return existing.some(isDelegationEntry)
    ? existing.map(entry =>
        isDelegationEntry(entry)
          ? {
              ...entry,
              serviceEndpoint:
                delegation as unknown as ServiceEndpoint['serviceEndpoint']
            }
          : entry
      )
    : [
        ...existing,
        generationDelegationServiceEntry({ clientAnnexDid, delegation })
      ]
}

/**
 * Parses the auxiliary Space id and generation id out of an annex DID
 * string. Both are permanent substrings of every annex DID by
 * construction: the generation id is the final path segment of the annex
 * DID (`did:webvh:<scid>:<host>:...:space:<spaceId>:<generationId>`), and it
 * is the generation-identifying half of the annex rung HKDF
 * labels, so this parse is what lets an enrollee derive its writing key from
 * the pointer alone -- no log read, no registry.
 *
 * @param options {object}
 * @param options.did {string}   an annex did:webvh string
 * @returns {{ spaceId: string, generationId: string }}
 */
export function clientAnnexDidParts({ did }: { did: string }): {
  spaceId: string
  generationId: string
} {
  const parts = did.split(':')
  const generationId = parts[parts.length - 1]
  const spaceId = parts[parts.length - 2]
  if (
    parts.length < 7 ||
    parts[0] !== 'did' ||
    parts[1] !== 'webvh' ||
    parts[parts.length - 3] !== 'space' ||
    generationId === undefined ||
    spaceId === undefined ||
    spaceId.length === 0
  ) {
    throw new Error(`Not a client annex did:webvh: "${did}".`)
  }
  assertGenerationId(generationId)
  return { spaceId, generationId }
}

/**
 * Thrown when the published annex log commits neither the writing
 * credential's rung-0 key nor its hash -- the mid-generation lockout: a
 * credential bound after the generation's genesis cannot write the annex
 * until an existing writer commits its rung-0 hash or the next GC swap's
 * genesis does. Typed so callers can map it to the fresh-generation path
 * where one is licensed (the transient-recovery continuation) or to honest
 * copy where none is.
 */
export class ClientAnnexRungUncommittedError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ClientAnnexRungUncommittedError'
  }
}

/**
 * The narrow store seam an annex entry is read and published through: the
 * log read and the conditional `did.jsonl` PUT, nothing else (an annex has
 * no `did.json` projection and no key map). Satisfied by
 * {@link clientAnnexLogStore} (controller-tier signing) and by the delegated
 * store a transient session writes through (`delegatedWebvhLogStore`,
 * invoking the credential's sibling delegation).
 */
export type ClientAnnexWriteStore = Pick<
  WebvhIdStore,
  'getIdResourceRaw' | 'putIdResource'
>

/**
 * Reads and resolves the published annex log through the narrow seam, or
 * throws when the generation's `did.jsonl` is missing (an unpointed or
 * deleted generation -- nothing to enroll into).
 *
 * @param options {object}
 * @param options.store {ClientAnnexWriteStore}
 * @param [options.expectedDid] {string}
 * @param [options.pinStore] {ResourceLogPinStore}
 * @param [options.logId] {string}
 * @returns {Promise<PublishedWebvhLog>}
 */
async function readClientAnnexLogOrThrow({
  store,
  expectedDid,
  pinStore,
  logId
}: {
  store: ClientAnnexWriteStore
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<PublishedWebvhLog> {
  // readPublishedLog only calls getIdResourceRaw, so the narrow seam is safe.
  const published = await readPublishedLog({
    idStore: store as WebvhIdStore,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore !== undefined ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {})
  })
  if (!published) {
    throw new Error(
      'client annex: did.jsonl is missing; the generation was never minted or ' +
        'has been collected.'
    )
  }
  return published
}

/**
 * TRANSIENT ENROLLMENT: publishes one per-visit verification method into a
 * annex generation's log -- one atomic entry, signed by the writing
 * credential's static rung 0 (derived from the ladder seed and the generation
 * id;
 * see `clientAnnexRung`). The entry:
 *
 * - reveals the writer's rung-0 key into `updateKeys` at its first annex
 *   write (later writes re-state it unchanged);
 * - re-states `nextKeyHashes` verbatim -- every standing credential's rung-0
 *   hash, the writer's own carry-over hash included -- explicitly on the
 *   entry, never inherited from the prior entry's parameters;
 * - adds the transient VM under `capabilityInvocation` ONLY, with all five
 *   relationship arrays stated explicitly (no `authentication`, no
 *   `assertionMethod`, no `keyAgreement` twin -- the DIDAuth path signs as
 *   the bare did:key, and the controller-marker convention does not arise in
 *   the annex at all).
 *
 * The transient key set carries no update key, and nothing here touches the
 * ACCOUNT log's `updateKeys` or `nextKeyHashes`. There is no two-entry
 * reveal/add split and no attribution scan: a CAS loser re-signs with the
 * SAME key via the ordinary conflict retry, and resumability reduces to the
 * published document's own state -- a VM already present is a no-op.
 *
 * A writer whose rung-0 key is neither revealed nor committed is refused
 * ({@link ClientAnnexRungUncommittedError}): annex entries verify against
 * the log's own hash-commitment chain, so no admission rule can make an
 * uncommitted key verify mid-log.
 *
 * @param options {object}
 * @param options.store {ClientAnnexWriteStore}   the generation's log store
 *   (delegated through the credential's sibling delegation, or
 *   controller-tier)
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed, from
 *   its unlock record
 * @param options.generationId {string}   the generation collection's name
 * @param options.transientKeyMultibase {string}   the visit's in-memory
 *   Ed25519 signing key, public multibase
 * @param [options.services] {ServiceEndpoint[]}   the annex document's
 *   full service-entry list, replacing the published one wholesale; omitted,
 *   the prior entries are preserved verbatim (or extended by
 *   `mintGenerationDelegation` below). Supplying both is refused in favor of
 *   the explicit list
 * @param [options.mintGenerationDelegation] {Function}
 *   `({ clientAnnexDid }) => Promise<IZcap>` -- mints the generation
 *   delegation this entry installs when it publishes the generation's FIRST
 *   transient verification method (and the document carries no delegation
 *   entry yet). Never invoked otherwise: the delegation is installed with
 *   the first transient VM or by the GC ceremony's own install stage, never
 *   by genesis (a genesis-embedded signed zcap can never verify -- its
 *   `controller` embeds the SCID the genesis hash derives from)
 * @param [options.expectedDid] {string}   the annex DID the log must
 *   resolve to, from the account document's pointer
 * @param [options.pinStore] {ResourceLogPinStore}   chain-head pins (a
 *   transient session passes an in-memory store)
 * @param [options.logId] {string}   the generation's pin-slot key, from
 *   {@link clientAnnexLogPinId}; required whenever a `pinStore` is supplied
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}
 */
export async function enrollClientAnnexTransientClient(options: {
  store: ClientAnnexWriteStore
  ladderSeed: Uint8Array
  generationId: string
  transientKeyMultibase: string
  services?: ServiceEndpoint[]
  mintGenerationDelegation?: (options: {
    clientAnnexDid: string
  }) => Promise<IZcap>
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  return withLogConflictRetry(() =>
    enrollClientAnnexTransientClientOnce(options)
  )
}

/**
 * One attempt of {@link enrollClientAnnexTransientClient}, re-invoked by the
 * conflict retry (with the same signing key -- static rung 0 has no
 * advanced-rung retry shape).
 *
 * @param options {object}   see {@link enrollClientAnnexTransientClient}
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}
 */
async function enrollClientAnnexTransientClientOnce({
  store,
  ladderSeed,
  generationId,
  transientKeyMultibase,
  services,
  mintGenerationDelegation: mintDelegation,
  expectedDid,
  pinStore,
  logId
}: {
  store: ClientAnnexWriteStore
  ladderSeed: Uint8Array
  generationId: string
  transientKeyMultibase: string
  services?: ServiceEndpoint[]
  mintGenerationDelegation?: (options: {
    clientAnnexDid: string
  }) => Promise<IZcap>
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  assertGenerationId(generationId)
  const published = await readClientAnnexLogOrThrow({
    store,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore !== undefined ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {})
  })
  const { did, doc } = published
  const vmId = `${did}#${transientKeyMultibase}`

  // Already enrolled (a completed earlier run): the VM and everything the
  // atomic entry carries beside it landed together, so presence alone is the
  // completion predicate.
  const existingMethods = (doc.verificationMethod ?? []) as VerificationMethod[]
  if (existingMethods.some(method => method.id === vmId)) {
    return { did, doc, log: published.log }
  }

  const rung = await clientAnnexRung({ ladderSeed, generationId })
  const rungHash = await deriveNextKeyHash(rung.keyMultibase)
  const revealed = published.updateKeys.includes(rung.keyMultibase)
  if (!revealed && !published.nextKeyHashes.includes(rungHash)) {
    throw new ClientAnnexRungUncommittedError(
      "client annex: the log commits neither this credential's rung-0 key nor " +
        'its hash; a credential bound mid-generation cannot write the ' +
        'annex until a writer commits its hash or the next GC swap does.'
    )
  }
  // A non-rotating entry re-states `updateKeys`, which the resolver checks
  // against the previous entry's commitments -- genesis enforces the
  // carry-over convention, and this refuses a log that lost it anyway.
  await assertCarryOverCommitments({ published })

  // The generation delegation installs with the first transient VM (never at
  // genesis): a delegation-less document about to receive its first method
  // gets the entry minted and appended here, so a generation with no visits
  // never carries a delegation and stays authorization-inert.
  if (
    services === undefined &&
    mintDelegation !== undefined &&
    existingMethods.length === 0 &&
    embeddedGenerationDelegation({ doc }) === undefined
  ) {
    const delegation = await mintDelegation({ clientAnnexDid: did })
    services = withGenerationDelegationEntry({
      doc,
      clientAnnexDid: did,
      delegation
    })
  }

  const transientMethod: VerificationMethod = {
    id: vmId,
    type: MULTIKEY_VM_TYPE,
    controller: did,
    publicKeyMultibase: transientKeyMultibase
  }
  const signer = await updateKeySigner({ seed: rung.seed })
  const updated = await updateDID({
    log: published.log,
    signer,
    additionalContext: [MULTIKEY_CONTEXT_URL],
    updateKeys: [...new Set([...published.updateKeys, rung.keyMultibase])],
    // Re-stated verbatim, the writer's carry-over hash among them; the
    // explicit re-statement (never parameter inheritance) is what lets the
    // NEXT entry's re-stated `updateKeys` resolve.
    nextKeyHashes: [...published.nextKeyHashes],
    verificationMethods: [...existingMethods, transientMethod],
    // All five relationship arrays stated explicitly: the library defaults a
    // purpose-less method into `authentication` at normalization, and the
    // explicit arrays are what override that -- the transient VM appears
    // under `capabilityInvocation` and nowhere else.
    authentication: relationIds(doc.authentication),
    assertionMethod: relationIds(doc.assertionMethod),
    keyAgreement: relationIds(doc.keyAgreement),
    capabilityInvocation: [
      ...new Set([...relationIds(doc.capabilityInvocation), vmId])
    ],
    capabilityDelegation: relationIds(doc.capabilityDelegation),
    ...(services !== undefined ? { services } : {})
  })
  // The log only -- an annex has no did:web projection -- conditional on
  // the read this entry was built on.
  await putLogResource({ store, log: updated.log, ifMatch: published.etag })
  return { did: updated.did, doc: updated.doc, log: updated.log }
}

/**
 * Points the account document's delegated-clients service entry at a
 * annex DID -- the first install after a generation's genesis, and the GC
 * swap's re-point alike. One ordinary document-update entry, signed by an
 * enrolled durable client's active update key; the annex log always
 * publishes FIRST (see {@link mintClientAnnexGeneration}), so a tear leaves an
 * unpointed, authorization-inert generation, never a dangling pointer.
 *
 * An existing delegated-clients entry is re-pointed in place, its fragment id
 * preserved verbatim (the id is non-semantic and stable); absent one, a fresh
 * entry is appended ({@link delegatedClientsServiceEntry}). Every other
 * service entry, the verification methods, and the relationship arrays are
 * preserved untouched. Idempotent: a document already pointing at the DID is
 * a no-op on the log (it still heals a lagging `did.json`).
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}   the ACCOUNT log's store; with
 *   `logOnly`, only its log read and `did.jsonl` PUT are used, so the narrow
 *   delegated seam satisfies it
 * @param options.updateKeys {ClientWebvhUpdateKeys}   this durable client's
 *   update-key seeds -- or the ladder-rung idiom on a ladder-anchored
 *   account (`{ updateSeed: rung0.seed, stagedSeed: rung1.seed }`), as the
 *   credential-anchored genesis and the transient-recovery continuation pass
 * @param options.clientAnnexDid {string}   the generation to point at
 * @param [options.expectedDid] {string}   the account DID the log must
 *   resolve to, from the account pointer
 * @param [options.pinStore] {ResourceLogPinStore}   this client's chain-head
 *   pins for the account log
 * @param [options.logId] {string}   the account log's pin-slot key, from
 *   `accountLogPinId({ spaceId })`; required whenever a `pinStore` is
 *   supplied
 * @param [options.logOnly] {boolean}   publish `did.jsonl` only, never the
 *   `did.json` projection -- the transient-recovery continuation writing
 *   through the record's bridge delegation, whose narrow scope covers nothing
 *   but the log. The projection heals at the next authorized write (the log
 *   is the source of truth)
 * @returns {Promise<{ did: string, doc: DIDDoc }>}
 */
export async function setDelegatedClientsPointer(options: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  clientAnnexDid: string
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
  logOnly?: boolean
}): Promise<{ did: string; doc: DIDDoc }> {
  return withLogConflictRetry(() => setDelegatedClientsPointerOnce(options))
}

/**
 * One attempt of {@link setDelegatedClientsPointer}, re-invoked by the
 * conflict retry.
 *
 * @param options {object}   see {@link setDelegatedClientsPointer}
 * @returns {Promise<{ did: string, doc: DIDDoc }>}
 */
async function setDelegatedClientsPointerOnce({
  idStore,
  updateKeys,
  clientAnnexDid,
  expectedDid,
  pinStore,
  logId,
  logOnly = false
}: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  clientAnnexDid: string
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
  logOnly?: boolean
}): Promise<{ did: string; doc: DIDDoc }> {
  // Refuses a malformed target before anything is read or written.
  clientAnnexDidParts({ did: clientAnnexDid })
  const published = await readPublishedLog({
    idStore,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore !== undefined ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {})
  })
  if (!published) {
    throw new Error(
      'did:webvh: did.jsonl is missing; nothing to point at a client annex.'
    )
  }
  const { did, doc } = published
  if (delegatedClientsPointer({ doc }) === clientAnnexDid) {
    if (!logOnly) {
      await concludeWithPublishedLog({ idStore, published })
    }
    return { did, doc }
  }

  // The entry is signed by this client's active update key; a log that does
  // not authorize it (a rotation torn elsewhere) must heal first.
  const activeKey = await updateKeyMultibase({ seed: updateKeys.updateSeed })
  if (!published.updateKeys.includes(activeKey)) {
    throw new Error(
      "did:webvh: the published log does not authorize this client's active " +
        'update key; finalize the pending rotation before re-pointing the ' +
        'delegated-clients entry.'
    )
  }
  await assertCarryOverCommitments({ published })

  const services = servicesPointedAtClientAnnex({
    doc,
    accountDid: did,
    clientAnnexDid
  })

  const signer = await updateKeySigner({ seed: updateKeys.updateSeed })
  const updated = await updateDID({
    log: published.log,
    signer,
    alsoKnownAsWeb: true,
    // Re-stated unchanged (the library requires them explicitly while
    // prerotation is active); the carry-over commitments are what make the
    // re-statement resolvable.
    updateKeys: published.updateKeys,
    nextKeyHashes: published.nextKeyHashes,
    services
  })
  if (logOnly) {
    await putLogResource({
      store: idStore,
      log: updated.log,
      ifMatch: published.etag
    })
  } else {
    await publishUpdatedLog({ idStore, updated, ifMatch: published.etag })
  }
  return { did: updated.did, doc: updated.doc }
}

/**
 * The whole transient-enrollment ceremony as the enrollee runs it: resolve
 * the account document's delegated-clients pointer, enroll the visit's key
 * into the pointed generation, then RE-READ the pointer -- the GC-race
 * closure. An enrollment landing between a GC pass's guard check and its
 * re-point would otherwise yield a session whose generation the pointer then
 * abandons and whose delegation is already revoked; the enrollee closes the
 * race with one extra read, re-enrolling into the fresh generation on a
 * mismatch. Convergent under retry (each round enrolls into whatever the
 * pointer names NOW), and idempotent per generation like the entry itself.
 *
 * @param options {object}
 * @param options.readAccountDocument {Function}   reads the VERIFIED account
 *   document (the caller's `verifyAccountLog` read, pins and `expectedDid`
 *   applied there); called once per round
 * @param options.storeForGenerationId {Function}   builds the generation's log
 *   store for a generation id (the delegated store over the credential's
 *   sibling
 *   delegation, or a controller-tier store)
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed
 * @param options.transientKeyMultibase {string}   the visit's in-memory
 *   signing key, public multibase
 * @param [options.mintGenerationDelegation] {Function}
 *   `({ clientAnnexDid }) => Promise<IZcap>` -- forwarded to the enrollment
 *   entry, which installs the minted delegation when it publishes the
 *   generation's first transient VM (see
 *   {@link enrollClientAnnexTransientClient}). The closure receives whichever
 *   annex DID the round enrolls into, so a GC-race re-enroll mints for
 *   the fresh generation
 * @param [options.pinStore] {ResourceLogPinStore}   chain-head pins for the
 *   generation logs (a transient session passes an in-memory store); slot
 *   keys are derived per generation with {@link clientAnnexLogPinId}
 * @param [options.maxRounds] {number}   how many pointer moves to chase
 *   before giving up (a GC pass is quarterly, so more than one mid-ceremony
 *   move means something else is wrong)
 * @returns {Promise<{ clientAnnexDid: string, doc: DIDDoc, log: DIDLog }>}
 */
export async function enrollTransientClient({
  readAccountDocument,
  storeForGenerationId,
  ladderSeed,
  transientKeyMultibase,
  mintGenerationDelegation: mintDelegation,
  pinStore,
  maxRounds = 3
}: {
  readAccountDocument: () => Promise<DIDDoc>
  storeForGenerationId: (generationId: string) => ClientAnnexWriteStore
  ladderSeed: Uint8Array
  transientKeyMultibase: string
  mintGenerationDelegation?: (options: {
    clientAnnexDid: string
  }) => Promise<IZcap>
  pinStore?: ResourceLogPinStore
  maxRounds?: number
}): Promise<{ clientAnnexDid: string; doc: DIDDoc; log: DIDLog }> {
  let accountDoc = await readAccountDocument()
  for (let round = 0; round < maxRounds; round++) {
    const clientAnnexDid = delegatedClientsPointer({ doc: accountDoc })
    if (clientAnnexDid === undefined) {
      throw new Error(
        'client annex: the account document carries no delegated-clients ' +
          'service entry; no generation exists to enroll into.'
      )
    }
    const { spaceId, generationId } = clientAnnexDidParts({
      did: clientAnnexDid
    })
    const enrolled = await enrollClientAnnexTransientClient({
      store: storeForGenerationId(generationId),
      ladderSeed,
      generationId,
      transientKeyMultibase,
      expectedDid: clientAnnexDid,
      ...(mintDelegation !== undefined
        ? { mintGenerationDelegation: mintDelegation }
        : {}),
      ...(pinStore !== undefined
        ? { pinStore, logId: clientAnnexLogPinId({ spaceId, generationId }) }
        : {})
    })
    // The GC-race re-read: an unchanged pointer means the enrollment stands
    // in the pointed generation; a moved one means a concurrent GC abandoned
    // it, and the next round enrolls into the fresh generation.
    accountDoc = await readAccountDocument()
    if (delegatedClientsPointer({ doc: accountDoc }) === clientAnnexDid) {
      return { clientAnnexDid, doc: enrolled.doc, log: enrolled.log }
    }
  }
  throw new Error(
    'client annex: the delegated-clients pointer kept moving across ' +
      `${String(maxRounds)} enrollment rounds; giving up.`
  )
}

/**
 * RENEW PRECEDES MINT: the blocking pre-mint stage a transient App Connect
 * approval runs before delegating any grant. Reads the annex document
 * and hands back its embedded generation delegation -- renewing it first
 * when it is expired or inside the 30-day renewal window ({@link
 * zcapExpiring}): a fresh delegation is minted through the caller's closure
 * (ladder-signed -- the renewal must not depend on the very delegation it
 * replaces; published through the store, which in a transient session is
 * the credential's sibling delegation, so even a hard-expired delegation is
 * recoverable), and one annex entry replaces the service entry's
 * endpoint in place, signed by the writing credential's static rung 0.
 *
 * An annex document carrying no delegation entry at all installs one the
 * same way (the GC ceremony's own install stage and the first-VM install
 * make this rare; a heal, not a policy).
 *
 * Beside the expiry axis, an `accountDoc` adds the SIGNER-DEATH axis: a
 * standing delegation whose proof key is no longer in the supplied verified
 * account document has rotted under the current-key-set rule (the durable
 * client that minted it was revoked, or the ladder VM that signed it left
 * with the first durable self-enrollment) and is replaced the same way. No
 * revocation POST accompanies the replacement: a rotted chain no longer
 * verifies at the revocation endpoint, and the expiry-renewal path never
 * revoked either.
 *
 * Failure is the caller's failure: a renewal that cannot complete throws,
 * and the App Connect approval fails with the standard retryable-ceremony
 * posture -- deliberately no clamp-on-failure fallback, which would deliver
 * exactly the silently short grant this stage exists to prevent. By
 * construction a grant minted behind a completed renewal never meets the
 * monotonicity clamp below its full TTL except for 365-day-class grants at
 * 30 or more days remaining ({@link clampGrantExpires}).
 *
 * @param options {object}
 * @param options.store {ClientAnnexWriteStore}   the generation's log store
 *   (delegated through the credential's sibling delegation, or
 *   controller-tier)
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed, from
 *   its unlock record
 * @param options.generationId {string}   the generation collection's name
 * @param options.mintGenerationDelegation {Function}
 *   `({ clientAnnexDid }) => Promise<IZcap>` -- mints the replacement
 *   delegation (ladder-signed in a transient session)
 * @param [options.expectedDid] {string}   the annex DID the log must
 *   resolve to, from the account document's pointer
 * @param [options.pinStore] {ResourceLogPinStore}   chain-head pins (a
 *   transient session passes an in-memory store)
 * @param [options.logId] {string}   the generation's pin-slot key, from
 *   {@link clientAnnexLogPinId}; required whenever a `pinStore` is supplied
 * @param [options.accountDoc] {PublishedKeyDocument}   the locally VERIFIED
 *   account document; supplied, a standing delegation whose proof key it no
 *   longer lists is replaced (the signer-death axis above)
 * @param [options.force] {boolean}   replace the embedded delegation
 *   unconditionally, however healthy it looks -- the last-durable-client
 *   forget's replacement stage, where the standing delegation has just been
 *   revoked server-side (a state no client-side predicate can read)
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {Promise<{ delegation: IZcap, renewed: boolean }>}
 */
export async function ensureGenerationDelegationCurrent(options: {
  store: ClientAnnexWriteStore
  ladderSeed: Uint8Array
  generationId: string
  mintGenerationDelegation: (options: {
    clientAnnexDid: string
  }) => Promise<IZcap>
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
  accountDoc?: PublishedKeyDocument
  force?: boolean
  now?: number
}): Promise<{ delegation: IZcap; renewed: boolean }> {
  return withLogConflictRetry(() =>
    ensureGenerationDelegationCurrentOnce(options)
  )
}

/**
 * One attempt of {@link ensureGenerationDelegationCurrent}, re-invoked by the
 * conflict retry (with the same signing key -- static rung 0 has no
 * advanced-rung retry shape).
 *
 * @param options {object}   see {@link ensureGenerationDelegationCurrent}
 * @returns {Promise<{ delegation: IZcap, renewed: boolean }>}
 */
async function ensureGenerationDelegationCurrentOnce({
  store,
  ladderSeed,
  generationId,
  mintGenerationDelegation: mintDelegation,
  expectedDid,
  pinStore,
  logId,
  accountDoc,
  force = false,
  now
}: {
  store: ClientAnnexWriteStore
  ladderSeed: Uint8Array
  generationId: string
  mintGenerationDelegation: (options: {
    clientAnnexDid: string
  }) => Promise<IZcap>
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
  accountDoc?: PublishedKeyDocument
  force?: boolean
  now?: number
}): Promise<{ delegation: IZcap; renewed: boolean }> {
  assertGenerationId(generationId)
  const published = await readClientAnnexLogOrThrow({
    store,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore !== undefined ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {})
  })
  const { did, doc } = published
  const standing = embeddedGenerationDelegation({ doc })
  const signerRotted =
    standing !== undefined &&
    accountDoc !== undefined &&
    !delegationKeyInDocument({
      doc: accountDoc,
      ...(delegationProofKeyId(standing) !== undefined
        ? { delegationKeyId: delegationProofKeyId(standing) }
        : {})
    })
  if (
    !force &&
    standing !== undefined &&
    !signerRotted &&
    !zcapExpiring({
      ...((standing as { expires?: string }).expires !== undefined
        ? { expires: (standing as { expires?: string }).expires }
        : {}),
      ...(now !== undefined ? { now } : {})
    })
  ) {
    return { delegation: standing, renewed: false }
  }

  // The rung refusal precedes the mint: nothing is delegated for a writer
  // who cannot publish the entry that would carry it.
  const rung = await clientAnnexRung({ ladderSeed, generationId })
  const rungHash = await deriveNextKeyHash(rung.keyMultibase)
  const revealed = published.updateKeys.includes(rung.keyMultibase)
  if (!revealed && !published.nextKeyHashes.includes(rungHash)) {
    throw new ClientAnnexRungUncommittedError(
      "client annex: the log commits neither this credential's rung-0 key nor " +
        'its hash; a credential bound mid-generation cannot renew the ' +
        'generation delegation until a writer commits its hash or the next ' +
        'GC swap does.'
    )
  }
  await assertCarryOverCommitments({ published })
  const fresh = await mintDelegation({ clientAnnexDid: did })

  const signer = await updateKeySigner({ seed: rung.seed })
  const updated = await updateDID({
    log: published.log,
    signer,
    // The writer's rung-0 key reveals at its first annex write, exactly
    // as the enrollment entry does; `nextKeyHashes` is re-stated verbatim,
    // never inherited. Verification methods, relationship arrays, and every
    // other service entry ride the library's prior-state clone untouched.
    updateKeys: [...new Set([...published.updateKeys, rung.keyMultibase])],
    nextKeyHashes: [...published.nextKeyHashes],
    services: withGenerationDelegationEntry({
      doc,
      clientAnnexDid: did,
      delegation: fresh
    })
  })
  await putLogResource({ store, log: updated.log, ifMatch: published.etag })
  return { delegation: fresh, renewed: true }
}

/**
 * THE CLIENT-ANNEX RUNG STRIKE: drops a retired credential's annex posture
 * from a generation's log -- its revealed rung-0 key out of `updateKeys` and
 * its standing rung-0 hash out of `nextKeyHashes` -- in one atomic entry
 * signed by ANOTHER credential's committed rung 0 (an annex entry cannot
 * remove its own signing key: the entry verifies against its own re-stated
 * `updateKeys`). The credential-rotation ceremony's annex reach.
 *
 * A log committing neither the retired rung's key nor its hash is already
 * clean and the strike no-ops (`struck: false`) -- the resumable shape, and
 * the common one: a credential that never minted or wrote this generation
 * has no posture in it. An acting rung the log does not commit (after the
 * retired members are excluded -- so the retired credential can never sign
 * its own strike) is refused with {@link ClientAnnexRungUncommittedError},
 * which the caller maps to the generation-swap fallback: a fresh generation
 * minted from a surviving credential's seed retires the rung with the whole
 * generation.
 *
 * @param options {object}
 * @param options.store {ClientAnnexWriteStore}   the pointed generation's log
 *   store (controller-tier, or delegated through a sibling delegation)
 * @param options.retiredLadderSeed {Uint8Array}   the RETIRED credential's
 *   ladder seed (its rung is derived per generation, so the seed is the only
 *   way to name what to strike)
 * @param options.actingLadderSeed {Uint8Array}   a surviving credential's
 *   ladder seed, whose committed rung 0 signs the strike entry
 * @param options.generationId {string}   the generation collection's name
 * @param [options.expectedDid] {string}   the annex DID the log must
 *   resolve to, from the account document's pointer
 * @param [options.pinStore] {ResourceLogPinStore}
 * @param [options.logId] {string}   the generation's pin-slot key, from
 *   {@link clientAnnexLogPinId}; required whenever a `pinStore` is supplied
 * @returns {Promise<{ struck: boolean }>}
 */
export async function retireClientAnnexRung(options: {
  store: ClientAnnexWriteStore
  retiredLadderSeed: Uint8Array
  actingLadderSeed: Uint8Array
  generationId: string
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ struck: boolean }> {
  return withLogConflictRetry(() => retireClientAnnexRungOnce(options))
}

/**
 * One attempt of {@link retireClientAnnexRung}, re-invoked by the conflict
 * retry (with the same signing key -- static rung 0 has no advanced-rung
 * retry shape).
 *
 * @param options {object}   see {@link retireClientAnnexRung}
 * @returns {Promise<{ struck: boolean }>}
 */
async function retireClientAnnexRungOnce({
  store,
  retiredLadderSeed,
  actingLadderSeed,
  generationId,
  expectedDid,
  pinStore,
  logId
}: {
  store: ClientAnnexWriteStore
  retiredLadderSeed: Uint8Array
  actingLadderSeed: Uint8Array
  generationId: string
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ struck: boolean }> {
  assertGenerationId(generationId)
  const published = await readClientAnnexLogOrThrow({
    store,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore !== undefined ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {})
  })

  const retired = await clientAnnexRung({
    ladderSeed: retiredLadderSeed,
    generationId
  })
  const retiredHash = await deriveNextKeyHash(retired.keyMultibase)
  const remainingKeys = published.updateKeys.filter(
    key => key !== retired.keyMultibase
  )
  const remainingHashes = published.nextKeyHashes.filter(
    hash => hash !== retiredHash
  )
  if (
    remainingKeys.length === published.updateKeys.length &&
    remainingHashes.length === published.nextKeyHashes.length
  ) {
    // Already clean: the retired credential holds no posture in this
    // generation (never committed, or a completed earlier strike).
    return { struck: false }
  }

  // The acting rung must be committed AFTER the retired members are
  // excluded, so the retired credential can never sign its own strike.
  const acting = await clientAnnexRung({
    ladderSeed: actingLadderSeed,
    generationId
  })
  const actingHash = await deriveNextKeyHash(acting.keyMultibase)
  const revealed = remainingKeys.includes(acting.keyMultibase)
  if (!revealed && !remainingHashes.includes(actingHash)) {
    throw new ClientAnnexRungUncommittedError(
      "client annex: the log commits neither the acting credential's rung-0 " +
        'key nor its hash (or it is the retired rung itself); the strike ' +
        'needs a distinct committed writer -- swap the generation instead.'
    )
  }
  await assertCarryOverCommitments({ published })

  const signer = await updateKeySigner({ seed: acting.seed })
  const updated = await updateDID({
    log: published.log,
    signer,
    // The acting rung reveals at its first annex write, exactly as the
    // enrollment entry does; the retired rung's key and hash are dropped by
    // explicit re-statement (never parameter inheritance). Verification
    // methods, relationship arrays, and the service entries ride the
    // library's prior-state clone untouched.
    updateKeys: [...new Set([...remainingKeys, acting.keyMultibase])],
    nextKeyHashes: [...remainingHashes]
  })
  await putLogResource({ store, log: updated.log, ifMatch: published.etag })
  return { struck: true }
}

/**
 * THE CLIENT-ANNEX RUNG COMMIT: adds a freshly bound credential's rung-0
 * hash to a generation's `nextKeyHashes` -- one atomic hash-restating entry
 * signed by an already-committed credential's rung 0. The bind ceremonies'
 * annex reach (passkey add, passphrase change): a bind runs from a logged-in
 * session whose own login credential's rung 0 is committed, so committing the
 * new credential's hash here is what keeps it out of the mid-generation
 * lockout ({@link ClientAnnexRungUncommittedError} at its first transient
 * login, otherwise standing until the next GC swap's genesis).
 *
 * A log already committing the bound rung's hash (or carrying its revealed
 * key) is a no-op (`committed: false`) -- the resumable shape. An acting rung
 * the log does not commit is refused with
 * {@link ClientAnnexRungUncommittedError}: the bind ceremony maps that to an
 * honest skip (nothing licenses it to mint a generation), and the lockout
 * consequence stands as documented.
 *
 * @param options {object}
 * @param options.store {ClientAnnexWriteStore}   the pointed generation's log
 *   store (controller-tier, or delegated through a sibling delegation)
 * @param options.boundLadderSeed {Uint8Array}   the freshly bound
 *   credential's ladder seed (its rung is derived per generation, so the seed
 *   is the only way to name what to commit)
 * @param options.actingLadderSeed {Uint8Array}   the logged-in session's
 *   login credential's ladder seed, whose committed rung 0 signs the entry
 * @param options.generationId {string}   the generation collection's name
 * @param [options.expectedDid] {string}   the annex DID the log must
 *   resolve to, from the account document's pointer
 * @param [options.pinStore] {ResourceLogPinStore}
 * @param [options.logId] {string}   the generation's pin-slot key, from
 *   {@link clientAnnexLogPinId}; required whenever a `pinStore` is supplied
 * @returns {Promise<{ committed: boolean }>}
 */
export async function commitClientAnnexRung(options: {
  store: ClientAnnexWriteStore
  boundLadderSeed: Uint8Array
  actingLadderSeed: Uint8Array
  generationId: string
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ committed: boolean }> {
  return withLogConflictRetry(() => commitClientAnnexRungOnce(options))
}

/**
 * One attempt of {@link commitClientAnnexRung}, re-invoked by the conflict
 * retry (with the same signing key -- static rung 0 has no advanced-rung
 * retry shape).
 *
 * @param options {object}   see {@link commitClientAnnexRung}
 * @returns {Promise<{ committed: boolean }>}
 */
async function commitClientAnnexRungOnce({
  store,
  boundLadderSeed,
  actingLadderSeed,
  generationId,
  expectedDid,
  pinStore,
  logId
}: {
  store: ClientAnnexWriteStore
  boundLadderSeed: Uint8Array
  actingLadderSeed: Uint8Array
  generationId: string
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ committed: boolean }> {
  assertGenerationId(generationId)
  const published = await readClientAnnexLogOrThrow({
    store,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore !== undefined ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {})
  })

  const bound = await clientAnnexRung({
    ladderSeed: boundLadderSeed,
    generationId
  })
  const boundHash = await deriveNextKeyHash(bound.keyMultibase)
  if (
    published.updateKeys.includes(bound.keyMultibase) ||
    published.nextKeyHashes.includes(boundHash)
  ) {
    // Already committed (or even revealed): a completed earlier run, or a
    // generation the bound credential itself minted.
    return { committed: false }
  }

  const acting = await clientAnnexRung({
    ladderSeed: actingLadderSeed,
    generationId
  })
  const actingHash = await deriveNextKeyHash(acting.keyMultibase)
  const revealed = published.updateKeys.includes(acting.keyMultibase)
  if (!revealed && !published.nextKeyHashes.includes(actingHash)) {
    throw new ClientAnnexRungUncommittedError(
      "client annex: the log commits neither the acting credential's rung-0 " +
        'key nor its hash; a commit entry needs a committed writer -- the ' +
        'bound credential stays locked out until the next GC swap.'
    )
  }
  await assertCarryOverCommitments({ published })

  const signer = await updateKeySigner({ seed: acting.seed })
  const updated = await updateDID({
    log: published.log,
    signer,
    // The acting rung reveals at its first annex write, exactly as the
    // enrollment entry does; the bound rung's hash is added by explicit
    // re-statement (never parameter inheritance). Verification methods,
    // relationship arrays, and the service entries ride the library's
    // prior-state clone untouched.
    updateKeys: [...new Set([...published.updateKeys, acting.keyMultibase])],
    nextKeyHashes: [...published.nextKeyHashes, boundHash]
  })
  await putLogResource({ store, log: updated.log, ifMatch: published.etag })
  return { committed: true }
}
