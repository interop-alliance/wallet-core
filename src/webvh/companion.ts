/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The companion did:webvh: the disposable sidecar log holding transient
 * per-visit verification methods, one generation per flat `gen-` collection
 * inside the account's stable auxiliary companion Space -- so per-visit facts
 * stay out of the account's identity log entirely. This module is the
 * generation's identity, genesis, and enrollment machinery: the
 * `gen-<random>` segment convention, the typed auxiliary Space ensure, the
 * genesis parameters, the pin-slot key for companion continuity, the atomic
 * transient-enrollment entry, and the account document's delegated-clients
 * service entry (the pointer at the current generation).
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
import type { WasClient } from '@interop/was-client'
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
import { companionRung } from '../unlock/ladder.js'
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
} from './didWebvh.js'
import type {
  ClientWebvhUpdateKeys,
  PublishedWebvhLog,
  WebvhIdStore
} from './didWebvh.js'
import { STANDING_ZCAP_TTL_MS, zcapExpiring } from './standingZcap.js'
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
 * The Multikey context, appended to the companion document's `@context` by
 * the entry that first publishes a transient verification method (genesis
 * carries the DID core context only, having no typed members to define).
 */
const MULTIKEY_CONTEXT_URL = 'https://w3id.org/security/multikey/v1'

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

/**
 * The type IRI of the account document's delegated-clients service entry --
 * the pointer at the current companion generation's DID. Wire-level and
 * permanent: readers (this module's {@link delegatedClientsPointer}, the
 * server's companion-chain inspector clause) dispatch on this IRI, never on
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
 * The `serviceEndpoint` is the companion DID STRING, deliberately not a URL:
 * the DID is self-certifying and host-independent, and the account pointer
 * already carries the host.
 *
 * @param options {object}
 * @param options.accountDid {string}   the account did:webvh
 * @param options.companionDid {string}   the current generation's companion
 *   DID
 * @returns {ServiceEndpoint}
 */
export function delegatedClientsServiceEntry({
  accountDid,
  companionDid
}: {
  accountDid: string
  companionDid: string
}): ServiceEndpoint {
  return {
    id: `${accountDid}#${DELEGATED_CLIENTS_SERVICE_FRAGMENT}`,
    type: DELEGATED_CLIENTS_SERVICE_TYPE,
    serviceEndpoint: companionDid
  }
}

/**
 * The companion DID the account document currently points at: the
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
 * The unlock-record sibling delegation's `allowedAction` set: GET beside PUT,
 * so an enrolling transient client can read the companion head it appends to.
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
 * Mints one delegated-clients (companion-Space) delegation: the pre-minted
 * zcap sealed into a standing credential's unlock record beside the account
 * bridge, which is what lets a transient login reach the companion log with
 * nothing but the credential. The shape is a permanent wire artifact
 * (wallet-core decision 0005):
 *
 * - `invocationTarget` is the AUXILIARY companion Space's items subtree --
 *   the Space URL with a trailing slash, built with was-client's paths
 *   helpers so the bytes match the server's target check on a sub-path
 *   deployment. Generation coverage comes from segment-bounded attenuation
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
 * @param options.companionSpaceId {string}   the auxiliary companion
 *   Space's id
 * @param options.controller {string}   the credential-derived signing DID
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {Promise<IZcap>}
 */
export async function mintDelegatedClientsDelegation({
  zcapClient,
  wasServerUrl,
  companionSpaceId,
  controller,
  now = Date.now()
}: {
  zcapClient: ZcapClient
  wasServerUrl: string
  companionSpaceId: string
  controller: string
  now?: number
}): Promise<IZcap> {
  const spaceUrl = toUrl({
    serverUrl: wasServerUrl,
    path: spacePath(companionSpaceId)
  })
  return (await zcapClient.delegate({
    capability: rootCapabilityId(spaceUrl),
    invocationTarget: toUrl({
      serverUrl: wasServerUrl,
      path: spaceItems(companionSpaceId)
    }),
    controller,
    allowedActions: [...DELEGATED_CLIENTS_DELEGATION_ACTIONS],
    expires: new Date(now + DELEGATED_CLIENTS_DELEGATION_TTL_MS)
  })) as IZcap
}

/**
 * The auxiliary companion Space id a delegated-clients delegation targets,
 * read out of its `invocationTarget` (the items-subtree URL,
 * `.../space/<companionSpaceId>/`). The id has no other home -- a transient
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
 * The type IRI of the companion document's generation-delegation service
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
 * - `controller` is the bare companion DID string. Transient keys invoke as
 *   `<companionDid>#<vm>`, and the server's inspector clause compares this
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
 * @param options.companionDid {string}   the generation's companion DID
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {Promise<IZcap>}
 */
export async function mintGenerationDelegation({
  zcapClient,
  wasServerUrl,
  spaceId,
  companionDid,
  now = Date.now()
}: {
  zcapClient: ZcapClient
  wasServerUrl: string
  spaceId: string
  companionDid: string
  now?: number
}): Promise<IZcap> {
  companionDidParts({ did: companionDid })
  const spaceUrl = toUrl({ serverUrl: wasServerUrl, path: spacePath(spaceId) })
  return (await zcapClient.delegate({
    capability: rootCapabilityId(spaceUrl),
    invocationTarget: toUrl({
      serverUrl: wasServerUrl,
      path: spaceItems(spaceId)
    }),
    controller: companionDid,
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
 * Builds a fresh generation-delegation service entry for a companion
 * document. The `serviceEndpoint` is the full delegated-zcap JSON as a
 * single map, byte-identical to what `zcapClient.delegate` produced -- the
 * companion entry proof (JCS canonicalization) then covers it byte for byte,
 * so host tampering with the stored delegation is client-visible.
 *
 * @param options {object}
 * @param options.companionDid {string}   the generation's companion DID
 * @param options.delegation {IZcap}   the minted generation delegation
 * @returns {ServiceEndpoint}
 */
export function generationDelegationServiceEntry({
  companionDid,
  delegation
}: {
  companionDid: string
  delegation: IZcap
}): ServiceEndpoint {
  return {
    id: `${companionDid}#${GENERATION_DELEGATION_SERVICE_FRAGMENT}`,
    type: GENERATION_DELEGATION_SERVICE_TYPE,
    serviceEndpoint: delegation as unknown as ServiceEndpoint['serviceEndpoint']
  }
}

/**
 * The generation delegation a companion document carries: the
 * `serviceEndpoint` map of the service entry whose `type` names (or
 * includes) {@link GENERATION_DELEGATION_SERVICE_TYPE}. Only a map-form
 * endpoint counts (the delegation is embedded as the zcap JSON itself,
 * never as a URL or an encoded string).
 *
 * @param options {object}
 * @param options.doc {DIDDoc}   the resolved (and verified) companion
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
 * The companion document's service list with the generation delegation
 * installed: an existing entry's endpoint is replaced in place, its fragment
 * id preserved verbatim (the id is non-semantic and stable); absent one, a
 * fresh entry is appended. Every other service entry is preserved untouched.
 *
 * @param options {object}
 * @param options.doc {DIDDoc}   the companion document as published
 * @param options.companionDid {string}
 * @param options.delegation {IZcap}
 * @returns {ServiceEndpoint[]}
 */
function withGenerationDelegationEntry({
  doc,
  companionDid,
  delegation
}: {
  doc: DIDDoc
  companionDid: string
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
        generationDelegationServiceEntry({ companionDid, delegation })
      ]
}

/**
 * Parses the auxiliary Space id and generation segment out of a companion DID
 * string. Both are permanent substrings of every companion DID by
 * construction (`did:webvh:<scid>:<host>:...:space:<spaceId>:<segment>`), and
 * the segment is the generation-identifying half of the companion rung HKDF
 * labels, so this parse is what lets an enrollee derive its writing key from
 * the pointer alone -- no log read, no registry.
 *
 * @param options {object}
 * @param options.did {string}   a companion did:webvh string
 * @returns {{ spaceId: string, segment: string }}
 */
export function companionDidParts({ did }: { did: string }): {
  spaceId: string
  segment: string
} {
  const parts = did.split(':')
  const segment = parts[parts.length - 1]
  const spaceId = parts[parts.length - 2]
  if (
    parts.length < 7 ||
    parts[0] !== 'did' ||
    parts[1] !== 'webvh' ||
    parts[parts.length - 3] !== 'space' ||
    segment === undefined ||
    spaceId === undefined ||
    spaceId.length === 0
  ) {
    throw new Error(`Not a companion did:webvh: "${did}".`)
  }
  assertGenerationSegment(segment)
  return { spaceId, segment }
}

/**
 * Thrown when the published companion log commits neither the writing
 * credential's rung-0 key nor its hash -- the mid-generation lockout: a
 * credential bound after the generation's genesis cannot write the companion
 * until an existing writer commits its rung-0 hash or the next GC swap's
 * genesis does. Typed so callers can map it to the fresh-generation path
 * where one is licensed (the transient-recovery continuation) or to honest
 * copy where none is.
 */
export class CompanionRungUncommittedError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CompanionRungUncommittedError'
  }
}

/**
 * The narrow store seam a companion entry is read and published through: the
 * log read and the conditional `did.jsonl` PUT, nothing else (a companion has
 * no `did.json` projection and no key map). Satisfied by
 * {@link companionLogStore} (controller-tier signing) and by the delegated
 * store a transient session writes through (`delegatedWebvhLogStore`,
 * invoking the credential's sibling delegation).
 */
export type CompanionWriteStore = Pick<
  WebvhIdStore,
  'getIdResourceRaw' | 'putIdResource'
>

/**
 * Reads and resolves the published companion log through the narrow seam, or
 * throws when the generation's `did.jsonl` is missing (an unpointed or
 * deleted generation -- nothing to enroll into).
 *
 * @param options {object}
 * @param options.store {CompanionWriteStore}
 * @param [options.expectedDid] {string}
 * @param [options.pinStore] {ResourceLogPinStore}
 * @param [options.logId] {string}
 * @returns {Promise<PublishedWebvhLog>}
 */
async function readCompanionLogOrThrow({
  store,
  expectedDid,
  pinStore,
  logId
}: {
  store: CompanionWriteStore
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
      'companion: did.jsonl is missing; the generation was never minted or ' +
        'has been collected.'
    )
  }
  return published
}

/**
 * TRANSIENT ENROLLMENT: publishes one per-visit verification method into a
 * companion generation's log -- one atomic entry, signed by the writing
 * credential's static rung 0 (derived from the ladder seed and the segment;
 * see `companionRung`). The entry:
 *
 * - reveals the writer's rung-0 key into `updateKeys` at its first companion
 *   write (later writes re-state it unchanged);
 * - re-states `nextKeyHashes` verbatim -- every standing credential's rung-0
 *   hash, the writer's own carry-over hash included -- explicitly on the
 *   entry, never inherited from the prior entry's parameters;
 * - adds the transient VM under `capabilityInvocation` ONLY, with all five
 *   relationship arrays stated explicitly (no `authentication`, no
 *   `assertionMethod`, no `keyAgreement` twin -- the DIDAuth path signs as
 *   the bare did:key, and the controller-marker convention does not arise in
 *   the companion at all).
 *
 * The transient key set carries no update key, and nothing here touches the
 * ACCOUNT log's `updateKeys` or `nextKeyHashes`. There is no two-entry
 * reveal/add split and no attribution scan: a CAS loser re-signs with the
 * SAME key via the ordinary conflict retry, and resumability reduces to the
 * published document's own state -- a VM already present is a no-op.
 *
 * A writer whose rung-0 key is neither revealed nor committed is refused
 * ({@link CompanionRungUncommittedError}): companion entries verify against
 * the log's own hash-commitment chain, so no admission rule can make an
 * uncommitted key verify mid-log.
 *
 * @param options {object}
 * @param options.store {CompanionWriteStore}   the generation's log store
 *   (delegated through the credential's sibling delegation, or
 *   controller-tier)
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed, from
 *   its unlock record
 * @param options.segment {string}   the generation collection's name
 * @param options.transientKeyMultibase {string}   the visit's in-memory
 *   Ed25519 signing key, public multibase
 * @param [options.services] {ServiceEndpoint[]}   the companion document's
 *   full service-entry list, replacing the published one wholesale; omitted,
 *   the prior entries are preserved verbatim (or extended by
 *   `mintGenerationDelegation` below). Supplying both is refused in favor of
 *   the explicit list
 * @param [options.mintGenerationDelegation] {Function}
 *   `({ companionDid }) => Promise<IZcap>` -- mints the generation
 *   delegation this entry installs when it publishes the generation's FIRST
 *   transient verification method (and the document carries no delegation
 *   entry yet). Never invoked otherwise: the delegation is installed with
 *   the first transient VM or by the GC ceremony's own install stage, never
 *   by genesis (a genesis-embedded signed zcap can never verify -- its
 *   `controller` embeds the SCID the genesis hash derives from)
 * @param [options.expectedDid] {string}   the companion DID the log must
 *   resolve to, from the account document's pointer
 * @param [options.pinStore] {ResourceLogPinStore}   chain-head pins (a
 *   transient session passes an in-memory store)
 * @param [options.logId] {string}   the generation's pin-slot key, from
 *   {@link companionLogPinId}; required whenever a `pinStore` is supplied
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}
 */
export async function enrollCompanionTransientClient(options: {
  store: CompanionWriteStore
  ladderSeed: Uint8Array
  segment: string
  transientKeyMultibase: string
  services?: ServiceEndpoint[]
  mintGenerationDelegation?: (options: {
    companionDid: string
  }) => Promise<IZcap>
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  return withLogConflictRetry(() => enrollCompanionTransientClientOnce(options))
}

/**
 * One attempt of {@link enrollCompanionTransientClient}, re-invoked by the
 * conflict retry (with the same signing key -- static rung 0 has no
 * advanced-rung retry shape).
 *
 * @param options {object}   see {@link enrollCompanionTransientClient}
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}
 */
async function enrollCompanionTransientClientOnce({
  store,
  ladderSeed,
  segment,
  transientKeyMultibase,
  services,
  mintGenerationDelegation: mintDelegation,
  expectedDid,
  pinStore,
  logId
}: {
  store: CompanionWriteStore
  ladderSeed: Uint8Array
  segment: string
  transientKeyMultibase: string
  services?: ServiceEndpoint[]
  mintGenerationDelegation?: (options: {
    companionDid: string
  }) => Promise<IZcap>
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  assertGenerationSegment(segment)
  const published = await readCompanionLogOrThrow({
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

  const rung = await companionRung({ ladderSeed, segment })
  const rungHash = await deriveNextKeyHash(rung.keyMultibase)
  const revealed = published.updateKeys.includes(rung.keyMultibase)
  if (!revealed && !published.nextKeyHashes.includes(rungHash)) {
    throw new CompanionRungUncommittedError(
      "companion: the log commits neither this credential's rung-0 key nor " +
        'its hash; a credential bound mid-generation cannot write the ' +
        'companion until a writer commits its hash or the next GC swap does.'
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
    const delegation = await mintDelegation({ companionDid: did })
    services = withGenerationDelegationEntry({
      doc,
      companionDid: did,
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
  // The log only -- a companion has no did:web projection -- conditional on
  // the read this entry was built on.
  await putLogResource({ store, log: updated.log, ifMatch: published.etag })
  return { did: updated.did, doc: updated.doc, log: updated.log }
}

/**
 * Points the account document's delegated-clients service entry at a
 * companion DID -- the first install after a generation's genesis, and the GC
 * swap's re-point alike. One ordinary document-update entry, signed by an
 * enrolled durable client's active update key; the companion log always
 * publishes FIRST (see {@link mintCompanionGeneration}), so a tear leaves an
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
 * @param options.idStore {WebvhIdStore}   the ACCOUNT log's store
 * @param options.updateKeys {ClientWebvhUpdateKeys}   this durable client's
 *   update-key seeds
 * @param options.companionDid {string}   the generation to point at
 * @param [options.expectedDid] {string}   the account DID the log must
 *   resolve to, from the account pointer
 * @param [options.pinStore] {ResourceLogPinStore}   this client's chain-head
 *   pins for the account log
 * @param [options.logId] {string}   the account log's pin-slot key, from
 *   `accountLogPinId({ spaceId })`; required whenever a `pinStore` is
 *   supplied
 * @returns {Promise<{ did: string, doc: DIDDoc }>}
 */
export async function setDelegatedClientsPointer(options: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  companionDid: string
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
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
  companionDid,
  expectedDid,
  pinStore,
  logId
}: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  companionDid: string
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; doc: DIDDoc }> {
  // Refuses a malformed target before anything is read or written.
  companionDidParts({ did: companionDid })
  const published = await readPublishedLog({
    idStore,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore !== undefined ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {})
  })
  if (!published) {
    throw new Error(
      'did:webvh: did.jsonl is missing; nothing to point at a companion.'
    )
  }
  const { did, doc } = published
  if (delegatedClientsPointer({ doc }) === companionDid) {
    await concludeWithPublishedLog({ idStore, published })
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

  const existing = (doc.service ?? []) as ServiceEndpoint[]
  const isPointerEntry = (entry: ServiceEndpoint) => {
    const types = Array.isArray(entry.type) ? entry.type : [entry.type]
    return types.includes(DELEGATED_CLIENTS_SERVICE_TYPE)
  }
  const services = existing.some(isPointerEntry)
    ? existing.map(entry =>
        isPointerEntry(entry)
          ? { ...entry, serviceEndpoint: companionDid }
          : entry
      )
    : [
        ...existing,
        delegatedClientsServiceEntry({ accountDid: did, companionDid })
      ]

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
  await publishUpdatedLog({ idStore, updated, ifMatch: published.etag })
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
 * @param options.storeForSegment {Function}   builds the generation's log
 *   store for a segment (the delegated store over the credential's sibling
 *   delegation, or a controller-tier store)
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed
 * @param options.transientKeyMultibase {string}   the visit's in-memory
 *   signing key, public multibase
 * @param [options.mintGenerationDelegation] {Function}
 *   `({ companionDid }) => Promise<IZcap>` -- forwarded to the enrollment
 *   entry, which installs the minted delegation when it publishes the
 *   generation's first transient VM (see
 *   {@link enrollCompanionTransientClient}). The closure receives whichever
 *   companion DID the round enrolls into, so a GC-race re-enroll mints for
 *   the fresh generation
 * @param [options.pinStore] {ResourceLogPinStore}   chain-head pins for the
 *   generation logs (a transient session passes an in-memory store); slot
 *   keys are derived per generation with {@link companionLogPinId}
 * @param [options.maxRounds] {number}   how many pointer moves to chase
 *   before giving up (a GC pass is quarterly, so more than one mid-ceremony
 *   move means something else is wrong)
 * @returns {Promise<{ companionDid: string, doc: DIDDoc, log: DIDLog }>}
 */
export async function enrollTransientClient({
  readAccountDocument,
  storeForSegment,
  ladderSeed,
  transientKeyMultibase,
  mintGenerationDelegation: mintDelegation,
  pinStore,
  maxRounds = 3
}: {
  readAccountDocument: () => Promise<DIDDoc>
  storeForSegment: (segment: string) => CompanionWriteStore
  ladderSeed: Uint8Array
  transientKeyMultibase: string
  mintGenerationDelegation?: (options: {
    companionDid: string
  }) => Promise<IZcap>
  pinStore?: ResourceLogPinStore
  maxRounds?: number
}): Promise<{ companionDid: string; doc: DIDDoc; log: DIDLog }> {
  let accountDoc = await readAccountDocument()
  for (let round = 0; round < maxRounds; round++) {
    const companionDid = delegatedClientsPointer({ doc: accountDoc })
    if (companionDid === undefined) {
      throw new Error(
        'companion: the account document carries no delegated-clients ' +
          'service entry; no generation exists to enroll into.'
      )
    }
    const { spaceId, segment } = companionDidParts({ did: companionDid })
    const enrolled = await enrollCompanionTransientClient({
      store: storeForSegment(segment),
      ladderSeed,
      segment,
      transientKeyMultibase,
      expectedDid: companionDid,
      ...(mintDelegation !== undefined
        ? { mintGenerationDelegation: mintDelegation }
        : {}),
      ...(pinStore !== undefined
        ? { pinStore, logId: companionLogPinId({ spaceId, segment }) }
        : {})
    })
    // The GC-race re-read: an unchanged pointer means the enrollment stands
    // in the pointed generation; a moved one means a concurrent GC abandoned
    // it, and the next round enrolls into the fresh generation.
    accountDoc = await readAccountDocument()
    if (delegatedClientsPointer({ doc: accountDoc }) === companionDid) {
      return { companionDid, doc: enrolled.doc, log: enrolled.log }
    }
  }
  throw new Error(
    'companion: the delegated-clients pointer kept moving across ' +
      `${String(maxRounds)} enrollment rounds; giving up.`
  )
}

/**
 * RENEW PRECEDES MINT: the blocking pre-mint stage a transient App Connect
 * approval runs before delegating any grant. Reads the companion document
 * and hands back its embedded generation delegation -- renewing it first
 * when it is expired or inside the 30-day renewal window ({@link
 * zcapExpiring}): a fresh delegation is minted through the caller's closure
 * (ladder-signed -- the renewal must not depend on the very delegation it
 * replaces; published through the store, which in a transient session is
 * the credential's sibling delegation, so even a hard-expired delegation is
 * recoverable), and one companion entry replaces the service entry's
 * endpoint in place, signed by the writing credential's static rung 0.
 *
 * A companion document carrying no delegation entry at all installs one the
 * same way (the GC ceremony's own install stage and the first-VM install
 * make this rare; a heal, not a policy).
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
 * @param options.store {CompanionWriteStore}   the generation's log store
 *   (delegated through the credential's sibling delegation, or
 *   controller-tier)
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed, from
 *   its unlock record
 * @param options.segment {string}   the generation collection's name
 * @param options.mintGenerationDelegation {Function}
 *   `({ companionDid }) => Promise<IZcap>` -- mints the replacement
 *   delegation (ladder-signed in a transient session)
 * @param [options.expectedDid] {string}   the companion DID the log must
 *   resolve to, from the account document's pointer
 * @param [options.pinStore] {ResourceLogPinStore}   chain-head pins (a
 *   transient session passes an in-memory store)
 * @param [options.logId] {string}   the generation's pin-slot key, from
 *   {@link companionLogPinId}; required whenever a `pinStore` is supplied
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {Promise<{ delegation: IZcap, renewed: boolean }>}
 */
export async function ensureGenerationDelegationCurrent(options: {
  store: CompanionWriteStore
  ladderSeed: Uint8Array
  segment: string
  mintGenerationDelegation: (options: {
    companionDid: string
  }) => Promise<IZcap>
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
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
  segment,
  mintGenerationDelegation: mintDelegation,
  expectedDid,
  pinStore,
  logId,
  now
}: {
  store: CompanionWriteStore
  ladderSeed: Uint8Array
  segment: string
  mintGenerationDelegation: (options: {
    companionDid: string
  }) => Promise<IZcap>
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
  now?: number
}): Promise<{ delegation: IZcap; renewed: boolean }> {
  assertGenerationSegment(segment)
  const published = await readCompanionLogOrThrow({
    store,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore !== undefined ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {})
  })
  const { did, doc } = published
  const standing = embeddedGenerationDelegation({ doc })
  if (
    standing !== undefined &&
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
  const rung = await companionRung({ ladderSeed, segment })
  const rungHash = await deriveNextKeyHash(rung.keyMultibase)
  const revealed = published.updateKeys.includes(rung.keyMultibase)
  if (!revealed && !published.nextKeyHashes.includes(rungHash)) {
    throw new CompanionRungUncommittedError(
      "companion: the log commits neither this credential's rung-0 key nor " +
        'its hash; a credential bound mid-generation cannot renew the ' +
        'generation delegation until a writer commits its hash or the next ' +
        'GC swap does.'
    )
  }
  await assertCarryOverCommitments({ published })
  const fresh = await mintDelegation({ companionDid: did })

  const signer = await updateKeySigner({ seed: rung.seed })
  const updated = await updateDID({
    log: published.log,
    signer,
    // The writer's rung-0 key reveals at its first companion write, exactly
    // as the enrollment entry does; `nextKeyHashes` is re-stated verbatim,
    // never inherited. Verification methods, relationship arrays, and every
    // other service entry ride the library's prior-state clone untouched.
    updateKeys: [...new Set([...published.updateKeys, rung.keyMultibase])],
    nextKeyHashes: [...published.nextKeyHashes],
    services: withGenerationDelegationEntry({
      doc,
      companionDid: did,
      delegation: fresh
    })
  })
  await putLogResource({ store, log: updated.log, ifMatch: published.etag })
  return { delegation: fresh, renewed: true }
}
