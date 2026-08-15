/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * did:webvh hosting: provisions and publishes a hash-chained, self-certifying
 * did:webvh DID log alongside the did:web document, in the same `id`
 * collection of the user's WAS Space, with the log's update keys held by the
 * wallet client itself (never by the KMS).
 *
 * The log (`did.jsonl`) is one more WAS Resource in the world-readable `id`
 * collection (which carries a collection-level `PublicCanRead` policy), so
 * hosting needs zero server changes:
 * `did:webvh:<scid>:<host>:space:<spaceId>:id` resolves to
 * `https://<host>/space/<spaceId>/id/did.jsonl`. Adopting the parallel
 * `webDoc` (`did:web:` projection with `alsoKnownAs` cross-links) as the new
 * `did.json` makes the log the single source of truth.
 *
 * The document is the enrolled-client roster: each enrolled client contributes
 * its Ed25519 signing key (published under `authentication`, `assertionMethod`,
 * `capabilityInvocation` and `capabilityDelegation`) and its X25519
 * key-agreement key (under `keyAgreement`, the source of record for
 * user-key-wrap recipient keys). The genesis comes in two flavors: a wallet
 * that keeps a KMS supplies its `didWebKeys` map and the document gains one
 * server-held key, the KMS `authentication` key (a convenience for DIDAuth);
 * a wallet with no KMS supplies no map and the document holds client keys
 * only (a later log entry can still add the KMS authentication key when the
 * first KMS-capable client appears). In either flavor every other relation
 * lists client keys only. In particular no server-held key may appear under
 * `keyAgreement` (no server key is a wrap target) or under `assertionMethod`
 * (membership there is what entitles a key to issue assertions as the account
 * and, under the App Connect Resource Log Profile, to append to the account's
 * co-managed resource logs).
 *
 * All protocol logic lives in `@interop/did-method-webvh`; this module is the
 * glue: a `Signer` bridge over a client-held update-key seed, the idempotent,
 * crash-resumable provisioning flow (`ensureDidWebvh`), the per-client
 * update-key rotation ceremony (`rotateWebvhUpdateKey`), the two-entry client
 * enrollment ceremony (`enrollWebvhClient`), and the lost-`keys.json` recovery
 * path for the did:web relationship bindings (`repairKeyBindings`). Update-key
 * seeds are minted here but persisted by the caller -- with client-held keys a
 * lost seed is lost update authority, so every publish is preceded by a
 * caller-durable write.
 *
 * Every ceremony publishes `did.jsonl` CONDITIONALLY: the read that produced
 * the state an entry was built on carries the log's ETag, and the publish
 * passes it back as the write's precondition (a create passes
 * create-if-absent), so two clients extending the log concurrently can never
 * silently erase each other -- the loser gets a {@link WebvhLogConflictError}
 * and re-runs from the top, rebasing its entry on the winner's head
 * ({@link withLogConflictRetry}). Against a backend that serves no ETags the
 * precondition is absent and the publish degrades to an unconditional write.
 *
 * The Space-side I/O runs through the narrow {@link WebvhIdStore} seam, which
 * each wallet app satisfies with its own remote-store class.
 *
 * Prerotation convention: `nextKeyHashes` commits the hash of every client's
 * ACTIVE update key alongside every staged key (the carry-over commitments).
 * The resolver re-checks each entry's full (re-stated) `updateKeys` against
 * the previous entry's `nextKeyHashes`, so without the active-key hashes no
 * entry could ever keep a key authorized -- a multi-client log (an enrollment
 * commit, a rotation that preserves the other clients' keys) depends on them.
 * The trade is deliberate: an active update key can author non-rotating
 * entries, where the original single-key convention forced every entry to
 * reveal the staged key.
 */
import {
  createDID,
  deriveNextKeyHash,
  generateParallelDidWeb,
  logToJsonlString,
  readLogFromString,
  resolveDIDFromLog,
  SCID_PLACEHOLDER,
  signerFromExternalKey,
  updateDID
} from '@interop/did-method-webvh'
import type {
  DIDDoc,
  DIDLog,
  Signer,
  VerificationMethod
} from '@interop/did-method-webvh'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { x25519RecipientFromDidKey } from '@interop/was-client/edv'
import type { KeystoreAgent } from '@interop/webkms-client'
import {
  DID_DOCUMENT_RESOURCE,
  DID_LOG_RESOURCE,
  ID_COLLECTION
} from '../space/collections.js'
import { ResourceLogContinuityError } from '../resourceLog/errors.js'
import type {
  ResourceLogHeadPin,
  ResourceLogPinStore
} from '../resourceLog/pin.js'
import { multibaseOf } from './didWeb.js'
import type { DidWebKey, DidWebKeyMap } from './didWeb.js'
import { accountLogPinId, checkAccountLogContinuity } from './verifyLog.js'

/**
 * The Space-side seam this module reads and writes through: the world-readable
 * `id` collection (the DID log and document) and the private `key-map`
 * collection's `keys.json`. A wallet app's own remote-store class satisfies
 * the shape structurally -- no adapter needed.
 */
export interface WebvhIdStore {
  /**
   * The raw text body of an `id` collection resource (the JSON-Lines log)
   * together with its ETag validator, or `undefined` when it is not published.
   * The `etag` is the compare-and-swap token a ceremony hands back as
   * {@link putIdResource}'s `ifMatch`; it is absent against a backend that does
   * not version resources, in which case the ceremony's publish degrades to an
   * unconditional write.
   */
  getIdResourceRaw(options: {
    resourceId: string
  }): Promise<{ text: string; etag?: string } | undefined>
  /**
   * The parsed JSON body of an `id` collection resource (the DID document), or
   * `undefined` when it is not published.
   */
  getIdResource(options: { resourceId: string }): Promise<unknown>
  /**
   * Writes (upserts) an `id` collection resource, optionally conditionally:
   * `ifMatch` writes only if the resource's current ETag matches (an
   * update-if-unchanged), `ifNoneMatch` writes only if the resource is absent
   * (a create-if-absent). With neither the write is unconditional.
   *
   * Contract: a failed precondition MUST surface as an error whose `name` is
   * `'PreconditionFailedError'` (was-client's class; any implementation may
   * throw its own error carrying that name), which this module maps to
   * {@link WebvhLogConflictError}.
   */
  putIdResource(options: {
    resourceId: string
    content: object | string
    contentType?: string
    ifMatch?: string
    ifNoneMatch?: boolean
  }): Promise<void>
  /**
   * Writes (upserts) `keys.json` in the private `key-map` collection.
   */
  putKeyMap(options: { content: object }): Promise<void>
}

/**
 * The Multikey verification-method type the did:webvh data model uses for both
 * the Ed25519 (authentication/assertionMethod/capability*) and X25519
 * (keyAgreement) keys. The same key material and multibase are carried as by
 * the 2020 suite types, only `type` and `@context` change, and credential
 * verifiers verify `Ed25519Signature2020` / `eddsa-rdfc-2022` proofs against
 * it.
 */
export const MULTIKEY_VM_TYPE = 'Multikey'

/**
 * The byte length of a did:webvh update-key seed (an Ed25519 secret seed).
 */
const UPDATE_SEED_BYTES = 32

/**
 * The client-held did:webvh update-key material: 32-byte Ed25519 seeds.
 * `pendingStagedSeed` is present only mid-rotation (minted and persisted
 * before the log entry publishes, promoted to `stagedSeed` after).
 */
export interface ClientWebvhUpdateKeys {
  updateSeed: Uint8Array
  stagedSeed: Uint8Array
  pendingStagedSeed?: Uint8Array
}

/**
 * The public halves of one enrolled client's key set, as they appear in the
 * document: the Ed25519 signing key (`z6Mk...`) and its X25519 key-agreement
 * twin (`z6LS...`).
 */
export interface WebvhClientKeys {
  signingKeyMultibase: string
  keyAgreementKeyMultibase: string
}

/**
 * The CONTROLLER MARKER an enrolled client's `keyAgreement` verification
 * method carries: the client's own did:key, rather than the account DID every
 * other method carries. It is the document's one statement of which signing
 * key a published key-agreement key belongs to, so a reader pairs a client
 * with its key-agreement key by reading the document instead of deriving a
 * twin -- and it agrees with the DID half of the client's roster kid.
 *
 * Only a CLIENT's key-agreement method is marked. Signing keys are never
 * marked (a did:key controller on a proof key breaks controller-based proof
 * verification), and a recovery code's key-agreement method is deliberately
 * left unmarked, so client listings and revocation removals never match it.
 *
 * @param options {object}
 * @param options.signingKeyMultibase {string}   the client's Ed25519 signing
 *   key, as the document publishes it
 * @returns {string}
 */
export function clientKeyAgreementController({
  signingKeyMultibase
}: {
  signingKeyMultibase: string
}): string {
  return `did:key:${signingKeyMultibase}`
}

/**
 * The multibase of an Ed25519 signing key's canonical X25519 twin. Delegates
 * to was-client's `x25519RecipientFromDidKey`, the one rule for this
 * derivation, which also refuses a multibase that is not an Ed25519 key (no
 * twin exists for anything else).
 *
 * Nothing DERIVES a client's published key-agreement key with it -- the
 * listing reads that off the document's controller marker. It is the
 * canonicality rule instead: {@link markedVerificationMethodPair} runs it at
 * every site that writes the marker, and the enrollment ceremony runs it
 * early enough to refuse a connect code before an approver ever sees it, so
 * the marker's claim ("this key-agreement key belongs to that signing key")
 * is true of every method a wallet publishes.
 *
 * @param options {object}
 * @param options.signingKeyMultibase {string}
 * @returns {string}
 */
export function keyAgreementTwinMultibase({
  signingKeyMultibase
}: {
  signingKeyMultibase: string
}): string {
  return x25519RecipientFromDidKey({ did: `did:key:${signingKeyMultibase}` })
    .publicKeyMultibase
}

/**
 * The one builder of a client's published verification-method pair: the
 * account-controlled Ed25519 signing method first, then the X25519
 * key-agreement method under the controller marker
 * ({@link clientKeyAgreementController}). Every site that writes the marker
 * -- the genesis assembly, the enrollment add entry, and the recovery
 * continuation's add-and-retire entry -- builds through it, so the permanent
 * document convention is applied in one place rather than remembered at each
 * site.
 *
 * It refuses a pair whose key-agreement key is not the canonical X25519 twin
 * of the signing key, which is what makes the marker's claim true wherever it
 * is written: no public entry point can publish a marker the account cannot
 * back.
 *
 * @param options {object}
 * @param options.controller {string}   the account's controller id, used both
 *   as the methods' id prefix and as the signing method's controller (the
 *   `{SCID}` template at genesis, the resolved DID afterwards)
 * @param options.signingKeyMultibase {string}
 * @param options.keyAgreementKeyMultibase {string}
 * @returns {VerificationMethod[]}   the signing method, then the marked
 *   key-agreement method
 */
export function markedVerificationMethodPair({
  controller,
  signingKeyMultibase,
  keyAgreementKeyMultibase
}: {
  controller: string
  signingKeyMultibase: string
  keyAgreementKeyMultibase: string
}): VerificationMethod[] {
  if (
    keyAgreementKeyMultibase !==
    keyAgreementTwinMultibase({ signingKeyMultibase })
  ) {
    throw new Error(
      "The client's key-agreement key is not the canonical X25519 twin of " +
        'its signing key; it cannot be published under the controller ' +
        'marker, which would state a pairing this account cannot back.'
    )
  }
  return [
    {
      id: `${controller}#${signingKeyMultibase}`,
      type: MULTIKEY_VM_TYPE,
      controller,
      publicKeyMultibase: signingKeyMultibase
    },
    {
      id: `${controller}#${keyAgreementKeyMultibase}`,
      type: MULTIKEY_VM_TYPE,
      controller: clientKeyAgreementController({ signingKeyMultibase }),
      publicKeyMultibase: keyAgreementKeyMultibase
    }
  ]
}

/**
 * The `webvh` block added to `keys.json` v2, a sibling of the did:web
 * relationship map. Absent block = a record written before did:webvh hosting;
 * everything degrades to did:web behavior, no format-version bump (additive
 * convention). It carries only the published DID: the update keys are
 * client-held seeds, never recorded in a Space-hosted resource.
 */
export interface DidWebvhBlock {
  did?: string
}

/**
 * `keys.json` v2: the did:web key map plus the optional `webvh` block. The
 * did:web parse/guard tolerates and preserves the block, so a round-trip
 * through the did:web provisioning never strips it.
 */
export type DidWebKeyMapV2 = DidWebKeyMap & { webvh?: DidWebvhBlock }

/**
 * The `did:webvh:{SCID}:<host>:space:<spaceId>:id` controller template, with
 * the literal `{SCID}` placeholder the library replaces at creation. The host
 * segment percent-encodes a port (`localhost:8080` becomes `localhost%3A8080`),
 * matching the library's `toDidDomainComponent`.
 *
 * @param options {object}
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}
 * @returns {string}
 */
export function didWebvhControllerTemplate({
  wasServerUrl,
  spaceId
}: {
  wasServerUrl: string
  spaceId: string
}): string {
  const { host } = new URL(wasServerUrl)
  return `did:webvh:${SCID_PLACEHOLDER}:${encodeURIComponent(host)}:space:${spaceId}:id`
}

/**
 * Mints a fresh pair of client-held update-key seeds (active + staged) for a
 * brand-new did:webvh log. The caller owns persistence: these seeds are the
 * only update authority the log will ever accept, so they must be durable
 * before {@link ensureDidWebvh} publishes anything.
 *
 * @returns {Promise<ClientWebvhUpdateKeys>}
 */
export async function mintClientWebvhUpdateKeys(): Promise<ClientWebvhUpdateKeys> {
  return {
    updateSeed: randomSeed(),
    stagedSeed: randomSeed()
  }
}

/**
 * A fresh 32-byte Ed25519 update-key seed.
 *
 * @returns {Uint8Array}
 */
function randomSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(UPDATE_SEED_BYTES))
}

/**
 * The `publicKeyMultibase` of the Ed25519 update key a seed derives, as it
 * appears in the log's `parameters.updateKeys`.
 *
 * @param options {object}
 * @param options.seed {Uint8Array}   a 32-byte Ed25519 seed
 * @returns {Promise<string>}
 */
export async function updateKeyMultibase({
  seed
}: {
  seed: Uint8Array
}): Promise<string> {
  const keyPair = await Ed25519VerificationKey.generate({ seed })
  return keyPair.publicKeyMultibase
}

/**
 * Bridges a client-held update-key seed to the did:webvh `Signer` interface via
 * the library's `signerFromExternalKey`. The only wallet-side seam is the shape
 * adapter: the key pair's `signer().sign({ data })` matches the factory's
 * `sign({ data })` bridge exactly, so the proof-value multibase encoding and
 * the load-bearing `did:key:<pkm>#<pkm>` verification-method id (which the
 * resolver matches against the entry's authorized `updateKeys`) are owned by
 * the library, not duplicated here.
 *
 * @param options {object}
 * @param options.seed {Uint8Array}   the 32-byte update-key seed
 * @returns {Promise<Signer>}
 */
export async function updateKeySigner({
  seed
}: {
  seed: Uint8Array
}): Promise<Signer> {
  const keyPair = await Ed25519VerificationKey.generate({ seed })
  const { publicKeyMultibase } = keyPair
  // The key pair refuses to hand out a signer without an id; the did:key form
  // is also the verification-method id the resolver matches against the log's
  // authorized updateKeys.
  keyPair.id = `did:key:${publicKeyMultibase}#${publicKeyMultibase}`
  const keySigner = keyPair.signer()
  return signerFromExternalKey({
    publicKeyMultibase,
    sign: async ({ data }: { data: Uint8Array }) => {
      const signature = await keySigner.sign({ data })
      // Re-wrap as a plain Uint8Array: a signer may return a Node Buffer (or
      // a cross-realm view), which the library's strict byte check rejects.
      return new Uint8Array(
        signature.buffer,
        signature.byteOffset,
        signature.byteLength
      )
    }
  })
}

/**
 * Assembles the document's verification methods as `{SCID}`-templated Multikey
 * entries for the create entry: the enrolled client's own key set -- its
 * Ed25519 signing key under all four Ed25519 relationships and its X25519
 * key-agreement key as the sole `keyAgreement` entry -- plus, when the wallet
 * keeps a KMS (`didWebKeys` supplied), the KMS-held authentication key (a
 * server-side convenience). With no key map the document holds client keys
 * only. Every relation except `authentication` lists client keys only in
 * either flavor: no server-held key is a wrap target (so the KMS keyAgreement
 * key is deliberately absent), and `assertionMethod` membership confers
 * assertion and resource-log-append authority (so the KMS assertion key is
 * deliberately absent too).
 *
 * Each id carries the full `publicKeyMultibase` fragment, so `createDID` mints
 * `did:webvh:<scid>:...#<multibase>` ids -- no KMS read. The client's
 * `keyAgreement` method is the one entry published under the controller
 * marker ({@link clientKeyAgreementController}); every other method, the KMS
 * authentication key included, carries the account's own controller.
 *
 * @param options {object}
 * @param options.controllerTemplate {string}   the `{SCID}` controller id
 * @param [options.didWebKeys] {DidWebKeyMap}   absent on a client-keys-only
 *   genesis
 * @param options.clientKeys {WebvhClientKeys}
 * @returns {object}   `verificationMethods` + relationship arrays for createDID
 */
function assembleWebvhVerificationMethods({
  controllerTemplate,
  didWebKeys,
  clientKeys
}: {
  controllerTemplate: string
  didWebKeys?: DidWebKeyMap
  clientKeys: WebvhClientKeys
}): {
  verificationMethods: VerificationMethod[]
  authentication: string[]
  assertionMethod: string[]
  keyAgreement: string[]
  capabilityInvocation: string[]
  capabilityDelegation: string[]
} {
  const { signingKeyMultibase, keyAgreementKeyMultibase } = clientKeys
  const vmId = (publicKeyMultibase: string) =>
    `${controllerTemplate}#${publicKeyMultibase}`
  const method = (publicKeyMultibase: string): VerificationMethod => ({
    id: vmId(publicKeyMultibase),
    type: MULTIKEY_VM_TYPE,
    controller: controllerTemplate,
    publicKeyMultibase
  })
  // The founding client's key-agreement method alone carries the controller
  // marker, and the pair builder is what enforces that the marked key really
  // is the signing key's twin.
  const clientMethods = markedVerificationMethodPair({
    controller: controllerTemplate,
    signingKeyMultibase,
    keyAgreementKeyMultibase
  })
  const kmsAuthentication = didWebKeys
    ? multibaseOf(didWebKeys.authentication.vmId)
    : undefined

  return {
    verificationMethods: [
      ...(kmsAuthentication !== undefined ? [method(kmsAuthentication)] : []),
      ...clientMethods
    ],
    authentication: [
      ...(kmsAuthentication !== undefined ? [vmId(kmsAuthentication)] : []),
      vmId(signingKeyMultibase)
    ],
    assertionMethod: [vmId(signingKeyMultibase)],
    keyAgreement: [vmId(keyAgreementKeyMultibase)],
    capabilityInvocation: [vmId(signingKeyMultibase)],
    capabilityDelegation: [vmId(signingKeyMultibase)]
  }
}

/**
 * Creates the one-entry did:webvh log and its parallel `webDoc`. `portable:
 * true` is set at entry 1 (it can only be enabled there); the document's
 * verification methods come from {@link assembleWebvhVerificationMethods},
 * signed by the client-held active update key with prerotation committed to
 * the staged key.
 *
 * @param options {object}
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}
 * @param [options.didWebKeys] {DidWebKeyMap}   absent on a client-keys-only
 *   genesis
 * @param options.clientKeys {WebvhClientKeys}
 * @param options.updateKeyPublicKeyMultibase {string}
 * @param options.nextKeyHashes {string[]}
 * @param options.signer {Signer}
 * @returns {Promise<{ log: DIDLog; webDoc: object; did: string }>}
 */
async function createWebvhLog({
  wasServerUrl,
  spaceId,
  didWebKeys,
  clientKeys,
  updateKeyPublicKeyMultibase,
  nextKeyHashes,
  signer
}: {
  wasServerUrl: string
  spaceId: string
  didWebKeys?: DidWebKeyMap
  clientKeys: WebvhClientKeys
  updateKeyPublicKeyMultibase: string
  nextKeyHashes: string[]
  signer: Signer
}): Promise<{ log: DIDLog; webDoc: object; did: string }> {
  const { host } = new URL(wasServerUrl)
  const controllerTemplate = didWebvhControllerTemplate({
    wasServerUrl,
    spaceId
  })
  const {
    verificationMethods,
    authentication,
    assertionMethod,
    keyAgreement,
    capabilityInvocation,
    capabilityDelegation
  } = assembleWebvhVerificationMethods({
    controllerTemplate,
    didWebKeys,
    clientKeys
  })

  const result = await createDID({
    address: host,
    paths: ['space', spaceId, ID_COLLECTION.id],
    signer,
    updateKeys: [updateKeyPublicKeyMultibase],
    nextKeyHashes,
    verificationMethods,
    authentication,
    assertionMethod,
    keyAgreement,
    capabilityInvocation,
    capabilityDelegation,
    alsoKnownAsWeb: true,
    portable: true
  })
  if (!result.webDoc) {
    throw new Error('createDID did not return a webDoc despite alsoKnownAsWeb.')
  }
  return { log: result.log, webDoc: result.webDoc, did: result.did }
}

/**
 * Thrown when a conditional publish of `did.jsonl` lost a race to a concurrent
 * ceremony: the log moved on between the read this ceremony built its entry on
 * and the PUT that would have appended it. The `cause` is the store's
 * precondition error. A ceremony that meets one either re-runs (rebasing its
 * entry on the new head -- what {@link withLogConflictRetry} does) or refuses,
 * but it never overwrites the winner's entry.
 */
export class WebvhLogConflictError extends Error {
  constructor(
    message = 'did:webvh: the published did.jsonl changed under this ceremony ' +
      '(a concurrent ceremony extended the log); the entry was not appended.',
    options?: { cause?: unknown }
  ) {
    super(message, options)
    this.name = 'WebvhLogConflictError'
  }
}

/**
 * Re-runs `run` when it fails with a {@link WebvhLogConflictError}, up to three
 * total attempts, then rethrows. The retry IS the rebase: every ceremony in
 * this module re-reads the published head and rebuilds its entry on it, and
 * every one of them detects its own completion from durable state alone, so a
 * naive re-run after a lost race appends on top of the winner instead of over
 * it. A ceremony whose preconditions no longer hold after the re-read (the
 * retrying client was itself revoked, the staged key it was about to reveal is
 * no longer committed) surfaces its own typed refusal instead of looping.
 *
 * @param run {Function}   the ceremony body, re-invokable from the top
 * @returns {Promise<*>}   whatever the ceremony returns
 */
export async function withLogConflictRetry<T>(
  run: () => Promise<T>
): Promise<T> {
  const attempts = 3
  for (let attempt = 1; ; attempt++) {
    try {
      return await run()
    } catch (err) {
      if (!(err instanceof WebvhLogConflictError) || attempt >= attempts) {
        throw err
      }
    }
  }
}

/**
 * PUTs the serialized log to `did.jsonl`, forwarding the conditional-write
 * preconditions and mapping a failed one to {@link WebvhLogConflictError}. The
 * single place that mapping exists: the store seam is app-implemented, so the
 * precondition error is matched on `err.name` rather than by `instanceof`,
 * keeping the check implementation-agnostic. With neither precondition the PUT
 * is unconditional -- the degradation on a backend that serves no ETags.
 *
 * @param options {object}
 * @param options.store {object}   anything with the seam's `putIdResource`
 * @param options.log {DIDLog}
 * @param [options.ifMatch] {string}   publish only if the log is unchanged
 * @param [options.ifNoneMatch] {boolean}   publish only if the log is absent
 * @returns {Promise<void>}
 */
export async function putLogResource({
  store,
  log,
  ifMatch,
  ifNoneMatch
}: {
  store: Pick<WebvhIdStore, 'putIdResource'>
  log: DIDLog
  ifMatch?: string
  ifNoneMatch?: boolean
}): Promise<void> {
  try {
    await store.putIdResource({
      resourceId: DID_LOG_RESOURCE,
      content: logToJsonlString(log),
      contentType: 'text/jsonl',
      ifMatch,
      ifNoneMatch
    })
  } catch (err) {
    if ((err as { name?: string })?.name === 'PreconditionFailedError') {
      throw new WebvhLogConflictError(undefined, { cause: err })
    }
    throw err
  }
}

/**
 * Publishes an already-created log: PUT `did.jsonl` (`text/jsonl`) then PUT
 * `did.json` from `webDoc` (`application/did+json`, adopting the webvh
 * projection). Both land in the `id` collection, whose collection-level
 * `PublicCanRead` policy (set at provisioning) makes them world-readable, so
 * the publish tail no longer sets per-resource policies. The shared publish
 * tail of the create and rotate paths.
 *
 * The log PUT carries the caller's precondition (`ifMatch`, the ETag of the
 * read the entry was built on, or `ifNoneMatch` for a create), so a ceremony
 * that lost a race to a concurrent one fails with
 * {@link WebvhLogConflictError} instead of silently erasing the winner's entry.
 * The `did.json` projection PUT stays unconditional by design: it runs only
 * after the log's compare-and-swap was WON, so it is already serialized behind
 * that win; the log is the source of truth and the projection a derived cache;
 * and {@link concludeWithPublishedLog} re-derives and republishes the
 * projection from the resolved log on every ceremony's no-op path, healing any
 * lag a race or a torn publish leaves behind.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.log {DIDLog}
 * @param options.webDoc {object}
 * @param [options.ifMatch] {string}   publish only if `did.jsonl` is unchanged
 * @param [options.ifNoneMatch] {boolean}   publish only if `did.jsonl` is absent
 * @returns {Promise<void>}
 */
export async function publishWebvhLog({
  idStore,
  log,
  webDoc,
  ifMatch,
  ifNoneMatch
}: {
  idStore: WebvhIdStore
  log: DIDLog
  webDoc: object
  ifMatch?: string
  ifNoneMatch?: boolean
}): Promise<void> {
  await putLogResource({ store: idStore, log, ifMatch, ifNoneMatch })
  await idStore.putIdResource({
    resourceId: DID_DOCUMENT_RESOURCE,
    content: webDoc,
    contentType: 'application/did+json'
  })
}

/**
 * The shared guard-and-publish tail of every ceremony that extends the log
 * through `updateDID`: the parallel `webDoc` must be there (it is, whenever
 * `alsoKnownAsWeb` was passed), then log and projection are published under the
 * caller's compare-and-swap token.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.updated {object}   the `updateDID` result
 * @param options.updated.log {DIDLog}
 * @param [options.updated.webDoc] {object}
 * @param [options.ifMatch] {string}   the ETag of the read this entry was built
 *   on
 * @returns {Promise<void>}
 */
export async function publishUpdatedLog({
  idStore,
  updated,
  ifMatch
}: {
  idStore: WebvhIdStore
  updated: { log: DIDLog; webDoc?: object }
  ifMatch?: string
}): Promise<void> {
  if (!updated.webDoc) {
    throw new Error(
      'did:webvh: updateDID returned no webDoc despite the did:web alsoKnownAs.'
    )
  }
  await publishWebvhLog({
    idStore,
    log: updated.log,
    webDoc: updated.webDoc,
    ifMatch
  })
}

/**
 * Writes `keys.json` v2: the did:web relationship map plus the `webvh` block,
 * preserving the three did:web relationships.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.didWebKeys {DidWebKeyMap}
 * @param options.webvh {DidWebvhBlock}
 * @returns {Promise<void>}
 */
async function writeKeysJson({
  idStore,
  didWebKeys,
  webvh
}: {
  idStore: WebvhIdStore
  didWebKeys: DidWebKeyMap
  webvh: DidWebvhBlock
}): Promise<void> {
  const content: DidWebKeyMapV2 = { ...didWebKeys, webvh }
  await idStore.putKeyMap({ content })
}

/**
 * The verified state of the published log: the log itself, the resolved DID
 * and document, and the effective update-key parameters (the authorized
 * `updateKeys` and the standing `nextKeyHashes` commitments).
 */
export interface PublishedWebvhLog {
  log: DIDLog
  did: string
  doc: DIDDoc
  updateKeys: string[]
  nextKeyHashes: string[]
  /**
   * The `did.jsonl` ETag observed by the read that produced this state -- the
   * `ifMatch` token for the publish of any entry built on it. Absent against a
   * backend that serves no ETags, where the publish degrades to unconditional.
   */
  etag?: string
}

/**
 * Reads and resolves the published `did.jsonl`, or returns `undefined` when
 * the log is not published. A log that exists but fails to resolve throws --
 * a published-but-broken log is never silently re-created over.
 *
 * Given an `expectedDid`, a log resolving to any other DID is refused rather
 * than built on: the substituted-account check `verifyAccountLog` runs on the
 * world-readable read, applied here to the ceremony's own read. Callers that
 * hold the account pointer (or an earlier read of the same log, mid-ceremony)
 * pass it; a caller discovering the DID from the log itself cannot.
 *
 * Given a `pinStore`, the resolved log takes the same chain-head continuity
 * check `verifyAccountLog` runs, through literally the same seam and refusal
 * class: a served log that is a rollback, a fork, or an SCID/method switch
 * relative to the pinned head is refused with a
 * {@link ResourceLogContinuityError} rather than built on, and the pin is
 * established at first contact and advanced only by a log that verifies past
 * it. This is what stops a host from feeding a ceremony a valid PREFIX of the
 * real log -- same SCID, same DID, resolves cleanly -- and having the ceremony
 * republish the truncated history plus one entry as durable state. A
 * `rollback` is the one reason that may be nothing worse than replication lag,
 * exactly as on a governed resource log; nothing rolled back is ever adopted
 * here either way. An ABSENT log under a held pin is not "not yet published"
 * but a full truncation of a history this client has already seen, so it is
 * refused as a `rollback` instead of read as `undefined`.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param [options.expectedDid] {string}   the DID the log must resolve to
 * @param [options.pinStore] {ResourceLogPinStore}   this client's chain-head
 *   pins for the account log
 * @param [options.logId] {string}   the account log's pin-slot key, from
 *   `accountLogPinId({ spaceId })`; required whenever a `pinStore` is supplied
 * @returns {Promise<PublishedWebvhLog | undefined>}
 */
export async function readPublishedLog({
  idStore,
  expectedDid,
  pinStore,
  logId
}: {
  idStore: WebvhIdStore
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<PublishedWebvhLog | undefined> {
  if (pinStore && logId === undefined) {
    throw new TypeError('logId is required when pinStore is supplied')
  }
  // The pin slot this read checks against, present only when both halves are.
  const pinned =
    pinStore && logId !== undefined ? { store: pinStore, logId } : null
  const read = await idStore.getIdResourceRaw({
    resourceId: DID_LOG_RESOURCE
  })
  if (read === undefined) {
    if (pinned) {
      const pin = await pinned.store.read({ logId: pinned.logId })
      if (pin) {
        throw new ResourceLogContinuityError({
          reason: 'rollback',
          pinnedHead: pin.head
        })
      }
    }
    return undefined
  }
  const log = readLogFromString(read.text)
  const resolved = await resolveDIDFromLog(log)
  if (resolved.meta.error || !resolved.did || !resolved.doc) {
    throw new Error(
      `did:webvh: existing did.jsonl failed to resolve (${resolved.meta.error}).`
    )
  }
  if (expectedDid !== undefined && resolved.did !== expectedDid) {
    throw new Error(
      'did:webvh: the published did.jsonl resolves to a different DID ' +
        `(${resolved.did}) than expected (${expectedDid}).`
    )
  }
  if (pinned) {
    const pin = await pinned.store.read({ logId: pinned.logId })
    const served = checkAccountLogContinuity({ log, pin })
    // Advanced only when the served head is genuinely ahead of the pin: the
    // check above has already refused everything that is not.
    if (!pin || pin.head !== served.head) {
      await pinned.store.write({ logId: pinned.logId, pin: served })
    }
  }
  return {
    log,
    did: resolved.did,
    doc: resolved.doc,
    updateKeys: resolved.meta.updateKeys ?? [],
    nextKeyHashes: resolved.meta.nextKeyHashes ?? [],
    etag: read.etag
  }
}

/**
 * The chain-head pin a log establishes: the genesis entry's method and SCID
 * plus the head entry's `versionId`. Used where this client is the one that
 * just published the log and so knows its genesis firsthand -- first contact
 * should not be left to whatever the host serves back on the next read.
 *
 * @param log {DIDLog}
 * @returns {ResourceLogHeadPin}
 */
function pinOfLog(log: DIDLog): ResourceLogHeadPin {
  return checkAccountLogContinuity({ log, pin: null })
}

/**
 * The shared tail of every ceremony path that has nothing left to append to
 * the log -- an adoption, a resumed rotation, an already-enrolled no-op, an
 * already-revoked no-op. All of them used to infer completion from `did.jsonl`
 * alone, which is a half of the state: {@link publishWebvhLog} writes the log
 * and its `did:web` projection in two non-atomic PUTs, so a crash between them
 * leaves a `did.jsonl` that is complete beside a `did.json` that lags it
 * forever (nothing else republishes the projection).
 *
 * So the projection is re-derived from the resolved log and re-PUT
 * unconditionally rather than compared first: the write is idempotent and one
 * request either way, and the resolved log is the source of truth for what the
 * projection must say. A ceremony that no-ops on the log therefore still heals
 * a torn earlier publish. The projection PUT is deliberately unconditional
 * here too: healing it is the whole point, and the log it was derived from is
 * the state this call just read and resolved.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.published {PublishedWebvhLog}   the resolved published log
 * @returns {Promise<{ did: string; doc: DIDDoc }>}   the published DID and its
 *   resolved document
 */
export async function concludeWithPublishedLog({
  idStore,
  published
}: {
  idStore: WebvhIdStore
  published: PublishedWebvhLog
}): Promise<{ did: string; doc: DIDDoc }> {
  await idStore.putIdResource({
    resourceId: DID_DOCUMENT_RESOURCE,
    content: generateParallelDidWeb(published.did, published.doc),
    contentType: 'application/did+json'
  })
  return { did: published.did, doc: published.doc }
}

/**
 * The per-entry EFFECTIVE `updateKeys` / `nextKeyHashes` of a log, with
 * did:webvh's carry-forward semantics applied (an entry that omits a
 * parameter inherits the previous entry's value). Shared by the revocation
 * edit's staged-hash attribution and the enrolled-client listing's
 * update-key attribution.
 *
 * @param log {DIDLog}
 * @returns {Array<{ updateKeys: string[]; nextKeyHashes: string[] }>}
 */
export function effectiveParameters(
  log: DIDLog
): Array<{ updateKeys: string[]; nextKeyHashes: string[] }> {
  const out: Array<{ updateKeys: string[]; nextKeyHashes: string[] }> = []
  let updateKeys: string[] = []
  let nextKeyHashes: string[] = []
  for (const entry of log) {
    if (entry.parameters?.updateKeys) {
      updateKeys = entry.parameters.updateKeys
    }
    if (entry.parameters?.nextKeyHashes) {
      nextKeyHashes = entry.parameters.nextKeyHashes
    }
    out.push({ updateKeys, nextKeyHashes })
  }
  return out
}

/**
 * The `publicKeyMultibase` of every update-key seed this client holds, in
 * role order (active, staged, pending).
 *
 * @param options {object}
 * @param options.updateKeys {ClientWebvhUpdateKeys}
 * @returns {Promise<{ update: string; staged: string; pendingStaged?: string }>}
 */
async function updateKeyMultibases({
  updateKeys
}: {
  updateKeys: ClientWebvhUpdateKeys
}): Promise<{ update: string; staged: string; pendingStaged?: string }> {
  return {
    update: await updateKeyMultibase({ seed: updateKeys.updateSeed }),
    staged: await updateKeyMultibase({ seed: updateKeys.stagedSeed }),
    pendingStaged: updateKeys.pendingStagedSeed
      ? await updateKeyMultibase({ seed: updateKeys.pendingStagedSeed })
      : undefined
  }
}

/**
 * The published-but-not-finalized state of a rotation, if the log is in one:
 * the seed the log has already promoted to active, plus the seed it committed
 * as the next key (absent when this client no longer holds it, which is
 * unrecoverable).
 *
 * @param options {object}
 * @param options.published {object}   the resolved log's authorized updateKeys
 * @param options.multibases {object}   this client's update-key multibases
 * @param options.updateKeys {ClientWebvhUpdateKeys}
 * @returns {object | undefined}
 */
function advancedSeeds({
  published,
  multibases,
  updateKeys
}: {
  published: { updateKeys: string[] }
  multibases: { staged: string; pendingStaged?: string }
  updateKeys: ClientWebvhUpdateKeys
}): { updateSeed: Uint8Array; stagedSeed?: Uint8Array } | undefined {
  if (published.updateKeys.includes(multibases.staged)) {
    return {
      updateSeed: updateKeys.stagedSeed,
      stagedSeed: updateKeys.pendingStagedSeed
    }
  }
  if (
    multibases.pendingStaged &&
    updateKeys.pendingStagedSeed &&
    published.updateKeys.includes(multibases.pendingStaged)
  ) {
    return { updateSeed: updateKeys.pendingStagedSeed }
  }
  return undefined
}

/**
 * Idempotently provisions and publishes the user's did:webvh DID log. A wallet
 * that keeps a KMS runs it directly after the did:web provisioning (non-fatal)
 * and supplies the resulting `didWebKeys`; a wallet with no KMS supplies none,
 * gets the client-keys-only genesis, and no `keys.json` is ever written (the
 * record exists to bind DID relationships to KMS keys, and there are none).
 * The durable anchor is the caller-persisted update-key seeds, so the flow is
 * a simple probe:
 *
 * - `did.jsonl` published: sanity-check that the log's authorized `updateKeys`
 *   still name one of this client's seeds (active, staged, or pending -- a
 *   rotation in flight finalizes separately), adopt the resolved DID, and
 *   (with a key map) write the `keys.json` webvh block if it is missing or
 *   stale.
 * - `did.jsonl` absent: create the log with the active update key, prerotation
 *   committed to the staged key, publish log + `did.json`, then (with a key
 *   map) record the DID in `keys.json`.
 *
 * A published log whose `updateKeys` match none of the seeds is fatal: with
 * client-held update keys a lost seed is lost update authority, and no KMS
 * repair path exists by design.
 *
 * The create publishes `did.jsonl` create-if-absent, so two concurrent signups
 * cannot double-create the log: the loser re-runs (see
 * {@link withLogConflictRetry}) and takes the adoption path against the
 * winner's log -- adopting it when it holds this client's seeds, and raising
 * the lost-seed refusal when it does not.
 *
 * The probe read is checked against the DID this run expects -- a caller's
 * `expectedDid`, else the `webvh` block of the `keys.json` it was handed -- and
 * against a supplied `pinStore`, so neither a substituted log nor a truncated
 * prefix of the real one can be adopted here. One exemption, and it is the
 * documented first-contact case: an adoption holding neither a caller-supplied
 * `expectedDid` nor a `keys.json` webvh block legitimately discovers the DID
 * from the log itself, and runs unchecked. On the create path a supplied
 * `pinStore` is pinned to the log this run just published, since the creator
 * knows the true genesis and first contact should not be left to the next read.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}
 * @param [options.didWebKeys] {DidWebKeyMapV2}   the parsed keys.json (with any
 *   webvh block) returned by the did:web provisioning; absent on a
 *   client-keys-only genesis (no KMS anywhere in the path)
 * @param options.clientKeys {WebvhClientKeys}   this client's published keys
 * @param options.updateKeys {ClientWebvhUpdateKeys}   already durably persisted
 * @param [options.expectedDid] {string}   the DID the published log must
 *   resolve to, when the caller holds the account pointer
 * @param [options.pinStore] {ResourceLogPinStore}   this client's chain-head
 *   pins; the account log's slot is keyed by `accountLogPinId` over the
 *   `spaceId` above
 * @returns {Promise<{ did: string }>}
 */
export async function ensureDidWebvh(options: {
  idStore: WebvhIdStore
  wasServerUrl: string
  spaceId: string
  didWebKeys?: DidWebKeyMapV2
  clientKeys: WebvhClientKeys
  updateKeys: ClientWebvhUpdateKeys
  expectedDid?: string
  pinStore?: ResourceLogPinStore
}): Promise<{ did: string }> {
  return withLogConflictRetry(() => ensureDidWebvhOnce(options))
}

/**
 * One attempt of {@link ensureDidWebvh}, re-invoked by the conflict retry.
 *
 * @param options {object}   see {@link ensureDidWebvh}
 * @returns {Promise<{ did: string }>}
 */
async function ensureDidWebvhOnce({
  idStore,
  wasServerUrl,
  spaceId,
  didWebKeys,
  clientKeys,
  updateKeys,
  expectedDid,
  pinStore
}: {
  idStore: WebvhIdStore
  wasServerUrl: string
  spaceId: string
  didWebKeys?: DidWebKeyMapV2
  clientKeys: WebvhClientKeys
  updateKeys: ClientWebvhUpdateKeys
  expectedDid?: string
  pinStore?: ResourceLogPinStore
}): Promise<{ did: string }> {
  // The DID this run expects the published log to resolve to: the caller's,
  // else the one keys.json already records. Undefined only on the documented
  // first-contact adoption, which discovers the DID from the log itself.
  const expected = expectedDid ?? didWebKeys?.webvh?.did
  const logId = accountLogPinId({ spaceId })
  const published = await readPublishedLog({
    idStore,
    ...(expected !== undefined ? { expectedDid: expected } : {}),
    ...(pinStore ? { pinStore, logId } : {})
  })
  const multibases = await updateKeyMultibases({ updateKeys })

  if (published) {
    // Adoption: the log is already public (this client provisioned it, or a
    // torn earlier run published before recording the did). Accept any of the
    // three roles -- an interrupted rotation leaves the log at the staged or
    // pending key, and rotateWebvhUpdateKey finalizes it.
    const authorized = [
      multibases.update,
      multibases.staged,
      multibases.pendingStaged
    ].some(
      publicKeyMultibase =>
        publicKeyMultibase !== undefined &&
        published.updateKeys.includes(publicKeyMultibase)
    )
    if (!authorized) {
      throw new Error(
        "did:webvh: the published did.jsonl authorizes none of this client's " +
          'update keys -- the update-key seed is lost and the log can never ' +
          'be updated again.'
      )
    }
    if (didWebKeys && didWebKeys.webvh?.did !== published.did) {
      await writeKeysJson({
        idStore,
        didWebKeys,
        webvh: { did: published.did }
      })
    }
    // Heals a did.json left lagging by a torn earlier publish.
    const { did } = await concludeWithPublishedLog({ idStore, published })
    return { did }
  }

  const signer = await updateKeySigner({ seed: updateKeys.updateSeed })
  const created = await createWebvhLog({
    wasServerUrl,
    spaceId,
    didWebKeys,
    clientKeys,
    updateKeyPublicKeyMultibase: multibases.update,
    // The active key's own hash is committed beside the staged key's (the
    // carry-over convention in the module doc): the resolver checks every
    // later entry's re-stated updateKeys against these commitments, so
    // without it no non-rotating entry (an enrollment commit) could follow.
    nextKeyHashes: [
      await deriveNextKeyHash(multibases.update),
      await deriveNextKeyHash(multibases.staged)
    ],
    signer
  })
  await publishWebvhLog({
    idStore,
    log: created.log,
    webDoc: created.webDoc,
    // Create-if-absent: a concurrent signup that already published its own
    // log wins, and this run re-reads and adopts (or refuses) instead of
    // erasing it.
    ifNoneMatch: true
  })
  // Trust-on-first-use, established by the creator itself: this run minted the
  // genesis, so the pin it writes needs no served log to be believed.
  if (pinStore) {
    await pinStore.write({ logId, pin: pinOfLog(created.log) })
  }
  if (didWebKeys) {
    await writeKeysJson({
      idStore,
      didWebKeys,
      webvh: { did: created.did }
    })
  }
  return { did: created.did }
}

/**
 * Rotates this client's did:webvh update key (the user-triggered ceremony on
 * the wallet's settings screen). The staged key is revealed to sign its own
 * activation and become the sole active update key, a freshly minted staged
 * key is committed as the new `nextKeyHashes`, and the caller's persisted
 * seeds roll forward. No KMS and no `keys.json` involvement: the update keys
 * are client-held, and the published DID does not change.
 *
 * The persist-before-publish invariant is load-bearing: the new staged seed is
 * handed to `persistUpdateKeys` (as `pendingStagedSeed`) and awaited BEFORE the
 * log entry committing it is published, so no published log can ever depend on
 * a seed that is not durable. A crash between publish and finalize is
 * recovered on the next run: the log already sits at the staged (or pending)
 * key, and the seeds are simply rolled forward locally without touching it.
 *
 * Divergence that is NOT that recoverable case is refused up front, before any
 * durable write: the log must still authorize this client's active update key
 * AND commit its staged key's hash as a next key. Both are checked here rather
 * than left to the resolver, so a diverged client fails with a statement of
 * what diverged instead of persisting rolled seeds and then failing opaquely.
 *
 * The entry publishes conditionally on the log this ceremony read, so a
 * concurrent ceremony's entry is never erased; a lost race re-runs from the top
 * (see {@link withLogConflictRetry}), which mints and persists a fresh staged
 * seed again -- the documented cost of a torn rotation, one unused staged key.
 *
 * A rotation is a publish, so the read it builds on carries the full check: an
 * `expectedDid` refuses a substituted log, and a `pinStore` refuses a served
 * history that is a rollback, a fork, or an SCID/method switch -- without it a
 * host serving a truncated prefix gets this ceremony to republish the
 * truncation plus its own entry as the log's durable state. The pin advances
 * to the head this ceremony publishes, so a host that rolls the log back
 * immediately afterwards is caught by the next read.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.updateKeys {ClientWebvhUpdateKeys}   the current seeds
 * @param options.persistUpdateKeys {Function}   awaited before every publish
 *   that changes the log's authorized update keys
 * @param [options.expectedDid] {string}   the DID the published log must
 *   resolve to
 * @param [options.pinStore] {ResourceLogPinStore}   this client's chain-head
 *   pins for the account log
 * @param [options.logId] {string}   the account log's pin-slot key, built by
 *   the caller with `accountLogPinId({ spaceId })`; required whenever a
 *   `pinStore` is supplied
 * @returns {Promise<{ did: string }>}
 */
export async function rotateWebvhUpdateKey(options: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  persistUpdateKeys: (next: ClientWebvhUpdateKeys) => Promise<void>
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string }> {
  return withLogConflictRetry(() => rotateWebvhUpdateKeyOnce(options))
}

/**
 * One attempt of {@link rotateWebvhUpdateKey}, re-invoked by the conflict
 * retry.
 *
 * @param options {object}   see {@link rotateWebvhUpdateKey}
 * @returns {Promise<{ did: string }>}
 */
async function rotateWebvhUpdateKeyOnce({
  idStore,
  updateKeys,
  persistUpdateKeys,
  expectedDid,
  pinStore,
  logId
}: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  persistUpdateKeys: (next: ClientWebvhUpdateKeys) => Promise<void>
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string }> {
  if (pinStore && logId === undefined) {
    throw new TypeError('logId is required when pinStore is supplied')
  }
  const published = await readPublishedLog({
    idStore,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore && logId !== undefined ? { pinStore, logId } : {})
  })
  if (!published) {
    throw new Error('did:webvh: did.jsonl is missing; nothing to rotate.')
  }
  const multibases = await updateKeyMultibases({ updateKeys })

  // Crash recovery: a prior ceremony published the extended log but never
  // finalized the local seeds, so the log already sits at a key this client
  // holds without having promoted it. Roll the seeds forward and stop --
  // re-signing would fork the log.
  const advanced = advancedSeeds({ published, multibases, updateKeys })
  if (advanced) {
    if (!advanced.stagedSeed) {
      // The active key is recovered, but the next key that entry committed was
      // never persisted here, so no future entry can reveal it.
      throw new Error(
        'did:webvh: the published log has advanced to a key whose committed ' +
          'next key this client does not hold; the log can no longer be ' +
          'rotated.'
      )
    }
    await persistUpdateKeys({
      updateSeed: advanced.updateSeed,
      stagedSeed: advanced.stagedSeed
    })
    // The torn ceremony may have published did.jsonl without did.json.
    const { did } = await concludeWithPublishedLog({ idStore, published })
    return { did }
  }

  // Diverged-state guard: the log must still be at this client's active update
  // key, or another client has rotated it out from under us.
  if (!published.updateKeys.includes(multibases.update)) {
    throw new Error(
      "did:webvh: the published log has diverged from this client's update " +
        'keys (it authorizes neither the active nor the staged key); ' +
        'refusing to rotate.'
    )
  }

  // ... and the staged key this client is about to reveal must be the one the
  // log committed as its next key, or the reveal cannot verify. Caught here,
  // BEFORE any durable write, because the alternative is persisting a rolled
  // seed set and then failing deep inside the resolver with an opaque error.
  const stagedKeyHash = await deriveNextKeyHash(multibases.staged)
  if (!published.nextKeyHashes.includes(stagedKeyHash)) {
    throw new Error(
      "did:webvh: this client's update keys have diverged from the published " +
        'log (the staged key is not the log-committed next key); refusing to ' +
        'rotate.'
    )
  }

  // Mint the NEW staged seed and persist it BEFORE publishing anything, keeping
  // the current roles intact until the ceremony finalizes.
  const newStagedSeed = randomSeed()
  await persistUpdateKeys({
    updateSeed: updateKeys.updateSeed,
    stagedSeed: updateKeys.stagedSeed,
    pendingStagedSeed: newStagedSeed
  })

  // Extend the log. The revealed staged key signs its own activation and
  // replaces THIS client's active update key; every other enrolled client's
  // key is preserved (their hashes ride the carry-over commitments, so the
  // re-stated set still resolves). The retired key's hash is dropped and the
  // new staged key's committed. updateDID is sparse (no document directives)
  // so the verification methods are preserved -- a key-only rotation.
  const signer = await updateKeySigner({ seed: updateKeys.stagedSeed })
  const retiredKeyHash = await deriveNextKeyHash(multibases.update)
  const updated = await updateDID({
    log: published.log,
    signer,
    alsoKnownAsWeb: true,
    updateKeys: [
      ...published.updateKeys.filter(key => key !== multibases.update),
      multibases.staged
    ],
    nextKeyHashes: [
      ...new Set([
        ...published.nextKeyHashes.filter(hash => hash !== retiredKeyHash),
        await deriveNextKeyHash(multibases.staged),
        await deriveNextKeyHash(
          await updateKeyMultibase({ seed: newStagedSeed })
        )
      ])
    ]
  })

  // Publish the extended log and republish did.json (its did:web projection),
  // then finalize the local seeds: the staged key is now active, the pending
  // one is the new staged key.
  await publishUpdatedLog({ idStore, updated, ifMatch: published.etag })
  // Advance the pin to what this ceremony just published, so a host rolling
  // the log back straight afterwards is refused on the next read.
  if (pinStore && logId !== undefined) {
    await pinStore.write({ logId, pin: pinOfLog(updated.log) })
  }
  await persistUpdateKeys({
    updateSeed: updateKeys.stagedSeed,
    stagedSeed: newStagedSeed
  })
  return { did: updated.did }
}

/**
 * Asserts the carry-over commitment convention holds for every currently
 * authorized update key -- the precondition for any entry that re-states
 * `updateKeys` (the resolver checks the re-stated set against the previous
 * entry's `nextKeyHashes`). A log minted before the convention cannot take a
 * non-rotating entry and must be re-provisioned.
 *
 * @param options {object}
 * @param options.published {PublishedWebvhLog}
 * @returns {Promise<void>}
 */
export async function assertCarryOverCommitments({
  published
}: {
  published: PublishedWebvhLog
}): Promise<void> {
  for (const key of published.updateKeys) {
    if (!published.nextKeyHashes.includes(await deriveNextKeyHash(key))) {
      throw new Error(
        'did:webvh: the published log does not carry the active update ' +
          "keys' own hashes in nextKeyHashes (it predates the carry-over " +
          'commitment convention); re-provision the account first.'
      )
    }
  }
}

/**
 * The public halves of a client being enrolled: its published key set (the
 * Ed25519 signing key and X25519 key-agreement twin that become document
 * verification methods) plus its update-key pair -- the active key that joins
 * `updateKeys` and the staged key whose hash is committed so the new client
 * can later self-rotate. All four are `publicKeyMultibase` strings; the seeds
 * behind them never leave the client being enrolled.
 */
export interface WebvhEnrollmentKeys extends WebvhClientKeys {
  updateKeyMultibase: string
  stagedUpdateKeyMultibase: string
}

/**
 * The relationship references of a resolved document as verification-method
 * ids, tolerating embedded objects beside string references.
 *
 * @param relation {Array}   the relationship array, when present
 * @returns {string[]}
 */
export function relationIds(
  relation: Array<string | { id?: string }> | undefined
): string[] {
  const ids: string[] = []
  for (const entry of relation ?? []) {
    const id = typeof entry === 'string' ? entry : entry?.id
    if (id) {
      ids.push(id)
    }
  }
  return ids
}

/**
 * Enrolls a second wallet client into the published did:webvh document -- the
 * log half of the enrollment ceremony (the user key roster wrap happens first,
 * outside this module). Two entries, forced by prerotation (a new update key
 * must hash into the PREVIOUS entry's `nextKeyHashes`):
 *
 * 1. **Commit**: a sparse entry extending `nextKeyHashes` with the new
 *    client's update-key and staged-key hashes (document and `updateKeys`
 *    untouched).
 * 2. **Add**: an entry adding the new client's verification methods (its
 *    Ed25519 key under the four signing relationships, its X25519 twin under
 *    `keyAgreement`) and its update key to `updateKeys`.
 *
 * Both entries are signed by THIS client's active update key (quorum-of-one:
 * any single enrolled client can enroll). The ceremony is resumable from
 * durable state alone: a tear after the commit is detected by its hashes
 * already standing in `nextKeyHashes` (skip to the add entry), and a
 * completed enrollment is detected by the update key already being authorized
 * (no-op). Re-running with the same key set converges without forking the
 * log.
 *
 * Each entry publishes conditionally on the read it was built on (the add
 * entry on the mid-ceremony re-read), so a concurrent ceremony -- a revocation,
 * another enrollment -- can never be erased by this one; a lost race re-runs
 * from the top (see {@link withLogConflictRetry}) and rebases on the new head.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.updateKeys {ClientWebvhUpdateKeys}   THIS client's seeds
 * @param options.newClient {WebvhEnrollmentKeys}   the enrollee's public halves
 * @returns {Promise<{ did: string }>}
 */
export async function enrollWebvhClient(options: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  newClient: WebvhEnrollmentKeys
}): Promise<{ did: string }> {
  return withLogConflictRetry(() => enrollWebvhClientOnce(options))
}

/**
 * One attempt of {@link enrollWebvhClient}, re-invoked by the conflict retry.
 *
 * @param options {object}   see {@link enrollWebvhClient}
 * @returns {Promise<{ did: string }>}
 */
async function enrollWebvhClientOnce({
  idStore,
  updateKeys,
  newClient
}: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  newClient: WebvhEnrollmentKeys
}): Promise<{ did: string }> {
  let published = await readPublishedLog({ idStore })
  if (!published) {
    throw new Error('did:webvh: did.jsonl is missing; nothing to enroll into.')
  }
  const multibases = await updateKeyMultibases({ updateKeys })

  // Already enrolled (a completed earlier run): the new client's update key is
  // authorized, which only the add entry writes. Idempotent no-op on the log,
  // but it still heals a did.json the earlier run left lagging.
  if (published.updateKeys.includes(newClient.updateKeyMultibase)) {
    const { did } = await concludeWithPublishedLog({ idStore, published })
    return { did }
  }

  // Both entries are signed by this client's active update key; a log that
  // does not authorize it (a rotation torn elsewhere) must heal first.
  if (!published.updateKeys.includes(multibases.update)) {
    throw new Error(
      "did:webvh: the published log does not authorize this client's active " +
        'update key; finalize the pending rotation before enrolling.'
    )
  }

  const newUpdateKeyHash = await deriveNextKeyHash(newClient.updateKeyMultibase)
  const newStagedKeyHash = await deriveNextKeyHash(
    newClient.stagedUpdateKeyMultibase
  )

  // The commit entry (skipped when a torn earlier run already published it).
  const committed =
    published.nextKeyHashes.includes(newUpdateKeyHash) &&
    published.nextKeyHashes.includes(newStagedKeyHash)
  if (!committed) {
    // A sparse entry re-states the authorized updateKeys, and the resolver
    // checks each against the PREVIOUS entry's commitments -- so every
    // currently authorized key's hash must already stand in nextKeyHashes
    // (the carry-over convention). A log minted before the convention cannot
    // take a non-rotating entry.
    for (const key of published.updateKeys) {
      if (!published.nextKeyHashes.includes(await deriveNextKeyHash(key))) {
        throw new Error(
          'did:webvh: the published log does not carry the active update ' +
            "keys' own hashes in nextKeyHashes (it predates the carry-over " +
            'commitment convention); re-provision the account before ' +
            'enrolling.'
        )
      }
    }
    const signer = await updateKeySigner({ seed: updateKeys.updateSeed })
    const updated = await updateDID({
      log: published.log,
      signer,
      alsoKnownAsWeb: true,
      // Re-stated unchanged (the library requires them explicitly while
      // prerotation is active); the carry-over commitments are what make the
      // re-statement resolvable.
      updateKeys: published.updateKeys,
      nextKeyHashes: [
        ...new Set([
          ...published.nextKeyHashes,
          newUpdateKeyHash,
          newStagedKeyHash
        ])
      ]
    })
    await publishUpdatedLog({ idStore, updated, ifMatch: published.etag })
    // Re-read through the same verifying path the resume case uses, so the
    // add entry below always builds on the published, resolved state. It must
    // still be the same account: the DID the first read resolved to is what
    // the entry just published extends.
    published = await readPublishedLog({ idStore, expectedDid: published.did })
    if (!published) {
      throw new Error('did:webvh: did.jsonl vanished mid-enrollment.')
    }
  }

  // The add entry: the new client's two verification methods and its update
  // key, on top of the full existing document (updateDID replaces the
  // verification-method set and relationship arrays wholesale).
  const {
    did,
    doc,
    log,
    updateKeys: authorizedKeys,
    nextKeyHashes,
    etag
  } = published
  const vmId = (publicKeyMultibase: string) => `${did}#${publicKeyMultibase}`
  // The signing method is controlled by the account; the key-agreement method
  // alone carries the controller marker, and the pair builder refuses a
  // key-agreement key that is not the signing key's canonical twin.
  const addedMethods: VerificationMethod[] = markedVerificationMethodPair({
    controller: did,
    signingKeyMultibase: newClient.signingKeyMultibase,
    keyAgreementKeyMultibase: newClient.keyAgreementKeyMultibase
  })
  const existingMethods = (doc.verificationMethod ?? []) as VerificationMethod[]
  const verificationMethods = [
    ...existingMethods.filter(
      method => !addedMethods.some(added => added.id === method.id)
    ),
    ...addedMethods
  ]
  const withReference = (
    relation: Array<string | { id?: string }> | undefined,
    id: string
  ) => [...new Set([...relationIds(relation), id])]
  const signingVmId = vmId(newClient.signingKeyMultibase)

  const signer = await updateKeySigner({ seed: updateKeys.updateSeed })
  const updated = await updateDID({
    log,
    signer,
    alsoKnownAsWeb: true,
    updateKeys: [...new Set([...authorizedKeys, newClient.updateKeyMultibase])],
    nextKeyHashes,
    verificationMethods,
    authentication: withReference(doc.authentication, signingVmId),
    assertionMethod: withReference(doc.assertionMethod, signingVmId),
    keyAgreement: withReference(
      doc.keyAgreement,
      vmId(newClient.keyAgreementKeyMultibase)
    ),
    capabilityInvocation: withReference(doc.capabilityInvocation, signingVmId),
    capabilityDelegation: withReference(doc.capabilityDelegation, signingVmId)
  })
  // The etag of the read this entry was built on: the mid-ceremony re-read
  // when the commit entry ran here, the original read when it was skipped.
  await publishUpdatedLog({ idStore, updated, ifMatch: etag })
  return { did: updated.did }
}

/**
 * Rebuilds `keys.json` from the published artifacts plus a WebKMS key listing
 * -- the recovery path for a lost or rolled-back `keys.json`. List Keys is
 * authorized as `read` against the keystore controller, which only the
 * root-controlled keystore agent can invoke.
 *
 * KMS key local ids are server-generated random and appear in no published
 * artifact, so the bindings are rediscovered by public key material instead.
 * List the keystore once -- each listed description carries `keyUrl`, the
 * key's canonical invocation URL (the signable handle its alias-overridden
 * `id` erases) -- then match `did.json`'s relationship verification methods
 * by `publicKeyMultibase` and rewrite `keys.json` from what matched. The
 * `authentication` and `keyAgreement` bindings are required; `assertionMethod`
 * lists client keys only, so no KMS binding exists there and none is rebuilt.
 * When `did.jsonl` is published, its resolved DID is recorded in the `webvh`
 * block; there is nothing else to repair there, since the log's update keys are
 * client-held seeds that no keystore listing could recover.
 *
 * An unmatchable binding is unrepairable and throws: a published artifact
 * depends on a key the keystore no longer lists.
 *
 * The log read takes the same checks every other ceremony read does, and for
 * the same reason: what it reads is written straight back into the rebuilt
 * `keys.json`, so a substituted log would rewrite the `webvh` block to a wrong
 * DID and a truncated one would be adopted as this account's history. A caller
 * that still holds the account pointer passes `expectedDid` and its
 * `pinStore`; the pure-recovery caller that has lost everything but the
 * keystore has no DID to expect and passes neither, which is the one read here
 * that legitimately discovers the DID from the log itself.
 *
 * @param options {object}
 * @param options.keystoreAgent {KeystoreAgent}
 * @param options.idStore {WebvhIdStore}
 * @param [options.expectedDid] {string}   the DID the published log must
 *   resolve to
 * @param [options.pinStore] {ResourceLogPinStore}   this client's chain-head
 *   pins for the account log
 * @param [options.logId] {string}   the account log's pin-slot key, built by
 *   the caller with `accountLogPinId({ spaceId })`; required whenever a
 *   `pinStore` is supplied
 * @returns {Promise<DidWebKeyMapV2>}   the rebuilt, persisted keys.json
 */
export async function repairKeyBindings({
  keystoreAgent,
  idStore,
  expectedDid,
  pinStore,
  logId
}: {
  keystoreAgent: KeystoreAgent
  idStore: WebvhIdStore
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<DidWebKeyMapV2> {
  if (pinStore && logId === undefined) {
    throw new TypeError('logId is required when pinStore is supplied')
  }
  const didDoc = (await idStore.getIdResource({
    resourceId: DID_DOCUMENT_RESOURCE
  })) as
    | {
        verificationMethod?: Array<{ id?: string; publicKeyMultibase?: string }>
        authentication?: Array<string | { id?: string }>
        keyAgreement?: Array<string | { id?: string }>
      }
    | undefined
  if (!didDoc) {
    throw new Error(
      'keys.json repair: did.json is not published; there is nothing to ' +
        'match key bindings against.'
    )
  }

  // One listing, matched by public key material below. `keyUrl` is the
  // list-only projection field (webkms-client >= 14.7.1 types it; an older
  // server omits it, so entries without one are skipped and simply fail to
  // match).
  const listed = (await keystoreAgent.listKeys()) as Array<{
    publicKeyMultibase?: string
    keyUrl?: string
  }>
  const keyUrlByMultibase = new Map<string, string>()
  for (const description of listed) {
    if (description.publicKeyMultibase && description.keyUrl) {
      keyUrlByMultibase.set(description.publicKeyMultibase, description.keyUrl)
    }
  }

  // A relationship's first keystore-backed verification method. A
  // relationship can name several verification methods now that enrolled
  // clients publish their own keys beside the KMS ones, so every reference is
  // tried and the first keystore-backed one wins; a client-held key simply
  // fails to match and is skipped.
  const findKmsBacked = (
    relationship: 'authentication' | 'keyAgreement'
  ): { bound?: DidWebKey; tried: string[] } => {
    const tried: string[] = []
    for (const reference of didDoc[relationship] ?? []) {
      const vmId = typeof reference === 'string' ? reference : reference?.id
      if (!vmId) {
        continue
      }
      const method = didDoc.verificationMethod?.find(entry => entry.id === vmId)
      const publicKeyMultibase = method?.publicKeyMultibase ?? multibaseOf(vmId)
      tried.push(publicKeyMultibase)
      const kmsKeyId = keyUrlByMultibase.get(publicKeyMultibase)
      if (kmsKeyId) {
        return { bound: { vmId, kmsKeyId }, tried }
      }
    }
    return { tried }
  }
  const bind = (relationship: 'authentication' | 'keyAgreement'): DidWebKey => {
    if ((didDoc[relationship] ?? []).length === 0) {
      throw new Error(
        `keys.json repair: did.json declares no ${relationship} verification method.`
      )
    }
    const { bound, tried } = findKmsBacked(relationship)
    if (!bound) {
      throw new Error(
        `keys.json repair: no keystore key matches the ${relationship} ` +
          `verification method (${tried.join(', ')}).`
      )
    }
    return bound
  }
  const repaired: DidWebKeyMapV2 = {
    authentication: bind('authentication'),
    keyAgreement: bind('keyAgreement')
  }

  // The webvh block, recovered from the published log: the DID and nothing
  // else, since the update keys never left the client that minted them.
  const published = await readPublishedLog({
    idStore,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore && logId !== undefined ? { pinStore, logId } : {})
  })
  if (published) {
    repaired.webvh = { did: published.did }
  }

  // Persist the rebuilt anchor in one write.
  await idStore.putKeyMap({ content: repaired })
  return repaired
}
