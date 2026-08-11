/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The App Connect app-key credential: a self-issued VC that carries a 32-byte
 * seed an app keeps in the user's wallet so it can open its encrypted data on
 * this and other devices. Unlike an ordinary credential, the issuer and
 * subject are NOT the wallet user's DID -- they are a did:key derived from the
 * seed itself (self-issued by the app key), so the credential validates
 * standalone and the same seed reconstitutes the same identity on every
 * client. The credential is bound to the attested requesting origin
 * (`credentialSubject.origin`) and to the application's canonical URL
 * (`credentialSubject.appUrl`), and matched wallet-side against both, so a
 * phishing origin can neither recover an existing app key nor be handed one
 * minted for another origin, and applications sharing an origin are kept
 * apart by their `appUrl`s.
 *
 * Ported from Freewallet's `src/lib/appKey.ts`, migrated from the
 * `credentialType` / `vocabBase` model to the App Connect spec's `appUrl`
 * model: the type array is a fixed two-entry list, the inline `@context` is
 * one static object identical for every application, and which application a
 * credential belongs to is a claim (`credentialSubject.appUrl`), not a type.
 * See the App Connect spec's App Key Credential section for the normative
 * shape, matching, and minting rules this module implements.
 */
import * as vc from '@interop/vc'
import { base64urlnopad } from '@scure/base'
import { CapabilityAgent } from '@interop/webkms-client'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import {
  issuerId,
  subjectId,
  typeArray
} from '@interop/data-integrity-core/guards'
import { documentLoader } from './composeVp.js'
import type { IAppConnectApp } from './types.js'

/**
 * The semantic `handle` mixed into seed derivation. It identifies the agent
 * but does not affect the derived key (only the seed bytes and the key name
 * enter the HMAC), so it is cosmetic; kept for legibility.
 */
const APP_KEY_HANDLE = 'freewallet-app-key'

/**
 * The key name mixed into seed derivation. Unlike the handle this is
 * load-bearing: it is the HMAC message in `CapabilityAgent` derivation, so the
 * exact string is a pinned input of the App Connect key-derivation rule --
 * every existing app-key credential's identity depends on it.
 */
export const APP_KEY_KEY_NAME = 'app-key'

const VC_1_CONTEXT_URL = 'https://www.w3.org/2018/credentials/v1'

/**
 * The marker type every app-key credential carries, mapped to one stable IRI
 * for every application. It makes "presents as an app key" a term check rather
 * than a shape heuristic, which is what the store-time refusal
 * ({@link assertStorableAppKey}) and the match path key off.
 *
 * It is a self-declaration, not evidence: the `type` array of a planted
 * credential is attacker-controlled like the rest of it. The seed-to-subject
 * binding ({@link appKeySeedBindsSubject}) authenticates only a credential's
 * internal consistency, never its provenance (a fully attacker-generated
 * credential binds perfectly). That is exactly why external ingest refuses on
 * the marker alone, binding or not ({@link assertStorableAppKey}): app keys
 * are wallet-minted, never imported.
 */
export const APP_KEY_CREDENTIAL_TYPE = 'AppKeyCredential'

/**
 * The fixed `type` array of every app-key credential: exactly two entries, in
 * this order, identical for every application. Which application a credential
 * belongs to is the `credentialSubject.appUrl` claim, not a type.
 */
export const APP_KEY_TYPE_ARRAY: readonly string[] = Object.freeze([
  'VerifiableCredential',
  APP_KEY_CREDENTIAL_TYPE
])

/**
 * The static inline `@context` object every app-key credential carries as the
 * second entry of its `@context` array (after the VC 1.1 context URL). The
 * shape is normative and byte-identical for every application and every
 * credential: carrying the terms inline keeps the credential verifiable with
 * no remote vocabulary fetch on either side.
 */
export const APP_KEY_CONTEXT: Readonly<Record<string, unknown>> = Object.freeze(
  {
    '@protected': true,
    AppKeyCredential: 'https://w3id.org/byoe#AppKeyCredential',
    appUrl: 'https://w3id.org/byoe#appUrl',
    seed: 'https://w3id.org/byoe#seed',
    origin: 'https://w3id.org/byoe#origin',
    name: 'https://schema.org/name',
    description: 'https://schema.org/description'
  }
)

/**
 * The number of random bytes in an app-key seed.
 */
const SEED_BYTE_LENGTH = 32

/**
 * Whether a credential presents as an app key -- that is, carries the
 * {@link APP_KEY_CREDENTIAL_TYPE} marker in its `type` array. Says nothing
 * about whether it IS one; that is the seed-to-subject binding's job.
 *
 * @param credential {IVerifiableCredential}
 * @returns {boolean}
 */
export function presentsAsAppKey(credential: IVerifiableCredential): boolean {
  return typeArray(credential.type).includes(APP_KEY_CREDENTIAL_TYPE)
}

/**
 * The refusal a store path raises for a credential that presents as an app key
 * but arrived from outside the wallet's own mint path. A distinct class so the
 * UI can show its own translated wording rather than this message.
 */
export class AppKeyRefusedError extends Error {
  constructor() {
    super(
      'This credential claims to be an app key. App keys are created by the ' +
        'wallet itself and cannot be added from outside, so it was not stored.'
    )
    this.name = 'AppKeyRefusedError'
  }
}

/**
 * Refuses any credential that presents as an app key, unconditionally --
 * whether or not it binds to its own seed. Called on every path that puts a
 * credential in the store from outside the wallet (a CHAPI store offer, a
 * URL / QR / manual-paste import), so an externally arriving app key never
 * reaches the store, the credential list, or the user's Space.
 *
 * The seed-to-subject binding ({@link appKeySeedBindsSubject}) authenticates
 * only the credential's internal consistency, not its provenance: a fully
 * attacker-generated credential binds perfectly (a fresh seed, the victim
 * app's `origin` and `appUrl`, self-issued), and storing it would make its
 * DID the controller the wallet delegates the user's storage to. So there is
 * no "binds, so it stores" carve-out here: app-key credentials are
 * wallet-minted, never imported, and only the wallet's own mint path may
 * store one.
 *
 * A credential with no marker is left alone, so an ordinary credential that
 * merely happens to carry a `seed` or `origin` claim is never caught.
 *
 * @param credential {IVerifiableCredential}
 * @returns {void}   throws the refusal reason
 */
export function assertStorableAppKey(credential: IVerifiableCredential): void {
  if (presentsAsAppKey(credential)) {
    throw new AppKeyRefusedError()
  }
}

/**
 * Whether an app-key credential's subject DID is the one its own seed derives
 * -- the binding that makes the credential an app key rather than merely a
 * self-issued claim to be one. Self-issuance is a weak signal (anyone can
 * self-issue); this is the strong one, and it is fully local: the credential
 * carries the seed, so re-derive with the same call `mintAppKeyCredential`
 * uses and compare. Fails closed on an absent, non-base64url, or otherwise
 * unusable seed rather than throwing out of the match path.
 *
 * @param credential {IVerifiableCredential}
 * @returns {Promise<boolean>}
 */
export async function appKeySeedBindsSubject(
  credential: IVerifiableCredential
): Promise<boolean> {
  const subjectDid = subjectId(credential)
  const seed = appKeySeedBytes(credential)
  if (!subjectDid || !seed || seed.length !== SEED_BYTE_LENGTH) {
    return false
  }
  try {
    const agent = await CapabilityAgent.fromSeed({
      seed,
      handle: APP_KEY_HANDLE,
      keyName: APP_KEY_KEY_NAME
    })
    return agent.id === subjectDid
  } catch {
    return false
  }
}

/**
 * Raised by {@link assertMintedAppKey} when a credential offered to the mint
 * path's store door does not carry the mint invariants. Reaching it means a
 * caller tried to route a foreign credential through the wallet's own mint
 * door -- a programming error, not a user-facing refusal, so it is not
 * translated like {@link AppKeyRefusedError}.
 */
export class AppKeyMintInvariantError extends Error {
  constructor() {
    super(
      'Only a wallet-minted app-key credential (marker type present, subject ' +
        'DID derived from its own seed) can be stored through the mint path.'
    )
    this.name = 'AppKeyMintInvariantError'
  }
}

/**
 * Asserts the mint invariants on a credential the wallet claims to have just
 * minted: it presents as an app key (the marker type) and its subject DID
 * re-derives from the seed it carries. The mirror image of
 * {@link assertStorableAppKey} -- external ingest refuses every marker
 * credential, the mint door stores only credentials that carry the full mint
 * shape -- kept beside it so the two halves of the app-key store policy live
 * in one module.
 *
 * @param credential {IVerifiableCredential}
 * @returns {Promise<void>}   throws {@link AppKeyMintInvariantError}
 */
export async function assertMintedAppKey(
  credential: IVerifiableCredential
): Promise<void> {
  if (
    !presentsAsAppKey(credential) ||
    !(await appKeySeedBindsSubject(credential))
  ) {
    throw new AppKeyMintInvariantError()
  }
}

/**
 * Whether a credential is self-issued: it names an issuer, and that issuer is
 * its own subject. The shape every app-key credential has and every planted
 * one must not be allowed to fake alone.
 */
function isSelfIssued(credential: IVerifiableCredential): boolean {
  const issuer = issuerId(credential.issuer)
  return !!issuer && issuer === subjectId(credential)
}

/**
 * The instant a credential's `issuanceDate` denotes, or NaN when it is
 * absent, not a string, or does not parse. Ranking is over instants, not raw
 * strings: the ranking decides which DID the wallet delegates to, so a
 * comparison manipulable by the *spelling* of a date (a numeric offset,
 * differing fractional-second precision) would reopen the planted-credential
 * path in a narrower form.
 */
function issuanceInstant(credential: IVerifiableCredential): number {
  const raw = (credential as { issuanceDate?: unknown }).issuanceDate
  if (typeof raw !== 'string') {
    return NaN
  }
  return Date.parse(raw)
}

/**
 * Sort comparator ordering credentials latest-first by the instant their
 * `issuanceDate` denotes; a credential whose date is absent or unparseable
 * sorts last.
 */
function byIssuanceInstantDesc(
  first: IVerifiableCredential,
  second: IVerifiableCredential
): number {
  const firstInstant = issuanceInstant(first)
  const secondInstant = issuanceInstant(second)
  if (Number.isNaN(firstInstant)) {
    return Number.isNaN(secondInstant) ? 0 : 1
  }
  if (Number.isNaN(secondInstant)) {
    return -1
  }
  return secondInstant - firstInstant
}

/**
 * The app-key candidates for an app + origin, latest-first: everything the
 * cheap, synchronous predicates accept, so only plausible candidates pay for
 * a key derivation. A candidate must carry the marker (required, not merely
 * tolerated: a credential can then only reach the delegation path by carrying
 * it, which is exactly what the store-time refusal screens), name the
 * request's `appUrl` in `credentialSubject.appUrl` (both sides in serialized
 * form -- the wallet mints the claim serialized, so the comparison is an
 * exact string match), be self-issued, and be bound to the attested
 * requesting origin. Sorting here (rather than after the binding check) lets
 * {@link findAppKeyCredential} stop at the newest credential that binds.
 *
 * @param options {object}
 * @param options.credentials {IVerifiableCredential[]}
 * @param options.appUrl {string} - The request's `app.appUrl` in serialized
 *   form.
 * @param options.origin {string} - The attested requesting origin.
 * @returns {IVerifiableCredential[]}
 */
export function appKeyCandidates({
  credentials,
  appUrl,
  origin
}: {
  credentials: IVerifiableCredential[]
  appUrl: string
  origin: string
}): IVerifiableCredential[] {
  return credentials
    .filter(
      credential =>
        presentsAsAppKey(credential) &&
        appKeyAppUrl(credential) === appUrl &&
        isSelfIssued(credential) &&
        appKeyOrigin(credential) === origin
    )
    .sort(byIssuanceInstantDesc)
}

/**
 * The current (latest) app-key credential for an app + origin, or undefined
 * when the user has none -- which signals first run for that (origin,
 * `appUrl`) pair.
 *
 * @param options {object}
 * @param options.credentials {IVerifiableCredential[]}
 * @param options.appUrl {string} - The request's `app.appUrl` in serialized
 *   form.
 * @param options.origin {string} - The attested requesting origin.
 * @returns {Promise<IVerifiableCredential | undefined>}
 */
export async function findAppKeyCredential({
  credentials,
  appUrl,
  origin
}: {
  credentials: IVerifiableCredential[]
  appUrl: string
  origin: string
}): Promise<IVerifiableCredential | undefined> {
  // Newest-first, returning at the first credential that binds: a non-binding
  // one ranked above it is discarded on the way, and the credentials below it
  // never pay for a key derivation.
  for (const candidate of appKeyCandidates({ credentials, appUrl, origin })) {
    if (await appKeySeedBindsSubject(candidate)) {
      return candidate
    }
  }
  return undefined
}

/**
 * Assembles and signs an app-key credential for a seed the caller supplies:
 * the fixed two-entry type array, the static inline context, issuer and
 * subject both the seed-derived DID, and the `seed` / `appUrl` / `origin`
 * claims. `vc.issue` auto-fills `issuanceDate` in the canonical UTC form the
 * ranking expects. Shared by the fresh mint and the legacy re-issue.
 */
async function issueAppKeyCredential({
  seedBytes,
  appName,
  appUrl,
  origin,
  description
}: {
  seedBytes: Uint8Array
  appName: string
  appUrl: string
  origin: string
  description: string
}): Promise<{ credential: IVerifiableCredential; subjectDid: string }> {
  const agent = await CapabilityAgent.fromSeed({
    seed: seedBytes,
    handle: APP_KEY_HANDLE,
    keyName: APP_KEY_KEY_NAME
  })
  const controllerDid = agent.id
  const credential = {
    '@context': [VC_1_CONTEXT_URL, { ...APP_KEY_CONTEXT }],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: [...APP_KEY_TYPE_ARRAY],
    name: `${appName} app key`,
    description,
    issuer: controllerDid,
    credentialSubject: {
      id: controllerDid,
      seed: base64urlnopad.encode(seedBytes),
      appUrl,
      origin
    }
  }
  const suite = new Ed25519Signature2020({ signer: agent.getSigner() })
  const signed = (await vc.issue({
    credential,
    suite,
    documentLoader
  })) as IVerifiableCredential
  return { credential: signed, subjectDid: controllerDid }
}

/**
 * Mints a fresh app-key credential for an app + origin: generates a 32-byte
 * seed, derives the seed's did:key, and self-issues the credential (issuer ==
 * subject == the seed-derived DID) with the `credentialSubject.appUrl` claim
 * set from the validated request value. Does NOT store the result -- the
 * caller stores it before delegating, so a failed delegation is found as
 * "returning" on the next attempt rather than minting a second identity.
 *
 * @param options {object}
 * @param options.app {IAppConnectApp} - The validated app identity; its
 *   `appUrl` must already be in serialized form (`appConnectRequestOf`
 *   guarantees this).
 * @param options.origin {string} - The attested requesting origin, never a
 *   value taken from the request body.
 * @returns {Promise<{ credential: IVerifiableCredential; subjectDid: string }>}
 */
export async function mintAppKeyCredential({
  app,
  origin
}: {
  app: IAppConnectApp
  origin: string
}): Promise<{ credential: IVerifiableCredential; subjectDid: string }> {
  const seedBytes = crypto.getRandomValues(new Uint8Array(SEED_BYTE_LENGTH))
  return issueAppKeyCredential({
    seedBytes,
    appName: app.name,
    appUrl: app.appUrl,
    origin,
    description:
      `The ${app.name} app keeps this key in your wallet so it can open ` +
      'your encrypted data on this and other devices.'
  })
}

/**
 * The latest legacy app-key credential for an origin, or undefined. A legacy
 * credential predates the `appUrl` model: it carries the marker and a
 * per-app third type entry, but no `credentialSubject.appUrl` claim. Its
 * identity was scoped to (origin, `credentialType`), and the request no
 * longer carries a `credentialType` to select on, so the mapping is
 * recoverable only when it is unambiguous: when the binding legacy candidates
 * for the origin all name one subject DID. Two distinct legacy identities on
 * one origin yield undefined rather than a guess -- re-issuing the wrong one
 * would hand one application another's identity, which is worse than the
 * caller treating the connect as a first run.
 *
 * @param options {object}
 * @param options.credentials {IVerifiableCredential[]}
 * @param options.origin {string} - The attested requesting origin.
 * @returns {Promise<IVerifiableCredential | undefined>}
 */
export async function findLegacyAppKeyCredential({
  credentials,
  origin
}: {
  credentials: IVerifiableCredential[]
  origin: string
}): Promise<IVerifiableCredential | undefined> {
  const candidates = credentials
    .filter(
      credential =>
        presentsAsAppKey(credential) &&
        appKeyAppUrl(credential) === undefined &&
        isSelfIssued(credential) &&
        appKeyOrigin(credential) === origin
    )
    .sort(byIssuanceInstantDesc)
  const bound: IVerifiableCredential[] = []
  for (const candidate of candidates) {
    if (await appKeySeedBindsSubject(candidate)) {
      bound.push(candidate)
    }
  }
  if (bound.length === 0) {
    return undefined
  }
  const subjects = new Set(bound.map(credential => subjectId(credential)))
  if (subjects.size > 1) {
    return undefined
  }
  return bound[0]
}

/**
 * Re-issues a legacy app-key credential in place under the `appUrl` model:
 * the same seed (so the same derived DID -- the app's identity and its
 * encrypted-data access are preserved), the fixed two-entry type array, the
 * static inline context, and the `credentialSubject.appUrl` claim set from
 * the validated request value. A fresh mint would roll the seed and orphan
 * the identity, and must never be the migration path. The fresh
 * `issuanceDate` ranks the re-issued credential ahead of the legacy one, so
 * subsequent connects match it directly.
 *
 * Does NOT store the result; the caller stores it through the mint door
 * (it satisfies {@link assertMintedAppKey}) and may retire the legacy record.
 *
 * @param options {object}
 * @param options.credential {IVerifiableCredential} - The legacy credential;
 *   it must bind per {@link appKeySeedBindsSubject} and be bound to `origin`,
 *   else this throws {@link AppKeyMintInvariantError}.
 * @param options.app {IAppConnectApp} - The validated app identity; its
 *   `appUrl` must already be in serialized form.
 * @param options.origin {string} - The attested requesting origin.
 * @returns {Promise<{ credential: IVerifiableCredential; subjectDid: string }>}
 */
export async function reissueAppKeyCredential({
  credential,
  app,
  origin
}: {
  credential: IVerifiableCredential
  app: IAppConnectApp
  origin: string
}): Promise<{ credential: IVerifiableCredential; subjectDid: string }> {
  if (
    !(await appKeySeedBindsSubject(credential)) ||
    appKeyOrigin(credential) !== origin
  ) {
    throw new AppKeyMintInvariantError()
  }
  const seedBytes = appKeySeedBytes(credential)
  if (!seedBytes) {
    throw new AppKeyMintInvariantError()
  }
  const legacyDescription = (credential as { description?: unknown })
    .description
  return issueAppKeyCredential({
    seedBytes,
    appName: app.name,
    appUrl: app.appUrl,
    origin,
    description:
      typeof legacyDescription === 'string'
        ? legacyDescription
        : `The ${app.name} app keeps this key in your wallet so it can ` +
          'open your encrypted data on this and other devices.'
  })
}

/**
 * The subject DID (`credentialSubject.id`) of an app-key credential, or
 * undefined. For a valid app-key credential this equals the issuer.
 *
 * @param credential {IVerifiableCredential}
 * @returns {string | undefined}
 */
export function appKeySubjectDid(
  credential: IVerifiableCredential
): string | undefined {
  return subjectId(credential)
}

/**
 * The 32-byte seed an app-key credential carries
 * (`credentialSubject.seed`, base64url-no-pad), or undefined when it is absent
 * or malformed. This is the app's client secret, the root of its identity and
 * of the keys it encrypts its own data with. The wallet reads it only to
 * re-derive the credential's subject DID ({@link appKeySeedBindsSubject}) and
 * to re-issue a legacy credential under the same identity; nothing downstream
 * of the match takes the seed, so it never reaches the grant path.
 *
 * @param credential {IVerifiableCredential}
 * @returns {Uint8Array | undefined}
 */
function appKeySeedBytes(
  credential: IVerifiableCredential
): Uint8Array | undefined {
  const subject = credential.credentialSubject as { seed?: unknown } | undefined
  if (!subject || typeof subject.seed !== 'string') {
    return undefined
  }
  try {
    return base64urlnopad.decode(subject.seed)
  } catch {
    return undefined
  }
}

/**
 * The origin (`credentialSubject.origin`) an app-key credential is bound to,
 * when present.
 *
 * @param credential {IVerifiableCredential}
 * @returns {string | undefined}
 */
export function appKeyOrigin(
  credential: IVerifiableCredential
): string | undefined {
  const subject = credential.credentialSubject as
    { origin?: unknown } | undefined
  return subject && typeof subject.origin === 'string'
    ? subject.origin
    : undefined
}

/**
 * The application URL (`credentialSubject.appUrl`) an app-key credential is
 * scoped to, when present. Absent on a legacy (pre-`appUrl`) credential.
 *
 * @param credential {IVerifiableCredential}
 * @returns {string | undefined}
 */
export function appKeyAppUrl(
  credential: IVerifiableCredential
): string | undefined {
  const subject = credential.credentialSubject as
    { appUrl?: unknown } | undefined
  return subject && typeof subject.appUrl === 'string'
    ? subject.appUrl
    : undefined
}
