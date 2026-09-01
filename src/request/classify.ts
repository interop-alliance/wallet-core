/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Classification of incoming VC API messages: turns a raw CHAPI event (or a QR
 * / pasted payload) into a typed `IVPRequest` / `IVPOffer`, and provides the
 * helpers used to dispatch on what was actually asked for (VC sharing, DID
 * Authentication, capability delegation, or a combination).
 *
 * Ported from Freewallet's `src/lib/walletRequest/classify.ts` (the superset of
 * DCW's `app/lib/exchanges.ts` / `walletRequestApi.ts` dispatch helpers). The
 * shared classifier covers the three VPR-spec query types plus the App Connect
 * `AppConnectQuery` extension (`appConnectRequestOf`), whose `app` block is
 * validated here against the attested requesting origin.
 */
import type {
  CHAPIStoreEvent,
  IAppConnectCapabilityQuery,
  IAppConnectQuery,
  IAppConnectRequest,
  ICapabilityQueryDetail,
  ICredentialQuery,
  IDIDAuthenticationQuery,
  IQueryByExample,
  IVPOffer,
  IVPRequest,
  IVPRDetails,
  IVPRQuery,
  IVerifiableCredential,
  IVerifiablePresentation,
  IZcapQuery,
  WalletRequestProfile
} from './types.js'
import type { CHAPIGetEvent } from './types.js'
import { typeArray } from '@interop/data-integrity-core/guards'

const VC_1_CONTEXT_URL = 'https://www.w3.org/2018/credentials/v1'
const VC_2_CONTEXT_URL = 'https://www.w3.org/ns/credentials/v2'

/**
 * Narrows an untrusted value to a string-keyed record, or `undefined` when it
 * is not an object.
 *
 * @param value {unknown}
 * @returns {Record<string, unknown> | undefined}
 */
function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object') {
    return undefined
  }
  return value as Record<string, unknown>
}

/**
 * The VC data model version a presentation carrying the given credentials must
 * use, so its `@context` stays coherent with what it carries: `2.0` when any
 * credential is a VC 2.0 one, else `1.0`. Shared by the bare-credential
 * wrapping below and by the unsigned branch of `composeVp` (the signed branch
 * takes its version from the negotiated cryptosuite instead).
 *
 * @param credentials {IVerifiableCredential[]}
 * @returns {number}
 */
export function presentationVersionFor(
  credentials: IVerifiableCredential[]
): number {
  const isV2 = credentials.some(credential => {
    const contexts = credential?.['@context']
    const contextArray = Array.isArray(contexts) ? contexts : [contexts]
    return contextArray.includes(VC_2_CONTEXT_URL)
  })
  return isV2 ? 2.0 : 1.0
}

/**
 * Wraps a bare Verifiable Credential in an unsigned Verifiable Presentation,
 * matching the credential's VC data model version so the presentation's
 * `@context` stays coherent with the credential it carries.
 *
 * @param credential {IVerifiableCredential}
 * @returns {IVerifiablePresentation}
 */
function presentationWrapping(
  credential: IVerifiableCredential
): IVerifiablePresentation {
  const isV2 = presentationVersionFor([credential]) === 2.0
  return {
    '@context': [isV2 ? VC_2_CONTEXT_URL : VC_1_CONTEXT_URL],
    type: ['VerifiablePresentation'],
    verifiableCredential: [credential]
  } as IVerifiablePresentation
}

/**
 * The offered payload as a Verifiable Presentation: passed through when the
 * issuer already offered one, and wrapped when it offered a bare Verifiable
 * Credential. A `data` payload that is not an object at all is unrecognized,
 * and reported with the same descriptive error as an unrecognized object.
 *
 * @param credential {CHAPIStoreEvent['credential']}
 * @returns {IVerifiablePresentation}
 */
function offeredPresentation({
  dataType,
  data
}: CHAPIStoreEvent['credential']): IVerifiablePresentation {
  const payload = asRecord(data)
  const types = typeArray(payload?.type)
  const isPresentation =
    !!payload &&
    (dataType === 'VerifiablePresentation' ||
      types.includes('VerifiablePresentation') ||
      'verifiableCredential' in payload)
  if (isPresentation) {
    return data as IVerifiablePresentation
  }
  if (
    payload &&
    (dataType === 'VerifiableCredential' ||
      types.includes('VerifiableCredential'))
  ) {
    return presentationWrapping(data as IVerifiableCredential)
  }
  throw new Error(
    `CHAPI store event offered an unrecognized payload (dataType: ${
      dataType ?? 'undefined'
    }, type: ${JSON.stringify(types)}).`
  )
}

/**
 * The Verifiable Credentials carried by a presentation, normalized to an array.
 *
 * @param presentation {IVerifiablePresentation}
 * @returns {IVerifiableCredential[]}
 */
export function credentialsOf(
  presentation: IVerifiablePresentation
): IVerifiableCredential[] {
  const { verifiableCredential } = presentation
  if (!verifiableCredential) {
    return []
  }
  return Array.isArray(verifiableCredential)
    ? verifiableCredential
    : [verifiableCredential]
}

/**
 * Wraps a CHAPI get event as an `IVPRequest`.
 *
 * @param event {CHAPIGetEvent}
 * @returns {IVPRequest}
 */
export function classifyCHAPIGetEvent(event: CHAPIGetEvent): IVPRequest {
  const verifiablePresentationRequest =
    event.credentialRequestOptions?.web?.VerifiablePresentation
  if (!verifiablePresentationRequest) {
    throw new Error(
      'CHAPI get event is missing a VerifiablePresentation request.'
    )
  }
  return {
    verifiablePresentationRequest,
    credentialRequestOrigin: event.credentialRequestOrigin
  }
}

/**
 * Wraps a CHAPI store event as an `IVPOffer`. A bare offered credential is
 * wrapped in an unsigned presentation, so downstream code always sees a VP.
 *
 * @param event {CHAPIStoreEvent}
 * @returns {IVPOffer}
 */
export function classifyCHAPIStoreEvent(event: CHAPIStoreEvent): IVPOffer {
  return {
    verifiablePresentation: offeredPresentation(event.credential),
    credentialRequestOrigin: event.credentialRequestOrigin
  }
}

/**
 * Returns true if the query set contains a `DIDAuthentication` query. Throws if
 * more than one is present -- a single DID-Auth proof answers the request.
 *
 * @param options {object}
 * @param options.queries {IVPRQuery[]}
 * @returns {boolean}
 */
export function isDIDAuthRequested({
  queries
}: {
  queries: IVPRQuery[]
}): boolean {
  const didAuthRequests = queries.filter(
    query => query.type === 'DIDAuthentication'
  )
  if (didAuthRequests.length > 1) {
    throw new Error('More than one DIDAuthentication request found, exiting.')
  }
  return didAuthRequests.length === 1
}

/**
 * Normalizes a VPR's `query` (which may be a single object or an array) to an
 * array, dropping anything that is not a typed query object. A VPR body can
 * legitimately carry no queries at all -- a CHAPI request that names a
 * `protocols` exchange sends an empty body -- so callers get an empty array
 * rather than an array holding `undefined`.
 *
 * @param request {IVPRDetails}
 * @returns {IVPRQuery[]}
 */
export function queriesOf(request: IVPRDetails): IVPRQuery[] {
  const { query } = request
  const queries = Array.isArray(query) ? query : [query]
  return queries.filter(
    (entry): entry is IVPRQuery =>
      !!entry &&
      typeof entry === 'object' &&
      typeof (entry as { type?: unknown }).type === 'string'
  )
}

/**
 * Normalizes a `QueryByExample`'s `credentialQuery` (a single detail object or
 * an array of them) to an array.
 *
 * @param query {IQueryByExample}
 * @returns {ICredentialQuery[]}
 */
export function credentialQueriesOf(
  query: IQueryByExample
): ICredentialQuery[] {
  const { credentialQuery } = query
  if (!credentialQuery) {
    return []
  }
  return Array.isArray(credentialQuery) ? credentialQuery : [credentialQuery]
}

/**
 * Whether a query is a standalone capability query, under either type string:
 * `AuthorizationCapabilityQuery` (the canonical VCALM spelling) or the legacy
 * `ZcapQuery`.
 *
 * The one reader of that alias pair. Both exclusivity checks and both
 * capability extractors ask through here, so retiring or extending the pair
 * is one edit rather than four.
 *
 * @param query {IVPRQuery}
 * @returns {boolean}
 */
export function isZcapQuery(query: IVPRQuery): query is IZcapQuery {
  return (
    query.type === 'AuthorizationCapabilityQuery' || query.type === 'ZcapQuery'
  )
}

/**
 * Collects the requested capabilities from a query set: filters the two zcap
 * query type strings (`AuthorizationCapabilityQuery` canonical, `ZcapQuery`
 * legacy alias), normalizes each `capabilityQuery` (object or array) to an
 * array, and flattens. A zcap query whose `capabilityQuery` is missing or not
 * an object is malformed -- there is nothing to ask consent for -- so it throws
 * rather than letting an `undefined` descriptor reach grant resolution;
 * classification-time callers surface the throw as a malformed-request state.
 *
 * @param queries {IVPRQuery[]}
 * @returns {ICapabilityQueryDetail[]}
 */
export function zcapQueriesOf(queries: IVPRQuery[]): ICapabilityQueryDetail[] {
  return queries.filter(isZcapQuery).flatMap(({ type, capabilityQuery }) => {
    const detailEntries = Array.isArray(capabilityQuery)
      ? capabilityQuery
      : [capabilityQuery]
    for (const detail of detailEntries) {
      if (!detail || typeof detail !== 'object') {
        throw new Error(
          `A "${type}" query is missing its capabilityQuery detail.`
        )
      }
    }
    return detailEntries
  })
}

/**
 * Validates an App Connect `app.appUrl` against the attested requesting origin
 * and returns its serialized form. The value must parse as an absolute URL,
 * must not carry a fragment, and its origin must equal the attested origin;
 * any violation throws (the query is malformed). All storage and comparison
 * downstream uses the returned serialization, so spellings differing only in
 * a default port, percent-encoding case, or dot-segments do not name distinct
 * applications.
 *
 * The fragment check reads the serialized URL rather than `url.hash`: a bare
 * trailing `#` sets an empty (non-null) fragment that `hash` reports as `''`,
 * and a percent-encoded `%23` never appears as `#` in the serialization.
 *
 * @param options {object}
 * @param options.appUrl {string} - The request's `app.appUrl`.
 * @param options.origin {string} - The attested requesting origin.
 * @returns {string} The parsed URL's serialization.
 */
export function serializedAppUrl({
  appUrl,
  origin
}: {
  appUrl: string
  origin: string
}): string {
  let url: URL
  try {
    url = new URL(appUrl)
  } catch (err) {
    throw new Error(
      `An AppConnectQuery "appUrl" must be an absolute URL (got "${appUrl}").`,
      { cause: err }
    )
  }
  if (url.href.includes('#')) {
    throw new Error(
      `An AppConnectQuery "appUrl" must not carry a fragment (got "${appUrl}").`
    )
  }
  let attestedOrigin: string
  try {
    attestedOrigin = new URL(origin).origin
  } catch {
    attestedOrigin = origin
  }
  if (url.origin !== attestedOrigin) {
    throw new Error(
      `An AppConnectQuery "appUrl" must be same-origin with the requesting ` +
        `origin "${origin}" (got "${appUrl}").`
    )
  }
  return url.href
}

/**
 * Extracts the App Connect request from a query set, when one is present. An
 * `AppConnectQuery` is one mental model per popup: the request must not also
 * carry `QueryByExample` or standalone zcap queries, at most one
 * `AppConnectQuery` is allowed, and its `app` block must carry the display
 * `name` and the `appUrl` the wallet needs to match or mint the app-key
 * credential -- with the `appUrl` validated against the attested requesting
 * origin and rewritten to its serialized form ({@link serializedAppUrl}).
 * Violations throw; classification-time callers surface the throw as a
 * malformed-request state. The capability queries are normalized to an array
 * (absent means "no grants requested" -- a connect that only recovers the app
 * key is legal), and each entry is rebuilt from an allowlist of the declared
 * fields (`referenceId`, `allowedAction`, `invocationTarget`): the type-level
 * Omit does not bind an actual request body, so any other wire-level field --
 * a smuggled `reason`, an attacker-chosen `controller`, a future
 * display-bearing addition -- is made unrepresentable here, before the entries
 * reach the profile the consent screen and the delegation path read.
 *
 * @param options {object}
 * @param options.queries {IVPRQuery[]}
 * @param options.origin {string} - The attested requesting origin the
 *   `appUrl` is validated against.
 * @returns {IAppConnectRequest | null}
 */
export function appConnectRequestOf({
  queries,
  origin
}: {
  queries: IVPRQuery[]
  origin: string
}): IAppConnectRequest | null {
  // `AppConnectQuery` extends the spec query union, so it is matched by its
  // `type` string and upcast rather than narrowed via a type predicate.
  const appConnectQueries = queries.filter(
    query => (query.type as string) === 'AppConnectQuery'
  ) as unknown as IAppConnectQuery[]
  if (appConnectQueries.length === 0) {
    return null
  }
  if (appConnectQueries.length > 1) {
    throw new Error('More than one AppConnectQuery found, exiting.')
  }
  const mixed = queries.some(
    query =>
      query.type === 'QueryByExample' ||
      isZcapQuery(query) ||
      (query.type as string) === 'WalletOnboardingQuery'
  )
  if (mixed) {
    throw new Error(
      'An AppConnectQuery cannot be combined with QueryByExample, ' +
        'standalone capability queries, or a WalletOnboardingQuery.'
    )
  }
  const { app, capabilityQuery } = appConnectQueries[0]!
  if (!app || typeof app.name !== 'string' || typeof app.appUrl !== 'string') {
    throw new Error('An AppConnectQuery is missing its app name / appUrl.')
  }
  const appUrl = serializedAppUrl({ appUrl: app.appUrl, origin })
  const rawQueries =
    capabilityQuery === undefined
      ? []
      : Array.isArray(capabilityQuery)
        ? capabilityQuery
        : [capabilityQuery]
  const capabilityQueries: IAppConnectCapabilityQuery[] = rawQueries.map(
    detail => {
      if (!detail || typeof detail !== 'object') {
        throw new Error(
          'An AppConnectQuery carries a malformed capabilityQuery entry.'
        )
      }
      const { referenceId, allowedAction, invocationTarget } = detail
      return {
        ...(referenceId !== undefined && { referenceId }),
        ...(allowedAction !== undefined && { allowedAction }),
        invocationTarget
      }
    }
  )
  return { app: { name: app.name, appUrl }, capabilityQueries }
}

/**
 * The longest self-declared agent name a request may carry, after trimming.
 */
export const AGENT_NAME_MAX_LENGTH = 64

/**
 * Normalizes a self-declared agent name to the form the consent surface and
 * the Login activity carry: trimmed, 1 to {@link AGENT_NAME_MAX_LENGTH}
 * characters, with no control characters (C0 or C1, line breaks included).
 * Any Unicode letter is fine -- names are not ASCII-only -- but a name that
 * could spoof layout or sneak past a one-line render is refused. Both the
 * requester side (`composeCapabilityRequest`) and the wallet side
 * (`requestingAgentOf`) run this, so a name the requester could compose is
 * one the wallet accepts.
 *
 * @param options {object}
 * @param options.name {unknown}   the raw `agent.name` value
 * @returns {string}   the trimmed name
 */
export function normalizeAgentName({ name }: { name: unknown }): string {
  if (typeof name !== 'string') {
    throw new Error('A request\'s "agent.name" must be a string.')
  }
  const trimmed = name.trim()
  if (trimmed.length === 0) {
    throw new Error('A request\'s "agent.name" must not be empty.')
  }
  if (trimmed.length > AGENT_NAME_MAX_LENGTH) {
    throw new Error(
      `A request's "agent.name" must be at most ${AGENT_NAME_MAX_LENGTH} ` +
        `characters (got ${trimmed.length}).`
    )
  }
  if (/\p{Cc}/u.test(trimmed)) {
    throw new Error(
      'A request\'s "agent.name" must not contain control characters.'
    )
  }
  return trimmed
}

/**
 * Reads the requester's self-declared identity off a VPR body, when present:
 * the root `agent` member, whose `name` is validated and trimmed by
 * {@link normalizeAgentName}. An absent member is fine (the wallet shows the
 * grantee key alone); a present one that is not an object or whose name fails
 * the limits is malformed and throws, so classification-time callers surface
 * it as a malformed-request state rather than rendering an unbounded string.
 *
 * @param request {IVPRDetails}
 * @returns {{ name: string } | undefined}
 */
export function requestingAgentOf(
  request: IVPRDetails
): { name: string } | undefined {
  const { agent } = request
  if (agent === undefined) {
    return undefined
  }
  if (!agent || typeof agent !== 'object' || Array.isArray(agent)) {
    throw new Error('A request\'s "agent" member must be an object.')
  }
  return { name: normalizeAgentName({ name: agent.name }) }
}

/**
 * Classifies a VPR body onto the independent axes the consent screen and
 * response assembly work from: whether DID Authentication is requested, and
 * separately the credential (`QueryByExample`) and capability
 * (`AuthorizationCapabilityQuery` / `ZcapQuery`) content asked for, plus the
 * requester's self-declared `agent` name when the body carries one. Any
 * combination is valid, including zcap-only.
 *
 * @param request {IVPRDetails}
 * @returns {WalletRequestProfile}
 */
export function classifyRequest(request: IVPRDetails): WalletRequestProfile {
  const queries = queriesOf(request)
  const agent = requestingAgentOf(request)
  return {
    didAuth: isDIDAuthRequested({ queries }),
    vcQueries: queries.filter(
      (query): query is IQueryByExample => query.type === 'QueryByExample'
    ),
    zcapRequests: zcapQueriesOf(queries),
    ...(agent !== undefined && { agent })
  }
}

/**
 * Whether a classified request is DID-Authentication *only*: it asks the wallet
 * to prove control of its DID and nothing else (no credential queries, no
 * capability requests). Derived from the profile so a popup's restore fast-path
 * and its render both dispatch on the one predicate.
 *
 * @param profile {WalletRequestProfile}
 * @returns {boolean}
 */
export function isDidAuthOnly(profile: WalletRequestProfile): boolean {
  return (
    profile.didAuth &&
    profile.vcQueries.length === 0 &&
    profile.zcapRequests.length === 0
  )
}

/**
 * Returns true if the wallet can satisfy the DID method a `DIDAuthentication`
 * query constrains to. A wallet holding only `did:key` can satisfy a request
 * that lists `key` among `acceptedMethods` or omits the constraint entirely. A
 * malformed `acceptedMethods` (not an array, or holding non-object entries) is
 * read for the entries it does have rather than dereferenced blindly: an
 * `acceptedMethods` that is not a list of constraints at all imposes none.
 *
 * @param queries {IVPRQuery[]}
 * @returns {boolean}
 */
export function didAuthMethodSupported(queries: IVPRQuery[]): boolean {
  const didAuth = queries.find(query => query.type === 'DIDAuthentication') as
    IDIDAuthenticationQuery | undefined
  const acceptedMethods = didAuth?.acceptedMethods
  if (!Array.isArray(acceptedMethods) || acceptedMethods.length === 0) {
    return true
  }
  return acceptedMethods.some(entry => asRecord(entry)?.method === 'key')
}
