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
 * App Connect query kind is a Freewallet-only extension and stays app-side; the
 * shared classifier covers the three VPR-spec query types.
 */
import type {
  CHAPIStoreEvent,
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
  const contexts = credential['@context']
  const contextArray = Array.isArray(contexts) ? contexts : [contexts]
  const isV2 = contextArray.includes(VC_2_CONTEXT_URL)
  return {
    '@context': [isV2 ? VC_2_CONTEXT_URL : VC_1_CONTEXT_URL],
    type: ['VerifiablePresentation'],
    verifiableCredential: [credential]
  } as IVerifiablePresentation
}

/**
 * The offered payload as a Verifiable Presentation: passed through when the
 * issuer already offered one, and wrapped when it offered a bare Verifiable
 * Credential.
 *
 * @param credential {CHAPIStoreEvent['credential']}
 * @returns {IVerifiablePresentation}
 */
function offeredPresentation({
  dataType,
  data
}: CHAPIStoreEvent['credential']): IVerifiablePresentation {
  const types = typeArray((data as { type?: unknown })?.type)
  const isPresentation =
    dataType === 'VerifiablePresentation' ||
    types.includes('VerifiablePresentation') ||
    'verifiableCredential' in (data ?? {})
  if (isPresentation) {
    return data as IVerifiablePresentation
  }
  if (
    dataType === 'VerifiableCredential' ||
    types.includes('VerifiableCredential')
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
  const didAuthRequests = queries.filter(q => q.type === 'DIDAuthentication')
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
  return queries
    .filter(
      (query): query is IZcapQuery =>
        query.type === 'AuthorizationCapabilityQuery' ||
        query.type === 'ZcapQuery'
    )
    .flatMap(({ type, capabilityQuery }) => {
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
 * Classifies a VPR body onto the independent axes the consent screen and
 * response assembly work from: whether DID Authentication is requested, and
 * separately the credential (`QueryByExample`) and capability
 * (`AuthorizationCapabilityQuery` / `ZcapQuery`) content asked for. Any
 * combination is valid, including zcap-only.
 *
 * @param request {IVPRDetails}
 * @returns {WalletRequestProfile}
 */
export function classifyRequest(request: IVPRDetails): WalletRequestProfile {
  const queries = queriesOf(request)
  return {
    didAuth: isDIDAuthRequested({ queries }),
    vcQueries: queries.filter(
      (query): query is IQueryByExample => query.type === 'QueryByExample'
    ),
    zcapRequests: zcapQueriesOf(queries)
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
 * that lists `key` among `acceptedMethods` or omits the constraint entirely.
 *
 * @param queries {IVPRQuery[]}
 * @returns {boolean}
 */
export function didAuthMethodSupported(queries: IVPRQuery[]): boolean {
  const didAuth = queries.find(query => query.type === 'DIDAuthentication') as
    IDIDAuthenticationQuery | undefined
  const acceptedMethods = didAuth?.acceptedMethods
  if (!acceptedMethods || acceptedMethods.length === 0) {
    return true
  }
  return acceptedMethods.some(({ method }) => method === 'key')
}
