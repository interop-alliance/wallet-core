/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Framework-agnostic request processing: turns a classified VPR body plus the
 * user's VC selection into a {@link WalletResponse} (a possibly-signed VP, plus
 * any delegated zcaps). The response channel (CHAPI `respondWith`, an
 * exchange-URL POST) stays with the caller -- this function only returns data,
 * and assumes the user has already consented and picked which credentials to
 * send.
 *
 * Ported from Freewallet's `src/lib/walletRequest/processRequest.ts` (the pure
 * shape). The two app-specific side effects -- capability delegation and the App
 * Connect branch -- are injected as {@link RequestProcessors} rather than
 * imported, so this layer carries no session / grant-resolution machinery. The
 * signer and holder DID are injected as a {@link PresentationSigner}.
 */
import { classifyRequest, queriesOf } from './classify.js'
import { composeVp } from './composeVp.js'
import { negotiateCryptosuite } from './presentationSuite.js'
import type {
  IVerifiableCredential,
  IVPRDetails,
  IZcap,
  PresentationSigner,
  RequestProcessors,
  WalletResponse
} from './types.js'

/**
 * Extracts the host (`host:port`) from a value that may be a full URL or a bare
 * host / host:port. Returns undefined if it cannot be parsed.
 */
function hostOf(value: string): string | undefined {
  try {
    const url = value.includes('://')
      ? new URL(value)
      : new URL(`https://${value}`)
    return url.host
  } catch (err) {
    console.warn(`Could not parse host from "${value}":`, err)
    return undefined
  }
}

/**
 * Domain-binding check (VCALM §3.4.3 advisement): a DID-Auth `domain` MUST match
 * the channel the request arrived on, otherwise a dishonest verifier could relay
 * the challenge from another origin and replay the response.
 *
 * @param options {object}
 * @param options.domain {string} - The `domain` from the request.
 * @param [options.origin] {string} - The channel origin (for CHAPI,
 *   `event.credentialRequestOrigin`).
 * @returns {boolean}
 */
export function domainMatchesOrigin({
  domain,
  origin
}: {
  domain: string
  origin?: string
}): boolean {
  if (!origin) {
    return false
  }
  const originHost = hostOf(origin)
  const domainHost = hostOf(domain)
  return !!originHost && originHost === domainHost
}

/**
 * Processes a Verifiable Presentation Request and composes the wallet's
 * response. Assumes the user has already consented and (for VC sharing) picked
 * which credentials to send.
 *
 * @param options {object}
 * @param options.request {IVPRDetails} - The VPR body.
 * @param options.presentationSigner {PresentationSigner} - Authentication signer
 *   and holder DID.
 * @param [options.selectedVCs] {IVerifiableCredential[]} - VCs the user chose to
 *   share (empty for a DID-Auth-only or zcap-only response).
 * @param [options.credentialRequestOrigin] {string} - Channel origin, used for
 *   the domain-binding check and required by the App Connect branch.
 * @param [options.processors] {RequestProcessors} - App-side capability /
 *   App Connect processors.
 * @param [options.cryptosuite] {string} - Cryptosuite override; when absent it
 *   is negotiated from the request's `acceptedCryptosuites`.
 * @param [options.vocabBaseIri] {string} - Vocabulary base IRI passed through to
 *   {@link composeVp} for embedded-grant term definitions.
 * @returns {Promise<WalletResponse>} The response VP (and any granted zcaps), or
 *   `{}` when there is nothing to send.
 */
export async function processRequest({
  request,
  presentationSigner,
  selectedVCs = [],
  credentialRequestOrigin,
  processors,
  cryptosuite,
  vocabBaseIri
}: {
  request: IVPRDetails
  presentationSigner: PresentationSigner
  selectedVCs?: IVerifiableCredential[]
  credentialRequestOrigin?: string
  processors?: RequestProcessors
  cryptosuite?: string
  vocabBaseIri?: string
}): Promise<WalletResponse> {
  const { didAuth, zcapRequests } = classifyRequest(request)
  const queries = queriesOf(request)
  const { challenge, domain } = request
  // Honor any cryptosuite the verifier asks for (VCALM `acceptedCryptosuites`),
  // unless the caller pinned one.
  const negotiatedCryptosuite = cryptosuite ?? negotiateCryptosuite(queries)

  // Security: never sign an authentication proof bound to a domain the request
  // did not actually arrive from. Enforced whenever a `domain` is present,
  // including a zcap-only request whose (unsigned) VP still names an origin.
  if (
    domain &&
    !domainMatchesOrigin({ domain, origin: credentialRequestOrigin })
  ) {
    throw new Error(
      `DID Auth domain "${domain}" does not match request origin ` +
        `"${credentialRequestOrigin}".`
    )
  }

  // An App Connect request (a Freewallet-only query kind) takes its own
  // single-round branch, handled entirely by the injected processor. The
  // requesting origin is what the app key is bound to, so it is required.
  // `AppConnectQuery` is a Freewallet-side extension to the VPR query union, so
  // it is matched by its `type` string rather than a union member here.
  const appConnectRequested = queries.some(
    q => (q.type as string) === 'AppConnectQuery'
  )
  if (appConnectRequested) {
    if (!processors?.processAppConnect) {
      throw new Error(
        'An App Connect request was received but no processAppConnect ' +
          'processor was provided.'
      )
    }
    if (!credentialRequestOrigin) {
      throw new Error('An App Connect request requires a requesting origin.')
    }
    return processors.processAppConnect({
      request,
      origin: credentialRequestOrigin,
      challenge,
      domain,
      didAuthRequested: didAuth,
      cryptosuite: negotiatedCryptosuite
    })
  }

  // Delegate the approved capabilities first, then embed them in the VP.
  const zcaps: IZcap[] =
    zcapRequests.length > 0 && processors?.processZcaps
      ? await processors.processZcaps({ zcapRequests })
      : []

  if (!didAuth && selectedVCs.length === 0 && zcaps.length === 0) {
    // Nothing to send: no DID Auth, no VCs, and no satisfiable grants.
    return {}
  }

  const verifiablePresentation = await composeVp({
    presentationSigner,
    selectedVcs: selectedVCs,
    challenge,
    domain,
    didAuthRequested: didAuth,
    cryptosuite: negotiatedCryptosuite,
    zcaps,
    ...(vocabBaseIri !== undefined && { vocabBaseIri })
  })
  // Return the delegated capabilities alongside the VP so the caller can log
  // exactly what was granted from these objects, rather than reading them back
  // off the composed VP.
  return { verifiablePresentation, zcaps }
}
