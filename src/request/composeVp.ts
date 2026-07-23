/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Composes a Verifiable Presentation to send back to a requester. The VP is
 * signed when DID Authentication was requested (proving control of the holder's
 * DID over the request's `challenge`, and `domain` when the verifier sends
 * one), and unsigned otherwise.
 *
 * Merged from DCW's `app/lib/composeVp.ts` and Freewallet's
 * `src/lib/walletRequest/composeVP.ts`. The signer and holder DID are injected
 * as a {@link PresentationSigner} -- each app resolves them from its own key
 * material -- and the optional zcap / appConnect embedding (grants ride inside
 * the VP, added before signing so a DIDAuth proof covers them) is carried over
 * from Freewallet. The DIDAuth guard follows DCW: `challenge` is required,
 * `domain` is optional (a wallet that needs the stricter "domain always
 * present" invariant enforces it in its own wrapper before calling here).
 */
import * as vc from '@interop/vc'
import { securityLoader } from '@interop/security-document-loader'
import type { IDocumentLoader } from '@interop/data-integrity-core'
import { presentationSuiteFor } from './presentationSuite.js'
import type {
  IVerifiablePresentation,
  IVerifiableCredential,
  IZcap,
  PresentationSigner
} from './types.js'

/**
 * Shared JSON-LD document loader for presentation and credential signing.
 * Exported so single-VC issuance paths reuse the same context resolution the VP
 * compose path uses.
 */
export const documentLoader: IDocumentLoader = securityLoader({
  fetchRemoteContexts: true
}).build()

/**
 * The default JSON-LD vocabulary base IRI for the embedded-grant term
 * definitions. This IRI is canonicalized into the DIDAuth proof, so it must be
 * byte-stable: the default is Freewallet's value, keeping Freewallet's signed
 * output byte-identical after extraction. A wallet that embeds grants under a
 * different vocabulary passes its own `vocabBaseIri`.
 */
const DEFAULT_VOCAB_BASE_IRI = 'urn:freewallet:vocab#'

/**
 * A presentation carrying an embedded `zcap` array (and optional `appConnect`
 * marker). Embedded before signing so a DIDAuth proof covers the grants. Each
 * zcap entry is a self-contained, self-authenticating delegated capability
 * carrying its own `@context`.
 */
type PresentationWithZcaps = IVerifiablePresentation & {
  zcap?: IZcap[]
  appConnect?: { firstRun: boolean }
}

/** Reads a presentation's `@context` as a mutable array of entries. */
function contextEntries(
  presentation: PresentationWithZcaps
): Array<string | object> {
  const base = presentation['@context'] as string | Array<string | object>
  return Array.isArray(base) ? [...base] : [base]
}

/** Writes a presentation's `@context` from an array of entries. */
function setContext(
  presentation: PresentationWithZcaps,
  entries: Array<string | object>
): void {
  ;(presentation as { '@context': unknown })['@context'] = entries
}

/**
 * The bare `zcap` term definition appended to the VP `@context` when grants are
 * embedded. Only the top-level term is defined (mapped to `${vocabBaseIri}zcap`);
 * the zcap sub-contexts are *not* hoisted -- each embedded zcap self-describes
 * via its own `@context`. Defining the term is what lets JSON-LD safe-mode
 * canonicalization include (rather than reject) the grants, so the
 * authentication proof genuinely covers them.
 */
function zcapTermContext(vocabBaseIri: string): object {
  return {
    '@protected': true,
    zcap: { '@id': `${vocabBaseIri}zcap`, '@container': '@set' }
  }
}

/**
 * The `appConnect` term definition appended to the VP `@context` when an App
 * Connect response marker is embedded. The member is a JSON literal
 * (`@type: '@json'`) so its `firstRun` boolean canonicalizes as one opaque
 * value; embedding happens before signing, so the DIDAuth proof covers the
 * marker the same way it covers the grants.
 */
function appConnectTermContext(vocabBaseIri: string): object {
  return {
    '@protected': true,
    appConnect: { '@id': `${vocabBaseIri}appConnect`, '@type': '@json' }
  }
}

/**
 * Embeds the delegated capabilities on the presentation and adds the bare
 * `zcap` term to its `@context`.
 */
function embedZcaps(
  presentation: PresentationWithZcaps,
  zcaps: IZcap[],
  vocabBaseIri: string
): void {
  if (zcaps.length === 0) {
    return
  }
  setContext(presentation, [
    ...contextEntries(presentation),
    zcapTermContext(vocabBaseIri)
  ])
  presentation.zcap = zcaps
}

/**
 * Embeds the App Connect response marker (the wallet-provided `firstRun`
 * signal) on the presentation and adds the `appConnect` term to its `@context`.
 */
function embedAppConnect(
  presentation: PresentationWithZcaps,
  appConnect: { firstRun: boolean } | undefined,
  vocabBaseIri: string
): void {
  if (!appConnect) {
    return
  }
  setContext(presentation, [
    ...contextEntries(presentation),
    appConnectTermContext(vocabBaseIri)
  ])
  presentation.appConnect = appConnect
}

/**
 * Creates a Verifiable Presentation for the requester.
 *
 * @param options {object}
 * @param [options.presentationSigner] {PresentationSigner} - The authentication
 *   signer and the holder DID to name on a signed VP. Required when
 *   `didAuthRequested` is true; an unsigned (or zcap-only) VP needs none.
 * @param [options.selectedVcs] {IVerifiableCredential[]} - VCs the user chose to
 *   share (empty for a DID-Auth-only or zcap-only response).
 * @param [options.challenge] {string} - Required when DID Auth is requested.
 * @param [options.domain] {string} - Signed into the proof when present;
 *   optional per the VPR spec.
 * @param options.didAuthRequested {boolean} - Whether to sign the VP.
 * @param [options.cryptosuite] {string} - Negotiated cryptosuite; falls back to
 *   the wallet default (Ed25519Signature2020) when absent.
 * @param [options.zcaps] {IZcap[]} - Delegated capabilities to embed as the
 *   VP's `zcap` array (before signing, so a DIDAuth proof covers them).
 * @param [options.appConnect] {{ firstRun: boolean }} - App Connect response
 *   marker to embed (before signing, like the grants).
 * @param [options.vocabBaseIri] {string} - Vocabulary base IRI for the embedded
 *   term definitions; defaults to Freewallet's value.
 * @param [options.documentLoader] {IDocumentLoader} - JSON-LD loader; defaults
 *   to the shared security loader.
 * @returns {Promise<IVerifiablePresentation>}
 */
export async function composeVp({
  presentationSigner,
  selectedVcs = [],
  challenge,
  domain,
  didAuthRequested,
  cryptosuite,
  zcaps = [],
  appConnect,
  vocabBaseIri = DEFAULT_VOCAB_BASE_IRI,
  documentLoader: loader = documentLoader
}: {
  presentationSigner?: PresentationSigner
  selectedVcs?: IVerifiableCredential[]
  challenge?: string
  domain?: string
  didAuthRequested: boolean
  cryptosuite?: string
  zcaps?: IZcap[]
  appConnect?: { firstRun: boolean }
  vocabBaseIri?: string
  documentLoader?: IDocumentLoader
}): Promise<IVerifiablePresentation> {
  if (!didAuthRequested && selectedVcs.length === 0 && zcaps.length === 0) {
    throw new Error(
      'A VP requires credentials, capabilities, or a DID Auth request.'
    )
  }
  if (didAuthRequested && !challenge) {
    throw new Error('A "challenge" is required for DID Auth.')
  }

  if (!didAuthRequested) {
    // Return an unsigned VP. verify: false skips per-VC validation (including
    // expiration checks). A zcap-only response rides here: the grants are
    // individually signed and controller-bound, so they need no VP proof.
    const presentation = vc.createPresentation({
      verifiableCredential: selectedVcs.length > 0 ? selectedVcs : undefined,
      verify: false,
      version: 1.0
    }) as PresentationWithZcaps
    embedZcaps(presentation, zcaps, vocabBaseIri)
    embedAppConnect(presentation, appConnect, vocabBaseIri)
    return presentation
  }

  if (!presentationSigner) {
    throw new Error('A "presentationSigner" is required for DID Auth.')
  }
  const { signer, holder } = presentationSigner

  // Sign with the cryptosuite the verifier requested (via VCALM
  // `acceptedCryptosuites`), falling back to the wallet default. The suite
  // dictates the VC data model version: eddsa-rdfc-2022 proofs require VC 2.0,
  // the default Ed25519Signature2020 proof uses VC 1.0.
  const { suite, version } = presentationSuiteFor({ signer, cryptosuite })

  const presentation = vc.createPresentation({
    holder,
    verifiableCredential: selectedVcs.length > 0 ? selectedVcs : undefined,
    verify: false,
    version
  }) as PresentationWithZcaps

  // Embed the grants (and any App Connect marker) before signing so the
  // authentication proof covers them; the grants additionally self-authenticate
  // via their own delegation proofs and carry their own `@context`.
  embedZcaps(presentation, zcaps, vocabBaseIri)
  embedAppConnect(presentation, appConnect, vocabBaseIri)

  return (await vc.signPresentation({
    presentation,
    challenge,
    ...(domain !== undefined && { domain }),
    documentLoader: loader,
    suite
  })) as IVerifiablePresentation
}

/**
 * @deprecated Use {@link composeVp}. Retained for Freewallet, which imports the
 * `composeVP` spelling.
 */
export const composeVP = composeVp
