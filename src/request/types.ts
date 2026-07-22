/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Shared types for the `@interop/wallet-core/request` subpath. The Verifiable
 * Presentation Request (VPR) vocabulary itself is owned by
 * `@interop/data-integrity-core` (its `VPR` module) and re-exported here so a
 * request consumer imports one package; this file adds only the request-local
 * types the app sources carried alongside that vocabulary: the CHAPI event
 * shapes, the VC-API exchange reply shape, the classified-request profile, and
 * the injection-seam types (`PresentationSigner`, `FetchLike`,
 * `RequestProcessors`) that keep this layer free of any single app's session /
 * network / consent machinery.
 *
 * Ported from DCW's `app/lib/walletRequestApi.ts` and Freewallet's
 * `src/lib/walletRequest/{types,classify}.ts`.
 *
 * The VPR vocabulary (and the loose-shape guards in `classify` / `matching`) is
 * imported from the `@interop/data-integrity-core/vpr` and `/guards` subpaths
 * rather than the package root: the vocabulary was added to data-integrity-core
 * without a version bump, so the package root can dedup onto an older cached
 * build that predates it, whereas the subpath entry points resolve only against
 * the current build that defines them.
 */
import type { ISigner } from '@interop/data-integrity-core'
import type {
  IVerifiableCredential,
  IVerifiablePresentation,
  IZcap
} from '@interop/data-integrity-core'
import type {
  ICapabilityQueryDetail,
  IQueryByExample,
  IVPRDetails,
  WalletResponse
} from '@interop/data-integrity-core/vpr'

// Re-export the canonical VPR vocabulary so `@interop/wallet-core/request`
// consumers pull the message types from one package. The deprecated `IVp*`
// spellings ride along for the apps that still import them. The vocabulary is
// pulled from the `/vpr` subpath (see the module note below).
export type {
  IVPRequest,
  IVPOffer,
  IIssueRequest,
  IExchangeInvitation,
  IOid4VCIOffer,
  IVPRDetails,
  IVPRInteract,
  IVPRQuery,
  IQueryByExample,
  ICredentialQuery,
  IAcceptedCryptosuites,
  IDIDAuthenticationQuery,
  IZcapQuery,
  ICapabilityQueryDetail,
  IInvocationTarget,
  IAllowedAction,
  WalletApiMessage,
  WalletResponse,
  IVpRequest,
  IVpOffer,
  IVprDetails,
  IVprQuery,
  IDidAuthenticationQuery
} from '@interop/data-integrity-core/vpr'
export type {
  IVerifiableCredential,
  IVerifiablePresentation,
  IZcap
} from '@interop/data-integrity-core'

/**
 * The protocol handles a verifier offers alongside a CHAPI request. Only
 * `vcapi` (and the newer `interact` meta-protocol) are acted on; `OID4VP` /
 * `OID4VCI` are recognized but unused.
 */
export interface CHAPIProtocols {
  vcapi?: string
  interact?: string
  OID4VP?: string
  OID4VCI?: string
}

/**
 * Raw CHAPI credential-get event. The `VerifiablePresentation` object CHAPI
 * hands us *is* the VPR body (`query` / `challenge` / `domain`); classification
 * rewraps it as an `IVPRequest`. When the verifier names a `protocols` handle
 * it sends that body empty instead, and the VPR must be fetched from the
 * protocol exchange (see `exchangeClient.ts`).
 */
export interface CHAPIGetEvent {
  credentialRequestOrigin: string
  credentialRequestOptions?: {
    web?: {
      VerifiablePresentation?: IVPRDetails
      protocols?: CHAPIProtocols
    }
  }
  respondWith(
    promise: Promise<{ dataType: string; data: unknown } | null>
  ): void
}

/**
 * Raw CHAPI credential-store event. `credential.data` is the offered payload,
 * and `credential.dataType` names its shape: issuers may offer either a
 * `VerifiablePresentation` wrapping the credential(s), or a bare
 * `VerifiableCredential` (what vcplayground.org sends). An issuer that names a
 * `protocols` handle in `credential.options` sends `data` empty instead, and
 * the offered credentials must be fetched from the protocol exchange (see
 * `exchangeClient.ts`).
 */
export interface CHAPIStoreEvent {
  credentialRequestOrigin?: string
  credential: {
    dataType?: string
    data: IVerifiablePresentation | IVerifiableCredential
    options?: {
      protocols?: CHAPIProtocols
      recommendedHandlerOrigins?: string[]
    }
  }
  respondWith(
    promise: Promise<{ dataType: string; data: unknown } | null>
  ): void
}

/**
 * The exchange's reply to either wallet call. A multi-step exchange answers a
 * submitted presentation with another `verifiablePresentationRequest`; a
 * finished one answers with nothing, or with credentials it issued, or with a
 * `redirectUrl` for the user to land on.
 */
export interface VCAPIExchangeResponse {
  verifiablePresentationRequest?: IVPRDetails
  verifiablePresentation?: IVerifiablePresentation
  redirectUrl?: string
}

/**
 * A VP Request classified on independent axes: whether DID Authentication is
 * requested, what credentials are asked for (`vcQueries`), and what capability
 * delegations are asked for (`zcapRequests`). Any combination is valid,
 * including zcap-only. An app that layers additional query kinds on top (e.g.
 * Freewallet's App Connect) extends this shape with its own field.
 */
export interface WalletRequestProfile {
  didAuth: boolean
  vcQueries: IQueryByExample[]
  zcapRequests: ICapabilityQueryDetail[]
}

/**
 * The authentication signer plus the DID to name as the VP `holder`. Each app
 * resolves this from its own key material (DCW from the selected profile's
 * `authentication` signer + DID; Freewallet from the KMS did:web key or the
 * passphrase-derived root key) before handing it to the shared compose path.
 */
export interface PresentationSigner {
  signer: ISigner
  holder: string
}

/**
 * Injected network transport. Defaults to `globalThis.fetch`; DCW passes its
 * `fetchWithTimeout`, Freewallet its CORS-proxy fetch.
 */
export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>

/**
 * App-side processors injected into {@link processRequest}. Both are optional:
 * a wallet that grants no capabilities omits `processZcaps`, and a wallet
 * without an App Connect flow omits `processAppConnect` (the branch is then
 * inert).
 */
export interface RequestProcessors {
  /**
   * Delegates the approved capabilities and returns the minted zcaps.
   * Freewallet supplies `processZcaps(session)`; DCW supplies a no-op / `[]`.
   */
  processZcaps?: (args: {
    zcapRequests: ICapabilityQueryDetail[]
  }) => Promise<IZcap[]>
  /**
   * Handles the App Connect single-round branch (Freewallet only). Invoked when
   * the request carries an `AppConnectQuery`; absent for DCW.
   */
  processAppConnect?: (args: {
    request: IVPRDetails
    origin: string
    challenge?: string
    domain?: string
    didAuthRequested: boolean
    cryptosuite?: string
  }) => Promise<WalletResponse>
}
