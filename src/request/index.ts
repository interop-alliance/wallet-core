/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/request` subpath: wallet-request / exchange-protocol
 * handling shared by the Interop wallet apps (DCW and Freewallet).
 *
 * - `types` re-exports the VPR message vocabulary from
 *   `@interop/data-integrity-core` and declares the request-local types (CHAPI
 *   events, the classified-request profile, and the `PresentationSigner` /
 *   `FetchLike` / `RequestProcessors` injection seams).
 * - `parse` / `classify` turn a raw URL, JSON string, or CHAPI event into a
 *   typed message and dispatch on what it asks for.
 * - `matching` filters stored credentials against a QueryByExample (both the
 *   jsonpath deep matcher and the type/issuer matcher).
 * - `presentationSuite` negotiates the response cryptosuite; `composeVp` builds
 *   the (optionally signed, optionally grant-embedding) response VP.
 * - `exchangeClient` is the fetch-injectable VC-API exchange client;
 *   `interactionUrl` resolves VCALM `interaction:` URLs.
 * - `processRequest` is the pure request-to-response pipeline, with the
 *   app-side side effects injected.
 *
 * The signing / document-loader dependency graph lives entirely behind this
 * subpath; `@interop/wallet-core`'s plaintext consumers never pull it in.
 */
export * from './types.js'
export * from './parse.js'
export * from './classify.js'
export * from './matching.js'
export * from './presentationSuite.js'
export * from './composeVp.js'
export * from './exchangeClient.js'
export * from './interactionUrl.js'
export * from './processRequest.js'
