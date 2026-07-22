/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * `@interop/wallet-core` -- shared wallet-domain logic for Interop wallet apps.
 * The subpaths are canonical and can be imported directly:
 *
 * - `@interop/wallet-core/sync` -- the WAS replication engine core.
 * - `@interop/wallet-core/space` -- the wallet Space layout contract.
 * - `@interop/wallet-core/request` -- wallet-request / exchange protocol
 *   handling (classification and parsing, QueryByExample matching, cryptosuite
 *   negotiation, VP composition, the VC-API exchange client, and VCALM
 *   `interaction:` URL handling).
 * - `@interop/wallet-core/display` -- pure VC derivation / display helpers and
 *   credential input parsing (raw values out; formatting stays in the UI).
 *
 * This root re-exports `sync` and `space` for convenience. `request` and
 * `display` are deliberately NOT re-exported here, so plaintext consumers of
 * the root never pull the signing / document-loader dependency graph (the
 * was-client subpath-isolation pattern).
 */
export * from './sync/index.js'
export * from './space/index.js'
