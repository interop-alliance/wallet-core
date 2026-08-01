/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * `@interop/wallet-core` -- shared wallet-domain logic for Interop wallet apps.
 * The subpaths are canonical and can be imported directly:
 *
 * - `@interop/wallet-core/sync` -- the WAS replication engine core.
 * - `@interop/wallet-core/space` -- the wallet Space layout contract.
 * - `@interop/wallet-core/identity` -- the WAS identity derivation
 *   (`agentsFromSecret` / `agentsFromSeed`, `singleKeyResolver`) both wallet
 *   apps must perform byte-for-byte identically.
 * - `@interop/wallet-core/request` -- wallet-request / exchange protocol
 *   handling (classification and parsing, QueryByExample matching, cryptosuite
 *   negotiation, VP composition, the VC-API exchange client, and VCALM
 *   `interaction:` URL handling).
 * - `@interop/wallet-core/display` -- pure VC derivation / display helpers and
 *   credential input parsing (raw values out; formatting stays in the UI).
 * - `@interop/wallet-core/webvh` -- the account's did:webvh identity: the
 *   hosted DID log, its per-client update-key rotation, the client enrollment
 *   entries, and ZCap signing under the did:webvh verification-method id.
 * - `@interop/wallet-core/keys` -- the per-user key (PUK) and its
 *   `key-map/puk.json` wrap-set roster.
 * - `@interop/wallet-core/keyring` -- the unlock layer: the unlock derivation,
 *   the account-pointer record codec, and the unlock Space.
 * - `@interop/wallet-core/enrollment` -- the client enrollment ceremony
 *   (connect code, approval, completion).
 *
 * This root re-exports `sync` and `space` for convenience. `identity`,
 * `request`, `display`, `webvh`, `keys`, `keyring`, and `enrollment` are
 * deliberately NOT re-exported here, so plaintext consumers of the root never
 * pull the signing / KMS / document-loader dependency graph (the was-client
 * subpath-isolation pattern).
 */
export * from './sync/index.js'
export * from './space/index.js'
