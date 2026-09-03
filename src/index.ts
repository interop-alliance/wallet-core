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
 * - `@interop/wallet-core/webvh` -- the account's did:webvh identity: the
 *   hosted DID log, its per-client update-key rotation, the client enrollment
 *   entries, and ZCap signing under the did:webvh verification-method id.
 * - `@interop/wallet-core/keys` -- the user key and its
 *   `key-map/user-key.jsonl` wrap-set roster log.
 * - `@interop/wallet-core/descriptors` -- collection encryption-descriptor
 *   acquisition (fetch / cache / offline fallback) and the unknown-epoch
 *   refresh policy, including a self-refreshing EDV document cipher.
 * - `@interop/wallet-core/keyring` -- the unlock layer: the unlock derivation,
 *   the account-pointer record codec, and the unlock Space.
 * - `@interop/wallet-core/enrollment` -- the client enrollment ceremony
 *   (connect code, approval, completion).
 * - `@interop/wallet-core/recovery` -- recovery codes on the roster identity
 *   model: a code as a minimal always-enrolled wallet client.
 *
 * The root also exports the logging port: `setLogger` and the `Logger`
 * type (`src/log.ts`), the seam an app wires once at bootstrap so this
 * package's internal `console` fallback is replaced with a real logger
 * (the sibling logging package's `createLogger`, for one). Beside it sit
 * the `StageNotifier` type, the observational stage-boundary hook the long
 * ceremonies take, and `stageNotifier`, the adapter that turns an optional
 * one into a notifier every stage can call unconditionally -- an app
 * composing its own per-stage timing wraps that helper rather than
 * re-implementing its swallow.
 *
 * This root re-exports `sync` and `space` for convenience. `identity`,
 * `request`, `webvh`, `keys`, `descriptors`, `keyring`,
 * `enrollment`, and `recovery` are deliberately NOT re-exported here, so
 * plaintext consumers of the root never pull the signing / KMS /
 * document-loader dependency graph (the was-client subpath-isolation pattern).
 */
export * from './sync/index.js'
export * from './space/index.js'
export { setLogger, stageNotifier } from './log.js'
export type { Logger, StageNotifier } from './log.js'
