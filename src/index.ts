/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * `@interop/wallet-core` -- shared wallet-domain logic for Interop wallet apps.
 * The two subpaths are canonical and can be imported directly:
 *
 * - `@interop/wallet-core/sync` -- the WAS replication engine core.
 * - `@interop/wallet-core/space` -- the wallet Space layout contract.
 *
 * This root re-exports both for convenience.
 */
export * from './sync/index.js'
export * from './space/index.js'
