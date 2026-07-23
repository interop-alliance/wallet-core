/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/identity` subpath: the WAS identity derivation
 * both wallet apps must perform byte-for-byte identically.
 *
 * - `agentsFromSecret` / `agentsFromSeed` -- controller secret or 32-byte seed
 *   to `ProfileAgents` (did:key CapabilityAgent, ZcapClient, X25519 KAK,
 *   single-key resolver) under the fixed bootstrap handle / key name.
 * - `singleKeyResolver` -- the one-key `IKeyResolver` factory (also used by
 *   app-side derivations such as a keyring unlock identity).
 * - `deriveCollectionKeys` -- per-collection vault-key (KAK) derivation:
 *   `HKDF-SHA256(master seed, 'kak:v1:<collectionId>')` to a per-collection
 *   seed, then the Ed25519-to-X25519 key-agreement key plus its resolver.
 *
 * Kept out of the root export: this subpath pulls the webkms-client / ezcap /
 * x25519 dependency graph (the same isolation pattern as `./request`).
 */
export {
  BOOTSTRAP_HANDLE,
  BOOTSTRAP_KEY_NAME,
  agentsFromSecret,
  agentsFromSeed
} from './agents.js'
export type { ProfileAgents } from './agents.js'
export { singleKeyResolver } from './keyResolver.js'
export { deriveCollectionKeys, DEFAULT_KAK_HANDLE } from './collectionKeys.js'
export type { CollectionKeys } from './collectionKeys.js'
