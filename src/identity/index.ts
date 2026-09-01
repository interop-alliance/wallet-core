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
 * - `agentsFromKeyAgent` -- the same assembly from a CapabilityAgent an app
 *   derived itself, so the Montgomery conversion has one implementation.
 * - `zcapClientForSigner` -- the library's one `ZcapClient` construction, so
 *   every zcap it mints is signed with `eddsa-jcs-2022`.
 * - `singleKeyResolver` -- the one-key `IKeyResolver` factory (also used by
 *   app-side derivations such as a keyring unlock identity).
 *
 * Kept out of the root export: this subpath pulls the webkms-client / ezcap /
 * x25519 dependency graph (the same isolation pattern as `./request`).
 */
export {
  BOOTSTRAP_HANDLE,
  BOOTSTRAP_KEY_NAME,
  agentsFromKeyAgent,
  agentsFromSecret,
  agentsFromSeed,
  zcapClientForSigner
} from './agents.js'
export type { ProfileAgents } from './agents.js'
export { singleKeyResolver } from './keyResolver.js'
