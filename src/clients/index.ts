/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/clients` subpath: the enrolled-client management
 * surface -- the place "disconnect this wallet" lives -- and the cascades
 * behind it.
 *
 * - `listAccountClients` / `currentAccountSigningKeys` /
 *   `currentAccountRecordSigners` -- the listing over the locally verified
 *   did:webvh log, with display labels merged; the same read reduced to the
 *   key set an app grant's delegation signer is checked against; and that
 *   set widened by the document's ladder VMs, the allowlist a re-minted
 *   unlock or recovery record's proof is settled against. All take an
 *   already-verified log in place of fetching one.
 * - `disconnectEligibility` / `revokedClientKeysFor` / `cascadeCompletion` --
 *   the disconnect-eligibility policy as data and pure functions, so both
 *   surfaces refuse the same rows for the same reasons and report a partial
 *   fan-out as the resumable success it is.
 * - `revokeAccountClient` -- the revocation cascade in dependency order
 *   (document edit, roster rotation with its seal backstop, collection
 *   fan-out, optional recovery re-mints), with the app-specific stages
 *   injected.
 * - `checkUserKeyRosterAtLogin` / `convergeUserKeyRosterToAccount` -- the
 *   login-time
 *   roster policy: which roster failures refuse a session, and the standing
 *   convergence of the roster onto the account document (recipients, then
 *   the roster log's seal).
 */
export {
  currentAccountRecordSigners,
  currentAccountSigningKeys,
  listAccountClients
} from './listing.js'
export type {
  AccountClientView,
  AccountLogPointer,
  VerifiedAccountLog
} from './listing.js'

export {
  cascadeCompletion,
  disconnectEligibility,
  revokedClientKeysFor
} from './policy.js'
export type { DisconnectRefusal } from './policy.js'

export { revokeAccountClient } from './revocation.js'
export type {
  CascadeCollections,
  ClientRevocationResult,
  GenerationDelegationRemint,
  RosterSealReport
} from './revocation.js'

export {
  checkUserKeyRosterAtLogin,
  convergeUserKeyRosterToAccount
} from './rosterPolicy.js'
export type { AdoptedUserKey } from './rosterPolicy.js'
