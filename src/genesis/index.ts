/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/genesis` subpath: the account-genesis ceremony --
 * minting a brand-new account's key set and provisioning its data Space in
 * the one stage order both wallet apps must encode identically.
 *
 * - `mintAccountKeySet` / `mintSpaceId` -- the local mint of a new account's
 *   complete key set (Space id, client identity seed, user key, did:webvh
 *   update keys), before anything touches the network.
 * - `ensureAccountGenesis` -- the ceremony itself: Space provisioning, the
 *   optional KMS authentication binding (acquired alongside it), did:webvh
 *   genesis, user-key roster
 *   genesis, epoch[0] on every encrypted roster collection, and
 *   Space-controller promotion; idempotent end to end, so a torn run heals
 *   by re-running.
 * - `ensurePromotedSpaceController` -- the promotion stage standing alone,
 *   the state machine a login-time heal drives directly.
 *
 * The ceremony's credential-anchored variant
 * (`ensureCredentialAnchoredAccountGenesis`) lives in
 * `@interop/wallet-core/clientAnnex` with the rest of the annex-anchored
 * ceremonies.
 */
export {
  AccountGenesisSpaceError,
  ensureAccountGenesis,
  ensurePromotedSpaceController,
  mintAccountKeySet,
  mintSpaceId
} from './accountGenesis.js'
export { KMS_AUTHENTICATION_STAGE } from '../stages.js'
export type {
  AccountGenesisResult,
  AccountGenesisStage,
  AccountKeySet,
  SpaceControllerPromotion
} from './accountGenesis.js'
