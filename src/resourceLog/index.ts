/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/resourceLog` entry: the client side of the
 * Resource Log Profile (App Connect spec `#resource-log-profile`) -- full
 * chain verification against an adversarial host (parse shape, SCID and
 * entry-hash recomputation, entry proofs, the external-authorization rule
 * against the independently verified did:webvh controller document, terminal
 * entries), the chain-head pin with its continuity rules, the append path
 * (verified-head build, CAS with rebase-and-retry, read-back confirmation),
 * and the sealing sweep (the idempotent backstop append that re-anchors a
 * log's head past the controller's latest membership change).
 * Transport (JSON Lines, the store seam, the projection write) lives in
 * `@interop/was-client/log`; the hashing and proof kernel in
 * `@interop/did-method-webvh`. Kept out of the root export: this subpath
 * pulls the did:webvh and ed25519 dependency graph.
 */
export {
  webvhResourceLogController,
  type ResourceLogController
} from './controller.js'
export {
  ResourceLogClosedError,
  ResourceLogContinuityError,
  ResourceLogIntegrityError
} from './errors.js'
export {
  buildResourceLogEntry,
  buildResourceLogGenesis,
  type ResourceLogSigner
} from './entry.js'
export {
  memoryResourceLogPinStore,
  resourceLogPinId,
  type ResourceLogHeadPin,
  type ResourceLogPinStore
} from './pin.js'
export {
  isTerminalResourceLogEntry,
  verifyResourceLog,
  verifyResourceLogHandover,
  type VerifiedResourceLog
} from './verify.js'
export {
  appendResourceLog,
  createResourceLog,
  readResourceLog
} from './append.js'
export { latestAssertionRemovalIndex, sealResourceLog } from './seal.js'
export { vmFragmentOf } from './vmFragment.js'
