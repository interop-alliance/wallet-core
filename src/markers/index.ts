/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/markers` subpath: collection-encryption marker
 * acquisition and the unknown-epoch refresh policy -- the one implementation
 * of "which key epoch does this collection encrypt under, and when do we ask
 * again" that every wallet replica must share (a drift here does not fail
 * loudly; it fails as a resource one replica cannot decrypt).
 *
 * - `MarkerSource` / `MarkerCache` -- the narrow seams a host implements:
 *   one signed Collection Description read, and a durable get/put pre-scoped
 *   to one account's Space.
 * - `wasMarkerSource` -- the `MarkerSource` over a was-client handle.
 * - `acquireMarker` / `acquireMarkers` -- fetch + cache with the cached
 *   fallback (offline, a previously-shared collection keeps encrypting under
 *   its current epoch; no marker at all is the single-key path).
 * - `MarkerRefreshPolicy` -- the once-per-collection-per-session unknown-epoch
 *   refresh guard, plus the refresh-and-re-read-once wrapper for hosts whose
 *   reads scan rows and count unknown-epoch skips.
 * - `createRefreshingEdvDocCipher` -- `createEdvDocCipher` bound to both: a
 *   cipher that acquires its own marker and, on an unknown-epoch decrypt,
 *   re-reads the description, swaps itself, and retries exactly once per
 *   instance.
 */
export { acquireMarker, acquireMarkers, wasMarkerSource } from './acquire.js'
export type { MarkerCache, MarkerSource } from './acquire.js'

export { MarkerRefreshPolicy } from './refresh.js'

export { createRefreshingEdvDocCipher } from './cipher.js'
