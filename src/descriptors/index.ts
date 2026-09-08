/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/descriptors` subpath: the log-governed descriptor
 * source, the wallet's implementation of `@interop/was-client/edv`'s
 * `EncryptionDescriptorSource` seam for collections whose encryption
 * descriptor is governed by a resource log. The acquisition, cache-fallback,
 * and unknown-epoch refresh policy that source plugs into (`acquireDescriptor`,
 * `DescriptorRefreshPolicy`, `createRefreshingEdvDocCipher`, and the
 * `isKeyUnwrapError` matcher) ship from `@interop/was-client/edv`, and this
 * subpath re-exports none of them: one owner per name.
 *
 * - `logGovernedDescriptorSource` -- every read (including the unknown-epoch
 *   refresh) re-verifies the log and resolves to its verified head state,
 *   refusing a head that is not a `WasEpochConfiguration`. Reads run under the
 *   collection-descriptor log class, so a ladder-signed append admits on
 *   `assertionMethod` membership alone. It keys each collection's chain-head
 *   pin by `collectionDescriptorLogPinId` over the Space id, the library-named
 *   slot (`space/<spaceId>/<collectionId>/meta/log`, the log's own home), so no
 *   app builds one. It is the one governed-descriptor reader this subpath
 *   publishes: the bare-controller read under it
 *   (`readGovernedEpochConfiguration`, was-client's) states no log class and
 *   would read a collection log under the roster's license, so it stays
 *   module-internal.
 */
export {
  collectionDescriptorLogPinId,
  logGovernedDescriptorSource
} from './logSource.js'
