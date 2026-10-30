/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/descriptors` subpath: the log-governed descriptor
 * source, the wallet's implementation of `@interop/pws-client/edv`'s
 * `EncryptionDescriptorSource` seam for collections whose encryption
 * descriptor is governed by a resource log. The acquisition, cache-fallback,
 * and unknown-epoch refresh policy that source plugs into (`acquireDescriptor`,
 * `DescriptorRefreshPolicy`, `createRefreshingEdvDocCipher`, and the
 * `isKeyUnwrapError` matcher) ship from `@interop/pws-client/edv`, and this
 * subpath re-exports none of them: one owner per name.
 *
 * - `logGovernedDescriptorSource` -- every read (including the unknown-epoch
 *   refresh) resolves to the log's verified head state, refusing a head that
 *   is not a `WasEpochConfiguration`; a repeat read of a collection verifies
 *   only the entries added since the source last verified it. Reads run under
 *   the collection-descriptor log class, so a ladder-signed append admits on
 *   `assertionMethod` membership alone. It keys each collection's chain-head
 *   pin by `collectionDescriptorLogPinId` over the Space URL, the library-named
 *   slot, so no app builds one. It is the one governed-descriptor reader this
 *   subpath publishes: the bare-controller read under it
 *   (`readGovernedEpochConfiguration`, pws-client's) states no log class and
 *   would read a collection log under the roster's license, so it stays
 *   module-internal.
 *
 * A consumer passes `requireGoverned: true` to pws-client's acquisition
 * functions with this source for every `edv` collection it expects to be
 * governed. The source declares `verifiesHistory: true`, so the option admits
 * it, and refuses a plain source before any fetch.
 */
export {
  collectionDescriptorLogPinId,
  logGovernedDescriptorSource
} from './logSource.js'
