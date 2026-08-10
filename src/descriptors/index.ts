/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/descriptors` subpath: collection
 * encryption-descriptor acquisition and the unknown-epoch refresh policy --
 * the one implementation of "which key epoch does this collection encrypt
 * under, and when do we ask again" that every wallet replica must share (a
 * drift here does not fail loudly; it fails as a resource one replica cannot
 * decrypt).
 *
 * - `EncryptionDescriptorSource` / `EncryptionDescriptorCache` -- the narrow
 *   seams a host implements: one signed Collection Description read, and a
 *   durable get/put pre-scoped to one account's Space.
 * - `wasDescriptorSource` -- the `EncryptionDescriptorSource` over a
 *   was-client handle.
 * - `acquireDescriptor` / `acquireDescriptors` -- fetch + cache with the
 *   cached fallback whenever the fetch yields no descriptor, thrown or empty
 *   (offline, a collection keeps encrypting under its current epoch; an empty
 *   description is ambiguous, since WAS masks an unauthorized read as an
 *   absent one). No descriptor anywhere means a plaintext collection, or an
 *   encrypted one whose epoch[0] install has not landed -- which a caller that
 *   has declared the collection encrypted must refuse fail-closed.
 * - `DescriptorRefreshPolicy` -- the once-per-collection-per-session
 *   unknown-epoch refresh guard, plus the refresh-and-re-read-once wrapper
 *   for hosts whose reads scan rows and count unknown-epoch skips.
 * - `createRefreshingEdvDocCipher` -- `createEdvDocCipher` bound to both: a
 *   cipher that acquires its own descriptor and, on an unknown-epoch decrypt,
 *   re-reads the description, swaps itself, and retries exactly once per
 *   instance.
 */
export {
  acquireDescriptor,
  acquireDescriptors,
  wasDescriptorSource
} from './acquire.js'
export type {
  EncryptionDescriptorCache,
  EncryptionDescriptorSource
} from './acquire.js'

export { DescriptorRefreshPolicy } from './refresh.js'

export { createRefreshingEdvDocCipher } from './cipher.js'
