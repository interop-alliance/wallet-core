/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The portable keyring lookup: an unlock secret to the account it locates.
 * One derivation, one read of the unlock Space's single resource, one unwrap.
 *
 * Deliberately I/O-only over the remote copy, which is the source of truth: an
 * app's local caching, account-pointer pinning, and client-key-record handling
 * wrap around this rather than living inside it, because those are per-app
 * storage concerns with per-app durability rules.
 */
import type { UnlockKdf } from './kdf.js'
import { deriveUnlockIdentity, KEYRING_KDF } from './kdf.js'
import { getUnlockKeyring } from './unlockSpace.js'
import { unwrapKeyringRecord } from './record.js'
import type { KeyringRecordContents } from './record.js'

/**
 * Fetches, verifies, and unwraps the keyring record an unlock secret
 * addresses, or
 * resolves `null` when no record exists there (an unknown secret). The derived
 * unlock Space id is returned alongside the contents -- it is already computed,
 * and callers key their local state on it.
 *
 * @param options {object}
 * @param options.secret {string | Uint8Array}   the unlock secret
 * @param [options.kdf] {UnlockKdf}   the unlock method's parameter set
 * @param options.storageServerUrl {string}   the WAS server origin
 * @returns {Promise<(KeyringRecordContents & { unlockSpaceId: string }) | null>}
 */
export async function fetchKeyringRecord({
  secret,
  kdf = KEYRING_KDF,
  storageServerUrl
}: {
  secret: string | Uint8Array
  kdf?: UnlockKdf
  storageServerUrl: string
}): Promise<(KeyringRecordContents & { unlockSpaceId: string }) | null> {
  const unlock = await deriveUnlockIdentity({ secret, kdf })
  const record = await getUnlockKeyring({
    storageServerUrl,
    zcapClient: unlock.zcapClient,
    spaceId: unlock.spaceId
  })
  if (record === null) {
    return null
  }
  const contents = await unwrapKeyringRecord({
    record,
    keyAgreementKey: unlock.keyAgreementKey,
    keyResolver: unlock.keyResolver,
    // The unlock identity's own signing key: derived from the secret the
    // caller typed, so the record's proof is verified against a prior this
    // client holds rather than anything the server served beside it.
    expectedKeyMultibase: unlock.recordSigner.keyMultibase
  })
  return { ...contents, unlockSpaceId: unlock.spaceId }
}
