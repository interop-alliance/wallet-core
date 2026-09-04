/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The recovery-code format layer and its deterministic derivations. A recovery
 * code is 16 random bytes rendered as base58 (Bitcoin alphabet), shown to the
 * user exactly once at issuance. Under the roster identity model the code is a
 * **minimal always-enrolled wallet client**: everything the code needs to act
 * -- the unlock identity that locates its keyring record, the client key set
 * behind its `keyAgreement` verification method and user-key-roster wrap, and
 * the did:webvh update key whose hash stands pre-committed in `nextKeyHashes`
 * -- derives deterministically from the code's bytes, so the key material
 * exists nowhere until the code is typed.
 *
 * The derivations are wire-level: two wallet apps must produce byte-identical
 * output for the same code, or a code issued in one could not recover in the
 * other. Every salt below is therefore permanent -- changing one orphans every
 * issued code.
 */
import { base58 } from '@scure/base'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import type { UnlockKdf } from '../keyring/kdf.js'
import { unlockClientIdentityFromSeed } from '../unlock/standingClient.js'
import type { UnlockClientIdentity } from '../unlock/standingClient.js'
// The pinned base-side edge onto the ladder derivation helpers: a code's
// update authority IS a ladder, and re-deriving its rungs here would be a
// second copy of a permanent wire-level derivation.
import { ladderRung, ladderVmKeyMultibase } from '../clientAnnex/ladder.js'

/**
 * The byte length of a recovery code: 16 random bytes is ~128 bits, enough
 * that the unlock derivation is a single expansion rather than a stretched
 * KDF (there is nothing to stretch -- the code is already uniform).
 */
export const RECOVERY_CODE_BYTES = 16

/**
 * HKDF parameters for the recovery-code unlock derivation
 * (`unlockSeed = HKDF(codeBytes)`). The salt differs from every other unlock
 * method's salt, so a code and a passphrase that stringify alike can never
 * derive the same unlock Space; as with the other unlock KDFs, `version` pins
 * the parameter set and the salt is permanent.
 */
export const RECOVERY_KDF: UnlockKdf = {
  version: 1,
  algorithm: 'HKDF',
  hash: 'SHA-256',
  salt: 'freewallet/keyring/recovery-code/v1',
  info: 'freewallet/unlock-seed'
}

/**
 * The HKDF salt for the code's client-side key set (distinct from the unlock
 * salt above, so the unlock identity and the client identity can never
 * collide), and the per-key expansion labels. All permanent. The
 * `ladder-seed` expansion replaced a standalone `update-key` one, whose label
 * is retired and never reused: a code's committed update key is rung 0 of the
 * ladder now, which is a different key, so a code issued under the retired
 * label commits a rung nothing derives and cannot spend.
 */
const RECOVERY_CLIENT_SALT = 'freewallet/recovery/client-keys/v1'
const RECOVERY_CLIENT_SEED_INFO = 'client-seed'
const RECOVERY_LADDER_SEED_INFO = 'ladder-seed'

/**
 * The HKDF info string for the code's account-binding MAC key, expanded
 * under the unlock salt beside the unlock-seed expansion above. The key MACs
 * the recovery record's `{ controller, pointer }` core at issuance, so only
 * a holder of the code bytes -- never the storage host -- can bind a record
 * to an account. Permanent, like every other expansion here.
 */
const RECOVERY_BINDING_MAC_INFO = 'freewallet/binding-mac'

/**
 * Thrown for text that is not a well-formed recovery code (characters outside
 * the base58 alphabet, or the wrong decoded length). Deliberately distinct
 * from "no account found for this code" -- a malformed code was mistyped; a
 * well-formed code that resolves to nothing was never issued or has been
 * revoked.
 */
export class RecoveryCodeInvalidError extends Error {
  constructor(message = 'This is not a valid recovery code.') {
    super(message)
    this.name = 'RecoveryCodeInvalidError'
  }
}

/**
 * Generates a fresh recovery code: 16 random bytes, base58-encoded.
 *
 * @returns {string}
 */
export function generateRecoveryCode(): string {
  const bytes = new Uint8Array(RECOVERY_CODE_BYTES)
  crypto.getRandomValues(bytes)
  return base58.encode(bytes)
}

/**
 * Renders a recovery code in dash-separated groups of four for display
 * ("6yCL-Ho5s-..."). Purely cosmetic; `normalizeRecoveryCode` strips the
 * grouping back out on entry.
 *
 * @param options {object}
 * @param options.code {string}
 * @returns {string}
 */
export function formatRecoveryCode({ code }: { code: string }): string {
  return code.replace(/(.{4})(?=.)/g, '$1-')
}

/**
 * Normalizes user-entered recovery code text: strips whitespace and the
 * display dashes. Base58 is case-sensitive, so casing is preserved.
 *
 * @param options {object}
 * @param options.input {string}
 * @returns {string}
 */
export function normalizeRecoveryCode({ input }: { input: string }): string {
  return input.replace(/[\s-]+/g, '')
}

/**
 * Decodes a (possibly formatted) recovery code back to its 16 bytes,
 * throwing `RecoveryCodeInvalidError` on anything malformed.
 *
 * @param options {object}
 * @param options.code {string}   the user-entered code (grouping tolerated)
 * @returns {Uint8Array}
 */
export function decodeRecoveryCode({ code }: { code: string }): Uint8Array {
  const normalized = normalizeRecoveryCode({ input: code })
  let bytes: Uint8Array
  try {
    // Throws on characters outside the base58 alphabet.
    bytes = base58.decode(normalized)
  } catch {
    throw new RecoveryCodeInvalidError()
  }
  if (bytes.length !== RECOVERY_CODE_BYTES) {
    throw new RecoveryCodeInvalidError()
  }
  return bytes
}

/**
 * The code's full client identity, derived deterministically from its bytes:
 * the 32-byte client seed (behind the code's Ed25519 signing pair and X25519
 * key-agreement twin), the ladder seed behind its update authority, the
 * derived agents, and the public multibases / ids the issuance and recovery
 * flows publish and look up.
 */
export interface RecoveryClient extends UnlockClientIdentity {
  codeBytes: Uint8Array
  /**
   * The code's update-key ladder seed. Its VM is what signs the code's own
   * bridge delegation, and its rung 0 is the code's committed update key, so
   * the spend's reveal-and-commit entry is the ordinary ladder reveal. A code
   * is spent on use and never self-rotates, so no rung past 0 is ever
   * revealed; the ladder is what gives the code a verification method of its
   * own beside that single rung.
   */
  ladderSeed: Uint8Array
  /**
   * Rung 0's 32-byte update-key seed -- the key the code's committed hash
   * stands for, and the one the reveal-and-commit entry signs with.
   */
  updateSeed: Uint8Array
  /**
   * The symmetric key that MACs the recovery record's account binding:
   * computed at issuance, verified at recovery before the pointer is trusted.
   * Derived from the code bytes, so the storage host never holds it.
   */
  bindingMacKey: Uint8Array
  /**
   * Rung 0's public multibase: the code's `updateKeyMultibase` as the
   * registry records it and the document commits its hash.
   */
  updateKeyMultibase: string
  /**
   * The ladder VM's public multibase, as the account document publishes it
   * under `assertionMethod` and `capabilityDelegation`.
   */
  ladderVmKeyMultibase: string
}

/**
 * Derives the code's whole client identity from a (possibly formatted) code.
 * Deterministic: the same code always yields the same key set. Throws
 * `RecoveryCodeInvalidError` on malformed text; whether the derived identity
 * actually unlocks anything is the caller's question.
 *
 * @param options {object}
 * @param options.code {string}   the recovery code (grouping tolerated)
 * @returns {Promise<RecoveryClient>}
 */
export async function recoveryClientFromCode({
  code
}: {
  code: string
}): Promise<RecoveryClient> {
  const codeBytes = decodeRecoveryCode({ code })
  const salt = new TextEncoder().encode(RECOVERY_CLIENT_SALT)
  const clientSeed = hkdf(
    sha256,
    codeBytes,
    salt,
    new TextEncoder().encode(RECOVERY_CLIENT_SEED_INFO),
    32
  )
  const ladderSeed = hkdf(
    sha256,
    codeBytes,
    salt,
    new TextEncoder().encode(RECOVERY_LADDER_SEED_INFO),
    32
  )
  const bindingMacKey = hkdf(
    sha256,
    codeBytes,
    new TextEncoder().encode(RECOVERY_KDF.salt),
    new TextEncoder().encode(RECOVERY_BINDING_MAC_INFO),
    32
  )
  const identity = await unlockClientIdentityFromSeed({ clientSeed })
  // Rung 0 through the shared ladder derivation, so the code's committed
  // update key is the same key the ladder's own reveal attributes.
  const rung0 = await ladderRung({ ladderSeed, index: 0 })
  return {
    ...identity,
    codeBytes,
    ladderSeed,
    updateSeed: rung0.seed,
    bindingMacKey,
    updateKeyMultibase: rung0.keyMultibase,
    ladderVmKeyMultibase: await ladderVmKeyMultibase({ ladderSeed })
  }
}
