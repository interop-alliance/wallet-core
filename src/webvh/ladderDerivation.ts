/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The update-key ladder's pure derivation: the rung seeds, the rungs, and the
 * ladder VM key a random 32-byte ladder seed yields. Each is one HKDF
 * expansion, and the keyed ones add an Ed25519 public key derivation.
 *
 * The file imports a hash library and the update-key leaf alone, so an
 * offline caller that turns a recovery code into a recovery client loads no
 * did:webvh log or ceremony code. The attribution walks that scan a published
 * log for these rungs live in `webvh/ladder.ts`. A client-annex generation's static rung 0 derives through
 * the same {@link ladderDerive} from `clientAnnex/generationRung.ts`, so the
 * one salt and HKDF triple stay in this file.
 *
 * The rung derivation is wire-level (both wallet apps must climb the same
 * ladder from the same seed), so the salt and info labels are permanent.
 */
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { updateKeyMultibase } from './updateKeyMultibase.js'

/**
 * The HKDF salt for rung derivation and the per-rung info prefix (the rung
 * index in decimal follows it). Both permanent -- changing either orphans
 * every bound credential's ladder.
 */
const LADDER_SALT = 'freewallet/unlock/update-ladder/v1'
const LADDER_RUNG_INFO_PREFIX = 'rung/'

/**
 * The info label of the ladder VM -- the stable sibling key a standing
 * credential publishes in the account document for as long as it stands. One
 * salt for everything ladder-seed-derived, with the info namespace doing the
 * separation: `vm` can never collide with a `rung/<n>` label. Permanent.
 */
const LADDER_VM_INFO = 'vm'

/**
 * The one HKDF invocation of the ladder derivation family. Every
 * ladder-seed-derived key (rungs, the ladder VM) comes through here, so the
 * permanent wire-level triple -- SHA-256, {@link LADDER_SALT}, 32 bytes --
 * lives in exactly one place and only the info label varies. Exported for
 * the client annex's generation rung alone; every other label is minted
 * here.
 *
 * @param options {object}
 * @param options.ladderSeed {Uint8Array}
 * @param options.info {string}
 * @returns {Uint8Array}
 */
export function ladderDerive({
  ladderSeed,
  info
}: {
  ladderSeed: Uint8Array
  info: string
}): Uint8Array {
  return hkdf(
    sha256,
    ladderSeed,
    new TextEncoder().encode(LADDER_SALT),
    new TextEncoder().encode(info),
    32
  )
}

/**
 * One rung of the ladder: its index, the 32-byte Ed25519 seed behind it, and
 * the update key's public multibase as the log carries it.
 */
export interface LadderRung {
  index: number
  seed: Uint8Array
  keyMultibase: string
}

/**
 * Derives the 32-byte update-key seed of rung `index`.
 *
 * @param options {object}
 * @param options.ladderSeed {Uint8Array}
 * @param options.index {number}   the rung index, from 0
 * @returns {Uint8Array}
 */
export function ladderRungSeed({
  ladderSeed,
  index
}: {
  ladderSeed: Uint8Array
  index: number
}): Uint8Array {
  if (!Number.isInteger(index) || index < 0) {
    throw new Error(`Invalid ladder rung index "${String(index)}".`)
  }
  return ladderDerive({
    ladderSeed,
    info: `${LADDER_RUNG_INFO_PREFIX}${index}`
  })
}

/**
 * Derives rung `index` in full: seed and public multibase.
 *
 * @param options {object}
 * @param options.ladderSeed {Uint8Array}
 * @param options.index {number}   the rung index, from 0
 * @returns {Promise<LadderRung>}
 */
export async function ladderRung({
  ladderSeed,
  index
}: {
  ladderSeed: Uint8Array
  index: number
}): Promise<LadderRung> {
  const seed = ladderRungSeed({ ladderSeed, index })
  return { index, seed, keyMultibase: await updateKeyMultibase({ seed }) }
}

/**
 * Derives the 32-byte Ed25519 seed of the ladder VM -- the STABLE SIBLING: a
 * dedicated key derived once from the ladder seed, distinct from every rung,
 * published verbatim in the account document (the seed is random, so the
 * hash-commitment rule permits it) and stable across rung spends, so a
 * delegation it signed survives every ladder advance. It carries the
 * credential's document-visible authority (`assertionMethod` and
 * `capabilityDelegation`), while update authority stays on the rungs -- the
 * two roles never share a key.
 *
 * Its life is the credential's: the VM is installed in the entry that makes
 * the credential standing (`publishUnlockKey`) and struck in the entry that
 * retires it (`removeUnlockKey`). Enrollment never touches it, so several
 * VMs stand on an account with several standing credentials.
 *
 * Because the key is derived, removing its verification method is never the
 * terminal remedy: a later reinstall republishes the same key under the same
 * id, and any still-unexpired delegation it signed resumes verifying the
 * moment the method returns. Revoking the delegations themselves (and,
 * ultimately, rotating the credential) is what actually ends its authority.
 *
 * @param options {object}
 * @param options.ladderSeed {Uint8Array}
 * @returns {Uint8Array}
 */
export function ladderVmSeed({
  ladderSeed
}: {
  ladderSeed: Uint8Array
}): Uint8Array {
  return ladderDerive({ ladderSeed, info: LADDER_VM_INFO })
}

/**
 * The ladder VM's public key multibase, as the document publishes it (see
 * {@link ladderVmSeed} for what the key is).
 *
 * @param options {object}
 * @param options.ladderSeed {Uint8Array}
 * @returns {Promise<string>}
 */
export async function ladderVmKeyMultibase({
  ladderSeed
}: {
  ladderSeed: Uint8Array
}): Promise<string> {
  return updateKeyMultibase({ seed: ladderVmSeed({ ladderSeed }) })
}
