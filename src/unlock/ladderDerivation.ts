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
 * log for these rungs live in `clientAnnex/ladder.ts`, which re-exports this
 * file's names.
 *
 * The rung derivation is wire-level (both wallet apps must climb the same
 * ladder from the same seed), so the salt and info labels are permanent.
 */
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { updateKeyMultibase } from '../webvh/updateKeyMultibase.js'

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
 * The info-label suffix of a client-annex rung: the label is
 * `<generationId>/rung/<k>` where `<generationId>` is the generation
 * collection's name
 * (`gen-<random>`) and `k` is pinned at 0 -- the annex log's update
 * authority is each standing credential's STATIC rung 0 (chain length one,
 * never advanced), so only `/rung/0` is ever derived. The three families
 * under the one salt stay disjoint: `rung/<n>` labels carry exactly one
 * slash followed by a decimal index, `vm` carries none, and an annex
 * label always carries two slashes behind its `gen-` generation id.
 * Permanent.
 */
const CLIENT_ANNEX_RUNG_INFO_SUFFIX = '/rung/0'

/**
 * The one HKDF invocation of the ladder derivation family. Every
 * ladder-seed-derived key (rungs, the ladder VM) comes through here, so the
 * permanent wire-level triple -- SHA-256, {@link LADDER_SALT}, 32 bytes --
 * lives in exactly one place and only the info label varies.
 *
 * @param options {object}
 * @param options.ladderSeed {Uint8Array}
 * @param options.info {string}
 * @returns {Uint8Array}
 */
function ladderDerive({
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

/**
 * Derives the 32-byte update-key seed of an annex generation's rung 0 --
 * the credential's STATIC update key on that generation's annex log. The
 * sequence is domain-separated per generation by the generation id
 * (`<generationId>/rung/0` under the one ladder salt): one shared sequence
 * would hand the storage host, a legitimate reader of the private annex, a
 * revealed key matching the ACCOUNT log's standing commitment, and a fresh
 * per-generation sequence is what makes GC replacement self-healing (no rung
 * index survives the deleted log, and none is needed).
 *
 * The generation id is trusted here rather than re-validated -- the annex
 * ceremonies assert the `gen-<random>` shape (`assertGenerationId`)
 * before any derivation, and the label families stay disjoint for any
 * generation id regardless (an account-rung label carries exactly one
 * slash).
 *
 * @param options {object}
 * @param options.ladderSeed {Uint8Array}
 * @param options.generationId {string}   the generation collection's name
 * @returns {Uint8Array}
 */
export function clientAnnexRungSeed({
  ladderSeed,
  generationId
}: {
  ladderSeed: Uint8Array
  generationId: string
}): Uint8Array {
  return ladderDerive({
    ladderSeed,
    info: `${generationId}${CLIENT_ANNEX_RUNG_INFO_SUFFIX}`
  })
}
