/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A client-annex generation's static rung 0: the one update key a standing
 * credential holds on that generation's annex log. The annex chain has
 * length one, so there is no rung to advance to and no attribution scan to
 * run; the derivation is index-free. The label family is the annex's own
 * (`<generationId>/rung/0`), minted through the shared {@link ladderDerive}
 * so the salt and HKDF triple stay in `webvh/ladderDerivation.ts`.
 */
import { ladderDerive } from '../webvh/ladderDerivation.js'
import { updateKeyMultibase } from '../webvh/updateKeyMultibase.js'

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

/**
 * Derives an annex generation's rung 0 in full: seed and public multibase.
 *
 * @param options {object}
 * @param options.ladderSeed {Uint8Array}
 * @param options.generationId {string}   the generation collection's name
 * @returns {Promise<{ seed: Uint8Array, keyMultibase: string }>}
 */
export async function clientAnnexRung({
  ladderSeed,
  generationId
}: {
  ladderSeed: Uint8Array
  generationId: string
}): Promise<{ seed: Uint8Array; keyMultibase: string }> {
  const seed = clientAnnexRungSeed({ ladderSeed, generationId })
  return { seed, keyMultibase: await updateKeyMultibase({ seed }) }
}
