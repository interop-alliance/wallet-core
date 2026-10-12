/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A standing credential's static annex rung: the one update key it holds on
 * every client-annex generation's log. The annex chain has length one, so
 * there is no rung to advance to and no attribution scan to run. The
 * derivation takes the ladder seed alone and is minted through the shared
 * {@link ladderDerive}, so the salt and HKDF triple stay in
 * `webvh/ladderDerivation.ts`.
 *
 * The rung is static across generations on purpose. A generation swap mints
 * a fresh genesis, and it can carry over only the commitments it can
 * attribute from the superseded generation's log. With one key per
 * credential, that log's update-key membership IS the standing credentials'
 * annex commitment set, and the swap restates it. A key derived per
 * generation could not be restated without every credential's seed, and a
 * wallet session holds only its own, so every swap locked every other
 * credential out of the annex.
 */
import { ladderDerive } from '../webvh/ladderDerivation.js'
import { updateKeyMultibase } from '../webvh/updateKeyMultibase.js'

/**
 * The HKDF info label of the annex rung, under the ladder's one salt.
 * Permanent. The three label families under that salt stay disjoint:
 * `rung/<n>` (the account rungs) carries exactly one slash followed by a
 * decimal index, `vm` carries none, and this label carries two slashes
 * behind its `annex` prefix. The separate label is also what keeps a
 * revealed annex key from matching the account log's rung-0 commitment,
 * since the annex log is readable by its storage host.
 */
const CLIENT_ANNEX_RUNG_INFO = 'annex/rung/0'

/**
 * Derives the 32-byte update-key seed of a credential's annex rung, the
 * static update key it holds on every annex generation's log.
 *
 * @param options {object}
 * @param options.ladderSeed {Uint8Array}
 * @returns {Uint8Array}
 */
export function clientAnnexRungSeed({
  ladderSeed
}: {
  ladderSeed: Uint8Array
}): Uint8Array {
  return ladderDerive({ ladderSeed, info: CLIENT_ANNEX_RUNG_INFO })
}

/**
 * Derives a credential's annex rung in full: seed and public multibase.
 *
 * @param options {object}
 * @param options.ladderSeed {Uint8Array}
 * @returns {Promise<{ seed: Uint8Array, keyMultibase: string }>}
 */
export async function clientAnnexRung({
  ladderSeed
}: {
  ladderSeed: Uint8Array
}): Promise<{ seed: Uint8Array; keyMultibase: string }> {
  const seed = clientAnnexRungSeed({ ladderSeed })
  return { seed, keyMultibase: await updateKeyMultibase({ seed }) }
}
