/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The update-key ladder: a standing unlock credential's latent-and-consumed
 * did:webvh update authority. Rungs derive deterministically from a random
 * 32-byte ladder seed carried inside the credential's unlock record -- never
 * from the unlock secret itself, because a revealed rung lives verbatim in
 * the world-readable `updateKeys` forever, where no hash commitment can
 * protect it, so a secret-derived rung would be a standing offline grind
 * oracle against the credential.
 *
 * Between uses only `hash(rung i)` stands in the document's `nextKeyHashes`;
 * each self-enrollment is one loud reveal-and-commit entry signing with rung
 * `i` and committing `hash(rung i + 1)`, after which the add entry retires
 * the spent rung. The credential never holds a standing `updateKeys` member.
 *
 * There is no stored counter: which rung is current is recovered by
 * re-deriving and scanning the published log's standing parameters
 * ({@link attributeLadderRung}), and ambiguity fails closed rather than
 * guessing -- the clients-listing attribution precedent. A lost
 * compare-and-swap race resolves by determinism: the winner's entry commits
 * `hash(rung i + 1)`, which IS the loser's retry key, so a re-run
 * re-attributes and climbs one rung.
 *
 * The rung derivation is wire-level (both wallet apps must climb the same
 * ladder from the same seed), so the salt and info labels are permanent.
 */
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { updateKeyMultibase } from '../webvh/didWebvh.js'

/**
 * The byte length of a ladder seed: 32 random bytes, minted at bind time and
 * carried only inside the unlock record's sealed ladder member.
 */
export const LADDER_SEED_BYTES = 32

/**
 * The HKDF salt for rung derivation and the per-rung info prefix (the rung
 * index in decimal follows it). Both permanent -- changing either orphans
 * every bound credential's ladder.
 */
const LADDER_SALT = 'freewallet/unlock/update-ladder/v1'
const LADDER_RUNG_INFO_PREFIX = 'rung/'

/**
 * The info label of the ladder VM -- the stable sibling key published in the
 * account document while the account has no enrolled durable client. One salt
 * for everything ladder-seed-derived, with the info namespace doing the
 * separation: `vm` can never collide with a `rung/<n>` label. Permanent.
 */
const LADDER_VM_INFO = 'vm'

/**
 * The info-label suffix of a companion rung: the label is
 * `<segment>/rung/<k>` where `<segment>` is the generation collection's name
 * (`gen-<random>`) and `k` is pinned at 0 -- the companion log's update
 * authority is each standing credential's STATIC rung 0 (chain length one,
 * never advanced), so only `/rung/0` is ever derived. The three families
 * under the one salt stay disjoint: `rung/<n>` labels carry exactly one
 * slash followed by a decimal index, `vm` carries none, and a companion
 * label always carries two slashes behind its `gen-` segment. Permanent.
 */
const COMPANION_RUNG_INFO_SUFFIX = '/rung/0'

/**
 * How many rungs {@link attributeLadderRung} derives before concluding the
 * log commits none of them. Generous: one rung is consumed per
 * self-enrollment, so a real ladder's standing commitment sits at the number
 * of self-enrollments the credential has ever performed.
 */
export const LADDER_MAX_SCAN = 128

/**
 * Thrown when the published log's standing parameters match no derivable rung
 * -- the credential's posture was revoked (or never published), the ladder
 * seed does not belong to this account, or the scan bound was exceeded -- or
 * when they match more than one rung in the same role, which no legitimate
 * history produces. Self-enrollment refuses loudly rather than guessing.
 */
export class LadderAttributionError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'LadderAttributionError'
  }
}

/**
 * Generates a fresh random ladder seed.
 *
 * @returns {Uint8Array}
 */
export function generateLadderSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(LADDER_SEED_BYTES))
}

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
 * client-less window's document-visible authority (`assertionMethod` and
 * `capabilityDelegation`), while update authority stays on the rungs -- the
 * two roles never share a key.
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
 * Derives the 32-byte update-key seed of a companion generation's rung 0 --
 * the credential's STATIC update key on that generation's companion log. The
 * sequence is domain-separated per generation by the collection segment
 * (`<segment>/rung/0` under the one {@link LADDER_SALT}): one shared sequence
 * would hand the storage host, a legitimate reader of the private companion,
 * a revealed key matching the ACCOUNT log's standing commitment, and a fresh
 * per-generation sequence is what makes GC replacement self-healing (no rung
 * index survives the deleted log, and none is needed).
 *
 * The segment is trusted here rather than re-validated -- the companion
 * ceremonies assert the `gen-<random>` shape (`assertGenerationSegment`)
 * before any derivation, and the label families stay disjoint for any
 * segment regardless (an account-rung label carries exactly one slash).
 *
 * @param options {object}
 * @param options.ladderSeed {Uint8Array}
 * @param options.segment {string}   the generation collection's name
 * @returns {Uint8Array}
 */
export function companionRungSeed({
  ladderSeed,
  segment
}: {
  ladderSeed: Uint8Array
  segment: string
}): Uint8Array {
  return ladderDerive({
    ladderSeed,
    info: `${segment}${COMPANION_RUNG_INFO_SUFFIX}`
  })
}

/**
 * Derives a companion generation's rung 0 in full: seed and public multibase.
 * Deliberately index-free -- the companion chain has length one, so there is
 * no rung to advance to and no attribution scan to run (see
 * {@link companionRungSeed}).
 *
 * @param options {object}
 * @param options.ladderSeed {Uint8Array}
 * @param options.segment {string}   the generation collection's name
 * @returns {Promise<{ seed: Uint8Array, keyMultibase: string }>}
 */
export async function companionRung({
  ladderSeed,
  segment
}: {
  ladderSeed: Uint8Array
  segment: string
}): Promise<{ seed: Uint8Array; keyMultibase: string }> {
  const seed = companionRungSeed({ ladderSeed, segment })
  return { seed, keyMultibase: await updateKeyMultibase({ seed }) }
}

/**
 * Where an attributed rung stands in the published log: `'committed'` (the
 * steady state -- only its hash stands in `nextKeyHashes`) or `'revealed'` (a
 * torn self-enrollment published the reveal entry but not the add entry, so
 * the rung sits in `updateKeys` awaiting the resumed add).
 */
export type LadderRungState = 'committed' | 'revealed'

/**
 * Recovers the ladder's current rung from the published log's standing
 * parameters -- the counter recovery that replaces any stored counter. Scans
 * rungs `0..maxScan - 1`; a rung whose key stands in `updateKeys` is a torn
 * self-enrollment to resume (`'revealed'`), else a rung whose hash stands in
 * `nextKeyHashes` is the standing commitment (`'committed'`). Exactly one
 * revealed rung, or exactly one committed rung beside it, is legitimate --
 * the reveal entry keeps the spent rung's hash committed so a resumed run can
 * re-state it, which is why a revealed rung wins over a committed one.
 * Anything else fails closed with {@link LadderAttributionError}.
 *
 * @param options {object}
 * @param options.ladderSeed {Uint8Array}
 * @param options.published {object}   the resolved log's standing parameters
 * @param options.published.updateKeys {string[]}
 * @param options.published.nextKeyHashes {string[]}
 * @param [options.maxScan] {number}   how many rungs to derive before giving
 *   up; defaults to {@link LADDER_MAX_SCAN}
 * @returns {Promise<{ rung: LadderRung, state: LadderRungState }>}
 */
export async function attributeLadderRung({
  ladderSeed,
  published,
  maxScan = LADDER_MAX_SCAN
}: {
  ladderSeed: Uint8Array
  published: { updateKeys: string[]; nextKeyHashes: string[] }
  maxScan?: number
}): Promise<{ rung: LadderRung; state: LadderRungState }> {
  const revealed: LadderRung[] = []
  const committed: LadderRung[] = []
  for (let index = 0; index < maxScan; index++) {
    const rung = await ladderRung({ ladderSeed, index })
    if (published.updateKeys.includes(rung.keyMultibase)) {
      revealed.push(rung)
    } else if (
      published.nextKeyHashes.includes(
        await deriveNextKeyHash(rung.keyMultibase)
      )
    ) {
      committed.push(rung)
    }
  }
  if (revealed.length > 1 || committed.length > 1) {
    throw new LadderAttributionError(
      'The published log commits more than one rung of this ladder in the ' +
        'same role; refusing to self-enroll on an ambiguous attribution.'
    )
  }
  if (revealed.length === 1) {
    return { rung: revealed[0]!, state: 'revealed' }
  }
  if (committed.length === 1) {
    return { rung: committed[0]!, state: 'committed' }
  }
  throw new LadderAttributionError(
    'The published log commits no rung of this ladder; the credential has ' +
      'been revoked, was never published, or does not belong to this account.'
  )
}
