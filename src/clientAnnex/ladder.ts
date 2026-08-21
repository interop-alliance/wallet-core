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
import type { DIDLog } from '@interop/did-method-webvh'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { effectiveParameters, updateKeyMultibase } from '../webvh/didWebvh.js'
import { LADDER_SEED_BYTES } from '../unlock/unlockRecord.js'

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
 * ladder-anchored window's document-visible authority (`assertionMethod` and
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
 * Derives the 32-byte update-key seed of an annex generation's rung 0 --
 * the credential's STATIC update key on that generation's annex log. The
 * sequence is domain-separated per generation by the generation id
 * (`<generationId>/rung/0` under the one {@link LADDER_SALT}): one shared
 * sequence
 * would hand the storage host, a legitimate reader of the private annex,
 * a revealed key matching the ACCOUNT log's standing commitment, and a fresh
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
 * Deliberately index-free -- the annex chain has length one, so there is
 * no rung to advance to and no attribution scan to run (see
 * {@link clientAnnexRungSeed}).
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

/**
 * Everything of one ladder that currently stands in the published log's
 * parameters: the revealed rung keys still authorized in `updateKeys` and the
 * committed hashes the ladder accounts for in `nextKeyHashes` -- including,
 * for a torn self-enrollment, the hashes the reveal entry committed under the
 * rung's authority for a client that was never published (its update- and
 * staged-key hashes), which are as much a latent re-seizure credential as the
 * rung's own commitment.
 */
export interface LadderStandingPosture {
  revealedKeys: string[]
  committedHashes: string[]
}

/**
 * Attributes a ladder's FULL standing posture from the log -- the retirement
 * counterpart of {@link attributeLadderRung}, which recovers only the single
 * current rung. Retiring a credential must strike every standing artifact its
 * ladder accounts for, so this walks the log's effective parameters forward
 * from an anchor (the recorded bind-time rung, however stale) and tracks the
 * ladder's footprint entry by entry:
 *
 * - a newly authorized key whose hash was a known ladder commitment is a rung
 *   REVEAL; the hashes that entry (and any entry while the rung stays
 *   revealed) newly commits are claimed by the ladder, since the rung's
 *   authority signed them;
 * - the entry that retires the revealed rung while authorizing a key whose
 *   hash sits among those claims is the enrollment's COMPLETION: the new
 *   client's update-key hash and the claim committed immediately after it
 *   (its staged hash -- a reveal-and-commit entry appends the next rung's
 *   hash LAST among its newly committed hashes, the ordering convention in
 *   `decisions/0007-ladder-reveal-hash-order.md`) transfer to the client and
 *   stop being ladder-owned, while the residue (the next rung's commitment)
 *   stays;
 * - a claim or revealed key that later leaves the parameters without a
 *   completion was struck by some other edit and simply stops standing.
 *
 * With the ladder seed in hand (`ladderSeed`), every rung's key and hash are
 * additionally known a priori, so the attribution does not depend on the
 * anchor being current; without it, the walk is anchored on
 * `anchorKeyMultibase` alone. More than one ladder reveal standing or arriving
 * at once matches no legitimate history and fails closed
 * ({@link LadderAttributionError}).
 *
 * @param options {object}
 * @param options.log {DIDLog}   a resolved, caller-verified log
 * @param options.anchorKeyMultibase {string}   the credential's recorded
 *   update-key multibase (bind-time rung 0, or a refreshed later rung)
 * @param [options.ladderSeed] {Uint8Array}   the credential's ladder seed,
 *   when the caller holds it
 * @param [options.maxScan] {number}   seeded pre-derivation bound; defaults to
 *   {@link LADDER_MAX_SCAN}
 * @returns {Promise<LadderStandingPosture>}   what currently stands; both
 *   arrays empty when the log carries nothing of the ladder any more
 */
export async function attributeLadderPosture({
  log,
  anchorKeyMultibase,
  ladderSeed,
  maxScan = LADDER_MAX_SCAN
}: {
  log: DIDLog
  anchorKeyMultibase: string
  ladderSeed?: Uint8Array
  maxScan?: number
}): Promise<LadderStandingPosture> {
  const ladderKeys = new Set<string>([anchorKeyMultibase])
  const ladderHashes = new Set<string>([
    await deriveNextKeyHash(anchorKeyMultibase)
  ])
  if (ladderSeed) {
    for (let index = 0; index < maxScan; index++) {
      const rung = await ladderRung({ ladderSeed, index })
      ladderKeys.add(rung.keyMultibase)
      ladderHashes.add(await deriveNextKeyHash(rung.keyMultibase))
    }
  }

  const params = effectiveParameters(log)
  let pending: { key: string; claims: string[] } | undefined
  let prevUpdateKeys = new Set<string>()
  let prevHashes = new Set<string>()
  for (const entry of params) {
    const currentUpdateKeys = new Set(entry.updateKeys)
    const addedKeys = entry.updateKeys.filter(key => !prevUpdateKeys.has(key))
    // Order-preserving on purpose: the completion transfer below reads the
    // claim committed immediately after the client's update-key hash as its
    // staged hash (the reveal entry's append order, a ratified convention).
    const addedHashes = entry.nextKeyHashes.filter(
      hash => !prevHashes.has(hash)
    )

    // Completion first: the pending revealed rung left `updateKeys`. When the
    // same entry authorizes a key whose hash sits among the reveal's claims,
    // the enrollment completed -- that hash and its successor (the client's
    // staged hash) transfer to the client. A rung leaving any other way was
    // struck, and its claims simply stop standing.
    if (pending && !currentUpdateKeys.has(pending.key)) {
      for (const key of addedKeys) {
        const index = pending.claims.indexOf(await deriveNextKeyHash(key))
        if (index === -1) {
          continue
        }
        ladderHashes.delete(pending.claims[index]!)
        const staged = pending.claims[index + 1]
        if (staged !== undefined) {
          ladderHashes.delete(staged)
        }
        break
      }
      pending = undefined
    }

    // A newly authorized key matching a known ladder commitment is a reveal.
    const reveals: string[] = []
    for (const key of addedKeys) {
      if (
        ladderKeys.has(key) ||
        ladderHashes.has(await deriveNextKeyHash(key))
      ) {
        reveals.push(key)
      }
    }
    if (reveals.length > 1 || (reveals.length === 1 && pending)) {
      throw new LadderAttributionError(
        'The published log reveals more than one rung of this ladder at ' +
          'once; refusing to attribute an ambiguous history.'
      )
    }
    if (reveals.length === 1) {
      const key = reveals[0]!
      ladderKeys.add(key)
      pending = { key, claims: [...addedHashes] }
      for (const hash of addedHashes) {
        ladderHashes.add(hash)
      }
    } else if (pending) {
      // The rung is still revealed: hashes committed while it stands were
      // signed under its authority (the ladder-anchored window's separate
      // commit entry), so they join its claims.
      pending.claims.push(...addedHashes)
      for (const hash of addedHashes) {
        ladderHashes.add(hash)
      }
    }

    prevUpdateKeys = currentUpdateKeys
    prevHashes = new Set(entry.nextKeyHashes)
  }

  const final = params[params.length - 1] ?? {
    updateKeys: [],
    nextKeyHashes: []
  }
  return {
    revealedKeys: final.updateKeys.filter(key => ladderKeys.has(key)),
    committedHashes: final.nextKeyHashes.filter(hash => ladderHashes.has(hash))
  }
}
