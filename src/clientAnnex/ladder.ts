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
import type { DIDLog, DIDLogEntry } from '@interop/did-method-webvh'
import { vmFragmentOf } from '@interop/vh-resource-log'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import {
  currentLogParameters,
  effectiveParameters,
  relationIds,
  updateKeyMultibase
} from '../webvh/didWebvh.js'
import { ladderVmIds, listEnrolledWebvhClients } from '../webvh/listClients.js'
import {
  credentialKeyAgreementMethods,
  resolvedKeyAgreementMethods,
  type KeyAgreementDocument
} from '../webvh/keyAgreement.js'
import { survivingClientKeyProtection } from '../webvh/revokeClient.js'
import { log as logger } from '../log.js'
import { LADDER_SEED_BYTES } from '../unlock/unlockRecord.js'

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
 * How many rungs {@link attributeLadderRung} derives before concluding the
 * log commits none of them. Generous: one rung is consumed per
 * self-enrollment, so a real ladder's standing commitment sits at the number
 * of self-enrollments the credential has ever performed.
 */
export const LADDER_MAX_SCAN = 128

/**
 * Thrown when the published log's standing parameters match no derivable rung
 * -- the credential's inventory was revoked (or never published), the ladder
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
 * Everything of one ladder that currently stands in the published log: the
 * revealed rung keys still authorized in `updateKeys`, the ladder VMs the
 * final document publishes that this ladder is attributed as the publisher of
 * (`ladderVmIds`), and the
 * committed hashes the ladder accounts for in `nextKeyHashes` -- including,
 * for a torn self-enrollment, the hashes the reveal entry committed under the
 * rung's authority for a client that was never published (its update- and
 * staged-key hashes), which are as much a latent re-seizure credential as the
 * rung's own commitment.
 */
export interface LadderStandingInventory {
  revealedKeys: string[]
  committedHashes: string[]
  ladderVmIds: string[]
}

/**
 * Whether a log entry was signed by a key this ladder accounts for. A
 * did:webvh entry proof names its key as `did:key:<multibase>#<multibase>`
 * -- the id form the resolver matches against the entry's authorized
 * `updateKeys` -- so the fragment IS the update-key multibase. The log is
 * caller-verified, so a proof standing here has already been checked against
 * the authorized set; this only asks whose it was.
 *
 * @param options {object}
 * @param options.entry {DIDLogEntry | undefined}
 * @param options.ladderKeys {Set<string>}   the rung keys known so far
 * @returns {boolean}
 */
function ladderSigned({
  entry,
  ladderKeys
}: {
  entry: DIDLogEntry | undefined
  ladderKeys: Set<string>
}): boolean {
  return entrySigners({ entry }).some(key => ladderKeys.has(key))
}

/**
 * The update-key multibases that signed a log entry (the fragment of each
 * proof's `did:key:<multibase>#<multibase>` id; see {@link ladderSigned}).
 *
 * @param options {object}
 * @param options.entry {DIDLogEntry | undefined}
 * @returns {string[]}
 */
function entrySigners({ entry }: { entry: DIDLogEntry | undefined }): string[] {
  return (entry?.proof ?? []).flatMap(proof => {
    const id = proof.verificationMethod
    const keyMultibase = id === undefined ? undefined : vmFragmentOf(id)
    return keyMultibase === undefined ? [] : [keyMultibase]
  })
}

/**
 * Whether the document an entry publishes still carries the retiring
 * credential's own `keyAgreement` verification method -- asked at the entry
 * that completes an enrollment the ladder's rung revealed, where it is the
 * test of whether the CREDENTIAL survives its own ceremony. A self-enrollment
 * leaves the credential's inventory untouched (it climbs to the next rung),
 * while a spend -- the recovery continuation, whose add-and-retire entry
 * strikes the code's inventory and publishes its successor's -- ends it.
 *
 * With no id supplied the question cannot be asked, so the answer is a
 * conservative `false`: a claim the ladder cannot attribute is released rather
 * than struck.
 *
 * @param options {object}
 * @param options.entry {DIDLogEntry | undefined}
 * @param options.vmId {string | undefined}   the credential's key-agreement
 *   verification-method id, where the caller supplied one
 * @returns {boolean}
 */
function credentialSurvives({
  entry,
  vmId
}: {
  entry: DIDLogEntry | undefined
  vmId: string | undefined
}): boolean {
  if (vmId === undefined || !entry?.state) {
    return false
  }
  // The `keyAgreement` RELATION alone, rather than the bare
  // `verificationMethod` array: an entry that dereferences the method while
  // leaving its object behind has ended the credential's inventory, and reading
  // that as a climb would claim -- and strike -- a successor credential's
  // commitment.
  return relationIds(
    entry.state.keyAgreement as Array<string | { id?: string }> | undefined
  ).includes(vmId)
}

/**
 * The credential-class `keyAgreement` verification-method ids an entry
 * INTRODUCES: those its document publishes and the previous entry's document
 * did not. Credential-class means account-controlled
 * (`credentialKeyAgreementMethods`), so an enrolled client's marked twin
 * never counts. The co-introduction arm of the ladder-VM attribution reads
 * this and refuses to act unless the answer is exactly this credential.
 *
 * @param options {object}
 * @param options.doc {KeyAgreementDocument}   the entry's document
 * @param [options.prevDoc] {KeyAgreementDocument}   the previous entry's
 * @param options.did {string}   the account DID
 * @returns {string[]}   in document order
 */
function introducedCredentialKeys({
  doc,
  prevDoc,
  did
}: {
  doc: KeyAgreementDocument
  prevDoc: KeyAgreementDocument | undefined
  did: string
}): string[] {
  const before = new Set(
    (prevDoc ? credentialKeyAgreementMethods({ doc: prevDoc, did }) : []).map(
      method => method.id
    )
  )
  return credentialKeyAgreementMethods({ doc, did })
    .map(method => method.id)
    .filter((id): id is string => id !== undefined && !before.has(id))
}

/**
 * What one log entry did to the standing parameters, in the form both
 * attribution walks read: the update keys it newly authorized, the ones it
 * retired, the hashes it newly committed (order-preserving, because the
 * positional rules of `decisions/0007-ladder-reveal-hash-order.md` are read
 * off that order), and the update-key multibases that signed it.
 */
interface LadderEntryFacts {
  addedKeys: string[]
  removedKeys: string[]
  addedHashes: string[]
  signers: string[]
}

/**
 * Where a standing hash was FIRST committed: the entry, and the position it
 * took among that entry's newly committed hashes. `nextKeyHashes` re-states
 * every still-active commitment on every entry (the carry-over convention),
 * so only the first appearance carries attribution meaning.
 */
interface LadderCommitOrigin {
  entryIndex: number
  at: number
}

/**
 * The log-derived indexes every attribution walk starts from, computed once
 * per log rather than once per credential.
 *
 * `effectiveParameters`, `indexLadderLog` and the enrolled-client attribution
 * are pure functions of the log, and a retirement walks the SAME log once per
 * retiring credential ({@link attributeRetiredCredentialRungs}), so without
 * this the recovery-spend and last-client-forget ceremonies rebuild all three
 * N times over. Keyed on the log's own identity: a log is read fresh and
 * never mutated in place, so an entry keyed by one can never describe
 * another.
 */
const ladderLogIndexes = new WeakMap<
  DIDLog,
  {
    params: Array<{ updateKeys: string[]; nextKeyHashes: string[] }>
    facts: LadderEntryFacts[]
    commitIndex: Map<string, LadderCommitOrigin>
  }
>()

/**
 * {@link effectiveParameters} and {@link indexLadderLog} over a log, memoized
 * on the log.
 *
 * @param log {DIDLog}
 * @returns {object}
 */
function indexedLadderLog(log: DIDLog): {
  params: Array<{ updateKeys: string[]; nextKeyHashes: string[] }>
  facts: LadderEntryFacts[]
  commitIndex: Map<string, LadderCommitOrigin>
} {
  const cached = ladderLogIndexes.get(log)
  if (cached) {
    return cached
  }
  const params = effectiveParameters(log)
  const { facts, commitIndex } = indexLadderLog({ log, params })
  const indexed = { params, facts, commitIndex }
  ladderLogIndexes.set(log, indexed)
  return indexed
}

/**
 * The account's enrolled clients as the log attributes them, memoized on the
 * log for the same reason as {@link indexedLadderLog}.
 *
 * @param log {DIDLog}
 * @returns {ReturnType<typeof listEnrolledWebvhClients>}
 */
const enrolledClientsByLog = new WeakMap<
  DIDLog,
  ReturnType<typeof listEnrolledWebvhClients>
>()

function indexedEnrolledClients(
  log: DIDLog
): ReturnType<typeof listEnrolledWebvhClients> {
  const cached = enrolledClientsByLog.get(log)
  if (cached) {
    return cached
  }
  const clients = listEnrolledWebvhClients({ log })
  enrolledClientsByLog.set(log, clients)
  return clients
}

/**
 * The one pre-pass over the log's effective parameters: per-entry facts, plus
 * the commit index both walks project their positional questions through. The
 * forward walk asks what an entry added and who signed it; the backward walk
 * asks where a hash came from and what stood beside it there.
 *
 * @param options {object}
 * @param options.log {DIDLog}
 * @param options.params {Array<{ updateKeys: string[], nextKeyHashes: string[] }>}
 *   the log's effective parameters, entry by entry
 * @returns {{ facts: LadderEntryFacts[], commitIndex: Map<string, LadderCommitOrigin> }}
 */
function indexLadderLog({
  log,
  params
}: {
  log: DIDLog
  params: Array<{ updateKeys: string[]; nextKeyHashes: string[] }>
}): {
  facts: LadderEntryFacts[]
  commitIndex: Map<string, LadderCommitOrigin>
} {
  const facts: LadderEntryFacts[] = []
  const commitIndex = new Map<string, LadderCommitOrigin>()
  let prevUpdateKeys = new Set<string>()
  let prevHashes = new Set<string>()
  for (const [entryIndex, entry] of params.entries()) {
    const currentUpdateKeys = new Set(entry.updateKeys)
    const addedKeys = entry.updateKeys.filter(key => !prevUpdateKeys.has(key))
    const removedKeys = [...prevUpdateKeys].filter(
      key => !currentUpdateKeys.has(key)
    )
    const addedHashes = entry.nextKeyHashes.filter(
      hash => !prevHashes.has(hash)
    )
    const signers = entrySigners({ entry: log[entryIndex] })
    addedHashes.forEach((hash, at) => {
      if (!commitIndex.has(hash)) {
        commitIndex.set(hash, { entryIndex, at })
      }
    })
    facts.push({ addedKeys, removedKeys, addedHashes, signers })
    prevUpdateKeys = currentUpdateKeys
    prevHashes = new Set(entry.nextKeyHashes)
  }
  return { facts, commitIndex }
}

/**
 * Walks the ladder BACKWARDS from the anchor, recovering the rungs the anchor
 * has already climbed past. Run only when no ladder seed is in hand, which is
 * the case the anchor's staleness would otherwise decide: the one writer that
 * advances a recorded anchor does so after a self-enrollment, and every entry
 * the spent rungs signed would then be invisible to the forward walk.
 *
 * Each step reads one hash's origin and asks which of the format's two
 * positional rules put it there
 * (`decisions/0007-ladder-reveal-hash-order.md`). Both rules are read here in
 * reverse, so the shapes the emitters produce forwards are the shapes this
 * recognizes backwards.
 *
 * The LAST-POSITION rule is a climb. A hash appended last among its entry's
 * additions is the committer's own next commitment, so the key that signed
 * that entry is the rung before it. The step is taken only when the entry
 * authorized exactly one key and that key signed the entry, which makes it a
 * prerotation reveal rather than mere adjacency, and only when the credential
 * itself still stands in the entry's document.
 *
 * The ADJACENCY rule is a handover. A hash not in last position sits beside
 * the rung committed immediately before it, and that predecessor is revealed
 * later by the entry that retires the committer. The step is taken only when
 * such a revealing entry exists and the credential stands in ITS document.
 *
 * What each guard protects. The credential-membership test stops the walk at a
 * plain client genesis, at the enrolled-client bind that carries no member of
 * ours yet, and at the spent recovery code whose reveal entry commits the
 * REPLACEMENT code's hash last -- without it the replacement's retirement
 * would recover the spent code's key and go on to strike the fresh
 * credential's rungs. The single-self-revealing-key test stops it at the bind
 * entry an enrolled client signs, which authorizes no key of its own, so the
 * binding client's update key is never recovered as a rung. The strictly
 * decreasing entry cursor and the already-recovered test keep the walk finite
 * and acyclic.
 *
 * @param options {object}
 * @param options.log {DIDLog}
 * @param options.facts {LadderEntryFacts[]}   from {@link indexLadderLog}
 * @param options.commitIndex {Map<string, LadderCommitOrigin>}   likewise
 * @param options.anchorHash {string}   `hash(anchorKeyMultibase)`
 * @param options.credentialVmId {string}   the credential's own `keyAgreement`
 *   verification-method id
 * @param options.maxScan {number}   how many rungs to walk back
 * @returns {Promise<Array<{ key: string, hash: string }>>}   the recovered
 *   rungs, nearest the anchor first
 */
async function recoverEarlierRungs({
  log,
  facts,
  commitIndex,
  anchorHash,
  credentialVmId,
  maxScan
}: {
  log: DIDLog
  facts: LadderEntryFacts[]
  commitIndex: Map<string, LadderCommitOrigin>
  anchorHash: string
  credentialVmId: string
  maxScan: number
}): Promise<Array<{ key: string; hash: string }>> {
  const recovered: Array<{ key: string; hash: string }> = []
  const seenHashes = new Set<string>([anchorHash])
  let cursorHash = anchorHash
  let cursorEntry = Number.POSITIVE_INFINITY
  for (let step = 0; step < maxScan; step++) {
    const origin = commitIndex.get(cursorHash)
    if (origin === undefined || origin.entryIndex >= cursorEntry) {
      return recovered
    }
    const originFacts = facts[origin.entryIndex]!
    if (origin.at === originFacts.addedHashes.length - 1) {
      // The last-position rule, read backwards: a climb.
      const predecessor = originFacts.addedKeys[0]
      if (
        originFacts.addedKeys.length !== 1 ||
        predecessor === undefined ||
        !originFacts.signers.includes(predecessor) ||
        !credentialSurvives({
          entry: log[origin.entryIndex],
          vmId: credentialVmId
        })
      ) {
        return recovered
      }
      const hash = await deriveNextKeyHash(predecessor)
      if (seenHashes.has(hash)) {
        return recovered
      }
      recovered.push({ key: predecessor, hash })
      seenHashes.add(hash)
      cursorHash = hash
      cursorEntry = origin.entryIndex
      continue
    }
    // The adjacency rule, read backwards: a handover.
    const partner =
      origin.at > 0 ? originFacts.addedHashes[origin.at - 1] : undefined
    if (partner === undefined || seenHashes.has(partner)) {
      return recovered
    }
    const reveal = await findRungReveal({
      facts,
      after: origin.entryIndex,
      committerSigners: originFacts.signers,
      hash: partner
    })
    if (
      reveal === undefined ||
      !credentialSurvives({
        entry: log[reveal.entryIndex],
        vmId: credentialVmId
      })
    ) {
      return recovered
    }
    recovered.push({ key: reveal.key, hash: partner })
    seenHashes.add(partner)
    cursorHash = partner
    cursorEntry = origin.entryIndex
  }
  return recovered
}

/**
 * The entry that reveals a committed hash's key while retiring one of the
 * signers that committed it -- the handover the adjacency rule describes.
 * Earliest such entry wins, since a key is authorized once.
 *
 * @param options {object}
 * @param options.facts {LadderEntryFacts[]}
 * @param options.after {number}   search entries strictly after this index
 * @param options.committerSigners {string[]}   the committing entry's signers
 * @param options.hash {string}   the committed hash whose key is sought
 * @returns {Promise<{ entryIndex: number, key: string } | undefined>}
 */
async function findRungReveal({
  facts,
  after,
  committerSigners,
  hash
}: {
  facts: LadderEntryFacts[]
  after: number
  committerSigners: string[]
  hash: string
}): Promise<{ entryIndex: number; key: string } | undefined> {
  for (let entryIndex = after + 1; entryIndex < facts.length; entryIndex++) {
    const candidate = facts[entryIndex]!
    if (!candidate.removedKeys.some(key => committerSigners.includes(key))) {
      continue
    }
    for (const key of candidate.addedKeys) {
      if ((await deriveNextKeyHash(key)) === hash) {
        return { entryIndex, key }
      }
    }
  }
  return undefined
}

/**
 * Thrown when an edit's `nextKeyHashes` would come out empty. An empty list
 * switches prerotation off in did:webvh, so an entry that struck every
 * commitment would leave the account with no staged key at all. Every ceremony
 * that strikes hashes commits its own successors in the same entry, so the
 * list is non-empty by construction; this is the assertion that says so.
 */
export class NextKeyHashesEmptyError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'NextKeyHashesEmptyError'
  }
}

/**
 * Refuses to publish an entry whose `nextKeyHashes` came out empty.
 *
 * @param options {object}
 * @param options.nextKeyHashes {string[]}
 * @param options.ceremony {string}   named in the refusal
 * @returns {string[]}   the list, unchanged
 */
export function assertNextKeyHashesRemain({
  nextKeyHashes,
  ceremony
}: {
  nextKeyHashes: string[]
  ceremony: string
}): string[] {
  if (nextKeyHashes.length === 0) {
    throw new NextKeyHashesEmptyError(
      `did:webvh: ${ceremony} would publish an entry committing no next key ` +
        'hash, which switches prerotation off; the entry was not published.'
    )
  }
  return nextKeyHashes
}

/**
 * A document read for both its `keyAgreement` methods and its
 * `capabilityInvocation` membership.
 */
type ClientAwareDocument = KeyAgreementDocument & {
  capabilityInvocation?: Array<string | { id?: string }>
}

/**
 * The enrolled-client members an entry INTRODUCES: new `capabilityInvocation`
 * ids, and new `keyAgreement` methods the account DID does not control (a
 * client's marked twin). The bind-anchor read refuses any entry that
 * introduces one, because an entry publishing a client also publishes that
 * client's update key, and reading that key as a credential's rung 0 would
 * anchor the walk on a surviving client.
 *
 * @param options {object}
 * @param options.doc {KeyAgreementDocument}   the entry's document
 * @param [options.prevDoc] {KeyAgreementDocument}   the previous entry's
 * @param options.did {string}   the account DID
 * @returns {boolean}
 */
function introducesEnrolledClient({
  doc,
  prevDoc,
  did
}: {
  doc: ClientAwareDocument
  prevDoc: ClientAwareDocument | undefined
  did: string
}): boolean {
  const beforeInvocation = new Set(relationIds(prevDoc?.capabilityInvocation))
  if (
    relationIds(doc.capabilityInvocation).some(id => !beforeInvocation.has(id))
  ) {
    return true
  }
  const markedIds = (
    entryDoc: KeyAgreementDocument | undefined
  ): Set<string> => {
    if (entryDoc === undefined) {
      return new Set()
    }
    const credential = new Set(
      credentialKeyAgreementMethods({ doc: entryDoc, did }).map(
        method => method.id
      )
    )
    return new Set(
      resolvedKeyAgreementMethods({ doc: entryDoc })
        .map(method => method.id)
        .filter((id): id is string => id !== undefined && !credential.has(id))
    )
  }
  const before = markedIds(prevDoc)
  return [...markedIds(doc)].some(id => !before.has(id))
}

/**
 * The anchor a credential's ladder walk starts from when the caller holds no
 * recorded update key -- the log-only anchoring a cold browser needs. The
 * credential's own `keyAgreement` member id is the anchor: the entry that
 * FIRST introduced that member is the credential's bind entry, and what that
 * entry did to the standing parameters names rung 0.
 *
 * Two shapes are read, both fail-closed:
 *
 * - the entry authorized exactly one update key and that key signed it (a
 *   prerotation reveal, the ladder-anchored genesis shape), so rung 0 is that
 *   key outright;
 * - the entry authorized no key of its own and newly committed exactly one
 *   hash (the `publishUnlockKey` bind an enrolled client signs, and the
 *   recovery-code issuance sharing it), so rung 0's hash is that hash.
 *
 * Anything else is ambiguous and returns `undefined`, which the callers report
 * as unclaimed rather than acting on. The reachable ambiguity is a bind entry
 * introducing more than one credential-class member: a recovery
 * add-and-retire entry introduces the fresh credential and the replacement
 * code together, so neither is anchorable this way.
 *
 * @param options {object}
 * @param options.log {DIDLog}   a resolved, caller-verified log
 * @param options.credentialVmId {string}   the credential's `keyAgreement`
 *   verification-method id
 * @returns {Promise<{ anchorKeyMultibase?: string, anchorHash?: string } |
 *   undefined>}
 */
export async function credentialLadderAnchor({
  log,
  credentialVmId
}: {
  log: DIDLog
  credentialVmId: string
}): Promise<{ anchorKeyMultibase?: string; anchorHash?: string } | undefined> {
  const { facts } = indexedLadderLog(log)
  return resolveBindAnchor({ log, facts, credentialVmId })
}

/**
 * The synchronous core of {@link credentialLadderAnchor}, over a pre-pass the
 * caller already ran.
 *
 * @param options {object}
 * @param options.log {DIDLog}
 * @param options.facts {LadderEntryFacts[]}   from {@link indexLadderLog}
 * @param options.credentialVmId {string}
 * @returns {{ anchorKeyMultibase?: string, anchorHash?: string } | undefined}
 */
function resolveBindAnchor({
  log,
  facts,
  credentialVmId
}: {
  log: DIDLog
  facts: LadderEntryFacts[]
  credentialVmId: string
}): { anchorKeyMultibase?: string; anchorHash?: string } | undefined {
  const did = credentialVmId.split('#')[0]
  if (did === undefined || did === '') {
    return undefined
  }
  // Every update key the log attributes to a client the final document still
  // lists, so the self-signed arm can refuse one outright. A client whose
  // active key the log cannot attribute leaves that arm unable to refuse
  // anything, so no anchor is named at all.
  const enrolledClients = indexedEnrolledClients(log)
  if (enrolledClients.some(client => client.updateKeyMultibase === undefined)) {
    return undefined
  }
  const enrolledClientKeys = new Set(
    enrolledClients
      .map(client => client.updateKeyMultibase)
      .filter((key): key is string => key !== undefined)
  )
  let prevDoc: KeyAgreementDocument | undefined
  for (const [index, entry] of log.entries()) {
    const doc = entry.state as KeyAgreementDocument | undefined
    if (doc === undefined) {
      continue
    }
    const introduced = introducedCredentialKeys({ doc, prevDoc, did })
    const prevDocBefore = prevDoc as ClientAwareDocument | undefined
    prevDoc = doc
    if (!introduced.includes(credentialVmId)) {
      continue
    }
    // The bind entry. More than one credential-class member introduced here
    // and nothing below can say which addition is whose.
    if (introduced.length !== 1) {
      return undefined
    }
    const bind = facts[index]
    if (bind === undefined) {
      return undefined
    }
    // The fourth condition: an entry that also publishes an enrolled client
    // names no credential's rung. The remembered recovery's add-and-retire
    // entry is exactly this shape -- the new client's key-agreement method is
    // client-marked, so the credential-class count above sees only the
    // replacement code and the ambiguity guard does not fire, while the one
    // key the entry authorizes is the CLIENT's update key.
    if (
      introducesEnrolledClient({
        doc: doc as ClientAwareDocument,
        prevDoc: prevDocBefore,
        did
      })
    ) {
      return undefined
    }
    const revealed = bind.addedKeys[0]
    if (
      bind.addedKeys.length === 1 &&
      revealed !== undefined &&
      bind.signers.includes(revealed) &&
      // Belt and braces beside the condition above: never anchor on a key the
      // log attributes to an enrolled client, whichever entry published it.
      !enrolledClientKeys.has(revealed)
    ) {
      return { anchorKeyMultibase: revealed }
    }
    if (bind.addedKeys.length === 0 && bind.addedHashes.length === 1) {
      // No enrolled-client check of its own: this arm reads a hash rather
      // than a key, and no ceremony fuses a credential bind with a client's
      // hash commitment.
      return { anchorHash: bind.addedHashes[0]! }
    }
    return undefined
  }
  return undefined
}

/**
 * Whether one retiring credential's rung inventory can be claimed from the log
 * at all: its bind entry must name an anchor, and the walk from that anchor
 * must not refuse. This is the log-only test, so it answers the same before
 * and after the retirement entry lands -- which is what lets a resumed run
 * report the same unclaimed set the first run reported.
 *
 * @param options {object}
 * @param options.log {DIDLog}
 * @param options.credentialVmId {string}
 * @param options.maxScan {number}
 * @returns {Promise<LadderStandingInventory | undefined>}   the walk's result,
 *   or `undefined` when the credential cannot be claimed
 */
async function claimLadderInventory({
  log,
  credentialVmId,
  maxScan
}: {
  log: DIDLog
  credentialVmId: string
  maxScan: number
}): Promise<LadderStandingInventory | undefined> {
  try {
    return await attributeLadderInventory({ log, credentialVmId, maxScan })
  } catch {
    // An ambiguous anchor or an ambiguous history. Fail closed.
    return undefined
  }
}

/**
 * The strike a retirement entry ALREADY published, recomputed by re-running
 * {@link attributeRetiredCredentialRungs} over the log as it stood just before
 * that entry. A resumed ceremony reports what its first run reported this way,
 * rather than through a second definition of "unclaimed" that could answer
 * differently.
 *
 * The entry is located by the key it authorized: every ceremony that calls
 * this detects its own completion by that key standing in `updateKeys`, and
 * the entry that FIRST authorized it is the one to walk back to. A log that
 * does not authorize the key, or authorizes it at the genesis entry, has no
 * usable prefix and is refused: a caller that reached this had already seen
 * the key authorized, so either shape is a caller defect rather than a
 * state to answer for.
 *
 * @param options {object}
 * @param options.log {DIDLog}   the post-entry log
 * @param options.authorizedKeyMultibase {string}   the update key the entry
 *   authorized
 * @param options.credentialVmIds {string[]}   the credentials the entry
 *   retired, as the caller derived them from the log
 * @param [options.protectedHashes] {string[]}   the same set the first run
 *   passed
 * @param [options.protectedKeys] {string[]}   likewise
 * @param [options.maxScan] {number}
 * @returns {Promise<{ struckHashes: string[], struckKeys: string[],
 *   unclaimedCredentialVmIds: string[] }>}
 */
export async function retiredCredentialRungsBeforeKey({
  log,
  authorizedKeyMultibase,
  credentialVmIds,
  protectedHashes = [],
  protectedKeys = [],
  maxScan = LADDER_MAX_SCAN
}: {
  log: DIDLog
  authorizedKeyMultibase: string
  credentialVmIds: string[]
  protectedHashes?: string[]
  protectedKeys?: string[]
  maxScan?: number
}): Promise<{
  struckHashes: string[]
  struckKeys: string[]
  unclaimedCredentialVmIds: string[]
}> {
  const params = effectiveParameters(log)
  const entryIndex = params.findIndex(entry =>
    entry.updateKeys.includes(authorizedKeyMultibase)
  )
  if (entryIndex <= 0) {
    throw new Error(
      `retiredCredentialRungsBeforeKey: the log ${
        entryIndex < 0 ? 'never authorizes' : 'authorizes at genesis'
      } update key ${authorizedKeyMultibase}, so no pre-entry prefix exists`
    )
  }
  return attributeRetiredCredentialRungs({
    log: log.slice(0, entryIndex),
    credentialVmIds,
    protectedHashes,
    protectedKeys,
    maxScan
  })
}

/**
 * What a full retirement must strike from the standing parameters for a set of
 * credentials being retired in one entry: their committed rung hashes, and any
 * rung of theirs standing revealed in `updateKeys`. Each credential is
 * anchored from the log alone ({@link credentialLadderAnchor}), so a cold
 * browser holding no registry and no seed can still strike them.
 *
 * The bias is under-striking, deliberately. Over-striking is silent and
 * unhealable -- a surviving credential or client keeps its verification
 * methods and its roster wrap, and only fails when someone finally uses it --
 * while under-striking leaves a committed rung a retired credential's holder
 * could reveal, which the report names. Five things keep it that way:
 *
 * - a credential whose anchor is ambiguous or whose walk refuses is reported
 *   as unclaimed and nothing of its is struck;
 * - only what the walk positively claims is a candidate;
 * - a hash or key the caller names as its own (`protectedHashes` /
 *   `protectedKeys`, the successors the entry itself commits) is dropped;
 * - every SURVIVING enrolled client's active update key, its carry-over hash
 *   and its staged hash are dropped, whatever the walk claimed
 *   ({@link survivingClientKeyProtection}). That guard is structural rather
 *   than a property of the walk, because a mis-anchored walk landing on a
 *   client's key would otherwise end that client's ability to extend the
 *   account log for good. The walks therefore run FIRST, and the hashes they
 *   claimed are passed to the protection as known-latent, so a retiring
 *   credential's own rung cannot make a client's staged attribution ambiguous
 *   and get itself protected as a candidate;
 * - a listed enrolled client whose ACTIVE update key the log cannot attribute
 *   withholds the WHOLE strike: nothing is struck and every credential is
 *   reported, since the structural guard cannot say what that client holds.
 *
 * The report is a not-fully-retired report rather than a nothing-happened one.
 * A credential appears on `unclaimedCredentialVmIds` when its walk refused,
 * when it claimed nothing, AND when any single hash or key it claimed was
 * withheld by one of the kept sets. The rest of that credential's claims are
 * still struck; what the caller must not be told is that a partial retirement
 * was a whole one.
 *
 * @param options {object}
 * @param options.log {DIDLog}   a resolved, caller-verified log, read BEFORE
 *   the entry is built
 * @param options.credentialVmIds {string[]}   the retiring credentials'
 *   `keyAgreement` verification-method ids
 * @param [options.protectedHashes] {string[]}   hashes the entry itself
 *   commits, never struck
 * @param [options.protectedKeys] {string[]}   update keys the entry itself
 *   authorizes, never struck
 * @param [options.maxScan] {number}   the ladder walk's bound
 * @returns {Promise<{ struckHashes: string[], struckKeys: string[],
 *   unclaimedCredentialVmIds: string[] }>}
 */
export async function attributeRetiredCredentialRungs({
  log,
  credentialVmIds,
  protectedHashes = [],
  protectedKeys = [],
  maxScan = LADDER_MAX_SCAN
}: {
  log: DIDLog
  credentialVmIds: string[]
  protectedHashes?: string[]
  protectedKeys?: string[]
  maxScan?: number
}): Promise<{
  struckHashes: string[]
  struckKeys: string[]
  unclaimedCredentialVmIds: string[]
}> {
  // The walks first, so what they claimed can be vouched for as latent when
  // the surviving clients' staged hashes are attributed below.
  const claims = new Map<string, LadderStandingInventory | undefined>()
  const claimedHashes = new Set<string>()
  for (const credentialVmId of credentialVmIds) {
    const inventory = await claimLadderInventory({
      log,
      credentialVmId,
      maxScan
    })
    claims.set(credentialVmId, inventory)
    for (const hash of inventory?.committedHashes ?? []) {
      claimedHashes.add(hash)
    }
  }

  // The structural guard, resolved once from the log rather than per
  // credential: what the account's surviving enrolled clients hold.
  const surviving = await survivingClientKeyProtection({
    log,
    retiredVmIds: credentialVmIds,
    knownLatentHashes: [...claimedHashes]
  })
  if (surviving.ambiguous.length > 0) {
    logger.warn(
      'Withholding a credential rung strike: an enrolled client whose ' +
        'active update key the log cannot attribute would be unprotected',
      { clients: surviving.ambiguous }
    )
    return {
      struckHashes: [],
      struckKeys: [],
      unclaimedCredentialVmIds: [...credentialVmIds]
    }
  }

  const keptHashes = new Set([...protectedHashes, ...surviving.hashes])
  const keptKeys = new Set([...protectedKeys, ...surviving.keys])
  const struckHashes = new Set<string>()
  const struckKeys = new Set<string>()
  const unclaimedCredentialVmIds: string[] = []
  for (const credentialVmId of credentialVmIds) {
    const inventory = claims.get(credentialVmId)
    if (inventory === undefined) {
      unclaimedCredentialVmIds.push(credentialVmId)
      continue
    }
    let withheld = false
    let struckAny = false
    for (const hash of inventory.committedHashes) {
      if (keptHashes.has(hash)) {
        withheld = true
        continue
      }
      struckHashes.add(hash)
      struckAny = true
    }
    for (const key of inventory.revealedKeys) {
      if (keptKeys.has(key)) {
        withheld = true
        continue
      }
      struckKeys.add(key)
      struckAny = true
    }
    if (withheld || !struckAny) {
      unclaimedCredentialVmIds.push(credentialVmId)
    }
  }
  return {
    struckHashes: [...struckHashes],
    struckKeys: [...struckKeys],
    unclaimedCredentialVmIds
  }
}

/**
 * Attributes a ladder's FULL standing inventory from the log -- the retirement
 * counterpart of {@link attributeLadderRung}, which recovers only the single
 * current rung. Retiring a credential must strike every standing artifact its
 * ladder accounts for, so this walks the log's effective parameters forward
 * from an anchor (the recorded bind-time rung, however stale) and tracks the
 * ladder's inventory entry by entry:
 *
 * - a newly authorized key whose hash was a known ladder commitment is a rung
 *   REVEAL; the hashes that entry newly commits are claimed by the ladder,
 *   as are those of any later entry the ladder itself signed, since the
 *   rung's authority stood behind them. Hashes an entry signed by some other
 *   key commits stay OUT, even while the rung sits in `updateKeys`: a rung
 *   stands revealed indefinitely after a forget (and after a torn
 *   self-enrollment), and the account's enrolled clients go on extending the
 *   log the whole time. One exception, the HANDOVER: when the revealed rung's
 *   hash was committed earlier by a key the revealing entry itself retires
 *   (the recovery continuation -- the spent code commits the fresh
 *   credential's `hash(rung 0)` and `hash(rung 1)` adjacently with the
 *   replacement code's hash last, then the add entry revealing rung 0 strikes
 *   the code), the hash committed immediately after the rung's in that entry,
 *   when it is not the entry's last addition, is the ladder's next commitment
 *   and is claimed too, so a seed-less walk over a continuation log sees
 *   rung 1;
 * - the entry that retires the revealed rung while authorizing a key whose
 *   hash sits among those claims is the enrollment's COMPLETION: the new
 *   client's update-key hash and the claim committed immediately after it
 *   (its staged hash -- a reveal-and-commit entry appends the credential's
 *   own next commitment LAST among its newly committed hashes, the ordering
 *   convention in `decisions/0007-ladder-reveal-hash-order.md`) transfer to
 *   the client and stop being ladder-owned. What the completion did not
 *   transfer stays ladder-owned only where the ladder can say so POSITIVELY:
 *   the hash derives from the ladder's own seed (or is the recorded key's),
 *   or the credential itself survives the completing entry, which is what
 *   makes the residue its next standing commitment. A SPEND -- the recovery
 *   continuation, whose one entry retires the code's own inventory and
 *   publishes its successor's -- leaves the replacement credential's
 *   commitment in that position instead, and striking that would leave the
 *   replacement unusable and unhealable;
 * - a claim or revealed key that later leaves the parameters without a
 *   completion was struck by some other edit and simply stops standing;
 * - a ladder VM standing in the final document belongs to this ladder on
 *   either of two arms, asked at the entry that PUBLISHED it (the entry at
 *   which the id appeared among the document's ladder VMs). The SIGNER arm:
 *   that entry was signed by a key this ladder accounted for at that point,
 *   which covers every install a ladder rung signs (the ladder-anchored
 *   genesis, the ladder-VM install, the transient recovery's add-and-retire
 *   entry). The CO-INTRODUCTION arm: that entry also introduced this
 *   credential's own `keyAgreement` member (`credentialVmId`), which is what
 *   reaches a bind entry an ENROLLED CLIENT signed -- the shape
 *   `publishUnlockKey` writes, whose signer is the binding client's update
 *   key rather than a rung. Three guards keep that arm from over-claiming:
 *   it needs `credentialVmId` in hand, the entry must introduce exactly ONE
 *   credential-class `keyAgreement` member (the account-controlled class,
 *   `credentialKeyAgreementMethods`; the transient recovery entry introduces
 *   two and is left to the signer arm), and the entry must introduce exactly
 *   ONE ladder VM. The question is anchored rather than free-standing: it
 *   answers "is this VM mine", and a VM no anchored ladder claims is
 *   identified by subtraction and left standing, since striking a key this
 *   ladder cannot show it owns would take out a surviving credential's.
 *   The COMMITMENT arm: that entry committed a hash the ladder knows a priori
 *   (the anchor's, a seed-derived rung's, or one the backward pre-pass
 *   recovered), introduced exactly one ladder VM, and introduced no OTHER
 *   credential's `keyAgreement` member. It reaches the reinstall an
 *   `establishStandingUnlock` re-run writes, which mints a fresh ladder seed
 *   for a credential whose member already stands, so neither of the other
 *   arms can see it. Like the co-introduction arm it needs `credentialVmId`
 *   in hand, since with no id the foreign-member guard would pass vacuously.
 *
 * The attribution is anchor-invariant across the shapes where each rung's
 * hash was committed by an entry that also revealed the previous rung, or by
 * a handover. The signer arm's key set is the anchor plus every earlier rung
 * a backward pre-pass recovers from the log's own positional rules ({@link
 * recoverEarlierRungs}, over `decisions/0007-ladder-reveal-hash-order.md`),
 * so an entry a spent rung signed is attributed however far the anchor has
 * since climbed. The ladder seed (`ladderSeed`) remains a shortcut and a
 * cross-check rather than a requirement: it makes every rung's key and hash
 * known outright and skips the pre-pass. A residue no arm can attribute is
 * still released -- the retirement then strikes what the recorded inventory
 * names and nothing more. More than one ladder reveal standing or arriving at
 * once matches no legitimate history and fails closed ({@link
 * LadderAttributionError}).
 *
 * One shape is out of reach seedlessly, and it is reachable today. The
 * last-client transition strikes the ladder VM and reinstalls it in the same
 * run (`forgetLastEnrolledClient` stage 1): same seed, the credential's
 * member standing, the acting rung's hash still committed, and no hash added.
 * A later self-enrollment then spends that already-revealed rung, so its
 * reveal-and-commit entry authorizes no key while committing the next rung's
 * hash, and the registry anchor advances to that next rung. The backward walk
 * climbs from the anchor by asking which key the entry that committed its
 * hash authorized; that entry authorized none, so the walk cannot name the
 * rung that signed it, and the earlier rung and the reinstalled VM go
 * unrecovered. A seedless retirement then reports the VM as `unclaimed` and
 * leaves it standing. Tracked as WC-158.
 *
 * The anchor comes in three forms, and the walk is the same afterwards. A
 * recorded update-key multibase (`anchorKeyMultibase`) is what a caller
 * holding a registry entry passes. A hash (`anchorHash`) is the same anchor
 * with the key withheld: the rung is picked up when the log reveals it, since
 * the reveal test already matches on the commitment. With neither, and a
 * `credentialVmId` in hand, the anchor is read off the credential's bind entry
 * ({@link credentialLadderAnchor}) -- the cold-browser mode, where no registry
 * is readable before the entry is written. An anchor the bind entry cannot
 * name unambiguously refuses with {@link LadderAttributionError} rather than
 * walking from a guess.
 *
 * @param options {object}
 * @param options.log {DIDLog}   a resolved, caller-verified log
 * @param [options.anchorKeyMultibase] {string}   the credential's recorded
 *   update-key multibase (bind-time rung 0, or a refreshed later rung)
 * @param [options.anchorHash] {string}   the same anchor as a committed hash,
 *   for a caller that resolved one without the key
 * @param [options.ladderSeed] {Uint8Array}   the credential's ladder seed,
 *   when the caller holds it
 * @param [options.credentialVmId] {string}   the credential's own
 *   `keyAgreement` verification-method id, which tells a climb (the
 *   credential stands afterwards) from a spend (its inventory goes in the same
 *   entry), which the ladder VM's co-introduction arm is anchored on, and
 *   which supplies the anchor itself when neither anchor form is passed
 * @param [options.maxScan] {number}   seeded pre-derivation bound; defaults to
 *   {@link LADDER_MAX_SCAN}
 * @returns {Promise<LadderStandingInventory>}   what currently stands; every
 *   array empty when the log carries nothing of the ladder any more
 */
export async function attributeLadderInventory({
  log,
  anchorKeyMultibase,
  anchorHash: suppliedAnchorHash,
  ladderSeed,
  credentialVmId,
  maxScan = LADDER_MAX_SCAN
}: {
  log: DIDLog
  anchorKeyMultibase?: string
  anchorHash?: string
  ladderSeed?: Uint8Array
  credentialVmId?: string
  maxScan?: number
}): Promise<LadderStandingInventory> {
  const { params, facts, commitIndex } = indexedLadderLog(log)
  // The anchor, in the caller's order of preference: the recorded update key,
  // a hash the caller resolved itself, or -- holding neither, the cold-browser
  // case -- the credential's own bind entry, read off the log.
  let anchorKey = anchorKeyMultibase
  let anchorHash = suppliedAnchorHash
  if (anchorKey === undefined && anchorHash === undefined) {
    const resolved =
      credentialVmId === undefined
        ? undefined
        : resolveBindAnchor({ log, facts, credentialVmId })
    if (resolved === undefined) {
      throw new LadderAttributionError(
        'The ladder walk was given no anchor, and the log does not name an ' +
          'unambiguous bind entry for this credential; refusing to ' +
          'attribute an ambiguous history.'
      )
    }
    anchorKey = resolved.anchorKeyMultibase
    anchorHash = resolved.anchorHash
  }
  if (anchorHash === undefined) {
    anchorHash = await deriveNextKeyHash(anchorKey!)
  }
  const ladderKeys = new Set<string>(anchorKey === undefined ? [] : [anchorKey])
  // What the ladder knows a priori: the recorded key's hash and, with the
  // seed in hand, every rung's. A claim outside this set is held on the
  // evidence of the entry that committed it, and released again when a
  // completion shows it was never the ladder's.
  const derivedHashes = new Set<string>([anchorHash])
  const ladderHashes = new Set<string>([anchorHash])
  if (ladderSeed) {
    for (let index = 0; index < maxScan; index++) {
      const rung = await ladderRung({ ladderSeed, index })
      ladderKeys.add(rung.keyMultibase)
      const rungHash = await deriveNextKeyHash(rung.keyMultibase)
      derivedHashes.add(rungHash)
      ladderHashes.add(rungHash)
    }
  }

  // Without the seed, the anchor alone would hide every entry a spent rung
  // signed. Recover those rungs from the log's positional rules first, and
  // treat them exactly as seed-derived ones: known a priori, on both sets.
  if (!ladderSeed && credentialVmId !== undefined) {
    const earlier = await recoverEarlierRungs({
      log,
      facts,
      commitIndex,
      anchorHash,
      credentialVmId,
      maxScan
    })
    for (const rung of earlier) {
      ladderKeys.add(rung.key)
      derivedHashes.add(rung.hash)
      ladderHashes.add(rung.hash)
    }
  }

  let pending: { key: string; claims: string[] } | undefined
  let prevHashes = new Set<string>()
  // Whether the entry that published each ladder VM seen so far was signed by
  // a key this ladder accounted for at that point. Re-answered at every
  // publication, so a VM struck and later republished by another ladder is
  // attributed to whoever put the standing copy there.
  let prevLadderVmIds = new Set<string>()
  let prevEntryDoc: KeyAgreementDocument | undefined
  const ladderVmClaims = new Map<string, boolean>()
  // The account DID, read off the credential's own verification-method id:
  // the co-introduction arm needs it to tell a credential-class
  // `keyAgreement` member (controlled by the account) from an enrolled
  // client's marked twin.
  const credentialDid = credentialVmId?.split('#')[0]
  for (const [index, entry] of params.entries()) {
    const currentUpdateKeys = new Set(entry.updateKeys)
    // The pre-pass keeps these order-preserving on purpose: the completion
    // transfer below reads the claim committed immediately after the client's
    // update-key hash as its staged hash (the reveal entry's append order, a
    // ratified convention).
    const { addedKeys, removedKeys, addedHashes } = facts[index]!

    // Completion first: the pending revealed rung left `updateKeys`. When the
    // same entry authorizes a key whose hash sits among the reveal's claims,
    // the enrollment completed -- that hash and its successor (the client's
    // staged hash) transfer to the client. A rung leaving any other way was
    // struck, and its claims simply stop standing.
    if (pending && !currentUpdateKeys.has(pending.key)) {
      const transferred = new Set<string>()
      for (const key of addedKeys) {
        const at = pending.claims.indexOf(await deriveNextKeyHash(key))
        if (at === -1) {
          continue
        }
        transferred.add(pending.claims[at]!)
        const staged = pending.claims[at + 1]
        if (staged !== undefined) {
          transferred.add(staged)
        }
        break
      }
      // What the reveal committed and the completion did not transfer is
      // ladder-owned only on positive attribution -- a hash the ladder
      // derives itself, or any residue of a ceremony the credential came out
      // of still standing (a climb, whose residue really is its next rung's
      // commitment). A spend's residue is its SUCCESSOR's commitment, and
      // striking that is silent, unhealable damage: the replacement keeps its
      // verification method and its roster wrap, and only fails when someone
      // finally types it.
      const stands = credentialSurvives({
        entry: log[index],
        vmId: credentialVmId
      })
      for (const hash of pending.claims) {
        if (transferred.has(hash) || !(stands || derivedHashes.has(hash))) {
          ladderHashes.delete(hash)
        }
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
      // The HANDOVER: a rung whose hash some OTHER key committed earlier, in
      // an entry this reveal retires the signer of. That is the recovery
      // continuation's shape -- the spent code's reveal-and-commit entry
      // commits the fresh credential's `hash(rung 0)` and `hash(rung 1)`
      // adjacently and the replacement code's hash last, and the
      // add-and-retire entry revealing rung 0 strikes the code -- and it is
      // the one case in which a hash another key committed belongs to this
      // ladder: the committer was handing its standing over, not committing
      // for itself. The hash appended immediately after the rung's in that
      // entry is the ladder's next commitment, provided it is not the entry's
      // LAST addition: what an entry hands to a successor credential comes
      // last (the adjacency and the last-position rule both in
      // `decisions/0007-ladder-reveal-hash-order.md`). The condition is
      // reachable outside the continuation -- a forget entry reveals the rung
      // while retiring the client that signed the bind -- and stays inert
      // there only because a bind appends its one hash last. It is a CLAIM
      // like the rest: the completion below still releases it unless the
      // credential survives or the seed derives it.
      const keyHash = await deriveNextKeyHash(key)
      const origin = prevHashes.has(keyHash)
        ? commitIndex.get(keyHash)
        : undefined
      const originFacts =
        origin === undefined ? undefined : facts[origin.entryIndex]
      if (origin !== undefined && originFacts !== undefined) {
        const successor = originFacts.addedHashes[origin.at + 1]
        const successorLast = origin.at + 2 === originFacts.addedHashes.length
        if (
          successor !== undefined &&
          !successorLast &&
          originFacts.signers.some(signer => removedKeys.includes(signer))
        ) {
          pending.claims.unshift(successor)
          ladderHashes.add(successor)
        }
      }
    } else if (pending && ladderSigned({ entry: log[index], ladderKeys })) {
      // The rung is still revealed AND signed this entry, so the hashes it
      // commits were committed under the rung's authority and join its
      // claims.
      // Signature, not mere presence in `updateKeys`, is what attributes
      // them: the rung's reveal outlives the ceremony that revealed it, so
      // claiming everything committed afterwards would sweep up hashes of
      // other credentials and of racing enrollments -- and striking those on
      // retirement is silent, unhealable damage.
      pending.claims.push(...addedHashes)
      for (const hash of addedHashes) {
        ladderHashes.add(hash)
      }
    }

    // After the reveal branch, so a VM installed by the very entry that
    // reveals the rung signing it (the ladder-anchored genesis, the ladder-VM
    // install) is attributed to this ladder rather than missed.
    const entryDoc = log[index]?.state as
      | (KeyAgreementDocument & {
          capabilityInvocation?: Array<string | { id?: string }>
          capabilityDelegation?: Array<string | { id?: string }>
        })
      | undefined
    const publishedVmIds = entryDoc ? ladderVmIds({ doc: entryDoc }) : []
    const newVmIds = publishedVmIds.filter(vmId => !prevLadderVmIds.has(vmId))
    // The co-introduction arm, under its three guards (see the header): one
    // new ladder VM, one newly introduced credential-class `keyAgreement`
    // member, and that member is this credential's. It is what reaches the
    // bind entry an enrolled client signs, which no rung stands behind.
    const introduced =
      credentialDid !== undefined && entryDoc !== undefined
        ? introducedCredentialKeys({
            doc: entryDoc,
            prevDoc: prevEntryDoc,
            did: credentialDid
          })
        : []
    const coIntroduced =
      credentialVmId !== undefined &&
      newVmIds.length === 1 &&
      introduced.length === 1 &&
      introduced[0] === credentialVmId
    // The COMMITMENT arm (see the header): the entry committed a hash this
    // ladder knows a priori, published one ladder VM, and introduced no other
    // credential's member. `derivedHashes` rather than `ladderHashes`: a hash
    // held on the evidence of the entry that committed it is not proof of
    // ownership, and reading one here would claim a VM on a claim the
    // completion may yet release. It needs `credentialVmId` in hand for the
    // same reason the co-introduction arm does: with no id, `introduced` is
    // empty and the foreign-member guard would pass vacuously.
    const commitmentClaimed =
      credentialVmId !== undefined &&
      newVmIds.length === 1 &&
      addedHashes.some(hash => derivedHashes.has(hash)) &&
      introduced.every(id => id === credentialVmId)
    for (const vmId of newVmIds) {
      ladderVmClaims.set(
        vmId,
        coIntroduced ||
          commitmentClaimed ||
          ladderSigned({ entry: log[index], ladderKeys })
      )
    }
    prevLadderVmIds = new Set(publishedVmIds)
    prevEntryDoc = entryDoc

    prevHashes = new Set(entry.nextKeyHashes)
  }

  const final = currentLogParameters({ log })
  return {
    revealedKeys: final.updateKeys.filter(key => ladderKeys.has(key)),
    committedHashes: final.nextKeyHashes.filter(hash => ladderHashes.has(hash)),
    ladderVmIds: [...prevLadderVmIds].filter(
      vmId => ladderVmClaims.get(vmId) === true
    )
  }
}
