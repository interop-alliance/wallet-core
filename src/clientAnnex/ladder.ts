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
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import {
  effectiveParameters,
  relationIds,
  updateKeyMultibase
} from '../webvh/didWebvh.js'
import { ladderVmIds } from '../webvh/listClients.js'
import {
  credentialKeyAgreementMethods,
  type KeyAgreementDocument
} from '../webvh/keyAgreement.js'
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
    const keyMultibase = proof.verificationMethod?.split('#')[1]
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
 *
 * With the ladder seed in hand (`ladderSeed`), every rung's key and hash are
 * additionally known a priori, so the attribution does not depend on the
 * anchor being current; without it, the walk is anchored on
 * `anchorKeyMultibase` and on `credentialVmId` alone, and a residue neither
 * can attribute is released -- the retirement then strikes what the recorded
 * inventory names and nothing more. More than one ladder reveal standing or
 * arriving at once matches no legitimate history and fails closed
 * ({@link LadderAttributionError}).
 *
 * @param options {object}
 * @param options.log {DIDLog}   a resolved, caller-verified log
 * @param options.anchorKeyMultibase {string}   the credential's recorded
 *   update-key multibase (bind-time rung 0, or a refreshed later rung)
 * @param [options.ladderSeed] {Uint8Array}   the credential's ladder seed,
 *   when the caller holds it
 * @param [options.credentialVmId] {string}   the credential's own
 *   `keyAgreement` verification-method id, which tells a climb (the
 *   credential stands afterwards) from a spend (its inventory goes in the same
 *   entry), and which the ladder VM's co-introduction arm is anchored on
 * @param [options.maxScan] {number}   seeded pre-derivation bound; defaults to
 *   {@link LADDER_MAX_SCAN}
 * @returns {Promise<LadderStandingInventory>}   what currently stands; every
 *   array empty when the log carries nothing of the ladder any more
 */
export async function attributeLadderInventory({
  log,
  anchorKeyMultibase,
  ladderSeed,
  credentialVmId,
  maxScan = LADDER_MAX_SCAN
}: {
  log: DIDLog
  anchorKeyMultibase: string
  ladderSeed?: Uint8Array
  credentialVmId?: string
  maxScan?: number
}): Promise<LadderStandingInventory> {
  const anchorHash = await deriveNextKeyHash(anchorKeyMultibase)
  const ladderKeys = new Set<string>([anchorKeyMultibase])
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

  const params = effectiveParameters(log)
  let pending: { key: string; claims: string[] } | undefined
  let prevUpdateKeys = new Set<string>()
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
  // Where each standing hash was FIRST committed: the entry's signers, the
  // hash appended immediately after it there, and whether that successor
  // closed the entry's additions. Read back at a reveal whose committing
  // entry the reveal itself retires (below).
  const firstCommit = new Map<
    string,
    { signers: string[]; successor: string | undefined; successorLast: boolean }
  >()
  for (const [index, entry] of params.entries()) {
    const currentUpdateKeys = new Set(entry.updateKeys)
    const addedKeys = entry.updateKeys.filter(key => !prevUpdateKeys.has(key))
    const removedKeys = [...prevUpdateKeys].filter(
      key => !currentUpdateKeys.has(key)
    )
    // Order-preserving on purpose: the completion transfer below reads the
    // claim committed immediately after the client's update-key hash as its
    // staged hash (the reveal entry's append order, a ratified convention).
    const addedHashes = entry.nextKeyHashes.filter(
      hash => !prevHashes.has(hash)
    )
    const signers = entrySigners({ entry: log[index] })
    addedHashes.forEach((hash, at) => {
      if (!firstCommit.has(hash)) {
        firstCommit.set(hash, {
          signers,
          successor: addedHashes[at + 1],
          successorLast: at + 2 === addedHashes.length
        })
      }
    })

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
        ? firstCommit.get(keyHash)
        : undefined
      if (
        origin?.successor !== undefined &&
        !origin.successorLast &&
        origin.signers.some(signer => removedKeys.includes(signer))
      ) {
        pending.claims.unshift(origin.successor)
        ladderHashes.add(origin.successor)
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
    for (const vmId of newVmIds) {
      ladderVmClaims.set(
        vmId,
        coIntroduced || ladderSigned({ entry: log[index], ladderKeys })
      )
    }
    prevLadderVmIds = new Set(publishedVmIds)
    prevEntryDoc = entryDoc

    prevUpdateKeys = currentUpdateKeys
    prevHashes = new Set(entry.nextKeyHashes)
  }

  const final = params[params.length - 1] ?? {
    updateKeys: [],
    nextKeyHashes: []
  }
  return {
    revealedKeys: final.updateKeys.filter(key => ladderKeys.has(key)),
    committedHashes: final.nextKeyHashes.filter(hash => ladderHashes.has(hash)),
    ladderVmIds: [...prevLadderVmIds].filter(
      vmId => ladderVmClaims.get(vmId) === true
    )
  }
}
