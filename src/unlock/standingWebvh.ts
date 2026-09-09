/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The did:webvh INVENTORY half of the standing unlock-credential lifecycle: the
 * split configuration every unlock method holds under the standing model, as one
 * merged add/remove document edit.
 *
 * At bind time the document gains the credential's `keyAgreement` entry --
 * the key verbatim for a high-entropy credential (a passkey PRF output, a
 * recovery code), or a `MultikeyCommitment` entry for a low-entropy-derived
 * key (a passphrase), so the world-readable document carries a check on the
 * key without carrying the key -- and `nextKeyHashes` gains the hash of the
 * credential's current update key (a ladder rung, or a code's single derived
 * key). A credential that carries a ladder gains its LADDER VM in the same
 * entry, under `assertionMethod` and `capabilityDelegation`: the VM's life is
 * the credential's, installed when it becomes standing and struck when it
 * retires, and enrollment never touches it.
 * Decryption standing, authority latent: the credential's update key joins
 * `updateKeys` nowhere, and the key-agreement entry is deliberately unmarked,
 * so client listings (keyed on `capabilityInvocation`) and revocation
 * removals never see it; the VM's relation asymmetry keeps it out of the same
 * listings. {@link publishUnlockKey} / {@link removeUnlockKey} are one merged
 * add/remove pair, shared verbatim by the recovery-code wrappers.
 *
 * The ceremonies that EXERCISE a credential's ladder against the account log
 * -- the ladder-anchored genesis, the self-enrolling continuation, the
 * one-entry forget -- live in `clientAnnex/ladderAnchored.ts`. What stays
 * here is the verify-side half every wallet needs regardless of account configuration.
 */
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import type {
  DIDDoc,
  DIDLog,
  VerificationMethod
} from '@interop/did-method-webvh'
import {
  MULTIKEY_COMMITMENT_VM_TYPE,
  MULTIKEY_VM_TYPE,
  ladderVerificationMethod,
  readPublishedLogOrThrow,
  withLogConflictRetry
} from '../webvh/didWebvh.js'
import { signAccountEntry } from '../webvh/accountEntry.js'
import type { AccountLogSigner } from '../webvh/accountEntry.js'
import { preEntryProjectionPublisher } from '../webvh/didWebProjection.js'
import { ladderVmIds, relationIds } from '../resourceLog/document.js'
import type { WebvhIdStore } from '../webvh/didWebvh.js'
// The one deliberate base-side dependency on the annex subpath, pinned as an
// exception in the lint rule: this module resolves a credential's CURRENT
// ladder inventory from the log itself (the shared attribution helpers in
// `clientAnnex/ladder.ts`), never touching the annex log machinery, and
// derives the credential's ladder VM from its seed at the install.
import {
  attributeLadderInventory,
  credentialLadderAnchor,
  credentialLadderCommitment,
  LadderAttributionError,
  ladderRung,
  ladderVmIdsIntroducedWithCredential,
  ladderVmKeyMultibase,
  type LadderStandingInventory
} from '../clientAnnex/ladder.js'

/**
 * The narrow store seam the self-enrolling and delegated-bridge ceremonies
 * write through: a public read of the log and the delegated `did.jsonl` PUT.
 * A subset of {@link WebvhIdStore}, so an app's remote-store class satisfies
 * it too.
 */
export type UnlockLogStore = Pick<
  WebvhIdStore,
  'getIdResourceRaw' | 'putIdResource' | 'pin'
>

/**
 * Which half of a credential's inventory one bind entry carries. `'all'` is
 * the merged entry: the `keyAgreement` member, the update-key commitment, and
 * the ladder VM together. The split halves exist for a ceremony that must
 * land the credential's decryption material before its authority: `'key'`
 * publishes the `keyAgreement` member alone, `'authority'` installs the
 * ladder VM and commits the rung-0 hash.
 */
export type UnlockInventoryPart = 'all' | 'key' | 'authority'

/**
 * A retirement whose ladder attribution could not claim the retired
 * credential's ladder VM, refused with nothing written. The shape is the
 * seedless strike claiming nothing: the credential still stands in the
 * document, the walk struck no ladder VM, and ladder VMs stand there that it
 * could not claim. A leftover VM would keep the retired credential's
 * delegation authority alive -- under `capabilityDelegation` it can still
 * sign a DELETE-only capability on the account Space -- and nothing
 * downstream can tell such a leftover from a sibling credential's standing
 * VM, so the retirement is the one place the state can be closed
 * (`decisions/0015`).
 *
 * `unclaimedLadderVmIds` names every ladder VM the walk left unclaimed, and
 * `anchorKeyMultibase` the update key the walk was anchored on (a recovery
 * code's revocation anchors on the rung-0 multibase the registry recorded at
 * issuance). On a
 * multi-credential account that list carries the siblings' VMs beside the
 * retired credential's, since telling them apart is exactly what the walk
 * could not do. `retryableWithLadderSeed` says whether a retry supplying the
 * credential's ladder seed can let attribution succeed. The gate raises this
 * error only from a seedless claim (a seeded one either strikes the derived
 * VM or proves there is none), so the hint is `true` from this library; the
 * member is the wallets' read for the retry they offer.
 * Matched on `name` (the error crosses app-injected seams that may resolve
 * to another copy of this package).
 */
export class UnclaimedLadderVmRetirementError extends Error {
  readonly unclaimedLadderVmIds: string[]
  readonly retryableWithLadderSeed: boolean
  readonly anchorKeyMultibase?: string

  constructor({
    unclaimedLadderVmIds,
    retryableWithLadderSeed,
    anchorKeyMultibase
  }: {
    unclaimedLadderVmIds: string[]
    retryableWithLadderSeed: boolean
    anchorKeyMultibase?: string
  }) {
    super(
      "did:webvh: the retirement cannot claim the retired credential's ladder " +
        `VM (standing unclaimed: ${unclaimedLadderVmIds.join(', ')}` +
        (anchorKeyMultibase === undefined
          ? ''
          : `; anchored on ${anchorKeyMultibase}`) +
        '); nothing was published and the credential still stands. ' +
        (retryableWithLadderSeed
          ? "Retry with the credential's ladder seed in hand."
          : 'No retry with the ladder seed can claim it.')
    )
    this.name = 'UnclaimedLadderVmRetirementError'
    this.unclaimedLadderVmIds = unclaimedLadderVmIds
    this.retryableWithLadderSeed = retryableWithLadderSeed
    if (anchorKeyMultibase !== undefined) {
      this.anchorKeyMultibase = anchorKeyMultibase
    }
  }
}

/**
 * What the removal edit says about ladder VMs: `struck`, the ids this entry
 * removed from the document, and `unclaimed`, the ladder VMs still standing
 * afterwards that this credential's attribution could not claim.
 *
 * `unclaimed` is information, and the caller cannot read an orphan out of it
 * by subtraction alone: a VM standing here may perfectly well be a SIBLING
 * credential's, which this ladder has no business claiming. The gate that
 * refuses the seedless strike claiming nothing is narrower
 * ({@link assertLadderVmClaimed}): it reads `struck` empty beside a
 * non-empty `unclaimed` while the credential itself still stands, and it
 * runs only for a credential that carries a ladder.
 */
export interface LadderVmRemovalReport {
  struck: string[]
  unclaimed: string[]
}

/**
 * How a credential's key-agreement key is published in the document: the key
 * verbatim (a high-entropy credential -- passkey PRF, recovery code), or its
 * hash commitment (`keyAgreementCommitment`) for a low-entropy-derived key.
 * A commitment withholds the key material and gives the roster's recipient
 * resolver a document-anchored check to verify a roster-carried key against.
 */
export type UnlockKeyAgreementPublication =
  { publicKeyMultibase: string } | { commitment: string }

/**
 * A standing credential's public inventory as the document and log carry it:
 * its key-agreement publication and the update key whose hash stands in
 * `nextKeyHashes` (ladder rung 0 at bind time, for every credential kind).
 */
export interface StandingUnlockKeys {
  keyAgreement: UnlockKeyAgreementPublication
  updateKeyMultibase: string
}

/**
 * The verification-method id a credential's key-agreement entry publishes
 * under: `<did>#<multibase>` for a verbatim key (indistinguishable by id from
 * any other keyAgreement entry), `<did>#<commitment>` for a commitment entry
 * (the commitment string is deterministic, so the id is too).
 *
 * @param options {object}
 * @param options.did {string}   the account's did:webvh
 * @param options.keyAgreement {UnlockKeyAgreementPublication}
 * @returns {string}
 */
export function unlockKeyVmId({
  did,
  keyAgreement
}: {
  did: string
  keyAgreement: UnlockKeyAgreementPublication
}): string {
  const fragment =
    'publicKeyMultibase' in keyAgreement
      ? keyAgreement.publicKeyMultibase
      : keyAgreement.commitment
  return `${did}#${fragment}`
}

/**
 * What of a standing credential's ladder currently stands in the published
 * log, resolved from the two anchors a ceremony holds and cross-checked
 * between them. The registry's recorded update key (`updateKeyMultibase`,
 * rung 0 at bind time or a later rung a self-enrollment advanced it to) is
 * one anchor; the credential's own `keyAgreement` member names the other,
 * its rung-0 commitment (`ladderCommitment`, read by
 * {@link credentialLadderAnchor}). Either one alone can be wrong for this
 * credential -- a registry entry recording another ladder's key, a member a
 * foreign update-key holder restated -- and a walk that trusts one strikes
 * whatever ladder that anchor names. The removal edit uses the result to
 * know what to strike; the retirement ceremony uses it one stage earlier,
 * to name the ladder VM it is about to strike to the pass that re-mints
 * whatever that VM signed for other credentials.
 *
 * Seedless, both walks run when the member names an anchor. The
 * member-anchored walk starts at rung 0 and needs no backward recovery, so
 * it is the complete reading; the registry-anchored walk may start at a
 * later rung and recover the earlier ones from the log's positional rules,
 * which leaves it at best equal and in one reachable history (WC-158)
 * short of the member's. So the registry-anchored inventory must be
 * contained in the member-anchored one, and the member-anchored one is what
 * is returned. Anything else -- the two anchors naming different ladders --
 * refuses with {@link LadderAttributionError}. A member naming no anchor
 * (a split bind torn before its authority entry, a member without the
 * property) leaves the registry walk to answer alone, as before. With the
 * ladder seed in hand the cross-check is direct: the seed's rung-0 hash must
 * be the member's named anchor, and the seeded walk is returned.
 *
 * It lives here rather than in the ceremony because this module is the one
 * base-side holder of the annex attribution helpers (the pinned lint
 * exception).
 *
 * @param options {object}
 * @param options.log {DIDLog}   a resolved, caller-verified log
 * @param options.did {string}   the account DID the log resolves to
 * @param options.unlockKeys {StandingUnlockKeys}   the credential's recorded
 *   public inventory
 * @param [options.ladderSeed] {Uint8Array}   the credential's ladder seed,
 *   when the ceremony holds it
 * @returns {Promise<LadderStandingInventory>}
 */
export async function attributeUnlockLadderInventory({
  log,
  did,
  unlockKeys,
  ladderSeed
}: {
  log: DIDLog
  did: string
  unlockKeys: StandingUnlockKeys
  ladderSeed?: Uint8Array
}): Promise<LadderStandingInventory> {
  const credentialVmId = unlockKeyVmId({
    did,
    keyAgreement: unlockKeys.keyAgreement
  })
  const memberAnchor = credentialLadderAnchor({ log, credentialVmId })
  if (ladderSeed) {
    const rung0 = await ladderRung({ ladderSeed, index: 0 })
    const seedAnchorHash = await deriveNextKeyHash(rung0.keyMultibase)
    if (
      memberAnchor !== undefined &&
      memberAnchor.anchorHash !== seedAnchorHash
    ) {
      throw new LadderAttributionError(
        "The credential's keyAgreement member names a ladder commitment the " +
          'supplied ladder seed does not derive; refusing to act on a ladder ' +
          'the seed and the document disagree about.'
      )
    }
    // The seed derives every rung, so the recorded key adds nothing the walk
    // needs -- and a registry entry recording a sibling's rung would put that
    // key into the claims. The walk anchors on the seed's own rung 0.
    return attributeLadderInventory({
      log,
      anchorHash: seedAnchorHash,
      credentialVmId,
      ladderSeed
    })
  }
  const registryAnchored = await attributeLadderInventory({
    log,
    anchorKeyMultibase: unlockKeys.updateKeyMultibase,
    credentialVmId
  })
  if (memberAnchor === undefined) {
    return registryAnchored
  }
  const memberAnchored = await attributeLadderInventory({
    log,
    anchorHash: memberAnchor.anchorHash,
    credentialVmId
  })
  const contained = (subset: keyof LadderStandingInventory): boolean => {
    const within = new Set(memberAnchored[subset])
    return registryAnchored[subset].every(item => within.has(item))
  }
  if (
    !contained('revealedKeys') ||
    !contained('committedHashes') ||
    !contained('ladderVmIds')
  ) {
    throw new LadderAttributionError(
      "The credential's recorded update key and its keyAgreement member's " +
        'ladder commitment resolve to different ladders; refusing to strike ' +
        'on anchors that disagree.'
    )
  }
  return memberAnchored
}

/**
 * What of the document's ladder VMs a credential's attribution claims: the
 * VM its seed derives (when the ceremony holds one), plus every VM the log
 * attributes to its ladder. Resolved once here and shared by the removal
 * edit, the retirement ceremony's pre-edit stage, and the read-only
 * pre-flight, so the three agree on what is struck and what is left.
 *
 * `struck` is what the removal edit strikes: the derived id when it stands,
 * and the attributed ids. `unclaimed` is every ladder VM standing in the
 * document that neither the seed nor the attribution claims -- on a
 * multi-credential account, the siblings' VMs at least. A supplied seed also
 * cross-checks the attribution: a log attributing a VM the seed does not
 * derive refuses with {@link LadderAttributionError}.
 *
 * @param options {object}
 * @param options.doc {DIDDoc}   the document the attribution ran over
 * @param options.did {string}   the account DID
 * @param options.inventory {LadderStandingInventory}   the credential's
 *   attributed ladder inventory ({@link attributeUnlockLadderInventory})
 * @param [options.ladderSeed] {Uint8Array}   the credential's ladder seed
 * @returns {Promise<{ ladderVmId?: string, struck: string[], unclaimed:
 *   string[] }>}   the seed-derived VM id when a seed was held
 */
export async function ladderVmClaimOf({
  doc,
  did,
  inventory,
  ladderSeed
}: {
  doc: DIDDoc
  did: string
  inventory: LadderStandingInventory
  ladderSeed?: Uint8Array
}): Promise<{ ladderVmId?: string; struck: string[]; unclaimed: string[] }> {
  const ladderVmId = ladderSeed
    ? `${did}#${await ladderVmKeyMultibase({ ladderSeed })}`
    : undefined
  if (ladderVmId !== undefined) {
    const foreign = inventory.ladderVmIds.filter(id => id !== ladderVmId)
    if (foreign.length > 0) {
      throw new LadderAttributionError(
        "The published log attributes a ladder VM this credential's seed " +
          'does not derive; refusing to strike on an ambiguous ' +
          'attribution.'
      )
    }
  }
  const standing = ladderVmIds({ doc })
  const struck = new Set<string>()
  if (ladderVmId !== undefined && standing.includes(ladderVmId)) {
    struck.add(ladderVmId)
  }
  for (const id of inventory.ladderVmIds) {
    struck.add(id)
  }
  const claimed = new Set([
    ...struck,
    ...(ladderVmId !== undefined ? [ladderVmId] : [])
  ])
  return {
    ...(ladderVmId !== undefined ? { ladderVmId } : {}),
    struck: [...struck],
    unclaimed: standing.filter(id => !claimed.has(id))
  }
}

/**
 * The retirement gate (`decisions/0015`): refuses, with
 * {@link UnclaimedLadderVmRetirementError}, a retirement of a
 * ladder-carrying credential whose SEEDLESS claim struck nothing while a
 * ladder VM that COULD BE THIS CREDENTIAL'S stands unclaimed and the
 * credential itself still stands in the document. Deliberately narrower than
 * "`unclaimed` is non-empty", which every retirement on a healthy
 * multi-credential account produces, and narrower again than the standing
 * unclaimed set: a sibling credential's VM is nothing this retirement could
 * leave behind.
 *
 * Which unclaimed VMs are candidates is
 * {@link ladderVmIdsIntroducedWithCredential}'s question, read off the log's
 * entry shapes rather than off an attribution that has already refused: a VM
 * introduced by the entry that introduced this credential's `keyAgreement`
 * member, or by the entry that committed or authorized its anchor (the split
 * bind, whose key and authority entries sit two versions apart). None, and
 * the credential never had a VM to leave standing, so the retirement
 * completes and strikes what it can. That is the torn issuance's orphan -- a
 * credential with a `keyAgreement` member, no ladder VM, and no committed
 * rung -- which previously could never be removed at all, since a sibling's
 * standing VM refused it forever.
 *
 * Two shapes pass ahead of that. A credential whose `keyAgreement` member is
 * already gone is a completed retirement re-running. And a claim resolved
 * WITH the seed never refuses: the derived VM is either standing (and
 * struck) or absent, and an absent derived VM is proof the credential has
 * nothing to claim -- the last-client transition torn between its strike and
 * reinstall entries leaves exactly that, and a seeded retirement there must
 * complete rather than wait on the transition's re-run. So the error's retry
 * hint is `true` whenever this gate raises it.
 *
 * The caller decides whether the credential carries a ladder.
 *
 * @param options {object}
 * @param options.log {DIDLog}   the verified log the claim was resolved over
 * @param options.doc {DIDDoc}   the document the claim was resolved over
 * @param options.credentialVmId {string}   the credential's `keyAgreement`
 *   verification-method id ({@link unlockKeyVmId})
 * @param options.claim {{ ladderVmId?: string, struck: string[], unclaimed:
 *   string[] }}   from {@link ladderVmClaimOf}
 * @param [options.anchorKeyMultibase] {string}   the update key the walk was
 *   anchored on: the candidate reading's second anchor form, and named in
 *   the refusal
 * @returns {Promise<void>}
 */
export async function assertLadderVmClaimed({
  log,
  doc,
  credentialVmId,
  claim,
  anchorKeyMultibase
}: {
  log: DIDLog
  doc: DIDDoc
  credentialVmId: string
  claim: { ladderVmId?: string; struck: string[]; unclaimed: string[] }
  anchorKeyMultibase?: string
}): Promise<void> {
  const credentialStands = (doc.verificationMethod ?? []).some(
    method => method.id === credentialVmId
  )
  if (
    !credentialStands ||
    claim.ladderVmId !== undefined ||
    claim.struck.length > 0 ||
    claim.unclaimed.length === 0
  ) {
    return
  }
  const candidates = await ladderVmIdsIntroducedWithCredential({
    log,
    credentialVmId,
    ...(anchorKeyMultibase !== undefined ? { anchorKeyMultibase } : {})
  })
  const unclaimed = claim.unclaimed.filter(id => candidates.includes(id))
  if (unclaimed.length === 0) {
    return
  }
  throw new UnclaimedLadderVmRetirementError({
    unclaimedLadderVmIds: unclaimed,
    retryableWithLadderSeed: true,
    ...(anchorKeyMultibase !== undefined ? { anchorKeyMultibase } : {})
  })
}

/**
 * The retirement gate run read-only, before anything is written: one pinned
 * read of the account log, the credential's ladder attribution, and
 * {@link assertLadderVmClaimed} over the result. A caller that establishes a
 * replacement credential before it retires the old one (a passphrase change,
 * a tap-confirmed passkey removal) runs this first, so a gate refusal lands
 * the way an invalid-input check does -- nothing established, no
 * pending-shaped registry entry written -- rather than after establishment,
 * where the refusal would leave a torn state no seedless repair can clear.
 * The in-ceremony gate stays as defense in depth, and it is what answers a
 * log entry landing between the pre-flight and the retirement: the
 * pre-flight's verdict holds for the head it read, and nothing binds the two
 * reads.
 *
 * @param options {object}
 * @param options.idStore {UnlockLogStore}   the account's `id` collection
 *   read side
 * @param options.unlockKeys {StandingUnlockKeys}   the credential's recorded
 *   public inventory
 * @param [options.ladderSeed] {Uint8Array}   the credential's ladder seed,
 *   when the caller holds it
 * @param [options.expectedDid] {string}   the account DID the log must
 *   resolve to. The read runs under the store's own chain-head pin
 * @param [options.missingMessage] {string}   the absent-log refusal's
 *   message, for a caller whose own ceremony names what it was reading for
 * @returns {Promise<object>}   the removal report (what the retirement would
 *   strike and what it would leave unclaimed) widened with the attributed
 *   ladder VM ids and the document the gate ran over, which the in-ceremony
 *   caller acts on
 */
export async function preflightUnlockCredentialRetirement({
  idStore,
  unlockKeys,
  ladderSeed,
  expectedDid,
  missingMessage = 'did:webvh: did.jsonl is missing; nothing to retire from.'
}: {
  idStore: Pick<WebvhIdStore, 'getIdResourceRaw' | 'pin'>
  unlockKeys: StandingUnlockKeys
  ladderSeed?: Uint8Array
  expectedDid?: string
  missingMessage?: string
}): Promise<
  LadderVmRemovalReport & { ladderVmIds: string[]; document: DIDDoc }
> {
  const published = await readPublishedLogOrThrow({
    idStore,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    missingMessage
  })
  const { did, doc } = published
  const inventory = await attributeUnlockLadderInventory({
    log: published.log,
    did,
    unlockKeys,
    ...(ladderSeed ? { ladderSeed } : {})
  })
  const claim = await ladderVmClaimOf({
    doc,
    did,
    inventory,
    ...(ladderSeed ? { ladderSeed } : {})
  })
  await assertLadderVmClaimed({
    log: published.log,
    doc,
    credentialVmId: unlockKeyVmId({
      did,
      keyAgreement: unlockKeys.keyAgreement
    }),
    claim,
    anchorKeyMultibase: unlockKeys.updateKeyMultibase
  })
  return {
    struck: claim.struck,
    unclaimed: claim.unclaimed,
    ladderVmIds: inventory.ladderVmIds,
    document: doc
  }
}

/**
 * The write-side shape of a credential-class `keyAgreement` member, the
 * twin of the read side's `ResolvedKeyAgreementMethod`: a `VerificationMethod`
 * carrying the key verbatim (`publicKeyMultibase`) or its hash commitment
 * (`publicKeyCommitment`), and always the ladder's rung-0 commitment. Every
 * bind site builds one through {@link unlockKeyVerificationMethod}, so the
 * permanent property is typed where it is written rather than cast in.
 */
export type CredentialKeyAgreementMethod = VerificationMethod & {
  controller: string
  ladderCommitment: string
} & ({ publicKeyMultibase: string } | { publicKeyCommitment: string })

/**
 * The credential's `keyAgreement` verification method: an ordinary unmarked
 * entry carrying either the key verbatim (a `Multikey` with
 * `publicKeyMultibase`) or its hash commitment (a `MultikeyCommitment` with
 * `publicKeyCommitment` -- the document convention for a low-entropy-derived
 * key, which withholds the key material and gives the roster resolver a
 * document-anchored check). Controlled by the account and deliberately
 * unmarked: a credential is not a listed client, so its entry must never
 * carry the controller marker a client listing or a revocation removal
 * matches on.
 *
 * Either flavor names its ladder's rung-0 commitment (`ladderCommitment`):
 * `hash(rung 0)` in the multihash form `nextKeyHashes` carries, the same
 * value the bind commits there. It is what a seedless reader anchors the
 * credential's ladder walk on (`credentialLadderAnchor`), so no reader
 * infers the anchor from the shape of the entry that introduced the member.
 * Every bind site builds the member here, so no emitter can omit it; the
 * roster resolver and the client listings ignore it.
 *
 * "The value is `hash(rung 0)`" is a checked contract wherever the emitter
 * holds the ladder seed. A seeded {@link publishUnlockKey} derives the
 * commitment from the seed's rung 0 and refuses (`LadderAttributionError`,
 * nothing written) a fresh bind whose recorded update key is another rung,
 * or a standing member naming another hash; the ladder-anchored genesis and
 * the transient recovery continuation derive the pair from one seed. Two
 * emitters take the value on trust, since they hold no seed: a seedless
 * `publishUnlockKey` (`ladderSeed: null`) commits the recorded key's hash as
 * given, and the remembered recovery continuation names the hash of the
 * replacement code's `updateKeyMultibase` as handed in. A caller feeding
 * either an attributed later rung would mint a member anchored mid-ladder,
 * unclaimable by every seedless reader.
 *
 * @param options {object}
 * @param options.did {string}   the account's did:webvh
 * @param options.keyAgreement {UnlockKeyAgreementPublication}
 * @param options.ladderCommitment {string}   `hash(rung 0)` of the
 *   credential's ladder, as `deriveNextKeyHash` renders it; must be rung 0
 *   and not a later rung the registry attributed after a self-enrollment
 * @returns {CredentialKeyAgreementMethod}
 */
export function unlockKeyVerificationMethod({
  did,
  keyAgreement,
  ladderCommitment
}: {
  did: string
  keyAgreement: UnlockKeyAgreementPublication
  ladderCommitment: string
}): CredentialKeyAgreementMethod {
  const id = unlockKeyVmId({ did, keyAgreement })
  if ('publicKeyMultibase' in keyAgreement) {
    return {
      id,
      type: MULTIKEY_VM_TYPE,
      controller: did,
      publicKeyMultibase: keyAgreement.publicKeyMultibase,
      ladderCommitment
    }
  }
  return {
    id,
    type: MULTIKEY_COMMITMENT_VM_TYPE,
    controller: did,
    publicKeyCommitment: keyAgreement.commitment,
    ladderCommitment
  }
}

/**
 * BIND (run by an enrolled client, root authority): publishes a standing
 * credential's split configuration into the document -- one entry adding the
 * credential's `keyAgreement` entry (verbatim or commitment), committing its
 * current update key's hash in `nextKeyHashes`, and installing its LADDER VM
 * under `assertionMethod` and `capabilityDelegation`, and under no other
 * relation -- the asymmetry that recognizes it. The update key joins `updateKeys` nowhere.
 * One entry for the whole inventory: a separate install would open a window
 * in which the credential stands without the key it signs with.
 *
 * The ladder seed is the CALLER's to mint and to have already written
 * durably. This function never mints one, so a torn bind's re-run tests
 * idempotence against the SAME seed, finds the completed stage and publishes
 * nothing -- where a mint-when-absent would publish a second VM that no
 * anchored attribution could later strike. A credential with no ladder at all
 * passes `null` and gets no VM. The same rule is enforced against the
 * document, since a caller can mint a fresh seed for a member that already
 * stands (a torn establishment re-run, a registry entry recording the wrong
 * key): a standing member names its ladder's rung-0 commitment
 * (`ladderCommitment`), and a bind whose rung-0 hash differs from it refuses
 * with {@link LadderAttributionError} and writes nothing. Re-adding the
 * member under the new hash would leave it unclaimable by every seedless
 * reader for the rest of its standing run and the first ladder's VM and
 * commitment as orphans; the re-run that converges holds the seed that bound
 * the member. A standing member naming the same hash is extended as before,
 * which is what a split bind's authority entry does. A FRESH bind is held to
 * the seed the same way: with a seed in hand the recorded
 * `unlockKeys.updateKeyMultibase` must be that seed's rung 0, and a later
 * rung (the attributed key a registry records after a self-enrollment)
 * refuses with {@link LadderAttributionError} before any entry is built,
 * since the member it would mint anchors mid-ladder. Only a seedless bind
 * (`ladderSeed: null`) commits the recorded key's hash unchecked.
 *
 * `part` splits the bind across two entries where a ceremony needs the
 * credential's decryption material to precede its authority: `'key'`
 * publishes the `keyAgreement` member alone, `'authority'` installs the
 * ladder VM and commits the rung-0 hash, and `'all'` (the default) is the one
 * merged entry every other caller writes.
 *
 * Idempotent: an inventory already published is a no-op, so re-running a torn
 * bind converges. The entry publishes conditionally on the log this call
 * read; a race lost to a concurrent ceremony re-runs and rebases on the new
 * head.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.signer {AccountLogSigner}   who signs the entry: the BINDING
 *   client's own did:webvh update-key seeds, or the acting credential's
 *   ladder seed
 * @param options.unlockKeys {StandingUnlockKeys}   the credential's public
 *   inventory
 * @param options.ladderSeed {Uint8Array | null}   the credential's ladder
 *   seed, whose VM this entry installs; `null` for a credential that carries
 *   no ladder
 * @param [options.part] {string}   `'all'` (the default), `'key'`, or
 *   `'authority'` -- see above
 * @param [options.expectedDid] {string}   the account DID the log must resolve
 *   to, from the caller's stored account pointer. The read runs under the
 *   store's own chain-head pin: a served log that is a rollback, a fork, or
 *   an identity switch against the pinned head is refused
 *   (`ResourceLogContinuityError`)
 * @param [options.verb] {string}   what the caller is doing, for the
 *   pending-rotation refusal message (e.g. `'issuing a recovery code'`)
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}   the account
 *   DID and the document and log as this call leaves them (unchanged when the
 *   inventory was already settled), which is what the caller's roster-side half
 *   converges onto
 */
export async function publishUnlockKey(options: {
  idStore: WebvhIdStore
  signer: AccountLogSigner
  unlockKeys: StandingUnlockKeys
  ladderSeed: Uint8Array | null
  part?: UnlockInventoryPart
  expectedDid?: string
  verb?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  return withLogConflictRetry(() =>
    setUnlockKeyInventoryOnce({ ...options, polarity: 'publish' })
  )
}

/**
 * REMOVAL (run by an enrolled client, root authority): removes a standing
 * credential's inventory from the document -- its `keyAgreement` entry and
 * everything of its ladder that still stands -- in one entry. Idempotent. The
 * roster-side half (rotating the user key epoch off the credential's wrap) is
 * the caller's, and runs after this so the resolver's document no longer
 * backs the removed entry.
 *
 * The recorded `unlockKeys.updateKeyMultibase` is treated as an ANCHOR, not
 * as truth: a credential that has self-enrolled since its bind advanced its
 * standing commitment past the recorded rung, so the removal resolves the
 * ladder's current inventory from the log itself
 * ({@link attributeLadderInventory}) and strikes all of it -- every committed
 * hash the ladder accounts for AND, for a torn self-enrollment, the revealed
 * rung key still sitting in `updateKeys` (plus the never-claimed hashes its
 * reveal entry committed). Trusting the recorded multibase alone would leave
 * the live rung commitment standing: a latent re-seizure credential via the
 * reveal mechanism. The seedless walk recovers the rungs BEHIND the anchor
 * too, reading the log's positional rules backwards, so an anchor advanced by
 * a self-enrollment resolves the same inventory a bind-time anchor does
 * wherever each rung's hash was committed by an entry that also revealed the
 * previous rung, or by a handover. The credential's own member names a
 * second anchor, its rung-0 commitment, and the removal walks from both and
 * cross-checks them ({@link attributeUnlockLadderInventory}): the
 * member-anchored walk reads the whole history forward and is what the
 * strike acts on, the registry-anchored one must be contained in it, and
 * two anchors resolving to different ladders refuse with
 * {@link LadderAttributionError}. That is what reads the one history the
 * backward walk cannot -- a ladder VM the last-client transition reinstalled,
 * whose acting rung a later self-enrollment then spends, so that the
 * registry anchor advances past a reveal-and-commit entry that authorized no
 * key. A supplied `ladderSeed` is then a shortcut and a cross-check rather
 * than a requirement (every rung known outright, no backward walk). For a
 * single-key credential (a recovery code, a never-self-enrolled bind) the
 * resolution degenerates to exactly the recorded key's hash, as before.
 *
 * The credential's LADDER VM goes in the same entry, so a retired credential
 * no longer signs governed-log appends or account delegations. This is the
 * sole remover, and it needs no seed to do it: the VM is attributed from the
 * log on any of three arms ({@link attributeLadderInventory}). The SIGNER
 * arm claims a VM whose publishing entry a ladder rung signed. The
 * CO-INTRODUCTION arm claims one whose publishing entry also introduced this
 * credential's own `keyAgreement` member, which is what reaches a bind entry
 * an enrolled client signed; it fires only when that entry introduced exactly
 * one credential-class key-agreement member and exactly one ladder VM. The
 * COMMITMENT arm claims one whose publishing entry committed a hash this
 * ladder knows a priori and introduced no other credential's member, which is
 * what reaches a reinstall for a credential whose member already stands. A VM
 * no arm claims is left standing rather than struck -- on an account
 * with several standing credentials, striking an unattributed key would take
 * out a survivor's. With the seed in hand the derived id is struck too, and
 * an attribution naming any OTHER VM refuses with
 * {@link LadderAttributionError} rather than acting on a ladder the seed and
 * the recorded anchor disagree about.
 *
 * Every credential removed here carries a ladder, so the retirement gate
 * ({@link assertLadderVmClaimed}) runs unconditionally, before any write:
 * when the claim struck nothing while ladder VMs stand unclaimed and the
 * credential still stands, the edit refuses with
 * {@link UnclaimedLadderVmRetirementError}, naming the recorded update key
 * the walk was anchored on. The retirement ceremony and a recovery code's
 * removal both rely on it.
 *
 * @param options {object}   see {@link publishUnlockKey}, plus:
 * @param [options.ladderSeed] {Uint8Array}   the retired credential's ladder
 *   seed, when in hand
 * @param [options.projectionStore] {object}   an `id`-collection store the
 *   caller may write through (a transient session's, bound to its generation
 *   delegation; an enrolled client's own root-invoking store). Supplied, the
 *   post-strike `did:web` projection is PUT through it immediately BEFORE
 *   this entry publishes, which is what keeps a ladder-signed removal from
 *   leaving `did.json` naming the retired credential. Best-effort: a failed
 *   PUT is warned and the removal proceeds. Omitted, the ladder arm leaves
 *   the projection to the next visit's `ensureDidWebProjection` and the
 *   client arm publishes it after the entry, as before
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog, ladderVm:
 *   LadderVmRemovalReport }>}   see {@link publishUnlockKey}, plus the ladder
 *   VM report: what this entry struck, and what stands unclaimed after it
 */
export async function removeUnlockKey(options: {
  idStore: WebvhIdStore
  signer: AccountLogSigner
  projectionStore?: Pick<WebvhIdStore, 'getIdResourceRaw' | 'putIdResource'>
  unlockKeys: StandingUnlockKeys
  ladderSeed?: Uint8Array
  expectedDid?: string
  verb?: string
}): Promise<{
  did: string
  doc: DIDDoc
  log: DIDLog
  ladderVm: LadderVmRemovalReport
}> {
  return withLogConflictRetry(() =>
    setUnlockKeyInventoryOnce({ ...options, polarity: 'remove' })
  )
}

/**
 * One attempt of the merged inventory edit, re-invoked by the conflict retry.
 * The publish and remove polarities are one function because the entry they
 * build is the same edit with the set operations inverted -- a divergence
 * between two copies would be published into an append-only log.
 *
 * @param options {object}   see {@link publishUnlockKey}, plus `polarity`
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}
 */
async function setUnlockKeyInventoryOnce({
  idStore,
  signer,
  projectionStore,
  unlockKeys,
  ladderSeed,
  part = 'all',
  expectedDid,
  verb,
  polarity
}: {
  idStore: WebvhIdStore
  signer: AccountLogSigner
  projectionStore?: Pick<WebvhIdStore, 'getIdResourceRaw' | 'putIdResource'>
  unlockKeys: StandingUnlockKeys
  ladderSeed?: Uint8Array | null
  part?: UnlockInventoryPart
  expectedDid?: string
  verb?: string
  polarity: 'publish' | 'remove'
}): Promise<{
  did: string
  doc: DIDDoc
  log: DIDLog
  ladderVm: LadderVmRemovalReport
}> {
  let ladderVmReport: LadderVmRemovalReport = { struck: [], unclaimed: [] }
  const outcome = await signAccountEntry({
    idStore,
    signer,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    missingMessage: 'did:webvh: did.jsonl is missing; nothing to enroll into.',
    verb: verb ?? 'changing an unlock credential',
    // The post-strike projection, published while the caller's store can
    // still write it and before the entry the ladder arm cannot publish it
    // with. Only the removal polarity is ever handed one: a publish adds
    // inventory, which the served projection under-lists until some later
    // writer refreshes it -- the safe direction.
    ...(projectionStore
      ? {
          beforePublish: preEntryProjectionPublisher({
            store: projectionStore
          })
        }
      : {}),
    build: async ({ published }) => {
      const { did, doc } = published
      const keyHash = await deriveNextKeyHash(unlockKeys.updateKeyMultibase)
      const vmId = unlockKeyVmId({ did, keyAgreement: unlockKeys.keyAgreement })
      // What the bind commits and names as the member's ladder commitment:
      // `hash(rung 0)` derived from the seed the bind holds, which is what
      // the recorded key must be at bind time. A recorded key that has since
      // advanced (a registry refreshed by a self-enrollment) must neither
      // move the anchor a re-run tests against nor be published as one.
      const seedRung0Hash =
        polarity === 'publish' && ladderSeed
          ? await deriveNextKeyHash(
              (await ladderRung({ ladderSeed, index: 0 })).keyMultibase
            )
          : undefined
      const anchorHash = seedRung0Hash ?? keyHash

      const vmPresent = (doc.verificationMethod ?? []).some(
        method => method.id === vmId
      )
      const reading =
        polarity === 'publish' && vmPresent
          ? credentialLadderCommitment({
              log: published.log,
              credentialVmId: vmId
            })
          : undefined
      if (
        polarity === 'publish' &&
        !vmPresent &&
        seedRung0Hash !== undefined &&
        seedRung0Hash !== keyHash
      ) {
        throw new LadderAttributionError(
          "did:webvh: the credential's recorded update key is not rung 0 of " +
            'the ladder seed handed to the bind; refusing to publish an ' +
            'inventory the seed does not derive.'
        )
      }
      if (polarity === 'publish' && vmPresent) {
        // The write-side half of the anchor rule: a standing member's
        // `ladderCommitment` is what every seedless reader anchors the
        // credential's ladder on, and only the ladder that bound the member
        // may extend its inventory. A bind reaching a standing member under
        // another rung-0 hash -- a torn establishment re-run that minted a
        // fresh seed, a registry entry naming the wrong key, a sibling's
        // rung -- would re-add the member naming the new hash, leaving the
        // member unclaimable for the rest of its standing run and the first
        // ladder's VM and commitment as orphans. It refuses instead, with
        // nothing written: the re-run that converges is the one holding the
        // seed that bound the member.
        if (reading?.retargeted || reading?.named !== anchorHash) {
          throw new LadderAttributionError(
            "did:webvh: the credential's keyAgreement member already stands " +
              'naming a ladder commitment this bind does not derive; ' +
              'refusing to re-bind a standing member under another ladder. ' +
              'Re-run with the ladder seed that bound it.'
          )
        }
      }
      // The remove polarity strikes the ladder's CURRENT inventory, resolved
      // from the log with the recorded key as anchor -- never just the
      // recorded key's hash, which a self-enrollment since the bind leaves
      // stale (see {@link removeUnlockKey}). The credential's own
      // verification-method id goes along: it is what tells the walk a climb
      // from a spend, so the removal never annexes the commitment a spend
      // handed to its replacement.
      const inventory =
        polarity === 'remove'
          ? await attributeUnlockLadderInventory({
              log: published.log,
              did,
              unlockKeys,
              ...(ladderSeed ? { ladderSeed } : {})
            })
          : { revealedKeys: [], committedHashes: [], ladderVmIds: [] }
      const removedHashes = new Set(inventory.committedHashes)
      const removedKeys = new Set(inventory.revealedKeys)
      // The credential's ladder VM: installed by the publish polarity in this
      // same entry, struck by the remove polarity in this same entry. The
      // derived id is what the install publishes; the removal takes it from
      // the seed when the ceremony holds one and from the log's attribution
      // otherwise, so a seedless retirement still ends the credential's
      // delegation authority.
      const ladderVmKey = ladderSeed
        ? await ladderVmKeyMultibase({ ladderSeed })
        : undefined
      const ladderVmId =
        ladderVmKey === undefined ? undefined : `${did}#${ladderVmKey}`
      const standingLadderVmIds = ladderVmIds({ doc })
      const claim =
        polarity === 'remove'
          ? await ladderVmClaimOf({
              doc,
              did,
              inventory,
              ...(ladderSeed ? { ladderSeed } : {})
            })
          : { struck: [], unclaimed: [] }
      if (polarity === 'remove') {
        // The retirement gate, before any write: a ladder-carrying credential
        // whose claim struck nothing while ladder VMs stand unclaimed is
        // refused rather than retired with its VM left standing. Every
        // credential removed here carries a ladder, so the gate is
        // unconditional on this polarity.
        await assertLadderVmClaimed({
          log: published.log,
          doc,
          credentialVmId: vmId,
          claim,
          anchorKeyMultibase: unlockKeys.updateKeyMultibase
        })
      }
      const struckLadderVmIds = new Set(claim.struck)
      const ladderVmPresent =
        polarity === 'publish'
          ? ladderVmId !== undefined && standingLadderVmIds.includes(ladderVmId)
          : struckLadderVmIds.size > 0
      const struckIds = new Set([vmId, ...struckLadderVmIds])
      // The authority half is settled once the log committed the anchor for
      // the member: standing still, or spent since by a self-enrollment that
      // climbed the ladder past it.
      const hashCommitted =
        published.nextKeyHashes.includes(anchorHash) ||
        reading?.committed === true
      // What this entry is responsible for, by `part`: the key half publishes
      // the `keyAgreement` member alone, the authority half the ladder VM and
      // the rung's commitment, and the default entry both.
      const publishesKey = part === 'all' || part === 'key'
      const publishesAuthority = part === 'all' || part === 'authority'
      const settled =
        polarity === 'publish'
          ? (!publishesKey || vmPresent) &&
            (!publishesAuthority ||
              (hashCommitted && (ladderVmId === undefined || ladderVmPresent)))
          : !vmPresent &&
            !ladderVmPresent &&
            removedHashes.size === 0 &&
            removedKeys.size === 0
      ladderVmReport = {
        struck: claim.struck,
        unclaimed: claim.unclaimed
      }
      if (settled) {
        return undefined
      }

      const existingMethods = (doc.verificationMethod ??
        []) as VerificationMethod[]
      // The publish polarity commits the credential's update-key hash through
      // the seam's `commitHashes`, so on a ladder-signed entry it lands after
      // the acting rung's own carry-over hash (`decisions/0007` order).
      const commitHashes =
        polarity === 'publish' && publishesAuthority && !hashCommitted
          ? [anchorHash]
          : []
      const nextKeyHashes =
        polarity === 'publish'
          ? undefined
          : published.nextKeyHashes.filter(hash => !removedHashes.has(hash))
      // A torn self-enrollment leaves a revealed rung in `updateKeys`; the
      // remove polarity strikes it in the same entry as its hash, keeping the
      // carry-over invariant self-consistent. On the publish polarity and the
      // ordinary committed-only removal this is the published set unchanged.
      const statedUpdateKeys =
        polarity === 'publish'
          ? undefined
          : published.updateKeys.filter(key => !removedKeys.has(key))
      const installedLadderVmKey = publishesAuthority ? ladderVmKey : undefined
      const verificationMethods =
        polarity === 'publish'
          ? [
              ...existingMethods.filter(
                method =>
                  method.id !== (publishesKey ? vmId : undefined) &&
                  method.id !== (publishesAuthority ? ladderVmId : undefined)
              ),
              ...(publishesKey
                ? [
                    unlockKeyVerificationMethod({
                      did,
                      keyAgreement: unlockKeys.keyAgreement,
                      /**
                       * The recorded update key is rung 0 at bind time, so
                       * its hash is the member's ladder commitment -- on a
                       * split bind too, where the authority entry commits it
                       * two versions later.
                       */
                      ladderCommitment: anchorHash
                    })
                  ]
                : []),
              ...(installedLadderVmKey !== undefined
                ? [
                    ladderVerificationMethod({
                      controller: did,
                      publicKeyMultibase: installedLadderVmKey
                    })
                  ]
                : [])
            ]
          : existingMethods.filter(
              method => method.id === undefined || !struckIds.has(method.id)
            )
      // On the remove polarity every relation drops the struck ids: the
      // credential's entry sits under `keyAgreement` alone and the ladder VM
      // under `assertionMethod` and `capabilityDelegation` alone, so one
      // filter serves all five without restating either placement here.
      const relation = (
        ids: Array<string | { id?: string }> | undefined
      ): string[] =>
        polarity === 'publish'
          ? relationIds(ids)
          : relationIds(ids).filter(id => !struckIds.has(id))
      const keyAgreement =
        polarity === 'publish'
          ? publishesKey
            ? [...new Set([...relationIds(doc.keyAgreement), vmId])]
            : relationIds(doc.keyAgreement)
          : relation(doc.keyAgreement)
      // The ladder VM's two relations, and only those: the asymmetry is what
      // recognizes it (`ladderVmIds`) and what keeps it out of every client
      // listing.
      const withLadderVm = (
        ids: Array<string | { id?: string }> | undefined
      ): string[] =>
        installedLadderVmKey === undefined || ladderVmId === undefined
          ? relationIds(ids)
          : [...new Set([...relationIds(ids), ladderVmId])]
      const assertionMethod =
        polarity === 'publish'
          ? withLadderVm(doc.assertionMethod)
          : relation(doc.assertionMethod)
      const capabilityDelegation =
        polarity === 'publish'
          ? withLadderVm(doc.capabilityDelegation)
          : relation(doc.capabilityDelegation)

      return {
        // The byoe context that defines a commitment entry's terms is
        // installed at genesis and carried forward by every update, so no
        // edit re-appends it.
        ...(statedUpdateKeys !== undefined
          ? { updateKeys: statedUpdateKeys }
          : {}),
        ...(nextKeyHashes !== undefined ? { nextKeyHashes } : {}),
        ...(commitHashes.length > 0 ? { commitHashes } : {}),
        verificationMethods,
        authentication: relation(doc.authentication),
        assertionMethod,
        keyAgreement,
        capabilityInvocation: relation(doc.capabilityInvocation),
        capabilityDelegation
      }
    }
  })
  const settledHead = outcome.updated ?? outcome.published
  return {
    did: settledHead.did,
    doc: settledHead.doc,
    log: settledHead.log,
    ladderVm: ladderVmReport
  }
}
