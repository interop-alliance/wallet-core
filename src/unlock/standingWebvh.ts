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
import { deriveNextKeyHash, updateDID } from '@interop/did-method-webvh'
import type {
  DIDDoc,
  DIDLog,
  VerificationMethod
} from '@interop/did-method-webvh'
import {
  assertCarryOverCommitments,
  MULTIKEY_COMMITMENT_VM_TYPE,
  MULTIKEY_VM_TYPE,
  ladderVerificationMethod,
  publishUpdatedLog,
  readPublishedLogOrThrow,
  updateKeyMultibase,
  updateKeySigner,
  withLogConflictRetry
} from '../webvh/didWebvh.js'
import { ladderVmIds, relationIds } from '../resourceLog/document.js'
import type { ClientWebvhUpdateKeys, WebvhIdStore } from '../webvh/didWebvh.js'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
// The one deliberate base-side dependency on the annex subpath, pinned as an
// exception in the lint rule: this module resolves a credential's CURRENT
// ladder inventory from the log itself (the shared attribution helpers in
// `clientAnnex/ladder.ts`), never touching the annex log machinery, and
// derives the credential's ladder VM from its seed at the install.
import {
  attributeLadderInventory,
  LadderAttributionError,
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
  'getIdResourceRaw' | 'putIdResource'
>

/**
 * The ladder inventory the removal edit resolved from the log diverges from
 * what the caller was told one read earlier. A ceremony that names its
 * expected ladder VM ids (the retirement's stage 0, which hands the same list
 * to the dependent-record re-mint pass) gets this refusal BEFORE the edit is
 * published, so a concurrent ceremony -- or a host serving different log
 * versions to the two reads -- cannot make the strike diverge from what the
 * re-mint pass acted on. Nothing is written. Matched on `name` (the error
 * crosses app-injected seams that may resolve to another copy of this
 * package).
 */
export class LadderInventoryDriftError extends Error {
  readonly expected: string[]
  readonly attributed: string[]

  constructor({
    expected,
    attributed
  }: {
    expected: string[]
    attributed: string[]
  }) {
    super(
      'did:webvh: the published log attributes a different ladder VM set to ' +
        'this credential than the caller resolved a moment earlier ' +
        `(expected ${expected.join(', ') || '(none)'}; attributed ` +
        `${attributed.join(', ') || '(none)'}); the inventory edit was not ` +
        'published. Re-run the retirement on a fresh read.'
    )
    this.name = 'LadderInventoryDriftError'
    this.expected = expected
    this.attributed = attributed
  }
}

/**
 * What the removal edit says about ladder VMs: `struck`, the ids this entry
 * removed from the document, and `unclaimed`, the ladder VMs still standing
 * afterwards that this credential's attribution could not claim.
 *
 * `unclaimed` is information rather than a gate, and the caller cannot read
 * an orphan out of it by subtraction alone: a VM standing here may perfectly
 * well be a SIBLING credential's, which this ladder has no business claiming.
 * What it does catch is the seedless strike whose attribution claims nothing
 * -- a retirement that returns clean while the credential's VM stands on --
 * which would otherwise be reported as a completed removal.
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
 * `nextKeyHashes` (ladder rung 0 at bind time; a code's single derived key).
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
 * log, resolved with the recorded update key as ANCHOR and the credential's
 * own key-agreement id as the attribution's second arm. The removal edit uses
 * it to know what to strike; the retirement ceremony uses it one stage
 * earlier, to name the ladder VM it is about to strike to the pass that
 * re-mints whatever that VM signed for other credentials.
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
  return attributeLadderInventory({
    log,
    anchorKeyMultibase: unlockKeys.updateKeyMultibase,
    credentialVmId: unlockKeyVmId({
      did,
      keyAgreement: unlockKeys.keyAgreement
    }),
    ...(ladderSeed ? { ladderSeed } : {})
  })
}

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
 * @param options {object}
 * @param options.did {string}   the account's did:webvh
 * @param options.keyAgreement {UnlockKeyAgreementPublication}
 * @returns {VerificationMethod}
 */
export function unlockKeyVerificationMethod({
  did,
  keyAgreement
}: {
  did: string
  keyAgreement: UnlockKeyAgreementPublication
}): VerificationMethod {
  const id = unlockKeyVmId({ did, keyAgreement })
  if ('publicKeyMultibase' in keyAgreement) {
    return {
      id,
      type: MULTIKEY_VM_TYPE,
      controller: did,
      publicKeyMultibase: keyAgreement.publicKeyMultibase
    }
  }
  return {
    id,
    type: MULTIKEY_COMMITMENT_VM_TYPE,
    controller: did,
    publicKeyCommitment: keyAgreement.commitment
  } as VerificationMethod
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
 * (a recovery code, whose inventory is one key-agreement method and one
 * update key) passes `null` and gets no VM.
 *
 * Idempotent: an inventory already published is a no-op, so re-running a torn
 * bind converges. The entry publishes conditionally on the log this call
 * read; a race lost to a concurrent ceremony re-runs and rebases on the new
 * head.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.updateKeys {ClientWebvhUpdateKeys}   the BINDING client's own
 *   did:webvh update-key seeds
 * @param options.unlockKeys {StandingUnlockKeys}   the credential's public
 *   inventory
 * @param options.ladderSeed {Uint8Array | null}   the credential's ladder
 *   seed, whose VM this entry installs; `null` for a credential that carries
 *   no ladder
 * @param [options.expectedDid] {string}   the account DID the log must resolve
 *   to, from the caller's stored account pointer
 * @param [options.pinStore] {ResourceLogPinStore}   the caller's chain-head
 *   pins; a served log that is a rollback, a fork, or an identity switch
 *   against the pinned head is refused (`ResourceLogContinuityError`)
 * @param [options.logId] {string}   the account log's pin slot
 *   (`accountLogPinId({ spaceId })`); required whenever a `pinStore` is
 *   supplied
 * @param [options.verb] {string}   what the caller is doing, for the
 *   pending-rotation refusal message (e.g. `'issuing a recovery code'`)
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}   the account
 *   DID and the document and log as this call leaves them (unchanged when the
 *   inventory was already settled), which is what the caller's roster-side half
 *   converges onto
 */
export async function publishUnlockKey(options: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  unlockKeys: StandingUnlockKeys
  ladderSeed: Uint8Array | null
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
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
 * previous rung, or by a handover. One reachable shape falls outside that: a
 * ladder VM the last-client transition reinstalled, whose acting rung a later
 * self-enrollment then spends. That reveal-and-commit entry authorizes no key,
 * so the backward walk cannot name the rung that signed it, and the VM stays
 * standing as `unclaimed` (WC-158). A supplied `ladderSeed` is then a shortcut
 * and a cross-check rather than a requirement (every rung known outright, no
 * backward walk). For a
 * single-key credential (a
 * recovery code, a never-self-enrolled bind) the resolution degenerates to
 * exactly the recorded key's hash, as before.
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
 * @param options {object}   see {@link publishUnlockKey}, plus:
 * @param [options.ladderSeed] {Uint8Array}   the retired credential's ladder
 *   seed, when in hand
 * @param [options.expectedLadderVmIds] {string[]}   the ladder VM ids the
 *   caller already resolved for this credential, from its own read of the
 *   log. Supplied, this edit's own attribution must match them as a set --
 *   after the seed cross-check above -- or the edit refuses with
 *   {@link LadderInventoryDriftError} before writing anything. That is what
 *   ties the retirement's stage-0 read (whose list the dependent-record
 *   re-mint pass acted on) to this one, which is otherwise independent
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog, ladderVm:
 *   LadderVmRemovalReport }>}   see {@link publishUnlockKey}, plus the ladder
 *   VM report: what this entry struck, and what stands unclaimed after it
 */
export async function removeUnlockKey(options: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  unlockKeys: StandingUnlockKeys
  ladderSeed?: Uint8Array
  expectedLadderVmIds?: string[]
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
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
  updateKeys,
  unlockKeys,
  ladderSeed,
  expectedLadderVmIds,
  expectedDid,
  pinStore,
  logId,
  verb,
  polarity
}: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  unlockKeys: StandingUnlockKeys
  ladderSeed?: Uint8Array | null
  expectedLadderVmIds?: string[]
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
  verb?: string
  polarity: 'publish' | 'remove'
}): Promise<{
  did: string
  doc: DIDDoc
  log: DIDLog
  ladderVm: LadderVmRemovalReport
}> {
  const published = await readPublishedLogOrThrow({
    idStore,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {}),
    missingMessage: 'did:webvh: did.jsonl is missing; nothing to enroll into.'
  })
  const { did, doc } = published
  const keyHash = await deriveNextKeyHash(unlockKeys.updateKeyMultibase)
  const vmId = unlockKeyVmId({ did, keyAgreement: unlockKeys.keyAgreement })

  const vmPresent = (doc.verificationMethod ?? []).some(
    method => method.id === vmId
  )
  // The remove polarity strikes the ladder's CURRENT inventory, resolved from
  // the log with the recorded key as anchor -- never just the recorded key's
  // hash, which a self-enrollment since the bind leaves stale (see
  // {@link removeUnlockKey}). The credential's own verification-method id
  // goes along: it is what tells the walk a climb from a spend, so the
  // removal never annexes the commitment a spend handed to its replacement.
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
  // derived id is what the install publishes; the removal takes it from the
  // seed when the ceremony holds one and from the log's attribution
  // otherwise, so a seedless retirement still ends the credential's
  // delegation authority.
  const ladderVmKey = ladderSeed
    ? await ladderVmKeyMultibase({ ladderSeed })
    : undefined
  const ladderVmId =
    ladderVmKey === undefined ? undefined : `${did}#${ladderVmKey}`
  const standingLadderVmIds = ladderVmIds({ doc })
  const struckLadderVmIds = new Set<string>()
  if (polarity === 'remove') {
    if (ladderVmId !== undefined) {
      const foreign = inventory.ladderVmIds.filter(id => id !== ladderVmId)
      if (foreign.length > 0) {
        throw new LadderAttributionError(
          "The published log attributes a ladder VM this credential's seed " +
            'does not derive; refusing to strike on an ambiguous ' +
            'attribution.'
        )
      }
      if (standingLadderVmIds.includes(ladderVmId)) {
        struckLadderVmIds.add(ladderVmId)
      }
    }
    for (const id of inventory.ladderVmIds) {
      struckLadderVmIds.add(id)
    }
    // The drift check, before any write: this edit's own attribution against
    // the list the caller resolved a read earlier. A concurrent ceremony, or
    // a host serving two different log versions to the two reads, would
    // otherwise let the strike diverge from what the caller's dependent-record
    // pass already acted on.
    if (expectedLadderVmIds !== undefined) {
      const attributed = new Set(inventory.ladderVmIds)
      const expected = new Set(expectedLadderVmIds)
      const sameSet =
        attributed.size === expected.size &&
        [...expected].every(id => attributed.has(id))
      if (!sameSet) {
        throw new LadderInventoryDriftError({
          expected: [...expected],
          attributed: [...attributed]
        })
      }
    }
  }
  const ladderVmPresent =
    polarity === 'publish'
      ? ladderVmId !== undefined && standingLadderVmIds.includes(ladderVmId)
      : struckLadderVmIds.size > 0
  const struckIds = new Set([vmId, ...struckLadderVmIds])
  const hashCommitted = published.nextKeyHashes.includes(keyHash)
  const settled =
    polarity === 'publish'
      ? vmPresent &&
        hashCommitted &&
        (ladderVmId === undefined || ladderVmPresent)
      : !vmPresent &&
        !ladderVmPresent &&
        removedHashes.size === 0 &&
        removedKeys.size === 0
  const ladderVmReport = (
    resultDoc: DIDDoc,
    struck: Set<string>
  ): LadderVmRemovalReport => {
    const claimed = new Set([
      ...struck,
      ...inventory.ladderVmIds,
      ...(ladderVmId !== undefined ? [ladderVmId] : [])
    ])
    return {
      struck: [...struck],
      unclaimed: ladderVmIds({ doc: resultDoc }).filter(id => !claimed.has(id))
    }
  }
  if (settled) {
    return {
      did,
      doc,
      log: published.log,
      ladderVm: ladderVmReport(doc, struckLadderVmIds)
    }
  }

  const activeKey = await updateKeyMultibase({ seed: updateKeys.updateSeed })
  if (!published.updateKeys.includes(activeKey)) {
    throw new Error(
      "did:webvh: the published log does not authorize this client's active " +
        'update key; finalize the pending rotation before ' +
        `${verb ?? 'changing an unlock credential'}.`
    )
  }
  await assertCarryOverCommitments({ published })

  const existingMethods = (doc.verificationMethod ?? []) as VerificationMethod[]
  const signer = await updateKeySigner({ seed: updateKeys.updateSeed })
  const nextKeyHashes =
    polarity === 'publish'
      ? [...new Set([...published.nextKeyHashes, keyHash])]
      : published.nextKeyHashes.filter(hash => !removedHashes.has(hash))
  // A torn self-enrollment leaves a revealed rung in `updateKeys`; the remove
  // polarity strikes it in the same entry as its hash, keeping the carry-over
  // invariant self-consistent. On the publish polarity and the ordinary
  // committed-only removal this is the published set unchanged.
  const statedUpdateKeys =
    polarity === 'publish'
      ? published.updateKeys
      : published.updateKeys.filter(key => !removedKeys.has(key))
  const verificationMethods =
    polarity === 'publish'
      ? [
          ...existingMethods.filter(
            method => method.id !== vmId && method.id !== ladderVmId
          ),
          unlockKeyVerificationMethod({
            did,
            keyAgreement: unlockKeys.keyAgreement
          }),
          ...(ladderVmKey !== undefined
            ? [
                ladderVerificationMethod({
                  controller: did,
                  publicKeyMultibase: ladderVmKey
                })
              ]
            : [])
        ]
      : existingMethods.filter(
          method => method.id === undefined || !struckIds.has(method.id)
        )
  // On the remove polarity every relation drops the struck ids: the
  // credential's entry sits under `keyAgreement` alone and the ladder VM under
  // `assertionMethod` and `capabilityDelegation` alone, so one filter serves
  // all five without restating either placement here.
  const relation = (
    ids: Array<string | { id?: string }> | undefined
  ): string[] =>
    polarity === 'publish'
      ? relationIds(ids)
      : relationIds(ids).filter(id => !struckIds.has(id))
  const keyAgreement =
    polarity === 'publish'
      ? [...new Set([...relationIds(doc.keyAgreement), vmId])]
      : relation(doc.keyAgreement)
  // The ladder VM's two relations, and only those: the asymmetry is what
  // recognizes it (`ladderVmIds`) and what keeps it out of every client
  // listing.
  const withLadderVm = (
    ids: Array<string | { id?: string }> | undefined
  ): string[] =>
    ladderVmId === undefined
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

  const updated = await updateDID({
    log: published.log,
    signer,
    alsoKnownAsWeb: true,
    // The byoe context that defines a commitment entry's terms is installed
    // at genesis and carried forward by every update, so no edit re-appends it.
    updateKeys: statedUpdateKeys,
    nextKeyHashes,
    verificationMethods,
    authentication: relation(doc.authentication),
    assertionMethod,
    keyAgreement,
    capabilityInvocation: relation(doc.capabilityInvocation),
    capabilityDelegation
  })
  await publishUpdatedLog({ idStore, updated, ifMatch: published.etag })
  return {
    did: updated.did,
    doc: updated.doc,
    log: updated.log,
    ladderVm: ladderVmReport(updated.doc, struckLadderVmIds)
  }
}
