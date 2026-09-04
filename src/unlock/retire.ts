/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Retiring a standing unlock credential: the ceremony behind "change my
 * passphrase" and "remove this passkey", run synchronously in an enrolled
 * client, in dependency order. A standing credential is not a stored string to
 * overwrite -- it holds a wrap in the user key roster and a `keyAgreement`
 * inventory in the account's did:webvh document -- so retiring one is a real
 * rotation, on the same stages the client-revocation cascade runs.
 *
 * 0. **The dependent-record re-mint** (the injected `remintDependentRecords`
 *    closure), against the PRE-edit document: the credential's ladder VM is
 *    about to be struck, and a struck VM rots every record and bridge
 *    delegation it signed for OTHER credentials -- the last-client transition
 *    signs siblings' records with one, and `currentAccountRecordSigners`
 *    accepts it. The stage names the doomed VM ids to the pass, which
 *    re-signs those records under a key that outlives the edit.
 * 1. **The document inventory edit** (`removeUnlockKey`): the credential's
 *    `keyAgreement` entry (verbatim key or commitment) and its committed
 *    update-key hash leave the document in one log entry. That kills the
 *    credential's latent self-enrollment authority -- with its rung
 *    commitment gone, no reveal entry it could sign verifies -- and it is
 *    what makes stage 2 converge: the roster resolver, backed by this
 *    document, no longer keys the credential's entry.
 * 2. **The roster rotation and the collection fan-out**
 *    (`rotateRosterToDocumentAndCascade`): the user key rotates off the
 *    credential's wrap and every encrypted collection re-epochs onto the
 *    fresh key, so writes stop landing under epochs the retired credential
 *    could open.
 *
 * The order is load-bearing, and in that direction: the document removal
 * first means a run torn anywhere after it leaves the roster keying a
 * recipient the document no longer backs -- exactly the state the login-time
 * sweep detects and finishes. Torn the other way around, a rotation with the
 * inventory still standing would simply re-escrow the credential and look
 * healthy.
 *
 * Stage 0 is the one stage that runs BEFORE the edit, and its placement is
 * the point. Run after the edit it would leave a window in which every
 * sibling credential's record is unverifiable, and a run torn there bricks
 * exactly what the stage exists to protect: a record whose frame proof names
 * a struck key refuses before decryption, and the credential's own login dies
 * at that check with no repair arm. Run before it, a tear leaves the sibling
 * records signed by a key that still stands and the retiring credential still
 * standing -- the correct resting state, converged by a re-run. So the stage
 * is fail-closed rather than best-effort: a throw from the closure aborts the
 * retirement before anything is published, unlike the annex closure at 1b.
 *
 * That corrects what this module used to reason. A retired credential's own
 * bridge delegation does die with its unlock Space, which the app deletes as
 * part of the change-method ceremony. Its ladder VM is the part that reaches
 * further: other credentials' records and bridges chain through it.
 *
 * The client annex reach is its own stage (1b, the injected
 * `retireClientAnnexInventory` closure), between the document edit and the
 * roster tail: a standing credential's annex rung-0 key and hash live in
 * the pointed generation's log, kept nowhere the account document edit can
 * reach, so without it a retired credential keeps annex-write authority
 * for the life of the generation. The closure runs strike-or-swap: a
 * dedicated strike entry signed by a distinct committed rung
 * (`retireClientAnnexRung`) where the ceremony holds one, else a fresh
 * generation minted from a surviving credential's seed and re-pointed under
 * account-log update authority (`swapClientAnnexGeneration`), the retired rung
 * dying with the old generation. It also owns retiring the credential's
 * `delegatedClients` sibling: no server revocation is possible or needed --
 * the sibling delegation's record dies with the unlock Space the caller
 * deletes, and a swap (or the ordinary GC cadence) retires the generation it
 * targeted. Best-effort by contract, enforced by the ceremony itself: a
 * throw escaping the closure is caught here and reported as the `failed`
 * skip, so the roster rotation -- the ceremony's essential remedy -- always
 * runs.
 *
 * Both stages carry the retirement gate (`decisions/0015`): a credential
 * retired here carries a ladder, so its ladder VM must be claimed -- by the
 * seed, or by the log's attribution -- before the edit strikes anything. A
 * claim that strikes nothing while ladder VMs stand unclaimed refuses with
 * `UnclaimedLadderVmRetirementError`, at stage 0 before the re-mint pass
 * writes a sibling record and again inside the edit before its entry
 * publishes, so the credential still stands and the log is unchanged. The
 * leftover the gate closes is a retired credential's VM standing under
 * `capabilityDelegation`, which could still sign a DELETE-only capability on
 * the account Space. Callers that establish a replacement before retiring
 * run `preflightUnlockCredentialRetirement` first, so the refusal lands
 * before establishment rather than in a torn state. The recovery-code
 * removal shares the edit but not the gate: a code carries no ladder VM to
 * claim.
 *
 * Stage 0 and stage 1 each read the log for themselves, and the two reads are
 * tied by a cross-check rather than by luck: stage 0 hands its attributed
 * ladder VM ids to the edit as `expectedLadderVmIds`, and the edit refuses
 * before writing when its own attribution resolves a different set
 * (`LadderInventoryDriftError`). So a concurrent ceremony, or a host serving
 * different log versions to the two reads, cannot leave the strike diverging
 * from what the re-mint pass acted on. Both reads take the caller's
 * `pinStore` and `logId`, so both are checked against the same chain head.
 *
 * Convergence is the design: every stage detects its own completion from
 * durable state alone -- the inventory edit no-ops when the document is already
 * settled, the rotation no-ops once every current-epoch recipient is
 * document-backed, and a collection is stale exactly when its current epoch
 * names a non-current user key generation -- so a naive full re-run finishes
 * a torn ceremony and a healthy account writes nothing.
 *
 * The honest limitation is the cascade's: ciphertext the credential's holder
 * already fetched and decrypted stays readable, and old epochs stay open to
 * the user key generations the credential already delivered. Retirement stops
 * future reads.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import {
  rotateRosterToDocumentAndCascade,
  type CascadeCollections,
  type RosterSealReport,
  type UserKey,
  type UserKeyCascadeResult
} from '../keys/index.js'
import type { WebvhIdStore } from '../webvh/index.js'
import type { AccountLogSigner } from '../webvh/accountEntry.js'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import { readPublishedLogOrThrow } from '../webvh/didWebvh.js'
import {
  assertLadderVmClaimed,
  attributeUnlockLadderInventory,
  ladderVmClaimOf,
  removeUnlockKey,
  unlockKeyVmId,
  type LadderVmRemovalReport,
  type StandingUnlockKeys
} from './standingWebvh.js'

/**
 * What a completed retirement reports: whether the roster actually rotated on
 * this run (a re-run of an already-complete retirement reports `false`), the
 * roster's seal-backstop report (present when the roster store is sealable and
 * the roster stage ran), the per-collection fan-out result, the document as
 * the inventory edit left it, the rotated key with the roster descriptor it
 * was read from, whatever the dependent-record re-mint pass returned
 * (`dependentRecords`, absent when no closure was supplied), and the
 * inventory edit's ladder VM report (`ladderVm`: what the edit struck, and
 * what stands unclaimed after it -- a seedless strike that claimed nothing
 * reports its credential's VM there rather than reading as clean).
 */
export interface UnlockCredentialRetirementResult {
  rotated: boolean
  ladderVm: LadderVmRemovalReport
  rosterSeal?: RosterSealReport
  collections: UserKeyCascadeResult
  document: object
  userKey?: UserKey
  rosterDescriptor?: CollectionEncryption
  clientAnnex?: ClientAnnexInventoryRetirement
  dependentRecords?: unknown
}

/**
 * What the annex-inventory stage reports: `struck` (a strike entry dropped
 * the retired rung's key and hash), `swapped` (a fresh generation replaced
 * the old one wholesale), `clean` (the pointed generation held no inventory
 * for the retired credential), or `skipped` with the reason (`no-pointer`:
 * the account has no annex inventory; `no-ladder-seed`: the ceremony holds
 * no seed that could strike or swap; `failed`: the closure reported a
 * failure, or threw and the ceremony caught it).
 */
export interface ClientAnnexInventoryRetirement {
  action: 'struck' | 'swapped' | 'clean' | 'skipped'
  reason?: 'no-pointer' | 'no-ladder-seed' | 'failed'
}

/**
 * Retires one standing unlock credential from an account. See the module doc
 * for the order and the convergence story. Once the inventory edit lands, a
 * thrown later stage leaves durable state a naive re-run -- or the login-time
 * sweep -- converges from.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}   the account's `id` collection store
 * @param options.signer {AccountLogSigner}   who signs the inventory edit:
 *   the retiring enrolled client's own did:webvh update-key seeds, or the
 *   ACTING (surviving or successor) credential's ladder seed
 * @param options.unlockKeys {StandingUnlockKeys}   the retired credential's
 *   public inventory (its key-agreement publication and its recorded update
 *   key, which the inventory edit treats as a ladder anchor rather than truth
 *   -- see `removeUnlockKey`)
 * @param [options.ladderSeed] {Uint8Array}   the retired credential's ladder
 *   seed, when the ceremony holds the credential's secret; it strengthens the
 *   ladder attribution, and it is what a retry supplies after a seedless run
 *   refused with `UnclaimedLadderVmRetirementError`
 * @param [options.projectionStore] {object}   an `id`-collection store the
 *   caller may write through, passed straight to the inventory edit: the
 *   post-strike `did:web` projection is PUT through it immediately before
 *   that entry publishes, so a ladder-signed retirement does not leave
 *   `did.json` naming the retired credential. Best-effort, and omitted the
 *   behavior is unchanged (see `removeUnlockKey`)
 * @param [options.expectedDid] {string}   the account DID from the caller's
 *   stored account pointer; supplied, the inventory edit refuses a `did.jsonl`
 *   resolving to any other account
 * @param [options.pinStore] {ResourceLogPinStore}   this client's chain-head
 *   pins, threaded to BOTH account-log reads the ceremony makes -- stage 0's
 *   attribution read and the inventory edit's own read inside its
 *   conflict-retry loop -- so a served rollback or fork is refused before
 *   anything is published
 * @param [options.logId] {string}   the account log's pin slot
 *   (`accountLogPinId({ spaceId })`); required whenever a `pinStore` is
 *   supplied
 * @param [options.verb] {string}   what the caller is doing, for the
 *   pending-rotation refusal message (e.g. `'changing your passphrase'`)
 * @param options.rosterStore {EncryptionDescriptorStore}   the
 *   `key-map/user-key.jsonl` roster store
 * @param [options.userKey] {UserKey}   this client's cached user key
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key -- its roster entry
 * @param [options.pinnedEpochId] {string}   the locally pinned latest-seen
 *   roster epoch
 * @param [options.onUserKeyAdopted] {Function}   persists a rotated key:
 *   called with `{ userKey, latestEpochId, descriptor }` after the roster read
 *   and BEFORE the fan-out. The key and the epoch pin must persist atomically
 * @param options.collections {CascadeCollections}   the fan-out's work
 * @param [options.remintDependentRecords] {Function}   `({ document,
 *   retiringKeyMultibases }) => Promise<unknown>` -- the dependent-record
 *   re-mint (stage 0), run against the PRE-edit document with the ladder VM
 *   ids this retirement is about to strike. Fail-closed: a throw aborts the
 *   retirement before the document edit. Absent, the stage is skipped and no
 *   log read happens for it (the no-WAS path). It is also skipped on the
 *   ladder arm: every unlock record is signed by its own credential's ladder
 *   VM, so this strike rots no sibling record, and there is nothing to
 *   re-mint (`decisions/0019`)
 * @param [options.retireClientAnnexInventory] {Function}   `({ document }) =>
 *   Promise<ClientAnnexInventoryRetirement>` -- the annex reach (stage 1b in
 *   the module doc), run against the post-edit document; a throw is caught
 *   and reported as `{ action: 'skipped', reason: 'failed' }`
 * @param [options.onRotationAdopted] {Function}   `({ userKey }) =>
 *   Promise<void>` -- the live-session adoption of a rotated key, run last so
 *   the session keeps operating without a re-login
 * @returns {Promise<UnlockCredentialRetirementResult>}
 */
export async function retireUnlockCredential({
  idStore,
  signer,
  unlockKeys,
  ladderSeed,
  projectionStore,
  expectedDid,
  pinStore,
  logId,
  verb,
  rosterStore,
  userKey,
  clientKeyAgreementKey,
  pinnedEpochId,
  onUserKeyAdopted,
  collections,
  remintDependentRecords,
  retireClientAnnexInventory,
  onRotationAdopted
}: {
  idStore: WebvhIdStore
  signer: AccountLogSigner
  unlockKeys: StandingUnlockKeys
  ladderSeed?: Uint8Array
  projectionStore?: Pick<WebvhIdStore, 'getIdResourceRaw' | 'putIdResource'>
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
  verb?: string
  rosterStore: EncryptionDescriptorStore
  userKey?: UserKey
  clientKeyAgreementKey: IKeyAgreementKey
  pinnedEpochId?: string | null
  onUserKeyAdopted?: (adopted: {
    userKey: UserKey
    latestEpochId: string
    descriptor: CollectionEncryption
  }) => Promise<void>
  collections: CascadeCollections
  remintDependentRecords?: (options: {
    document: object
    retiringKeyMultibases: string[]
  }) => Promise<unknown>
  retireClientAnnexInventory?: (options: {
    document: object
  }) => Promise<ClientAnnexInventoryRetirement>
  onRotationAdopted?: (rotation: { userKey: UserKey }) => Promise<void>
}): Promise<UnlockCredentialRetirementResult> {
  // 0. The dependent-record re-mint, against the PRE-edit document: whatever
  // the doomed ladder VM signed for OTHER credentials is re-signed under a
  // key that outlives the edit. The pass is named the VM ids the attribution
  // claims for this credential, and it runs even when that list is empty:
  // the pass has an expiry axis of its own, and a near-lapse sibling bridge
  // is worth refreshing in the same window. Fail-closed -- a throw aborts
  // here, with the credential still standing.
  const pinned = {
    ...(pinStore ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {})
  }
  let dependentRecords: unknown
  let expectedLadderVmIds: string[] | undefined
  // The stage is the enrolled branch's alone. On the ladder arm a record's
  // bridge and sibling are signed by its own credential's ladder VM, so this
  // strike reaches no record but the retired credential's own, which the
  // caller deletes with its unlock Space (`decisions/0019`).
  const ranRemint = Boolean(remintDependentRecords) && signer.kind === 'client'
  if (ranRemint && remintDependentRecords) {
    const published = await readPublishedLogOrThrow({
      idStore,
      ...(expectedDid !== undefined ? { expectedDid } : {}),
      ...pinned,
      missingMessage: 'did:webvh: did.jsonl is missing; nothing to enroll into.'
    })
    const inventory = await attributeUnlockLadderInventory({
      log: published.log,
      did: published.did,
      unlockKeys,
      ...(ladderSeed ? { ladderSeed } : {})
    })
    // The gate, before the pass writes anything: a claim that strikes no
    // ladder VM while VMs stand unclaimed refuses here, with the credential
    // still standing and no sibling record touched.
    await assertLadderVmClaimed({
      log: published.log,
      doc: published.doc,
      credentialVmId: unlockKeyVmId({
        did: published.did,
        keyAgreement: unlockKeys.keyAgreement
      }),
      claim: await ladderVmClaimOf({
        doc: published.doc,
        did: published.did,
        inventory,
        ...(ladderSeed ? { ladderSeed } : {})
      }),
      anchorKeyMultibase: unlockKeys.updateKeyMultibase
    })
    // What the edit's own attribution must resolve to: the pass below acts on
    // this list, so an edit that resolved a different one would strike
    // something the pass never covered.
    expectedLadderVmIds = inventory.ladderVmIds
    dependentRecords = await remintDependentRecords({
      document: published.doc,
      retiringKeyMultibases: inventory.ladderVmIds
    })
  }

  // 1. The document inventory edit -- the credential's standing, first. It
  // resolves the document as it now stands, which is what stage 2 resolves
  // its remaining recipients from.
  const { did, doc, log, ladderVm } = await removeUnlockKey({
    idStore,
    signer,
    unlockKeys,
    ...(ladderSeed ? { ladderSeed } : {}),
    ...(projectionStore ? { projectionStore } : {}),
    ...(expectedLadderVmIds !== undefined ? { expectedLadderVmIds } : {}),
    requireLadderVmClaim: true,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...pinned,
    ...(verb !== undefined ? { verb } : {})
  })

  // 1b. The annex reach, against the post-edit document: strike the
  // retired credential's rung inventory out of the pointed generation, or swap
  // the generation out from under it. Best-effort by contract, enforced here:
  // a throw escaping the closure maps to the `failed` skip, so the roster
  // rotation below always runs.
  let clientAnnex: ClientAnnexInventoryRetirement | undefined
  if (retireClientAnnexInventory) {
    try {
      clientAnnex = await retireClientAnnexInventory({ document: doc })
    } catch {
      clientAnnex = { action: 'skipped', reason: 'failed' }
    }
  }

  // 2. The shared roster-and-cascade tail: the roster rotation onto the
  // post-edit document (with its post-edit minimum controller version and its seal
  // backstop), then the collection fan-out onto the fresh key.
  const tail = await rotateRosterToDocumentAndCascade({
    rosterStore,
    did,
    doc,
    log,
    ...(userKey ? { userKey } : {}),
    clientKeyAgreementKey,
    pinnedEpochId,
    ...(onUserKeyAdopted ? { onUserKeyAdopted } : {}),
    collections
  })
  if (!tail.rosterDescriptor || !tail.userKey) {
    // No roster to rotate: the inventory edit has landed, so the credential IS
    // retired -- a completed ceremony with nothing rotated.
    return {
      rotated: false,
      ladderVm,
      collections: tail.collections,
      document: doc,
      ...(clientAnnex ? { clientAnnex } : {}),
      ...(ranRemint ? { dependentRecords } : {})
    }
  }

  if (tail.rotated) {
    await onRotationAdopted?.({ userKey: tail.userKey })
  }

  return {
    rotated: tail.rotated,
    ladderVm,
    ...(tail.rosterSeal ? { rosterSeal: tail.rosterSeal } : {}),
    collections: tail.collections,
    document: doc,
    userKey: tail.userKey,
    rosterDescriptor: tail.rosterDescriptor,
    ...(clientAnnex ? { clientAnnex } : {}),
    ...(ranRemint ? { dependentRecords } : {})
  }
}
