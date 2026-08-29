/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The mend entry point: a converging ensure over the tear states the
 * credential-anchored establishment can leave, so any door into a torn
 * account (a transient login, a remembered resume, a future step-up, another
 * wallet app) runs the same repairs instead of hand-rolling its own. The
 * arms, in order -- each fires at most once per invocation, and arms may
 * cascade within one invocation (there is deliberately no repair-wide
 * single shot):
 *
 * - The ESTABLISHMENT arm, when the pointer names no did:webvh. It probes
 *   durable state first: an account log that already resolves, attributes
 *   to this credential's ladder, AND carries the delegated-clients pointer
 *   means the DID-less record is a RECORD DOWNGRADE left by a concurrent or
 *   stale heal, and the mend is re-binding the record to the published DID
 *   -- never re-running stage 1, which would re-write the DID-less record
 *   and then die on the promoted Space, permanently. A revealed rung with
 *   NO pointer is instead the stage-3 tear (the pointer entry never
 *   landed), and falls through with every other probe outcome to the whole
 *   establishment run, itself the ensure. Either way the arm returns
 *   immediately with `reenter: true` on convergence: the record changed
 *   durably, so the caller must re-fetch it through its own keyring fetcher
 *   and re-enter -- and the single-shot re-entry marker stays CALLER-side,
 *   on that re-entry glue (a mend-internal counter would reset on each
 *   fresh invocation, letting a host that pins a stale DID-less record
 *   drive an unbounded establish/re-fetch loop). A re-bind additionally
 *   reports `reenterRepairShaped: true` -- its root registry window is
 *   closed, so the caller's re-entry must carry `repairShaped: true` for
 *   the registry arm to fire. A throw from the establishment run is caught
 *   into the report as the arm's error, never propagated raw -- with one
 *   exception: the probe's `ResourceLogContinuityError` rethrows by name,
 *   since a served rollback, fork, or identity switch must surface as the
 *   continuity refusal it is, never be met with a fresh establishment.
 * - The PROMOTION arm, on a promoted-pointer record. Two triggers: a
 *   caller-supplied failed delegated read (`delegatedRead`), or an
 *   authority-neutral probe. The probe must not mistake healthy for torn:
 *   `space.describe()` under the bootstrap did:key cannot distinguish
 *   "unpromoted" from "unauthorized" (WAS masks refusals), so a null read
 *   is EVIDENCE OF PROMOTION and the tear classifies only on an authorized
 *   read showing a non-account controller. The mend is
 *   `ensurePromotedSpaceController` under the ladder VM's bare did:key. On
 *   the delegated-read trigger the arm retries the read once and, on a
 *   promotion attempt or retry that still fails, RETHROWS THE ORIGINAL
 *   error unchanged (a healthy account's doomed promotion attempt lands
 *   here too, which is what keeps a mere transport flap distinguishable
 *   caller-side). Only a promotion that WROTE (`promoted` / `healed`) marks
 *   the entry repair-shaped for the arms below; a `confirmed` outcome means
 *   the account was healthy and the failed read a flap. The probe-triggered
 *   direction has no antecedent error; its non-convergence is a report
 *   member.
 * - The ROSTER-AND-EPOCHS arm, gated on the completion test "roster
 *   delivered AND every encrypted collection carries epoch[0]" -- durable
 *   state alone, never roster presence alone: a present roster is followed
 *   by the completion probe (~one Description read per encrypted
 *   collection, the stated budget) unless another trigger already fired the
 *   arm. The healthy fast path never invokes the mend at all. A fresh user
 *   key is minted ONLY when the shared stage's own decide-read observes the
 *   roster absent, and only under the mint preconditions -- checked at that
 *   same mint decision (`beforeMint`), whichever trigger fired the arm: no
 *   client-local roster-epoch pin held, no OTHER standing credential published
 *   in the verified document, no encrypted collection already epoch'd or
 *   unreadable -- a fabricated-absent roster must not become a
 *   single-recipient genesis that evicts every other standing credential.
 *   The ensure, the delivered-key re-read, and the fan-out are the shared
 *   mint-policy stage ({@link ensureRosterDeliveredEpochs}); a lost
 *   roster-genesis race adopts and reports converged-elsewhere, and a
 *   roster adopted with no wrap for this credential is its own outcome,
 *   never folded into "no roster". A FAILED roster or descriptor read is a
 *   transport error, never an incompleteness signal: it reports, and
 *   neither fires a spurious mint nor a spurious refusal.
 * - The REGISTRY arm, on an entry the invocation found repair-shaped (an
 *   arm above mended, or the caller flagged it): re-fires the caller's
 *   read-first `beforePromotion` hook under the caller-supplied
 *   post-promotion authority. The hook encapsulates its own registry
 *   protocol (read-first upsert, skip on a refused read); the mend knows
 *   nothing of the registry shape and only synthesizes the
 *   establishment-shaped context the hook expects. Detection therefore
 *   costs nothing on the healthy fast path: no tear, no hook fire.
 *
 * Caller obligations (they cross a package boundary, so they are contract,
 * not convention):
 *
 * - `account` MUST come from a BINDING-VERIFIED standing record: the
 *   pointer, controller, and ladder seed are trusted here, and a caller
 *   wiring the mend to a signature-checked but not binding-verified record
 *   would let a malicious host steer a full establishment (and the
 *   promotion arm) at an attacker-chosen account.
 * - Loudness ordering: every arm past the establishment arm exercises
 *   credential-derived authority (a Space Description PUT, roster appends,
 *   collection re-epochs) that extends no world-readable log, so the caller
 *   must have made its loud entry (the transient enrollment, or an enrolled
 *   client's standing) before invoking those arms.
 * - The re-entry single-shot marker for the establishment arm lives on the
 *   caller's re-entry glue, exactly as today's `healAttempted` rides.
 *
 * The return contract is deliberately mixed, and callers consume it as
 * typed API: the establishment and roster arms report non-convergence as
 * outcome members (the arm's own error carried on the member); the
 * promotion arm THROWS the original delegated-read error unchanged when
 * that trigger's mend or retry fails, and reports on the probe-triggered
 * direction. "Converged" always means the durable state the arm gated on
 * CHANGED, never merely that the arm ran without throwing.
 */
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'
import type { WasClient } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import type { ZcapClient } from '@interop/ezcap'
import { ensurePromotedSpaceController } from '../genesis/accountGenesis.js'
import type { SpaceControllerPromotion } from '../genesis/accountGenesis.js'
import {
  keyAgreementCommitment,
  readPublishedLog,
  relationIds
} from '../webvh/didWebvh.js'
import type {
  DidWebKeyMapV2,
  PublishedWebvhLog,
  WebvhIdStore
} from '../webvh/didWebvh.js'
import { isWebvhDid } from '../webvh/did.js'
import { accountLogPinId } from '../webvh/verifyLog.js'
import type { ICapabilityAgent } from '../webvh/zcap.js'
import type { AccountPointer } from '../keyring/record.js'
import {
  delegateLogWrite,
  delegationProofKeyId
} from '../recovery/recoveryDelegation.js'
import { mintUserKey, type UserKey } from '../keys/index.js'
import type { CollectionEncryption } from '@interop/was-client'
import { WALLET_SPACE_PROVISION_ROSTER } from '../space/collections.js'
import { attributeLadderRung } from './ladder.js'
import type { LadderRung, LadderRungState } from './ladder.js'
import { ladderVmAgent, ladderVmZcapClient } from './zcap.js'
import {
  clientAnnexDidParts,
  delegatedClientsPointer,
  mintDelegatedClientsDelegation
} from './log.js'
import {
  assertBindResult,
  currentLogParameters,
  establishCredentialAnchoredAccount,
  zcapExpires
} from './establish.js'
import type {
  CredentialAnchoredBindRecordHook,
  CredentialAnchoredEstablishment,
  CredentialAnchoredStandingFields
} from './establish.js'
import { ensureRosterDeliveredEpochs } from './rosterDeliveredEpochs.js'
import { stageNotifier, type StageNotifier } from '../log.js'

/**
 * The BINDING-VERIFIED account core the mend acts on, as one object rather
 * than loose fields: the caller's codec (the keyring layer) must have
 * verified the record's binding MAC before these members are trusted -- see
 * the module doc's caller obligations.
 */
export interface CredentialAnchoredAccountCore {
  controller: string
  pointer: AccountPointer
  ladderSeed: Uint8Array
}

/**
 * The registry-arm context: the standing record members the synthesized
 * `beforePromotion` context carries in place of a live establishment result.
 * All of it comes from the caller's own record; the mend records nothing of
 * the registry protocol itself.
 */
export interface CredentialAnchoredRegistryContext {
  unlockSpaceId: string
  manageCapability?: IZcap
  delegation?: IZcap
  delegatedClients?: IZcap
  unlockKeyAgreementKeyId?: string
  unlockKeyAgreementKeyMultibase?: string
}

/**
 * What one mend invocation did. A member is present iff its arm FIRED (found
 * its tear, or was triggered); a healthy account that was never repair-shaped
 * produces an empty report. `reenter: true` says the establishment arm
 * changed the record durably (a completed establishment, or a record re-bind)
 * and the caller must re-fetch the record and re-enter -- carrying its own
 * single-shot marker across that re-entry.
 */
export interface CredentialAnchoredMendReport {
  reenter: boolean
  /**
   * Set beside `reenter: true` when the re-entered record is still
   * repair-shaped: the record-downgrade re-bind rewrote the record but ran
   * no registry hook (the root window a live establishment's own write uses
   * is permanently closed here). The caller's re-entry glue MUST pass
   * `repairShaped: true` on the re-entry invocation so the registry arm
   * fires under the post-promotion authority.
   */
  reenterRepairShaped?: boolean
  establishment?: {
    converged: boolean
    outcome: 'established' | 'rebound'
    did?: string
    error?: unknown
  }
  promotion?: {
    converged: boolean
    outcome?: 'promoted' | 'retried'
    error?: unknown
  }
  rosterEpochs?: {
    converged: boolean
    outcome?: 'delivered' | 'converged-elsewhere' | 'no-wrap' | 'mint-refused'
    userKey?: UserKey
    error?: unknown
    epochsFailed?: Array<{ collectionId: string; error: unknown }>
  }
  registry?: {
    converged: boolean
    skipped?: string
    error?: unknown
  }
}

/**
 * Mends a credential-anchored account from whatever tear state its durable
 * artifacts show (see the module doc for the arms, their order, the caller
 * obligations, and the mixed return contract). The options are a superset of
 * {@link establishCredentialAnchoredAccount}'s hooks -- the establishment arm
 * hands them through verbatim -- so a caller passes one bundle.
 *
 * @param options {object}
 * @param options.account {CredentialAnchoredAccountCore}   the
 *   BINDING-VERIFIED account core (controller, pointer, ladder seed) from
 *   the caller's standing record; never loose or unverified fields
 * @param options.standing {object}   the credential's standing client
 *   identity (`clientDid`, `keyAgreementKeyMultibase`, `recipientKid`,
 *   `keyAgreementKey`), as the establishment takes it
 * @param options.bindRecord {CredentialAnchoredBindRecordHook}   REQUIRED:
 *   the unlock-record codec closure; the establishment arm's re-run and the
 *   record-downgrade re-bind both write through it
 * @param options.rosterStoreFor {Function}   REQUIRED: the establishment's
 *   bootstrap-invoked roster store builder (`({ did }) => store`); used only
 *   inside the establishment arm's re-run
 * @param options.bootstrapWasFor {Function}   REQUIRED:
 *   `({ keyAgent }) => WasClient` signing as the ladder VM's bare did:key;
 *   the promotion arm's mend and the establishment arm ride it
 * @param options.idStore {WebvhIdStore}   the account's `id` collection
 *   store (the establishment arm's probe and the registry arm's rung
 *   attribution read through it)
 * @param options.lowEntropy {boolean}   threaded to the establishment arm
 *   (the hash-commitment fail-safe is the establishment's)
 * @param [options.priorCreatedAt] {string}   the standing record's freshness
 *   stamp; threads to the establishment re-run (skipping its first bind) and
 *   to the record-downgrade re-bind
 * @param [options.delegatedClients] {IZcap}   the record's sibling
 *   delegation, for the establishment arm's stage-3 Space resolution
 * @param [options.provideDidWebKeys] {Function}   the establishment's
 *   best-effort KMS/did:web thunk, handed through
 * @param [options.promoteKeystore] {Function}   the establishment's
 *   best-effort keystore promotion, handed through
 * @param [options.beforePromotion] {Function}   the caller's read-first
 *   registry hook. The establishment arm's re-run fires it in its own root
 *   window; the registry arm re-fires it under the post-promotion
 *   `invocation` authority on a repair-shaped entry. It must encapsulate its
 *   own read-first-and-skip-on-refused-read rule
 * @param [options.invocation] {object}   the post-promotion authority
 *   triple: `was` and `zcapClient` signing as the caller's live invocation
 *   identity (a transient visit's annex identity, or an enrolled client), and
 *   `capability` (the generation delegation) their requests ride. Required
 *   by the roster-and-epochs and registry arms
 * @param [options.rosterStore] {EncryptionDescriptorStore}   the user-key
 *   roster's store under the SAME post-promotion authority, with a
 *   ladder-signed log signer -- the roster arm's store (the bootstrap
 *   `rosterStoreFor` cannot serve it: the promoted Space refuses bootstrap
 *   invocations)
 * @param [options.delegatedRead] {object}   the promotion arm's
 *   failed-delegated-read trigger: `error` (the original failure, rethrown
 *   unchanged on a non-converging mend) and `retry` (re-runs the caller's
 *   read once after the promotion lands; its result stays caller-side)
 * @param options.hasRosterEpochPin {Function}   REQUIRED:
 *   `() => Promise<boolean>` -- the mint precondition port: whether this
 *   caller holds a client-local roster-epoch pin for the account. A caller with
 *   no client-local pins (the transient visit's in-memory pins) passes
 *   `async () => false` explicitly, so "no pin" is always a statement, never
 *   a dropped option
 * @param [options.registry] {CredentialAnchoredRegistryContext}   the
 *   registry arm's context, from the caller's own standing record
 * @param [options.userKey] {UserKey}   the session's user key, when the
 *   caller already holds one -- the registry arm's context when the roster
 *   arm did not deliver a key this invocation
 * @param [options.repairShaped] {boolean}   the caller's explicit
 *   repair-shaped flag: fires the roster completion and registry arms even
 *   when no earlier arm found a tear (the registry-only tear's entry, and
 *   the re-entry after a `reenterRepairShaped` report)
 * @param [options.collectionIds] {string[]}   the encrypted-collection set
 *   the roster arm covers (the completion probe, the mint preconditions, and
 *   the epoch fan-out); defaults to the wallet Space roster's encrypted
 *   collections
 * @param [options.pinStore] {ResourceLogPinStore}   chain-head pins for the
 *   log reads here
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @param [options.onStage] {StageNotifier}   observational: called as each
 *   arm finishes, with `establishment-arm`, `promotion-arm`,
 *   `roster-epochs-arm`, and `registry-arm` -- only for the arms that
 *   actually ran. It is forwarded into the establishment re-run, so that
 *   arm's own stage names arrive first
 * @returns {Promise<CredentialAnchoredMendReport>}
 * @throws {TypeError}   synchronously, when a required hook is missing
 * @throws the original `delegatedRead.error`, unchanged, when that trigger's
 *   promotion mend or read retry fails
 * @throws the establishment-arm probe's `ResourceLogContinuityError`,
 *   unchanged: a served log refused against the chain-head pin must surface
 *   as the continuity refusal it is, never be swallowed into a full
 *   establishment re-run over a rolled-back or substituted log
 */
export function mendCredentialAnchoredAccount(options: {
  account: CredentialAnchoredAccountCore
  standing: {
    clientDid: string
    keyAgreementKeyMultibase: string
    recipientKid: string
    keyAgreementKey: IKeyAgreementKey
  }
  bindRecord: CredentialAnchoredBindRecordHook
  rosterStoreFor: (options: { did: string }) => EncryptionDescriptorStore
  bootstrapWasFor: (options: { keyAgent: ICapabilityAgent }) => WasClient
  idStore: WebvhIdStore
  lowEntropy: boolean
  priorCreatedAt?: string
  delegatedClients?: IZcap
  provideDidWebKeys?: () => Promise<DidWebKeyMapV2 | undefined>
  promoteKeystore?: (options: { did: string }) => Promise<void>
  beforePromotion?: (context: {
    was: WasClient
    zcapClient: ZcapClient
    did: string
    userKey: UserKey
    establishment: CredentialAnchoredEstablishment
  }) => Promise<void>
  invocation?: { was: WasClient; zcapClient: ZcapClient; capability: IZcap }
  rosterStore?: EncryptionDescriptorStore
  delegatedRead?: { error: unknown; retry: () => Promise<void> }
  hasRosterEpochPin: () => Promise<boolean>
  registry?: CredentialAnchoredRegistryContext
  userKey?: UserKey
  repairShaped?: boolean
  collectionIds?: string[]
  pinStore?: ResourceLogPinStore
  now?: number
  onStage?: StageNotifier
}): Promise<CredentialAnchoredMendReport> {
  if (typeof options.bindRecord !== 'function') {
    throw new TypeError(
      'mendCredentialAnchoredAccount requires bindRecord: both the ' +
        'establishment re-run and the record-downgrade re-bind write the ' +
        'record through it.'
    )
  }
  if (typeof options.rosterStoreFor !== 'function') {
    throw new TypeError(
      'mendCredentialAnchoredAccount requires rosterStoreFor: the ' +
        "establishment arm's re-run cannot land a roster without it."
    )
  }
  if (typeof options.bootstrapWasFor !== 'function') {
    throw new TypeError(
      'mendCredentialAnchoredAccount requires bootstrapWasFor: the ' +
        "promotion arm signs as the ladder VM's bare did:key."
    )
  }
  if (typeof options.hasRosterEpochPin !== 'function') {
    throw new TypeError(
      'mendCredentialAnchoredAccount requires hasRosterEpochPin: the mint ' +
        'preconditions must be told whether a client-local roster-epoch pin ' +
        'is held (a caller with no client-local pins passes ' +
        'async () => false).'
    )
  }
  return mendCredentialAnchoredAccountChecked(options)
}

/**
 * The checked body of {@link mendCredentialAnchoredAccount}.
 *
 * @param options {object}   see {@link mendCredentialAnchoredAccount}
 * @returns {Promise<CredentialAnchoredMendReport>}
 */
async function mendCredentialAnchoredAccountChecked(
  options: Parameters<typeof mendCredentialAnchoredAccount>[0]
): Promise<CredentialAnchoredMendReport> {
  const { account, standing, idStore, pinStore } = options
  const { pointer, ladderSeed } = account
  const report: CredentialAnchoredMendReport = { reenter: false }
  const stage = stageNotifier(options.onStage)
  // The bootstrap identity every arm needs. A failure here (a malformed
  // ladder seed, a throwing factory) rides the report of whichever arm the
  // pointer shape selects, keeping the documented throw surface -- except
  // under the delegated-read trigger, whose contract is the original error.
  let bootstrapAgent: ICapabilityAgent
  let bootstrapWas: WasClient
  try {
    bootstrapAgent = await ladderVmAgent({ ladderSeed })
    bootstrapWas = options.bootstrapWasFor({ keyAgent: bootstrapAgent })
  } catch (err) {
    if (!isWebvhDid(pointer.did)) {
      report.establishment = {
        converged: false,
        outcome: 'established',
        error: err
      }
      return report
    }
    if (options.delegatedRead !== undefined) {
      throw options.delegatedRead.error
    }
    report.promotion = { converged: false, error: err }
    return report
  }
  const pinned =
    pinStore !== undefined
      ? { pinStore, logId: accountLogPinId({ spaceId: pointer.spaceId }) }
      : {}

  // The establishment arm: a DID-less pointer. Probe durable state before
  // re-running -- an already-resolvable, ladder-attributing log means the
  // record was DOWNGRADED and the mend is a re-bind, never a stage-1 re-run.
  if (!isWebvhDid(pointer.did)) {
    let published: PublishedWebvhLog | undefined
    try {
      published = await readPublishedLog({ idStore, ...pinned })
    } catch (err) {
      // A continuity refusal against the chain-head pin is a served
      // rollback, fork, or identity switch: surface it as itself, never
      // swallow it into "no log" and re-run an establishment over it.
      if ((err as { name?: string }).name === 'ResourceLogContinuityError') {
        throw err
      }
      // Any other unreadable log probes as unresolved; the establishment
      // run below meets (and reports) whatever the store's real state is.
      published = undefined
    }
    const attributed =
      published === undefined
        ? undefined
        : await attributeLadderRungSafely({
            ladderSeed,
            published
          })
    // The re-bind classifies ONLY a fully established account: the log
    // resolves, the ladder attributes with a revealed rung, AND the
    // document already points at a generation. A revealed rung with no
    // pointer is the stage-3 tear (the pointer entry never landed), whose
    // mender is the establishment run itself -- its pointer stage is the
    // ensure -- never a re-bind that has no sibling target to name.
    const pointed =
      published === undefined
        ? undefined
        : delegatedClientsPointer({ doc: published.doc })
    if (
      published !== undefined &&
      attributed?.state === 'revealed' &&
      pointed !== undefined
    ) {
      try {
        await rebindDowngradedRecord({
          options,
          published,
          pointed,
          bootstrapAgent
        })
        report.establishment = {
          converged: true,
          outcome: 'rebound',
          did: published.did
        }
        report.reenter = true
        report.reenterRepairShaped = true
      } catch (err) {
        report.establishment = {
          converged: false,
          outcome: 'rebound',
          error: err
        }
      }
      stage('establishment-arm')
      return report
    }
    try {
      const established = await establishCredentialAnchoredAccount({
        wasServerUrl: pointer.host,
        spaceId: pointer.spaceId,
        ladderSeed,
        standing,
        bindRecord: options.bindRecord,
        rosterStoreFor: options.rosterStoreFor,
        bootstrapWasFor: options.bootstrapWasFor,
        idStore,
        lowEntropy: options.lowEntropy,
        ...(published !== undefined ? { expectedDid: published.did } : {}),
        ...(options.priorCreatedAt !== undefined
          ? { priorCreatedAt: options.priorCreatedAt }
          : {}),
        ...(options.delegatedClients !== undefined
          ? { delegatedClients: options.delegatedClients }
          : {}),
        ...(options.provideDidWebKeys
          ? { provideDidWebKeys: options.provideDidWebKeys }
          : {}),
        ...(options.promoteKeystore
          ? { promoteKeystore: options.promoteKeystore }
          : {}),
        ...(options.beforePromotion
          ? { beforePromotion: options.beforePromotion }
          : {}),
        ...(pinStore !== undefined ? { pinStore } : {}),
        ...(options.now !== undefined ? { now: options.now } : {}),
        ...(options.onStage !== undefined ? { onStage: options.onStage } : {})
      })
      report.establishment = {
        converged: true,
        outcome: 'established',
        did: established.did
      }
      report.reenter = true
    } catch (err) {
      report.establishment = {
        converged: false,
        outcome: 'established',
        error: err
      }
    }
    stage('establishment-arm')
    return report
  }

  // The promoted-pointer arms.
  const did = pointer.did
  let mended = false

  // The promotion arm, delegated-read trigger: the caller's read already
  // failed, so mend and retry -- and rethrow the ORIGINAL error unchanged
  // when either the mend or the retry still fails (a healthy account's
  // doomed promotion attempt refuses too, landing exactly here).
  if (options.delegatedRead !== undefined) {
    const delegatedRead = options.delegatedRead
    let promotionOutcome: SpaceControllerPromotion
    try {
      promotionOutcome = await ensurePromotedSpaceController({
        was: bootstrapWas,
        wasAsClient: bootstrapWas,
        spaceId: pointer.spaceId,
        did
      })
    } catch {
      throw delegatedRead.error
    }
    try {
      await delegatedRead.retry()
    } catch {
      throw delegatedRead.error
    }
    report.promotion = { converged: true, outcome: 'retried' }
    // Only a promotion that WROTE marks the entry repair-shaped: a
    // `confirmed` outcome means the account was healthy all along (the
    // failed read was a flap), and firing the roster completion and
    // registry arms off it would repair nothing.
    mended = promotionOutcome !== 'confirmed'
  } else {
    // The authority-neutral probe: a null read under the bootstrap did:key
    // is evidence of promotion (WAS masks "unauthorized" as absence), and
    // only an AUTHORIZED read showing a non-account controller classifies
    // the tear. Non-convergence here reports; there is no antecedent error
    // to rethrow.
    let described: { controller?: string } | null = null
    let probeFailed = false
    try {
      described = (await bootstrapWas.space(pointer.spaceId).describe()) as {
        controller?: string
      } | null
    } catch (err) {
      probeFailed = true
      report.promotion = { converged: false, error: err }
    }
    if (!probeFailed && described !== null && described.controller !== did) {
      try {
        const promotionOutcome = await ensurePromotedSpaceController({
          was: bootstrapWas,
          wasAsClient: bootstrapWas,
          spaceId: pointer.spaceId,
          did
        })
        report.promotion = { converged: true, outcome: 'promoted' }
        // A concurrent run may have promoted between the probe and the
        // ensure; `confirmed` then repairs nothing here either.
        mended = promotionOutcome !== 'confirmed'
      } catch (err) {
        report.promotion = { converged: false, error: err }
      }
    }
  }
  stage('promotion-arm')

  // The roster-and-epochs arm, gated on the ratified completion test --
  // "roster delivered AND every encrypted collection carries epoch[0]",
  // durable state alone, never roster presence alone. Fires on: an absent
  // roster head, an epoch-less encrypted collection behind a present roster
  // (the completion probe, ~one Description read per encrypted collection,
  // the stated budget), a prior arm's mend, or the caller's repair-shaped
  // flag.
  const rosterStore = options.rosterStore
  const invocation = options.invocation
  if (rosterStore !== undefined && invocation !== undefined) {
    let rosterAbsent = false
    let detectionFailed = false
    try {
      rosterAbsent = (await rosterStore.read()) === null
    } catch (err) {
      // Transport, never incompleteness: report, mint nothing, refuse
      // nothing.
      detectionFailed = true
      report.rosterEpochs = { converged: false, error: err }
    }
    let collectionEpochless = false
    if (!detectionFailed && !rosterAbsent && !mended && !options.repairShaped) {
      try {
        collectionEpochless = await hasEpochlessEncryptedCollection({
          options,
          invocation
        })
      } catch (err) {
        detectionFailed = true
        report.rosterEpochs = { converged: false, error: err }
      }
    }
    if (
      !detectionFailed &&
      (rosterAbsent || collectionEpochless || mended || options.repairShaped)
    ) {
      report.rosterEpochs = await runRosterEpochsArm({
        options,
        did,
        rosterStore,
        invocation
      })
      if (report.rosterEpochs.converged) {
        mended = true
      }
    }
    stage('roster-epochs-arm')
  }

  // The registry arm: a repair-shaped entry re-fires the caller's
  // read-first hook under the post-promotion authority (the root window the
  // establishment's own write used is permanently closed). The hook owns
  // the registry protocol; a hook that skips on a refused read is the
  // caller's own rule.
  if (
    options.beforePromotion !== undefined &&
    (mended || options.repairShaped)
  ) {
    report.registry = await runRegistryArm({ options, did, report })
    stage('registry-arm')
  }

  return report
}

/**
 * The ladder attribution over a published log, resolved as a value: the
 * establishment-arm probe treats an attribution failure (another ladder's
 * account, a struck inventory) the same as an unresolved log -- the
 * establishment run is what meets and reports the real state.
 *
 * @param options {object}
 * @param options.ladderSeed {Uint8Array}
 * @param options.published {PublishedWebvhLog}
 * @returns {Promise<object | undefined>}   the attributed rung and its
 *   state, or undefined when the attribution refuses
 */
async function attributeLadderRungSafely({
  ladderSeed,
  published
}: {
  ladderSeed: Uint8Array
  published: PublishedWebvhLog
}): Promise<{ rung: LadderRung; state: LadderRungState } | undefined> {
  try {
    return await attributeLadderRung({
      ladderSeed,
      published: currentLogParameters(published)
    })
  } catch {
    return undefined
  }
}

/**
 * The record-downgrade re-bind (the establishment's stage 4, standalone):
 * fresh ladder-VM-signed bridge and sibling delegations, then the record
 * re-bound to the published DID with the management delegation. Runs only
 * when the ladder attributes on the published log AND the document already
 * carries the delegated-clients pointer (the caller's gate), so the
 * delegations it signs verify under the standing document and the sibling
 * has a target to name.
 *
 * @param options {object}
 * @param options.options {object}   the mend options
 * @param options.published {PublishedWebvhLog}   the resolved account log
 * @param options.pointed {string}   the document's delegated-clients pointer
 *   (the annex DID the sibling delegation targets)
 * @param options.bootstrapAgent {ICapabilityAgent}   the ladder VM's bare
 *   did:key agent (the record's controller field, matching the
 *   establishment's own binds)
 * @returns {Promise<void>}
 */
async function rebindDowngradedRecord({
  options,
  published,
  pointed,
  bootstrapAgent
}: {
  options: Parameters<typeof mendCredentialAnchoredAccount>[0]
  published: PublishedWebvhLog
  pointed: string
  bootstrapAgent: ICapabilityAgent
}): Promise<void> {
  const { account, standing } = options
  const { pointer, ladderSeed } = account
  const fullPointer: AccountPointer = {
    spaceId: pointer.spaceId,
    host: pointer.host,
    did: published.did
  }
  const ladderZcap = await ladderVmZcapClient({
    accountDid: published.did,
    ladderSeed
  })
  const bridge = await delegateLogWrite({
    zcapClient: ladderZcap,
    pointer: fullPointer,
    recoveryClientDid: standing.clientDid
  })
  const sibling = await mintDelegatedClientsDelegation({
    zcapClient: ladderZcap,
    wasServerUrl: pointer.host,
    clientAnnexSpaceId: clientAnnexDidParts({ did: pointed }).spaceId,
    controller: standing.clientDid,
    ...(options.now !== undefined ? { now: options.now } : {})
  })
  const rebind = await options.bindRecord({
    controller: bootstrapAgent.id,
    pointer: fullPointer,
    delegation: bridge,
    delegatedClients: sibling,
    delegateManagementTo: published.did,
    ...(options.priorCreatedAt !== undefined
      ? { priorCreatedAt: options.priorCreatedAt }
      : {})
  })
  assertBindResult({ bind: rebind, stage: 'downgrade re-bind' })
}

/**
 * The refusing mint preconditions, carried as a throwable so the shared
 * mint-policy stage's `beforeMint` seam can surface them: thrown and caught
 * inside this module only, so `instanceof` is safe here.
 */
class RosterMintRefusedSignal extends Error {
  refusal: NonNullable<CredentialAnchoredMendReport['rosterEpochs']>

  constructor(options: {
    refusal: NonNullable<CredentialAnchoredMendReport['rosterEpochs']>
  }) {
    super('The roster mint preconditions refused.')
    this.name = 'RosterMintRefusedSignal'
    this.refusal = options.refusal
  }
}

/**
 * The encrypted-collection set the roster arm covers: the caller's
 * `collectionIds` override, or the wallet Space roster's encrypted
 * collections.
 *
 * @param options {object}   the mend options
 * @returns {string[]}
 */
function encryptedCollectionIds(
  options: Parameters<typeof mendCredentialAnchoredAccount>[0]
): string[] {
  return (
    options.collectionIds ??
    WALLET_SPACE_PROVISION_ROSTER.filter(spec => spec.encryption === 'edv').map(
      spec => spec.collectionId
    )
  )
}

/**
 * The completion probe's per-collection half: whether any encrypted
 * collection lacks epoch[0], read under the caller's post-promotion
 * authority. A null Description counts as epoch-less here: with the roster
 * present no mint can follow, so firing the arm on an absent (or masked)
 * collection only drives the create-if-absent fan-out, whose own refusals
 * ride the report's `epochsFailed` list. A thrown read propagates to the
 * caller as transport.
 *
 * @param options {object}
 * @param options.options {object}   the mend options
 * @param options.invocation {object}   the post-promotion authority triple
 * @returns {Promise<boolean>}
 */
async function hasEpochlessEncryptedCollection({
  options,
  invocation
}: {
  options: Parameters<typeof mendCredentialAnchoredAccount>[0]
  invocation: NonNullable<
    Parameters<typeof mendCredentialAnchoredAccount>[0]['invocation']
  >
}): Promise<boolean> {
  const space = invocation.was.space(options.account.pointer.spaceId, {
    capability: invocation.capability
  })
  for (const collectionId of encryptedCollectionIds(options)) {
    const description = (await space.collection(collectionId).describe()) as {
      encryption?: CollectionEncryption
    } | null
    if ((description?.encryption?.epochs?.length ?? 0) === 0) {
      return true
    }
  }
  return false
}

/**
 * The roster-and-epochs arm's body: the shared mint-policy stage under the
 * caller's post-promotion authority, with the mint preconditions threaded
 * into the stage's own mint decision (`beforeMint`) -- checked against the
 * SAME absent-roster observation the mint acts on, whichever trigger fired
 * the arm, never against the arm's earlier detection read.
 *
 * @param options {object}
 * @param options.options {object}   the mend options
 * @param options.did {string}   the account DID
 * @param options.rosterStore {EncryptionDescriptorStore}
 * @param options.invocation {object}   the post-promotion authority triple
 * @returns {Promise<object>}   the report member
 */
async function runRosterEpochsArm({
  options,
  did,
  rosterStore,
  invocation
}: {
  options: Parameters<typeof mendCredentialAnchoredAccount>[0]
  did: string
  rosterStore: EncryptionDescriptorStore
  invocation: NonNullable<
    Parameters<typeof mendCredentialAnchoredAccount>[0]['invocation']
  >
}): Promise<NonNullable<CredentialAnchoredMendReport['rosterEpochs']>> {
  const { account, standing } = options
  let delivered
  try {
    delivered = await ensureRosterDeliveredEpochs({
      store: rosterStore,
      candidateUserKey: await mintUserKey(),
      clientKeyAgreementKey: standing.keyAgreementKey,
      was: invocation.was,
      spaceId: account.pointer.spaceId,
      capability: invocation.capability,
      ...(options.collectionIds !== undefined
        ? { collectionIds: options.collectionIds }
        : {}),
      beforeMint: async () => {
        const refusal = await rosterMintRefusal({ options, did, invocation })
        if (refusal !== undefined) {
          throw new RosterMintRefusedSignal({ refusal })
        }
      }
    })
  } catch (err) {
    if (err instanceof RosterMintRefusedSignal) {
      return err.refusal
    }
    // The shared stage rethrows transport errors unchanged; here they are
    // the arm's report, never a refusal shape of their own.
    return { converged: false, error: err }
  }
  if (delivered.outcome === 'no-wrap') {
    return { converged: false, outcome: 'no-wrap', error: delivered.error }
  }
  if (delivered.epochs.failed.length > 0) {
    return {
      converged: false,
      outcome: delivered.outcome,
      userKey: delivered.userKey,
      epochsFailed: delivered.epochs.failed
    }
  }
  return {
    converged: true,
    outcome: delivered.outcome,
    userKey: delivered.userKey
  }
}

/**
 * The mint preconditions, fired from the shared stage's `beforeMint` seam --
 * on the same absent-roster observation the mint acts on: a
 * fabricated-absent roster must not become a single-recipient genesis. Each
 * refusal (and a precondition read that failed or masked, which cannot
 * prove the mint safe) reports as `mint-refused` with the reason as its
 * error.
 *
 * @param options {object}
 * @param options.options {object}   the mend options
 * @param options.did {string}
 * @param options.invocation {object}
 * @returns {Promise<object | undefined>}   the refusing report member, or
 *   undefined when the mint may proceed
 */
async function rosterMintRefusal({
  options,
  did,
  invocation
}: {
  options: Parameters<typeof mendCredentialAnchoredAccount>[0]
  did: string
  invocation: NonNullable<
    Parameters<typeof mendCredentialAnchoredAccount>[0]['invocation']
  >
}): Promise<CredentialAnchoredMendReport['rosterEpochs']> {
  const { account, standing, idStore, pinStore } = options
  const refused = (error: unknown) => ({
    converged: false,
    outcome: 'mint-refused' as const,
    error
  })
  try {
    if (await options.hasRosterEpochPin()) {
      return refused(
        new Error(
          'A client-local roster-epoch pin is held for this account; a ' +
            'served absent roster reads as a rollback, not a mint license.'
        )
      )
    }
    // No OTHER standing credential in the verified document: every
    // keyAgreement entry must be this credential's own publication
    // (verbatim, or its hash commitment).
    const published = await readPublishedLog({
      idStore,
      expectedDid: did,
      ...(pinStore !== undefined
        ? {
            pinStore,
            logId: accountLogPinId({ spaceId: account.pointer.spaceId })
          }
        : {})
    })
    if (published === undefined) {
      return refused(
        new Error(
          'The account log did not resolve; the mint preconditions cannot ' +
            'be verified.'
        )
      )
    }
    const commitment = await keyAgreementCommitment({
      keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase
    })
    const own = new Set([
      `${did}#${standing.keyAgreementKeyMultibase}`,
      `${did}#${commitment}`
    ])
    const doc = published.doc as {
      keyAgreement?: Array<string | { id?: string }>
    }
    const foreign = relationIds(doc.keyAgreement).filter(id => !own.has(id))
    if (foreign.length > 0) {
      return refused(
        new Error(
          'The verified document publishes another standing credential ' +
            `(${foreign.join(', ')}); minting a fresh roster would evict it.`
        )
      )
    }
    // No encrypted collection already epoch'd: a collection keyed under an
    // earlier user key beside an "absent" roster is fabricated absence.
    const space = invocation.was.space(account.pointer.spaceId, {
      capability: invocation.capability
    })
    for (const collectionId of encryptedCollectionIds(options)) {
      const description = (await space.collection(collectionId).describe()) as {
        encryption?: CollectionEncryption
      } | null
      if (description === null) {
        // WAS masks an unauthorized read as absence, so a null Description
        // cannot prove the collection epoch-less: refuse as unreadable
        // rather than license the mint on it.
        return refused(
          new Error(
            `Collection "${collectionId}" has no readable Description ` +
              'under this authority; the mint preconditions cannot be ' +
              'verified.'
          )
        )
      }
      if ((description.encryption?.epochs?.length ?? 0) > 0) {
        return refused(
          new Error(
            `Collection "${collectionId}" already carries a key epoch; a ` +
              'served absent roster beside it is fabricated absence.'
          )
        )
      }
    }
  } catch (err) {
    return refused(err)
  }
  return undefined
}

/**
 * The registry arm's body: synthesize the establishment-shaped context from
 * the caller's standing record and the log-attributed rung, then fire the
 * caller's read-first hook under the post-promotion authority.
 *
 * @param options {object}
 * @param options.options {object}   the mend options
 * @param options.did {string}
 * @param options.report {CredentialAnchoredMendReport}   the report so far
 *   (the roster arm's delivered key feeds the hook context)
 * @returns {Promise<object>}   the report member
 */
async function runRegistryArm({
  options,
  did,
  report
}: {
  options: Parameters<typeof mendCredentialAnchoredAccount>[0]
  did: string
  report: CredentialAnchoredMendReport
}): Promise<NonNullable<CredentialAnchoredMendReport['registry']>> {
  const { account, standing, idStore, pinStore } = options
  const invocation = options.invocation
  if (invocation === undefined) {
    return { converged: false, skipped: 'no-invocation' }
  }
  const registry = options.registry
  if (registry === undefined) {
    return { converged: false, skipped: 'no-registry-context' }
  }
  const userKey = report.rosterEpochs?.userKey ?? options.userKey
  if (userKey === undefined) {
    return { converged: false, skipped: 'no-user-key' }
  }
  try {
    const published = await readPublishedLog({
      idStore,
      expectedDid: did,
      ...(pinStore !== undefined
        ? {
            pinStore,
            logId: accountLogPinId({ spaceId: account.pointer.spaceId })
          }
        : {})
    })
    if (published === undefined) {
      return { converged: false, skipped: 'no-account-log' }
    }
    const attributed = await attributeLadderRungSafely({
      ladderSeed: account.ladderSeed,
      published
    })
    if (attributed?.state !== 'revealed') {
      return { converged: false, skipped: 'no-revealed-rung' }
    }
    const delegationKeyId = registry.delegation
      ? delegationProofKeyId(registry.delegation)
      : undefined
    const delegatedClientsKeyId = registry.delegatedClients
      ? delegationProofKeyId(registry.delegatedClients)
      : undefined
    const standingFields: CredentialAnchoredStandingFields = {
      rosterKid: standing.recipientKid,
      keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase,
      updateKeyMultibase: attributed.rung.keyMultibase,
      unlockClientDid: standing.clientDid,
      ...(delegationKeyId ? { delegationKeyId } : {}),
      ...(registry.delegation && zcapExpires(registry.delegation)
        ? { delegationExpires: zcapExpires(registry.delegation) }
        : {}),
      ...(delegatedClientsKeyId ? { delegatedClientsKeyId } : {}),
      ...(registry.delegatedClients && zcapExpires(registry.delegatedClients)
        ? { delegatedClientsExpires: zcapExpires(registry.delegatedClients) }
        : {}),
      ...(registry.unlockKeyAgreementKeyId
        ? { unlockKeyAgreementKeyId: registry.unlockKeyAgreementKeyId }
        : {}),
      ...(registry.unlockKeyAgreementKeyMultibase
        ? {
            unlockKeyAgreementKeyMultibase:
              registry.unlockKeyAgreementKeyMultibase
          }
        : {})
    }
    const establishment: CredentialAnchoredEstablishment = {
      did,
      unlockSpaceId: registry.unlockSpaceId,
      ...(registry.manageCapability
        ? { manageCapability: registry.manageCapability }
        : {}),
      standingFields,
      failed: []
    }
    await options.beforePromotion!({
      was: invocation.was,
      zcapClient: invocation.zcapClient,
      did,
      userKey,
      establishment
    })
    return { converged: true }
  } catch (err) {
    return { converged: false, error: err }
  }
}
