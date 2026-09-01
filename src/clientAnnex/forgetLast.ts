/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The LAST enrolled client's forget: the transition ceremony that takes an
 * account from one enrolled client to the client-less, ladder-anchored
 * state -- the same state a credential-anchored signup and a
 * transient recovery produce. Decision 0004's 2026-08-19 amendment fixes the
 * entry order, and it is forced twice over: the server's revocation endpoint
 * verifies a to-be-revoked capability's chain against the CURRENTLY resolved
 * document (so a ladder-signed chain revokes only while the ladder VM is
 * published), and the ladder VM carries no `capabilityInvocation` (so once
 * the client's verification method is gone, nothing can sign the revocation
 * POST at all). So:
 *
 * 1. **The strike-and-reinstall pair**
 *    ({@link strikeLadderVmWebvh}, then {@link installLadderVmWebvh}): this
 *    credential's own ladder VM leaves the document and returns in the next
 *    entry, the client's whole inventory standing throughout. A ladder VM's
 *    life is keyed to its credential rather than to the account's client
 *    census, so the VM already stands when the transition starts and a bare
 *    install would publish nothing; the reinstall is what carries the
 *    ceremony's inventory-changing document version under the ceremony-tail
 *    license. The strike reaches one credential's VM -- the id derives from
 *    the ladder seed -- so another standing credential's VM is untouched.
 *    The pair republishes the identical key under the identical id and
 *    revokes nothing, so the revocation stage below is undisturbed by it and
 *    every unexpired ladder-signed delegation keeps verifying. Its costs are
 *    stated rather than hidden: the reinstall reveals a rung that stands in
 *    `updateKeys`, as the single install already did, now over two entries;
 *    and a run torn between the two leaves the account with no ladder VM
 *    while the client still stands, which a re-run mends (the strike no-ops,
 *    the install reinstalls). The pair runs only when the rotation is still
 *    owed or the VM is missing, so a resumed run past the rotation publishes
 *    neither entry.
 *
 *    Both entries publish through `clientLogStore`, the store invoked under
 *    the ENROLLED client's root authority, and not through the credential's
 *    bridge delegation. The bridge is often signed by the very VM the strike
 *    removes -- the readiness stage's renewal mints it as the ladder, and
 *    stage 6 re-signs it as the ladder again -- so a bridge-invoked reinstall
 *    would be authorized against the post-strike document under the
 *    current-key-set rule and refused, leaving the account VM-less with every
 *    ladder-signed delegation rotted and a re-run failing identically. The
 *    client stands until stage 7 and holds root authority on the Space, so
 *    its store is the one that carries the pair. Only the HTTP invocation
 *    changes: both entries stay ladder-SIGNED.
 * 2. **The roster rotation**, ladder-signed, anchored at the reinstall entry,
 *    HTTP-invoked under the still-standing client: the user key rotates off
 *    this client's wrap in ONE append (the license's one-shot shape), read
 *    back through the credential's standing wrap. Because the append's
 *    signer is the ladder VM -- a key the post-removal document still lists
 *    -- the roster log needs no seal repair afterwards, which matters on
 *    an account where no enrolled client's login sweep will ever run again.
 * 3. **The collection fan-out**, still under this client's invocation
 *    authority: every encrypted collection re-epochs onto the fresh key.
 * 4. **The generation-delegation replacement and revocations**: a fresh
 *    ladder-signed generation delegation replaces the embedded one when the
 *    house staleness policy, read against a projected post-edit document,
 *    says it is owed -- this credential's ladder VM and the forgotten client
 *    are both named retiring, which is every key this ceremony ends. Then
 *    EVERY still-unexpired delegation the annex log's history ever embedded
 *    that this credential's ladder VM signed is revoked at the server (a
 *    renewal inside the 30-day window can leave two) -- closing the
 *    resurrection window a reinstalled derived-key VM would otherwise
 *    reopen. The replacement is what keeps the account
 *    transient-login-reachable after the transition; replace-before-revoke
 *    is what keeps a torn run from stranding the generation delegation-less.
 *    A delegation a surviving sibling credential's ladder signed is left
 *    standing, since the revocation loop never reaches it either.
 * 5. **The other unlock methods' record re-mint** (`unlockMethods`): every
 *    other standing credential's and recovery code's bridge (and
 *    `delegatedClients` sibling, where the record carries one) is re-signed
 *    by the ladder VM and its record re-sealed through the entry's
 *    management zcap -- the revocation cascade's re-mint pass
 *    (`remintRecoveryDelegations`), run with the ladder VM as the delegating
 *    and record-signing key and the forgotten client named as retiring, so
 *    every delegation it signed counts as rotted ahead of the removal entry.
 *    Delegations the removed client had signed rot at that entry, and on a
 *    client-less account no remembered login's refresh block will ever run
 *    again to heal them, so this is the one pass that reaches them. The
 *    HTTP side still invokes under the still-standing client (the
 *    management zcaps are granted to the account DID, which only an enrolled
 *    client can invoke) -- which is why the stage must run before the
 *    removal entry. The pass walks every entry and reports each one's fate,
 *    but the ceremony does not carry an unsettled entry past this point: a
 *    `failed` or `pending-entry` outcome refuses the removal entry
 *    ({@link RecordRemintFailedError}, naming the records the pass left
 *    unreached), since after the removal nothing could ever re-sign that
 *    record's bridge. The client stays
 *    enrolled, and a re-run reaches the entry again.
 * 6. **The record re-bind seam** (`onBeforeRemoval`, required): the caller
 *    re-signs the LOGIN credential's bridge and `delegatedClients` sibling
 *    with the ladder VM and re-seals its unlock record with the credential
 *    in hand (a full re-wrap, proof verified rather than settled). Stage 5
 *    deliberately skips that credential (its record is re-sealed with the
 *    credential in hand rather than through a management zcap), so the
 *    seam is the only thing that ever re-signs the login credential's own
 *    bridge with the ladder VM. Without it the removal entry would leave
 *    every bridge signed by the struck key on an account with no enrolled
 *    client -- an account nothing can write to -- which is why a call that
 *    omits the seam is refused before any read.
 * 7. **The removal entry** ({@link forgetLastWebvhClient}): the client's
 *    whole document inventory out while the reinstalled ladder VM keeps the
 *    account anchored. The app's local wipe runs after this ceremony
 *    returns.
 *
 * Torn-state map: every stage detects completion from durable state, so a
 * run torn anywhere before the removal entry reads as "not forgotten" and a
 * re-run converges. A tear BETWEEN the pair's two entries is the one worth
 * stating in full: it leaves the account with no ladder VM while the client
 * still stands, and the re-run's reinstall converges because it rides the
 * client's root authority rather than the credential's bridge -- the bridge
 * the strike may itself have rotted cannot authorize that write, and nothing
 * else on a one-client account could. Both entries of the pair are
 * idempotent and the pair is
 * skipped once the rotation has landed, an already-rotated
 * roster skips the append (no second ladder-signed append is ever
 * attempted), the fan-out is staleness-driven, a re-POSTed revocation's 400
 * already-revoked answer reads as success (decision 0006's resume contract),
 * the generation stage re-asks the same staleness policy (a prior run's own
 * fresh delegation reads as retiring, so a re-run churns one delegation and
 * strands nothing, while a sibling-signed one churns none), and the record
 * re-mint re-checks staleness per entry (a record
 * already ladder-signed reads as current, one whose re-mint failed is still
 * rotted and is re-minted). Torn after the removal entry is the
 * finish-the-wipe state the app's next login maps.
 *
 * The honest limitation is the cascade's, as everywhere: ciphertext this
 * browser already fetched stays forensically recoverable from its storage,
 * and old epochs stay open to keys it already held.
 */
import type { DIDDoc, DIDLog } from '@interop/did-method-webvh'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import type { CollectionEncryption, IDelegatedZcap } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import {
  readPublishedLog,
  readPublishedLogOrThrow,
  withLogConflictRetry
} from '../webvh/didWebvh.js'
import type { PublishedWebvhLog } from '../webvh/didWebvh.js'
import { accountLogPinId } from '../webvh/verifyLog.js'
import {
  clientRemovalTarget,
  type RevokedClientKeys
} from '../webvh/revokeClient.js'
import { delegationProofKeyId } from '../webvh/standingZcap.js'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import { vmFragmentOf } from '@interop/vh-resource-log'
import {
  cascadeCollectionsToUserKey,
  readUserKeyRoster,
  rosterRecipientKid,
  rotateUserKeyRoster,
  type CascadeCollections,
  type UserKey,
  type UserKeyCascadeResult
} from '../keys/index.js'
import type { UnlockLogStore } from '../unlock/standingWebvh.js'
import type { AccountPointer } from '../keyring/record.js'
import { recordSignerFromAgent } from '../keyring/record.js'
import {
  remintRecoveryDelegations,
  type RecordRemintOutcome,
  type RecoveryDelegationEntry
} from '../recovery/recoveryDelegation.js'
import { ladderVmKeyMultibase } from './ladder.js'
import { ladderVmIds, relationIds } from '../resourceLog/document.js'
import type { PublishedKeyDocument } from '../webvh/listClients.js'
import { ladderVmAgent, ladderVmZcapClient } from './zcap.js'
import {
  clientForgetEntryOnce,
  installLadderVmWebvh,
  strikeLadderVmWebvh
} from './ladderAnchored.js'
import {
  clientAnnexDidParts,
  clientAnnexLogPinId,
  delegatedClientsDelegationMinter,
  delegatedClientsPointer,
  ensureGenerationDelegationCurrent,
  generationDelegationHistory,
  mintGenerationDelegation,
  revokeTreatingAlreadyRevokedAsSuccess,
  type ClientAnnexWriteStore
} from './log.js'

/**
 * What the ceremony's generation stage did: the revoked delegation ids, and
 * whether it wrote a replacement -- `false` with no `skipped` reason means
 * nothing was owed, the standing delegation being one a surviving sibling
 * credential's ladder signed. A `skipped` reason names the stage
 * that could not run -- `no-pointer` (the account points at no generation:
 * nothing to revoke or replace), `log-unreadable` (the pointed generation's
 * `did.jsonl` is gone; the delegation bytes are unrecoverable, decision
 * 0006's honest limit), `rung-uncommitted` (this credential cannot write the
 * generation's log; the account lands delegation-less until a
 * fresh-generation heal), `already-removed` (the whole ceremony completed on
 * an earlier run; nothing here can still invoke) -- and a skip never fails
 * the ceremony.
 */
export interface GenerationDelegationRetirement {
  revoked: string[]
  replaced: boolean
  skipped?:
    'no-pointer' | 'log-unreadable' | 'rung-uncommitted' | 'already-removed'
}

/**
 * The other unlock methods' reach for the record re-mint stage: the registry
 * entries to walk (the OTHER methods' -- the login credential's own record is
 * the `onBeforeRemoval` seam's, re-wrapped with the credential in hand; an
 * entry for it here is harmless but redundant), the unlock Spaces' storage
 * server, the management-zcap client factory (invoking as the still-standing
 * client), and the registry record-back seam. The shape is the revocation
 * cascade's re-mint seams verbatim, so an app binds both from one place.
 */
export interface UnlockMethodsRemintReach<
  Entry extends RecoveryDelegationEntry = RecoveryDelegationEntry
> {
  entries: Entry[]
  pointer: AccountPointer
  storageServerUrl: string
  managementZcapClient: (options: { capability: IZcap }) => ZcapClient
  recordEntry: (options: { entry: Entry }) => Promise<void>
}

/**
 * What a completed last-client forget reports: whether the reinstall half of
 * the strike-and-reinstall pair ran on this call (`false` on a resumed run
 * that owed no rotation, so neither entry was published), whether the
 * roster's wrap for the
 * forgotten client was retired on this run, the per-collection fan-out
 * result, the generation stage's report, the other unlock methods' record
 * re-mint report (present when the caller supplied the reach: the counts and
 * every entry's fate; a completed ceremony never carries a `failed` outcome,
 * since that refuses the removal entry instead), the document as the removal
 * entry left it, and -- when the account has a roster -- the rotated key with
 * the roster descriptor it was read from.
 */
export interface LastEnrolledClientForgetResult {
  reinstalled: boolean
  rotated: boolean
  collections: UserKeyCascadeResult
  generation: GenerationDelegationRetirement
  unlockMethods?: {
    reminted: number
    skipped: number
    outcomes: RecordRemintOutcome[]
  }
  did: string
  document: object
  userKey?: UserKey
  rosterDescriptor?: CollectionEncryption
}

/**
 * The re-mint outcomes that withhold the removal entry: a record the pass
 * could not reach, and a pending-shaped entry it deliberately did not write
 * (re-minting one would seal a half-retired credential a fresh bridge into
 * the standing credential's record). Both leave a bridge the removal entry
 * would rot for good on an account that will never see a remembered login
 * again.
 */
const REMINT_BLOCKING_OUTCOMES: RecordRemintOutcome['outcome'][] = [
  'failed',
  'pending-entry'
]

/**
 * The record re-mint stage could not settle every other unlock method's
 * record, so the removal entry was refused: `failed` names the entries the
 * pass left unreached -- those whose re-mint threw (each carrying its cause)
 * and those it skipped as pending-shaped (the entry's identity members name
 * a credential other than the one its record is sealed to) -- and
 * `unlockMethods` is the whole stage report. A pending-shaped entry blocks
 * for the same reason a failed one does: its bridge is left signed by the
 * key the removal entry strikes, and on a client-less account no login will
 * ever heal it. The mender is a remembered login, which is exactly what the
 * removal would end. The forgotten client is still enrolled and every stage
 * before this one has landed, so a re-run resumes at the re-mint. Matched
 * on `name` (the errors cross app-injected seams that may resolve to another
 * copy of this package).
 */
export class RecordRemintFailedError extends Error {
  readonly failed: RecordRemintOutcome[]
  readonly unlockMethods: NonNullable<
    LastEnrolledClientForgetResult['unlockMethods']
  >

  constructor({
    unlockMethods
  }: {
    unlockMethods: NonNullable<LastEnrolledClientForgetResult['unlockMethods']>
  }) {
    const failed = unlockMethods.outcomes.filter(outcome =>
      REMINT_BLOCKING_OUTCOMES.includes(outcome.outcome)
    )
    super(
      'did:webvh: the last-client forget could not settle the record of ' +
        `${failed.length} other unlock method(s) (` +
        failed.map(outcome => `"${outcome.label}"`).join(', ') +
        '); the removal entry was not published. The client stays enrolled; ' +
        'run the forget again.'
    )
    this.name = 'RecordRemintFailedError'
    this.failed = failed
    this.unlockMethods = unlockMethods
  }
}

/**
 * Forgets the account's LAST enrolled client -- this browser's own
 * -- transitioning the account to the client-less, ladder-anchored state.
 * See the module doc for the stage order and the torn-state map. The caller
 * runs the local wipe only after this resolves. An account with another
 * enrolled client refuses: that forget is the ordinary ceremony
 * (`forgetEnrolledClient`), reached first, whose
 * `LastEnrolledClientForgetError` is what routes callers here.
 *
 * @param options {object}
 * @param options.logStore {UnlockLogStore}   the credential's delegated
 *   `did.jsonl` bridge store; also serves the ceremony's public reads
 * @param options.clientLogStore {UnlockLogStore}   the account-log store
 *   invoked under the STILL-STANDING enrolled client's root authority (an
 *   app's `wasWebvhIdStore` satisfies the narrower shape). The
 *   strike-and-reinstall pair publishes through it, because the bridge
 *   `logStore` is often signed by the ladder VM the strike removes and the
 *   reinstall would then be refused under the current-key-set rule. Both
 *   entries stay ladder-signed; only the HTTP invocation differs. Required:
 *   a call without it throws a `TypeError` before any read
 * @param [options.pinStore] {ResourceLogPinStore}   this client's chain-head
 *   pins, the account log's slot derived from `annex.accountSpaceId`. Every
 *   account-log read the ceremony makes -- the opening read, and the strike,
 *   reinstall, and removal entries' own reads inside their conflict-retry
 *   loops -- is checked against the pinned head, so a served truncated
 *   prefix is refused (`ResourceLogContinuityError`, `rollback`) before any
 *   roster append or log publish, and each entry advances the pin to the
 *   head it publishes. Without it the ceremony checks `expectedDid` only
 * @param options.ladderSeed {Uint8Array}   the login credential's ladder seed
 * @param options.forgottenClient {RevokedClientKeys}   this client's public
 *   halves; an `updateKeyMultibase` the log does not authorize (stale, or the
 *   staged key) is re-derived from the log
 * @param options.forgottenKeyAgreementKeyMultibase {string}   this client's
 *   identity key-agreement key (the X25519 twin), naming its roster wrap
 * @param [options.knownLatentHashes] {string[]}   standing latent commitments
 *   the caller vouches for (the recovery registry's update-key hashes),
 *   excluded from the staged-hash attribution
 * @param options.expectedDid {string}   the account DID from the caller's
 *   stored account pointer
 * @param options.rosterStoreFor {Function}   `({ did, log }) => store` --
 *   builds the `key-map/user-key.jsonl` roster store whose appends are
 *   SIGNED BY THE LADDER VM and whose controller view resolves from the
 *   supplied log -- the pre-transition head for the opening read, the
 *   post-reinstall head for the rotation (the inventory-changing anchor the
 *   ceremony-tail license admits), while its HTTP requests invoke under the still-standing
 *   client
 * @param options.credentialKeyAgreementKey {IKeyAgreementKey}   the standing
 *   credential's key-agreement key -- the recipient whose wrap survives the
 *   rotation, reading the fresh key back and unwrapping the generations for
 *   the fan-out
 * @param [options.userKey] {UserKey}   this client's cached user key
 * @param [options.pinnedEpochId] {string}   the locally pinned latest-seen
 *   roster epoch
 * @param [options.onUserKeyAdopted] {Function}   persists a rotated key:
 *   called with `{ userKey, latestEpochId, descriptor }` after the roster
 *   read and BEFORE the fan-out
 * @param options.collections {CascadeCollections}   the fan-out's work
 * @param options.annex {object}   the generation stage's reach:
 * @param options.annex.storeFor {Function}
 *   `({ spaceId, generationId }) => ClientAnnexWriteStore` -- the pointed
 *   generation's log store, reading and writing under the still-standing
 *   client's authority
 * @param options.annex.revoke {Function}   `(delegation) => Promise<void>`
 *   -- POSTs a revocation (was-client's `WasClient#revoke`, bound by the
 *   caller; the invocation signs as the still-standing client)
 * @param options.annex.wasServerUrl {string}   the ACCOUNT Space's storage
 *   server (the fresh generation delegation's target host)
 * @param options.annex.accountSpaceId {string}   the ACCOUNT Space's id (the
 *   fresh delegation's target subtree)
 * @param [options.annex.pinStore] {ResourceLogPinStore}   chain-head pins
 *   for the pointed generation's read
 * @param [options.unlockMethods] {UnlockMethodsRemintReach}   the other
 *   unlock methods' record re-mint reach (stage 5): the registry entries
 *   whose bridge (and sibling) the ladder VM re-signs and whose records it
 *   re-seals through their management zcaps, invoked as the still-standing
 *   client. Omitted, the stage is skipped and the result carries no
 *   `unlockMethods` report -- the residue decision 0004's amendment stated.
 *   Supplied, an entry the pass could not re-mint -- or skipped as
 *   pending-shaped -- refuses the removal entry
 *   (`RecordRemintFailedError`)
 * @param options.onBeforeRemoval {Function}
 *   `({ did, doc, log }) => Promise<void>` -- the record re-bind seam: runs
 *   after the record re-mint stage, immediately before the removal entry,
 *   with the post-reinstall published state. The caller re-signs the login
 *   credential's bridge and `delegatedClients` sibling with the ladder VM
 *   and re-seals its unlock record here -- the only stage that reaches the
 *   login credential's record, which the `unlockMethods` pass skips. Must
 *   be idempotent (a resumed run invokes it again). Required: a call
 *   without it throws a `TypeError` before any read
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {Promise<LastEnrolledClientForgetResult>}
 */
export async function forgetLastEnrolledClient({
  logStore,
  clientLogStore,
  pinStore,
  ladderSeed,
  forgottenClient,
  forgottenKeyAgreementKeyMultibase,
  knownLatentHashes,
  expectedDid,
  rosterStoreFor,
  credentialKeyAgreementKey,
  userKey,
  pinnedEpochId,
  onUserKeyAdopted,
  collections,
  annex,
  unlockMethods,
  onBeforeRemoval,
  now = Date.now()
}: {
  logStore: UnlockLogStore
  clientLogStore: UnlockLogStore
  pinStore?: ResourceLogPinStore
  ladderSeed: Uint8Array
  forgottenClient: RevokedClientKeys
  forgottenKeyAgreementKeyMultibase: string
  knownLatentHashes?: string[]
  expectedDid: string
  rosterStoreFor: (options: {
    did: string
    log: DIDLog
  }) => EncryptionDescriptorStore
  credentialKeyAgreementKey: IKeyAgreementKey
  userKey?: UserKey
  pinnedEpochId?: string | null
  onUserKeyAdopted?: (adopted: {
    userKey: UserKey
    latestEpochId: string
    descriptor: CollectionEncryption
  }) => Promise<void>
  collections: CascadeCollections
  annex: {
    storeFor: (options: {
      spaceId: string
      generationId: string
    }) => ClientAnnexWriteStore
    revoke: (delegation: IDelegatedZcap) => Promise<void>
    wasServerUrl: string
    accountSpaceId: string
    pinStore?: ResourceLogPinStore
  }
  unlockMethods?: UnlockMethodsRemintReach
  onBeforeRemoval: (published: {
    did: string
    doc: object
    log: DIDLog
  }) => Promise<void>
  now?: number
}): Promise<LastEnrolledClientForgetResult> {
  // The seam is the only stage that re-signs the login credential's bridge
  // with the ladder VM; a run without it would land the removal entry over
  // a record the struck key signed, on an account nothing could then write
  // to. Refused before any read, so nothing is published.
  if (typeof onBeforeRemoval !== 'function') {
    throw new TypeError(
      'forgetLastEnrolledClient requires onBeforeRemoval: the login ' +
        "credential's record is re-bound only through that seam"
    )
  }

  // The pair's store is the enrolled client's, not the credential's bridge:
  // a bridge the strike rots cannot authorize the reinstall that follows it.
  // Refused before any read, so nothing is published.
  if (
    clientLogStore === undefined ||
    typeof clientLogStore.putIdResource !== 'function'
  ) {
    throw new TypeError(
      'forgetLastEnrolledClient requires clientLogStore: the ladder VM ' +
        "strike and reinstall publish under the enrolled client's root " +
        'authority'
    )
  }

  // The pre-install read and the two guards: a client with no remaining
  // presence means the removal entry already landed (the finish-the-wipe
  // state the app's next login maps -- nothing here can still invoke), and
  // an account with another enrolled client belongs to the ordinary
  // forget ceremony.
  // The account log's pin slot, shared by every read and entry below.
  const pinned = pinStore
    ? { pinStore, logId: accountLogPinId({ spaceId: annex.accountSpaceId }) }
    : {}
  const before = await readPublishedLogOrThrow({
    idStore: logStore,
    expectedDid,
    ...pinned,
    missingMessage: 'did:webvh: did.jsonl is missing; nothing to enroll into.'
  })
  const preTarget = await clientRemovalTarget({
    published: before,
    client: forgottenClient
  })
  if (!preTarget.present) {
    return {
      reinstalled: false,
      rotated: false,
      collections: { outcomes: {}, failed: [] },
      generation: { revoked: [], replaced: false, skipped: 'already-removed' },
      did: before.did,
      document: before.doc
    }
  }
  const signingVmId = `${before.did}#${forgottenClient.signingKeyMultibase}`
  const invocationIds = relationIds(before.doc.capabilityInvocation)
  if (invocationIds.some(id => id !== signingVmId)) {
    throw new Error(
      'did:webvh: another enrolled client remains; the last-client ' +
        'transition ceremony does not apply -- run the ordinary forget.'
    )
  }

  // What the rotation is decided on, read BEFORE any entry: the roster as it
  // stands on the pre-transition document. The pair below runs only when the
  // rotation is still owed, so a re-run past it publishes no entry for
  // nothing.
  const forgottenKid = rosterRecipientKid({
    signingKeyMultibase: forgottenClient.signingKeyMultibase,
    keyAgreementKeyMultibase: forgottenKeyAgreementKeyMultibase
  })
  const preRosterStore = rosterStoreFor({ did: before.did, log: before.log })
  const current = await preRosterStore.read()
  const currentEpoch = current
    ? (current.descriptor.epochs ?? []).find(
        epoch => epoch.id === current.descriptor.currentEpoch
      )
    : undefined
  const wrapped =
    currentEpoch?.recipients.some(
      entry => entry.header.kid === forgottenKid
    ) === true
  const ladderVmId = `${before.did}#${await ladderVmKeyMultibase({
    ladderSeed
  })}`
  const vmStands = ladderVmIds({ doc: before.doc }).includes(ladderVmId)

  // Stage 1: the strike-and-reinstall pair -- this credential's ladder VM
  // out of the document and straight back in, the client's inventory
  // untouched throughout. The credential-keyed lifecycle installs the VM at
  // bind time, so it already stands here and a bare install would publish
  // nothing; the pair is what gives the rotation below an inventory-changing
  // document version to anchor at, which is what the ceremony-tail license
  // admits. Both entries are ladder-signed by the attributed rung, so the
  // reinstall reveals a rung that stands in `updateKeys` -- the cost the
  // single install already carried, now over two entries.
  //
  // The revocation stage's ordering is undisturbed by the pair: the
  // reinstall republishes the IDENTICAL key under the identical id and
  // revokes nothing, and a zcap delegation proof carries no version anchor,
  // so every unexpired ladder-signed delegation keeps verifying across it.
  //
  // Run only when there is something for it to license (the rotation is
  // owed) or when the VM is missing -- the state a run torn between the two
  // entries leaves, where the strike no-ops and the reinstall converges.
  //
  // Both entries are inventory-changing, so the pair mints TWO license
  // shots rather than the one the rotation spends. That is accepted:
  // clause B already licenses every standing ladder against any
  // inventory-changing version, so the reinstall's own shot is spendable by
  // a sibling ladder in the same window whatever the strike's shot does.
  // What a sibling's spend costs is bounded either way. Spent at the strike
  // version, the rotation below stays licensed at the reinstall version
  // (`headControllerVersionIndex >= controllerVersionIndex` compares
  // positions, and the reinstall's is higher). Spent at the reinstall
  // version, the rotation refuses with `ResourceLogLicenseError` and the
  // run is foreclosed rather than wedged: `wrapped` stays true, since the
  // client still stands in the document and is therefore a recipient of the
  // sibling's fresh epoch too, so a re-run republishes the pair and mints a
  // fresh anchor. The install signs with the currently attributed rung and
  // keeps its own hash committed under the carry-over convention, so no
  // rung is burned; the cost is two account-log entries per attempt.
  let reinstalled = false
  let anchor: { did: string; doc: DIDDoc; log: DIDLog } = {
    did: before.did,
    doc: before.doc,
    log: before.log
  }
  if (wrapped || !vmStands) {
    await strikeLadderVmWebvh({
      store: clientLogStore,
      ladderSeed,
      expectedDid,
      ...pinned
    })
    const install = await installLadderVmWebvh({
      store: clientLogStore,
      ladderSeed,
      expectedDid,
      ...pinned
    })
    reinstalled = install.installed
    anchor = { did: install.did, doc: install.doc, log: install.log }
  }

  // Stage 2: the roster rotation off this client's wrap, ladder-signed and
  // anchored at the reinstall entry, then stage 3, the collection fan-out --
  // both HTTP-invoked under this client's still-standing authority. An
  // already-rotated roster skips the append entirely, so the one-shot
  // license is never asked for a second append at the same anchor.
  let rotated = false
  let read: { userKey: UserKey; descriptor: CollectionEncryption } | undefined
  let cascade: UserKeyCascadeResult = { outcomes: {}, failed: [] }
  const rosterStore = wrapped
    ? rosterStoreFor({ did: anchor.did, log: anchor.log })
    : preRosterStore
  if (current !== null) {
    let descriptor = current.descriptor
    if (wrapped) {
      descriptor = await rotateUserKeyRoster({
        store: rosterStore,
        document: anchor.doc,
        retireRecipientId: forgottenKid
      })
      rotated = true
    }
    // The fresh key comes back through the credential's standing wrap -- this
    // client's own is gone from the current epoch -- with the continuity and
    // possession checks still running on the threaded descriptor.
    const adopted = await readUserKeyRoster({
      store: rosterStore,
      descriptor,
      ...(userKey ? { userKey } : {}),
      clientKeyAgreementKey: credentialKeyAgreementKey,
      pinnedEpochId
    })
    if (adopted.rotated) {
      await onUserKeyAdopted?.({
        userKey: adopted.userKey,
        latestEpochId: adopted.latestEpochId,
        descriptor: adopted.descriptor
      })
    }
    read = { userKey: adopted.userKey, descriptor: adopted.descriptor }
    cascade = await cascadeCollectionsToUserKey({
      collectionIds:
        typeof collections.collectionIds === 'function'
          ? await collections.collectionIds()
          : collections.collectionIds,
      storeFor: collections.storeFor,
      ...(collections.isEncrypted
        ? { isEncrypted: collections.isEncrypted }
        : {}),
      rosterDescriptor: adopted.descriptor,
      clientKeyAgreementKey: credentialKeyAgreementKey,
      userKey: adopted.userKey
    })
  }

  // Stage 4: the generation-delegation replacement and revocations.
  const generation = await retireLadderGenerationDelegations({
    doc: anchor.doc,
    accountDid: anchor.did,
    ladderSeed,
    retiringSigningKeyMultibase: forgottenClient.signingKeyMultibase,
    annex,
    now
  })

  // Stage 5: the other unlock methods' record re-mint, ladder-signed, with
  // the forgotten client named as retiring -- the post-reinstall document
  // still lists it, so without that axis every bridge it signed would read
  // as standing and be left to rot at the removal entry.
  let remint: LastEnrolledClientForgetResult['unlockMethods']
  if (unlockMethods !== undefined) {
    remint = await remintUnlockMethodRecordsAsLadder({
      doc: anchor.doc,
      accountDid: anchor.did,
      ladderSeed,
      retiringSigningKeyMultibase: forgottenClient.signingKeyMultibase,
      reach: unlockMethods,
      now
    })
    // The one pass that will ever reach these records on a client-less
    // account: a record it could not re-seal -- or deliberately did not
    // write, the pending-shaped entry -- would be left with a bridge the
    // removal entry rots for good, so the removal is refused instead. The
    // stages already landed are idempotent and the client still stands, so
    // the re-run resumes here.
    if (
      remint.outcomes.some(outcome =>
        REMINT_BLOCKING_OUTCOMES.includes(outcome.outcome)
      )
    ) {
      throw new RecordRemintFailedError({ unlockMethods: remint })
    }
  }

  // Stage 6: the record re-bind seam -- the login credential's record, the
  // one stage 5 skipped -- while the removal has not landed (a
  // ladder-VM-signed bridge verifies from the reinstall entry on, and the old
  // client-signed one keeps verifying until the removal -- so a tear on
  // either side of this callback leaves a working login).
  await onBeforeRemoval({
    did: anchor.did,
    doc: anchor.doc,
    log: anchor.log
  })

  // Stage 7: the removal entry -- the client's whole inventory out, the
  // installed ladder VM keeping the account anchored.
  const removed = await forgetLastWebvhClient({
    store: logStore,
    ladderSeed,
    forgottenClient,
    ...(knownLatentHashes ? { knownLatentHashes } : {}),
    expectedDid,
    ...pinned
  })

  return {
    reinstalled,
    rotated,
    collections: cascade,
    generation,
    ...(remint ? { unlockMethods: remint } : {}),
    did: removed.did,
    document: removed.doc,
    ...(read
      ? { userKey: read.userKey, rosterDescriptor: read.descriptor }
      : {})
  }
}

/**
 * The generation stage: reads the pointed generation's log, replaces the
 * embedded delegation with a fresh ladder-signed one (so the account stays
 * transient-login-reachable), then revokes every still-unexpired delegation
 * the log's history embedded that this credential's ladder VM signed.
 * Replace-before-revoke is the tear-safety order: the fresh delegation is
 * never in the pre-replacement history, so the revocation loop cannot touch
 * it, and a run torn between the two leaves the generation with a live
 * delegation either way.
 *
 * The replacement is decided by the house staleness policy read against a
 * PROJECTED post-edit document, not by an unconditional force: this
 * credential's ladder VM is named as retiring (the revocations below end its
 * delegations, a state no client-side predicate can read) and so is the
 * forgotten client (the removal entry in stage 7 has yet to strike it). A
 * delegation signed by neither -- a sibling credential's ladder VM, which
 * survives the transition -- stands, and keeping it is the right answer: the
 * revocation loop below never reaches it.
 *
 * @param options {object}
 * @param options.doc {DIDDoc}   the post-reinstall account document
 * @param options.accountDid {string}
 * @param options.ladderSeed {Uint8Array}
 * @param options.retiringSigningKeyMultibase {string}   the forgotten
 *   client's signing key
 * @param options.annex {object}   see {@link forgetLastEnrolledClient}
 * @param options.now {number}
 * @returns {Promise<GenerationDelegationRetirement>}
 */
async function retireLadderGenerationDelegations({
  doc,
  accountDid,
  ladderSeed,
  retiringSigningKeyMultibase,
  annex,
  now
}: {
  doc: DIDDoc
  accountDid: string
  ladderSeed: Uint8Array
  retiringSigningKeyMultibase: string
  annex: {
    storeFor: (options: {
      spaceId: string
      generationId: string
    }) => ClientAnnexWriteStore
    revoke: (delegation: IDelegatedZcap) => Promise<void>
    wasServerUrl: string
    accountSpaceId: string
    pinStore?: ResourceLogPinStore
  }
  now: number
}): Promise<GenerationDelegationRetirement> {
  const pointedDid = delegatedClientsPointer({ doc })
  if (pointedDid === undefined) {
    return { revoked: [], replaced: false, skipped: 'no-pointer' }
  }
  const parts = clientAnnexDidParts({ did: pointedDid })
  const store = annex.storeFor(parts)
  const logId = clientAnnexLogPinId(parts)
  const published = await readPublishedLog({
    idStore: store,
    expectedDid: pointedDid,
    ...(annex.pinStore !== undefined ? { pinStore: annex.pinStore, logId } : {})
  })
  if (published === undefined) {
    return { revoked: [], replaced: false, skipped: 'log-unreadable' }
  }

  // The doomed set, collected BEFORE the replacement so the fresh delegation
  // can never join it: every delegation the history embedded whose proof key
  // is this credential's ladder VM and whose expiry has not passed. An
  // unparseable or absent expiry counts as unexpired -- fail-safe, since an
  // unbounded delegation is the worst resurrection credential.
  const ladderVmKey = await ladderVmKeyMultibase({ ladderSeed })
  const doomed = generationDelegationHistory({ log: published.log }).filter(
    delegation => {
      const proofKeyId = delegationProofKeyId(delegation)
      const fragment =
        proofKeyId === undefined ? null : vmFragmentOf(proofKeyId)
      if (fragment !== ladderVmKey) {
        return false
      }
      const expires = Date.parse(
        (delegation as { expires?: string }).expires ?? ''
      )
      return Number.isNaN(expires) || expires > now
    }
  )

  // The replacement first: a ladder-signed fresh delegation under the
  // reinstalled VM, the annex entry signed by this credential's committed
  // annex rung. A credential the generation does not commit cannot write the
  // entry -- the honest skip, leaving the generation delegation-less once
  // the doomed set is revoked below.
  let replaced = false
  let rungUncommitted = false
  const ladderClient = await ladderVmZcapClient({ accountDid, ladderSeed })
  try {
    const ensured = await ensureGenerationDelegationCurrent({
      store,
      ladderSeed,
      generationId: parts.generationId,
      mintGenerationDelegation: async ({ clientAnnexDid }) =>
        mintGenerationDelegation({
          zcapClient: ladderClient,
          wasServerUrl: annex.wasServerUrl,
          spaceId: annex.accountSpaceId,
          clientAnnexDid,
          now
        }),
      expectedDid: pointedDid,
      accountDoc: doc as PublishedKeyDocument,
      retiringKeyMultibases: [ladderVmKey, retiringSigningKeyMultibase],
      ...(annex.pinStore !== undefined
        ? { pinStore: annex.pinStore, logId }
        : {}),
      now
    })
    // `replaced` reports what the stage actually wrote. A delegation the
    // policy leaves standing -- a surviving sibling ladder's, which the
    // revocations below never reach -- ends the stage current rather than
    // replaced, with no `skipped` reason: nothing was owed.
    replaced = ensured.renewed
  } catch (err) {
    if ((err as { name?: string }).name !== 'ClientAnnexRungUncommittedError') {
      throw err
    }
    rungUncommitted = true
  }

  // The revocations, blind and resumable (400 already-revoked as success).
  const revoked: string[] = []
  for (const delegation of doomed) {
    await revokeTreatingAlreadyRevokedAsSuccess({
      revoke: annex.revoke,
      delegation
    })
    const id = (delegation as { id?: string }).id
    if (typeof id === 'string') {
      revoked.push(id)
    }
  }

  return rungUncommitted
    ? { revoked, replaced, skipped: 'rung-uncommitted' }
    : { revoked, replaced }
}

/**
 * The record re-mint stage: the revocation cascade's re-mint pass over the
 * other unlock methods' registry entries, with the ladder VM as both the
 * delegating key (the fresh bridge and sibling) and the record-frame signer
 * (`ladderVmAgent`'s did:key form, whose multibase the post-reinstall document
 * lists, so a reader settling the mixed-signer proof against the account
 * document accepts it after the removal too -- `currentAccountRecordSigners`
 * is that allowlist), and the forgotten client named as retiring. The sibling
 * minter reads the annex pointer off the post-reinstall document. The HTTP
 * side rides the caller's management-zcap clients, still invocable here.
 *
 * @param options {object}
 * @param options.doc {DIDDoc}   the post-reinstall account document
 * @param options.accountDid {string}
 * @param options.ladderSeed {Uint8Array}
 * @param options.retiringSigningKeyMultibase {string}   the forgotten
 *   client's signing key
 * @param options.reach {UnlockMethodsRemintReach}
 * @param options.now {number}
 * @returns {Promise<object>}   the pass's counts and per-entry outcomes
 */
async function remintUnlockMethodRecordsAsLadder({
  doc,
  accountDid,
  ladderSeed,
  retiringSigningKeyMultibase,
  reach,
  now
}: {
  doc: DIDDoc
  accountDid: string
  ladderSeed: Uint8Array
  retiringSigningKeyMultibase: string
  reach: UnlockMethodsRemintReach
  now: number
}): Promise<NonNullable<LastEnrolledClientForgetResult['unlockMethods']>> {
  const ladderClient = await ladderVmZcapClient({ accountDid, ladderSeed })
  const recordSigner = recordSignerFromAgent({
    keyAgent: await ladderVmAgent({ ladderSeed })
  })
  return remintRecoveryDelegations({
    doc,
    entries: reach.entries,
    pointer: reach.pointer,
    storageServerUrl: reach.storageServerUrl,
    zcapClient: ladderClient,
    recordSigner,
    managementZcapClient: reach.managementZcapClient,
    recordEntry: reach.recordEntry,
    mintDelegatedClientsDelegation: delegatedClientsDelegationMinter({
      doc,
      zcapClient: ladderClient,
      wasServerUrl: reach.pointer.host
    }),
    retiringKeyMultibases: [retiringSigningKeyMultibase],
    now
  })
}

/**
 * THE LAST-CLIENT REMOVAL ENTRY (stage 7, the transition's own removal): the
 * plain forget's removal shape (`clientForgetEntryOnce`) with this ceremony's
 * removability invariant injected instead of the plain forget's last-client
 * refusal -- the forgotten client IS the last enrolled client, and the
 * account stays invocable because the ladder VM the reinstall entry published
 * remains in the document. Run only from {@link forgetLastEnrolledClient},
 * which sequences the strike-and-reinstall pair, the rotation, and the
 * revocations before it.
 *
 * @param options {object}   see `forgetWebvhClient` in `ladderAnchored.ts`
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}
 */
export async function forgetLastWebvhClient(options: {
  store: UnlockLogStore
  ladderSeed: Uint8Array
  forgottenClient: RevokedClientKeys
  knownLatentHashes?: string[]
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  return withLogConflictRetry(() =>
    clientForgetEntryOnce({
      ...options,
      assertRemovable: async ({ published }) =>
        assertLadderAnchorStands({
          published,
          ladderSeed: options.ladderSeed
        })
    })
  )
}

/**
 * The transition's no-neither invariant, checked rather than assumed: the
 * removal may only publish while this credential's ladder VM stands in the
 * document (the reinstall entry ran), or the account would land with neither
 * an enrolled client nor the ladder anchor -- nothing that can invoke for it,
 * and no mender, since no login sweep will ever run on a client-less account.
 *
 * @param options {object}
 * @param options.published {PublishedWebvhLog}   the read the removal entry
 *   is being built on
 * @param options.ladderSeed {Uint8Array}
 * @returns {Promise<void>}
 */
async function assertLadderAnchorStands({
  published,
  ladderSeed
}: {
  published: PublishedWebvhLog
  ladderSeed: Uint8Array
}): Promise<void> {
  const ladderVmId = `${published.did}#${await ladderVmKeyMultibase({
    ladderSeed
  })}`
  if (!ladderVmIds({ doc: published.doc }).includes(ladderVmId)) {
    throw new Error(
      'did:webvh: the ladder VM is not installed in the document; the ' +
        'last-client removal entry would strand the account (the install ' +
        'entry runs first).'
    )
  }
}
