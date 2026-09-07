/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The credential-anchored establishment: everything between a derived unlock
 * credential and an account a transient login can enter, with no enrolled
 * client minted anywhere. One orchestrator serves the fresh signup and the
 * login-time re-run alike -- every stage is an ensure, so a run torn at any
 * point converges by running the whole thing again (the account log is
 * adopted by ladder attribution, never re-created: `createDID` timestamps
 * the genesis entry, so a naive re-create would mint a different SCID).
 *
 * The stage order, with the load-bearing ordering rules folded in:
 *
 * 1. The interim bridge and the FIRST bind, through the required
 *    `bindRecord` hook: the standing-layout unlock record -- ladder seed
 *    sealed in, pointer still DID-less, the bridge delegated by the ladder
 *    VM's bare did:key (functional until promotion; superseded by the
 *    re-bind) -- is durably written BEFORE the Space is created and before
 *    the genesis entry publishes rung 0 (the transposed
 *    persist-before-publish rule: a published rung nobody can re-derive is
 *    the orphan brick). CONDITIONAL: skipped when the caller passed
 *    `priorCreatedAt` from a standing keyring hit -- the record already
 *    carries the ladder seed, and re-writing it DID-less would let a
 *    concurrent heal downgrade a sibling browser's completed re-bind
 *    moments before dying on the promoted Space, a permanent lockout.
 * 2. `ensureCredentialAnchoredAccountGenesis` under the ladder VM's bare
 *    did:key as bootstrap controller, promotion deferred
 *    (`promoteController: false`): Space + collections, the optional KMS
 *    authentication binding (`provideKmsAuthentication`, an opaque
 *    best-effort thunk the caller owns, started alongside the Space),
 *    the one-entry ladder-anchored did:webvh genesis with the credential's
 *    `keyAgreement` publication folded in, the roster's epoch[0] wrapped to
 *    the credential's standing key-agreement key with a ladder-signed entry
 *    proof, and the collection epochs. The ceremony installs collection
 *    epochs only when the roster's current epoch IS the candidate key it was
 *    handed (`epochsSkipped` otherwise); its roster and epoch failures are
 *    FATAL here, before anything names the DID, so the tear is the heal-able
 *    kind (a DID-less record) rather than a registry sealed under a key only
 *    this tab ever held.
 *    2c. The adopted-roster arm: a re-run that adopted an earlier run's
 *    roster recovers the real user key from the credential's standing wrap
 *    and completes the collection epochs under it -- the one installer,
 *    through the shared mint-policy stage (`ensureRosterDeliveredEpochs`):
 *    epochs install under the key the roster DELIVERS, never the minted
 *    candidate.
 * 3. The annex generation block (`ensurePointedClientAnnexGeneration`),
 *    gated on no `#DelegatedClients` pointer: the annex Space resolved in
 *    the settled order (document pointer, else the record's sibling's
 *    target, else mint fresh), the generation minted under the bootstrap
 *    identity, the ladder-VM-signed generation delegation embedded while
 *    the auxiliary Space still answers to the bootstrap did:key, the
 *    Space's controller flipped to the account DID, and the pointer entry
 *    appended -- moved as the ladder (`movePointerAsLadder`): each attempt
 *    attributes the ladder's current rung, reveals it when only its hash
 *    stands committed, and signs with it, under the caller's chain-head
 *    pin, so a sibling self-enrollment that spends the rung mid-run is
 *    climbed past rather than refused. Within THIS ceremony the
 *    sibling arm never fires: the sibling is only written by stage 4,
 *    strictly after the pointer entry, so a stage-3 tear leaves no
 *    sibling; the arm serves callers holding a standing invocation
 *    authority (the add/change-method fold), and the establishment's own
 *    bootstrap authority falls back to a fresh mint when a sibling-named
 *    Space refuses it.
 *    The primitive's pre-mint rung attribution runs before anything is
 *    minted and strictly before the re-bind: an account whose document no
 *    longer anchors this ladder refuses while the record is still in its
 *    pre-re-bind shape.
 * 4. The re-bind, through the same `bindRecord` hook: the full pointer (DID
 *    in), the ladder-VM-signed bridge and annex-Space sibling, and the
 *    management delegation to the account DID -- durably written BEFORE
 *    promotion, so the next login signs under the promoted controller only
 *    once the record says to.
 * 5. The caller's `beforePromotion` hook (freewallet: the unlock-methods
 *    registry write), run under the bootstrap did:key -- the last window
 *    where a root invocation works. NOT swallowed here: a throw fails the
 *    establishment; a hook that must be best-effort swallows its own
 *    failures.
 * 6. The Space-controller promotion onto the account DID, last -- and, when
 *    the caller's KMS stage bound a keystore this run, the best-effort
 *    keystore-controller promotion beside it (`promoteKeystore`).
 *
 * The caller (the signup, or a login-time heal) then enters the account
 * through its ordinary transient composition. Known residue: a tear inside
 * stage 3 before the pointer entry can orphan a live annex Space nothing
 * enumerates (the annex Space id is a random mint nothing re-derives), and
 * within this ceremony each torn attempt orphans one -- no record names the
 * Space until stage 4's sibling, so an establishment re-run cannot converge
 * onto it and mints another. And a tear between the re-bind and the promotion
 * on a KMS deployment strands the keystore's controller on the ladder's
 * bare did:key -- outside the current-key-set rule -- with no mender here;
 * an open gap owned by the did:web-stage collapse.
 */
import type { DIDLog } from '@interop/did-method-webvh'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'
import type { WasClient } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import type { ZcapClient } from '@interop/ezcap'
import {
  ensurePromotedSpaceController,
  mintSpaceId,
  type AccountGenesisResult
} from '../genesis/accountGenesis.js'
import {
  currentLogParameters,
  keyAgreementCommitment,
  readPublishedLog
} from '../webvh/didWebvh.js'
import type {
  ClientWebvhUpdateKeys,
  KmsAuthenticationBinding,
  PublishedWebvhLog,
  WebvhIdStore
} from '../webvh/didWebvh.js'
import { didKeyZcapClient } from '../webvh/zcap.js'
import type { ICapabilityAgent } from '../webvh/zcap.js'
import type { UnlockKeyAgreementPublication } from '../unlock/standingWebvh.js'
import type { AccountPointer } from '../keyring/record.js'
import {
  delegateLogWrite,
  recordedDelegationFields
} from '../recovery/recoveryDelegation.js'
import { mintUserKey, type UserKey } from '../keys/index.js'
import { attributeLadderRung, type LadderRung } from './ladder.js'
import { ladderVmAgent, ladderVmSigners } from './zcap.js'
import type { PointerEntryOutcome } from './log.js'
import {
  clientAnnexDidParts,
  mintDelegatedClientsDelegation,
  mintPointedClientAnnexGeneration,
  setDelegatedClientsPointer
} from './log.js'
import {
  ladderSignedGenerationDelegationMinter,
  movePointerAsLadder,
  rawRequestStatus,
  resolveClientAnnexSpaceId
} from './heal.js'
import { ensureCredentialAnchoredAccountGenesis } from './credentialAnchoredGenesis.js'
import {
  CONTROLLER_PROMOTION_STAGE,
  type CredentialAnchoredEstablishmentStageName
} from './stages.js'
import { ensureRosterDeliveredEpochs } from './rosterDeliveredEpochs.js'
import { stageNotifier, type StageNotifier } from '../log.js'

/**
 * The standing members an unlock-methods registry entry records for the
 * established credential: its roster kid and key-agreement multibase, the
 * ladder's standing rung, the standing client's did:key, the bridge and
 * sibling delegations' signer key ids and expiries, and the unlock
 * key-agreement members the re-bind reported. The member names are the ones
 * the registry already records; nothing here mints a new field.
 */
export interface CredentialAnchoredStandingFields {
  rosterKid: string
  keyAgreementKeyMultibase: string
  updateKeyMultibase: string
  unlockClientDid: string
  delegationKeyId?: string
  delegationExpires?: string
  delegatedClientsKeyId?: string
  delegatedClientsExpires?: string
  unlockKeyAgreementKeyId?: string
  unlockKeyAgreementKeyMultibase?: string
}

/**
 * What the establishment hands back for the callers' tails: the published
 * DID, the record's unlock Space id and management zcap, the standing fields
 * a registry entry records, and the report members -- the genesis's
 * `epochsSkipped` marker and the best-effort stages' collected failures
 * (`kmsAuthentication`, `keystorePromotion`).
 */
export interface CredentialAnchoredEstablishment {
  did: string
  /**
   * The account log's verified head this run ends standing on -- the pointer
   * entry's own post-publish head when stage 3 wrote one, otherwise the head
   * stage 3 stood on. The caller enters the account straight after this
   * returns, so it seeds its session's verified-log memo from here rather
   * than fetching `did.jsonl` again (`verifiedAccountLogOf`); reuse is within
   * this one run alone.
   */
  accountLog: PublishedWebvhLog
  unlockSpaceId: string
  manageCapability?: IZcap
  standingFields: CredentialAnchoredStandingFields
  epochsSkipped?: AccountGenesisResult['epochsSkipped']
  failed: Array<{
    stage: 'kmsAuthentication' | 'keystorePromotion'
    error: unknown
  }>
}

/**
 * What the `bindRecord` hook must return: the bind's freshness stamp (the
 * re-bind's `priorCreatedAt` thread), and -- the standing-layout assertion's
 * observable half -- the record's unlock Space id, with the management zcap
 * and unlock key-agreement members when the bind minted them.
 */
export interface CredentialAnchoredBindResult {
  createdAt: string
  unlockSpaceId: string
  manageCapability?: IZcap
  unlockKeyAgreementKeyId?: string
  unlockKeyAgreementKeyMultibase?: string
}

/**
 * The unlock-record codec closure the caller supplies (freewallet:
 * `bindCredentialAnchoredUnlockSecret`), called at most twice -- the first
 * bind and the re-bind -- with the ceremony supplying the pointer shape, the
 * delegations, and `priorCreatedAt`. Its obligations, uncheckable here once
 * the codec is caller-supplied: the record it writes MUST carry the standing
 * layout (ladder seed, bridge, binding MAC -- no plain bind), and the
 * caller's local keyring-freshness pin floor is consumed INSIDE this closure
 * (advance-past stamping), so a remembered caller must wire it there.
 */
export type CredentialAnchoredBindRecordHook = (options: {
  controller: string
  pointer: AccountPointer
  delegation: IZcap
  delegatedClients?: IZcap
  delegateManagementTo?: string
  priorCreatedAt?: string
}) => Promise<CredentialAnchoredBindResult>

/**
 * The stage-3 primitive: ensure the account document points at a client-annex
 * generation, minting and pointing one when it does not. Gated on the
 * pointer: a document already carrying `#DelegatedClients` is returned
 * as-is (`generationMinted: false`). Otherwise the annex Space resolves in
 * the settled order ({@link resolveClientAnnexSpaceId}: the sibling
 * delegation's target, else a fresh Space minted here), and the fold runs in
 * the standing sub-step order: mint the generation, embed the generation
 * delegation while the Space still answers to its creation controller, flip
 * the Space's controller to the account DID, then append the pointer entry
 * -- strictly last in the block, so pointer-present implies every prior
 * sub-step landed. The pointer entry signs on the arm the caller states: an
 * enrolled client's own update keys, or the ladder (attributed, revealed,
 * and signed per attempt); every log touch rides the caller's chain-head pin
 * store. On the ladder arm the rung is attributed BEFORE anything is minted,
 * the pre-flight every pointer-moving arm runs: a ladder the log carries no
 * rung of, and an ambiguous attribution, throw the ladder's own
 * `LadderAttributionError` with no Space or generation minted, so a torn
 * establishment never orphans an annex Space on an account that no longer
 * anchors this ladder.
 *
 * Two invocation authorities, heal's pattern. A caller holding a standing
 * invocation authority (`invocation`: an enrolled client's storage handle
 * plus the sibling capability its annex writes ride) converges onto the
 * sibling-named Space as-is -- the Space is already account-controlled, so
 * no flip runs. The bootstrap-only caller (the establishment) can write a
 * sibling-named Space only while it still answers to the bootstrap did:key
 * (a tear before the flip); one an earlier run already flipped refuses its
 * writes, and that authorization refusal falls back to the fresh-mint arm
 * rather than failing the run. The bootstrap arm's own controller flip
 * swallows ONLY an authorization-class refusal (a concurrent run flipped
 * first); a transport failure there aborts BEFORE the pointer entry, since
 * a document pointing at a generation whose Space still answers to the bare
 * ladder did:key would be unreachable forever.
 *
 * The fold shape is fixed (a separate pointer entry); a ceremony whose
 * pointer move must ride another log entry atomically (the transient
 * recovery's add-and-retire) keeps its own inline fold rather than
 * parameterizing this one.
 *
 * @param options {object}
 * @param options.account {object}   the VERIFIED account log view
 *   (`{ did, doc, log }`; never re-fetched here)
 * @param options.wasServerUrl {string}   the account pointer's host
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed
 * @param options.was {WasClient}   the bootstrap storage client (the ladder
 *   VM's bare did:key), used by the fresh-mint arm
 * @param options.mintController {string}   the annex Space's creation
 *   controller (a did:key; the ladder VM's bare did:key here)
 * @param options.mintGenerationDelegation {Function}
 *   `({ clientAnnexDid }) => Promise<IZcap>` -- the generation-delegation
 *   minter (ladder-VM-signed on a ladder-anchored account)
 * @param options.idStore {WebvhIdStore}   the ACCOUNT log's store
 * @param options.signer {object}   who signs the pointer entry:
 *   `{ kind: 'client', updateKeys }`, an enrolled client's own update keys
 *   (freewallet's remembered-login fold), or `{ kind: 'ladder' }`, under
 *   which the entry is moved as the ladder with the supplied `ladderSeed`
 *   (`movePointerAsLadder`): every attempt of its conflict retry attributes
 *   the ladder's current rung from the head it reads, reveals it when only
 *   its hash stands committed, and signs with it -- so a racing ceremony that
 *   spends the rung is climbed past. A pair fixed by the caller could not be,
 *   since the client arm's not-authorized refusal is not a conflict the retry
 *   re-runs on. Stated explicitly rather than read off `updateKeys`'
 *   absence, since the ladder arm reveals a rung into the world-readable
 *   `updateKeys` and an omission must not select it silently
 * @param [options.delegatedClients] {IZcap}   the record's sibling
 *   delegation, for the Space resolution's settled order
 * @param [options.invocation] {object}   a standing invocation authority for
 *   the sibling-named Space's writes: `was` (the standing client's storage
 *   handle) and `capability` (the sibling delegation the annex writes ride).
 *   Absent, the sibling-named Space is attempted under the bootstrap client
 *   and an authorization refusal falls back to a fresh mint
 * @param [options.logOnly] {boolean}   pointer entries publish the log only
 *   (a bridge-delegated writer has no `did.json` projection rights); the
 *   establishment's root window omits it
 * @param [options.published] {PublishedWebvhLog}   the same account head as
 *   `account`, complete with the ETag its read carried, when the caller holds
 *   one. The pointer entry's first attempt then builds on it -- one saved
 *   read of the log the caller just read or published -- and a lost
 *   compare-and-swap falls through to a fresh pinned read
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {Promise<object>}   the pointed (or freshly minted) annex DID,
 *   the generation delegation when one was installed here, what ran, on
 *   `accountLog` the account head this block leaves standing (the
 *   post-pointer-entry one when it wrote, the supplied `published` verbatim
 *   when the document already pointed at a generation), and on the ladder
 *   arm `rung`: the rung the pointer entry was signed with when this call
 *   wrote one, else the ladder's currently attributed rung
 */
export async function ensurePointedClientAnnexGeneration({
  account,
  wasServerUrl,
  ladderSeed,
  was,
  mintController,
  mintGenerationDelegation,
  idStore,
  signer,
  delegatedClients,
  invocation,
  logOnly,
  published,
  now
}: {
  account: Pick<PublishedWebvhLog, 'did' | 'doc' | 'log'>
  wasServerUrl: string
  ladderSeed: Uint8Array
  was: WasClient
  mintController: string
  mintGenerationDelegation: (options: {
    clientAnnexDid: string
  }) => Promise<IZcap>
  idStore: WebvhIdStore
  signer:
    { kind: 'client'; updateKeys: ClientWebvhUpdateKeys } | { kind: 'ladder' }
  delegatedClients?: IZcap
  invocation?: { was: WasClient; capability: IZcap }
  logOnly?: boolean
  published?: PublishedWebvhLog
  now?: number
}): Promise<{
  clientAnnexDid: string
  generationDelegation?: IZcap
  generationMinted: boolean
  spaceMinted: boolean
  accountLog?: PublishedWebvhLog
  rung?: LadderRung
}> {
  // The ladder arm's pre-flight, before the pointer test and before anything
  // is minted: the ladder's current rung, attributed from the account log's
  // current parameters (rung 0, revealed, on a fresh establishment; a
  // committed-only rung after a sibling self-enrolled). An account whose
  // document no longer anchors this ladder throws here, with no Space or
  // generation minted and, in the establishment, while the record is still
  // in its pre-re-bind shape. A pre-flight only: the pointer entry
  // attributes again per attempt inside its own retry and reveals a
  // committed rung itself.
  const attributed =
    signer.kind === 'ladder'
      ? await attributeLadderRung({
          ladderSeed,
          published: currentLogParameters(account)
        })
      : undefined
  const { pointer, annexSpaceId } = resolveClientAnnexSpaceId({
    doc: account.doc,
    ...(delegatedClients !== undefined ? { delegatedClients } : {})
  })
  if (pointer !== undefined) {
    return {
      clientAnnexDid: pointer,
      generationMinted: false,
      spaceMinted: false,
      // Nothing was written, so the caller's head is still the standing one.
      ...(published !== undefined ? { accountLog: published } : {}),
      ...(attributed !== undefined ? { rung: attributed.rung } : {})
    }
  }

  const pointGeneration = async (
    clientAnnexDid: string
  ): Promise<PointerEntryOutcome> =>
    signer.kind === 'client'
      ? setDelegatedClientsPointer({
          idStore,
          signer,
          clientAnnexDid,
          expectedDid: account.did,
          ...(logOnly !== undefined ? { logOnly } : {}),
          ...(published !== undefined ? { published } : {})
        })
      : movePointerAsLadder({
          idStore,
          ladderSeed,
          clientAnnexDid,
          accountDid: account.did,
          ...(logOnly !== undefined ? { logOnly } : {}),
          ...(published !== undefined ? { published } : {})
        })
  // The one outcome shape both minting arms hand back.
  const pointedOutcome = (
    generation: Awaited<
      ReturnType<typeof mintPointedClientAnnexGeneration<PointerEntryOutcome>>
    >,
    spaceMinted: boolean
  ) => ({
    clientAnnexDid: generation.clientAnnexDid,
    generationDelegation: generation.generationDelegation,
    generationMinted: true,
    spaceMinted,
    accountLog: generation.pointed.published,
    ...(generation.pointed.rung !== undefined
      ? { rung: generation.pointed.rung }
      : {})
  })

  // The standing-authority arm: the sibling-named Space is already
  // account-controlled, its writes ride the supplied capability, and no
  // flip runs (heal's existing-Space pattern).
  if (annexSpaceId !== undefined && invocation !== undefined) {
    const generation = await mintPointedClientAnnexGeneration({
      was: invocation.was,
      wasServerUrl,
      spaceId: annexSpaceId,
      controller: account.did,
      ladderSeed,
      capability: invocation.capability,
      mintGenerationDelegation,
      point: pointGeneration,
      pinStore: idStore.pin.store,
      ...(now !== undefined ? { now } : {})
    })
    return pointedOutcome(generation, false)
  }

  // The bootstrap arm: mint, embed the delegation while the Space still
  // answers to its creation controller, flip, then the pointer entry.
  const bootstrapArm = async ({
    spaceId,
    spaceMinted
  }: {
    spaceId: string
    spaceMinted: boolean
  }) => {
    const generation = await mintPointedClientAnnexGeneration({
      was,
      wasServerUrl,
      spaceId,
      controller: mintController,
      ladderSeed,
      mintGenerationDelegation,
      point: pointGeneration,
      pinStore: idStore.pin.store,
      ...(now !== undefined ? { now } : {}),
      // The controller flip. ONLY an authorization-class refusal is
      // swallowed: this Space may be a sibling-named one a concurrent run
      // already flipped, so it no longer answers to this client. (The
      // transient visit's fresh-Space flip in `heal.ts` has no such case --
      // its Space id is freshly minted and no other run can hold it -- so it
      // swallows nothing.) A transport failure aborts BEFORE the pointer
      // entry -- publishing a pointer at a generation whose Space still
      // answers to the bare ladder did:key would leave it unreachable
      // forever, with nothing downstream ever re-running the flip.
      //
      // The mint's own ensure just read or wrote this Space Description, and
      // nothing since then has written one (the collection create, the
      // genesis publish, and the delegation embed all write collection
      // resources), so it rides along as `current` instead of a second
      // describe.
      beforePointerEntry: async ({ minted }) => {
        try {
          await was.space(spaceId).configure({
            ...(minted.spaceDescription !== undefined
              ? { current: minted.spaceDescription }
              : {}),
            controller: account.did,
            force: true
          })
        } catch (err) {
          if (!authorizationRefusal(err)) {
            throw err
          }
        }
      }
    })
    return pointedOutcome(generation, spaceMinted)
  }

  if (annexSpaceId !== undefined) {
    // A sibling-named Space under bootstrap authority alone: writable only
    // while it still answers to the bootstrap did:key (a tear before the
    // flip). One an earlier run already flipped refuses these writes; that
    // refusal falls back to the fresh mint below, and the flipped Space
    // stays the recorded orphan residue.
    try {
      return await bootstrapArm({ spaceId: annexSpaceId, spaceMinted: false })
    } catch (err) {
      if (!authorizationRefusal(err)) {
        throw err
      }
    }
  }
  return bootstrapArm({ spaceId: mintSpaceId(), spaceMinted: true })
}

/**
 * Whether an error is an authorization-class refusal (401/403, on the error,
 * its `cause`, or its carried response) rather than a transport or logic
 * failure. Matched structurally: was-client surfaces server refusals with
 * the HTTP status attached, and error classes do not survive crossing
 * package copies.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
function authorizationRefusal(err: unknown): boolean {
  const candidates = [err, (err as { cause?: unknown } | null)?.cause]
  for (const candidate of candidates) {
    if (candidate === null || typeof candidate !== 'object') {
      continue
    }
    const status = rawRequestStatus(candidate)
    if (status === 401 || status === 403) {
      return true
    }
    const carried = candidate as { name?: string }
    if (
      carried.name === 'NotAllowedError' ||
      carried.name === 'ForbiddenError' ||
      carried.name === 'UnauthorizedError'
    ) {
      return true
    }
  }
  return false
}

/**
 * Runs the whole credential-anchored establishment for one unlock credential
 * (see the module doc for the stage order and its whys). Idempotent under
 * re-run from durable state alone; a torn run converges by running again.
 *
 * @param options {object}
 * @param options.wasServerUrl {string}   the account pointer's host
 * @param options.spaceId {string}   the ACCOUNT Space's id, minted by the
 *   caller and carried in the account pointer (never minted here)
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed --
 *   freshly minted on a signup, recovered from the record on a heal re-run
 * @param options.standing {object}   the credential's standing client
 *   identity, from a BINDING-VERIFIED record or a fresh derivation:
 *   `clientDid`, `keyAgreementKeyMultibase`, `recipientKid`, and
 *   `keyAgreementKey` (the private-half key-agreement key, for the
 *   adopted-roster read-back)
 * @param options.bindRecord {CredentialAnchoredBindRecordHook}   REQUIRED:
 *   the unlock-record codec closure (see its type doc for the hook's
 *   standing-layout and freshness-floor obligations)
 * @param options.rosterStoreFor {Function}   REQUIRED: `({ did, log }) =>
 *   EncryptionDescriptorStore` -- the user-key roster's store, with a
 *   LADDER-signed log signer (the ceremony-tail license's first-entry
 *   shape), invoked as the bootstrap did:key. `log` is the account log this
 *   run adopted or published, so a store resolving its controller view reads
 *   it out of this run's own head instead of fetching `did.jsonl` again
 * @param options.bootstrapWasFor {Function}   REQUIRED:
 *   `({ keyAgent }) => WasClient` -- the storage client wiring, signing as
 *   the ladder VM's bare did:key (the agent is derived here from the seed)
 * @param options.idStore {WebvhIdStore}   the account's `id` collection
 *   store, signing as the same bootstrap did:key
 * @param [options.expectedDid] {string}   the account DID, when the caller's
 *   pointer already names one (a heal re-run)
 * @param options.lowEntropy {boolean}   whether the credential is
 *   low-entropy. REQUIRED (the compiler backstop at the passkey call site,
 *   where dropping it would publish the commitment and break the verbatim
 *   published key that call site's readers trigger on), and it still FAILS
 *   SAFE at runtime: the `keyAgreement` key publishes as a hash commitment
 *   unless the value is exactly `false` -- a verbatim KDF-derived key in
 *   the world-readable document is a standing offline-grind oracle
 *   removable only by credential rotation
 * @param [options.email] {string}   -- not taken here; carried inside the
 *   caller's `bindRecord` closure
 * @param [options.priorCreatedAt] {string}   the previous bind's freshness
 *   stamp, from a standing keyring hit. Its presence SKIPS stage 1: the
 *   record already carries the ladder seed, and a DID-less re-write could
 *   downgrade a sibling browser's completed re-bind
 * @param [options.delegatedClients] {IZcap}   the record's sibling
 *   delegation, when the caller holds one -- threaded into stage 3's Space
 *   resolution; under this ceremony's bootstrap-only authority a
 *   sibling-named Space it can no longer write falls back to a fresh mint
 * @param [options.provideKmsAuthentication] {Function}   `({ spaceReady }) =>
 *   Promise<KmsAuthenticationBinding | undefined>` -- the caller's opaque
 *   best-effort KMS thunk, started in stage 2 alongside the Space
 *   provisioning it reports through `spaceReady` (the caller owns its body
 *   and its timeout); a throw is the collected non-fatal `kmsAuthentication`
 *   failure. The thunk's obligation, since the genesis takes
 *   `authentication.vmId` verbatim into the world-readable entry: it adopts a
 *   served `keys.json` only after checking that `vmId`'s multibase against
 *   its own keystore listing, and mints otherwise
 * @param [options.promoteKeystore] {Function}   `({ did }) => Promise<void>`
 *   -- the best-effort keystore-controller promotion, called after the
 *   Space's own promotion; the caller's closure no-ops when its KMS stage
 *   bound no keystore this run. A throw is collected, never fatal
 * @param [options.beforePromotion] {Function}   runs after the re-bind and
 *   BEFORE the controller promotion -- the last window where a root
 *   invocation under the bootstrap did:key works (the signup's registry
 *   write). NOT swallowed here: a throw fails the establishment, so a hook
 *   that must be best-effort swallows its own failures
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @param [options.onStage] {StageNotifier}   observational: called as each
 *   stage finishes, so a caller can time them, in the order of
 *   `CREDENTIAL_ANCHORED_ESTABLISHMENT_STAGES` (`clientAnnex/stages.ts`).
 *   `interim-bind` is skipped with `priorCreatedAt`; `account-log-read` is
 *   kept as the stage-3 preamble's name, its span near-zero whenever the
 *   genesis's own head is reused instead of read; and the adopted-roster arm
 *   reports `roster-delivered-epochs` in place of `collection-epochs` (see
 *   `CREDENTIAL_ANCHORED_ESTABLISHMENT_STAGE_ALIASES` beside it). The two
 *   stages whose body is the caller's own closure -- `beforePromotion` and
 *   `promoteKeystore` -- are left for the caller to mark inside them, since
 *   only the caller can name what its closure does
 * @returns {Promise<CredentialAnchoredEstablishment>}
 * @throws {TypeError}   synchronously, when a required hook is missing
 * @throws {Error}   when the genesis's roster or epoch stage did not land
 *   (the underlying failure as `cause`); the record stays DID-less, so the
 *   next login's heal re-runs the establishment
 */
export function establishCredentialAnchoredAccount(options: {
  wasServerUrl: string
  spaceId: string
  ladderSeed: Uint8Array
  standing: {
    clientDid: string
    keyAgreementKeyMultibase: string
    recipientKid: string
    keyAgreementKey: IKeyAgreementKey
  }
  bindRecord: CredentialAnchoredBindRecordHook
  rosterStoreFor: (options: {
    did: string
    log: DIDLog
  }) => EncryptionDescriptorStore
  bootstrapWasFor: (options: { keyAgent: ICapabilityAgent }) => WasClient
  idStore: WebvhIdStore
  expectedDid?: string
  lowEntropy: boolean
  priorCreatedAt?: string
  delegatedClients?: IZcap
  provideKmsAuthentication?: (options: {
    spaceReady: Promise<unknown>
  }) => Promise<KmsAuthenticationBinding | undefined>
  promoteKeystore?: (options: { did: string }) => Promise<void>
  beforePromotion?: (context: {
    was: WasClient
    zcapClient: ZcapClient
    did: string
    userKey: UserKey
    establishment: CredentialAnchoredEstablishment
  }) => Promise<void>
  now?: number
  onStage?: StageNotifier
}): Promise<CredentialAnchoredEstablishment> {
  // Refused synchronously, before any write: the required hooks are the
  // persist-before-publish seams, and a run without them could publish a
  // rung nobody can re-derive.
  if (typeof options.bindRecord !== 'function') {
    throw new TypeError(
      'establishCredentialAnchoredAccount requires bindRecord: the unlock ' +
        'record must be durably written before anything publishes.'
    )
  }
  if (typeof options.rosterStoreFor !== 'function') {
    throw new TypeError(
      'establishCredentialAnchoredAccount requires rosterStoreFor: the ' +
        "user-key roster is the account's decryption root."
    )
  }
  if (typeof options.bootstrapWasFor !== 'function') {
    throw new TypeError(
      'establishCredentialAnchoredAccount requires bootstrapWasFor: every ' +
        "pre-promotion write signs as the ladder VM's bare did:key."
    )
  }
  return establishCredentialAnchoredAccountChecked(options)
}

/**
 * The checked body of {@link establishCredentialAnchoredAccount}.
 *
 * @param options {object}   see {@link establishCredentialAnchoredAccount}
 * @returns {Promise<CredentialAnchoredEstablishment>}
 */
async function establishCredentialAnchoredAccountChecked({
  wasServerUrl,
  spaceId,
  ladderSeed,
  standing,
  bindRecord,
  rosterStoreFor,
  bootstrapWasFor,
  idStore,
  expectedDid,
  lowEntropy,
  priorCreatedAt,
  delegatedClients,
  provideKmsAuthentication,
  promoteKeystore,
  beforePromotion,
  now,
  onStage
}: Parameters<
  typeof establishCredentialAnchoredAccount
>[0]): Promise<CredentialAnchoredEstablishment> {
  const stage = stageNotifier<CredentialAnchoredEstablishmentStageName>(onStage)
  const bootstrapAgent = await ladderVmAgent({ ladderSeed })
  const bootstrapZcap = didKeyZcapClient({ keyAgent: bootstrapAgent })
  const bootstrapWas = bootstrapWasFor({ keyAgent: bootstrapAgent })
  const pointer: AccountPointer = { spaceId, host: wasServerUrl }
  const failed: CredentialAnchoredEstablishment['failed'] = []

  // The hash-commitment rule, failing safe: a KDF-derived public key
  // published verbatim in the world-readable document is a standing
  // offline-grind oracle, so only an EXPLICIT `lowEntropy: false` publishes
  // the key itself; absent or ambiguous, the commitment publishes.
  const keyAgreement: UnlockKeyAgreementPublication =
    lowEntropy === false
      ? { publicKeyMultibase: standing.keyAgreementKeyMultibase }
      : {
          commitment: await keyAgreementCommitment({
            keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase
          })
        }

  // 1. The interim bridge and the first bind -- skipped when the caller's
  // record already carries the ladder seed (`priorCreatedAt` from a standing
  // hit): a DID-less re-write here could downgrade a sibling browser's
  // completed re-bind.
  let firstBindCreatedAt = priorCreatedAt
  if (priorCreatedAt === undefined) {
    const interimBridge = await delegateLogWrite({
      zcapClient: bootstrapZcap,
      pointer,
      recoveryClientDid: standing.clientDid
    })
    const firstBind = await bindRecord({
      controller: bootstrapAgent.id,
      pointer,
      delegation: interimBridge
    })
    assertBindResult({ bind: firstBind, stage: 'first bind' })
    firstBindCreatedAt = firstBind.createdAt
    stage('interim-bind')
  }

  // 2. The genesis ceremony under the bootstrap did:key. The candidate user
  // key seeds a fresh roster; an adopted (heal) roster keeps its own.
  const candidateUserKey = await mintUserKey()
  const genesis = await ensureCredentialAnchoredAccountGenesis({
    was: bootstrapWas,
    wasServerUrl,
    spaceId,
    ladderSeed,
    keyAgreement,
    standingRecipient: {
      id: standing.recipientKid,
      publicKeyMultibase: standing.keyAgreementKeyMultibase
    },
    userKey: candidateUserKey,
    idStore,
    rosterStoreFor,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(provideKmsAuthentication ? { provideKmsAuthentication } : {}),
    promoteController: false,
    ...(onStage !== undefined ? { onStage } : {})
  })
  // The KMS stage stays best-effort: a failed thunk is the ceremony's
  // collected `kmsAuthentication` stage, reported on the result and never
  // fatal -- the account proceeds keystore-less. The landing check below
  // deliberately ignores this stage.
  for (const entry of genesis.failed) {
    if (entry.stage === 'kmsAuthentication') {
      failed.push({ stage: 'kmsAuthentication', error: entry.error })
    }
  }
  const did = genesis.did
  const fullPointer: AccountPointer = { spaceId, host: wasServerUrl, did }
  // The ceremony collects its roster and epoch failures instead of
  // throwing; here they are fatal. A roster that never landed leaves the
  // candidate key held in this tab's memory alone, and a registry sealed
  // under it would be unreadable forever. Refusing BEFORE the re-bind keeps
  // the record DID-less, which is exactly what routes the next login into
  // the establishment re-run that converges.
  assertGenesisLanded({ failed: genesis.failed, epochs: genesis.epochs })
  if (!genesis.rosterDescriptor) {
    throw new Error('The user-key roster genesis did not land.')
  }

  // 2c. The adopted-roster arm: a re-run that adopted an earlier run's
  // roster recovers the real user key from the credential's standing wrap
  // and completes the collection epochs under it -- the one installer,
  // through the shared mint-policy stage. The stage's mint guard is the
  // genesis's own observation: it adopted a PRESENT roster a moment ago, so
  // a decide-read now serving it absent is a host contradicting itself, and
  // minting there would be a single-recipient roster genesis over a roster
  // that exists. Refused outright; nothing else licenses the mint here.
  let userKey: UserKey = candidateUserKey
  if (genesis.rosterDescriptor.currentEpoch !== candidateUserKey.id) {
    const adoptedEpoch = genesis.rosterDescriptor.currentEpoch
    const delivered = await ensureRosterDeliveredEpochs({
      store: rosterStoreFor({ did, log: genesis.published.log }),
      candidateUserKey,
      clientKeyAgreementKey: standing.keyAgreementKey,
      was: bootstrapWas,
      spaceId,
      beforeMint: async () => {
        throw new Error(
          'The user-key roster the genesis adopted (current epoch ' +
            `${String(adoptedEpoch)}) is now served absent; refusing to ` +
            'mint a fresh roster over it.'
        )
      }
    })
    if (delivered.outcome === 'no-wrap') {
      throw new Error(
        'The adopted user-key roster could not be read back with this ' +
          'credential.',
        { cause: delivered.error }
      )
    }
    userKey = delivered.userKey
    assertGenesisLanded({ failed: [], epochs: delivered.epochs })
    stage('roster-delivered-epochs')
  }

  // 3. The annex generation block, so the very next login can enroll a
  // transient client: reuse the pointed one; resolve, mint, embed the
  // delegation, flip the auxiliary Space's controller, and point otherwise.
  // The genesis stage already read or published this exact head, and nothing
  // between it and here writes the account log (the KMS thunk runs inside
  // the genesis, before its did:webvh stage; the adopted-roster arm writes
  // only the roster log). Two conditions decide whether it is reused.
  //
  // It must be a head this run MINTED. What stage 3 reads off the document
  // is the `#DelegatedClients` completion test, which no ETag protects: a
  // stale "no pointer yet" answer makes this run mint a generation the
  // account already has, and the CAS that then refuses the pointer entry
  // arrives far too late -- the Space is minted, nothing names it, and no
  // deleter exists. On the adopt branch (the heal re-run) the account is
  // live and a concurrent transient login can point a generation during the
  // roster genesis and the epoch fan-out, so this stage re-reads exactly as
  // it did before the head was threaded, keeping that window at its old
  // width. A minted head has no such window: the account did not exist a
  // moment ago, so no other writer can hold it.
  //
  // And it must carry an ETag, since the pointer entry below publishes under
  // a compare-and-swap and a head with no validator would degrade that to an
  // unconditional write.
  const published =
    genesis.logMinted && genesis.published.etag !== undefined
      ? genesis.published
      : await readPublishedLog({ idStore, expectedDid: did })
  if (published === undefined) {
    throw new Error('The account log the genesis published could not be read.')
  }
  stage('account-log-read')
  // Stage 3 on the ladder arm. Its pre-mint attribution is what refuses an
  // account whose document no longer anchors this ladder (a struck ladder
  // VM) while the record is still in its pre-re-bind shape, rather than
  // after a re-bind that would leave a rebound record with no registry entry
  // and no mender. The pointer entry rides the root-invoking store in this
  // window, so it republishes the `did:web` projection beside itself.
  const generation = await ensurePointedClientAnnexGeneration({
    account: published,
    wasServerUrl,
    ladderSeed,
    signer: { kind: 'ladder' },
    logOnly: false,
    was: bootstrapWas,
    mintController: bootstrapAgent.id,
    mintGenerationDelegation: ladderSignedGenerationDelegationMinter({
      accountDid: did,
      ladderSeed,
      wasServerUrl,
      spaceId,
      ...(now !== undefined ? { now } : {})
    }),
    idStore,
    published,
    ...(delegatedClients !== undefined ? { delegatedClients } : {}),
    ...(now !== undefined ? { now } : {})
  })
  stage('annex-generation')
  const clientAnnex = clientAnnexDidParts({ did: generation.clientAnnexDid })

  // 4. The final bridge and sibling, ladder-VM-signed (they must survive
  // promotion, which the interim did:key-signed bridge cannot), and the
  // re-bind: full pointer, both delegations, the management zcap to the
  // account DID.
  const { bridge, sibling, rebind } = await rebindCredentialAnchoredRecord({
    accountDid: did,
    pointer: fullPointer,
    ladderSeed,
    standingClientDid: standing.clientDid,
    clientAnnexSpaceId: clientAnnex.spaceId,
    bindRecord,
    stage: 're-bind',
    ...(firstBindCreatedAt !== undefined
      ? { priorCreatedAt: firstBindCreatedAt }
      : {}),
    ...(now !== undefined ? { now } : {})
  })
  stage('record-rebind')

  const establishment: CredentialAnchoredEstablishment = {
    did,
    // The pointer entry's post-publish head when stage 3 wrote one; the head
    // it stood on when the document already pointed at a generation.
    accountLog: generation.accountLog ?? published,
    unlockSpaceId: rebind.unlockSpaceId,
    ...(rebind.manageCapability
      ? { manageCapability: rebind.manageCapability }
      : {}),
    standingFields: credentialAnchoredStandingFields({
      standing,
      // The rung the pointer entry was signed with when stage 3 wrote one (a
      // lost race may have climbed past the pre-flight's answer), else the
      // rung stage 3's pre-flight found standing. The ladder arm always
      // reports one.
      updateKeyMultibase: generation.rung!.keyMultibase,
      bridge,
      sibling,
      unlock: rebind
    }),
    ...(genesis.epochsSkipped ? { epochsSkipped: genesis.epochsSkipped } : {}),
    failed
  }

  // 5. The caller's pre-promotion tail (the signup's registry write): the
  // last window where a root invocation under the bootstrap did:key works.
  // A throw here fails the establishment (some callers' registry writes
  // must land in this window or the credential has no rebuild); a hook that
  // must be best-effort swallows its own failures.
  if (beforePromotion) {
    await beforePromotion({
      was: bootstrapWas,
      zcapClient: bootstrapZcap,
      did,
      userKey,
      establishment
    })
  }

  // 6. The promotion, last: from here on the ladder's authority is exactly
  // its licensed document inventory (delegation and log-anchored signing),
  // and the bootstrap did:key stops verifying.
  await ensurePromotedSpaceController({
    was: bootstrapWas,
    wasAsClient: bootstrapWas,
    spaceId,
    did
  })
  stage(CONTROLLER_PROMOTION_STAGE)

  // The keystore half of the promotion, best-effort like every KMS touch
  // here: the caller's closure no-ops when its KMS stage bound no keystore
  // this run, and a throw is collected, never fatal -- the keystore's KMS
  // authority is independent of the Space controller, so a failed promotion
  // is retryable.
  if (promoteKeystore) {
    try {
      await promoteKeystore({ did })
    } catch (err) {
      failed.push({ stage: 'keystorePromotion', error: err })
    }
  }

  return establishment
}

/**
 * The re-bind every credential-anchored path ends on (the establishment's
 * stage 4, and the mend's record-downgrade re-bind): the ladder-VM-signed
 * bridge and `delegatedClients` sibling delegations, then the record
 * re-bound through the caller's `bindRecord` hook with the full pointer, both
 * delegations, and the management delegation to the account DID. The
 * delegations are ladder-VM-signed because they must survive promotion,
 * which the interim did:key-signed bridge cannot.
 *
 * @param options {object}
 * @param options.accountDid {string}   the published account DID
 * @param options.pointer {AccountPointer}   the full pointer, naming that DID
 * @param options.ladderSeed {Uint8Array}
 * @param options.standingClientDid {string}   the credential's standing
 *   client did:key, the delegations' controller
 * @param options.clientAnnexSpaceId {string}   the pointed generation's Space
 *   (the sibling delegation's target)
 * @param options.bindRecord {CredentialAnchoredBindRecordHook}
 * @param options.stage {string}   the bind's name in the result assertion
 * @param [options.priorCreatedAt] {string}   the earlier bind's stamp, when
 *   one stands
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {Promise<{ bridge: IZcap, sibling: IZcap,
 *   rebind: CredentialAnchoredBindResult }>}
 */
export async function rebindCredentialAnchoredRecord({
  accountDid,
  pointer,
  ladderSeed,
  standingClientDid,
  clientAnnexSpaceId,
  bindRecord,
  stage,
  priorCreatedAt,
  now
}: {
  accountDid: string
  pointer: AccountPointer
  ladderSeed: Uint8Array
  standingClientDid: string
  clientAnnexSpaceId: string
  bindRecord: CredentialAnchoredBindRecordHook
  stage: string
  priorCreatedAt?: string
  now?: number
}): Promise<{
  bridge: IZcap
  sibling: IZcap
  rebind: CredentialAnchoredBindResult
}> {
  // The record's controller field is the ladder VM's bare did:key, derived
  // from the same seed the delegations sign under so the two cannot diverge.
  const { agent: ladderAgent, zcapClient: ladderZcap } = await ladderVmSigners({
    accountDid,
    ladderSeed
  })
  const controller = ladderAgent.id
  const bridge = await delegateLogWrite({
    zcapClient: ladderZcap,
    pointer,
    recoveryClientDid: standingClientDid
  })
  const sibling = await mintDelegatedClientsDelegation({
    zcapClient: ladderZcap,
    wasServerUrl: pointer.host,
    clientAnnexSpaceId,
    controller: standingClientDid,
    ...(now !== undefined ? { now } : {})
  })
  const rebind = await bindRecord({
    controller,
    pointer,
    delegation: bridge,
    delegatedClients: sibling,
    delegateManagementTo: accountDid,
    ...(priorCreatedAt !== undefined ? { priorCreatedAt } : {})
  })
  assertBindResult({ bind: rebind, stage })
  return { bridge, sibling, rebind }
}

/**
 * The one builder of the standing fields a registry entry records, shared
 * by the establishment (from the delegations it just minted and the re-bind
 * it just ran) and the mend's registry arm (from the caller's standing
 * record). Optional members are present iff their source is.
 *
 * @param options {object}
 * @param options.standing {object}   the credential's standing client:
 *   `clientDid`, `keyAgreementKeyMultibase`, `recipientKid`
 * @param options.updateKeyMultibase {string}   the ladder's attributed rung
 * @param [options.bridge] {IZcap}   the record's bridge delegation
 * @param [options.sibling] {IZcap}   the record's `delegatedClients` sibling
 * @param [options.unlock] {object}   the unlock key-agreement members, from
 *   the bind result or the standing record
 * @returns {CredentialAnchoredStandingFields}
 */
export function credentialAnchoredStandingFields({
  standing,
  updateKeyMultibase,
  bridge,
  sibling,
  unlock
}: {
  standing: {
    clientDid: string
    keyAgreementKeyMultibase: string
    recipientKid: string
  }
  updateKeyMultibase: string
  bridge?: IZcap
  sibling?: IZcap
  unlock?: {
    unlockKeyAgreementKeyId?: string
    unlockKeyAgreementKeyMultibase?: string
  }
}): CredentialAnchoredStandingFields {
  return {
    rosterKid: standing.recipientKid,
    keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase,
    updateKeyMultibase,
    unlockClientDid: standing.clientDid,
    ...recordedDelegationFields({
      ...(bridge ? { delegation: bridge } : {}),
      ...(sibling ? { delegatedClients: sibling } : {})
    }),
    ...(unlock?.unlockKeyAgreementKeyId
      ? { unlockKeyAgreementKeyId: unlock.unlockKeyAgreementKeyId }
      : {}),
    ...(unlock?.unlockKeyAgreementKeyMultibase
      ? {
          unlockKeyAgreementKeyMultibase: unlock.unlockKeyAgreementKeyMultibase
        }
      : {})
  }
}

/**
 * Asserts a `bindRecord` result carries the members the ceremony reads --
 * the observable half of the hook's standing-layout obligation (the sealed
 * members are the codec's own duty and cannot be checked from here).
 *
 * @param options {object}
 * @param options.bind {CredentialAnchoredBindResult}
 * @param options.stage {string}
 * @throws {TypeError}
 */
export function assertBindResult({
  bind,
  stage
}: {
  bind: CredentialAnchoredBindResult
  stage: string
}): void {
  if (typeof bind?.createdAt !== 'string' || bind.createdAt.length === 0) {
    throw new TypeError(
      `The bindRecord hook's ${stage} returned no createdAt stamp; the ` +
        're-bind cannot advance past it.'
    )
  }
  if (
    typeof bind.unlockSpaceId !== 'string' ||
    bind.unlockSpaceId.length === 0
  ) {
    throw new TypeError(
      `The bindRecord hook's ${stage} returned no unlockSpaceId; the ` +
        'record it wrote cannot be located.'
    )
  }
}

/**
 * Refuses a genesis whose roster or epoch stages did not land: the ceremony
 * reports them on `failed` (a stage that could not run) and on
 * `epochs.failed` (a collection the fan-out could not epoch) rather than
 * throwing, and on a credential-anchored account no login-time sweep ever
 * finishes them -- the establishment re-run is the only mender, so the
 * establishment must stop here for it to be reached. A failed
 * `kmsAuthentication` stage is deliberately NOT refused: the KMS stage is best-effort (reported
 * on the result), and a keystore-less account is complete.
 *
 * @param options {object}
 * @param options.failed {Array}   the ceremony's collected stage failures
 * @param [options.epochs] {WalletSpaceEpochsResult}   the collection
 *   epoch fan-out's result, when the stage ran
 * @throws {Error}   carrying the first underlying failure as `cause`
 */
function assertGenesisLanded({
  failed,
  epochs
}: {
  failed: AccountGenesisResult['failed']
  epochs?: AccountGenesisResult['epochs']
}): void {
  const stage = failed.find(
    entry => entry.stage === 'roster' || entry.stage === 'epochs'
  )
  if (stage) {
    throw new Error(
      `The credential-anchored genesis's ${stage.stage} stage failed.`,
      { cause: stage.error }
    )
  }
  const collection = epochs?.failed[0]
  if (collection) {
    throw new Error(
      'The credential-anchored genesis could not install a key epoch on ' +
        `collection "${collection.collectionId}".`,
      { cause: collection.error }
    )
  }
}
