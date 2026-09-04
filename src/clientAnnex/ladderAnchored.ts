/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The ladder-anchored ceremonies on the ACCOUNT log -- everything a standing
 * credential's ladder does to the world-readable `did.jsonl` beyond the
 * split-configuration edits (which stay in `unlock/standingWebvh.ts`):
 *
 * - {@link createLadderAnchoredAccountLog} / {@link ensureLadderAnchoredDidWebvh}
 *   -- the genesis of an account with zero enrolled clients, anchored
 *   on the credential's ladder alone (rung 0 signs, the ladder VM and the
 *   credential's `keyAgreement` inventory fold into the one entry).
 * - {@link selfEnrollWebvhClient} -- the self-enrolling continuation a fresh
 *   browser runs with nothing but the credential: two entries through the
 *   record's delegated `did.jsonl` bridge --
 *
 *   1. **Reveal + commit**: ladder rung `i` joins `updateKeys` (its hash
 *      stands committed, which is what makes the entry verify) and
 *      `nextKeyHashes` extends with the new ordinary client's update- and
 *      staged-key hashes plus `hash(rung i + 1)` -- the credential's next
 *      standing commitment.
 *   2. **Add + retire the rung**: signed by the new client's update key
 *      (revealed from the commit), this entry publishes the new client's
 *      verification methods and update key and drops the spent rung and its
 *      hash. The credential's own inventory -- its `keyAgreement` entry and the
 *      freshly committed `hash(rung i + 1)` -- stands untouched, ready for
 *      the next self-enrollment. Nothing is spent, and no replacement exists.
 *      Every standing credential's ladder VM is left alone: a VM's life is
 *      keyed to its credential rather than to the account's client census, so
 *      it stands alongside the client this entry publishes.
 *
 * - {@link revealLadderRungWebvh} -- the reveal-and-commit entry on its own,
 *   for a credential-only visit that needs to sign one account-log entry
 *   after a self-enrollment spent the previously revealed rung.
 *
 * - {@link forgetWebvhClient} -- self-enrollment in reverse: one atomic
 *   ladder-signed removal entry through the bridge takes an enrolled client's
 *   whole document inventory out; the last enrolled client refuses
 *   ({@link LastEnrolledClientForgetError}).
 * - {@link strikeLadderVmWebvh} / {@link installLadderVmWebvh} /
 *   `forgetLastWebvhClient` -- the entries of the LAST enrolled
 *   client's forget (decision 0004's 2026-08-19 amendment): the credential's
 *   own ladder VM struck and then reinstalled while the client stands (the
 *   pair supplying the transition's inventory-changing document version),
 *   then -- after the revocations the composed ceremony runs in between -- a
 *   removal entry that takes the client out while the reinstalled VM keeps
 *   the account ladder-anchored. The composed ceremony is `forgetLast.ts`.
 *
 * Which rung is current is recovered from the log itself
 * (`attributeLadderRung`, fail-closed); a lost compare-and-swap race re-runs,
 * re-attributes, and climbs to the winner's committed rung -- the
 * retry-up-the-ladder resolution. Every stage is idempotent and resumable
 * from durable state alone, on the recovery continuation's pattern.
 */
import { deriveNextKeyHash, updateDID } from '@interop/did-method-webvh'
import type {
  DIDDoc,
  DIDLog,
  UpdateDIDResult,
  VerificationMethod
} from '@interop/did-method-webvh'
import {
  assertCanonicalClientKeys,
  backfillKeyMapWebvhBlock,
  concludeWithPublishedLog,
  createLadderAnchoredWebvhLog,
  didWebvhControllerTemplate,
  genesisNextKeyHashes,
  ladderVerificationMethod,
  markedVerificationMethodPair,
  pinOfLog,
  publishEntryPinned,
  publishWebvhLog,
  readPublishedLog,
  readPublishedLogOrThrow,
  servedHead,
  updateKeySigner,
  withLogConflictRetry,
  writeKeysJson
} from '../webvh/didWebvh.js'
import type {
  ClientWebvhUpdateKeys,
  CreatedWebvhLog,
  DidWebKeyMapV2,
  PublishedWebvhLog,
  WebvhEnrollmentKeys,
  WebvhIdStore
} from '../webvh/didWebvh.js'
import { putDidWebProjection } from '../webvh/didWebProjection.js'
import { accountLogPinId } from '../webvh/verifyLog.js'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import { ladderVmIds, relationIds } from '../resourceLog/document.js'
import {
  clientRemovalFields,
  clientRemovalTarget,
  type ClientRemovalTarget,
  type RevokedClientKeys
} from '../webvh/revokeClient.js'
import {
  unlockKeyVerificationMethod,
  type UnlockKeyAgreementPublication,
  type UnlockLogStore
} from '../unlock/standingWebvh.js'
import {
  attributeLadderRung,
  ladderRung,
  ladderVmKeyMultibase
} from './ladder.js'
import { signAccountEntry } from '../webvh/accountEntry.js'
import type { AccountEntryFields } from '../webvh/accountEntry.js'
import type { LadderRung, LadderRungState } from './ladder.js'

/**
 * LADDER-ANCHORED GENESIS: assembles the one-entry did:webvh log of an account
 * with zero enrolled clients, anchored on the minting credential's
 * ladder alone. Everything derives from the ladder seed: rung 0 is the sole
 * `updateKeys` member and signs the entry, `nextKeyHashes` commits rung 0's
 * own carry-over hash plus rung 1 (the staged rung) -- the carry-over hash is
 * what the first self-enrollment's reveal-and-commit entry,
 * re-stating `updateKeys` containing rung 0, requires --
 * and the ladder VM (the stable sibling) is published under `assertionMethod`
 * and `capabilityDelegation` only. The credential's `keyAgreement`
 * entry is FOLDED INTO GENESIS -- no enrolled client exists to run the
 * separate bind entry ({@link publishUnlockKey}) -- so the genesis
 * `keyAgreement` array holds only the credential's entry.
 *
 * The account stays ladder-anchored until a self-enrollment
 * ({@link selfEnrollWebvhClient}) publishes a client and retires rung 0. That
 * entry leaves the ladder VM standing: it is struck when the credential
 * retires, not when a client arrives.
 *
 * When the wallet keeps a KMS, `didWebKeys` folds the KMS-held
 * authentication key into the entry under `authentication` only -- the
 * enrolled-client genesis's server-side convenience, with its exclusions
 * intact (no KMS keyAgreement or assertion key).
 *
 * The caller owns publication (conditional, create-only) and the pointer
 * write that follows; this assembles and signs the log only.
 *
 * @param options {object}
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}
 * @param [options.didWebKeys] {DidWebKeyMapV2}   the parsed keys.json, when
 *   the wallet keeps a KMS; absent, the genesis is ladder-and-credential-only
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed
 * @param options.keyAgreement {UnlockKeyAgreementPublication}   the
 *   credential's key-agreement publication (commitment or verbatim)
 * @returns {Promise<CreatedWebvhLog>}
 */
export async function createLadderAnchoredAccountLog({
  wasServerUrl,
  spaceId,
  didWebKeys,
  ladderSeed,
  keyAgreement
}: {
  wasServerUrl: string
  spaceId: string
  didWebKeys?: DidWebKeyMapV2
  ladderSeed: Uint8Array
  keyAgreement: UnlockKeyAgreementPublication
}): Promise<CreatedWebvhLog> {
  const rung0 = await ladderRung({ ladderSeed, index: 0 })
  const rung1 = await ladderRung({ ladderSeed, index: 1 })
  const controllerTemplate = didWebvhControllerTemplate({
    wasServerUrl,
    spaceId
  })
  return createLadderAnchoredWebvhLog({
    wasServerUrl,
    spaceId,
    ...(didWebKeys ? { didWebKeys } : {}),
    ladderVmKeyMultibase: await ladderVmKeyMultibase({ ladderSeed }),
    credentialKeyAgreementMethod: unlockKeyVerificationMethod({
      did: controllerTemplate,
      keyAgreement
    }),
    updateKeyPublicKeyMultibase: rung0.keyMultibase,
    nextKeyHashes: await genesisNextKeyHashes({
      activeKeyMultibase: rung0.keyMultibase,
      stagedKeyMultibase: rung1.keyMultibase
    }),
    signer: await updateKeySigner({ seed: rung0.seed })
  })
}

/**
 * LADDER-ANCHORED GENESIS AS AN ENSURE: probe, adopt, or create-and-publish --
 * {@link createLadderAnchoredAccountLog} with the enrolled-client flow's
 * `ensureDidWebvh` convention wrapped around it. The convergence rule is what
 * makes signup a ceremony rather than a bare create: `createDID` timestamps
 * the genesis entry, so a naive re-run of a torn signup mints a DIFFERENT SCID
 * and its create-if-absent PUT can never land. So a published log is ADOPTED
 * instead -- iff `attributeLadderRung` attributes its update parameters to
 * this credential's ladder (rung revealed or committed; a foreign log fails
 * closed with `LadderAttributionError` and is never built on).
 *
 * The publish is a conditional create-if-absent, so a concurrent signup's
 * winner is adopted on the conflict re-run rather than erased. On the create
 * path a supplied `pinStore` is written from the log this run minted (the
 * account-log trust-on-first-use convention: the creator knows the true
 * genesis); on the probe path the read itself carries the pin check.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}
 * @param [options.didWebKeys] {DidWebKeyMapV2}   the parsed keys.json, when
 *   the wallet keeps a KMS; folded into the CREATE path only (see the
 *   adoption note in the body), which also records the minted DID into
 *   keys.json's webvh block as the enrolled-client ensure does
 * @param [options.keysJsonEtag] {string}   the ETag the KMS-authentication
 *   stage's own `keys.json` write returned, carried as the `ifMatch` of that
 *   rewrite
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed
 * @param options.keyAgreement {UnlockKeyAgreementPublication}   the
 *   credential's key-agreement publication (commitment or verbatim)
 * @param [options.expectedDid] {string}   the DID the published log must
 *   resolve to, when the caller holds the account pointer; a heal login on a
 *   fresh terminal legitimately holds none
 * @param [options.pinStore] {ResourceLogPinStore}   this client's chain-head
 *   pins; the account log's slot is keyed by `accountLogPinId` over the
 *   `spaceId` above
 * @returns {Promise<{ did: string, published: PublishedWebvhLog,
 *   logMinted: boolean }>}   `published` is the head this stage stands on --
 *   the served one on the adopt branch, the minted one paired with its
 *   create PUT's ETag on the create branch -- so the stage after it can build
 *   on this head instead of re-reading the log this one just read or wrote.
 *   Its `etag` is absent against a backend that serves none, which is one
 *   case a later stage must still read for itself. `logMinted` says WHICH
 *   branch produced it, which a later stage needs before reusing it: a
 *   minted head is one no other writer could have held a moment ago, while
 *   an adopted head is a snapshot of an account other clients are free to
 *   write to, and the parts of it no ETag protects (the document's
 *   completion tests) can be stale by the time a later stage reads them
 */
export async function ensureLadderAnchoredDidWebvh(options: {
  idStore: WebvhIdStore
  wasServerUrl: string
  spaceId: string
  didWebKeys?: DidWebKeyMapV2
  keysJsonEtag?: string
  ladderSeed: Uint8Array
  keyAgreement: UnlockKeyAgreementPublication
  expectedDid?: string
  pinStore?: ResourceLogPinStore
}): Promise<{
  did: string
  published: PublishedWebvhLog
  logMinted: boolean
}> {
  return withLogConflictRetry(() => ensureLadderAnchoredDidWebvhOnce(options))
}

/**
 * One attempt of {@link ensureLadderAnchoredDidWebvh}, re-invoked by the
 * conflict retry.
 *
 * @param options {object}   see {@link ensureLadderAnchoredDidWebvh}
 * @returns {Promise<{ did: string, published: PublishedWebvhLog,
 *   logMinted: boolean }>}
 */
async function ensureLadderAnchoredDidWebvhOnce({
  idStore,
  wasServerUrl,
  spaceId,
  didWebKeys,
  keysJsonEtag,
  ladderSeed,
  keyAgreement,
  expectedDid,
  pinStore
}: {
  idStore: WebvhIdStore
  wasServerUrl: string
  spaceId: string
  didWebKeys?: DidWebKeyMapV2
  keysJsonEtag?: string
  ladderSeed: Uint8Array
  keyAgreement: UnlockKeyAgreementPublication
  expectedDid?: string
  pinStore?: ResourceLogPinStore
}): Promise<{
  did: string
  published: PublishedWebvhLog
  logMinted: boolean
}> {
  const logId = accountLogPinId({ spaceId })
  const published = await readPublishedLog({
    idStore,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore ? { pinStore, logId } : {})
  })
  if (published) {
    // Adoption: a torn earlier signup (or a concurrent one) already published
    // the log. Adopt it iff this credential's ladder attributes it -- the
    // ladder-anchored analog of the enrolled-client path's "authorizes one
    // of this client's seeds" check. The attribution accepts a revealed rung
    // too, so an account that has since self-enrolled a client (retiring
    // rung 0) still adopts here rather than hard-failing. `didWebKeys` is
    // deliberately ignored on this path: adopting a published log never
    // edits it, and a log published without the KMS convenience key is
    // healed by a later login, not here.
    await attributeLadderRung({ ladderSeed, published })
    // Heals a keys.json left without its `webvh` block by a run torn between
    // the genesis entry and the rewrite: the served map's own binding gains
    // the DID this log resolves to. Gated on this run keeping a KMS, so a
    // KMS-less wallet spends no read on a resource it never writes.
    if (didWebKeys) {
      await backfillKeyMapWebvhBlock({ idStore, did: published.did })
    }
    // Heals a did.json left lagging by a torn earlier publish of this
    // controller-invoking genesis; a lag left by a later ladder-signed entry
    // is `ensureDidWebProjection`'s to mend.
    const { did } = await concludeWithPublishedLog({ idStore, published })
    // The served head verbatim: the projection PUT above touches no log, so
    // the read's own ETag is still the log's validator. `logMinted: false`
    // marks it as a snapshot of an account other clients may be writing to.
    return { did, published, logMinted: false }
  }
  const created = await createLadderAnchoredAccountLog({
    wasServerUrl,
    spaceId,
    ...(didWebKeys ? { didWebKeys } : {}),
    ladderSeed,
    keyAgreement
  })
  const written = await publishWebvhLog({
    idStore,
    log: created.log,
    webDoc: created.webDoc,
    // Create-if-absent: a concurrent signup that already published its own
    // log wins, and this run re-reads and adopts (or refuses) instead of
    // erasing it.
    ifNoneMatch: true
  })
  // Trust-on-first-use, established by the creator itself: this run minted the
  // genesis, so the pin it writes needs no served log to be believed.
  if (pinStore) {
    await pinStore.write({ logId, pin: pinOfLog(created.log) })
  }
  // The enrolled-client create path's keys.json record, verbatim: the
  // account DID joins the KMS bindings in the webvh block, so keys.json never
  // durably names the bindings without the DID they belong to.
  if (didWebKeys) {
    await writeKeysJson({
      idStore,
      didWebKeys,
      webvh: { did: created.did },
      ...(keysJsonEtag !== undefined && { ifMatch: keysJsonEtag })
    })
  }
  // The head this run just wrote, assembled from what `createDID` already
  // resolved plus the create PUT's own validator -- no second read, and no
  // second resolve.
  return {
    did: created.did,
    logMinted: true,
    published: {
      log: created.log,
      did: created.did,
      doc: created.doc,
      updateKeys: created.updateKeys,
      nextKeyHashes: created.nextKeyHashes,
      ...(written.etag !== undefined ? { etag: written.etag } : {})
    }
  }
}

/**
 * What a ladder-signed entry's `build` hands back -- the account-entry seam's
 * own field bundle, under the annex's name for its call sites.
 */
export type LadderSignedEntry = AccountEntryFields

/**
 * What {@link ladderSignedAccountEntry} reports. `skipped` says the
 * pre-attribution hook declined, so nothing was attributed and nothing was
 * published; `updated` is absent on that path AND where `build` itself
 * declined, which is the one test an idempotent caller needs ("did this call
 * publish an entry"). The ladder arm always attributes a rung, so `rung`,
 * `rungHash` and `state` stand on every non-skipped outcome -- which is what
 * this wrapper narrows over the seam's shared outcome.
 */
export type LadderSignedEntryOutcome =
  | {
      skipped: true
      published: PublishedWebvhLog
      rung?: undefined
      rungHash?: undefined
      state?: undefined
      updated?: undefined
    }
  | {
      skipped: false
      published: PublishedWebvhLog
      rung: LadderRung
      rungHash: string
      state: LadderRungState
      updated?: UpdateDIDResult
    }

/**
 * ONE LADDER-SIGNED ACCOUNT-LOG ENTRY: the account-entry seam
 * ({@link signAccountEntry}) on its ladder arm, narrowed to the outcome the
 * annex's ceremonies read. The seam owns the nine steps -- the pinned read,
 * the rung attribution, the rung's carry-over hash, the carry-over
 * precondition, the update-key signer, the self-reveal union into
 * `updateKeys`, the carry-over union into `nextKeyHashes`, the conditional
 * publish (`did.jsonl` alone, the bridge's whole reach), and the pin advance.
 *
 * No conflict retry of its own: a lost compare-and-swap surfaces as a
 * `WebvhLogConflictError` for the caller's {@link withLogConflictRetry} to
 * re-run, which is what re-attributes the rung and climbs to the winner's
 * committed one (the retry-up-the-ladder resolution).
 *
 * @param options {object}
 * @param options.store {UnlockLogStore}   public log read + delegated PUT
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed
 * @param [options.expectedDid] {string}   the account DID the log must resolve
 *   to, from the caller's stored account pointer
 * @param [options.pinStore] {ResourceLogPinStore}   the caller's chain-head
 *   pins: the read is checked against the pinned head, and the pin advances
 *   to the head this entry publishes
 * @param [options.logId] {string}   the account log's pin slot
 *   (`accountLogPinId({ spaceId })`); required whenever a `pinStore` is
 *   supplied
 * @param [options.skip] {function}   `(published) => boolean` -- run on the
 *   read, before any attribution; `true` returns `skipped` with nothing
 *   published
 * @param options.build {function}
 *   `({ published, rung, state }) => LadderSignedEntry | undefined` -- the
 *   entry's own members, or `undefined` to decline
 * @param [options.beforePublish] {function}   `({ updated }) => Promise<void>`
 *   -- the pre-publish seam, for the ceremonies that PUT their post-entry
 *   `did:web` projection while the authority they are about to end can still
 *   write it. See {@link signAccountEntry}
 * @returns {Promise<LadderSignedEntryOutcome>}
 */
export async function ladderSignedAccountEntry({
  store,
  ladderSeed,
  expectedDid,
  pinStore,
  logId,
  skip,
  build,
  beforePublish
}: {
  store: UnlockLogStore
  ladderSeed: Uint8Array
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
  skip?: (published: PublishedWebvhLog) => boolean | Promise<boolean>
  build: (context: {
    published: PublishedWebvhLog
    rung: LadderRung
    state: LadderRungState
  }) => LadderSignedEntry | undefined | Promise<LadderSignedEntry | undefined>
  beforePublish?: (built: { updated: UpdateDIDResult }) => Promise<void>
}): Promise<LadderSignedEntryOutcome> {
  const outcome = await signAccountEntry({
    idStore: store,
    signer: { kind: 'ladder', ladderSeed },
    build: ({ published, rung, state }) =>
      build({ published, rung: rung!, state: state! }),
    ...(skip ? { skip } : {}),
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {}),
    missingMessage: 'did:webvh: did.jsonl is missing; nothing to enroll into.',
    ...(beforePublish ? { beforePublish } : {})
  })
  if (outcome.skipped) {
    return { skipped: true, published: outcome.published }
  }
  return {
    skipped: false,
    published: outcome.published,
    rung: outcome.rung!,
    rungHash: outcome.rungHash!,
    state: outcome.state!,
    ...(outcome.updated ? { updated: outcome.updated } : {})
  }
}

/**
 * SELF-ENROLLMENT (run by the credential-derived client through the delegated
 * `did.jsonl` PUT): writes the standing continuation described in the module
 * doc -- the reveal-and-commit entry signed by the attributed ladder rung,
 * then the add entry signed by the new ordinary client's update key, which
 * also retires the spent rung. Resumable from durable state alone: a
 * completed continuation is detected by the new client's update key already
 * being authorized (no-op), a torn one by the attribution finding the rung
 * already revealed. Both entries publish conditionally on the read they were
 * built on, and a race lost to a concurrent ceremony re-runs from the top --
 * re-attributing, which is exactly the retry-up-the-ladder resolution.
 *
 * @param options {object}
 * @param options.store {UnlockLogStore}   public log read + delegated PUT
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed, from
 *   its unlock record
 * @param options.newClientKeys {WebvhEnrollmentKeys}   the new ordinary
 *   client's public halves
 * @param options.newClientUpdateSeeds {ClientWebvhUpdateKeys}   the new
 *   client's update-key seeds (minted by the self-enrolling flow, which
 *   therefore holds them and can sign the add entry)
 * @param options.onCommitted {function}
 *   `(committed: { builtOnHead: { scid, versionId } }) => Promise<void>` --
 *   the REQUIRED persist-before-publish seam. It runs once per attempt, after
 *   the reveal-and-commit entry stands (published here, or standing from a
 *   torn earlier run) and BEFORE the add entry -- the ceremony's pivot -- is
 *   built. The caller writes the pending client-key record to client-local
 *   storage there (the `pending` codec group of `keys/clientKeyRecord.ts`:
 *   ceremony `'self-enrollment'`, the handed-back `builtOnHead`), so the add
 *   entry can never publish a client whose seed nothing can re-derive, per the
 *   post-pivot derivability rule (`decisions/0010`). A throw propagates and
 *   the add entry is withheld. What a throw leaves behind is inert: the
 *   standing reveal entry's committed hashes for the unpersisted client stay
 *   in `nextKeyHashes` forever as orphans, but they commit keys of a lost
 *   random seed -- nothing can reveal them, so they are no re-seizure
 *   credential, and the per-entry staged-hash attribution passes over them.
 *   The seam must be idempotent: the conflict retry and a resumed run invoke
 *   it again. `builtOnHead` is the head of the log snapshot the add entry is
 *   about to be built on -- the SCID from the log's parameters and the latest
 *   entry's `versionId` -- which a resume hands back as this call's
 *   `builtOnHead` marker. The caveat to hold on to: the idempotent COMPLETED
 *   branch (the new client's update key already authorized) returns without
 *   ever entering the seam, so a caller resuming across processes must be
 *   able to treat an already-complete continuation as success on its own
 * @param [options.builtOnHead] {object}   `{ scid, versionId }` -- the resume
 *   marker a pending record recorded, from an earlier run's `onCommitted`.
 *   Supplied, the attempt's first read is refused with
 *   {@link BuiltOnHeadNotReachedError} unless the served log carries that
 *   SCID and an entry with that `versionId`. The chain-head pin cannot stand
 *   in for it: the pin is written non-atomically after the add entry
 *   publishes, and the continuity check accepts a log served at exactly the
 *   pinned length -- so only this marker stops a resume rebuilding the add
 *   entry over a log that never reached the head the pending record was
 *   written against. The marker covers the pre-pivot half of that gap only:
 *   a served log CONTAINING the recorded head but truncated behind the torn
 *   run's own add entry still passes it and is resumed onto, and the menders
 *   for that residual half are the ordinary ones -- this client's own
 *   chain-head pin once the add publish wrote it, and any other enrolled
 *   client's pinned read of the same log. Both members must be non-empty
 *   strings; a malformed marker is refused with a `TypeError` before any
 *   read, since a resume with an uncomparable marker is a resume with no
 *   fork guard
 * @param [options.expectedDid] {string}   the account DID the log must resolve
 *   to, from the credential-authenticated pointer
 * @param [options.pinStore] {ResourceLogPinStore}   this client's chain-head
 *   pins; every read both entries are built on is checked against the pinned
 *   head (a served prefix is refused before the reveal entry lands, not only
 *   by a verify that follows both entries), and the pin advances to each
 *   entry as it publishes
 * @param [options.logId] {string}   the account log's pin slot
 *   (`accountLogPinId({ spaceId })`); required whenever a `pinStore` is
 *   supplied
 * @returns {Promise<{ did: string, webDoc?: object, committed: boolean }>}
 *   the account DID, the final `did.json` projection when the add entry ran
 *   here, and `committed` -- whether THIS call published the pivot entry
 *   (`false` exactly on the idempotent completed branch, where a torn earlier
 *   run had already published it). It is an observability signal, not a
 *   success flag: a returning call means the continuation stands either way,
 *   so a caller clears its pending record on the RETURN, whatever `committed`
 *   says. Its absence from a return value is a build skew, which is why it is
 *   stated rather than inferred
 */
export async function selfEnrollWebvhClient(options: {
  store: UnlockLogStore
  ladderSeed: Uint8Array
  newClientKeys: WebvhEnrollmentKeys
  newClientUpdateSeeds: ClientWebvhUpdateKeys
  onCommitted: (committed: {
    builtOnHead: { scid: string; versionId: string }
  }) => Promise<void>
  builtOnHead?: { scid: string; versionId: string }
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; webDoc?: object; committed: boolean }> {
  // The seam is what persists the new client's seed client-local before the
  // pivot entry publishes it; a call omitting it would silently keep the
  // window in which the log names a client nothing can re-derive. Refused
  // before any read, so nothing is published.
  if (typeof options.onCommitted !== 'function') {
    throw new TypeError(
      'selfEnrollWebvhClient requires onCommitted: the pending client-key ' +
        'record must be persisted before the add entry publishes the client.'
    )
  }
  if (options.builtOnHead !== undefined) {
    assertBuiltOnHeadShape({ builtOnHead: options.builtOnHead })
  }
  // A non-canonical pair could only ever throw at the add-entry build, AFTER
  // the reveal entry published and the seam persisted; refused here, nothing
  // is published or persisted.
  assertCanonicalClientKeys({
    signingKeyMultibase: options.newClientKeys.signingKeyMultibase,
    keyAgreementKeyMultibase: options.newClientKeys.keyAgreementKeyMultibase
  })
  return withLogConflictRetry(() => selfEnrollWebvhClientOnce(options))
}

/**
 * Refuses a malformed resume marker before any read. A marker whose members
 * are missing or empty could not be compared against anything, so accepting
 * one would hand a resume the mint-skip WITHOUT the fork guard the marker
 * exists to apply -- fail-open exactly where the guard matters.
 *
 * @param options {object}
 * @param options.builtOnHead {unknown}   the supplied marker
 * @returns {void}
 */
export function assertBuiltOnHeadShape({
  builtOnHead
}: {
  builtOnHead: unknown
}): void {
  const { scid, versionId } = (builtOnHead ?? {}) as {
    scid?: unknown
    versionId?: unknown
  }
  if (
    builtOnHead === null ||
    typeof builtOnHead !== 'object' ||
    typeof scid !== 'string' ||
    scid === '' ||
    typeof versionId !== 'string' ||
    versionId === ''
  ) {
    throw new TypeError(
      'The self-enrollment resume marker (builtOnHead) must carry a non-empty ' +
        'scid and versionId; a marker that cannot be compared would resume ' +
        'with no fork guard at all.'
    )
  }
}

/**
 * Thrown when a resumed self-enrollment is served an account log that has not
 * reached the head its pending record was written against -- a different SCID,
 * or no entry carrying the recorded `versionId`. Rebuilding the add entry over
 * such a log would fork the account off a head the ceremony already committed
 * to, which the chain-head pin alone does not catch: the pin is written
 * non-atomically after the add entry publishes, so a run torn between the two
 * leaves a pin one entry behind, and the continuity check accepts a served log
 * at exactly the pinned length.
 *
 * **`name` is a stable contract.** It is always the string
 * `'BuiltOnHeadNotReachedError'`, and a consumer should match on that rather
 * than on `instanceof`: a wallet app that links this package (or holds two
 * copies of it through a dependency tree) gets a different class object for
 * the same error, so `instanceof` silently fails there while the name does
 * not.
 */
export class BuiltOnHeadNotReachedError extends Error {
  /**
   * The head the pending record recorded, which the served log did not reach.
   */
  builtOnHead: { scid: string; versionId: string }

  /**
   * @param options {object}
   * @param options.builtOnHead {object}   the recorded `{ scid, versionId }`
   */
  constructor({
    builtOnHead
  }: {
    builtOnHead: { scid: string; versionId: string }
  }) {
    super(
      'did:webvh: the served account log has not reached the head this ' +
        `self-enrollment was built on (scid ${builtOnHead.scid}, version ` +
        `${builtOnHead.versionId}); the resume is refused rather than ` +
        'rebuilt over it.'
    )
    this.name = 'BuiltOnHeadNotReachedError'
    this.builtOnHead = builtOnHead
  }
}

/**
 * One attempt of {@link selfEnrollWebvhClient}, re-invoked by the conflict
 * retry.
 *
 * @param options {object}   see {@link selfEnrollWebvhClient}
 * @returns {Promise<{ did: string, webDoc?: object, committed: boolean }>}
 */
async function selfEnrollWebvhClientOnce({
  store,
  ladderSeed,
  newClientKeys,
  newClientUpdateSeeds,
  onCommitted,
  builtOnHead,
  expectedDid,
  pinStore,
  logId
}: {
  store: UnlockLogStore
  ladderSeed: Uint8Array
  newClientKeys: WebvhEnrollmentKeys
  newClientUpdateSeeds: ClientWebvhUpdateKeys
  onCommitted: (committed: {
    builtOnHead: { scid: string; versionId: string }
  }) => Promise<void>
  builtOnHead?: { scid: string; versionId: string }
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; webDoc?: object; committed: boolean }> {
  // The reveal-and-commit entry, through the shared preamble and postamble.
  // It is skipped when a torn earlier run already published it (the rung
  // revealed AND every needed hash committed).
  const reveal = await ladderSignedAccountEntry({
    store,
    ladderSeed,
    expectedDid,
    pinStore,
    logId,
    skip: read => {
      // The resume marker, checked before anything else -- the completion
      // check included, so a truncated served log is refused rather than read
      // as "not complete yet" and rebuilt over.
      if (builtOnHead) {
        const genesisScid = read.log[0]?.parameters.scid ?? ''
        const reached = read.log.some(
          entry => entry.versionId === builtOnHead.versionId
        )
        if (genesisScid !== builtOnHead.scid || !reached) {
          throw new BuiltOnHeadNotReachedError({ builtOnHead })
        }
      }
      // Already complete (a torn earlier run finished the add entry): the new
      // client's update key is authorized, which only the add entry writes.
      // The seam is deliberately NOT entered on this path -- nothing is about
      // to be published, so there is no pivot to persist ahead of.
      return read.updateKeys.includes(newClientKeys.updateKeyMultibase)
    },
    build: async ({ published: read, rung, state }) => {
      const nextRung = await ladderRung({ ladderSeed, index: rung.index + 1 })
      const newUpdateHash = await deriveNextKeyHash(
        newClientKeys.updateKeyMultibase
      )
      const newStagedHash = await deriveNextKeyHash(
        newClientKeys.stagedUpdateKeyMultibase
      )
      const nextRungHash = await deriveNextKeyHash(nextRung.keyMultibase)
      const committed = [newUpdateHash, newStagedHash, nextRungHash].every(
        hash => read.nextKeyHashes.includes(hash)
      )
      if (state === 'revealed' && committed) {
        return undefined
      }
      // The spent rung's own hash is kept through this entry by the shared
      // carry-over union (so a resumed commit can re-state the revealed key);
      // the add entry drops it, while the next rung's hash stays as the
      // credential's standing commitment. The three land after it, in the
      // append order `decisions/0007` ratifies.
      return { commitHashes: [newUpdateHash, newStagedHash, nextRungHash] }
    }
  })
  if (reveal.skipped) {
    return { did: reveal.published.did, committed: false }
  }
  const { rung, rungHash } = reveal
  // The same account the reveal entry just extended, under the same pin.
  const published = reveal.updated
    ? await readPublishedLogOrThrow({
        idStore: store,
        expectedDid: reveal.published.did,
        pinStore,
        logId,
        missingMessage:
          'did:webvh: did.jsonl is missing; nothing to enroll into.'
      })
    : reveal.published

  // The persist-before-publish seam: the pending client-key record is
  // persisted client-local HERE, on the head the add entry is about to be
  // built on, before that entry -- the ceremony's pivot -- publishes a client
  // whose seed only this caller holds. Reached on both paths into the add
  // entry: the reveal entry just published above, or a torn earlier run's
  // reveal entry standing already.
  await onCommitted({ builtOnHead: servedHead(published.log) })

  // The add entry: the new client's verification methods and update key in;
  // the spent rung's key and hash out. The credential's keyAgreement entry
  // and the next rung's committed hash stand untouched. Signed by the new
  // client's update key, whose hash the commit entry just committed.
  const { did, doc } = published
  const vmId = (publicKeyMultibase: string) => `${did}#${publicKeyMultibase}`
  // Enrollment does not touch any ladder VM. A ladder VM's life is keyed to
  // its credential: the standing establishment installs it, the credential's
  // retirement strikes it, and every standing credential's VM stays in the
  // document alongside the enrolled clients this entry publishes. The only
  // ladder state this entry changes is the spent rung's, below.
  const addedMethods: VerificationMethod[] = markedVerificationMethodPair({
    controller: did,
    signingKeyMultibase: newClientKeys.signingKeyMultibase,
    keyAgreementKeyMultibase: newClientKeys.keyAgreementKeyMultibase
  })
  const existingMethods = (doc.verificationMethod ?? []) as VerificationMethod[]
  const verificationMethods = [
    ...existingMethods.filter(
      method => !addedMethods.some(added => added.id === method.id)
    ),
    ...addedMethods
  ]
  const withReference = (
    relation: Array<string | { id?: string }> | undefined,
    id: string
  ) => [...new Set([...relationIds(relation), id])]
  const signingVmId = vmId(newClientKeys.signingKeyMultibase)

  const signer = await updateKeySigner({
    seed: newClientUpdateSeeds.updateSeed
  })
  const updated = await updateDID({
    log: published.log,
    signer,
    alsoKnownAsWeb: true,
    updateKeys: [
      ...new Set([
        ...published.updateKeys.filter(key => key !== rung.keyMultibase),
        newClientKeys.updateKeyMultibase
      ])
    ],
    nextKeyHashes: published.nextKeyHashes.filter(hash => hash !== rungHash),
    verificationMethods,
    authentication: withReference(doc.authentication, signingVmId),
    assertionMethod: withReference(doc.assertionMethod, signingVmId),
    keyAgreement: withReference(
      doc.keyAgreement,
      vmId(newClientKeys.keyAgreementKeyMultibase)
    ),
    capabilityInvocation: withReference(doc.capabilityInvocation, signingVmId),
    capabilityDelegation: withReference(doc.capabilityDelegation, signingVmId)
  })
  // Conditional on the read this entry was built on: the re-read above when
  // the commit entry ran here, the first read when it was skipped.
  await publishEntryPinned({
    store,
    log: updated.log,
    ifMatch: published.etag,
    pinStore,
    logId
  })
  return { did: updated.did, webDoc: updated.webDoc, committed: true }
}

/**
 * Thrown when the client being forgotten is the account's LAST enrolled
 * client. Removing it through this entry would leave the document
 * with no client and no ladder verification method -- an account nothing can
 * invoke for -- so that case is its own ceremony (the two-entry
 * ladder-VM-install shape), and this primitive refuses rather than
 * transitioning the account by accident.
 *
 * **`name` is a stable contract.** It is always the string
 * `'LastEnrolledClientForgetError'`, and a consumer should match on that
 * rather than on `instanceof`: a wallet app that links this package (or holds
 * two copies of it through a dependency tree) gets a different class object
 * for the same error, so `instanceof` silently fails there while the name
 * does not.
 */
export class LastEnrolledClientForgetError extends Error {
  constructor() {
    super(
      'did:webvh: the client being forgotten is the last enrolled client; ' +
        'forgetting it takes the ladder-anchored transition ceremony, not ' +
        'the plain removal entry.'
    )
    this.name = 'LastEnrolledClientForgetError'
  }
}

/**
 * FORGET (run by the forgetting client itself, through the standing
 * credential's bridge): removes THIS browser's enrolled client from the
 * published document in ONE atomic ladder-signed entry -- self-enrollment in
 * reverse, collapsed to a single entry because a removal reveals no new key.
 * The signer is the credential's current ladder rung, recovered from the log
 * itself ({@link attributeLadderRung}): its hash stands committed by the
 * credential's inventory (or the rung is already revealed), which is exactly
 * what lets it reveal itself in the entry it signs under prerotation. The
 * entry's members are the revocation removal's, verbatim
 * (`clientRemovalTarget` / `clientRemovalFields`, shared with
 * `revokeWebvhClient` so the two removal shapes cannot drift): the client's
 * verification methods out of the document and all five relations, its update
 * key out of `updateKeys`, and its carry-over and staged hashes out of
 * `nextKeyHashes` -- plus the acting rung into `updateKeys` with its own hash
 * kept committed (the carry-over convention).
 *
 * Atomicity is the point of the one-entry shape: no torn state exists where
 * the rung is revealed and the client still stands. The honest residue is the
 * acting rung itself -- no entry can remove its own signing key, so the rung
 * stands REVEALED in `updateKeys` afterwards (the same standing state the
 * ladder-anchored accounts live in). That is credential-held authority, not
 * the forgotten client's: only the ladder seed derives it, the credential's
 * next self-enrollment consumes and retires it, and retiring the credential
 * itself strikes it (`attributeLadderInventory`).
 *
 * Forgetting the LAST enrolled client is refused
 * ({@link LastEnrolledClientForgetError}): that transition -- to the
 * client-less, ladder-anchored state -- is its own two-entry ceremony.
 *
 * Idempotent: a client with no remaining presence is a no-op that returns the
 * published state unchanged, so a naive re-run after a torn ceremony
 * converges. The entry publishes conditionally on the log this call read; a
 * lost race re-runs, re-attributes, and rebases on the winner's head.
 *
 * @param options {object}
 * @param options.store {UnlockLogStore}   the credential's delegated
 *   `did.jsonl` bridge store
 * @param [options.projectionStore] {object}   an `id`-collection store the
 *   FORGETTING client can still write through (its own root-invoking store):
 *   the post-removal `did:web` projection is PUT through it immediately
 *   before the removal entry publishes, and only when this run publishes that
 *   entry. See {@link clientForgetEntryOnce} for the ordering rationale.
 *   Omitted, `did.json` keeps naming the forgotten client until some later
 *   writer runs `ensureDidWebProjection`
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed
 * @param options.forgottenClient {RevokedClientKeys}   this client's public
 *   halves; an `updateKeyMultibase` the log does not authorize (stale, or the
 *   staged key) is re-derived from the log
 * @param [options.knownLatentHashes] {string[]}   standing latent commitments
 *   the caller vouches for (the recovery registry's update-key hashes),
 *   excluded from the staged-hash attribution
 * @param [options.expectedDid] {string}   the account DID the log must resolve
 *   to, from the caller's stored account pointer
 * @param [options.pinStore] {ResourceLogPinStore}   the caller's chain-head
 *   pins: the read inside each attempt is checked against the pinned head
 *   (a served truncated prefix is refused as a `rollback` before anything is
 *   built on it), and the pin advances to the head this entry publishes
 * @param [options.logId] {string}   the account log's pin slot
 *   (`accountLogPinId({ spaceId })`); required whenever a `pinStore` is
 *   supplied
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}   the account
 *   DID and the document and log as the removal entry leaves them (unchanged
 *   on the idempotent no-op path)
 */
export async function forgetWebvhClient(options: {
  store: UnlockLogStore
  projectionStore?: Pick<WebvhIdStore, 'getIdResourceRaw' | 'putIdResource'>
  ladderSeed: Uint8Array
  forgottenClient: RevokedClientKeys
  knownLatentHashes?: string[]
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  return withLogConflictRetry(() =>
    clientForgetEntryOnce({ ...options, assertRemovable: assertNotLastClient })
  )
}

/**
 * The plain forget's removability invariant: `capabilityInvocation` lists
 * exactly the enrolled clients' signing keys (a recovery code's key is
 * `keyAgreement`-only and the KMS convenience key `authentication`-only), so
 * the forgotten client standing alone there means removing it strands the
 * account. The transition ceremony supplies its own invariant instead
 * (`forgetLast.ts`), which is why this one is injected rather than selected
 * by a flag inside the shared entry builder.
 *
 * @param options {object}
 * @param options.published {PublishedWebvhLog}
 * @param options.target {ClientRemovalTarget}
 * @returns {void}
 */
function assertNotLastClient({
  published,
  target
}: {
  published: PublishedWebvhLog
  target: ClientRemovalTarget
}): void {
  const invocationIds = relationIds(published.doc.capabilityInvocation)
  if (
    invocationIds.includes(target.signingVmId) &&
    invocationIds.every(id => id === target.signingVmId)
  ) {
    throw new LastEnrolledClientForgetError()
  }
}

/**
 * One attempt of {@link forgetWebvhClient} or `forgetLastWebvhClient`
 * (`forgetLast.ts`), re-invoked by their conflict retries. The two share the
 * whole removal entry and differ only in what makes the removal admissible,
 * which each supplies as `assertRemovable` -- the plain forget refuses the
 * last enrolled client, the transition removal requires the ladder VM already
 * installed. The invariant travels with the ceremony that owns it rather than
 * living here as a flag.
 *
 * THE PROJECTION IS PUBLISHED BEFORE THE ENTRY, and the order is forced: the
 * removal entry is ladder-signed and publishes `did.jsonl` alone (the bridge
 * delegation covers nothing else), while the forgotten client's authority
 * dies at that entry under the current-key-set rule. So the post-removal
 * `did:web` projection has to be written while that client can still write
 * it. A run torn between the projection PUT and the entry leaves `did.json`
 * omitting a client the log still lists, which is fail-closed for a `did:web`
 * verifier and is re-PUT by the re-run; the reverse order would leave the
 * revoked client standing in `did.json` with nothing left able to remove it.
 * The idempotent already-forgotten path writes no projection at all: the
 * removal entry landed on an earlier run, so this client's authority is
 * already gone and its store can only be refused. A projection that path
 * leaves stale is mended by the next transient visit's
 * `ensureDidWebProjection`, which invokes under its generation delegation.
 *
 * @param options {object}   see {@link forgetWebvhClient}, plus:
 * @param options.assertRemovable {function}
 *   `({ published, target }) => void` -- run on the read, after the
 *   idempotent already-forgotten check and before anything is attributed or
 *   built; it throws to refuse the removal
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}
 */
export async function clientForgetEntryOnce({
  store,
  projectionStore,
  ladderSeed,
  forgottenClient,
  knownLatentHashes = [],
  expectedDid,
  pinStore,
  logId,
  assertRemovable
}: {
  store: UnlockLogStore
  projectionStore?: Pick<WebvhIdStore, 'getIdResourceRaw' | 'putIdResource'>
  ladderSeed: Uint8Array
  forgottenClient: RevokedClientKeys
  knownLatentHashes?: string[]
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
  assertRemovable: (options: {
    published: PublishedWebvhLog
    target: ClientRemovalTarget
  }) => void | Promise<void>
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  // Resolved by the skip hook on the read the entry is built on, and used by
  // the build below -- the same snapshot, never a second read.
  let target: ClientRemovalTarget | undefined
  const entry = await ladderSignedAccountEntry({
    store,
    ladderSeed,
    expectedDid,
    pinStore,
    logId,
    skip: async published => {
      target = await clientRemovalTarget({
        published,
        client: forgottenClient
      })
      if (!target.present) {
        // Already forgotten (a torn earlier run finished the entry). No
        // projection is written on this path: this client's verification
        // methods left the document with that entry, so its store is
        // authorized for nothing. The next transient visit's
        // `ensureDidWebProjection` is the mender.
        return true
      }
      await assertRemovable({ published, target })
      return false
    },
    build: async ({ published, rung }) => {
      // The ladder vouches for its own commitments: a self-enrolled client's
      // staged hash was committed in the same reveal entry as the next rung's
      // hash, so without these the staged-hash attribution cannot tell the
      // two apart. Every hash a reveal entry can have committed is for a rung
      // at or one past the current index.
      const ladderHashes: string[] = []
      for (let index = 0; index <= rung.index + 1; index++) {
        const laddered = await ladderRung({ ladderSeed, index })
        ladderHashes.push(await deriveNextKeyHash(laddered.keyMultibase))
      }
      // The removal's own filtered sets; the acting rung's key and hash are
      // unioned back in by the shared carry-over conventions.
      return clientRemovalFields({
        published,
        target: target as ClientRemovalTarget,
        knownLatentHashes: [...knownLatentHashes, ...ladderHashes]
      })
    },
    // The post-removal projection, published while the client being removed
    // can still write it (see the header). `webDoc` is the `alsoKnownAsWeb`
    // projection `ladderSignedAccountEntry` always asks `updateDID` for.
    ...(projectionStore
      ? {
          beforePublish: async ({ updated }: { updated: UpdateDIDResult }) => {
            if (!updated.webDoc) {
              // `publishUpdatedLog` states the same invariant: every entry is
              // built with `alsoKnownAsWeb`, so a missing projection is a
              // defect. Refusing here is what keeps the removal entry from
              // publishing with `did.json` left naming the removed client,
              // which on a client-less account nothing could mend.
              throw new Error(
                'did:webvh: updateDID returned no webDoc despite the ' +
                  'did:web alsoKnownAs.'
              )
            }
            await putDidWebProjection({
              store: projectionStore,
              webDoc: updated.webDoc
            })
          }
        }
      : {})
  })
  const settled = entry.updated ?? entry.published
  return { did: settled.did, doc: settled.doc, log: settled.log }
}

/**
 * THE LADDER-VM INSTALL ENTRY (the two-entry transition ceremony's first
 * entry): publishes the credential's ladder VM -- the stable sibling, under
 * `assertionMethod` and `capabilityDelegation` only -- leaving every enrolled
 * client's inventory untouched. A ladder VM and enrolled clients are
 * co-resident by design: the VM's life is keyed to its credential, so the
 * document carries one per standing credential for as long as that credential
 * stands. The entry is
 * ladder-signed by the attributed rung, which reveals itself into
 * `updateKeys` with its own hash kept committed (the carry-over convention),
 * exactly the removal entry's rung math -- so a torn ceremony's re-run
 * re-attributes the now-revealed rung and carries on.
 *
 * This entry is what makes the transition's document version INVENTORY-CHANGING
 * under the ceremony-tail license (the ladder-VM set gains a member), so the
 * ceremony's ONE ladder-signed roster append anchors here -- and it is what
 * lets the delegation revocations that follow verify their ladder-signed
 * chains against the currently resolved document while the still-standing
 * client signs the invocations.
 *
 * Idempotent: a document already carrying this credential's ladder VM (by
 * the relation-asymmetry recognition) returns unchanged with
 * `installed: false`. The entry publishes conditionally on the log this call
 * read; a lost race re-runs, re-attributes, and rebases on the winner's
 * head.
 *
 * @param options {object}
 * @param options.store {UnlockLogStore}   the credential's delegated
 *   `did.jsonl` bridge store
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed
 * @param [options.expectedDid] {string}   the account DID the log must resolve
 *   to, from the caller's stored account pointer
 * @param [options.pinStore] {ResourceLogPinStore}   the caller's chain-head
 *   pins: the read inside each attempt is checked against the pinned head,
 *   and the pin advances to the head this entry publishes
 * @param [options.logId] {string}   the account log's pin slot
 *   (`accountLogPinId({ spaceId })`); required whenever a `pinStore` is
 *   supplied
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog, installed: boolean }>}
 *   the account DID and the document and log as the install entry leaves them
 *   (unchanged on the idempotent no-op path); `installed` says whether the
 *   entry ran on this call
 */
export async function installLadderVmWebvh(options: {
  store: UnlockLogStore
  ladderSeed: Uint8Array
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog; installed: boolean }> {
  return withLogConflictRetry(() => installLadderVmWebvhOnce(options))
}

/**
 * One attempt of {@link installLadderVmWebvh}, re-invoked by the conflict
 * retry.
 *
 * @param options {object}   see {@link installLadderVmWebvh}
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog, installed: boolean }>}
 */
async function installLadderVmWebvhOnce(options: {
  store: UnlockLogStore
  ladderSeed: Uint8Array
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog; installed: boolean }> {
  const { changed, ...settled } = await setLadderVmPresenceOnce({
    ...options,
    present: true
  })
  return { ...settled, installed: changed }
}

/**
 * ONE LADDER-VM PRESENCE ENTRY, in either direction: `present: true`
 * publishes this credential's ladder VM, `present: false` strikes it, and the
 * entries are otherwise the same edit read backwards -- the VM in or out of
 * `verificationMethod`, `assertionMethod`, and `capabilityDelegation`, with
 * `authentication`, `keyAgreement`, and `capabilityInvocation` re-stated
 * untouched. That relation asymmetry (`assertionMethod` and
 * `capabilityDelegation` only, never `authentication` or
 * `capabilityInvocation`) is what the recognition reads and what keeps a
 * ladder VM out of every client listing, so the two directions must agree on
 * it exactly; stating it once is the point of the merge.
 *
 * The id derives from the ladder seed, so the entry reaches ONE credential's
 * VM: another standing credential's ladder VM, and every enrolled client's
 * inventory, stand untouched. Idempotent in both directions -- a document
 * already in the asked-for state is a no-op returning `changed: false`,
 * detected BEFORE the rung attribution so a re-run over a retired credential
 * returns unchanged rather than failing closed.
 *
 * @param options {object}   see {@link installLadderVmWebvh}, plus:
 * @param options.present {boolean}   the state the entry leaves the ladder VM
 *   in
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog, changed: boolean }>}
 */
async function setLadderVmPresenceOnce({
  store,
  ladderSeed,
  expectedDid,
  pinStore,
  logId,
  present
}: {
  store: UnlockLogStore
  ladderSeed: Uint8Array
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
  present: boolean
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog; changed: boolean }> {
  const ladderVmKey = await ladderVmKeyMultibase({ ladderSeed })
  const entry = await ladderSignedAccountEntry({
    store,
    ladderSeed,
    expectedDid,
    pinStore,
    logId,
    // Already in the asked-for state: a torn earlier run published the entry,
    // the account is mid-transition, or the credential never bound a VM here.
    skip: published =>
      ladderVmIds({ doc: published.doc }).includes(
        `${published.did}#${ladderVmKey}`
      ) === present,
    build: ({ published }) => {
      const { did, doc } = published
      const ladderVmId = `${did}#${ladderVmKey}`
      const withoutVm = (
        relation: Array<string | { id?: string }> | undefined
      ) => relationIds(relation).filter(id => id !== ladderVmId)
      const withVm = (
        relation: Array<string | { id?: string }> | undefined
      ) => [...new Set([...relationIds(relation), ladderVmId])]
      const inRelation = present ? withVm : withoutVm
      const otherMethods = (
        (doc.verificationMethod ?? []) as VerificationMethod[]
      ).filter(method => method.id !== ladderVmId)
      return {
        verificationMethods: present
          ? [
              ...otherMethods,
              ladderVerificationMethod({
                controller: did,
                publicKeyMultibase: ladderVmKey
              })
            ]
          : otherMethods,
        // The ladder VM's relation asymmetry: `assertionMethod` and
        // `capabilityDelegation` only -- no `authentication`, no
        // `capabilityInvocation` -- which is also what keeps it out of every
        // client listing.
        authentication: relationIds(doc.authentication),
        assertionMethod: inRelation(doc.assertionMethod),
        keyAgreement: relationIds(doc.keyAgreement),
        capabilityInvocation: relationIds(doc.capabilityInvocation),
        capabilityDelegation: inRelation(doc.capabilityDelegation)
      }
    }
  })
  const settled = entry.updated ?? entry.published
  return {
    did: settled.did,
    doc: settled.doc,
    log: settled.log,
    changed: entry.updated !== undefined
  }
}

/**
 * THE LADDER-VM STRIKE ENTRY: takes THIS credential's ladder VM out of the
 * document -- from `verificationMethod`, `assertionMethod`, and
 * `capabilityDelegation` -- and touches nothing else. The id comes from the
 * ladder seed, so the strike reaches one credential's VM: another standing
 * credential's ladder VM, and every enrolled client's inventory, stand
 * untouched. The account-wide filter the transient recovery's add-and-retire
 * entry runs is a different rule and stays there.
 *
 * Paired with {@link installLadderVmWebvh} it is the last-client
 * transition's opening move: the strike, then the reinstall of the identical
 * VM. That pair is what supplies the transition with an
 * inventory-changing document version for its one ladder-signed roster
 * append, on an account whose VM already stands (the credential-keyed
 * lifecycle installs it at bind time). The republished node is the same
 * `<accountDid>#<multibase>`, and a zcap delegation proof carries no version
 * anchor, so any unexpired ladder-signed delegation resumes verifying.
 *
 * Ladder-signed by the attributed rung, which reveals itself into
 * `updateKeys` with its own hash kept committed (the carry-over convention)
 * -- the install and removal entries' rung math exactly.
 *
 * Idempotent: a document carrying no ladder VM of this credential's returns
 * unchanged with `struck: false`. The entry publishes conditionally on the
 * log this call read; a lost race re-runs, re-attributes, and rebases on the
 * winner's head.
 *
 * @param options {object}
 * @param options.store {UnlockLogStore}   the credential's delegated
 *   `did.jsonl` bridge store
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed
 * @param [options.expectedDid] {string}   the account DID the log must resolve
 *   to, from the caller's stored account pointer
 * @param [options.pinStore] {ResourceLogPinStore}   the caller's chain-head
 *   pins: the read inside each attempt is checked against the pinned head,
 *   and the pin advances to the head this entry publishes
 * @param [options.logId] {string}   the account log's pin slot
 *   (`accountLogPinId({ spaceId })`); required whenever a `pinStore` is
 *   supplied
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog, struck: boolean }>}
 *   the account DID and the document and log as the strike entry leaves them
 *   (unchanged on the idempotent no-op path); `struck` says whether the entry
 *   ran on this call
 */
export async function strikeLadderVmWebvh(options: {
  store: UnlockLogStore
  ladderSeed: Uint8Array
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog; struck: boolean }> {
  return withLogConflictRetry(() => strikeLadderVmWebvhOnce(options))
}

/**
 * One attempt of {@link strikeLadderVmWebvh}, re-invoked by the conflict
 * retry.
 *
 * @param options {object}   see {@link strikeLadderVmWebvh}
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog, struck: boolean }>}
 */
async function strikeLadderVmWebvhOnce(options: {
  store: UnlockLogStore
  ladderSeed: Uint8Array
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog; struck: boolean }> {
  const { changed, ...settled } = await setLadderVmPresenceOnce({
    ...options,
    present: false
  })
  return { ...settled, struck: changed }
}

/**
 * THE STANDALONE REVEAL-AND-COMMIT ENTRY: reveals this credential's currently
 * committed ladder rung into `updateKeys`, keeping its own hash committed and
 * committing the next rung's (the carry-over convention). It is the same
 * entry {@link selfEnrollWebvhClient} writes first, minus the enrolling
 * client's hashes, and it exists so a credential-only visit can sign an
 * account-log entry of its own -- the `#DelegatedClients` pointer move -- on
 * an account whose self-enrollment already spent the previously revealed
 * rung.
 *
 * A rung already revealed (a torn earlier run, or a racing ceremony that got
 * there first) is a no-op: nothing is published and `revealed: false` comes
 * back. A ladder the log commits no rung of at all, and an ambiguous
 * attribution, fail closed with `LadderAttributionError`.
 *
 * This entry retires nothing. The revealed rung stands in `updateKeys` until
 * a later self-enrollment's add entry spends it or the credential retires;
 * the caller's comment states the consequence at its own site.
 *
 * No conflict retry of its own: a caller pairing this entry with a second one
 * must run both inside ONE {@link withLogConflictRetry}, so a race lost
 * between them re-runs the attribution rather than signing with a rung the
 * winner consumed.
 *
 * @param options {object}
 * @param options.store {UnlockLogStore}   the credential's delegated
 *   `did.jsonl` bridge store
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed
 * @param [options.expectedDid] {string}   the account DID the log must
 *   resolve to, from the caller's stored account pointer
 * @param [options.pinStore] {ResourceLogPinStore}   the caller's chain-head
 *   pins: the read is checked against the pinned head, and the pin advances
 *   to the head this entry publishes
 * @param [options.logId] {string}   the account log's pin slot
 *   (`accountLogPinId({ spaceId })`); required whenever a `pinStore` is
 *   supplied
 * @returns {Promise<{ revealed: boolean }>}   whether this call published the
 *   entry
 */
export async function revealLadderRungWebvh({
  store,
  ladderSeed,
  expectedDid,
  pinStore,
  logId
}: {
  store: UnlockLogStore
  ladderSeed: Uint8Array
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ revealed: boolean }> {
  const entry = await ladderSignedAccountEntry({
    store,
    ladderSeed,
    expectedDid,
    pinStore,
    logId,
    build: async ({ rung, state }) => {
      // A rung already revealed (a torn earlier run, or a racing ceremony
      // that got there first) leaves nothing to publish. The decline sits
      // after the attribution because the attribution is what answers it.
      if (state === 'revealed') {
        return undefined
      }
      // The entry commits the next rung only; the acting rung's own key and
      // carry-over hash come from the shared reveal and carry-over unions.
      const nextRung = await ladderRung({ ladderSeed, index: rung.index + 1 })
      return {
        commitHashes: [await deriveNextKeyHash(nextRung.keyMultibase)]
      }
    }
  })
  return { revealed: entry.updated !== undefined }
}
