/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * ONE ACCOUNT-LOG ENTRY, WHOEVER SIGNS IT: the seam every ceremony that
 * extends `did.jsonl` writes through, so a ceremony body describes its
 * document delta once and the signing arm is a parameter.
 *
 * Two arms, discriminated by {@link AccountLogSigner}, are what a ceremony
 * body accepts:
 *
 * - **client** -- an enrolled client's did:webvh update keys. The active key
 *   is derived from the seed, the published log must authorize it, and the
 *   carry-over commitments must hold.
 * - **ladder** -- a standing credential's ladder seed, signing through the
 *   record's bridge delegation. The rung is attributed from the published log
 *   ({@link attributeLadderRung}, fail-closed), the acting rung reveals itself
 *   in the entry it signs, and the rung's own hash is kept committed beside
 *   the build's own commit hashes in `decisions/0007` order.
 *
 * Neither arm writes the `did:web` projection through the log store. The
 * entry publishes `did.jsonl` through `idStore` on every arm, and `did.json`
 * is written only through a `projectionStore` the caller hands in, which is
 * how a bridge-delegated store (a PUT on `did.jsonl` alone) and a
 * controller-invoking one satisfy the same seam. The projection has two
 * timings and one failure rule each (`projectionTiming`): AFTER the entry,
 * the default, it is a derived cache of the entry that just landed, and a
 * failed PUT throws past the pivot so a re-run republishes it from the
 * idempotent path ({@link concludeUnchangedAccountEntry}); BEFORE the entry,
 * for a ceremony whose entry ends the authority that writes it, a failed PUT
 * warns and the entry publishes anyway, since a projection the next visit's
 * ensure mends is a smaller residue than a struck key the log still lists.
 * Which timing an entry takes is the seam's own decision, from the signer arm
 * and the caller's `removesInventory`: a ladder-signed removal writes before,
 * every other entry after. The idempotent path (`build`'s `concludeUnchanged`)
 * republishes only under the AFTER timing, since under BEFORE the store's
 * authority may already have ended at the entry an earlier run landed.
 *
 * A third arm is the seam's alone ({@link AccountEntrySigner}):
 *
 * - **committed** -- one bare update-key seed whose key stands committed in
 *   `nextKeyHashes` (or already revealed in `updateKeys`), revealing itself:
 *   the prerotation reveal with no attribution in front of it. The recovery
 *   continuation's two entries are this arm -- the spent code's rung 0 signs
 *   the reveal-and-commit entry, and the successor key the reveal committed
 *   signs the add-and-retire entry. The reveal union and the carry-over
 *   union are the ladder arm's. No ceremony body takes this arm as a
 *   parameter, since a committed key carries no ceremony authority of its
 *   own beyond the continuation that reveals it.
 *
 * Four of those steps are load-bearing conventions rather than plumbing:
 * omitting the reveal union publishes a log whose next entry cannot resolve,
 * omitting the carry-over hash switches prerotation off, omitting the
 * carry-over precondition publishes an entry no resolver accepts, and omitting
 * the pin advance leaves a pin behind an entry this client itself published.
 *
 * One property every arm rests on: an entry keeps its own signer. The ladder
 * and committed arms union the acting key back into `updateKeys` after the
 * build runs, so no entry can remove the key that signed it. A ceremony that must retire a
 * rung therefore needs a second entry, signed by the successor (the
 * two-entry passphrase change, and the recovery spend's reveal-then-retire
 * pair). The same rule is why a rung is not consumed per ceremony: rung
 * attribution prefers a revealed rung over a committed one, so a credential
 * signs every single-entry ceremony with the same rung until an entry
 * retires it.
 *
 * No conflict retry of its own: a lost compare-and-swap surfaces as a
 * `WebvhLogConflictError` for the caller's `withLogConflictRetry` to re-run,
 * which is what re-attributes the rung and climbs to the winner's committed
 * one (the retry-up-the-ladder resolution).
 */
import { updateDID } from '@interop/did-method-webvh'
import type {
  DIDDoc,
  DIDLog,
  UpdateDIDInterface,
  UpdateDIDResult
} from '@interop/did-method-webvh'
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import { log } from '../log.js'
import {
  assertCarryOverCommitments,
  assertPublishedLogDid,
  concludeWithPublishedLog,
  putLogResource,
  readPublishedLogOrThrow,
  updateKeyMultibase,
  updateKeySigner
} from './didWebvh.js'
import type {
  ClientWebvhUpdateKeys,
  PublishedWebvhLog,
  WebvhIdStore
} from './didWebvh.js'
import { putDidWebProjection } from './didWebProjection.js'
import type { DidWebProjectionStore } from './didWebProjection.js'
import {
  assertBuiltOnHeadReached,
  assertBuiltOnHeadShape
} from './builtOnHead.js'
import type { BuiltOnHead } from './builtOnHead.js'
import type { LadderRung } from './ladderDerivation.js'
import { attributeLadderRung } from './ladder.js'
import type { LadderRungState } from './ladder.js'

/**
 * Who signs an account-log entry. The enrolled arm carries an enrolled client's
 * own did:webvh update-key seeds; the ladder arm carries a standing unlock
 * credential's ladder seed, whose rungs sign through the credential's bridge
 * delegation. A ceremony body accepts no other arm and no absence: every one
 * that extends the account log states which of the two it acts as. The
 * seam's own committed-key arm is {@link AccountEntrySigner}'s.
 */
export type AccountLogSigner =
  | { kind: 'enrolled'; updateKeys: ClientWebvhUpdateKeys }
  | { kind: 'ladder'; ladderSeed: Uint8Array }

/**
 * Who may sign through {@link signAccountEntry} itself: the two ceremony arms
 * plus the committed-key arm, a bare update-key seed whose key the published
 * log commits or already authorizes. Kept apart from {@link AccountLogSigner}
 * so no ceremony body widens what it accepts by taking the seam's type.
 */
export type AccountEntrySigner =
  AccountLogSigner | { kind: 'committed'; updateSeed: Uint8Array }

/**
 * The store an account-log entry is read and published through: the public
 * log read and the `did.jsonl` PUT. A subset of {@link WebvhIdStore}, so a
 * controller-invoking client's store, a credential's bridge-delegated store
 * (`delegatedWebvhLogStore`), and an app's remote-store class all satisfy
 * it. It says nothing about the `did:web` projection: a write there takes a
 * {@link DidWebProjectionStore} the caller hands in separately, and no arm of
 * {@link signAccountEntry} asks this store for one.
 */
export type AccountLogStore = Pick<
  WebvhIdStore,
  'getIdResourceRaw' | 'putIdResource' | 'pin'
>

/**
 * What a build hands back: the `updateDID` parameters the entry sets, minus
 * the three {@link signAccountEntry} owns (`log`, `signer`,
 * `alsoKnownAsWeb`).
 *
 * `updateKeys` and `nextKeyHashes` default to the published sets; a build
 * whose entry REMOVES members (a removal entry) states the filtered set
 * instead. On the ladder arm the acting rung's key is unioned into the former
 * and the rung's own hash into the latter -- the self-reveal and carry-over
 * conventions, applied in one place rather than remembered per site.
 */
export interface AccountEntryFields extends Omit<
  UpdateDIDInterface,
  'log' | 'signer' | 'alsoKnownAsWeb'
> {
  /**
   * The hashes this entry newly commits, appended AFTER the acting rung's
   * carry-over hash. The position is wire behavior rather than a detail:
   * `decisions/0007-ladder-reveal-hash-order.md` ratifies the append order a
   * reveal-and-commit entry produces, and a seedless ladder walk reads that
   * order both forwards and backwards.
   */
  commitHashes?: string[]
}

/**
 * When the `did:web` projection is written relative to the entry's own
 * publish, and the failure rule that comes with each timing: `'after'`
 * throws (the entry stands, and a re-run republishes through the idempotent
 * path), `'before'` warns and continues (the entry still publishes).
 */
type ProjectionTiming = 'before' | 'after'

/**
 * The timing rule, applied in this one place. `'before'` only for a
 * ladder-signed entry that removes inventory, since that entry may strike the
 * ladder VM or the client the projection store invokes as. Every other entry
 * takes `'after'`, the enrolled arm's included: a client cannot remove
 * itself, so its authority survives what it signs.
 *
 * @param options {object}
 * @param options.signer {AccountEntrySigner}   the arm the ceremony acts as
 * @param options.removesInventory {boolean}   whether the entry strikes a
 *   member of the document's inventory
 * @returns {ProjectionTiming}
 */
function projectionTimingOf({
  signer,
  removesInventory
}: {
  signer: AccountEntrySigner
  removesInventory: boolean
}): ProjectionTiming {
  return removesInventory && signer.kind === 'ladder' ? 'before' : 'after'
}

/**
 * What {@link signAccountEntry} reports. `skipped` says the pre-signature
 * hook declined, so nothing was attributed and nothing was published;
 * `updated` is absent on that path AND where `build` itself declined, which
 * is the one test an idempotent caller needs ("did this call publish an
 * entry"). `rung`, `rungHash` and `state` are the ladder arm's, absent on the
 * enrolled arm.
 */
export type AccountEntryOutcome =
  | {
      skipped: true
      published: PublishedWebvhLog
      rung?: undefined
      rungHash?: undefined
      state?: undefined
      updated?: undefined
      etag?: undefined
    }
  | {
      skipped: false
      published: PublishedWebvhLog
      rung?: LadderRung
      rungHash?: string
      state?: LadderRungState
      updated?: UpdateDIDResult
      etag?: string
    }

/**
 * The head an entry leaves standing, assembled from what the entry's own
 * `updateDID` already resolved plus the publish's validator when an entry was
 * published, and the read the entry was built on verbatim when the build
 * declined (the head is then provably unchanged by this call). No second read
 * and no second resolve: the update-key parameters are the ones the entry
 * itself stated, so a caller building its next entry on this head signs
 * against exactly what it published.
 *
 * @param options {object}
 * @param options.outcome {AccountEntryOutcome}
 * @returns {PublishedWebvhLog}
 */
export function accountEntryHead({
  outcome
}: {
  outcome: AccountEntryOutcome
}): PublishedWebvhLog {
  const { updated } = outcome
  if (!updated) {
    return outcome.published
  }
  return {
    log: updated.log,
    did: updated.did,
    // Detached from the entry's own `state`, as every other producer of this
    // type is, so a consumer editing the document cannot edit the log.
    doc: structuredClone(updated.doc),
    updateKeys: updated.meta.updateKeys,
    nextKeyHashes: updated.meta.nextKeyHashes,
    meta: updated.meta,
    ...(outcome.etag !== undefined ? { etag: outcome.etag } : {})
  }
}

/**
 * Signs and publishes one account-log entry, preamble and postamble
 * included -- the pinned read, the signer arm's own preconditions, the
 * `updateDID` call, the conditional publish, and the pin advance. See the
 * module doc for what each arm owns.
 *
 * The caller supplies only what differs: an optional pre-signature `skip`
 * (the idempotent no-op every ceremony detects from stored state, checked
 * BEFORE any ladder attribution so a retired or never-bound credential's
 * re-run returns unchanged instead of failing closed on the attribution),
 * and a `build` that shapes the entry from the read and, on the ladder arm,
 * the attributed rung. A `build` returning `undefined` declines
 * post-attribution -- the same no-op, for a ceremony whose completion test
 * needs the rung.
 *
 * @param options {object}
 * @param options.idStore {AccountLogStore}   the log read and the
 *   `did.jsonl` PUT
 * @param options.signer {AccountEntrySigner}   who signs this entry
 * @param options.build {function}
 *   `({ published, rung, state, concludeUnchanged }) => AccountEntryFields |
 *   undefined` -- the entry's own members, or `undefined` to decline.
 *   `concludeUnchanged()` is the idempotent path's conclusion, bound to this
 *   call's projection store and timing: it republishes the projection from
 *   the read under the `'after'` timing alone (healing a lag a torn earlier
 *   run's thrown post-entry PUT left behind) and writes nothing under
 *   `'before'`, since the entry an earlier run landed may have ended the
 *   store's authority. A ceremony whose build finds its entry already landed
 *   awaits it and declines
 * @param [options.skip] {function}   `(published) => boolean` -- run on the
 *   read, before any attribution; `true` returns `skipped` with nothing
 *   published
 * @param [options.published] {PublishedWebvhLog}   a read the caller already
 *   made (checked against `expectedDid`), in place of this call's own read.
 *   The caller owns the staleness: a lost compare-and-swap surfaces as a
 *   conflict for its retry to re-run
 * @param [options.expectedDid] {string}   the account DID the log must
 *   resolve to, from the caller's stored account pointer. The store's own
 *   chain-head pin checks the read and advances to the head this entry
 *   publishes
 * @param [options.builtOnHead] {BuiltOnHead}   a resumed ceremony's marker,
 *   the head an earlier attempt's persist-before-publish seam handed its
 *   caller. Its shape is refused with a `TypeError` before any read, and each
 *   attempt's read is refused with `BuiltOnHeadNotReachedError` unless the
 *   served log carries that SCID and an entry with that `versionId`. Checked
 *   before `skip`, so a truncated served log is refused rather than read as
 *   "not complete yet" and rebuilt over
 * @param [options.missingMessage] {string}   the thrown `Error`'s message
 *   when `did.jsonl` is absent
 * @param [options.verb] {string}   what the caller is doing, for the client
 *   arm's pending-rotation refusal message (e.g. `'revoking a client'`)
 * @param [options.projectionStore] {DidWebProjectionStore}   a store whose
 *   authority reaches `did.json`. Given, the post-entry `did:web` projection
 *   (`updateDID`'s own `webDoc`) is PUT through it and through nothing else;
 *   omitted, no projection is written on any arm and the next
 *   `ensureDidWebProjection` is the mender. An enrolled client passes its
 *   controller-invoking store, a transient visit its generation-delegated
 *   store, and a caller holding the bridge delegation alone omits it
 * @param [options.removesInventory] {boolean}   whether this entry strikes
 *   a member of the document's inventory (default `false`). It decides the
 *   projection's timing. A ladder-signed removal PUTs the projection after
 *   `updateDID` and before the conditional publish, since the entry may end
 *   the authority the store invokes under, and a failed PUT is warned and
 *   the entry publishes anyway; that write runs once per attempt, so a
 *   conflict retry PUTs it again. Every other entry PUTs it after `did.jsonl`
 *   lands, and a failed PUT throws
 * @returns {Promise<AccountEntryOutcome>}
 */
export async function signAccountEntry({
  idStore,
  signer,
  build,
  skip,
  published: alreadyRead,
  expectedDid,
  builtOnHead,
  missingMessage,
  verb = 'extending the account log',
  projectionStore,
  removesInventory = false
}: {
  idStore: AccountLogStore
  signer: AccountEntrySigner
  build: (context: {
    published: PublishedWebvhLog
    rung?: LadderRung
    state?: LadderRungState
    concludeUnchanged: () => Promise<{ did: string; doc: DIDDoc; log: DIDLog }>
  }) => AccountEntryFields | undefined | Promise<AccountEntryFields | undefined>
  skip?: (published: PublishedWebvhLog) => boolean | Promise<boolean>
  published?: PublishedWebvhLog
  expectedDid?: string
  builtOnHead?: BuiltOnHead
  missingMessage?: string
  verb?: string
  projectionStore?: DidWebProjectionStore
  removesInventory?: boolean
}): Promise<AccountEntryOutcome> {
  const projectionTiming = projectionTimingOf({ signer, removesInventory })
  // A resume skips nothing on the strength of a marker it cannot compare:
  // refused before any read, rather than resuming unguarded.
  if (builtOnHead !== undefined) {
    assertBuiltOnHeadShape({ builtOnHead })
  }
  // THE PREAMBLE: each attempt reads for itself unless the caller threaded a
  // read in, so the continuity check runs on the read the compare-and-swap
  // publish is conditioned on rather than only on an orchestrator's pre-read.
  const published =
    alreadyRead !== undefined
      ? assertPublishedLogDid({
          published: alreadyRead,
          ...(expectedDid !== undefined ? { expectedDid } : {})
        })
      : await readPublishedLogOrThrow({
          idStore,
          ...(expectedDid !== undefined ? { expectedDid } : {}),
          ...(missingMessage !== undefined ? { missingMessage } : {})
        })
  // The resume marker, before `skip`'s completion check: a served log that
  // has not reached the recorded head is refused, not rebuilt over.
  if (builtOnHead !== undefined) {
    assertBuiltOnHeadReached({ log: published.log, builtOnHead })
  }
  if (skip && (await skip(published))) {
    return { skipped: true, published }
  }

  // The ladder arm's attribution: which rung is current, recovered from the
  // log itself. Fails closed with `LadderAttributionError` for a revoked (or
  // never-bound) credential and for any ambiguous history.
  const attributed =
    signer.kind === 'ladder'
      ? await attributeLadderRung({
          ladderSeed: signer.ladderSeed,
          published
        })
      : undefined
  const rungHash =
    attributed === undefined
      ? undefined
      : await deriveNextKeyHash(attributed.rung.keyMultibase)
  const ladderParts =
    attributed === undefined
      ? {}
      : { rung: attributed.rung, rungHash: rungHash!, state: attributed.state }

  const entry = await build({
    published,
    ...ladderParts,
    concludeUnchanged: () =>
      concludeUnchangedAccountEntry({
        projectionStore,
        projectionTiming,
        published
      })
  })
  if (!entry) {
    return { skipped: false, published, ...ladderParts }
  }

  const { commitHashes = [], updateKeys, nextKeyHashes, ...fields } = entry
  const statedKeys = updateKeys ?? published.updateKeys
  const statedHashes = nextKeyHashes ?? published.nextKeyHashes
  let entrySigner
  let signedUpdateKeys: string[]
  let signedHashes: string[]
  if (signer.kind === 'enrolled') {
    // The entry is signed by this client's active update key; a log that does
    // not authorize it (a rotation torn elsewhere) must heal first.
    const activeKey = await updateKeyMultibase({
      seed: signer.updateKeys.updateSeed
    })
    if (!published.updateKeys.includes(activeKey)) {
      throw new Error(
        "did:webvh: the published log does not authorize this client's " +
          `active update key; finalize the pending rotation before ${verb}.`
      )
    }
    entrySigner = await updateKeySigner({ seed: signer.updateKeys.updateSeed })
    signedUpdateKeys = statedKeys
    signedHashes = [...new Set([...statedHashes, ...commitHashes])]
  } else {
    // The revealing key: the attributed rung on the ladder arm, the bare seed's
    // key on the committed arm, which must stand committed or already
    // revealed -- the one precondition the ladder arm's attribution already
    // proved.
    let revealing: { seed: Uint8Array; keyMultibase: string; hash: string }
    if (signer.kind === 'ladder') {
      revealing = {
        seed: attributed!.rung.seed,
        keyMultibase: attributed!.rung.keyMultibase,
        hash: rungHash!
      }
    } else {
      const keyMultibase = await updateKeyMultibase({ seed: signer.updateSeed })
      const hash = await deriveNextKeyHash(keyMultibase)
      if (
        !published.updateKeys.includes(keyMultibase) &&
        !published.nextKeyHashes.includes(hash)
      ) {
        throw new Error(
          'did:webvh: the published log neither authorizes this update key ' +
            `nor commits its hash; nothing licenses it to sign while ${verb}.`
        )
      }
      revealing = { seed: signer.updateSeed, keyMultibase, hash }
    }
    entrySigner = await updateKeySigner({ seed: revealing.seed })
    // The acting key reveals itself in the entry it signs (its hash stands
    // committed, or the key is already revealed), and its own hash is kept
    // committed so the carry-over convention holds for the next entry.
    signedUpdateKeys = [...new Set([...statedKeys, revealing.keyMultibase])]
    signedHashes = [
      ...new Set([...statedHashes, revealing.hash, ...commitHashes])
    ]
  }
  await assertCarryOverCommitments({ published })
  const updated = await updateDID({
    ...fields,
    log: published.log,
    // The pinned read already resolved exactly these bytes, so the append
    // builds on its meta rather than resolving the log a second time.
    priorMeta: published.meta,
    signer: entrySigner,
    alsoKnownAsWeb: true,
    updateKeys: signedUpdateKeys,
    nextKeyHashes: signedHashes
  })
  const written = await publishAccountEntry({
    idStore,
    updated,
    ifMatch: published.etag,
    projectionStore,
    projectionTiming
  })
  return {
    skipped: false,
    published,
    ...ladderParts,
    updated,
    ...(written.etag !== undefined ? { etag: written.etag } : {})
  }
}

/**
 * The publish tail: `did.jsonl` under the caller's compare-and-swap token
 * (which advances the store's pin, for both arms, so a host rolling the log
 * back straight afterwards is refused on the next read), with the `did:web`
 * projection PUT through the projection store alone, before or after the
 * log per the timing. The log store is never asked for the projection.
 *
 * The two failure rules live here and nowhere else. After the pivot the PUT
 * throws: the entry stands, and the ceremony's re-run republishes the
 * projection through its idempotent path. Before the pivot the PUT is
 * best-effort, and the direction is deliberate: a projection published before
 * an entry that then fails under-lists a key the log still carries, which a
 * `did:web` verifier reads as less authority rather than more, while
 * withholding the entry over a failed projection would leave the struck key
 * standing in the log itself. The residue either way is a projection the next
 * `ensureDidWebProjection` mends.
 *
 * @param options {object}
 * @param options.idStore {AccountLogStore}
 * @param options.updated {object}   the `updateDID` result
 * @param [options.ifMatch] {string}   the ETag of the read this entry was
 *   built on
 * @param [options.projectionStore] {DidWebProjectionStore}   the one store the
 *   projection is written through; omitted, no projection is written
 * @param options.projectionTiming {ProjectionTiming}
 * @returns {Promise<{ etag?: string }>}   the LOG's new validator
 */
async function publishAccountEntry({
  idStore,
  updated,
  ifMatch,
  projectionStore,
  projectionTiming
}: {
  idStore: AccountLogStore
  updated: UpdateDIDResult
  ifMatch?: string
  projectionStore?: DidWebProjectionStore
  projectionTiming: ProjectionTiming
}): Promise<{ etag?: string }> {
  // One projection write, shared by both timings; only the failure rule
  // around it differs.
  const putProjection = async (store: DidWebProjectionStore) => {
    if (!updated.webDoc) {
      // Every entry is built with `alsoKnownAsWeb`, so this is a defect
      // rather than a state.
      throw new Error(
        'did:webvh: updateDID returned no webDoc despite the did:web ' +
          'alsoKnownAs.'
      )
    }
    await putDidWebProjection({ store, webDoc: updated.webDoc })
  }
  if (projectionStore !== undefined && projectionTiming === 'before') {
    try {
      await putProjection(projectionStore)
    } catch (err) {
      log.warn('did:webvh: the pre-entry did:web projection PUT failed.', {
        err
      })
    }
  }
  const written = await putLogResource({
    store: idStore,
    log: updated.log,
    ...(ifMatch !== undefined ? { ifMatch } : {})
  })
  if (projectionStore !== undefined && projectionTiming === 'after') {
    await putProjection(projectionStore)
  }
  return written
}

/**
 * The head a ceremony concludes on when its entry turns out to be
 * unnecessary -- the client is already enrolled, the removal already landed,
 * the pointer already set. `build` reaches it as `concludeUnchanged`, bound
 * to the seam call's own store and timing. There is nothing to publish either
 * way; what differs is the `did:web` projection. The projection is republished
 * from the resolved log through the store under the `'after'` timing, which
 * heals a lag a torn earlier run of the same ceremony left behind (a
 * post-entry PUT that threw after the log landed). Under the `'before'`
 * timing nothing is written: the entry an earlier run landed may have ended
 * the authority the store invokes under, so the PUT could only be refused.
 * Without a store the read is taken verbatim. Either way the projection is
 * otherwise left to `ensureDidWebProjection`.
 *
 * @param options {object}
 * @param [options.projectionStore] {DidWebProjectionStore}   the store the
 *   projection is republished through; omitted, nothing is written
 * @param options.projectionTiming {ProjectionTiming}   the timing the entry
 *   would have taken; `'before'` writes nothing here
 * @param options.published {PublishedWebvhLog}   the read the build stood on
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}
 */
async function concludeUnchangedAccountEntry({
  projectionStore,
  projectionTiming,
  published
}: {
  projectionStore?: DidWebProjectionStore
  projectionTiming: ProjectionTiming
  published: PublishedWebvhLog
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  if (projectionStore !== undefined && projectionTiming === 'after') {
    await concludeWithPublishedLog({ idStore: projectionStore, published })
  }
  return { did: published.did, doc: published.doc, log: published.log }
}
