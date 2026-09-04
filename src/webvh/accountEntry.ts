/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * ONE ACCOUNT-LOG ENTRY, WHOEVER SIGNS IT: the seam every ceremony that
 * extends `did.jsonl` writes through, so a ceremony body describes its
 * document delta once and the signing arm is a parameter.
 *
 * Two arms, discriminated by {@link AccountLogSigner}:
 *
 * - **client** -- an enrolled client's did:webvh update keys. The active key
 *   is derived from the seed, the published log must authorize it, the
 *   carry-over commitments must hold, and the entry publishes `did.jsonl`
 *   beside its `did:web` projection (the client invokes as the controller, so
 *   it may write both).
 * - **ladder** -- a standing credential's ladder seed, signing through the
 *   record's bridge delegation. The rung is attributed from the published log
 *   ({@link attributeLadderRung}, fail-closed), the acting rung reveals itself
 *   in the entry it signs, the rung's own hash is kept committed beside the
 *   build's own commit hashes in `decisions/0007` order, and the entry
 *   publishes `did.jsonl` alone -- the bridge's whole reach. The projection is
 *   the ceremony's own pre-entry PUT, or the next visit's ensure.
 *
 * Four of those steps are load-bearing conventions rather than plumbing:
 * omitting the reveal union publishes a log whose next entry cannot resolve,
 * omitting the carry-over hash switches prerotation off, omitting the
 * carry-over precondition publishes an entry no resolver accepts, and omitting
 * the pin advance leaves a pin behind an entry this client itself published.
 *
 * One property both arms rest on: an entry keeps its own signer. The ladder
 * arm unions the acting rung back into `updateKeys` after the build runs, so
 * no entry can remove the key that signed it. A ceremony that must retire a
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
  UpdateDIDInterface,
  UpdateDIDResult
} from '@interop/did-method-webvh'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import {
  assertCarryOverCommitments,
  assertPublishedLogDid,
  pinOfLog,
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
// The one deliberate dependency on the annex subpath, pinned as an exception
// in the lint rule (beside `unlock/standingWebvh.ts` and
// `recovery/recoveryWebvh.ts`): the ladder arm recovers the acting rung from
// the log through the shared attribution helper, and touches no annex log
// machinery.
import { attributeLadderRung } from '../clientAnnex/ladder.js'
import type { LadderRung, LadderRungState } from '../clientAnnex/ladder.js'

/**
 * Who signs an account-log entry. The client arm carries an enrolled client's
 * own did:webvh update-key seeds; the ladder arm carries a standing unlock
 * credential's ladder seed, whose rungs sign through the credential's bridge
 * delegation. There is no third arm and no absence: every ceremony body that
 * extends the account log states which one it acts as.
 */
export type AccountLogSigner =
  | { kind: 'client'; updateKeys: ClientWebvhUpdateKeys }
  | { kind: 'ladder'; ladderSeed: Uint8Array }

/**
 * The store an account-log entry is read and published through: the public
 * log read and the `did.jsonl` PUT. A subset of {@link WebvhIdStore}, so both
 * a controller-invoking client's store and a credential's bridge-backed
 * unlock-log store satisfy it.
 */
export type AccountLogStore = Pick<
  WebvhIdStore,
  'getIdResourceRaw' | 'putIdResource'
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
 * What {@link signAccountEntry} reports. `skipped` says the pre-signature
 * hook declined, so nothing was attributed and nothing was published;
 * `updated` is absent on that path AND where `build` itself declined, which
 * is the one test an idempotent caller needs ("did this call publish an
 * entry"). `rung`, `rungHash` and `state` are the ladder arm's, absent on the
 * client arm.
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
 * @param options.signer {AccountLogSigner}   who signs this entry
 * @param options.build {function}
 *   `({ published, rung, state }) => AccountEntryFields | undefined` -- the
 *   entry's own members, or `undefined` to decline
 * @param [options.skip] {function}   `(published) => boolean` -- run on the
 *   read, before any attribution; `true` returns `skipped` with nothing
 *   published
 * @param [options.published] {PublishedWebvhLog}   a read the caller already
 *   made (checked against `expectedDid`), in place of this call's own read.
 *   The caller owns the staleness: a lost compare-and-swap surfaces as a
 *   conflict for its retry to re-run
 * @param [options.expectedDid] {string}   the account DID the log must
 *   resolve to, from the caller's stored account pointer
 * @param [options.pinStore] {ResourceLogPinStore}   the caller's chain-head
 *   pins: the read is checked against the pinned head, and the pin advances
 *   to the head this entry publishes
 * @param [options.logId] {string}   the account log's pin slot
 *   (`accountLogPinId({ spaceId })`); required whenever a `pinStore` is
 *   supplied
 * @param [options.missingMessage] {string}   the thrown `Error`'s message
 *   when `did.jsonl` is absent
 * @param [options.verb] {string}   what the caller is doing, for the client
 *   arm's pending-rotation refusal message (e.g. `'revoking a client'`)
 * @param [options.logOnly] {boolean}   publish `did.jsonl` without its
 *   `did:web` projection. Implied by the ladder arm, whose bridge reaches
 *   `did.jsonl` alone
 * @param [options.beforePublish] {function}   `({ updated }) => Promise<void>`
 *   -- run on the built entry, AFTER `updateDID` and BEFORE the conditional
 *   publish. The seam exists for the `did:web` projection: a ladder-signed
 *   entry writes `did.jsonl` alone, so a ceremony whose entry removes
 *   inventory has to publish the post-entry projection while the authority it
 *   is about to end can still write it. A throw propagates and nothing is
 *   published. It runs once per attempt, so a conflict retry invokes it again
 *   and it must be idempotent
 * @returns {Promise<AccountEntryOutcome>}
 */
export async function signAccountEntry({
  idStore,
  signer,
  build,
  skip,
  published: alreadyRead,
  expectedDid,
  pinStore,
  logId,
  missingMessage,
  verb = 'extending the account log',
  logOnly = false,
  beforePublish
}: {
  idStore: AccountLogStore
  signer: AccountLogSigner
  build: (context: {
    published: PublishedWebvhLog
    rung?: LadderRung
    state?: LadderRungState
  }) => AccountEntryFields | undefined | Promise<AccountEntryFields | undefined>
  skip?: (published: PublishedWebvhLog) => boolean | Promise<boolean>
  published?: PublishedWebvhLog
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
  missingMessage?: string
  verb?: string
  logOnly?: boolean
  beforePublish?: (built: { updated: UpdateDIDResult }) => Promise<void>
}): Promise<AccountEntryOutcome> {
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
          ...(pinStore ? { pinStore } : {}),
          ...(logId !== undefined ? { logId } : {}),
          ...(missingMessage !== undefined ? { missingMessage } : {})
        })
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

  const entry = await build({ published, ...ladderParts })
  if (!entry) {
    return { skipped: false, published, ...ladderParts }
  }

  const { commitHashes = [], updateKeys, nextKeyHashes, ...fields } = entry
  const statedKeys = updateKeys ?? published.updateKeys
  const statedHashes = nextKeyHashes ?? published.nextKeyHashes
  let entrySigner
  let signedUpdateKeys: string[]
  let signedHashes: string[]
  if (signer.kind === 'client') {
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
    entrySigner = await updateKeySigner({ seed: attributed!.rung.seed })
    // The acting rung reveals itself in the entry it signs (its hash stands
    // committed, or the rung is already revealed), and its own hash is kept
    // committed so the carry-over convention holds for the next entry.
    signedUpdateKeys = [
      ...new Set([...statedKeys, attributed!.rung.keyMultibase])
    ]
    signedHashes = [...new Set([...statedHashes, rungHash!, ...commitHashes])]
  }
  await assertCarryOverCommitments({ published })
  const updated = await updateDID({
    ...fields,
    log: published.log,
    signer: entrySigner,
    alsoKnownAsWeb: true,
    updateKeys: signedUpdateKeys,
    nextKeyHashes: signedHashes
  })
  await beforePublish?.({ updated })
  const written = await publishAccountEntry({
    idStore,
    updated,
    ifMatch: published.etag,
    logOnly: logOnly || signer.kind === 'ladder',
    pinStore,
    logId
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
 * The publish tail: `did.jsonl` under the caller's compare-and-swap token,
 * its `did:web` projection where the signer may write one, then the pin
 * advance. The pin advances for both arms, so a host rolling the log back
 * straight afterwards is refused on the next read.
 *
 * @param options {object}
 * @param options.idStore {AccountLogStore}
 * @param options.updated {object}   the `updateDID` result
 * @param [options.ifMatch] {string}   the ETag of the read this entry was
 *   built on
 * @param options.logOnly {boolean}   skip the projection PUT
 * @param [options.pinStore] {ResourceLogPinStore}
 * @param [options.logId] {string}
 * @returns {Promise<{ etag?: string }>}   the LOG's new validator
 */
async function publishAccountEntry({
  idStore,
  updated,
  ifMatch,
  logOnly,
  pinStore,
  logId
}: {
  idStore: AccountLogStore
  updated: UpdateDIDResult
  ifMatch?: string
  logOnly: boolean
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ etag?: string }> {
  if (!logOnly && !updated.webDoc) {
    throw new Error(
      'did:webvh: updateDID returned no webDoc despite the did:web alsoKnownAs.'
    )
  }
  const written = await putLogResource({
    store: idStore,
    log: updated.log,
    ...(ifMatch !== undefined ? { ifMatch } : {})
  })
  if (!logOnly) {
    await putDidWebProjection({
      store: idStore,
      webDoc: updated.webDoc as object
    })
  }
  if (pinStore && logId !== undefined) {
    await pinStore.write({ logId, pin: pinOfLog(updated.log) })
  }
  return written
}
