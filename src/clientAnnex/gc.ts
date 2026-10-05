/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Client-annex GC: the quarterly wholesale replacement of the annex
 * generation, and the collection of everything it leaves behind.
 *
 * The ceremony has two halves with different rhythms:
 *
 * - The SWAP runs on the fixed quarterly cadence (90 days, at the first
 *   remembered login after the period elapses -- coarse on purpose, so the
 *   account log's permanent pointer-entry rhythm reveals little about
 *   transient-use frequency), and only when the pointed generation is
 *   GC-quiet (the 24-hour max-visit quiet bound over its newest entry's
 *   `versionTime`, with a skew-margin grace hour -- a deferral policy only,
 *   never a session expiry). Its stage order is fixed: mint + genesis,
 *   install the fresh generation's delegation service entry, revoke the old
 *   generation's delegation, re-point the account document. Revoke lands
 *   before the re-point (closing the window where a fail-open non-conforming
 *   server still honors the old delegation -- and the revocation POST itself
 *   only verifies while the pointer still makes the old chain resolve), and
 *   before the delete (the POST needs the capability bytes the delete
 *   destroys).
 *
 * - The COLLECT fan-out is predicate-driven and runs at every remembered login:
 *   every `gen-` collection the pointer does not name -- the generation a
 *   swap just superseded, a torn GC's leftover, a torn signup's orphan, a
 *   double-genesis loser -- gets identical treatment (revoke its embedded
 *   delegation blind, reading was-client's genuine `AlreadyRevokedError` as
 *   success and an already-expired delegation as needing no POST at all;
 *   write the digest; delete), so a GC torn anywhere resumes at the next
 *   login instead of waiting a quarter. The pointer it compares against is
 *   re-read from the account log under this client's pin right before the
 *   fan-out, and a generation that log never pointed at is collected only
 *   once it is GC-quiet (the same quiet bound the swap defers on), so a
 *   sibling client's swap -- landed, or still between its mint and its
 *   re-point -- never loses the generation the account points at. A
 *   generation the log once pointed at is collected at once: it cannot be a
 *   sibling's unpointed fresh generation, and a retire swap's refused revoke
 *   is retried on it without waiting a day. Failures are collected per
 *   generation and never abort the fan-out: a partial pass is a resumable
 *   success. The re-read itself and the collection listing sit outside that
 *   isolation: either failing rejects the pass, since there is nothing safe
 *   to collect against.
 *
 * - The REPAIR is the swap off its cadence: when the pointed generation's
 *   log does not exist (the pointer names a generation a stale pass
 *   collected, or one never minted), every transient visit is shut out until
 *   the pointer moves, so the pass mints a fresh generation and re-points at
 *   once, with nothing to revoke. The pointed log is read on every pass for
 *   this reason. The repair covers a dead generation inside a live Space
 *   only: when the auxiliary Space itself is gone, or its metadata read
 *   answers anything but 2xx, it refuses (`failed`), and the transient
 *   readiness ensure, whose two-probe rule tells a gone Space from a masked
 *   read, is the one that replaces a Space.
 *
 * Both the swap and the repair decide on the account log re-read under this
 * client's pin at the start of the pass, not on the caller's view, and
 * their re-point lands only while the account still points at the
 * generation they replace. A sibling client's swap that landed since the
 * caller's read, or while this pass minted, stands, and the pass reports
 * `not-due`.
 *
 * The completion predicate is durable state alone (exactly one `gen-`
 * collection exists in the auxiliary Space and it is the one the pointer
 * names); no marker resource exists anywhere -- the account document's
 * pointer-update entry is the record, and the cadence is read off its
 * `versionTime`. The digest (`GenerationCollect`, built by the caller's
 * `recordDigest` over `@interop/wallet-core/space`'s builder) is written
 * before the delete: it is the owner's only record of the collected window's
 * visits surviving the delete, and compromise detection ends at digest
 * granularity.
 *
 * Honest limitations: the "no unexpired delegation names a dead generation"
 * conjunct is an ordering obligation, not a check (the revocation protocol
 * exposes no read endpoint, and the dead generation's delegation bytes are
 * destroyed with its collection); orphaned generations are
 * authorization-inert (no delegation ever names an unpointed generation
 * under pointer equality), so what accretes between passes is a storage
 * leak, never an authority leak.
 */
import type { DIDLog } from '@interop/did-method-webvh'
import type { ZcapClient } from '@interop/ezcap'
import type { WasClient } from '@interop/was-client'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import { readSpaceMetadata } from './heal.js'
import {
  clientAnnexDidParts,
  clientAnnexLogStore,
  DelegatedClientsPointerMovedError,
  delegatedClientsPointer,
  delegatedClientsPointerHistory,
  embeddedGenerationDelegation,
  ensureGenerationDelegationCurrent,
  GENERATION_ID_PREFIX,
  mintCredentialClientAnnexGeneration,
  mintGenerationDelegation,
  readClientAnnexLogOrAbsent,
  revokeTreatingAlreadyRevokedAsSuccess,
  setDelegatedClientsPointer
} from './log.js'
import type { AccountLogSigner } from '../webvh/accountEntry.js'
import { readPublishedLogOrThrow } from '../webvh/didWebvh.js'
import type {
  ClientWebvhUpdateKeys,
  PublishedWebvhLog,
  WebvhIdStore
} from '../webvh/didWebvh.js'
import type { PublishedKeyDocument } from '../webvh/listClients.js'
import type { ClientAnnexSwapRevokeOutcome } from '../unlock/retire.js'

/**
 * The fixed GC cadence: a generation is replaced at the first remembered login
 * 90 days after the current pointer value was established. Wallet GC policy
 * over the account log's own timestamps, never a stored or wire value.
 */
export const GENERATION_GC_PERIOD_MS = 90 * 24 * 60 * 60 * 1000

/**
 * The quiet bound: a generation is GC-quiet when its newest entry's
 * `versionTime` is over 24 hours old. The bound defers the swap only; it
 * never expires a session. A visit outliving it merely loses guaranteed
 * guard protection, and in the rare case a quarterly pass lands on one, the
 * session's next authorization failure maps to the generation-lapse retry
 * state.
 */
export const GENERATION_QUIET_BOUND_MS = 24 * 60 * 60 * 1000

/**
 * The skew-margin grace floor on the quiet bound: three clocks meet at the
 * guard check (the enrolling writer's, any prior entry writer's, and the
 * GC-running client's), and `versionTime` is asserted by the writer's clock,
 * so the guard compares against the bound plus this margin. An hour is
 * generous against real-world skew and defers the swap by at most an hour
 * against a quarterly cadence.
 */
export const GENERATION_QUIET_GRACE_MS = 60 * 60 * 1000

/**
 * The `versionTime` of the account-log entry that established the CURRENT
 * `#DelegatedClients` pointer value: the newest entry whose state names a
 * different annex DID than the entry before it (or the first entry, when
 * the pointer has been there since genesis). This is the cadence's clock --
 * "the pointer-update entry is the record" -- and it is read off the log a
 * remembered login has already verified, so the cadence costs no extra fetch
 * and every enrolled client agrees on it.
 *
 * @param options {object}
 * @param options.log {DIDLog}   the VERIFIED account log
 * @returns {string | undefined}   the establishing entry's `versionTime`,
 *   or undefined when no entry carries a pointer
 */
export function delegatedClientsPointerEstablishedAt({
  log
}: {
  log: DIDLog
}): string | undefined {
  let establishedAt: string | undefined
  let previous: string | undefined
  for (const entry of log) {
    const pointed = delegatedClientsPointer({ doc: entry.state })
    if (pointed !== undefined && pointed !== previous) {
      establishedAt = entry.versionTime
    }
    if (pointed === undefined) {
      // A document with no pointer has no annex inventory; a later entry
      // restoring one establishes afresh.
      establishedAt = undefined
    }
    previous = pointed
  }
  return establishedAt
}

/**
 * Whether the quarterly swap is due: the current pointer value was
 * established {@link GENERATION_GC_PERIOD_MS} or more ago. A log with no
 * pointer is never due (there is no generation to replace).
 *
 * @param options {object}
 * @param options.log {DIDLog}   the VERIFIED account log
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {boolean}
 */
export function clientAnnexGcDue({
  log,
  now = Date.now()
}: {
  log: DIDLog
  now?: number
}): boolean {
  const establishedAt = delegatedClientsPointerEstablishedAt({ log })
  if (establishedAt === undefined) {
    return false
  }
  const establishedMs = Date.parse(establishedAt)
  return (
    Number.isFinite(establishedMs) &&
    now - establishedMs >= GENERATION_GC_PERIOD_MS
  )
}

/**
 * The live-entry guard: whether a generation is GC-quiet -- its newest
 * entry's `versionTime` is older than the quiet bound plus the skew grace
 * margin. On the POINTED generation it defers the swap, so a possibly-live
 * visit is not abandoned. On an unpointed generation the account log NEVER
 * pointed at it defers the collect: such a generation authorizes nothing
 * under pointer equality, but one written moments ago may be a sibling
 * client's fresh generation whose re-point has not landed yet, and collecting
 * it would leave the account pointing at a deleted generation. An
 * unparseable `versionTime` reads as not quiet, so both arms defer rather
 * than act.
 *
 * @param options {object}
 * @param options.log {DIDLog}   the generation's VERIFIED annex log
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {boolean}
 */
export function generationQuiet({
  log,
  now = Date.now()
}: {
  log: DIDLog
  now?: number
}): boolean {
  const newest = log[log.length - 1]?.versionTime
  if (newest === undefined) {
    return false
  }
  const newestMs = Date.parse(newest)
  return (
    Number.isFinite(newestMs) &&
    now - newestMs >= GENERATION_QUIET_BOUND_MS + GENERATION_QUIET_GRACE_MS
  )
}

/**
 * What the swap half of one GC pass did. `replaced` is the successful
 * quarterly swap; `repaired` is the off-cadence swap the pass runs when the
 * pointed generation's log does not exist (the account was left pointing at
 * a collected or never-minted generation, and no transient visit could
 * enroll), so the pointer names a live generation again; `not-due` and
 * `deferred-live` are the two healthy skips (cadence and quiet bound), and
 * `not-due` also covers a caller's dead pointer the account log has since
 * moved off; `no-pointer` means the account has no annex inventory (the
 * whole pass no-ops -- without a pointer there is no auxiliary Space to
 * list), or that the re-read ahead of a repair found the pointer removed;
 * `no-ladder-seed` means a swap was due, or a repair needed, but the login
 * held no ladder seed to mint with (a non-standing record); `failed` means
 * the pointed generation's read or a swap stage threw -- reported in
 * `failed` under the pointed generation's id, with the collect fan-out
 * still run.
 */
export type ClientAnnexGcSwapOutcome =
  | 'replaced'
  | 'repaired'
  | 'not-due'
  | 'deferred-live'
  | 'no-pointer'
  | 'no-ladder-seed'
  | 'failed'

/**
 * One GC pass's report: the swap outcome, the annex DID the account points
 * at after the pass (read back from the account log under this client's
 * pin, so it is what the host serves and not what this pass believes), the
 * generation ids collected (revoked, digested, deleted), the ids deferred
 * (unpointed but not yet GC-quiet, kept for a later pass), and the
 * per-generation failures. A report with `failed` or `deferred` entries is a
 * resumable success -- the next remembered login's pass picks up exactly the
 * generations still listed.
 */
export interface ClientAnnexGcReport {
  swap: ClientAnnexGcSwapOutcome
  pointedDid?: string
  collected: string[]
  deferred: string[]
  failed: Array<{ generationId: string; error: unknown }>
}

/**
 * One generation swap's outcome: the fresh annex DID the account now points
 * at, and what the revoke stage did with the old generation's embedded
 * delegation -- `revoked` (the POST landed, or was-client answered the
 * genuine `AlreadyRevokedError`), `expired` (the delegation's own `expires`
 * is past beyond doubt, so no POST was sent, or the server refused the POST
 * inside the skew band around `expires`), `signer-gone` (the server refused
 * the POST and the delegation's proof key has left the account document --
 * a rotted chain), `refused` (the server, or was-client before the POST,
 * refused the revocation for a reason the stage could not classify; the
 * error rides in `revokeError`, the re-point still landed, and the old
 * generation is left for the collect fan-out, which re-attempts the
 * revocation and keeps the generation while it keeps failing),
 * `no-delegation` (the old log stands and embeds none), or `log-absent` (the
 * pointed log does not exist, so there were no bytes to revoke; pointer
 * equality retires the delegation on a conforming server). Reported rather
 * than folded into the DID so a caller can tell a swap that revoked from one
 * that could not.
 *
 * A refusal does not abort the swap: by the time the revoke stage runs the
 * fresh generation is minted and its delegation installed, and a swap that
 * threw here would leave that orphan behind and mint another at every due
 * login, with the old generation never superseded. Re-pointing anyway costs
 * nothing the refusal did not already cost: a delegation the server refused
 * to revoke fails the chain check an invocation under it runs too, a
 * refusal raised client-side before any POST is a configuration fault the
 * next pass meets again, and the fan-out keeps the bytes until a pass
 * succeeds.
 */
export interface ClientAnnexGenerationSwap {
  clientAnnexDid: string
  revoke: ClientAnnexSwapRevokeOutcome
  revokeError?: unknown
}

/**
 * One annex GC pass: the quarterly swap when due and quiet, then the
 * predicate-driven collect fan-out over every non-pointed `gen-` collection.
 * See the module header for the stage order and its load-bearing constraints.
 *
 * Convergence: every stage detects completion from durable state. A re-run
 * after a tear re-POSTs the revocation blind (a genuine `AlreadyRevokedError`
 * reads as success; a delegation expired beyond the clock-skew margin is
 * skipped locally before any POST, and a refusal inside the skew band or of
 * a chain whose signer has left the document is read as that), re-writes
 * the digest (the deterministic payload id collapses the second row at read
 * time), and re-runs the idempotent delete; a swap torn before its re-point
 * leaves an unpointed fresh generation the same fan-out collects once it is
 * GC-quiet.
 *
 * Two guards keep the fan-out off the pointed generation. The pointer the
 * fan-out compares against is re-read from the account log under this
 * client's pin immediately before the fan-out, so a sibling client's swap,
 * or this pass's own re-point whose response was lost, is seen rather than
 * the caller's pre-pass view. And an unpointed generation the fresh log
 * never pointed at is collected only when GC-quiet, so a sibling mid-swap
 * (minted, not yet pointed) keeps its fresh generation; one the log once
 * pointed at is collected at once. A generation whose log does not exist
 * carries no timestamp and is deleted at once. A sibling whose genesis and
 * install both land in the gap between that read and the delete goes on to
 * re-point at the deleted generation; the next remembered login's repair,
 * or the next transient visit's readiness ensure, mends that.
 *
 * The pointed generation's log is read on every pass: when the swap is due
 * it is the quiet gate, and on every pass it is the detector of a dead
 * pointed generation (a collected or never-minted one the pointer still
 * names), which the pass repairs with an off-cadence swap so the next
 * transient visit can enroll. Before the repair the account log is re-read
 * under this client's pin: when the pointer has moved off the one the caller
 * passed, a sibling client swapped since the caller's read, and the pass
 * reports `not-due` and repairs nothing (`no-pointer` when the re-read
 * document carries none). The repair's own re-point is conditional on the
 * same pointer, so a sibling's re-point landing while the repair mints also
 * stands, and the pass reports `not-due`. The repair then confirms the
 * auxiliary Space
 * itself still answers, and refuses when it does not: replacing a gone Space
 * is the transient readiness ensure's, whose two-probe rule tells absence
 * from a masked read, and a repair racing it across two Spaces would strand
 * whichever Space lost the re-point.
 *
 * @param options {object}
 * @param options.was {WasClient}   the storage client, signing as an
 *   enrolled client (root tier on both the account and auxiliary Spaces)
 * @param options.wasServerUrl {string}   the account pointer's host
 * @param options.accountSpaceId {string}   the ACCOUNT Space's id (the
 *   generation delegation's target subtree)
 * @param options.account {object}   the VERIFIED account log
 *   (`{ did, doc, log }` -- `verifyAccountLog`'s shape)
 * @param options.idStore {WebvhIdStore}   the account log's id store, for
 *   the re-point
 * @param options.updateKeys {ClientWebvhUpdateKeys}   this enrolled client's
 *   update keys, signing the re-point entry
 * @param options.zcapClient {ZcapClient}   signs the fresh generation
 *   delegation (the promoted account keyId)
 * @param [options.ladderSeed] {Uint8Array}   the login credential's ladder
 *   seed; absent, a due swap or a needed repair reports `no-ladder-seed` and
 *   only the collect fan-out runs
 * @param options.recordDigest {Function}
 *   `({ generationId, firstEntry, lastEntry, entryCount }) => Promise<void>`
 *   -- writes the GenerationCollect wallet-activity row; called before the
 *   delete, and a throw keeps the generation for the next pass
 * @param [options.onCollected] {Function}
 *   `({ generationId }) => Promise<void>` -- local cleanup after a
 *   generation's delete (the caller's annex pin-slot drop); a throw is
 *   reported but cannot be retried (the collection is already gone)
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {Promise<ClientAnnexGcReport>}
 */
export async function runClientAnnexGc({
  was,
  wasServerUrl,
  accountSpaceId,
  account,
  idStore,
  updateKeys,
  zcapClient,
  ladderSeed,
  recordDigest,
  onCollected,
  now = Date.now()
}: {
  was: WasClient
  wasServerUrl: string
  accountSpaceId: string
  account: Pick<PublishedWebvhLog, 'did' | 'doc' | 'log'>
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  zcapClient: ZcapClient
  ladderSeed?: Uint8Array
  recordDigest: (digest: {
    generationId: string
    firstEntry?: string
    lastEntry?: string
    entryCount?: number
  }) => Promise<void>
  onCollected?: (options: { generationId: string }) => Promise<void>
  now?: number
}): Promise<ClientAnnexGcReport> {
  const pointedDid = delegatedClientsPointer({ doc: account.doc })
  if (pointedDid === undefined) {
    return { swap: 'no-pointer', collected: [], deferred: [], failed: [] }
  }
  // The annex logs pin in the same store the account log does: one pin
  // store per client, every slot derived by the store that serves it.
  const pinStore = idStore.pin.store
  const { spaceId, generationId: pointedGenerationId } = clientAnnexDidParts({
    did: pointedDid
  })
  const failed: ClientAnnexGcReport['failed'] = []

  // 1. The swap: the quarterly one when the cadence is due and the pointed
  // generation is quiet, or the off-cadence repair when the pointed
  // generation's log does not exist. The pointed log is read on every pass
  // for the second reason: a pointer naming a dead generation shuts every
  // transient visit out, and the cadence alone would not re-read it for a
  // quarter. A failure is collected under the pointed generation's id
  // rather than aborting the pass: the collect fan-out below still cleans
  // what it can, and the next remembered login re-attempts from durable
  // state.
  //
  // Both arms decide on the account log re-read under this client's pin,
  // not on the caller's pre-pass view, which a sibling's swap since then
  // can have left naming a generation the account no longer points at (the
  // module header has the account). The re-read failing rejects the pass:
  // there is nothing safe to swap or collect against.
  const head = await readPublishedLogOrThrow({
    idStore,
    expectedDid: account.did,
    missingMessage:
      'did:webvh: did.jsonl is missing; nothing to collect against.'
  })
  const headPointer = delegatedClientsPointer({ doc: head.doc })
  if (headPointer === undefined) {
    return { swap: 'no-pointer', collected: [], deferred: [], failed: [] }
  }
  // Whether the swap reached a write: set before the mint, so a swap torn
  // or raced anywhere past that point re-reads the account log below.
  let swapWrote = false
  const swap = await (async (): Promise<ClientAnnexGcSwapOutcome> => {
    try {
      if (headPointer !== pointedDid) {
        return 'not-due'
      }
      const pointed = await readClientAnnexGeneration({
        was,
        spaceId,
        generationId: pointedGenerationId,
        pinStore,
        expectedDid: pointedDid
      })
      // The caller's view and the re-read head name the same pointer, so
      // the entry that established it, and the cadence read off that
      // entry's `versionTime`, are the same in both.
      if (
        pointed !== undefined &&
        !clientAnnexGcDue({ log: account.log, now })
      ) {
        return 'not-due'
      }
      if (
        pointed !== undefined &&
        !generationQuiet({ log: pointed.log, now })
      ) {
        return 'deferred-live'
      }
      if (ladderSeed === undefined) {
        return 'no-ladder-seed'
      }
      if (pointed === undefined) {
        await assertAnnexSpacePresent({ was, spaceId })
      }
      // A `refused` revoke is not reported here: the swap completed, the old
      // generation is now unpointed, and the fan-out below re-attempts its
      // revocation in this same pass, reporting the failure under its id if
      // it fails again. A dead pointed generation has no bytes to revoke; the
      // revoke stage reports `log-absent` and pointer equality retires its
      // delegation on a conforming server.
      swapWrote = true
      await replaceClientAnnexGeneration({
        was,
        wasServerUrl,
        accountSpaceId,
        account: head,
        idStore,
        signer: { kind: 'enrolled', updateKeys },
        zcapClient,
        ladderSeed,
        clientAnnexSpaceId: spaceId,
        ...(pointed !== undefined ? { oldGeneration: pointed } : {}),
        head,
        now
      })
      return pointed === undefined ? 'repaired' : 'replaced'
    } catch (err) {
      if (err instanceof DelegatedClientsPointerMovedError) {
        // A sibling client re-pointed while this pass minted. Its pointer
        // stands, and the generation this pass minted is an unpointed orphan
        // a later pass collects once it is GC-quiet.
        return 'not-due'
      }
      failed.push({ generationId: pointedGenerationId, error: err })
      return 'failed'
    }
  })()

  // 2. The pointer the fan-out compares against: the account log as the
  // host serves it now, not the caller's pre-pass view and not what this
  // pass believes it published. A swap that reached a write is re-read
  // under this client's pin, since its re-point may have landed with the
  // response lost, or lost to a sibling's; a swap that wrote nothing left
  // the head read above as that view. A document with no pointer collects
  // nothing: the annex inventory is being removed, and nothing under it is
  // this pass's to delete.
  const fresh = swapWrote
    ? await readPublishedLogOrThrow({
        idStore,
        expectedDid: account.did,
        missingMessage:
          'did:webvh: did.jsonl is missing; nothing to collect against.'
      })
    : head
  const freshPointer = delegatedClientsPointer({ doc: fresh.doc })
  if (freshPointer === undefined) {
    return { swap, collected: [], deferred: [], failed }
  }
  const freshParts = clientAnnexDidParts({ did: freshPointer })
  // A pointer that moved to another auxiliary Space leaves this one wholly
  // unpointed; the quiet guard still keeps anything young in it.
  const currentGenerationId =
    freshParts.spaceId === spaceId ? freshParts.generationId : undefined
  // Every annex DID the fresh log ever pointed at: a generation among them
  // is a superseded one, not a sibling's fresh mint, so the quiet gate does
  // not apply to it.
  const everPointed = new Set(
    delegatedClientsPointerHistory({ log: fresh.log })
  )

  // 3. The collect fan-out: every `gen-` collection the fresh pointer does
  // not name. Orphan discovery is a plain prefix match over the auxiliary
  // Space's collection listing -- no registry of generations exists anywhere
  // -- and a torn GC's old generation, a torn signup's orphan, a sibling's
  // superseded generation, and a double-genesis loser get identical
  // treatment. One the log never pointed at is collected only once GC-quiet
  // (`deferred` otherwise), so a sibling's fresh generation is never
  // collected between its mint and its re-point.
  const space = was.space(spaceId)
  const stale: string[] = []
  for await (const page of space.collectionsPages()) {
    for (const item of page.items) {
      if (
        item.id.startsWith(GENERATION_ID_PREFIX) &&
        item.id !== currentGenerationId
      ) {
        stale.push(item.id)
      }
    }
  }

  const collected: string[] = []
  const deferred: string[] = []
  await Promise.all(
    stale.map(async generationId => {
      try {
        const outcome = await collectOneGeneration({
          was,
          spaceId,
          generationId,
          pinStore,
          recordDigest,
          onCollected,
          now,
          accountDoc: fresh.doc,
          everPointed
        })
        if (outcome === 'collected') {
          collected.push(generationId)
        } else {
          deferred.push(generationId)
        }
      } catch (err) {
        failed.push({ generationId, error: err })
      }
    })
  )

  return { swap, pointedDid: freshPointer, collected, deferred, failed }
}

/**
 * Reads and verifies one generation's published annex log, or resolves
 * undefined when its `did.jsonl` does not exist (a generation that never
 * finished minting, or whose collection outlived a torn delete). Absence is
 * read as absence even under a held pin ({@link readClientAnnexLogOrAbsent}):
 * a torn collect whose slot drop never ran must still collect.
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.spaceId {string}   the auxiliary annex Space's id
 * @param options.generationId {string}
 * @param options.pinStore {ResourceLogPinStore}   this client's chain-head
 *   pins (the account-log store's); the store derives the generation log's
 *   slot
 * @param [options.expectedDid] {string}
 * @returns {Promise<PublishedWebvhLog | undefined>}
 */
async function readClientAnnexGeneration({
  was,
  spaceId,
  generationId,
  pinStore,
  expectedDid
}: {
  was: WasClient
  spaceId: string
  generationId: string
  pinStore: ResourceLogPinStore
  expectedDid?: string
}): Promise<PublishedWebvhLog | undefined> {
  return readClientAnnexLogOrAbsent({
    store: clientAnnexLogStore({ was, spaceId, generationId, pinStore }),
    ...(expectedDid !== undefined ? { expectedDid } : {})
  })
}

/**
 * The swap's four stages, in the fixed order: mint + genesis; install the
 * fresh generation's delegation service entry; revoke the old generation's
 * delegation; re-point the account document. Returns the fresh annex
 * DID. The digest and the delete are deliberately NOT here -- once the
 * re-point lands, the old generation is an ordinary non-pointed `gen-`
 * collection and the standing collect fan-out handles it, which is also
 * what makes a swap torn after its re-point resume for free.
 *
 * @param options {object}   see {@link runClientAnnexGc}, plus:
 * @param options.clientAnnexSpaceId {string}   the auxiliary Space's id
 * @param [options.oldGeneration] {PublishedWebvhLog}   the pointed
 *   generation's verified log, read by the quiet check; absent (an
 *   off-cadence swap whose pointed log does not exist), the revoke stage is
 *   skipped and the old generation's delegation dies with the re-point on a
 *   conforming server
 * @param options.head {PublishedWebvhLog}   the verified account head the
 *   caller read; the re-point builds on it and lands only while the account
 *   log still points at the generation it names
 * @param options.now {number}   epoch milliseconds, read against the old
 *   delegation's own `expires`
 * @returns {Promise<ClientAnnexGenerationSwap>}   the fresh annex DID and
 *   what the revoke stage did
 * @throws {DelegatedClientsPointerMovedError}   when the account log no
 *   longer points at the generation `head` names
 */
async function replaceClientAnnexGeneration({
  was,
  wasServerUrl,
  accountSpaceId,
  account,
  idStore,
  signer,
  zcapClient,
  ladderSeed,
  clientAnnexSpaceId,
  oldGeneration,
  head,
  now
}: {
  was: WasClient
  wasServerUrl: string
  accountSpaceId: string
  account: Pick<PublishedWebvhLog, 'did' | 'doc'>
  idStore: WebvhIdStore
  signer: AccountLogSigner
  zcapClient: ZcapClient
  ladderSeed: Uint8Array
  clientAnnexSpaceId: string
  oldGeneration?: PublishedWebvhLog
  head: PublishedWebvhLog
  now: number
}): Promise<ClientAnnexGenerationSwap> {
  const pinStore = idStore.pin.store
  // 1. Mint + genesis: a fresh generation in the existing auxiliary Space
  // (the typed-Space ensure no-ops on it; the controller argument is only
  // read when the Space does not exist). The genesis commits the minting
  // credential's rung-0 hash for the fresh generation id.
  const minted = await mintCredentialClientAnnexGeneration({
    was,
    wasServerUrl,
    spaceId: clientAnnexSpaceId,
    controller: account.did,
    ladderSeed,
    pinStore
  })

  // 2. Install the fresh generation's delegation service entry (the
  // install-when-absent half of the renew-precedes-mint helper), the
  // delegation signed by this enrolled client's promoted account key and the
  // installing annex entry by the credential's rung 0.
  //
  // The install stands on the head the mint just published rather than
  // re-reading the log this run wrote a moment ago -- but only when that head
  // carries the PUT's own ETag, since the install's entry publishes under a
  // compare-and-swap and a head with no validator would degrade that to an
  // unconditional write. With no ETag the install reads for itself. Either
  // way its own publish advances the pin, so this generation's pin slot is
  // established by this run.
  await ensureGenerationDelegationCurrent({
    store: clientAnnexLogStore({
      was,
      spaceId: clientAnnexSpaceId,
      generationId: minted.generationId,
      pinStore
    }),
    ladderSeed,
    generationId: minted.generationId,
    mintGenerationDelegation: async ({ clientAnnexDid }) =>
      mintGenerationDelegation({
        zcapClient,
        wasServerUrl,
        spaceId: accountSpaceId,
        clientAnnexDid,
        now
      }),
    expectedDid: minted.did,
    ...(minted.etag !== undefined ? { published: minted } : {}),
    now
  })

  // 3. Revoke the old generation's delegation, before the re-point (the
  // revocation POST verifies against the currently resolved document, so it
  // only chains while the pointer still names the old generation) and
  // before the delete (the POST needs bytes the delete destroys).
  const oldDelegation =
    oldGeneration === undefined
      ? undefined
      : embeddedGenerationDelegation({ doc: oldGeneration.doc })
  let revoke: ClientAnnexGenerationSwap['revoke']
  let revokeError: unknown
  if (oldDelegation !== undefined) {
    try {
      const outcome = await revokeTreatingAlreadyRevokedAsSuccess({
        revoke: zcap => was.revoke(zcap),
        delegation: oldDelegation,
        now,
        accountDoc: account.doc
      })
      revoke =
        outcome === 'revoked' || outcome === 'already-revoked'
          ? 'revoked'
          : outcome
    } catch (err) {
      // Reported, not thrown: the fresh generation already stands, and a
      // swap that halts here re-mints an orphan at every due login while
      // the old generation is never superseded. The collect fan-out owns
      // the retry, keeping the old generation's bytes while it fails.
      revoke = 'refused'
      revokeError = err
    }
  } else {
    revoke = oldGeneration === undefined ? 'log-absent' : 'no-delegation'
  }

  // 4. Re-point the account document at the fresh generation, while it
  // still points at the one this swap replaces: the first attempt builds on
  // the caller's head, and a lost compare-and-swap re-reads and checks the
  // pointer again, where an unconditional re-point would rebase over a
  // sibling client's. On a conforming server the pointer equality itself
  // kills the old generation's ladder-signed delegations; the explicit
  // revoke above covered the fail-open case and the enrolled-client-signed
  // ones.
  await setDelegatedClientsPointer({
    idStore,
    signer,
    clientAnnexDid: minted.did,
    expectedDid: account.did,
    expectedPointer: delegatedClientsPointer({ doc: head.doc })!,
    published: head
  })
  return {
    clientAnnexDid: minted.did,
    revoke,
    ...(revoke === 'refused' ? { revokeError } : {})
  }
}

/**
 * AN OFF-CADENCE GENERATION SWAP: replaces the pointed annex generation
 * outside the quarterly rhythm -- the credential-rotation ceremony's
 * fallback when no distinct committed rung can sign a strike entry
 * (`retireClientAnnexRung`): a fresh generation minted from a SURVIVING
 * credential's seed commits only that credential's rung-0 hash, so the
 * retired credential's annex inventory dies with the whole generation the
 * moment the re-point lands. The abandoned generation is an ordinary
 * non-pointed `gen-` collection the standing collect fan-out picks up at the
 * next remembered login.
 *
 * Same four swap stages and ordering as the quarterly GC swap, minus the
 * cadence and quiet gates (the caller's reason for swapping is authority
 * removal, not hygiene). The pointed generation's log is read for the revoke
 * stage's delegation bytes. A pointed log that does not exist (a collected
 * generation the pointer still names) carries no delegation to revoke, so
 * the revoke is skipped and reported as `log-absent`, and pointer equality
 * retires the old delegation on a conforming server; a served log that fails
 * verification or falls behind this client's pin throws, since a swap over a
 * log this client cannot trust would skip a revoke it may owe. This is the
 * arm credential retirement calls, and the standing delegation there is
 * often signed by a ladder VM a PRIOR retirement already struck: the server
 * refuses that chain, and the revoke stage reads the refusal against the
 * caller's `account.doc` and reports `signer-gone`.
 *
 * The re-point lands only while the account log, re-read under this
 * client's pin before the mint, still points at the generation the caller's
 * `account.doc` names. A sibling's re-point that lands first stands, and the
 * swap throws rather than move the account off it; the caller re-runs its
 * ceremony over a fresh read.
 *
 * @param options {object}   see {@link runClientAnnexGc} for the shared
 *   members ({ was, wasServerUrl, accountSpaceId, account, idStore,
 *   updateKeys, zcapClient }); `ladderSeed` here is the SURVIVING
 *   credential's seed the fresh generation is minted from
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {Promise<ClientAnnexGenerationSwap>}   the fresh annex DID and
 *   what the revoke stage did
 * @throws {Error}   `DelegatedClientsPointerMovedError` when the account log
 *   no longer points at the generation `account.doc` names
 */
export async function swapClientAnnexGeneration({
  was,
  wasServerUrl,
  accountSpaceId,
  account,
  idStore,
  signer,
  zcapClient,
  ladderSeed,
  now = Date.now()
}: {
  was: WasClient
  wasServerUrl: string
  accountSpaceId: string
  account: Pick<PublishedWebvhLog, 'did' | 'doc'>
  idStore: WebvhIdStore
  signer: AccountLogSigner
  zcapClient: ZcapClient
  ladderSeed: Uint8Array
  now?: number
}): Promise<ClientAnnexGenerationSwap> {
  const pointedDid = delegatedClientsPointer({ doc: account.doc })
  if (pointedDid === undefined) {
    throw new Error(
      'clientAnnex: the account document carries no delegated-clients ' +
        'service entry; no generation exists to swap.'
    )
  }
  const { spaceId, generationId } = clientAnnexDidParts({ did: pointedDid })
  const head = await readPublishedLogOrThrow({
    idStore,
    expectedDid: account.did,
    missingMessage:
      'did:webvh: did.jsonl is missing; nothing to point at a client annex.'
  })
  if (delegatedClientsPointer({ doc: head.doc }) !== pointedDid) {
    throw new DelegatedClientsPointerMovedError()
  }
  const oldGeneration = await readClientAnnexGeneration({
    was,
    spaceId,
    generationId,
    pinStore: idStore.pin.store,
    expectedDid: pointedDid
  })
  return replaceClientAnnexGeneration({
    was,
    wasServerUrl,
    accountSpaceId,
    account,
    idStore,
    signer,
    zcapClient,
    ladderSeed,
    clientAnnexSpaceId: spaceId,
    ...(oldGeneration !== undefined ? { oldGeneration } : {}),
    head,
    now
  })
}

/**
 * Refuses the repair unless the auxiliary Space itself answers. The
 * enrolled client reads the Space Metadata object at the Space's `meta`
 * sub-resource. A 404 is absence or a masked unauthorized read, and either
 * way minting into the Space is not this pass's to do; a Space that is gone
 * is replaced by the transient readiness ensure, whose two-probe rule tells
 * the two apart. Any other non-2xx answer says nothing about the Space, and
 * the read itself throws on it, so the repair refuses rather than mint into
 * a Space it could not read.
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.spaceId {string}   the auxiliary annex Space's id
 * @returns {Promise<void>}
 */
async function assertAnnexSpacePresent({
  was,
  spaceId
}: {
  was: WasClient
  spaceId: string
}): Promise<void> {
  const answer = await readSpaceMetadata({ was, annexSpaceId: spaceId })
  if (answer === 'not-found') {
    throw new Error(
      `client annex: the pointed auxiliary Space "${spaceId}" is gone or ` +
        'unreadable; the repair mints nothing into it.'
    )
  }
}

/**
 * Collects one non-pointed generation: revoke its embedded delegation
 * (blind; a genuine `AlreadyRevokedError` reads as success, a delegation
 * expired beyond the clock-skew margin skips the POST, and a refusal the
 * helper cannot read as expiry or signer death throws, keeping the
 * generation and its delegation bytes for the next pass), write the
 * digest from its verified log, delete the collection, then the caller's
 * local cleanup. A generation whose `did.jsonl` does not exist held no
 * visits and is deleted without a digest row; one whose log exists but fails
 * verification is kept and reported (deleting it would destroy the evidence
 * of tampering). One whose log exists, that the account log never pointed
 * at, and that is not GC-quiet is kept untouched and resolves `deferred`:
 * its newest entry is too recent to rule out a sibling client mid-swap onto
 * it, and the next pass meets it quiet. One the account log once pointed at
 * is collected whatever its age.
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.spaceId {string}
 * @param options.generationId {string}
 * @param options.pinStore {ResourceLogPinStore}   the account-log store's
 *   pin store
 * @param options.recordDigest {Function}   see {@link runClientAnnexGc}
 * @param [options.onCollected] {Function}   see {@link runClientAnnexGc}
 * @param options.now {number}   epoch milliseconds, read against the
 *   embedded delegation's own `expires`
 * @param options.accountDoc {PublishedKeyDocument}   the VERIFIED account
 *   document the pass re-read, read against the embedded delegation's proof
 *   key when the server refuses the revocation
 * @param options.everPointed {ReadonlySet<string>}   every annex DID the
 *   re-read account log has ever pointed at
 * @returns {Promise<'collected' | 'deferred'>}
 */
async function collectOneGeneration({
  was,
  spaceId,
  generationId,
  pinStore,
  recordDigest,
  onCollected,
  now,
  accountDoc,
  everPointed
}: {
  was: WasClient
  spaceId: string
  generationId: string
  pinStore: ResourceLogPinStore
  recordDigest: (digest: {
    generationId: string
    firstEntry?: string
    lastEntry?: string
    entryCount?: number
  }) => Promise<void>
  onCollected?: (options: { generationId: string }) => Promise<void>
  now: number
  accountDoc: PublishedKeyDocument
  everPointed: ReadonlySet<string>
}): Promise<'collected' | 'deferred'> {
  // No expectedDid: an orphan was possibly never pointed from this client.
  // The read runs under the store's own chain-head pin; the slot it
  // establishes is the caller's to drop (`onCollected`) with the generation.
  // The log still fully verifies (hash chain, prerotation, rung signatures)
  // -- the digest quotes only a log that resolves.
  const published = await readClientAnnexGeneration({
    was,
    spaceId,
    generationId,
    pinStore
  })

  if (published !== undefined) {
    if (
      !everPointed.has(published.did) &&
      !generationQuiet({ log: published.log, now })
    ) {
      return 'deferred'
    }
    const oldDelegation = embeddedGenerationDelegation({ doc: published.doc })
    if (oldDelegation !== undefined) {
      await revokeTreatingAlreadyRevokedAsSuccess({
        revoke: zcap => was.revoke(zcap),
        delegation: oldDelegation,
        now,
        accountDoc
      })
    }
    // The digest, strictly before the delete: the delete destroys the
    // owner's only per-entry record of the window's visits, so a digest
    // that cannot be written keeps the generation for the next pass.
    await recordDigest({
      generationId,
      firstEntry: published.log[0]?.versionTime,
      lastEntry: published.log[published.log.length - 1]?.versionTime,
      entryCount: published.log.length
    })
  }

  // Idempotent: a re-run's delete of an already-deleted collection resolves.
  await was.space(spaceId).collection(generationId).delete()
  await onCollected?.({ generationId })
  return 'collected'
}
