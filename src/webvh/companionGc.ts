/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Companion GC: the quarterly wholesale replacement of the companion
 * generation, and the collection of everything it leaves behind.
 *
 * The ceremony has two halves with different rhythms:
 *
 * - The SWAP runs on the fixed quarterly cadence (90 days, at the first
 *   durable login after the period elapses -- coarse on purpose, so the
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
 * - The COLLECT fan-out is predicate-driven and runs at every durable login:
 *   every `gen-` collection the pointer does not name -- the generation a
 *   swap just superseded, a torn GC's leftover, a torn signup's orphan, a
 *   double-genesis loser -- gets identical treatment (revoke its embedded
 *   delegation blind, reading the server's 400 already-revoked answer as
 *   success; write the digest; delete), so a GC torn anywhere resumes at the
 *   next login instead of waiting a quarter. Failures are collected per
 *   generation and never abort the fan-out: a partial pass is a resumable
 *   success.
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
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import type { IDelegatedZcap, WasClient } from '@interop/was-client'
import type { ResourceLogPinStore } from '../resourceLog/pin.js'
import {
  companionDidParts,
  companionLogPinId,
  companionLogStore,
  delegatedClientsPointer,
  embeddedGenerationDelegation,
  ensureGenerationDelegationCurrent,
  GENERATION_ID_PREFIX,
  mintCredentialCompanionGeneration,
  mintGenerationDelegation,
  setDelegatedClientsPointer
} from './companion.js'
import { readPublishedLog } from './didWebvh.js'
import type {
  ClientWebvhUpdateKeys,
  PublishedWebvhLog,
  WebvhIdStore
} from './didWebvh.js'
import { accountLogPinId } from './verifyLog.js'

/**
 * The fixed GC cadence: a generation is replaced at the first durable login
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
 * different companion DID than the entry before it (or the first entry, when
 * the pointer has been there since genesis). This is the cadence's clock --
 * "the pointer-update entry is the record" -- and it is read off the log a
 * durable login has already verified, so the cadence costs no extra fetch
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
      // A document with no pointer has no companion posture; a later entry
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
export function companionGcDue({
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
 * margin. Applies to the POINTED generation only (an unpointed generation
 * authorizes nothing under pointer equality, so nothing inside it ever
 * defers deletion). An unparseable `versionTime` reads as not quiet: the
 * swap defers rather than abandoning a possibly-live visit.
 *
 * @param options {object}
 * @param options.log {DIDLog}   the pointed generation's VERIFIED companion
 *   log
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
 * What the swap half of one GC pass did. `replaced` is the successful swap;
 * `not-due` and `deferred-live` are the two healthy skips (cadence and quiet
 * bound); `no-pointer` means the account has no companion posture (the whole
 * pass no-ops -- without a pointer there is no auxiliary Space to list);
 * `no-ladder-seed` means the swap was due but the login held no ladder seed
 * to mint with (a non-standing record); `failed` means a swap stage threw --
 * reported in `failed` under the pointed generation's id, with the collect
 * fan-out still run.
 */
export type CompanionGcSwapOutcome =
  | 'replaced'
  | 'not-due'
  | 'deferred-live'
  | 'no-pointer'
  | 'no-ladder-seed'
  | 'failed'

/**
 * One GC pass's report: the swap outcome, the companion DID the account
 * points at after the pass, the generation ids collected (revoked, digested,
 * deleted), and the per-generation failures. A report with `failed` entries
 * is a resumable success -- the next durable login's pass picks up exactly
 * the generations still listed.
 */
export interface CompanionGcReport {
  swap: CompanionGcSwapOutcome
  pointedDid?: string
  collected: string[]
  failed: Array<{ generationId: string; error: unknown }>
}

/**
 * One companion GC pass: the quarterly swap when due and quiet, then the
 * predicate-driven collect fan-out over every non-pointed `gen-` collection.
 * See the module header for the stage order and its load-bearing constraints.
 *
 * Convergence: every stage detects completion from durable state. A re-run
 * after a tear re-POSTs the revocation blind (400 already-revoked reads as
 * success), re-writes the digest (the deterministic payload id collapses the
 * second row at read time), and re-runs the idempotent delete; a swap torn
 * before its re-point leaves an unpointed fresh generation the same fan-out
 * collects.
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
 *   seed; absent, a due swap reports `no-ladder-seed` and only the collect
 *   fan-out runs
 * @param options.recordDigest {Function}
 *   `({ generationId, firstEntry, lastEntry, entryCount }) => Promise<void>`
 *   -- writes the GenerationCollect wallet-activity row; called before the
 *   delete, and a throw keeps the generation for the next pass
 * @param [options.onCollected] {Function}
 *   `({ generationId }) => Promise<void>` -- local cleanup after a
 *   generation's delete (the caller's companion pin-slot drop); a throw is
 *   reported but cannot be retried (the collection is already gone)
 * @param [options.pinStore] {ResourceLogPinStore}   chain-head pins for the
 *   account-log re-point and the pointed generation's read
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {Promise<CompanionGcReport>}
 */
export async function runCompanionGc({
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
  pinStore,
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
  pinStore?: ResourceLogPinStore
  now?: number
}): Promise<CompanionGcReport> {
  const pointedDid = delegatedClientsPointer({ doc: account.doc })
  if (pointedDid === undefined) {
    return { swap: 'no-pointer', collected: [], failed: [] }
  }
  const { spaceId } = companionDidParts({ did: pointedDid })
  const failed: CompanionGcReport['failed'] = []

  // 1. The swap, when the quarterly cadence is due. Its own failure is
  // collected under the pointed generation's id rather than aborting the
  // pass: the collect fan-out below still cleans what it can, and the next
  // durable login re-attempts the swap from durable state.
  let swap: CompanionGcSwapOutcome = 'not-due'
  let currentDid = pointedDid
  if (companionGcDue({ log: account.log, now })) {
    swap =
      ladderSeed === undefined
        ? 'no-ladder-seed'
        : await (async (): Promise<CompanionGcSwapOutcome> => {
            const oldParts = companionDidParts({ did: pointedDid })
            try {
              const old = await readCompanionGeneration({
                was,
                spaceId,
                generationId: oldParts.generationId,
                expectedDid: pointedDid,
                pinStore
              })
              if (
                old === undefined ||
                !generationQuiet({ log: old.log, now })
              ) {
                // A missing pointed log is a broken state the collect
                // fan-out cannot touch (the pointer still names it); defer
                // rather than swap onto a generation this pass could not
                // read as quiet.
                return old === undefined ? 'failed' : 'deferred-live'
              }
              currentDid = await replaceCompanionGeneration({
                was,
                wasServerUrl,
                accountSpaceId,
                account,
                idStore,
                updateKeys,
                zcapClient,
                ladderSeed,
                companionSpaceId: spaceId,
                oldGeneration: old,
                pinStore
              })
              return 'replaced'
            } catch (err) {
              failed.push({ generationId: oldParts.generationId, error: err })
              return 'failed'
            }
          })()
  }

  // 2. The collect fan-out: every `gen-` collection the (possibly fresh)
  // pointer does not name. Orphan discovery is a plain prefix match over the
  // auxiliary Space's collection listing -- no registry of generations
  // exists anywhere -- and a torn GC's old generation, a torn signup's
  // orphan, and a double-genesis loser get identical treatment.
  const currentGenerationId = companionDidParts({
    did: currentDid
  }).generationId
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
  await Promise.all(
    stale.map(async generationId => {
      try {
        await collectOneGeneration({
          was,
          spaceId,
          generationId,
          recordDigest,
          onCollected
        })
        collected.push(generationId)
      } catch (err) {
        failed.push({ generationId, error: err })
      }
    })
  )

  return { swap, pointedDid: currentDid, collected, failed }
}

/**
 * Reads and verifies one generation's published companion log, or resolves
 * undefined when its `did.jsonl` does not exist (a generation that never
 * finished minting, or whose collection outlived a torn delete).
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.spaceId {string}   the auxiliary companion Space's id
 * @param options.generationId {string}
 * @param [options.expectedDid] {string}
 * @param [options.pinStore] {ResourceLogPinStore}
 * @returns {Promise<PublishedWebvhLog | undefined>}
 */
async function readCompanionGeneration({
  was,
  spaceId,
  generationId,
  expectedDid,
  pinStore
}: {
  was: WasClient
  spaceId: string
  generationId: string
  expectedDid?: string
  pinStore?: ResourceLogPinStore
}): Promise<PublishedWebvhLog | undefined> {
  const store = companionLogStore({ was, spaceId, generationId })
  return readPublishedLog({
    idStore: store as WebvhIdStore,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore !== undefined
      ? { pinStore, logId: companionLogPinId({ spaceId, generationId }) }
      : {})
  })
}

/**
 * The swap's four stages, in the fixed order: mint + genesis; install the
 * fresh generation's delegation service entry; revoke the old generation's
 * delegation; re-point the account document. Returns the fresh companion
 * DID. The digest and the delete are deliberately NOT here -- once the
 * re-point lands, the old generation is an ordinary non-pointed `gen-`
 * collection and the standing collect fan-out handles it, which is also
 * what makes a swap torn after its re-point resume for free.
 *
 * @param options {object}   see {@link runCompanionGc}, plus:
 * @param options.companionSpaceId {string}   the auxiliary Space's id
 * @param options.oldGeneration {PublishedWebvhLog}   the pointed
 *   generation's verified log, read by the quiet check
 * @returns {Promise<string>}   the fresh companion DID
 */
async function replaceCompanionGeneration({
  was,
  wasServerUrl,
  accountSpaceId,
  account,
  idStore,
  updateKeys,
  zcapClient,
  ladderSeed,
  companionSpaceId,
  oldGeneration,
  pinStore
}: {
  was: WasClient
  wasServerUrl: string
  accountSpaceId: string
  account: Pick<PublishedWebvhLog, 'did' | 'doc' | 'log'>
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  zcapClient: ZcapClient
  ladderSeed: Uint8Array
  companionSpaceId: string
  oldGeneration: PublishedWebvhLog
  pinStore?: ResourceLogPinStore
}): Promise<string> {
  // 1. Mint + genesis: a fresh generation in the existing auxiliary Space
  // (the typed-Space ensure no-ops on it; the controller argument is only
  // read when the Space does not exist). The genesis commits the minting
  // credential's rung-0 hash for the fresh generation id.
  const minted = await mintCredentialCompanionGeneration({
    was,
    wasServerUrl,
    spaceId: companionSpaceId,
    controller: account.did,
    ladderSeed
  })

  // 2. Install the fresh generation's delegation service entry (the
  // install-when-absent half of the renew-precedes-mint helper), the
  // delegation signed by this enrolled client's promoted account key and the
  // installing companion entry by the credential's rung 0.
  await ensureGenerationDelegationCurrent({
    store: companionLogStore({
      was,
      spaceId: companionSpaceId,
      generationId: minted.generationId
    }),
    ladderSeed,
    generationId: minted.generationId,
    mintGenerationDelegation: async ({ companionDid }) =>
      mintGenerationDelegation({
        zcapClient,
        wasServerUrl,
        spaceId: accountSpaceId,
        companionDid
      }),
    expectedDid: minted.did,
    ...(pinStore !== undefined
      ? {
          pinStore,
          logId: companionLogPinId({
            spaceId: companionSpaceId,
            generationId: minted.generationId
          })
        }
      : {})
  })

  // 3. Revoke the old generation's delegation, before the re-point (the
  // revocation POST verifies against the currently resolved document, so it
  // only chains while the pointer still names the old generation) and
  // before the delete (the POST needs bytes the delete destroys).
  const oldDelegation = embeddedGenerationDelegation({ doc: oldGeneration.doc })
  if (oldDelegation !== undefined) {
    await revokeTreatingAlreadyRevokedAsSuccess({
      was,
      delegation: oldDelegation
    })
  }

  // 4. Re-point the account document at the fresh generation. On a
  // conforming server the pointer equality itself kills the old
  // generation's delegations; the explicit revoke above covered the
  // fail-open case.
  await setDelegatedClientsPointer({
    idStore,
    updateKeys,
    companionDid: minted.did,
    expectedDid: account.did,
    ...(pinStore !== undefined
      ? { pinStore, logId: accountLogPinId({ spaceId: accountSpaceId }) }
      : {})
  })
  return minted.did
}

/**
 * Collects one non-pointed generation: revoke its embedded delegation
 * (blind; the server's 400 already-revoked answer reads as success), write
 * the digest from its verified log, delete the collection, then the
 * caller's local cleanup. A generation whose `did.jsonl` does not exist
 * held no visits and is deleted without a digest row; one whose log exists
 * but fails verification is kept and reported (deleting it would destroy
 * the evidence of tampering).
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.spaceId {string}
 * @param options.generationId {string}
 * @param options.recordDigest {Function}   see {@link runCompanionGc}
 * @param [options.onCollected] {Function}   see {@link runCompanionGc}
 * @returns {Promise<void>}
 */
async function collectOneGeneration({
  was,
  spaceId,
  generationId,
  recordDigest,
  onCollected
}: {
  was: WasClient
  spaceId: string
  generationId: string
  recordDigest: (digest: {
    generationId: string
    firstEntry?: string
    lastEntry?: string
    entryCount?: number
  }) => Promise<void>
  onCollected?: (options: { generationId: string }) => Promise<void>
}): Promise<void> {
  // No pin, no expectedDid: an orphan was possibly never pointed from this
  // client, and its chain-head slot is about to be dropped either way. The
  // log still fully verifies (hash chain, prerotation, rung signatures) --
  // the digest quotes only a log that resolves.
  const published = await readCompanionGeneration({
    was,
    spaceId,
    generationId
  })

  if (published !== undefined) {
    const oldDelegation = embeddedGenerationDelegation({ doc: published.doc })
    if (oldDelegation !== undefined) {
      await revokeTreatingAlreadyRevokedAsSuccess({
        was,
        delegation: oldDelegation
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
}

/**
 * Submits the revocation of a generation delegation, reading the server's
 * 400 answer as success: an already-revoked chain (a resumed GC's blind
 * re-POST) and an expired delegation (which no longer needs revoking) both
 * land there, and the revocation protocol exposes no read endpoint to
 * distinguish them beforehand. Matched on `err.name` -- error classes do not
 * survive crossing package copies.
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.delegation {IZcap}
 * @returns {Promise<void>}
 */
async function revokeTreatingAlreadyRevokedAsSuccess({
  was,
  delegation
}: {
  was: WasClient
  delegation: IZcap
}): Promise<void> {
  try {
    await was.revoke(delegation as unknown as IDelegatedZcap)
  } catch (err) {
    if ((err as { name?: string }).name === 'ValidationError') {
      return
    }
    throw err
  }
}
