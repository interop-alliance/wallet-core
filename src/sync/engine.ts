/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * `SyncEngine` -- drives one `(replica, collection)` feed through the pull/push
 * cycle. Single-flight (concurrent `sync()` calls coalesce and set a rerun
 * flag), migrate-once (the initial pull-before-migrate ordering that keeps
 * envelope minting from creating server-side duplicates), and self-healing via
 * exponential backoff + jitter on failure.
 *
 * All side effects are injected ({@link SyncEngineDeps}) so the engine runs
 * anywhere -- browser, Node, or React Native -- with a fake port, an in-memory
 * store, and a non-firing scheduler. The consuming app wires the real port,
 * DocCipher, provisioning, and lazy migration.
 */
import type { Json, ResolveConflict, SyncStore, WasSyncPort } from './types.js'
import { runPull } from './pull.js'
import { runPush } from './push.js'

/**
 * Per-feed replication status, surfaced to the app's state layer.
 */
export type SyncStatus = 'idle' | 'syncing' | 'synced' | 'error'

const DEFAULT_BATCH_SIZE = 100
const DEFAULT_BASE_DELAY_MS = 1_000
const DEFAULT_MAX_DELAY_MS = 60_000

/**
 * Everything the engine needs, injected. The pure protocol ({@link WasSyncPort},
 * {@link SyncStore}) plus the app-supplied seams: provisioning, the
 * migrated/last-synced stamps, decryption, and status/refetch callbacks. The
 * `schedule` / `random` seams make backoff deterministic under test.
 */
export interface SyncEngineDeps {
  port: WasSyncPort
  store: SyncStore
  /**
   * Decrypts a pulled body to its plaintext payload (DocCipher).
   */
  decryptDoc: (envelope: Json) => Promise<Json>
  /**
   * The collection's payload guard, when it has one: a pulled document that
   * decrypts but fails it is stored without being projected (see `pull.ts`).
   */
  validatePayload?: (payload: Json) => boolean
  /**
   * The 412 policy for a mutable (LWW) collection. Absent for insert-only
   * content-addressed collections, whose built-in push settlement covers every
   * conflict.
   */
  resolveConflict?: ResolveConflict
  batchSize?: number

  /**
   * Idempotent space + collection provisioning. For an encrypted collection
   * this MUST include publishing the collection's encryption descriptor with
   * its key-epoch roster (the wallet Space two-step: `provisionWalletSpace`,
   * then `ensureWalletSpaceEpochs`; `walletSpaceProvisioner` in
   * `@interop/wallet-core/keys` builds the closure that runs both). The
   * engine runs it ahead of every cycle's migration sweep and push, which is
   * what enforces the descriptor-before-first-content-push ordering
   * invariant: no envelope reaches the feed sealed under an epoch the
   * published descriptor does not carry.
   *
   * The engine memoizes it: once a call has resolved, later cycles skip the
   * seam until {@link SyncEngine.invalidateProvisioning} is called, so the
   * ordering stays structural on every cycle while only the first cycle pays
   * the descriptor round trip. A call that throws is not memoized, and the
   * next cycle runs it again. The caller invalidates whenever the account's
   * provisioning state can have changed under the replica: an unlock with a
   * fresh key set, a re-bind to a different account pointer, or a recovery.
   */
  ensureProvisioned: () => Promise<void>
  /**
   * The eager minter's create-loss re-mint, run on EVERY cycle between
   * provisioning and the migration sweep, so no pending envelope sealed under
   * a losing epoch reaches the push: the consumer builds its cipher from the
   * descriptor provisioning settled on and runs `remintPendingEnvelopes`
   * (`remint.ts`) with it. The re-mint decides per row from the envelope
   * itself, so in the settled case the call is free. A lazy minter, whose
   * envelopes are always minted under the settled descriptor, leaves it
   * absent.
   */
  remintPending?: (signal: AbortSignal) => Promise<void>
  /**
   * Has this feed's lazy migration already run (per-collection milestone)?
   */
  isMigrated: () => Promise<boolean>
  /**
   * Mint bodies for this feed's still-unlinked local rows.
   */
  runLazyMigration: (signal: AbortSignal) => Promise<void>
  /**
   * Record this feed's migrated milestone after a successful first migration.
   */
  stampMigrated: () => Promise<void>
  /**
   * Stamp the replica's last-synced time after a successful cycle.
   */
  stampLastSynced: () => Promise<void>

  /**
   * Called on every status transition (drives the app's state layer).
   */
  onStatusChange?: (status: SyncStatus) => void
  /**
   * Called at the end of a cycle whose pulls applied >= 1 document in total
   * (triggers the refetch). A first cycle pulls twice -- before the migration
   * sweep and after the push -- and both counts feed this. Not called when the
   * cycle unwinds early on an abort.
   */
  onPullApplied?: () => void

  backoff?: { baseDelayMs?: number; maxDelayMs?: number }
  /**
   * Schedules a retry; returns a canceller. Defaults to setTimeout.
   */
  schedule?: (fn: () => void, delayMs: number) => () => void
  /**
   * Jitter source in [0, 1). Defaults to Math.random.
   */
  random?: () => number
}

function defaultSchedule(fn: () => void, delayMs: number): () => void {
  const timer = setTimeout(fn, delayMs)
  return () => clearTimeout(timer)
}

export class SyncEngine {
  status: SyncStatus = 'idle'

  private readonly batchSize: number
  private readonly baseDelayMs: number
  private readonly maxDelayMs: number
  private readonly schedule: (fn: () => void, delayMs: number) => () => void
  private readonly random: () => number

  private running = false
  private rerunRequested = false
  private stopped = false
  private failureCount = 0
  private currentRun: Promise<void> | null = null
  private abortController: AbortController | null = null
  private cancelRetry: (() => void) | null = null
  private provisioned = false
  private provisioningGeneration = 0

  constructor(private readonly deps: SyncEngineDeps) {
    this.batchSize = deps.batchSize ?? DEFAULT_BATCH_SIZE
    this.baseDelayMs = deps.backoff?.baseDelayMs ?? DEFAULT_BASE_DELAY_MS
    this.maxDelayMs = deps.backoff?.maxDelayMs ?? DEFAULT_MAX_DELAY_MS
    this.schedule = deps.schedule ?? defaultSchedule
    this.random = deps.random ?? Math.random
  }

  /**
   * Requests a sync. Single-flight: if a cycle is in flight this only flags a
   * rerun (so writes that land mid-cycle are not lost) and resolves with the
   * in-flight run; otherwise it starts a fresh run. Never rejects -- failures
   * settle into `status = 'error'` plus a scheduled backoff retry, per the
   * local-first invariant (sync must never surface as a rejected write).
   *
   * @returns {Promise<void>}
   */
  sync(): Promise<void> {
    if (this.stopped) {
      return Promise.resolve()
    }
    if (this.running && this.currentRun !== null) {
      this.rerunRequested = true
      return this.currentRun
    }
    this.currentRun = this.run()
    return this.currentRun
  }

  /**
   * Forgets that provisioning was observed complete, so the next cycle runs
   * the `ensureProvisioned` seam again. Call it whenever the account's
   * provisioning state can have changed under this replica (a fresh key set,
   * a re-bound account pointer, a recovery); the memo is otherwise held for
   * the engine's life.
   */
  invalidateProvisioning(): void {
    this.provisioned = false
    // An invalidation that lands while a provisioning call is in flight must
    // outlive it: that call observed the state as it stood BEFORE the
    // invalidation, so its completion may not set the memo.
    this.provisioningGeneration += 1
  }

  /**
   * Stops the engine: aborts any in-flight cycle (the injected signal unwinds
   * pull/push between pages/rows), cancels a pending retry, and resets to idle.
   * The caller drops the cached agents/ciphers so key material does not outlive
   * the unlocked session.
   */
  stop(): void {
    this.stopped = true
    this.abortController?.abort()
    this.clearRetry()
    this.setStatus('idle')
  }

  private async run(): Promise<void> {
    this.running = true
    this.clearRetry()
    this.setStatus('syncing')
    const controller = new AbortController()
    this.abortController = controller
    const { signal } = controller
    try {
      do {
        this.rerunRequested = false
        await this.runCycle(signal)
      } while (this.rerunRequested && !signal.aborted && !this.stopped)

      if (!signal.aborted && !this.stopped) {
        this.failureCount = 0
        this.setStatus('synced')
      }
    } catch {
      // Local-first: an engine failure is never fatal. A stop-driven abort is
      // not an error; any other failure flips to `error` and schedules a retry.
      if (!signal.aborted && !this.stopped) {
        this.setStatus('error')
        this.scheduleRetry()
      }
    } finally {
      this.running = false
      this.currentRun = null
    }
  }

  /**
   * One full replication cycle. On the very first run (never migrated) it pulls
   * before the sweep so existing local rows hash-link to any bodies already on
   * the server -- the sweep then only encrypts genuinely-new records
   * (re-encrypting an existing one would mint a different content id and leave a
   * permanent server duplicate). The unlinked-record sweep (`runLazyMigration`)
   * runs on EVERY cycle, not just the first, so records that enter the replica
   * outside the synced write path -- an import, or a write whose minting failed
   * and fell back to a plain insert -- are still picked up and pushed (it is a
   * cheap no-op when there are none). Steady state is sweep-then-push-then-pull:
   * our own writes echo back in the same cycle's pull, idempotently.
   *
   * `ensureProvisioned` runs first (memoized once it has resolved, see its doc
   * on {@link SyncEngineDeps}): everything that mints or pushes envelopes is
   * downstream of it, which is what enforces the
   * descriptor-before-first-content-push invariant. The optional
   * `remintPending` runs right after it, ahead of the sweep and the push, so
   * an eager minter's envelopes sealed under a losing epoch are re-minted
   * under the settled descriptor before anything reaches the feed.
   */
  private async runCycle(signal: AbortSignal): Promise<void> {
    if (!this.provisioned) {
      const generation = this.provisioningGeneration
      await this.deps.ensureProvisioned()
      if (generation === this.provisioningGeneration) {
        this.provisioned = true
      }
    }
    if (signal.aborted) {
      return
    }
    if (this.deps.remintPending) {
      await this.deps.remintPending(signal)
      if (signal.aborted) {
        return
      }
    }

    // Both of a first cycle's pulls count toward the same refetch. The
    // pre-migration pull is where a freshly enrolled replica applies the whole
    // remote feed; the post-push pull then applies 0, so gating on it alone
    // would never fire the callback and the app's UI store would stay stale.
    let appliedTotal = 0

    const firstCycle = !(await this.deps.isMigrated())
    if (firstCycle) {
      appliedTotal += await this.pull(signal)
      if (signal.aborted) {
        return
      }
    }

    await this.deps.runLazyMigration(signal)
    if (signal.aborted) {
      return
    }
    if (firstCycle) {
      await this.deps.stampMigrated()
      if (signal.aborted) {
        return
      }
    }

    const { conflictsResolved } = await runPush({
      port: this.deps.port,
      store: this.deps.store,
      resolveConflict: this.deps.resolveConflict,
      signal
    })
    if (signal.aborted) {
      return
    }
    // A resolved last-write-wins conflict may leave a row dirty (local-wins
    // re-encrypt); rerun this run so the re-push settles instead of waiting for
    // the next external trigger. Idempotent once the conflict clears.
    if (conflictsResolved > 0) {
      this.rerunRequested = true
    }

    appliedTotal += await this.pull(signal)
    if (signal.aborted) {
      return
    }

    await this.deps.stampLastSynced()
    if (appliedTotal > 0) {
      this.deps.onPullApplied?.()
    }
  }

  private async pull(signal: AbortSignal): Promise<number> {
    const { applied } = await runPull({
      port: this.deps.port,
      store: this.deps.store,
      batchSize: this.batchSize,
      decryptDoc: this.deps.decryptDoc,
      validatePayload: this.deps.validatePayload,
      signal
    })
    return applied
  }

  private scheduleRetry(): void {
    const capped = Math.min(
      this.baseDelayMs * 2 ** this.failureCount,
      this.maxDelayMs
    )
    // Jitter over the upper half of the capped interval keeps N engines from
    // retrying in lockstep, while staying INSIDE the cap: the delay lands in
    // [capped / 2, capped], so it never exceeds `maxDelayMs`.
    const delay = capped * (0.5 + 0.5 * this.random())
    this.failureCount += 1
    this.cancelRetry = this.schedule(() => {
      this.cancelRetry = null
      void this.sync()
    }, delay)
  }

  private clearRetry(): void {
    if (this.cancelRetry !== null) {
      this.cancelRetry()
      this.cancelRetry = null
    }
  }

  private setStatus(status: SyncStatus): void {
    if (this.status === status) {
      return
    }
    this.status = status
    this.deps.onStatusChange?.(status)
  }
}
