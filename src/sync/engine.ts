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

/** Per-feed replication status, surfaced to the app's state layer. */
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
  /** Decrypts a pulled body to its plaintext payload (DocCipher). */
  decryptDoc: (envelope: Json) => Promise<Json>
  /**
   * The 412 policy for a mutable (LWW) collection. Absent for insert-only
   * content-addressed collections, whose built-in push settlement covers every
   * conflict.
   */
  resolveConflict?: ResolveConflict
  batchSize?: number

  /** Idempotent space + collection provisioning. */
  ensureProvisioned: () => Promise<void>
  /** Has this feed's lazy migration already run (per-collection milestone)? */
  isMigrated: () => Promise<boolean>
  /** Mint bodies for this feed's still-unlinked local rows. */
  runLazyMigration: (signal: AbortSignal) => Promise<void>
  /** Record this feed's migrated milestone after a successful first migration. */
  stampMigrated: () => Promise<void>
  /** Stamp the replica's last-synced time after a successful cycle. */
  stampLastSynced: () => Promise<void>

  /** Called on every status transition (drives the app's state layer). */
  onStatusChange?: (status: SyncStatus) => void
  /** Called after a pull that applied >= 1 document (triggers the refetch). */
  onPullApplied?: () => void

  backoff?: { baseDelayMs?: number; maxDelayMs?: number }
  /** Schedules a retry; returns a canceller. Defaults to setTimeout. */
  schedule?: (fn: () => void, delayMs: number) => () => void
  /** Jitter source in [0, 1). Defaults to Math.random. */
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
   */
  private async runCycle(signal: AbortSignal): Promise<void> {
    await this.deps.ensureProvisioned()
    if (signal.aborted) {
      return
    }

    const firstCycle = !(await this.deps.isMigrated())
    if (firstCycle) {
      await this.pull(signal)
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

    const applied = await this.pull(signal)
    if (signal.aborted) {
      return
    }

    await this.deps.stampLastSynced()
    if (applied > 0) {
      this.deps.onPullApplied?.()
    }
  }

  private async pull(signal: AbortSignal): Promise<number> {
    const { applied } = await runPull({
      port: this.deps.port,
      store: this.deps.store,
      batchSize: this.batchSize,
      decryptDoc: this.deps.decryptDoc,
      signal
    })
    return applied
  }

  private scheduleRetry(): void {
    const capped = Math.min(
      this.baseDelayMs * 2 ** this.failureCount,
      this.maxDelayMs
    )
    // Full jitter over the first half of the interval keeps N engines from
    // retrying in lockstep.
    const delay = capped + capped * 0.5 * this.random()
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
