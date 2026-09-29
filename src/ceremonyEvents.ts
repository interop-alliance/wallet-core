/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The ceremony event channel: one structured event convention over the
 * `Logger` seam, so a reader of the diagnostics stream can ask which
 * ceremonies ran, which stage each reached, and which mender fired, without
 * knowing any site's prose. Three kinds of event, each with a static message
 * and reserved `data` keys:
 *
 * - `'ceremony stage'` (debug): `{ ceremony, run, stage, ...detail }`. The
 *   stage is complete as of now; `detail.prior: true` marks a stage that
 *   detected its own prior completion.
 * - `'ceremony outcome'` (level by outcome): `{ ceremony, run, outcome,
 *   ...detail }`, plus `errorName` and `err` on `refused`, on `failed`, and
 *   on a `noop` classified from a pending throw. At most one per run. A run
 *   torn by tab death emits stages and no outcome.
 * - `'ceremony mender'` (level by outcome): `{ invariant, outcome,
 *   errorName?, ...detail, ceremony?, run?, err? }`, one per reported
 *   mend entry.
 *
 * The events are additive diagnostics beside a ceremony's outcome object and
 * typed errors, which stay the contract: no production code branches on one.
 * Every helper catches internally and never throws, so a log line never
 * fails a ceremony. `detail` is scalar-only, so an object, an array, or a
 * record body cannot typecheck into an event.
 *
 * A root-level leaf beside `log.ts`. It takes the vocabularies it names as
 * type-only imports and two import-free leaves at runtime, so every layer may
 * import it.
 */
import { errorNameOf } from './errorName.js'
import {
  LABEL_STRIPPED_CHARACTERS,
  ONBOARDING_LABEL_MAX_LENGTH
} from './labelText.js'
import type { Logger } from './log.js'
import type { MendReportEntry } from './menders/types.js'
import type { MendOutcomeKind } from './menders/vocabulary.js'
import type { CeremonyId } from './space/ceremony.js'

/**
 * A ceremony run's outcome: the mend outcome vocabulary, one closed set with
 * one level map (`clean` info, `noop` debug, `partial` warn, `refused` warn,
 * `failed` error).
 */
export type CeremonyOutcome = MendOutcomeKind

/**
 * The `data` keys the helpers own. A detail object cannot set one: the type
 * rejects it, and the helpers drop one smuggled past the type.
 */
const RESERVED_KEYS: ReadonlySet<string> = new Set([
  'ceremony',
  'run',
  'stage',
  'outcome',
  'invariant',
  'errorName',
  'err'
])

/**
 * An event's per-site detail: scalars only, the reserved keys excluded.
 * Counts, enum values, and permitted identifiers; never a record body, a
 * secret, or free-form server text.
 */
export type CeremonyDetail = {
  ceremony?: never
  run?: never
  stage?: never
  outcome?: never
  invariant?: never
  errorName?: never
  err?: never
} & Record<string, string | number | boolean | undefined>

/**
 * One ceremony run's emitter, minted by {@link ceremonyEvents} at the run's
 * public entry point.
 */
export interface CeremonyEmitter<Stage extends string> {
  /**
   * The run's `run` id, stamped on every event of the run.
   */
  readonly runId: string
  /**
   * Emits `'ceremony stage'` at debug. A stage already emitted in this run is
   * not emitted again, so a CAS retry that re-walks a stage stays silent.
   */
  stage(stage: Stage, detail?: CeremonyDetail): void
  /**
   * Emits `'ceremony outcome'` at the outcome's level. `err`, when passed,
   * rides `data.err` with its `errorName` beside it. Only the first call in a
   * run emits.
   */
  outcome(
    outcome: CeremonyOutcome,
    detail?: CeremonyDetail,
    err?: unknown
  ): void
  /**
   * The boundary combinator: awaits `fn`, emits the outcome `classify`
   * derives from its result (`clean` when omitted), and returns the result. On a throw it emits
   * `noop` when the error's name is one of the ceremony's `pending` names,
   * `refused` when it is one of its `refusals`, and `failed` otherwise, then
   * rethrows.
   */
  run<T>(
    fn: () => Promise<T>,
    classify?: (result: T) => {
      outcome: CeremonyOutcome
      detail?: CeremonyDetail
    }
  ): Promise<T>
}

/**
 * The logger method each outcome emits through.
 */
const OUTCOME_LEVELS: Record<CeremonyOutcome, keyof Logger> = {
  clean: 'info',
  noop: 'debug',
  partial: 'warn',
  refused: 'warn',
  failed: 'error'
}

/**
 * A short random id naming one run. It correlates the events of a run and
 * carries no authority, so a non-cryptographic source is enough, and it
 * cannot throw on a platform without a WebCrypto global.
 *
 * @returns {string}
 */
function mintRunId(): string {
  return Math.random().toString(36).slice(2, 10).padEnd(8, '0')
}

/**
 * Copies a detail's scalar values, dropping every reserved key and every
 * value that is not a scalar. A throwing getter drops its own key alone.
 *
 * @param detail {CeremonyDetail | undefined}
 * @returns {Record<string, string | number | boolean>}
 */
function scalarDetail(
  detail: CeremonyDetail | undefined
): Record<string, string | number | boolean> {
  const copied: Record<string, string | number | boolean> = {}
  if (detail === undefined || detail === null || typeof detail !== 'object') {
    return copied
  }
  let keys: string[]
  try {
    keys = Object.keys(detail)
  } catch {
    return copied
  }
  for (const key of keys) {
    if (RESERVED_KEYS.has(key)) {
      continue
    }
    try {
      const value: unknown = (detail as Record<string, unknown>)[key]
      if (
        typeof value === 'string' ||
        typeof value === 'number' ||
        typeof value === 'boolean'
      ) {
        copied[key] = value
      }
    } catch {
      // A throwing getter degrades to an event without that key.
    }
  }
  return copied
}

/**
 * Emits one event, swallowing anything the logger throws.
 *
 * @param options {object}
 * @param options.log {Logger}
 * @param options.level {keyof Logger}
 * @param options.msg {string}
 * @param options.data {Record<string, unknown>}
 */
function emit({
  log,
  level,
  msg,
  data
}: {
  log: Logger
  level: keyof Logger
  msg: string
  data: Record<string, unknown>
}): void {
  try {
    log[level](msg, data)
  } catch {
    // A log line never fails a ceremony.
  }
}

/**
 * The name a thrown value carries, or `'Error'` when even reading it throws.
 *
 * @param err {unknown}
 * @returns {string}
 */
function safeErrorName(err: unknown): string {
  try {
    return errorNameOf(err)
  } catch {
    return 'Error'
  }
}

/**
 * Makes a server-served identifier (a collection name from a listing, a
 * generation id from the annex listing) safe to carry in event detail: the
 * control and bidi characters the onboarding label sanitizer strips are
 * stripped, then the value is cut to {@link ONBOARDING_LABEL_MAX_LENGTH} code
 * points with a `...` suffix. Unlike the label sanitizer it never refuses,
 * since a log line never fails a ceremony.
 *
 * @param value {string}
 * @returns {string}
 */
export function servedIdentifier(value: string): string {
  try {
    const stripped = String(value).replace(LABEL_STRIPPED_CHARACTERS, '')
    const codePoints = [...stripped]
    if (codePoints.length <= ONBOARDING_LABEL_MAX_LENGTH) {
      return stripped
    }
    return `${codePoints.slice(0, ONBOARDING_LABEL_MAX_LENGTH).join('')}...`
  } catch {
    return ''
  }
}

/**
 * Mints one run's emitter at a ceremony's public entry point, outside any
 * CAS-retry wrapper. `Stage` is the ceremony's exported stage union.
 * `refusals` names the typed refusal classes (by `err.name`, which survives a
 * linked or duplicated install where `instanceof` does not) whose throw
 * classifies as `refused` rather than `failed`. `pending` names the throws a
 * caller polls through ("not ready yet, retry"), which classify as `noop` so
 * an ordinary wait logs at debug.
 *
 * @param options {object}
 * @param options.ceremony {CeremonyId}
 * @param options.log {Logger}   the emitting module's logger
 * @param [options.refusals] {ReadonlyArray<string>}   the ceremony's
 *   refusal class names
 * @param [options.pending] {ReadonlyArray<string>}   the ceremony's
 *   not-ready-yet class names
 * @returns {CeremonyEmitter<Stage>}
 */
export function ceremonyEvents<Stage extends string>({
  ceremony,
  log,
  refusals = [],
  pending = []
}: {
  ceremony: CeremonyId
  log: Logger
  refusals?: ReadonlyArray<string>
  pending?: ReadonlyArray<string>
}): CeremonyEmitter<Stage> {
  const runId = mintRunId()
  const emittedStages = new Set<string>()
  let outcomeEmitted = false

  function stage(name: Stage, detail?: CeremonyDetail): void {
    if (emittedStages.has(name)) {
      return
    }
    emittedStages.add(name)
    emit({
      log,
      level: 'debug',
      msg: 'ceremony stage',
      data: { ceremony, run: runId, stage: name, ...scalarDetail(detail) }
    })
  }

  function outcome(
    kind: CeremonyOutcome,
    detail?: CeremonyDetail,
    err?: unknown
  ): void {
    if (outcomeEmitted) {
      return
    }
    outcomeEmitted = true
    const data: Record<string, unknown> = {
      ceremony,
      run: runId,
      outcome: kind,
      ...scalarDetail(detail)
    }
    if (err !== undefined) {
      data.errorName = safeErrorName(err)
      data.err = err
    }
    emit({ log, level: OUTCOME_LEVELS[kind], msg: 'ceremony outcome', data })
  }

  async function run<T>(
    fn: () => Promise<T>,
    classify: (result: T) => {
      outcome: CeremonyOutcome
      detail?: CeremonyDetail
    } = () => ({ outcome: 'clean' })
  ): Promise<T> {
    let result: T
    try {
      result = await fn()
    } catch (err) {
      const name = safeErrorName(err)
      if (pending.includes(name)) {
        outcome('noop', undefined, err)
      } else {
        outcome(refusals.includes(name) ? 'refused' : 'failed', undefined, err)
      }
      throw err
    }
    try {
      const classified = classify(result)
      outcome(classified.outcome, classified.detail)
    } catch {
      // A throwing classifier emits no outcome rather than a wrong one.
    }
    return result
  }

  return { runId, stage, outcome, run }
}

/**
 * Emits one `'ceremony mender'` event from a landed mend report entry:
 * `invariant`, `outcome`, `errorName` when present, the entry's detail, and
 * `ceremony`, `run`, and `err` when passed. The entry's `ceremonies` array is
 * not carried. A `noop` entry emits at debug. Every site that reports an entry
 * passes it here unchanged, so an event cannot diverge from its report.
 *
 * @param options {object}
 * @param options.log {Logger}   the reporting site's logger
 * @param options.entry {MendReportEntry}   the entry as reported
 * @param [options.ceremony] {string}   the ceremony that just ran, on a
 *   ceremony-tail entry
 * @param [options.run] {string}   that ceremony run's `run` id, where the
 *   site holds its emitter
 * @param [options.err] {unknown}   the thrown value, where the site holds it
 */
export function menderEvent<Ceremony extends string = CeremonyId>({
  log,
  entry,
  ceremony,
  run,
  err
}: {
  log: Logger
  entry: MendReportEntry<Ceremony>
  ceremony?: Ceremony
  run?: string
  err?: unknown
}): void {
  try {
    const data: Record<string, unknown> = {
      invariant: entry.invariant,
      outcome: entry.outcome,
      ...scalarDetail(entry.detail as CeremonyDetail | undefined)
    }
    if (entry.errorName !== undefined) {
      data.errorName = entry.errorName
    }
    if (ceremony !== undefined) {
      data.ceremony = ceremony
    }
    if (run !== undefined) {
      data.run = run
    }
    if (err !== undefined) {
      data.err = err
    }
    emit({
      log,
      level: OUTCOME_LEVELS[entry.outcome] ?? 'error',
      msg: 'ceremony mender',
      data
    })
  } catch {
    // A log line never fails a ceremony or a login chain.
  }
}
