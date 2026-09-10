/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The mender runner: one try, warn, and skip discipline over the
 * registrations listed under one chain trigger. `runMenderBlock` runs them
 * in list order, since registration order is execution order and there is
 * no dependency graph. A seed step's failure aborts the block; a
 * registration's failure warns through the wallet's own `Logger` and the
 * block continues. Beside it sits `mendReportAccumulator`, the report
 * collector a wallet creates before a `Session` exists, so the entries a
 * routing site reports and the entries this runner reports assemble into
 * one `MendReport`.
 */
import type { Logger } from '../log.js'
import type { MenderRegistry } from './registry.js'
import type {
  LoginRoute,
  MendReport,
  MendReportEntry,
  Registration,
  RegistrationSite
} from './types.js'
import type { Authority, ChainTrigger } from './vocabulary.js'

/**
 * The `errorName` a normalized entry carries when a registration resolves
 * with entries that do not match the invariants it reports.
 */
export const MEND_REPORT_SHAPE_ERROR = 'MendReportShapeError'

/**
 * The report collector a wallet creates ahead of session assembly. A
 * routing entry reports into it from its own call site before a `Session`
 * exists, {@link runMenderBlock} reports the chain's entries into it
 * through `onOutcome`, and the wallet hands `settled` to the session as its
 * mend report.
 */
export interface MendReportAccumulator<Ceremony extends string = string> {
  /**
   * Records one entry. Bound to the accumulator, so it can be passed
   * directly as {@link runMenderBlock}'s `onOutcome`.
   */
  report(entry: MendReportEntry<Ceremony>): void
  /**
   * Every entry recorded so far, in report order.
   */
  entries(): MendReport<Ceremony>
  /**
   * Resolves {@link MendReportAccumulator.settled} with the entries
   * recorded so far. Idempotent: the first call fixes the resolved report,
   * and a later `report` call still lands in `entries()`.
   */
  settle(): MendReport<Ceremony>
  /**
   * The assembled report, resolved by `settle`. It never rejects.
   */
  readonly settled: Promise<MendReport<Ceremony>>
}

/**
 * Creates a report accumulator. Generic over the wallet's ceremony-id
 * union, which defaults to `string`.
 *
 * @returns {MendReportAccumulator}
 */
export function mendReportAccumulator<
  Ceremony extends string = string
>(): MendReportAccumulator<Ceremony> {
  const recorded: Array<MendReportEntry<Ceremony>> = []
  let resolveSettled: (report: MendReport<Ceremony>) => void = () => undefined
  const settled = new Promise<MendReport<Ceremony>>(resolve => {
    resolveSettled = resolve
  })
  let assembled: MendReport<Ceremony> | undefined
  return {
    report(entry) {
      recorded.push(entry)
    },
    entries: () => [...recorded],
    settle() {
      if (!assembled) {
        assembled = [...recorded]
        resolveSettled(assembled)
      }
      return assembled
    },
    settled
  }
}

/**
 * Runs one registration block: the registrations listed under `trigger`
 * whose every reported invariant declares an authority the session holds
 * and admits this login route, in list order.
 *
 * The discipline, in one place. An optional `seed` registration runs first,
 * and its failure aborts the block: nothing behind it runs, which is what a
 * rejected chain seed does today. Past the seed, a registration that throws
 * warns once per reported invariant with that declaration's own `warn`
 * string, reports `failed` for each of them, and the block carries on to
 * the next registration. Only `err.name` rides a report: a thrown error's
 * message routinely carries a DID or a Space id, so the error itself goes
 * to the logger alone.
 *
 * A registration that resolves with the wrong number of entries, or with an
 * entry whose `invariant` is not the id it reports at that position, is a
 * programming error. It warns and is normalized to `failed` entries
 * carrying {@link MEND_REPORT_SHAPE_ERROR} rather than throwing, so a
 * mismatched adapter cannot tear a login.
 *
 * `trigger` is one of the two chain values, so a `ceremony-tail` entry is
 * out of reach here. Such an entry has no registration at all: its body
 * stays inside its ceremony's sequenced code and it reports from there.
 *
 * `Deps` is the wallet's own type, one object per registration block,
 * handed to the seed and to every `converge` unread. This runner never
 * inspects it, and the raw passphrase does not cross into this package.
 *
 * `registrations` overrides which registrations the block runs, for a wallet
 * that runs one trigger's list in parts (a settle point partway through, say).
 * The same authority and route tests still admit each one, so the override
 * narrows the block and never widens it.
 *
 * A registry may index converge-free sites beside its registrations -- a
 * wallet's routing entries, or an entry whose own call site fires it -- and
 * such a site is never executed here, whichever list the block runs from.
 *
 * @param options {object}
 * @param options.registry {MenderRegistry}   the wallet's declarations and
 *   its registrations
 * @param options.trigger {ChainTrigger}   which chain is running
 * @param options.held {ReadonlyArray<Authority>}   the session's held
 *   authorities, from `heldAuthorities`
 * @param options.route {LoginRoute}   the login route each declaration's
 *   `when` predicate reads
 * @param options.deps {Deps}   passed to the seed and to every `converge`
 * @param options.logger {Logger}   the wallet's own sink, so its warn
 *   copy keeps the wallet's namespace
 * @param [options.registrations] {ReadonlyArray<Registration>}   the
 *   registrations to run, in place of the ones the registry lists under
 *   `trigger`. Each is admitted by the same authority and route tests
 * @param [options.seed] {Registration}   the step whose failure aborts the
 *   block. Admitted by the same authority and route tests as any other
 *   registration; one it does not pass is skipped rather than failed
 * @param [options.onOutcome] {(entry: MendReportEntry) => void}   called
 *   once per reported entry, in order. The single place a chain entry's
 *   outcome is reported
 * @returns {Promise<MendReport>}   the block's entries in order. It never
 *   rejects; a seed failure resolves with the seed's `failed` entries alone
 */
export async function runMenderBlock<
  Deps,
  Ceremony extends string = string,
  Site extends RegistrationSite = Registration<Deps, Ceremony>
>({
  registry,
  trigger,
  held,
  route,
  deps,
  logger,
  registrations,
  seed,
  onOutcome
}: {
  registry: MenderRegistry<Site, Deps, Ceremony>
  trigger: ChainTrigger
  held: ReadonlyArray<Authority>
  route: LoginRoute
  deps: Deps
  logger: Logger
  registrations?: ReadonlyArray<Registration<Deps, Ceremony>>
  seed?: Registration<Deps, Ceremony>
  onOutcome?: (entry: MendReportEntry<Ceremony>) => void
}): Promise<MendReport<Ceremony>> {
  const report: Array<MendReportEntry<Ceremony>> = []
  const collect = (entries: ReadonlyArray<MendReportEntry<Ceremony>>): void => {
    for (const entry of entries) {
      report.push(entry)
      onOutcome?.(entry)
    }
  }
  const admitted = (site: RegistrationSite): boolean =>
    registry.admits({ site, held, route })
  const listed = (
    registrations?.filter(admitted) ?? registry.dueAt({ held, trigger, route })
  ).filter(isRegistration<Deps, Ceremony>)
  // One ordered list, the seed first: the seed is the one step whose throw
  // ends the block.
  const steps = seed && admitted(seed) ? [seed, ...listed] : listed
  for (const registration of steps) {
    const outcome = await runRegistration({
      registry,
      registration,
      deps,
      logger,
      trigger
    })
    collect(outcome.entries)
    if (outcome.threw && registration === seed) {
      return report
    }
  }
  return report
}

/**
 * Runs one registration under the block's discipline, returning its entries
 * and whether it threw.
 */
async function runRegistration<
  Deps,
  Ceremony extends string,
  Site extends RegistrationSite
>({
  registry,
  registration,
  deps,
  logger,
  trigger
}: {
  registry: MenderRegistry<Site, Deps, Ceremony>
  registration: Registration<Deps, Ceremony>
  deps: Deps
  logger: Logger
  trigger: ChainTrigger
}): Promise<{
  entries: ReadonlyArray<MendReportEntry<Ceremony>>
  threw: boolean
}> {
  try {
    const entries = await registration.converge(deps)
    if (!matchesReports({ registration, entries })) {
      logger.warn(
        'A mender registration returned entries that do not match the invariants it reports',
        { trigger, reports: [...registration.reports] }
      )
      // A malformed return is a defect in the adapter rather than a mend
      // failure: the step ran to completion, so a malformed seed does not
      // abort the block.
      return {
        entries: failedEntries({
          registry,
          registration,
          errorName: MEND_REPORT_SHAPE_ERROR
        }),
        threw: false
      }
    }
    return { entries, threw: false }
  } catch (err) {
    for (const id of registration.reports) {
      logger.warn(registry.byId(id)?.warn ?? `Could not converge ${id}`, {
        invariant: id,
        trigger,
        err
      })
    }
    return {
      entries: failedEntries({
        registry,
        registration,
        errorName: errorNameOf(err)
      }),
      threw: true
    }
  }
}

/**
 * Whether a site carries a converger, so the block can run it. A wallet's
 * registry indexes its converge-free sites beside its registrations.
 *
 * @param site {RegistrationSite}
 * @returns {boolean}
 */
function isRegistration<Deps, Ceremony extends string>(
  site: RegistrationSite
): site is Registration<Deps, Ceremony> {
  return typeof (site as Registration<Deps, Ceremony>).converge === 'function'
}

/**
 * Whether a registration's entries name the invariants it reports, in that
 * order.
 */
function matchesReports<Deps, Ceremony extends string>({
  registration,
  entries
}: {
  registration: Registration<Deps, Ceremony>
  entries: ReadonlyArray<MendReportEntry<Ceremony>>
}): boolean {
  return (
    entries.length === registration.reports.length &&
    entries.every(
      (entry, index) => entry.invariant === registration.reports[index]
    )
  )
}

/**
 * One `failed` entry per reported invariant, carrying the declaration's
 * ceremonies where it names any.
 */
function failedEntries<
  Deps,
  Ceremony extends string,
  Site extends RegistrationSite
>({
  registry,
  registration,
  errorName
}: {
  registry: MenderRegistry<Site, Deps, Ceremony>
  registration: Registration<Deps, Ceremony>
  errorName: string
}): ReadonlyArray<MendReportEntry<Ceremony>> {
  return registration.reports.map(id => {
    const ceremonies = registry.byId(id)?.ceremonies
    return {
      invariant: id,
      outcome: 'failed' as const,
      errorName,
      ...(ceremonies && ceremonies.length > 0 ? { ceremonies } : {})
    }
  })
}

/**
 * The thrown value's class name alone. Its message may carry a DID or a
 * Space id, so a report keeps the name and the logger keeps the error. A
 * value that is not an `Error` still yields a name, so a report site never
 * carries `undefined` where a name belongs.
 *
 * @param err {unknown}
 * @returns {string}
 */
export function errorNameOf(err: unknown): string {
  if (err instanceof Error) {
    return err.name
  }
  if (typeof err === 'object' && err !== null && 'name' in err) {
    return String((err as { name: unknown }).name)
  }
  return 'Error'
}
