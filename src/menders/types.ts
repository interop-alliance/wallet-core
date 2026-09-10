/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The mender registry's structural types. A declaration is data: what must
 * hold between ceremonies and, where the detector is separable, how to see
 * it. A registration is code: the one place a callable `converge` lives,
 * reporting one or more declared invariants. The registry is the
 * declaration table plus the per-trigger registration lists, and the
 * derived-set helpers read the converge-free `RegistrationSite` shape a
 * registration extends, so an index of sites and a list of registrations
 * feed the same readers.
 */
import type { InvariantId } from './ids.js'
import type {
  AccountShape,
  Authority,
  Evidence,
  GapKind,
  MendOutcomeKind,
  Trigger
} from './vocabulary.js'

/**
 * The login route a declaration's `when` predicate reads: the popup axis
 * alone today, the CHAPI popup being the one route on which several chain
 * entries stand down.
 */
export interface LoginRoute {
  popup: boolean
}

/**
 * One invariant: a predicate over the account's server-held state (for a
 * few entries, over this browser's local state) that must hold between
 * ceremonies. Generic over the dependencies a wallet's detectors take and
 * over the wallet's ceremony-id union, which defaults to `string` for a
 * wallet that declares none.
 */
export interface InvariantDeclaration<Deps, Ceremony extends string = string> {
  /**
   * The stable kebab-case key, naming the predicate rather than the code.
   */
  id: InvariantId
  /**
   * One present-tense sentence stating what holds.
   */
  statement: string
  /**
   * The account shapes on which a violation can stand un-mended.
   */
  standsOn: ReadonlyArray<AccountShape>
  /**
   * The one authority a converger needs. A runtime filter at the two chain
   * triggers; a declaration-time claim, checked by the entry's own call
   * site, everywhere else.
   */
  authority: Authority
  /**
   * Where the predicate is checked today.
   */
  triggers: ReadonlyArray<Trigger>
  /**
   * The ceremonies whose torn runs can violate the predicate. May be
   * empty: several invariants are violated by ordinary drift.
   */
  ceremonies: ReadonlyArray<Ceremony>
  /**
   * What the detector trusts.
   */
  evidence: ReadonlyArray<Evidence>
  /**
   * The warning a runner logs when a registration reporting this invariant
   * throws.
   */
  warn: string
  /**
   * The popup axis: whether the entry runs on this login route. Absent
   * means every route.
   */
  when?(route: LoginRoute): boolean
  /**
   * The separable detector, reading state alone. `undetermined` is what a
   * transport failure returns, so a converger is never invited to write on
   * a flap.
   */
  holdsWhen?(deps: Deps): Promise<'holds' | 'violated' | 'undetermined'>
}

/**
 * Where a registration sits: the trigger it is listed under and the
 * invariants it reports, in report order. A routing site behind the
 * client-key-record probe says so, since only a browser holding such a
 * record reaches it; the guard is a routing-site member alone, so a chain
 * or ceremony-tail site cannot carry one and the chain readers never have
 * to honor it.
 */
export type RegistrationSite =
  | {
      trigger: Exclude<Trigger, 'login-routing'>
      reports: ReadonlyArray<InvariantId>
      guardedBy?: undefined
    }
  | {
      trigger: 'login-routing'
      reports: ReadonlyArray<InvariantId>
      guardedBy?: 'client-key-record'
    }

/**
 * A registration: the code that converges the invariants it reports.
 * `converge` returns exactly one entry per id in `reports`, in that order.
 */
export type Registration<
  Deps,
  Ceremony extends string = string
> = RegistrationSite & {
  converge(deps: Deps): Promise<ReadonlyArray<MendReportEntry<Ceremony>>>
}

/**
 * The outcome of one mend attempt. `detail` is scalar only, so a later emit
 * through the mender event channel needs no reshaping and no account
 * identifier rides a report.
 */
export interface MendOutcome {
  outcome: MendOutcomeKind
  detail?: Record<string, string | number | boolean | undefined>
  /**
   * The thrown error's class name alone; its message may carry a DID or a
   * Space id, which a report never does.
   */
  errorName?: string
}

/**
 * One reported invariant's outcome.
 */
export interface MendReportEntry<
  Ceremony extends string = string
> extends MendOutcome {
  invariant: InvariantId
  ceremonies?: ReadonlyArray<Ceremony>
}

/**
 * A login's or a ceremony's mend report.
 */
export type MendReport<Ceremony extends string = string> = ReadonlyArray<
  MendReportEntry<Ceremony>
>

/**
 * One declared gap, keyed by `{ invariant, tornState }`: one predicate can
 * hold several torn states, and each is its own gap.
 */
export interface InvariantGap {
  invariant: InvariantId
  /**
   * One sentence of prose naming the torn state.
   */
  tornState: string
  standsOn: ReadonlyArray<AccountShape>
  /**
   * The tracking work item.
   */
  item: string
  kind: GapKind
}
