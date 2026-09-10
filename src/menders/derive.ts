/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The derived sets a wallet's audit tests assert: the invariants a transient
 * visit reaches, the gaps the registration index implies, and census
 * completeness. Each is computed from the table and the sites alone, so a
 * converger that quietly loses a trigger a transient visit fires, or an
 * invariant no registration reports any more, moves a derived set and fails
 * the wallet's pin.
 */
import { INVARIANT_IDS, type InvariantId } from './ids.js'
import type { MenderRegistry } from './registry.js'
import { heldAuthorities } from './registry.js'
import type { InvariantGap, RegistrationSite } from './types.js'
import type { GapKind } from './vocabulary.js'

/**
 * The ids some site reports, whatever its trigger.
 */
function reportedIds(
  registry: MenderRegistry<RegistrationSite, never>
): ReadonlySet<InvariantId> {
  return new Set(registry.sites().flatMap(site => [...site.reports]))
}

/**
 * The invariants a transient visit on a standing credential reaches. The
 * two chain triggers are read through `dueAt` over the ladder held set; a
 * `login-routing` site counts unless the client-key-record probe guards it;
 * a `ceremony-tail` entry counts, every such ceremony running on any
 * session type; and a detector no site reports (a declaration carrying
 * `holdsWhen`) counts when it is checked at a trigger a transient visit
 * fires and, on the chain, under an authority the ladder held set carries.
 * An unreported declaration with no detector is reached by nothing.
 *
 * @param options {object}
 * @param options.registry {MenderRegistry}
 * @returns {ReadonlyArray<InvariantId>}   in table order
 */
export function transientReachableInvariants({
  registry
}: {
  registry: MenderRegistry<RegistrationSite, never>
}): ReadonlyArray<InvariantId> {
  const reached = new Set<InvariantId>()
  const held = heldAuthorities({ kind: 'ladder' })
  for (const site of registry.dueAt({
    held,
    trigger: 'transient-login-chain'
  })) {
    for (const id of site.reports) {
      reached.add(id)
    }
  }
  for (const site of registry.sites()) {
    if (site.trigger === 'login-routing' && !site.guardedBy) {
      for (const id of site.reports) {
        reached.add(id)
      }
    }
  }
  const reported = reportedIds(registry)
  for (const decl of registry.all()) {
    if (decl.triggers.includes('ceremony-tail')) {
      reached.add(decl.id)
    } else if (!reported.has(decl.id) && decl.holdsWhen) {
      const checkedOnVisit =
        decl.triggers.includes('login-routing') ||
        (decl.triggers.includes('transient-login-chain') &&
          held.includes(decl.authority))
      if (checkedOnVisit) {
        reached.add(decl.id)
      }
    }
  }
  return registry.all().flatMap(decl => (reached.has(decl.id) ? [decl.id] : []))
}

/**
 * The gaps the index implies. An invariant no site reports derives `none`,
 * unless it is checked at ceremony tails alone (converged by the ceremony's
 * own sequenced code, which is never registered). A detector is not a
 * mender: a declaration carrying `holdsWhen` and no registration derives
 * `none` like any other unreported one, so adding a detector never retires
 * a gap. A declaration naming a chain or routing trigger no site backs
 * derives `none` whatever else it names. An invariant reported only at sites
 * a transient visit cannot reach, on an account shape the violation can
 * stand on, derives `unreachable`. Nothing else derives a gap.
 *
 * @param options {object}
 * @param options.registry {MenderRegistry}
 * @returns {ReadonlyArray<{ invariant: InvariantId, kind: GapKind }>}
 */
export function deriveGaps({
  registry
}: {
  registry: MenderRegistry<RegistrationSite, never>
}): ReadonlyArray<{ invariant: InvariantId; kind: GapKind }> {
  const reported = reportedIds(registry)
  const reachable = new Set(transientReachableInvariants({ registry }))
  const gaps: Array<{ invariant: InvariantId; kind: GapKind }> = []
  for (const decl of registry.all()) {
    if (!reported.has(decl.id)) {
      const tailOnly =
        decl.triggers.length > 0 &&
        decl.triggers.every(trigger => trigger === 'ceremony-tail')
      if (!tailOnly) {
        gaps.push({ invariant: decl.id, kind: 'none' })
      }
    } else if (
      !reachable.has(decl.id) &&
      decl.standsOn.includes('client-less')
    ) {
      gaps.push({ invariant: decl.id, kind: 'unreachable' })
    }
  }
  return gaps
}

/**
 * Compares the derived gaps with a wallet's declared allowlist. The
 * derivation admits gaps and retires none: a declared row the derivation no
 * longer produces passes, and a derived gap with no declaration fails. A
 * derived `none` needs a declared `none` row for its invariant; a derived
 * `unreachable` needs any declared row for it, since a declared `none` may
 * be scoped to a different torn state of the same predicate.
 *
 * @param options {object}
 * @param options.derived {ReadonlyArray<{ invariant: InvariantId, kind: GapKind }>}
 * @param options.declared {ReadonlyArray<InvariantGap>}
 * @returns {ReadonlyArray<{ invariant: InvariantId, kind: GapKind }>}   the
 *   derived gaps no declaration covers; empty when the allowlist is complete
 */
export function undeclaredGaps({
  derived,
  declared
}: {
  derived: ReadonlyArray<{ invariant: InvariantId; kind: GapKind }>
  declared: ReadonlyArray<InvariantGap>
}): ReadonlyArray<{ invariant: InvariantId; kind: GapKind }> {
  return derived.filter(
    ({ invariant, kind }) =>
      !declared.some(
        gap =>
          gap.invariant === invariant &&
          (kind === 'unreachable' || gap.kind === 'none')
      )
  )
}

/**
 * Census completeness: the ids in {@link INVARIANT_IDS} the table does not
 * declare. Duplicated ids and undeclared reports are refused by
 * `menderRegistry` at construction, so a registry in hand has neither.
 *
 * @param options {object}
 * @param options.registry {MenderRegistry}
 * @returns {ReadonlyArray<InvariantId>}   empty when the census is complete
 */
export function undeclaredInvariants({
  registry
}: {
  registry: MenderRegistry<RegistrationSite, never>
}): ReadonlyArray<InvariantId> {
  const declared = new Set(registry.all().map(decl => decl.id))
  return INVARIANT_IDS.filter(id => !declared.has(id))
}
