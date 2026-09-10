/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The registry readers over a declaration table and its per-trigger
 * registration sites: `all` and `byId` read declarations, `admits` is the
 * one admission test (every reported invariant declares an authority the
 * session holds and admits this login route), and `dueAt` reads the sites
 * listed under one chain trigger that `admits` passes, in list order.
 * Registration order is execution order; there is no dependency graph and
 * no priority. The table and the sites are checked once, at construction: a
 * duplicated declaration id, a site reporting an undeclared invariant, or a
 * guard on a non-routing site is a `TypeError` there, so no reader meets the
 * defect later, depending on what a login happens to hold.
 */
import type { InvariantId } from './ids.js'
import type {
  InvariantDeclaration,
  LoginRoute,
  RegistrationSite
} from './types.js'
import type { Authority, ChainTrigger } from './vocabulary.js'

/**
 * The two authorities a session's account-ceremony context resolves to; the
 * remaining values, `none` and `account`, are the ones every resolved kind
 * subsumes. Derived from the vocabulary, so a new authority is a compile
 * error in `heldAuthorities` rather than a value it can never return.
 */
export type ResolvedAuthority = Exclude<Authority, 'none' | 'account'>

/**
 * The readers over one wallet's table. `Site` is the converge-free index
 * shape or a wallet's registration type extending it, so the same readers
 * serve the audit and the runner.
 */
export interface MenderRegistry<
  Site extends RegistrationSite,
  Deps,
  Ceremony extends string = string
> {
  all(): ReadonlyArray<InvariantDeclaration<Deps, Ceremony>>
  byId(id: InvariantId): InvariantDeclaration<Deps, Ceremony> | undefined
  sites(): ReadonlyArray<Site>
  /**
   * Whether a site's every reported invariant declares an authority in
   * `held` and, when a route is given, admits it. The one admission test,
   * shared by `dueAt` and by a runner admitting a site the caller supplies.
   *
   * @throws {TypeError}   when the site reports an undeclared invariant,
   *   reachable only for a site the registry does not index
   */
  admits(options: {
    site: RegistrationSite
    held: ReadonlyArray<Authority>
    route?: LoginRoute
  }): boolean
  dueAt(options: {
    held: ReadonlyArray<Authority>
    trigger: ChainTrigger
    route?: LoginRoute
  }): ReadonlyArray<Site>
}

/**
 * The held set a session derives from its account-ceremony context: `none`
 * always, plus `account` and the resolved kind when a context resolves.
 *
 * @param options {object}
 * @param [options.kind] {ResolvedAuthority}   the resolved context kind,
 *   absent for a guest, a no-WAS session, or a transient session whose
 *   record carries no standing members
 * @returns {ReadonlyArray<Authority>}
 */
export function heldAuthorities({
  kind
}: {
  kind?: ResolvedAuthority
}): ReadonlyArray<Authority> {
  return kind ? ['none', 'account', kind] : ['none']
}

/**
 * Builds the readers over one wallet's declarations and sites, checking
 * both once: every declaration id is unique, every reported id is declared,
 * and only a `login-routing` site carries `guardedBy`.
 *
 * @param options {object}
 * @param options.declarations {ReadonlyArray<InvariantDeclaration>}
 * @param options.sites {ReadonlyArray<RegistrationSite>}   every
 *   registration site, any trigger, in execution order within a trigger
 * @returns {MenderRegistry}
 * @throws {TypeError}   on a duplicated declaration id, an undeclared
 *   report, or a guard on a non-routing site
 */
export function menderRegistry<
  Site extends RegistrationSite,
  Deps,
  Ceremony extends string = string
>({
  declarations,
  sites
}: {
  declarations: ReadonlyArray<InvariantDeclaration<Deps, Ceremony>>
  sites: ReadonlyArray<Site>
}): MenderRegistry<Site, Deps, Ceremony> {
  const index = new Map<InvariantId, InvariantDeclaration<Deps, Ceremony>>()
  for (const decl of declarations) {
    if (index.has(decl.id)) {
      throw new TypeError(`An invariant is declared twice: ${decl.id}`)
    }
    index.set(decl.id, decl)
  }
  const requireDeclared = (
    id: InvariantId
  ): InvariantDeclaration<Deps, Ceremony> => {
    const decl = index.get(id)
    if (!decl) {
      throw new TypeError(
        `A registration reports an undeclared invariant: ${id}`
      )
    }
    return decl
  }
  for (const site of sites) {
    site.reports.forEach(requireDeclared)
    const { trigger, guardedBy } = site
    if (guardedBy !== undefined && trigger !== 'login-routing') {
      throw new TypeError(
        `A ${trigger} site carries a guard; only a login-routing site may`
      )
    }
  }
  const admits = ({
    site,
    held,
    route
  }: {
    site: RegistrationSite
    held: ReadonlyArray<Authority>
    route?: LoginRoute
  }): boolean =>
    site.reports.every(id => {
      const decl = requireDeclared(id)
      return (
        held.includes(decl.authority) &&
        (route === undefined || !decl.when || decl.when(route))
      )
    })
  return {
    all: () => declarations,
    byId: id => index.get(id),
    sites: () => sites,
    admits,
    dueAt: ({ held, trigger, route }) =>
      sites.filter(
        site => site.trigger === trigger && admits({ site, held, route })
      )
  }
}
