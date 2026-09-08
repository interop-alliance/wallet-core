/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Import-free helpers shared by the request classifiers: which VPR query
 * type a query object carries, and the parse-and-no-fragment core every URL
 * validated straight off a request body layers its own rule on top of. Kept
 * in one dependency-light leaf file so `onboarding.ts` can classify a
 * `WalletOnboardingQuery` without pulling `classify.ts`'s heavier graph.
 */
import type { IVPRQuery, IZcapQuery } from './types.js'

/**
 * Whether a query is a standalone capability query, under either type string:
 * `AuthorizationCapabilityQuery` (the canonical VCALM spelling) or the legacy
 * `ZcapQuery`.
 *
 * The one reader of that alias pair. Both exclusivity checks and both
 * capability extractors ask through here, so retiring or extending the pair
 * is one edit rather than four.
 *
 * @param query {IVPRQuery}
 * @returns {boolean}
 */
export function isZcapQuery(query: IVPRQuery): query is IZcapQuery {
  return (
    query.type === 'AuthorizationCapabilityQuery' || query.type === 'ZcapQuery'
  )
}

/**
 * The query types that stand alone in a request under the
 * one-mental-model-per-exchange rule: a screen that asks the person to
 * connect a wallet, or to join an account, must not simultaneously ask them
 * to share credentials or grant capabilities. Each type excludes
 * `QueryByExample`, standalone capability queries, and every other member of
 * this set, in both directions. The set is the one home of that mutual
 * exclusion: adding a third exclusive type is one entry here, and
 * {@link exclusiveQueryOf} refuses the new mixtures from every side.
 */
export const EXCLUSIVE_QUERY_TYPES = [
  'AppConnectQuery',
  'WalletOnboardingQuery'
] as const

/**
 * A member of {@link EXCLUSIVE_QUERY_TYPES}.
 */
export type ExclusiveQueryType = (typeof EXCLUSIVE_QUERY_TYPES)[number]

/**
 * Whether a query carries the given `type` string. The one comparison every
 * type test in this file runs through: `AppConnectQuery` and
 * `WalletOnboardingQuery` extend the spec query union rather than being part
 * of it, so they are matched by `type` string and upcast rather than narrowed
 * via a type predicate.
 *
 * @param options {object}
 * @param options.query {IVPRQuery}
 * @param options.typeName {string}
 * @returns {boolean}
 */
function isQueryOfType({
  query,
  typeName
}: {
  query: IVPRQuery
  typeName: string
}): boolean {
  return (query.type as string) === typeName
}

/**
 * Whether a query is an `AppConnectQuery`. Callers filtering on this still
 * cast the result to `IAppConnectQuery[]` (see {@link isQueryOfType}).
 *
 * @param query {IVPRQuery}
 * @returns {boolean}
 */
export function isAppConnectQuery(query: IVPRQuery): boolean {
  return isQueryOfType({ query, typeName: 'AppConnectQuery' })
}

/**
 * Whether a query set carries an `AppConnectQuery` at all: the gate
 * `processRequest` takes its App Connect branch on, and the presence half of
 * `appConnectRequestOf`'s extraction. The gate cannot simply run the
 * extractor, since the extractor needs the requesting origin whose absence
 * the gate must report, so the two share this predicate instead of each
 * filtering on the type string.
 *
 * @param queries {IVPRQuery[]}
 * @returns {boolean}
 */
export function hasAppConnectQuery(queries: IVPRQuery[]): boolean {
  return queries.some(isAppConnectQuery)
}

/**
 * Whether a query is a `WalletOnboardingQuery`. Matched the same way as
 * {@link isAppConnectQuery}.
 *
 * @param query {IVPRQuery}
 * @returns {boolean}
 */
export function isWalletOnboardingQuery(query: IVPRQuery): boolean {
  return isQueryOfType({ query, typeName: 'WalletOnboardingQuery' })
}

/**
 * The indefinite article a type name takes in a refusal message.
 *
 * @param typeName {string}
 * @returns {string}
 */
function articleFor(typeName: string): string {
  return /^[AEIOU]/.test(typeName) ? 'an' : 'a'
}

/**
 * The singleton query of a set for one of the {@link EXCLUSIVE_QUERY_TYPES}.
 * Returns `null` when no query of the type is present, the one query when
 * exactly one is, and throws when more than one appears or when a query of a
 * mutually exclusive type sits beside it: `QueryByExample`, a standalone
 * capability query, or any other exclusive type. The exclusion list is
 * derived from the shared set rather than written per caller, so no type can
 * be excluded from one direction only.
 *
 * @param options {object}
 * @param options.queries {IVPRQuery[]}   the request's query set
 * @param options.typeName {ExclusiveQueryType}   the singleton's type
 * @returns {IVPRQuery | null}
 */
export function exclusiveQueryOf({
  queries,
  typeName
}: {
  queries: IVPRQuery[]
  typeName: ExclusiveQueryType
}): IVPRQuery | null {
  const matches = queries.filter(query => isQueryOfType({ query, typeName }))
  if (matches.length === 0) {
    return null
  }
  if (matches.length > 1) {
    throw new Error(`More than one ${typeName} found, exiting.`)
  }
  const otherTypes = EXCLUSIVE_QUERY_TYPES.filter(other => other !== typeName)
  const isExcluded = (query: IVPRQuery): boolean =>
    query.type === 'QueryByExample' ||
    isZcapQuery(query) ||
    otherTypes.includes(query.type as ExclusiveQueryType)
  if (queries.some(isExcluded)) {
    const others = otherTypes.map(other => `${articleFor(other)} ${other}`)
    const article = articleFor(typeName)
    const capitalized = article[0]!.toUpperCase() + article.slice(1)
    throw new Error(
      `${capitalized} ${typeName} cannot be combined with QueryByExample, ` +
        `standalone capability queries, or ${others.join(', or ')}.`
    )
  }
  return matches[0]!
}

/**
 * Parses a wire value as an absolute URL with no fragment: the shared core
 * every request field that copies a URL verbatim from an untrusted body
 * layers its own rule on top of (an App Connect `appUrl`'s same-origin check,
 * a wallet-onboarding `host`'s http(s)-only check). Throws a caller-supplied
 * message on a parse failure (with the parse error as `cause`) or on a
 * fragment, so each site keeps its own wording while the parse-and-no-
 * fragment logic is written once.
 *
 * The fragment check reads the serialized URL rather than `url.hash`: a bare
 * trailing `#` sets an empty (non-null) fragment that `hash` reports as `''`,
 * and a percent-encoded `%23` never appears as `#` in the serialization.
 *
 * @param options {object}
 * @param options.value {string}   the raw wire value to parse
 * @param options.notAbsoluteMessage {string}   thrown, with the parse error
 *   as `cause`, when `value` does not parse as an absolute URL
 * @param options.fragmentMessage {string}   thrown when the parsed URL
 *   carries a fragment
 * @returns {URL}   the parsed URL
 */
export function parsedAbsoluteUrl({
  value,
  notAbsoluteMessage,
  fragmentMessage
}: {
  value: string
  notAbsoluteMessage: string
  fragmentMessage: string
}): URL {
  let url: URL
  try {
    url = new URL(value)
  } catch (err) {
    throw new Error(notAbsoluteMessage, { cause: err })
  }
  if (url.href.includes('#')) {
    throw new Error(fragmentMessage)
  }
  return url
}
