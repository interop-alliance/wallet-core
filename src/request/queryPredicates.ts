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
 * Whether a query is an `AppConnectQuery`. `AppConnectQuery` extends the spec
 * query union rather than being part of it, so it is matched by its `type`
 * string and upcast rather than narrowed via a type predicate -- callers
 * filtering on this still cast the result to `IAppConnectQuery[]`.
 *
 * @param query {IVPRQuery}
 * @returns {boolean}
 */
export function isAppConnectQuery(query: IVPRQuery): boolean {
  return (query.type as string) === 'AppConnectQuery'
}

/**
 * Whether a query is a `WalletOnboardingQuery`. Matched the same way as
 * {@link isAppConnectQuery}.
 *
 * @param query {IVPRQuery}
 * @returns {boolean}
 */
export function isWalletOnboardingQuery(query: IVPRQuery): boolean {
  return (query.type as string) === 'WalletOnboardingQuery'
}

/**
 * The singleton query of a set, under the one-mental-model-per-exchange rule:
 * a query type that stands alone in its request. Returns `null` when no query
 * of the type is present, the one query when exactly one is, and throws when
 * more than one appears or when a query of any mutually exclusive type sits
 * beside it. `AppConnectQuery` and `WalletOnboardingQuery` are the two such
 * types today, each excluding `QueryByExample`, standalone capability
 * queries, and the other; a third is one more call of this with its own
 * predicate and exclusion list.
 *
 * @param options {object}
 * @param options.queries {IVPRQuery[]}   the request's query set
 * @param options.isSingleton {(query: IVPRQuery) => boolean}   matches the
 *   singleton type
 * @param options.isExcluded {(query: IVPRQuery) => boolean}   matches the
 *   types that may not accompany it
 * @param options.typeName {string}   the singleton's type string, for the
 *   duplicate refusal
 * @param options.mixedMessage {string}   thrown when an excluded type is
 *   present
 * @returns {IVPRQuery | null}
 */
export function singletonQueryOf({
  queries,
  isSingleton,
  isExcluded,
  typeName,
  mixedMessage
}: {
  queries: IVPRQuery[]
  isSingleton: (query: IVPRQuery) => boolean
  isExcluded: (query: IVPRQuery) => boolean
  typeName: string
  mixedMessage: string
}): IVPRQuery | null {
  const matches = queries.filter(isSingleton)
  if (matches.length === 0) {
    return null
  }
  if (matches.length > 1) {
    throw new Error(`More than one ${typeName} found, exiting.`)
  }
  if (queries.some(isExcluded)) {
    throw new Error(mixedMessage)
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
