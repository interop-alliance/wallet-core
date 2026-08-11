/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `WalletOnboardingQuery` transport vocabulary: the VPR half of "connect a
 * new wallet client over an exchange". An already-enrolled client (the
 * inviter) composes a request body carrying the query and stores it on an
 * ephemeral exchange; a fresh wallet (the enrollee) scans the exchange's
 * interaction URL, classifies the query here, and answers with the onboarding
 * response envelope (`@interop/wallet-core/enrollment`).
 *
 * Vocabulary only -- the enrollment ceremony itself is untouched, and nothing
 * but public key multibases and a display label ever crosses the channel. The
 * query carries exactly one member, `host`: the WAS server base URL, so the
 * enrollee's server field is prefilled instead of typed. It names no account
 * and authorizes nothing.
 *
 * A wallet that predates the query type finds nothing it can satisfy in such a
 * request (`classifyRequest` reports no DID Auth, no credential queries, and
 * no capability requests) and refuses, rather than degrading into a partial
 * generic flow.
 */
import type {
  IVPRDetails,
  IVPRQuery,
  IWalletOnboardingQuery,
  IWalletOnboardingRequest
} from './types.js'

/**
 * Validates a wallet-onboarding `host` and returns its serialized form. The
 * value must parse as an absolute URL and must be `http:` or `https:` (it is
 * dereferenced as a WAS server base URL) and must not carry a fragment; any
 * violation throws. Compose and classification share this one rule, so the
 * spelling the inviter publishes is the spelling the enrollee resolves, and
 * URLs differing only in a default port, percent-encoding case, or dot
 * segments do not name distinct servers.
 *
 * There is no attested origin to compare against here -- an exchange has no
 * CHAPI requesting origin -- so unlike an App Connect `appUrl` the check is
 * shape only. The channel's trust comes from the point-to-point fingerprint
 * comparison of the enrollment ceremony, not from this value.
 *
 * The fragment check reads the serialized URL rather than `url.hash`: a bare
 * trailing `#` sets an empty (non-null) fragment that `hash` reports as `''`.
 *
 * @param options {object}
 * @param options.host {string} - The query's `host`.
 * @returns {string} The parsed URL's serialization.
 */
export function serializedOnboardingHost({ host }: { host: string }): string {
  let url: URL
  try {
    url = new URL(host)
  } catch (err) {
    throw new Error(
      `A WalletOnboardingQuery "host" must be an absolute URL (got "${host}").`,
      { cause: err }
    )
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(
      `A WalletOnboardingQuery "host" must be an http(s) URL (got "${host}").`
    )
  }
  if (url.href.includes('#')) {
    throw new Error(
      `A WalletOnboardingQuery "host" must not carry a fragment (got ` +
        `"${host}").`
    )
  }
  return url.href
}

/**
 * INVITER: the VPR details body to store on the ephemeral exchange -- one
 * `WalletOnboardingQuery` and nothing else, since the query is one mental
 * model per exchange. The `host` is validated and stored in its serialized
 * form ({@link serializedOnboardingHost}).
 *
 * @param options {object}
 * @param options.host {string} - The account's WAS server base URL.
 * @returns {IVPRDetails}
 */
export function composeWalletOnboardingRequest({
  host
}: {
  host: string
}): IVPRDetails {
  const query: IWalletOnboardingQuery = {
    type: 'WalletOnboardingQuery',
    host: serializedOnboardingHost({ host })
  }
  return { query: [query as unknown as IVPRQuery] }
}

/**
 * ENROLLEE: extracts the wallet-onboarding request from a query set, when one
 * is present. Like an `AppConnectQuery`, a `WalletOnboardingQuery` is one
 * mental model per exchange: at most one may appear, and it must not be
 * combined with `QueryByExample`, standalone capability queries, or an
 * `AppConnectQuery` (a screen that asks the person to connect a wallet must
 * not simultaneously ask them to share credentials or grant capabilities).
 * Its `host` must satisfy the URL rules and is rewritten to its serialized
 * form. Violations throw; classification-time callers surface the throw as a
 * malformed-request state.
 *
 * @param options {object}
 * @param options.queries {IVPRQuery[]}
 * @returns {IWalletOnboardingRequest | null}
 */
export function walletOnboardingRequestOf({
  queries
}: {
  queries: IVPRQuery[]
}): IWalletOnboardingRequest | null {
  // `WalletOnboardingQuery` extends the spec query union, so it is matched by
  // its `type` string and upcast rather than narrowed via a type predicate.
  const onboardingQueries = queries.filter(
    query => (query.type as string) === 'WalletOnboardingQuery'
  ) as unknown as IWalletOnboardingQuery[]
  if (onboardingQueries.length === 0) {
    return null
  }
  if (onboardingQueries.length > 1) {
    throw new Error('More than one WalletOnboardingQuery found, exiting.')
  }
  const mixed = queries.some(
    query =>
      query.type === 'QueryByExample' ||
      query.type === 'AuthorizationCapabilityQuery' ||
      query.type === 'ZcapQuery' ||
      (query.type as string) === 'AppConnectQuery'
  )
  if (mixed) {
    throw new Error(
      'A WalletOnboardingQuery cannot be combined with QueryByExample, ' +
        'standalone capability queries, or an AppConnectQuery.'
    )
  }
  const { host } = onboardingQueries[0]!
  if (typeof host !== 'string') {
    throw new Error('A WalletOnboardingQuery is missing its host.')
  }
  return { host: serializedOnboardingHost({ host }) }
}
