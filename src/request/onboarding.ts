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
 * secret crosses the channel: connect-code public halves travel one way, the
 * account pointer and controller the other. The query carries the account's
 * did:webvh `did`, its `spaceId` and `host` (together the account pointer),
 * and the account controller did:key, so the enrollee locates the account
 * without being asked for the account passphrase -- which a passkey-only
 * account does not even have. The inviter already holds all four values.
 *
 * The query names the account but authorizes nothing. A holder of the QR or
 * capability URL gains a world-readable DID log and nothing else; every act on
 * the Space still requires zcaps they do not have, and the rendezvous server
 * that sees the pointer is the same WAS server that hosts the Space and
 * already knows the account DID. Injection by a URL holder remains the real
 * threat, and remains covered by the ceremony's fingerprint / confirmation-
 * code comparison: nothing is authorized before that human check.
 *
 * A wallet that predates the query type finds nothing it can satisfy in such a
 * request (`classifyRequest` reports no DID Auth, no credential queries, and
 * no capability requests) and refuses, rather than degrading into a partial
 * generic flow.
 */
import { isWebvhDid } from '../webvh/did.js'
import { exclusiveQueryOf, parsedAbsoluteUrl } from './queryPredicates.js'
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
 * shape only, and the scheme check is what stands in for it: the value is
 * fetched, so only a scheme the fetch can dereference is a host. The two
 * validators are deliberately asymmetric -- this one checks the scheme and no
 * origin, `serializedAppUrl` checks the origin and no scheme -- over the one
 * shared parse-and-no-fragment core. The channel's trust comes from the
 * point-to-point fingerprint comparison of the enrollment ceremony, not from
 * this value.
 *
 * @param options {object}
 * @param options.host {string} - The query's `host`.
 * @returns {string} The parsed URL's serialization.
 */
export function serializedOnboardingHost({ host }: { host: string }): string {
  const url = parsedAbsoluteUrl({
    value: host,
    notAbsoluteMessage: `A WalletOnboardingQuery "host" must be an absolute URL (got "${host}").`,
    fragmentMessage:
      `A WalletOnboardingQuery "host" must not carry a fragment (got ` +
      `"${host}").`
  })
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(
      `A WalletOnboardingQuery "host" must be an http(s) URL (got "${host}").`
    )
  }
  return url.href
}

/**
 * Validates the account members a `WalletOnboardingQuery` carries and returns
 * them in the classified form: the account's did:webvh `did`, its `spaceId`,
 * the serialized `host`, and the account controller did:key. Compose and
 * classification share this one rule, so the two sides cannot drift.
 *
 * The `did` must be a did:webvh id: only a promoted account (one whose Space
 * controller is its published did:webvh) has the world-readable log the
 * enrollee verifies its approval from. The `controller` check is shape only
 * (a non-empty `did:key:` string) -- it is a discovery value the enrollee
 * stores, and the channel's trust comes from the ceremony's confirmation-code
 * comparison, not from any member of the query.
 *
 * @param options {object}
 * @param options.did {string | undefined}         the account's did:webvh id.
 * @param options.spaceId {string | undefined}     the account's Space id.
 * @param options.host {string | undefined}        the WAS server base URL.
 * @param options.controller {string | undefined}  the account controller
 *   did:key.
 * @returns {IWalletOnboardingRequest}
 */
export function validatedOnboardingAccount({
  did,
  spaceId,
  host,
  controller
}: {
  did?: string | undefined
  spaceId?: string | undefined
  host?: string | undefined
  controller?: string | undefined
}): IWalletOnboardingRequest {
  if (!isWebvhDid(did)) {
    throw new Error(
      'A WalletOnboardingQuery "did" must be the account\'s did:webvh id ' +
        `(got "${String(did)}") -- only a promoted account can onboard ` +
        'another wallet.'
    )
  }
  if (typeof spaceId !== 'string' || spaceId.length === 0) {
    throw new Error(
      'A WalletOnboardingQuery "spaceId" must be a non-empty string (got ' +
        `"${String(spaceId)}").`
    )
  }
  if (typeof host !== 'string') {
    throw new Error('A WalletOnboardingQuery is missing its host.')
  }
  if (typeof controller !== 'string' || !controller.startsWith('did:key:')) {
    throw new Error(
      'A WalletOnboardingQuery "controller" must be a did:key string (got ' +
        `"${String(controller)}").`
    )
  }
  return {
    host: serializedOnboardingHost({ host }),
    did,
    spaceId,
    controller
  }
}

/**
 * INVITER: the VPR details body to store on the ephemeral exchange -- one
 * `WalletOnboardingQuery` and nothing else, since the query is one mental
 * model per exchange. The account members are validated by
 * {@link validatedOnboardingAccount} and the `host` is stored in its
 * serialized form ({@link serializedOnboardingHost}).
 *
 * @param options {object}
 * @param options.pointer {object}  the account pointer (keyring's
 *   `AccountPointer` shape: the inviter passes its session pointer straight
 *   in), whose `did` must already be the promoted did:webvh id.
 * @param options.controller {string}  the account controller did:key.
 * @returns {IVPRDetails}
 */
export function composeWalletOnboardingRequest({
  pointer,
  controller
}: {
  pointer: { did?: string; spaceId: string; host: string }
  controller: string
}): IVPRDetails {
  const query: IWalletOnboardingQuery = {
    type: 'WalletOnboardingQuery',
    ...validatedOnboardingAccount({ ...pointer, controller })
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
 * Its account members must satisfy {@link validatedOnboardingAccount} (so a
 * query missing the pointer or the controller is malformed), and its `host` is
 * rewritten to its serialized form. Violations throw; classification-time
 * callers surface the throw as a malformed-request state.
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
  const onboardingQuery = exclusiveQueryOf({
    queries,
    typeName: 'WalletOnboardingQuery'
  }) as unknown as IWalletOnboardingQuery | null
  if (onboardingQuery === null) {
    return null
  }
  const { host, did, spaceId, controller } = onboardingQuery
  return validatedOnboardingAccount({ host, did, spaceId, controller })
}
