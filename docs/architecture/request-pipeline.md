<!-- Part of wallet-core's architecture docs. The map, the key hierarchy,
     the ceremony inventory, the permanent wire-level constants, and the
     glossary are in ../../ARCHITECTURE.md; this file holds one topic in full. -->

# The request pipeline (`request`)

`walletInput.ts` is the universal entry point for "scan or paste something": an
ordered discrimination in which **the order is the whole design**, because the
grammars are subsets of one another (most-specific first):

1. `was-link` (non-URL JSON blob)
2. `connect-code` (`freewallet-connect:` prefix)
3. `legacy-request` (deep link with both `vc_request_url` and `issuer`)
4. `interaction-url` (VCALM `interaction:` scheme or `iuv=1`)
5. `deep-link` (any other registered-scheme link)
6. `wallet-api-message` (raw JSON, or `?request=` on a non-registered link)
7. `credentials` (raw VC/VP JSON or a URL to fetch) -- last, because it cannot
   be recognized positively; there is no "unrecognized" state.

Classification only -- no fetch, navigate, or store.

Downstream, `parse.ts` takes deep links and JSON to typed messages and
`classify.ts` takes CHAPI events and VPRs to typed requests. `classify.ts` also
carries `appConnectRequestOf`: the `AppConnectQuery` `app` block is
`{ name, appUrl }`, and the `appUrl` must parse as an absolute URL, carry no
fragment, and be same-origin with the attested requesting origin, or the query
is malformed. An opaque origin serializes as `"null"` and is same-origin only
with itself, so it is refused rather than compared. No further scheme constraint
applies, and all storage and comparison uses the parsed URL's serialization. The
wallet-onboarding `host` validator in `onboarding.ts` is the deliberate mirror,
checking the scheme and no origin; both run one parse-and-no-fragment core,
`parsedAbsoluteUrl` in `queryPredicates.ts`.

`matching.ts` holds the QueryByExample matchers, and **two matchers ship
deliberately** -- DCW's deep matcher and freewallet's type/issuer matcher, since
each wallet matches only its own store and no cross-replica agreement is needed.
`composeVp.ts` puts grants inside the VP, added before signing so the DIDAuth
proof covers them, and `presentationSuite.ts` negotiates cryptosuites.

`appKey.ts` owns the App Connect app-key credential: the fixed two-entry type
array and hosted context URL; matching keyed on the `credentialSubject.appUrl`
claim plus marker / self-issuance / origin / seed-binds-subject, ranked
latest-first over `issuanceDate` instants; minting; the store-time refusal
policy, since app keys are wallet-minted rather than imported; the re-issue that
preserves the seed and so the derived identity; and the caller-supplied-seed
issuer `issueAppKeyCredential` under all of those, exported so an app's own
self-issue path signs the same shape.

`processRequest.ts` is pure: consent and the response channel stay with the
caller, zcap and App Connect processing arrive as `RequestProcessors`, and the
App Connect branch is validated via `appConnectRequestOf` before dispatch.

`onboarding.ts` is the `WalletOnboardingQuery` transport vocabulary: the
inviter's compose helper and the enrollee's classification, both validating the
query's members through one core -- the account's did:webvh `did`, a non-empty
`spaceId`, a `did:key:` `controller`, and a `host` that is an absolute http(s)
URL with no fragment. The pointer and controller let the enrollee join without
the account passphrase, and they name the account without authorizing anything.
One mental model per exchange, so the query refuses to mix with
`QueryByExample`, standalone capability queries, or an `AppConnectQuery`, and
`appConnectRequestOf` refuses the mixture from its side too. The response half
of that exchange is the onboarding-response envelope in `enrollment/`.

`exchangeClient.ts` runs VC-API exchanges over an injected `FetchLike` and
handles the empty-CHAPI-body plus `protocols.vcapi` redirect case.
`interactionUrl.ts` is VCALM indirection, and `interactionRequest.ts`'s
`openInteractionRequest` is the answering wallet's one-call entry point over an
interaction URL: resolve the protocols map, begin the named exchange, hand back
the VPR. Classification stays with the caller. `ephemeralExchange.ts` is the
requester's half of a WAS server's ephemeral exchange -- create one carrying a
VPR, then poll until the wallet answers, bounded by the caller's `AbortSignal`
or the poll's own deadline. Those routes are unauthenticated, so nothing there
signs a request. `capabilityRequest.ts`'s `composeCapabilityRequest` builds the
zcap-only VPR a requester stores on such an exchange: one
`AuthorizationCapabilityQuery` carrying the requested details verbatim, with no
`DIDAuthentication` query and no `domain`, since a requester without an attested
origin has no domain a wallet could check.

The App Connect exchange this pipeline serves -- the `AppConnectQuery`, the
app-key credential, and the response presentation's `zcap` / `appConnect`
members -- is specified in the App Connect companion spec
(<https://github.com/interop-alliance/app-connect-spec>; local checkout
`../app-connect-spec`, read `spec.md` there). The app-key identity is scoped to
(user, origin, `appUrl`), and the derivation constants in `appKey.ts` (the
`app-key` HMAC key name) are pinned inputs of that spec's key-derivation rule.
