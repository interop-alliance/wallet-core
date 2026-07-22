# @interop/wallet-core Changelog

## Unreleased - TBD

### Added

- Two new subpaths extracting the shared wallet-request / exchange protocol
  handling and the pure credential display helpers from the two wallet apps:
  - `@interop/wallet-core/request` -- request classification and parsing (CHAPI
    get/store events, wallet-api messages and URLs), QueryByExample matching
    (both the jsonpath deep matcher and the type/issuer helpers), cryptosuite
    negotiation (`negotiateCryptosuite` / `presentationSuiteFor`), `composeVp`
    (signer and holder injected via `PresentationSigner`; optional zcap /
    appConnect embedding with an injectable vocab base IRI), the pure
    `processRequest` (consent runs in the caller; zcap and App Connect
    processing injected via `RequestProcessors`; `domainMatchesOrigin` replay
    protection), the VC-API exchange client, `sendToExchanger`, and VCALM
    `interaction:` URL handling. Network is injected (`FetchLike`, defaulting to
    the global `fetch`). The VPR type vocabulary itself now lives in
    `@interop/data-integrity-core` and is re-exported here.
  - `@interop/wallet-core/display` -- pure VC derivation / display helpers
    returning raw values (ISO strings / `Date`; formatting stays in each app's
    UI): credential name, issuer render info (with registry overlay), subject
    extraction and `extractIssuedTo`, VC 1.0 + 2.0 validity periods, OBv3
    achievement / skill / evidence / alignment helpers, credential type
    predicates, the verification-to-UI checklist builders (labels injected), and
    credential input parsing (`credentialsFromJSON` / `resolveCredentialsInput`
    with injected URL fetching).

## 0.1.0-0.1.1 - 2026-07-22

### Added

- Initial release. Shared wallet-domain logic extracted from two WAS-enabled
  wallet apps, as two subpaths:
  - `@interop/wallet-core/sync` -- the WAS replication engine core: `SyncEngine`
    (single-flight coalescing, migrate-once ordering, exponential backoff with
    jitter, abort), the `runPull` / `projectionForDoc` and `runPush` algorithms
    (change-feed pagination, empty-page checkpoint rule, decrypt-outside-
    transaction, poison-doc skip, and the content-addressed conflict settlement
    table), the replica-side `SyncStore` / `SyncedRow` / `ProjectionAction` /
    `ResolveConflict` seam, and the generic `SyncedCollectionSpec` shape. The
    wire contract and port (`WasSyncPort`, `WireDoc`, `DocCipher`,
    `SyncCheckpoint`, `MasterState`, `Json`, and the conflict / not-found error
    classes) are re-exported from `@interop/was-client`.
  - `@interop/wallet-core/space` -- the wallet Space layout contract: the shared
    collection ids and descriptive specs (`private-credentials`,
    `public-credentials`, `wallet-activity`), the `WalletActivity` wire shape
    with pure `addHistory*` payload builders, `publicCredentialUrl`, and the
    `was-link` QR hand-off contract (`buildWasLinkPayload` /
    `parseWasLinkPayload` / `encodeWasLinkSecret`) with server-URL validation.
