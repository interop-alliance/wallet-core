# @interop/wallet-core Changelog

## 0.5.0 - TBD

### Added

- `deriveCollectionKeys` per-collection KAK derivation (moved from
  `@interop/was-react`) on the `@interop/wallet-core/identity` subpath,
  alongside `DEFAULT_KAK_HANDLE` and the `CollectionKeys` type. It derives one
  collection's X25519 key-agreement key from the master seed via
  `HKDF-SHA256(seed, 'kak:v1:<collectionId>')`, reusing `singleKeyResolver` for
  the bundled resolver.

## 0.4.1 - 2026-07-23

### Changed

- Update to latest `@interop/vc@11.0.6`.

## 0.4.0 - 2026-07-23

### Added

- `SyncedCollectionSpec` and `SyncEngineDeps` gain an optional `validatePayload`
  guard, threaded through `runPull` / `projectionForDoc`: a pulled document that
  decrypts but fails the collection's guard (written by the other replica --
  possibly a buggy or schema-incompatible writer) is stored with the checkpoint
  advancing, but never projected into the local read-model.

### Changed

- **Breaking:** `SyncStore.adoptMaster` is renamed `adoptLatest` (its `master`
  option is now `latest`). The wire-contract `MasterState` type keeps its
  RxDB-derived name for web parity.

## 0.3.1 - 2026-07-23

### Added

- New `@interop/wallet-core/request/matching` subpath: the pure QueryByExample
  matchers (and their query/credential types), importable without pulling the
  `./request` barrel's signing / document-loader dependency graph.

### Changed

- `composeVp` no longer requires a `presentationSigner` for unsigned VPs; it is
  now optional and enforced (with a thrown error) only when `didAuthRequested`
  is true.

## 0.3.0 - 2026-07-22

### Added

- New `@interop/wallet-core/identity` subpath: the WAS identity derivation both
  wallet apps must perform byte-for-byte identically. `agentsFromSecret` (string
  controller secret) and `agentsFromSeed` (already-derived 32-byte seed) return
  `ProfileAgents` -- the did:key `CapabilityAgent`, a `ZcapClient` signing
  invocations and delegations with the bootstrap key, the X25519 key agreement
  key (the Montgomery form of the signing key), and a single-key resolver. The
  load-bearing derivation names are exported as `BOOTSTRAP_HANDLE` /
  `BOOTSTRAP_KEY_NAME`, and the one-key `IKeyResolver` factory as
  `singleKeyResolver` (also usable by app-side derivations such as a keyring
  unlock identity). Kept out of the root export so plaintext consumers never
  pull the webkms-client / ezcap / x25519 dependency graph.

### Changed

- Bumped the `@interop/was-client` dependency range to `^0.20.0` (so consumers
  share one instance with apps already on 0.20.x).

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
