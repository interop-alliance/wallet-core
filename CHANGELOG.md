# @interop/wallet-core Changelog

## 0.12.0 - TBD

### Added

- `webvh` subpath: `listEnrolledWebvhClients` (with the `EnrolledWebvhClient`
  type) -- the enrolled-client listing over a caller-verified did:webvh log, for
  a "your wallets" management surface. Enumeration is keyed on the final
  document's `capabilityInvocation` (so a recovery key's `keyAgreement`-only
  method and the KMS-held conveniences are excluded structurally); each client's
  ACTIVE update key and its enrollment `versionTime` are recovered by log
  attribution, and a row with all three key members present is exactly a
  `RevokedClientKeys`. Also exported: `keyAgreementTwinMultibase` (an Ed25519
  signing key's canonical X25519 twin, the derivation every roster wrap uses).
- `keys` subpath: `readClientLabels` / `setClientLabel` / `removeClientLabel`
  (with the `ClientLabelsRecord` / `ClientLabelsStore` types) -- the
  enrolled-client display labels, a plain-JSON map from signing-key multibase to
  label in the new `key-map/client-labels.json` resource
  (`CLIENT_LABELS_RESOURCE` in the `space` subpath). Display metadata with no
  authority: reads degrade to an empty map, writes are last-write-wins.

## 0.11.0 - 2026-08-01

### Added

- `keys` subpath: `cascadeCollectionsToPuk` (with the `PukCascadeResult` type)
  -- the collection fan-out of the PUK rotation cascade, previously wallet-side.
  Re-epochs every named collection onto the roster's current PUK in parallel
  over a `storeFor(collectionId)` descriptor-store seam, with an optional
  per-collection `isEncrypted` pre-filter; per-collection failures are collected
  in `failed` rather than aborting the fan-out. Also the login-time
  cascade-completion sweep's driver.

## 0.10.0 - 2026-08-01

### Added

- `webvh` subpath: `revokeWebvhClient` -- the one-entry client-revocation edit,
  the document half of disconnecting an enrolled wallet client: its verification
  methods, update key, and both its standing `nextKeyHashes` commitments leave
  in a single log entry. The staged commitment is recovered by log attribution
  (callers pass the standing recovery codes' update-key hashes as
  `knownLatentHashes`); an attribution that cannot isolate a single hash throws
  the new `StagedCommitmentAmbiguousError` rather than guessing. Also exported:
  the `RevokedClientKeys` type, `relationIds`, and `assertCarryOverCommitments`
  (previously internal to the recovery module).
- `keys` subpath: the PUK rotation cascade. `rotatePukRoster` rotates the roster
  off a revoked recipient (remaining recipients resolved from the locally
  verified did:webvh document, no-op pull axis); `pukAsRecipient` /
  `unwrapPukGenerations` / `rotateCollectionEpochsToPuk` (with the
  `CollectionPukRotationOutcome` type) re-epoch one encrypted collection onto
  the roster's current PUK via was-client's `replaceRecipient`, with staleness
  detected from durable state alone and history escrowed to the current key.
  Design notes in the module docs.
- `keyring` subpath: `putUnlockKeyringWithCapability` -- upserts the keyring
  record under an attached management capability instead of a root invocation,
  so a revocation cascade can re-PUT a recovery code's unlock record without
  holding the code.
- `space` subpath: `ACTIVITY_TYPE.ClientRevoke` and the
  `addHistoryClientRevoked` wallet-activity payload builder.

### Upgraded

- `@interop/was-client` to ^0.24.0 (`replaceRecipient`, the exported
  `resolveEpochKeys`).

## 0.9.0 - 2026-08-01

### Changed

- **BREAKING**: `composeVp`'s default `vocabBaseIri` moves from
  `urn:freewallet:vocab#` to the shared BYOE vocabulary namespace
  `https://w3id.org/byoe#`, so the embedded `zcap` / `appConnect` VP terms now
  expand to `https://w3id.org/byoe#zcap` / `https://w3id.org/byoe#appConnect`
  (container/type behavior unchanged). Term IRIs are canonicalized into the
  DIDAuth proof, so presentations signed under the old default no longer match
  byte-for-byte.

## 0.8.0 - 2026-08-01

### Changed

- **BREAKING**: Rename "marker" to "encryption descriptor" across the API,
  matching the spec wording and `@interop/was-client` 0.23.0 (whose renamed
  `EncryptionDescriptorStore` / `resourceDescriptorStore` this release
  consumes). The value itself (`CollectionEncryption`) and the wire format are
  unchanged.
  - The `markers` subpath is now `descriptors`
    (`@interop/wallet-core/descriptors`).
  - `MarkerSource` / `MarkerCache` are now `EncryptionDescriptorSource` /
    `EncryptionDescriptorCache`; the cache members are `readDescriptor` /
    `writeDescriptor`, taking `{ collectionId, descriptor }`.
  - `acquireMarker` / `acquireMarkers` / `wasMarkerSource` are now
    `acquireDescriptor` / `acquireDescriptors` / `wasDescriptorSource`;
    `MarkerRefreshPolicy` is now `DescriptorRefreshPolicy`
    (`createRefreshingEdvDocCipher` keeps its name).
  - On the `keys` subpath, `pukRosterMarkerStore` is now
    `pukRosterDescriptorStore`, and `PukRosterReadResult.marker` is now
    `PukRosterReadResult.descriptor`.
- Document every subpath in the README (previously it stopped at the first five)
  and add the `recovery` subpath to the root module's list.

### Upgraded

- `@interop/was-client` to ^0.23.0.

## 0.7.0 - 2026-08-01

### Added

- New `markers` subpath: collection-encryption marker acquisition shared by both
  wallet apps -- the `MarkerSource` / `MarkerCache` host seams (plus
  `wasMarkerSource` over a was-client handle), `acquireMarker` /
  `acquireMarkers` (fetch + cache, falling back to the cached marker when the
  Collection Description cannot be fetched so a shared collection keeps
  encrypting under its current epoch offline), the once-per-collection-per-
  session `MarkerRefreshPolicy`, and `createRefreshingEdvDocCipher` (an EDV
  document cipher that, on an unknown-epoch decrypt, re-reads the description
  and retries once).
- New `recovery` subpath: recovery codes modeled as minimal, always-enrolled
  wallet clients on the roster identity model.
  - `generateRecoveryCode` / `formatRecoveryCode` / `normalizeRecoveryCode` /
    `decodeRecoveryCode` / `RECOVERY_KDF` -- the 16-byte base58 code format and
    its own unlock-derivation parameters (a distinct permanent HKDF salt, so a
    code and a passphrase can never derive the same unlock Space).
  - `recoveryClientFromCode` -- the deterministic key set a code derives: unlock
    identity, client seed, and a single did:webvh update key.
  - `wrapRecoveryRecord` / `unwrapRecoveryRecord` -- the keyring record carrying
    the account pointer and the pre-minted PUT-on-`did.jsonl` delegation (never
    a seed, never a PUK wrap).
  - `publishRecoveryKey` / `removeRecoveryKey` -- publish or revoke the code's
    `keyAgreement` verification method (an ordinary, unmarked entry: client
    surfaces exclude recovery keys structurally, by their absence from
    `capabilityInvocation`) and its update-key hash in `nextKeyHashes`; the
    update key never joins `updateKeys`.
  - `recoverWebvhClient` -- the self-enrolling recovery continuation: a
    reveal-and-commit entry signed by the code's pre-committed update key, then
    an entry enrolling the new client, retiring the spent code, and installing a
    replacement code. Publishes `did.jsonl` only, through the delegation's
    narrow scope.
- `webvh` subpath now exports `updateKeySigner`, `readPublishedLog`,
  `publishWebvhLog`, `relationIds`, `MULTIKEY_VM_TYPE`, and the
  `PublishedWebvhLog` type (previously module-private), so the recovery module
  composes over them instead of duplicating the log plumbing.

## 0.6.0 - 2026-08-01

### Added

- Four new subpaths with the account-identity and client-enrollment machinery
  shared by both wallet apps:
  - `webvh` -- did:webvh hosting (`ensureDidWebvh`, `rotateWebvhUpdateKey`,
    `enrollWebvhClient`, `repairKeyBindings`) and ZCap signing under the
    account's did:webvh verification-method id.
  - `keys` -- the per-user key (`mintPuk`, `pukVaultKeys`) and its
    `key-map/puk.json` wrap-set roster helpers.
  - `keyring` -- the unlock layer: `deriveUnlockIdentity`, `unlockSpaceIdFor`,
    the account-pointer record codec, and `fetchKeyringRecord`.
  - `enrollment` -- the client enrollment ceremony: the connect-code channel,
    `approveEnrollment`, and the portable `completeEnrollmentCore`.
- System collection and resource name constants for identity and key material on
  the `space` subpath.

### Changed

- The unlock derivation now uses `@noble/hashes` (PBKDF2 and HKDF) instead of
  WebCrypto's `crypto.subtle.deriveBits`, which React Native does not provide;
  output is byte-identical (verified by test).
- Requires `@interop/was-client@^0.22.0`; moves
  `@interop/ed25519-verification-key` to runtime dependencies; adds
  `@interop/did-method-webvh` and `@noble/hashes`.

### Removed

- **Breaking:** removed the unused `deriveCollectionKeys`, `DEFAULT_KAK_HANDLE`,
  and `CollectionKeys` from the `identity` subpath -- the per-collection KAK
  derivation was retired when recipient keys unified on the identity
  key-agreement key.

## 0.5.0 - 2026-07-23

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
