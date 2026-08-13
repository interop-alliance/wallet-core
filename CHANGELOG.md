# @interop/wallet-core Changelog

## 0.36.0 - 2026-08-12

### Added

- New `genesis` subpath: the account-genesis ceremony extracted from
  freewallet's signup. `mintAccountKeySet` mints a new account's key set (Space
  id, client seed, user key, did:webvh update keys); `ensureAccountGenesis`
  provisions the account in one shared stage order (Space provisioning, optional
  KMS key-map acquisition, did:webvh genesis, user-key roster genesis after DID
  publication, epoch[0] on every encrypted roster collection, Space-controller
  promotion), idempotent end to end so a torn run heals by re-running;
  `ensurePromotedSpaceController` is the promotion state machine standing alone,
  and a Space-provisioning failure is raised as the stable-named
  `AccountGenesisSpaceError` so a caller treating the later stages as non-fatal
  can still propagate a Space that never came up. The KMS key map and the
  promotion stage are optional, and the keyring bind is deliberately not a
  stage, so a client-keys-only wallet with no unlock method bound at creation
  can drive the same ceremony.
- `webvh`: `ensureDidWebvh`'s KMS key map (`didWebKeys`) is now optional. With
  no map the genesis is client-keys-only: the document's relations hold client
  keys only (no KMS authentication verification method) and no `keys.json` is
  written. A supplied map produces the same genesis as before. A later log entry
  can still add a KMS-held authentication verification method.

### Fixed

- `webvh`: revoking a client at its staged (committed but never revealed) update
  key now resolves the client's active key by log attribution and removes it,
  instead of stripping the verification methods while leaving the active key in
  `updateKeys`.

## 0.35.0 - 2026-08-12

### Added

- `keys`: `ensureIndexedFirstEpoch` installs a collection's epoch[0] together
  with its blinded-index HMAC key, wrapped to the same initial recipients, so an
  encrypted collection is indexable at birth. A collection provisioned before
  blind-index support (an epoch roster with no `hmac` member) is adopted as-is
  rather than refused; the key is installed at provisioning or never.
- `keys`: `ensureWalletSpaceEpochs` provisions every encrypted standard wallet
  collection with its blinded-index key, through that helper.

### Changed

- Update to `@interop/was-client@0.35.1`.

## 0.34.0 - 2026-08-12

### Fixed

- `clients`: the login-time roster policy's refusal match (`isRosterRefusal` in
  `rosterPolicy.ts`) keys on `err.name` instead of `instanceof`, so a refusal
  raised by a linked or duplicated copy of the package refuses the session
  instead of falling into the warn-and-proceed transport branch. Each refusal
  class's `name` is a stable contract; consumers dispatching on these classes
  should match the same way.

## 0.33.0 - 2026-08-12

### Added

- `webvh`: the ceremony-side `did.jsonl` reads run the same account-log
  continuity checks as `verifyAccountLog`. `readPublishedLog` accepts an
  optional `pinStore` (`ResourceLogPinStore`) and refuses a served log that is a
  rollback, a fork, or an SCID/method switch relative to the pinned head
  (`ResourceLogContinuityError`); under a held pin, an absent log refuses as a
  rollback too. `ensureDidWebvh`, `rotateWebvhUpdateKey` (its crash-recovery
  branch included), and `repairKeyBindings` accept optional `expectedDid` and
  `pinStore` options and thread both into their reads, so a truncated-prefix log
  cannot reach any entry-building step. `ensureDidWebvh` falls back to the
  `keys.json` webvh block's DID as the expectation; its first-contact adoption
  with neither stays exempt (it legitimately discovers the DID from the log).
  The create path establishes the pin from the log it minted, and a successful
  rotation advances it to the head it just published.

## 0.32.0 - 2026-08-12

### Added

- `webvh`: `verifyAccountLog` accepts an optional `pinStore`
  (`ResourceLogPinStore`, the same seam the governed resource logs use) and
  refuses a served account log that is a rollback, a fork, or an SCID/method
  switch relative to the pinned head, throwing `ResourceLogContinuityError` with
  the matching `reason` (a fork carries the served entries as evidence). The pin
  is established at first contact and advanced only by a log verifying past it,
  never regressed; it is persisted app-side. Without a `pinStore`, verification
  is unchanged. This closes the truncated-prefix hole: a valid prefix of the
  real log resolves to the same DID, so resolution alone accepted it and a
  ceremony built on it made erased enrollments and undone revocations durable.
- `webvh`: `readPublishedLog` accepts an optional `expectedDid` and refuses a
  `did.jsonl` resolving to any other account. Threaded as an optional option
  through `revokeWebvhClient`, `revokeAccountClient`, `publishRecoveryKey`,
  `removeRecoveryKey`, and `recoverWebvhClient`, and applied automatically to
  the mid-ceremony log re-reads in `enrollWebvhClient` and `recoverWebvhClient`.
- `clients`: `listAccountClients`, `currentAccountSigningKeys`, and
  `convergeUserKeyRosterToAccount` accept an optional `accountLogPinStore`;
  `enrollment`: `completeEnrollmentCore` does too.

## 0.31.0 - 2026-08-12

### Changed

- **BREAKING** `webvh`: every ceremony now publishes `did.jsonl` conditionally
  (compare-and-swap on the ETag of the read the entry was built on;
  create-if-absent for the initial provisioning), so two clients extending the
  log concurrently can never silently erase each other's entries. A lost race
  surfaces as the new typed `WebvhLogConflictError` and the ceremonies re-run
  themselves (rebasing on the new head) up to three attempts via the new
  `withLogConflictRetry`. Seam changes: `WebvhIdStore.getIdResourceRaw` returns
  `{ text, etag? }` instead of a bare string, and `putIdResource` accepts
  optional `ifMatch` / `ifNoneMatch` preconditions (a failed one must surface as
  an error named `PreconditionFailedError`). `wasWebvhIdStore` implements both
  via was-client's `getWithEtag` / conditional `put`. Against a backend without
  the `conditional-writes` feature the publish degrades to an unconditional
  write.
- `webvh`: the duplicated webDoc-guard-plus-publish tail of the six
  log-extending ceremonies is collapsed into one `publishUpdatedLog` helper, and
  the `did.jsonl` serialize-PUT-and-map-conflict core into `putLogResource`
  (shared with the recovery continuation's log-only publish).

## 0.30.1 - 2026-08-11

### Changed

- Update to latest `@interop/was-client@0.34.0`.

## 0.30.0 - 2026-08-11

### Added

- `space`: the four credential activity builders (`addHistoryCredentialCreated`
  / `Deleted` / `Shared` / `Unshared`) accept an optional `title` (the
  credential's display title at the time of the event). When given, the summary
  line names the title instead of the cid and `object` becomes `{ cid, title }`;
  without it the legacy shape is unchanged.

## 0.29.0 - 2026-08-11

### Changed

- **BREAKING** `request`: `WalletOnboardingQuery` now carries the account
  pointer (`did`, the account's did:webvh id, plus `spaceId` and `host`) and the
  account controller did:key, instead of `host` alone, so the enrollee joins
  without the account passphrase (which a passkey-only account does not have).
  `composeWalletOnboardingRequest` takes `{ pointer, controller }`;
  `walletOnboardingRequestOf` returns the same four members and shares one
  validator with compose. The query names the account but still authorizes
  nothing. A 0.28.0 host-only query is rejected as malformed.
- `webvh`: `isWebvhDid` moved to the `webvh/did.ts` leaf file (re-exported from
  `webvh/zcap.ts`, its unchanged public home), so the shape check can be
  imported without the zcap signing graph.

## 0.28.0 - 2026-08-11

### Added

- `request`: the `WalletOnboardingQuery` transport vocabulary --
  `composeWalletOnboardingRequest` (the inviter's VPR details body),
  `walletOnboardingRequestOf` (the enrollee's classification),
  `serializedOnboardingHost` (absolute http(s) URL, no fragment, stored as the
  parsed URL's serialization), and the `IWalletOnboardingQuery` /
  `IWalletOnboardingRequest` types. The query is one mental model per exchange:
  it refuses to mix with `QueryByExample`, standalone capability queries, or an
  `AppConnectQuery`.
- `enrollment`: the onboarding-response envelope -- `encodeOnboardingResponse` /
  `parseOnboardingResponse`, the `WalletOnboardingResponse` type,
  `ONBOARDING_RESPONSE_VERSION`, and `ONBOARDING_LABEL_MAX_LENGTH`. The envelope
  carries a connect code verbatim (validated with `parseEnrollmentRequest`; the
  connect-code version is unchanged) plus an optional suggested display label,
  which is control-character-stripped, trimmed, absent when it sanitizes to
  nothing, and refused rather than truncated past 64 characters.

### Changed

- `request`: `appConnectRequestOf` also refuses an `AppConnectQuery` combined
  with a `WalletOnboardingQuery`.

## 0.27.1 - 2026-08-11

### Changed

- Update to `was-client@0.33.0` (generator and generatorOrigin).

## 0.27.0 - 2026-08-11

### Added

- `space`: `unlock-methods` joins the shared Space layout as a system collection
  -- `UNLOCK_METHODS_COLLECTION`, `UNLOCK_METHODS_COLLECTION_SPEC` (private
  plaintext), and `UNLOCK_METHODS_RESOURCE` (`methods.json`). The spec is
  appended to `WALLET_SPACE_SYSTEM_SPECS`, so it flows into
  `WALLET_SPACE_PROVISION_ROSTER` and both wallets provision the same layout.

## 0.26.0 - 2026-08-11

### Added

- `space`: `addHistoryLogin`'s `appConnect` block accepts an optional `appUrl`
  (the validated App Connect request's parsed-URL serialization), carried
  through to the stored activity's `object.appConnect`.

## 0.25.0 - 2026-08-11

### Added

- `resourceLog`: the sealing sweep -- `sealResourceLog` and
  `latestAssertionRemovalIndex`, the idempotent backstop append that re-anchors
  a governed log's head past the controller document's latest `assertionMethod`
  removal (a rotation that no-ops leaves no post-edit entry, the gap the
  sealing-append rule closes). `VerifiedResourceLog` gains `headAnchorIndex`
  (the head's effective anchor; `null` on an unversioned controller).
- `keys`: the log-governed descriptor store is now sealable --
  `SealableEncryptionDescriptorStore` (a `seal()` method running the sealing
  sweep) with the `isSealableDescriptorStore` guard; returned by
  `logGovernedDescriptorStore` and `userKeyRosterDescriptorStore`.
- `descriptors`: `logGovernedDescriptorSource`, an `EncryptionDescriptorSource`
  over per-collection resource logs -- every acquisition (including the
  unknown-epoch refresh's re-read) re-verifies the log and resolves to its
  verified head state, refusing a head that is not a `WasEpochConfiguration`.
  `EPOCH_CONFIGURATION_STATE_TYPE` now lives here (still re-exported from
  `keys`).

### Changed

- `revokeAccountClient` runs the roster's seal backstop after the rotation
  (best-effort; reported in the new `rosterSeal` result member, never thrown),
  and `cascadeCompletion` accepts that report -- a failed seal makes the cascade
  `partial`.
- `convergeUserKeyRosterToAccount` seals the roster log after recipient
  convergence (refusal classes rethrow, transport warns) and reports `sealed` in
  its result.
- `rotateCollectionEpochsToUserKey` seals a sealable store on its no-op path;
  new `CollectionUserKeyRotationOutcome` value `'sealed'`.
- `acquireDescriptor` rethrows resource-log refusals
  (`ResourceLogIntegrityError`; `ResourceLogContinuityError` except reason
  `'rollback'`) instead of falling back to the cache -- a fabricated or forked
  log is a security signal, not an outage; a rollback still serves the cached
  copy without adopting anything.
- `request`: the app-key credential and the response presentation now carry the
  hosted App Connect context URL (`https://w3id.org/byoe/app-connect/v1`)
  instead of inline term-definition objects. `mintAppKeyCredential` /
  `reissueAppKeyCredential` set it as the credential `@context`'s second entry
  (`APP_CONNECT_CONTEXT_URL` replaces the removed `APP_KEY_CONTEXT` object);
  `composeVp` appends it once when the presentation embeds `zcap` or
  `appConnect` members, dropping the per-member term contexts and the
  `vocabBaseIri` option (also removed from `processRequest`). The shared
  document loader resolves the URL from the bundled `byoe-context` document, so
  neither signing nor verification fetches it.

## 0.24.0 - 2026-08-10

### Added

- New `resourceLog` subpath: the client side of the Resource Log Profile --
  `verifyResourceLog` (parse shape, SCID and entry-hash recomputation, entry
  proofs, the external-authorization rule against the independently verified
  did:webvh controller document with anchor monotonicity, terminal handover
  entries), `verifyResourceLogHandover`, the chain-head pin
  (`ResourceLogHeadPin` / `ResourceLogPinStore` / `memoryResourceLogPinStore`),
  the entry builders (`buildResourceLogGenesis` / `buildResourceLogEntry`,
  `ResourceLogSigner`), the read/append/create path (`readResourceLog` /
  `appendResourceLog` / `createResourceLog` with CAS rebase-and-retry and
  read-back confirmation), the `ResourceLogController` seam with its
  `webvhResourceLogController` adapter, and the `ResourceLogIntegrityError` /
  `ResourceLogContinuityError` / `ResourceLogClosedError` refusal taxonomy.
  Transport comes from `@interop/was-client/log`; hashing and proofs from
  `@interop/did-method-webvh`.
- `keys`: `logGovernedDescriptorStore` and `EPOCH_CONFIGURATION_STATE_TYPE` --
  an `EncryptionDescriptorStore` whose reads resolve to a resource log's
  verified head state and whose writes are signed log appends, so was-client's
  roster machinery drives the log unchanged.
- `space`: `USER_KEY_ROSTER_LOG_RESOURCE` (`user-key.jsonl`), the roster log's
  resource in `key-map`.
- `request`: App Connect moves into the shared pipeline under the App Connect
  spec's `appUrl` model (replacing the app-side `credentialType` / `vocabBase`
  mechanism). New `appConnectRequestOf` / `serializedAppUrl` in the classify
  path validate the `AppConnectQuery` `app` block (`{ name, appUrl }`; the
  `appUrl` must parse as an absolute URL, carry no fragment, and be same-origin
  with the attested requesting origin, else the query is malformed), and all
  storage and comparison uses the parsed URL's serialization. New `appKey`
  module: the app-key credential wire constants (fixed two-entry type array
  `["VerifiableCredential", "AppKeyCredential"]`, the static inline context with
  the `https://w3id.org/byoe#appUrl` term), matching keyed on the
  `credentialSubject.appUrl` claim (marker required, self-issuance, origin
  binding, seed-binds-subject, latest-first ranking over `issuanceDate` instants
  with absent/unparseable dates last), minting (`mintAppKeyCredential`), the
  store-time refusal policy (`assertStorableAppKey` / `assertMintedAppKey` and
  their error classes), and the stored-credential migration
  (`findLegacyAppKeyCredential` / `reissueAppKeyCredential`: a legacy
  pre-`appUrl` credential is re-issued in place with the same seed, preserving
  the derived DID; two distinct legacy identities on one origin refuse rather
  than guess).

### Changed

- Update to `@interop/security-document-loader@10`, which no longer bundles the
  BYOE App Connect context. The shared `request` document loader is unaffected:
  app-key credentials and response presentations carry their BYOE terms inline.

- `request`: `processRequest` now validates an `AppConnectQuery` before
  dispatching, and the `processAppConnect` processor seam receives the validated
  `appConnect` request (its `app.appUrl` already in serialized form) alongside
  the raw request.

- **BREAKING**: `keys`: the user key roster is now governed by a resource log
  (`key-map/user-key.jsonl`). Roster state is adopted only from a verified log
  head; the detached `epochsSig` and its machinery
  (`verifyUserKeyRosterEpochsSig`, `userKeyRosterEpochsSigner`, the `signEpochs`
  parameters) are removed -- the entry proof anchored in the did:webvh document
  took over that job. New `userKeyRosterLogSigner` builds the client's
  `ResourceLogSigner`. `userKeyRosterDescriptorStore` now takes
  `{ resolveController, pinStore, signer }`; `readUserKeyRoster` loses
  `document` / `resolveDocument` (the store's log verification subsumes the
  provenance step); `ensureUserKeyRoster`, `rotateUserKeyRoster`, and
  `convergeUserKeyRosterToDocument` lose `signEpochs`.
- **BREAKING**: `space`: `USER_KEY_ROSTER_RESOURCE` (`user-key.json`) is retired
  -- the Resource Log Profile no longer defines a point-state projection, so the
  roster log is the only serving of the roster and nothing writes or reads
  `user-key.json` (greenfield: no cleanup of a stale copy).
- **BREAKING**: `clients`: `checkUserKeyRosterAtLogin` loses `pointer` and
  `resolveDocument`; `convergeUserKeyRosterToAccount` and `revokeAccountClient`
  lose `signEpochs`; `isRosterRefusal` also treats `ResourceLogIntegrityError` /
  `ResourceLogContinuityError` as session refusals.
- **BREAKING**: `keys`: the `epochsMac` epoch-configuration MAC is retired
  stack-wide (with `@interop/was-client@0.32.0` and `@interop/storage-core`) --
  `readUserKeyRoster` no longer requires or verifies it, and roster writes no
  longer stamp it. On the log-governed roster its coverage was a strict subset
  of chain verification (the entry proof covers the full epoch configuration and
  there is no read path around the verifier), and its classic gaps --
  whole-configuration replay (the epoch pin's job) and fresh fabrication under a
  newly minted secret -- were gaps with or without it.
  `UserKeyRosterIntegrityError` stays for the non-MAC consistency refusal.
  Greenfield: no tolerance for MAC-bearing descriptors, no strip migration.
- **BREAKING**: `webvh`: `DidWebKeyMap` drops its optional `assertionMethod`
  member, and `repairKeyBindings` no longer rebuilds a KMS assertion binding
  from a legacy document -- no KMS-held assertion key exists anywhere
  (greenfield: accounts are re-provisioned, so no key map carries one), and the
  repair path never reads the document's `assertionMethod` relation.
- Update to latest `@interop/was-client@0.32.0`.

## 0.23.1 - 2026-08-10

### Changed

- Update to latest `@interop/was-client@0.30.0`.

## 0.23.0 - 2026-08-10

### Changed

- **BREAKING**: `webvh`: the KMS-held assertion key is no longer published in
  the did:webvh document -- `assertionMethod` (like every relation except
  `authentication`) now lists client keys only, since `assertionMethod`
  membership authorizes appends to co-managed resource logs. Accordingly,
  `DidWebKeyMap.assertionMethod` is optional, and `repairKeyBindings` rebuilds
  that binding only where a legacy document still publishes a KMS-backed
  assertion key.

## 0.22.1 - 2026-08-10

### Added

- `keyring`: `mintRecordEncryption` and `recordCipher` are exported -- the
  record-own-epoch envelope construction the keyring record seals with (a
  one-epoch descriptor wrapped to a KAK alone, and the EDV cipher over it), so a
  wallet app's own locally stored `{ version, encryption, wrapped }` records
  (e.g. a client-key record) seal the same way instead of re-deriving the
  construction. `recordCipher` gains an optional `collectionId` so a record
  kind's failures are labeled with its own cipher context (a diagnostic label;
  the codec is agnostic to it, and a record kind's swap protection remains its
  contents validation on unwrap -- the module docs now say so explicitly).
- `keyring`: `parseRecordFrame` is exported (with an optional `version`
  parameter defaulting to `KEYRING_RECORD_VERSION`), so a wallet app opens its
  records through the same frame validation the codec seals with instead of
  re-deriving it. `wrapKeyringRecord` / `wrapRecoveryRecord` now type the
  returned `encryption` as `CollectionEncryption` instead of `unknown`.

### Changed

- **BREAKING**: `sync`: `SyncStore.replacePending` resolves
  `{ applied: boolean }` instead of `void`, reporting whether the store's
  revision condition skipped the replace; `remintPendingEnvelopes` now requires
  a store implementing the seam at compile time (it stays optional on
  `SyncStore` itself).
- **BREAKING**: `keys`: `ensureWalletSpaceEpochs` returns `{ outcomes, failed }`
  -- per collection the settled encryption descriptor and whether this call
  installed epoch[0], plus collected per-collection failures -- instead of
  `Record<collectionId, boolean>`; one failing collection no longer rejects the
  whole call and discards what the others settled on.
- `sync`: `SyncEngineDeps.ensureProvisioned` documents that the seam must be
  memoized on a durable stamp (and when that stamp must be cleared), since the
  engine runs it unconditionally every cycle.
- `descriptors`: the retired single-key-path wording is purged from the module
  docs; an absent descriptor is documented as a plaintext collection, or an
  encrypted one whose epoch[0] install has not landed, which encrypted-declaring
  callers refuse fail-closed.
- Documented that collection content, like keyring and recovery records, is
  re-provisioned rather than migrated: installing epoch[0] onto an epoch-less
  descriptor leaves pre-epoch content unroutable, and nothing re-seals it.

### Fixed

- `descriptors`: acquisition falls back to the cached descriptor when a
  Collection Description read succeeds but carries no encryption member -- a WAS
  host masks an unauthorized read as an absent one, so an empty description is
  ambiguous and no longer takes an encrypted collection down for the session.
- `descriptors`: a failed unknown-epoch refresh no longer sticks: it may be
  retried on a later decrypt, and the original `UnknownEpochError` is rethrown
  so the create-loss re-mint still recognizes the row it repairs. A successful
  refresh stays spent once per collection per session.
- `sync`: `remintPendingEnvelopes` re-snapshots and retries rows the store
  skipped on a revision mismatch instead of counting them as re-minted, and
  throws (bounded) when a row never settles, so a skipped row can no longer
  reach the feed sealed under a superseded epoch.
- `keyring`: `parseRecordFrame` refuses a frame with no wrap before reaching the
  cipher, and names the retired pre-extraction version-1 record shape instead of
  reporting a missing encryption descriptor.

## 0.22.0 - 2026-08-10

### Added

- `sync`: the descriptor-before-first-content-push ordering invariant is stated
  and enforced at the engine's `ensureProvisioned` seam (provisioning, including
  an encrypted collection's descriptor publication, runs ahead of every cycle's
  migration sweep and push), and `remintPendingEnvelopes` implements the
  create-loss path for eager minters: adopt the winning provisioner's
  descriptor, re-mint pending (never-pushed) envelopes under its current epoch,
  then push. `SyncStore` gains the optional `replacePending` seam the re-mint
  writes through.
- `keys`: `ensureWalletSpaceEpochs` -- the provision-time key epoch[0] install
  for the wallet Space's encrypted collections: a fresh random epoch key per
  collection, wrapped to the user key, create-if-absent (an existing roster is
  adopted, never overwritten). The EDV-bearing second step every provisioner
  runs after `provisionWalletSpace`; reads and writes on an encrypted collection
  are refused fail-closed until it lands.

### Fixed

- `webvh` / `recovery`: pass `alsoKnownAsWeb: true` on every `updateDID` call,
  as `@interop/did-method-webvh@5.2.0` requires it explicitly to generate the
  parallel `did:web` document (it no longer infers it from the `alsoKnownAs`
  alias).
- Security: a collection-epoch escrow (a shared-collection grant, an App Connect
  app recipient) can no longer hand an external grantee a user-key generation
  secret, because no construction installs a user key as a collection epoch any
  more; a regression test pins the invariant.

### Changed

- **BREAKING**: upgraded to `@interop/was-client@0.29.1`: every encrypted
  collection's descriptor carries a key-epoch roster from creation, every
  envelope seals to an epoch key, and the direct-to-key-agreement-key cipher
  path is gone.
- **BREAKING**: `rotateCollectionEpochsToUserKey` is rotation-only. The
  no-epochs install branch -- the user-key-as-epoch construction, its CAS race
  handling, and the `'installed'` outcome -- is deleted; a descriptor met
  without epochs is refused fail-closed (it can only mean a tampering or
  pre-provisioning host).
- **BREAKING**: keyring and recovery records are now
  `{ version: 1, encryption, wrapped }`: the envelope seals under a record-own
  epoch whose key is wrapped to the unlock KAK, carried in the record's
  `encryption` member. The version counter is reset to 1 (greenfield -- no
  deployed records exist); records written by earlier package versions are
  refused, and such accounts are re-provisioned, not migrated.
- `descriptors`: `createRefreshingEdvDocCipher` refuses to build when no
  descriptor resolves from the source or cache, instead of falling back to a
  single-recipient cipher.
- `provisionWalletSpace` is now safe for ANY client the server authorizes as the
  Space controller, not just the wallet holding the Space's own root authority:
  `@interop/was-client@0.28.0`'s `ensureSpaceAndCollection` is create-if-absent
  and never overwrites an existing Space description, encryption descriptor, or
  access policy, so an enrolled client re-running the roster heals a torn
  signup's missing collections without touching settled configuration. The
  `controllerDid` option now applies only when the Space does not exist yet.
- The name-only configure retry for the key-epoch refusal is gone: the full
  ensure no longer re-declares `encryption` over an existing descriptor, so the
  refusal it worked around can no longer happen.
- `sync`: the push conflict/delete re-reads drop their check of
  `MasterState.deleted`, removed in `@interop/was-client@0.27.1` (an absent or
  tombstoned resource surfaces as the read resolving `null`).

## 0.21.0 - 2026-08-09

### Added

- `space`: the wallet Space provisioning roster, declared once for every wallet
  app. `SpaceProvisionSpec` (collection id, display name, `encryption`,
  `isPublic`) is the new base of `SpaceCollectionSpec`, and every spec now
  carries its friendly display `name`. New specs and lists:
  `CONTACTS_SPACE_COLLECTION_SPEC` / `CONTACTS_HISTORY_SPACE_COLLECTION_SPEC`
  (the social-core identity contract spread in, plus the wallet-Space storage
  attributes), `ID_COLLECTION_SPEC` / `KEY_MAP_COLLECTION_SPEC` (the
  provisioned-but-not-synced system collections), `WALLET_SPACE_SYNCED_SPECS`,
  `WALLET_SPACE_SYSTEM_SPECS`, and `WALLET_SPACE_PROVISION_ROSTER`.
- `space`: `provisionWalletSpace` -- the one-shot provisioner the Space-creating
  wallet runs: concurrently ensures every roster collection (synced feeds plus
  `id` / `key-map`) with its declared name, encryption, and public-read grant,
  including the name-only retry for an encrypted collection whose descriptor
  already carries key epochs. A Space provisioned through it is identical no
  matter which wallet app created it.

### Changed

- **BREAKING**: `space`: `WALLET_SPACE_COLLECTION_SPECS` (the three-spec,
  non-contacts list) is replaced by `WALLET_SPACE_SYNCED_SPECS` (all five synced
  feeds, contacts included).

## 0.20.0 - 2026-08-06

### Added

- `identity`: `agentsFromKeyAgent` is now exported -- assembles the derived
  agents (signer, `ZcapClient`, X25519 key agreement key, key resolver) from an
  existing `CapabilityAgent`, so downstream packages deriving their own agent
  share one implementation of the assembly.
- `space`: `WALLET_SPACE_NAME` -- the app-neutral Space display name ("Wallet
  Space") every wallet passes when provisioning, so a shared Space keeps one
  name no matter which wallet provisions it.

## 0.19.0 - 2026-08-06

### Added

- `space`: `addHistoryWalletLogin` -- the Login activity builder for a local
  wallet unlock ("Logged in to wallet."), distinct from the relying-party
  `addHistoryLogin`.

## 0.18.0 - 2026-08-06

### Changed

- **BREAKING**: the "PUK" abbreviation is retired across the package. The
  concept is unchanged (the account-wide key that is recipient zero of every
  encrypted collection, delivered through the wrap-set roster); identifiers
  become `userKey` / `UserKey` / `USER_KEY` and prose says "user key". Files
  `keys/puk.ts`, `keys/pukRoster.ts`, `keys/pukCascade.ts` are now
  `keys/userKey.ts`, `keys/userKeyRoster.ts`, `keys/userKeyCascade.ts`; the
  subpath export names (`/keys`, `/clients`, ...) are unchanged. Export map:
  - Types: `Puk` to `UserKey`, `AdoptedPuk` to `AdoptedUserKey`,
    `PukCascadeResult` to `UserKeyCascadeResult`, `CollectionPukRotationOutcome`
    to `CollectionUserKeyRotationOutcome`, `PukRosterReadResult` to
    `UserKeyRosterReadResult`.
  - Errors (class and `.name`): `PukRosterIntegrityError`,
    `PukRosterContinuityError`, `PukRosterUnwrapError` to
    `UserKeyRosterIntegrityError`, `UserKeyRosterContinuityError`,
    `UserKeyRosterUnwrapError`.
  - Functions: `mintPuk` to `mintUserKey`, `pukVaultKeys` to `userKeyVaultKeys`,
    `pukAsRecipient` to `userKeyAsRecipient`, `ensurePukRoster` to
    `ensureUserKeyRoster`, `readPukRoster` to `readUserKeyRoster`,
    `addPukRosterRecipient` to `addUserKeyRosterRecipient`, `rotatePukRoster` to
    `rotateUserKeyRoster`, `unwrapPukGenerations` to `unwrapUserKeyGenerations`,
    `cascadeCollectionsToPuk` to `cascadeCollectionsToUserKey`,
    `rotateCollectionEpochsToPuk` to `rotateCollectionEpochsToUserKey`,
    `convergePukRosterToDocument` to `convergeUserKeyRosterToDocument`,
    `convergePukRosterToAccount` to `convergeUserKeyRosterToAccount`,
    `checkPukRosterAtLogin` to `checkUserKeyRosterAtLogin`,
    `pukRosterDescriptorStore` to `userKeyRosterDescriptorStore`,
    `pukRosterRecipientResolver` to `userKeyRosterRecipientResolver`,
    `pukRosterEpochsSigner` to `userKeyRosterEpochsSigner`,
    `verifyPukRosterEpochsSig` to `verifyUserKeyRosterEpochsSig`,
    `parseClientRecordPuk` to `parseClientRecordUserKey`.
  - Constants: `PUK_ROSTER_RESOURCE` to `USER_KEY_ROSTER_RESOURCE`.
  - Options and members crossing the API: `options.puk` to `options.userKey`,
    `read.puk` to `read.userKey`, `onPukAdopted` to `onUserKeyAdopted`,
    `pukRosterStore` to `userKeyRosterStore`, and the `{ puk }` payload of
    `onRotationAdopted` to `{ userKey }`.
- **BREAKING**: `USER_KEY_ROSTER_RESOURCE` is now `'user-key.json'` (was
  `'puk.json'`). No read fallback onto the former name: accounts provisioned
  under it must be re-provisioned.
- **BREAKING**: the client-key record's persisted user key member is now
  `userKey` (was `puk`). No legacy parse: records written under the former name
  surface as key-less.

## 0.17.1 - 2026-08-05

### Fixed

- Update to latest was-client and social-core deps.

## 0.17.0 - 2026-08-05

### Fixed

- `sync`: `markPushed`/`markDeletedPushed` clear the dirty flag only when the
  row's `revision` token still matches the pushed one, so a local write racing
  an in-flight push stays dirty and is re-pushed instead of silently lost.
- `sync`: `runPull` treats only a server-signaled empty page (or an unadvanced
  checkpoint) as caught up, so a server that clamps `limit` below the requested
  batch size no longer stalls the backlog.
- `sync`: the retry delay's jitter now lands within
  `[maxDelayMs / 2, maxDelayMs]` instead of overshooting the cap by up to 50%.
- `webvh`: `revokeWebvhClient` re-derives the target's current update key from
  the log when the supplied key was rotated away between listing and revocation,
  refusing loudly when attribution is ambiguous -- a self-rotated client no
  longer retains log-update authority after a "successful" revocation.
- `webvh`: every completion path republishes `did.json` from the resolved log
  via the shared `concludeWithPublishedLog`, healing a publish torn between the
  `did.jsonl` and `did.json` PUTs.
- `request`: QueryByExample matching normalizes JSON-LD's single-value vs array
  duality in both directions -- a string example value matches a credential
  holding the array form (e.g. `type`), and an array example value matches the
  compacted single-value form.
- `request`: the unsigned-VP branch of `composeVp` derives the presentation's
  data model version from the shared credentials (via the new
  `presentationVersionFor`) instead of hardcoding VC 1.0, so a VC 2.0 credential
  shared without a DID-Auth query gets a v2-context presentation.
- `request`: a presentation request carrying more than one `DIDAuthentication`
  query is rejected at the parse boundary (`parseWalletApiMessage` /
  `isDIDAuthOnlyRequest`) instead of being accepted and then throwing
  mid-classification.
- `display`/`request`: malformed credential and request shapes (non-object
  `credentialSubject`, null `identifier`/`achievement`/`skill` entries,
  primitive CHAPI `data`, non-array or null-entry `acceptedMethods`) degrade to
  fallback rendering or a descriptive error instead of throwing a raw
  `TypeError`, via the shared `recordList`/`asRecord` shape guards.
- `clients`: `revokeAccountClient` checks roster existence before rotating, so
  disconnecting a client on an account with no encrypted collections completes
  gracefully instead of throwing after the document edit already landed.
- `clients`: `convergePukRosterToAccount` no longer reports a rotation it
  performed as `rotated: false` with the stale pre-rotation key -- past a
  successful rotation a failed adopting read throws, and roster
  continuity/integrity/unwrap refusals rethrow the same way
  `checkPukRosterAtLogin` rethrows them.
- `enrollment`: connect-code keys are validated by a full multibase/multicodec
  decode (base58 decodability, multicodec header, 32-byte length) before
  anything is signed or published into the append-only DID log, not just by
  their 4-character prefix.
- `keys`: `encodeClientKeyRecord` length-checks every 32-byte secret
  (`puk.secret`, `puk.signingSeed`, the webvh update seeds) at encode time,
  matching its decoder, so a wrong-length secret throws instead of writing a
  record the decoder will forever refuse.
- `space`: the WAS-link local-host check matches the WHATWG bracketed IPv6
  serialization (`[::1]`), so an IPv6-localhost dev server is treated as
  loopback like `localhost` / `127.0.0.1`.
- `keys`: the first-epoch branch of the PUK cascade handles a concurrent cascade
  winning the initial epoch install (`ValidationError` from `initRecipients`) by
  re-reading and converging, matching its two-generation sibling, instead of
  throwing out of the whole cascade.

### Changed

- **BREAKING**: PUK roster acceptance is now bound to the account's did:webvh
  document. Every roster write that changes the epoch configuration is signed by
  the writing client's enrolled Ed25519 key (`epochsSig`, stamped via
  `@interop/was-client`'s new `signEpochs` hook), and a read that adopts an
  epoch from the roster -- a rotation by another client, or a freshly enrolled
  client's first read -- verifies that signature against the locally verified
  document before adopting, refusing (`PukRosterIntegrityError`) a configuration
  no enrolled client signed. Previously those paths were authenticated only by
  the `epochsMac`, whose key is unwrapped from the served descriptor itself, so
  a compromised host could mint its own epoch, wrap it to a client's
  world-readable key-agreement key, and have the client adopt a host-known
  per-user key. API changes: `ensurePukRoster`, `rotatePukRoster`,
  `convergePukRosterToDocument`, `convergePukRosterToAccount`, and
  `revokeAccountClient` take a required `signEpochs` (build it with the new
  `pukRosterEpochsSigner`); `checkPukRosterAtLogin` takes the account-log
  `pointer` (the document is fetched and verified lazily, only when a read
  adopts); `readPukRoster` takes `document` / `resolveDocument`, required on the
  adopt path. Rosters written by earlier releases carry no `epochsSig`, so a
  rotated or first read refuses them until a signing client re-rotates the
  roster.
- **BREAKING**: contact head payloads carry `writerId` instead of `deviceId`,
  following the rename in `@interop/social-core`. The field is an unkeyed,
  clearable attribution label for the writing agent, not a hardware identity.
- `sync`: pulled pages decrypt concurrently instead of one document at a time.
- `sync`: the contacts last-write-wins rule now orders `updatedAt` stamps by
  parsed time (via `@interop/social-core`), so two writers emitting different
  fractional-second precisions no longer resolve a conflict to the older
  revision.
- Style sweep: JSDoc comments use the multi-line form throughout, and
  single-letter callback parameters in `display` and `request` were renamed to
  descriptive names. No behavior change.

### Added

- `webvh` subpath: `attributeClientUpdateKey` (the listing's client-to-update-
  key attribution, reused by revocation) and `concludeWithPublishedLog`.
- `display` subpath: `recordList` -- normalizes a loosely-typed JSON-LD field to
  an array of plain records, dropping null and primitive entries.
- `request`: `presentationVersionFor` -- the VC data model version a
  presentation carrying the given credentials must use.

## 0.16.0 - 2026-08-03

### Added

- `webvh` subpath: `delegationKeyInDocument` -- one predicate for "is this
  recorded delegation's verification method still published", matched on the key
  multibase so the did:key and did:webvh spellings of one key agree. A record
  with no key id reports NOT published (the conservative reading, so a
  regenerate nudge fires on records predating the field).
  `documentKeyMultibases` and the structural `PublishedKeyDocument` type are
  exported beside it.
- `clients` subpath: `listAccountClients` and `currentAccountSigningKeys` accept
  an optional `verifiedLog` (a `verifyAccountLog` result, exported as
  `VerifiedAccountLog`) instead of fetching and re-verifying `did.jsonl`
  themselves -- the seam for holding one verified log per session. Behavior is
  unchanged when the option is absent.

### Changed

- `rotateWebvhUpdateKey` refuses a diverged staged key up front ("the staged key
  is not the log-committed next key") instead of persisting rolled seeds and
  then failing in the resolver with an opaque error. The state remains
  self-healing; the guard buys early, loud diagnosis.
- `listAccountClients` reads the DID log and the client labels in parallel; they
  are independent reads that were queued in sequence.

## 0.15.0 - 2026-08-03

### Added

- `keys` subpath: the client-key record codec -- `encodeClientKeyRecord` /
  `decodeClientKeyRecord` over the semantic record
  `{ clientSeed, puk, webvhUpdateKeys, controller, pointerDid }`, with
  `parseClientRecordPuk` / `parseClientRecordWebvhKeys` exported for granular
  reuse and `assertEnrolledClientKeyRecord` narrowing a decoded record to a
  complete enrolled-client key set. Byte fields are base64url without padding
  and length-checked on the way in; an absent optional member is a record
  written before that member existed, while a present-and-malformed one throws,
  since both malformable members are load-bearing (the encrypted collections are
  keyed on the per-user key, and the identity log can only be extended with the
  update-key seeds). The module doc states the two ordering invariants an app's
  storage must honor: the per-user key and the roster epoch pin persist
  atomically, and rolled update-key seeds persist BEFORE the log entry that
  publishes them. Storage and wrapping stay app-side, so a browser wallet's
  unlock-layer envelope and a mobile wallet's encrypted database column now
  encode and validate identically. Also published as the leaf subpath
  `@interop/wallet-core/keys/clientKeyRecord`, whose only import is a base64url
  codec, so a storage layer (and a test runner loading it) never pulls in the
  crypto / EDV graph the `keys` subpath reaches; the `keys` re-export is
  unchanged.
- New `clients` subpath: the enrolled-client management surface both wallets'
  "connected wallets" screens are built on.
  - `listAccountClients` -- verify the account's did:webvh log locally,
    enumerate the clients it enrolls (keyed on `capabilityInvocation`, so a
    recovery code's key and the server-side conveniences are excluded
    structurally), merge the `client-labels.json` display labels, and mark the
    caller's own row. `currentAccountSigningKeys` moved in beside it -- the same
    read reduced to the key set a recorded app grant's delegation signer is
    checked against; the session-shaped gating (a guest, a storage-less session)
    stays app-side, as its own doc comment says.
  - `disconnectEligibility` / `revokedClientKeysFor` / `cascadeCompletion` --
    the disconnect-eligibility policy as data and pure functions:
    self-disconnect refused, the last enrolled client refused, disconnect
    disabled on an ambiguous update-key attribution, and a partial collection
    fan-out reported as the resumable success it is.
  - `revokeAccountClient` -- the revocation cascade in dependency order
    (document edit, roster rotation, collection fan-out, optional recovery
    re-mints), with the app-specific stages injected: a
    `remintRecoveryDelegations` callback and a `CascadeCollections` source whose
    `collectionIds` may be a fixed set or a remote listing. An account with no
    roster yet completes with `rotated: false` rather than throwing -- the
    document edit has landed, so the client IS disconnected.
  - `checkPukRosterAtLogin` / `convergePukRosterToAccount` -- the login-time
    roster policy: the three roster errors (rollback, failed authentication, no
    unwrappable wrap) refuse the session, anything else keeps the cached key for
    an offline start; the convergence runs before the fan-out and adopts through
    a callback, so adoption side effects stay app-side. The once-per-session
    guard stays with the caller, which is the only side that knows what a
    session is.
- `sync` subpath: `resolveContactHeadConflict` and `contactHeadPayloadOf` -- the
  last-write-wins rule for the one mutable collection, implemented once:
  tombstone on either side resolves to the remote master, both sides decrypted
  through the collection's document cipher and validated, `remotePayloadWins`
  decides, and anything unreachable falls back to the remote master (except a
  valid local side over a malformed remote one, which re-pushes and repairs the
  server copy). Lives here rather than in `@interop/social-core` because
  deciding it needs a `DocCipher` -- but it takes the envelope predicate and
  that seam from was-client's plain `sync` module, so the `sync` subpath stays
  free of the EDV graph and keeps loading in a plain test runner.
- `request` subpath: `classifyWalletInput` / `handleWalletInput` -- the ordered
  discrimination every "scan or paste something" entry point runs, with the
  per-grammar handlers injected and no fetching, navigation, or storage of its
  own. Routes the connection payload, the connect code, the legacy credential
  request, interaction URLs, registered-scheme deep links, wallet API messages
  (raw JSON or carried in an unregistered-scheme link's `request` parameter),
  and, as the deliberate fallback, raw credentials.
- `enrollment` subpath: `CONNECT_CODE_PREFIX` and `isConnectCode`, split into a
  leaf module so an input classifier can recognize a connect code without
  pulling in the ceremony's dependency graph.

### Changed

- `webvh` subpath: `StagedCommitmentAmbiguousError` documents its `name` as a
  stable contract -- consumers should match
  `err.name === 'StagedCommitmentAmbiguousError'` rather than `instanceof`,
  which does not survive a linked or duplicated copy of the package.
  `revokeAccountClient` re-throws it unwrapped, and says so.
- Depends on `@interop/social-core` (the contact head payload's shape and its
  last-write-wins comparison).

## 0.14.0 - 2026-08-03

### Changed

- Update to was-client 0.25.0

### Added

- `docs/cross-replica-sync-compatibility.md`: the compatibility contract between
  the two WAS replication engines (this package's `SyncEngine` and the web
  wallet's RxDB adapter), established by the cross-replica conformance exercise
  (`freewallet/tests/conformance/`): what is proven, which divergences are
  tolerated by construction (EDV `sequence` advisory, ciphertext-derived content
  ids), and the open defects the exercise caught.

## 0.13.0 - 2026-08-03

### Added

- `webvh` subpath: `verifyAccountLog` (with the `AccountLogMissingError` class)
  -- the published-log verification step every account ceremony runs first:
  fetch the world-readable did:webvh log over plain `fetch`, resolve it locally,
  refuse a log that resolves to a DID other than the one named, and hand back
  the document, the raw log, and the log's effective `updateKeys` /
  `nextKeyHashes`. An absent log throws `AccountLogMissingError` so an in-flight
  enrollment can read it as "not approved yet" rather than as a broken account.
- `webvh` subpath: `wasWebvhIdStore` -- the WAS-backed `WebvhIdStore` the
  did:webvh ceremonies write through (both identity collections addressed as
  plaintext; bodies written as raw bytes under the caller's content type, so the
  log stays `text/jsonl` and the document `application/did+json`).
- `keys` subpath: `wasClientLabelsStore` -- the WAS-backed `ClientLabelsStore`
  over `key-map/client-labels.json`.
- `keys` subpath: `rosterRecipientKid` -- the one builder of a client's roster
  kid (`did:key:<ed-multibase>#<x-multibase>`), shared by the enrollment wrap,
  the roster read that looks for it, and the rotation that retires it.
  `enrollmentRecipientKid` now delegates to it.
- `keys` subpath: `convergePukRosterToDocument` -- the standing detector for a
  revocation cascade torn between its document edit and its roster rotation.
  Given the verified account document (and optionally a descriptor already
  read), it finds every current-epoch roster recipient the document no longer
  keys and rotates the roster away from all of them in one epoch, reporting
  `rotated`, the stale recipient kids, and the resulting descriptor. A healthy
  account writes nothing; a current epoch with no document-backed recipient at
  all is refused (`PukRosterIntegrityError`) rather than rotated onto no one.

### Changed

- `webvh` subpath: `revokeWebvhClient` now resolves to `{ did, doc }` -- the
  account's document AFTER the revocation entry, which is what the roster
  rotation that follows resolves its remaining recipients from, so a caller no
  longer re-fetches and re-verifies the log it just extended.
- `enrollment` subpath: `approveEnrollment` now resolves to
  `{ did, clientDid, signingKeyMultibase }`, exposing the enrollee identity it
  already computes so a caller needs no second parse of the connect code.
- `enrollment` subpath: `completeEnrollmentCore` now performs its
  verify-the-published-log step through `verifyAccountLog` instead of its own
  inline fetch-and-resolve block (behavior unchanged: an absent log, or a log
  not yet listing this client's keys, still throws `EnrollmentPendingError`).

### Fixed

- The unresolvable-log error message no longer renders "(undefined)" when the
  resolver returns no DID document without reporting an error of its own.

## 0.12.0 - 2026-08-02

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
