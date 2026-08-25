# Architecture

The codebase map for `@interop/wallet-core`: what the library is, the module
layers and their dependency direction, the wallet Space layout, the key
hierarchy, the did:webvh client roster, the ceremonies and cascades, the
permanent wire-level constants, and where neighboring logic lives. For toolchain
rules (pnpm, build, tsconfigs, tests) see [AGENTS.md](AGENTS.md); for code
conventions see [CONTRIBUTING.md](CONTRIBUTING.md). The [README](README.md)
carries a one-paragraph blurb per subpath plus install/usage -- this document
goes deeper (dependency direction, flows, invariants) rather than restating
those blurbs.

## What this library is

`@interop/wallet-core` is the shared, correctness-critical wallet logic two
WAS-enabled wallet apps hold in common:

- **DCW** -- the React Native mobile wallet (SQLite-backed), and
- **freewallet** -- the browser wallet (RxDB/IndexedDB-backed).

Their checkouts live beside this repo (`../dcw`, `../freewallet`), and each has
its own ARCHITECTURE.md describing the app-side half of the flows below
(screens, session objects, storage managers).

The two apps are replicas of the same account: they must derive the same
identity from the same secret, lay out the same Space, produce byte-identical
wire artifacts, and converge when both write. The selection rule for what lives
here is therefore **cross-replica agreement**: code where a drift between the
apps corrupts an account or splits a sync feed. Code that only needs to be
correct within one app stays app-side.

Two properties hold everywhere in `src/`:

- **Isomorphic, no I/O of its own.** Runs in browser, Node.js, and React Native.
  Nothing here owns durable storage or UI; network access goes through injected
  seams (a `WasSyncPort`, a was-client handle, a `FetchLike`). The pervasive
  pattern is injected side effects: `SyncEngineDeps`, `SyncStore`, `DocCipher`,
  `EncryptionDescriptorSource` / `EncryptionDescriptorCache`, `WebvhIdStore`,
  `ClientLabelsStore`, `RecoveryLogStore`, `PresentationSigner`,
  `RequestProcessors`, `WalletInputHandlers`, injected `labels` maps and
  `fetchUrl`, injected `schedule` / `random` / `backoff`.
- **Pure derivation out, formatting and consent in the caller.** `request`'s
  `processRequest` is pure and leaves consent and the response channel to the
  app; the VC display derivation that follows the same rule (raw values out,
  formatting in the UI) lives in `@interop/vc-display`.

## Module map and dependency direction

Modules by layer; a module may import from lower layers only. There are no
cycles.

```
layer 0 (no internal deps):  sync   space   identity   resourceLog
                             (resourceLog sits over the external
                             @interop/vh-resource-log, the profile's
                             generic client side)
layer 1:                     webvh (space, resourceLog)
                             keyring (space, identity)
                             descriptors (resourceLog)
layer 2:                     keys (webvh, space, identity, resourceLog,
                             descriptors/logSource -- a leaf file)
layer 3:                     enrollment (webvh, keys, keyring, identity,
                             resourceLog)
                             unlock (webvh, keys, keyring, identity,
                             resourceLog, clientAnnex/ladder -- the one
                             pinned exception, see below)
                             genesis (webvh, keys, space, resourceLog)
layer 4:                     recovery (unlock, webvh, keyring, space, identity)
                             clients (webvh, keys, resourceLog)
top:                         clientAnnex (may import any base subpath;
                             nothing in the base imports from it)
cross-cutting:               request (enrollment/connectCode,
                             webvh/did -- all deliberately leaf files)
root barrel:                 src/index.ts re-exports sync + space, nothing else
```

| Subpath       | Role                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Internal deps                                                                      |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `sync`        | WAS replication engine core: `SyncEngine`, `runPull` / `runPush`, the `SyncStore` replica seam, contacts LWW conflict resolution                                                                                                                                                                                                                                                                                                                                                  | --                                                                                 |
| `space`       | Wallet Space layout contract: collection ids/specs, `wallet-activity` wire shape and builders, `publicCredentialUrl`, the `was-link` QR payload                                                                                                                                                                                                                                                                                                                                   | --                                                                                 |
| `identity`    | Byte-identical WAS identity derivation: `agentsFromSecret` / `agentsFromSeed`, `singleKeyResolver`                                                                                                                                                                                                                                                                                                                                                                                | --                                                                                 |
| `descriptors` | Collection encryption-descriptor acquisition (fetch / cache / offline fallback), the log-governed descriptor source, and the unknown-epoch refresh policy                                                                                                                                                                                                                                                                                                                         | resourceLog                                                                        |
| `resourceLog` | The wallet-domain residue of the Resource Log Profile client side (the generic half -- verifier, handover check, keyed chain-head pin store, entry builders, read/append/create path, sealing sweep -- lives in `@interop/vh-resource-log`): the ceremony-tail license on ladder-signed appends, and the inventory-aware `WebvhResourceLogController` extension of the library's controller port with its did:webvh adapter, supplying the library's `admitAppend` admission hook | --                                                                                 |
| `webvh`       | The account's did:webvh log: provisioning, per-client update-key rotation, enrollment/revocation entries, client listing (`ladderVmIds` recognition included), log verification, the WAS-backed and delegated log stores, zcap signing under the webvh keyId, the standing-zcap staleness policy (`standingZcap.ts`, a leaf `recovery` re-exports)                                                                                                                                | space, resourceLog                                                                 |
| `keyring`     | The unlock layer: unlock KDF, the keyring record codec, the unlock Space lifecycle                                                                                                                                                                                                                                                                                                                                                                                                | space, identity                                                                    |
| `keys`        | The user key, its wrap-set roster (log-governed, sealable), the rotation cascade's per-collection op, the provision-time collection epoch install, the client-key record codec, client display labels                                                                                                                                                                                                                                                                             | webvh, space, identity, resourceLog, descriptors (leaf)                            |
| `request`     | Wallet-request / exchange pipeline: input classification, parsing, QueryByExample matching, cryptosuite negotiation, VP composition, the App Connect app-key credential, the `WalletOnboardingQuery` vocabulary, VC-API client, the ephemeral-exchange requester side, the zcap-only VPR builder                                                                                                                                                                                  | enrollment, webvh (leaf files)                                                     |
| `enrollment`  | The client enrollment ceremony: connect code, approval, completion, the onboarding-response envelope                                                                                                                                                                                                                                                                                                                                                                              | webvh, keys, keyring, identity, resourceLog                                        |
| `unlock`      | Standing unlock credentials: the credential-derived client identity, the unlock record codec (shell / bridge / ladder / binding, `LADDER_SEED_BYTES` included -- the record format owns its member sizes), the merged document-inventory edit (verbatim key or hash commitment), the retirement ceremony                                                                                                                                                                          | webvh, keys, keyring, identity, resourceLog, clientAnnex/ladder (pinned exception) |
| `recovery`    | Recovery codes as minimal always-enrolled wallet clients over the `unlock` machinery (spend-on-use configuration, the durable recovery continuation); the pre-minted `did.jsonl` delegation builder and the revocation cascade's bridge re-mint core (the annex sibling's mint taken as an injected closure)                                                                                                                                                                      | unlock, webvh, keyring, space, identity                                            |
| `genesis`     | The account-genesis ceremony: the new-account key set mint and the staged provisioning of a fresh account (Space layout, optional KMS key map, did:webvh genesis, roster genesis, epoch[0] install, controller promotion)                                                                                                                                                                                                                                                         | webvh, keys, space, resourceLog                                                    |
| `clients`     | Enrolled-client management: listing, disconnect-eligibility policy, the revocation cascade orchestrator, the login-time roster policy                                                                                                                                                                                                                                                                                                                                             | webvh, keys, resourceLog                                                           |
| `clientAnnex` | The client annex -- the authoring and maintenance surface of everything ladder-anchored: the ladder (rung/VM derivation and the shared attribution walks), the annex log and its GC, ladder-VM zcap signing, the ladder-anchored account-log ceremonies (genesis, self-enrollment, forget), the credential-anchored account genesis, the transient-recovery continuation                                                                                                          | every base subpath it needs                                                        |

`sync`, `clients`, and `genesis` are never imported by another `src/` module
(`keys` imports exactly one `descriptors` leaf file, `logSource.ts`, for the
epoch-configuration state type it stamps onto governed log entries); `sync` and
`space` are the only modules the root barrel re-exports.

**The client-annex boundary.** `clientAnnex` sits on top: it may import from any
base subpath, and nothing in the base imports from it -- enforced by a
`no-restricted-imports` block in the lint pass (part of `pnpm test`/CI), so a
new base-to-annex edge is a build failure, not a review catch. The one pinned
exception is `unlock/standingWebvh.ts` -> `clientAnnex/ladder.js`:
`removeUnlockKey` resolves a retired credential's current ladder inventory with
the shared attribution helpers, a deliberate base-side dependency on the
attribution walk, never on the annex log machinery. The base keeps the
verify-side / wire-format halves every wallet needs regardless of account
configuration: the resource-log ladder-append license and the
`ControllerInventory` ladder-key computation (`resourceLog`), `ladderVmIds`
recognition (`webvh/listClients`), the unlock-record codec with its `ladder` and
`delegatedClients` members (`unlock`), `webvh/standingZcap.ts`, the generalized
`wasWebvhLogStore` / `delegatedWebvhLogStore` seams, and the `GenerationCollect`
activity builder (`space`). Two symbols stay defined in `webvh/didWebvh.ts` but
are surfaced by the `./clientAnnex` barrel (`ladderVerificationMethod`,
`createLadderAnchoredWebvhLog`): the genesis document builder's two-armed
clientKeys XOR ladderVm signature is base API and its ladder arm calls
`ladderVerificationMethod` internally, so moving them would re-open a
base-to-annex edge. The durable orchestrators keep declaring their
closure-result types (`GenerationDelegationRemint` in `clients/revocation.ts`,
`ClientAnnexInventoryRetirement` in `unlock/retire.ts`) -- the seam belongs to
the orchestrator, and the annex supplies implementations through injected
closures (the record re-mint's `mintDelegatedClientsDelegation` closure, built
by the annex's `delegatedClientsDelegationMinter`, is the same pattern). The
subsystem's decision records are the subpath's reading list: `decisions/0002`,
`0003`, `0005`, `0006`, and `0007`.

## Subpath isolation

The root export re-exports only `sync` + `space`, so plaintext consumers of the
root never pull the signing / KMS / document-loader dependency graph (the
was-client subpath-isolation pattern, stated in `src/index.ts`). Every other
subpath is **import-directly-only**. Each module has a four-key entry (`types` /
`react-native` / `import` / `default`) in the `package.json` `exports` map -- a
new module means a new entry there.

Two extra **leaf subpaths** exist for dependency isolation and must stay
dependency-light:

- `./keys/clientKeyRecord` -- the client-key record codec alone, importing only
  a base64url codec (its key types are type-only imports, erased at compile
  time), so a wallet's storage tests load without the crypto/EDV graph.
- `./request/matching` -- the QueryByExample matchers alone.

The same trick is used internally: `enrollment/connectCode.ts` holds only the
connect-code prefix and predicate so `request/walletInput.ts` can classify a
pasted code without pulling the ceremony graph, `webvh/did.ts` holds only the
did:webvh shape check so `request/onboarding.ts` can validate an account DID
without the zcap signing graph (`webvh/zcap.ts` re-exports it and remains its
public home).

## The wallet Space layout (`space`)

A **Space** is a Wallet Attached Storage (WAS) server-side container, addressed
as `https://<host>/space/<spaceId>/<collection>/<resource>`. An account has
**two** Spaces:

- the **data Space** -- credentials, activity, identity, key-map (its `spaceId`
  is an independent random id minted at signup, carried in the account pointer),
  and
- a minimal **unlock Space** -- one keyring resource, controlled by the unlock
  identity, addressed by `hash(unlock did:key)` as a discovery convention (see
  `keyring` below).

The synced collections both replicas must lay out field-for-field identically
(`space/collections.ts`; a drift splits the feed and never converges):

| Collection            | id derivation | mutable | encryption | public | shareable |
| --------------------- | ------------- | ------- | ---------- | ------ | --------- |
| `private-credentials` | content       | no      | EDV        | no     | yes       |
| `public-credentials`  | content       | no      | plaintext  | yes    | no        |
| `wallet-activity`     | content       | no      | EDV        | no     | yes       |
| `app-connections`     | content       | no      | EDV        | no     | no        |

`shareable` is the share-surface allowlist, not an encryption attribute: the
encrypted sets (cipher build, key epochs, the user-key cascade) still follow
`encryption`. `app-connections` holds the app-key credentials, seeds and all, so
it is encrypted like the credential replica but never offered for sharing.

Contacts (`contacts`, `contacts-history`) are deliberately **not** here -- their
specs live in `@interop/social-core`.

Provisioning is a two-step: `provisionWalletSpace` (in `space`, crypto-free so
the root barrel stays so) declares the roster create-if-absent, and
`ensureWalletSpaceEpochs` (in `keys`, EDV-bearing) installs each encrypted
collection's key epoch[0] -- a fresh random epoch key wrapped to the user key,
never a user-key generation itself. Every encrypted collection's descriptor
carries an epoch roster from birth; was-client refuses reads and writes
fail-closed until the install lands, and both steps adopt (never overwrite) what
an earlier provisioner landed, so a torn signup heals by re-running. Both steps
run before a collection's first content push (the sync engine's
`ensureProvisioned` seam; see the `sync` section's
descriptor-before-first-content-push invariant). The epoch install reports per
collection -- the settled descriptor plus whether this call installed it, and
the collections that failed -- rather than failing the whole fan-out, so a
transient failure on one collection never costs the caller the descriptors the
others settled on.

**Content is re-provisioned, not migrated**, exactly as the keyring and recovery
records are: the install puts a fresh epoch[0] onto ANY epoch-less descriptor
with no check for content already in the collection. Anything sealed before
epochs existed (straight to the user key's key-agreement key, in the shape that
predates the epoch roster) therefore stops being routable the moment epoch[0]
lands, and nothing re-seals it. That is deliberate rather than an oversight:
epoch-less encrypted content only ever existed in pre-release accounts, so the
affected population is effectively zero and re-provisioning from scratch is the
supported answer.

The system collections sit outside the synced set (never replicated; read and
written directly):

| Collection       | Access                    | Resources                                                            |
| ---------------- | ------------------------- | -------------------------------------------------------------------- |
| `id`             | world-readable            | `did.json` (did:web projection), `did.jsonl` (the did:webvh log)     |
| `key-map`        | private, capability-gated | `keys.json`, `user-key.jsonl` (the roster log), `client-labels.json` |
| `unlock-methods` | private, capability-gated | `methods.json` (the account's unlock-method registry)                |
| `keyring`        | in the unlock Space only  | `keyring.json` (the wrapped account pointer)                         |

`id` and `key-map` are split exactly so `id` can be world-readable without
exposing key material.

`space/activity.ts` defines the `WalletActivity` wire shape and its pure
`addHistory*` builders; the `type` strings and `summary` phrasings are
byte-significant across replicas. `space/wasLink.ts` defines the `was-link` QR
hand-off payload -- a non-URL JSON blob on purpose, so no OS deep-link handler
routes it and it cannot leak into history or link-preview fetchers.

## The key hierarchy

Top to bottom; each level's custody rule is load-bearing:

1. **Unlock secret** (passphrase or passkey PRF output) -- derives, via
   PBKDF2-600k (`keyring/kdf.ts`), the **unlock identity**: it addresses the
   unlock Space and holds the KAK the keyring record is wrapped to. It carries
   no authority over the account and nothing about the account is derivable from
   it.
2. **Keyring record** (`keyring/record.ts`,
   `{ version: 2, encryption, wrapped, proof }`) -- the unlock Space's one
   resource: account controller, bind-time email, bind timestamp, and the
   **account pointer** `{ did, spaceId, host }`. Deliberately no key material of
   any kind. The envelope seals under the record's own one-epoch descriptor
   (`encryption`, epoch[0] wrapped to the unlock KAK), so the record stays
   self-contained under the everything-seals-to-an-epoch rule. The unlock KAK's
   public half is derivable from the unlock did:key the server stores as the
   Space's controller, so confidentiality alone would let a hostile host seal a
   substitute that decrypts perfectly: the `proof` (eddsa-jcs-2022 over the
   sibling members, by the unlock identity's Ed25519 key) is the authenticity
   layer, verified before any decryption. The recovery record shares the frame
   under a mixed-signer rule -- the code's unlock key at issuance, an enrolled
   client's account key on a cascade re-mint (or the ladder VM on the
   last-client forget's re-mint), which the reader marks pending for checking
   against the verified did:webvh document (`currentAccountRecordSigners`).
3. **Data identity** (`identity/agents.ts`) -- controller secret or 32-byte
   seed, expanded under the fixed `'bootstrap'` / `'boostrap-key'` handles to
   the did:key `CapabilityAgent`, `ZcapClient`, and X25519 vault KAK. Fully
   deterministic; both apps must derive it byte-for-byte identically.
4. **Client key record** (`keys/clientKeyRecord.ts`) -- the local record each
   wallet client keeps its own material in: the client's 32-byte seed (behind
   its Ed25519 signing key and X25519 twin), its did:webvh update-key seeds, the
   cached user key, and the account controller it was bound for. Only the codec
   lives here; where the record is stored and what wraps it stay app-side
   (freewallet: unlock-wrapped in localStorage; DCW: a column in the encrypted
   DB).
5. **User key** (`keys/userKey.ts`; formerly "PUK", renamed in v0.18.0) -- the
   account-wide key that is **recipient zero** of every encrypted collection's
   key-epoch roster. Random, client-side-minted, never server-held, never
   derivable from any passphrase or seed.
6. **The wrap-set roster** (`key-map/user-key.jsonl`, `keys/userKeyRoster.ts`)
   -- a `CollectionEncryption` descriptor stored verbatim whose current epoch IS
   the current user key, wrapped once per enrolled client to that client's own
   KAK. A delivery channel, never a source of authority (see below).
7. **Recovery code** (`recovery/`) -- 16 bytes base58, from which a complete
   minimal client derives deterministically: its own unlock identity (under a
   distinct HKDF salt), a client key set, and a pre-committed did:webvh update
   key. The key material exists nowhere until the code is typed.

Two ordering invariants the apps must honor around the client key record
(unenforceable here; both are crash-durability rules):

- the user key and the roster epoch pin persist **atomically** -- one write or
  none; and a failed persist must surface, not degrade: the login policy's
  adoption callback (`checkUserKeyRosterAtLogin`'s `onRosterRead`) propagates a
  throw to the caller verbatim rather than folding it into the offline
  warn-and-carry-on class, since a session that silently proceeds on the retired
  cached key with the pin never advanced weakens the rollback guard on the next
  start;
- rolled update-key seeds persist **before** the log entry that publishes them
  (a tear after persist costs an unused staged key; a tear after publish strands
  a log this client can no longer extend).

## The did:webvh document is the client roster (`webvh`)

The account's stable id is a `did:webvh` whose hash-chained log is hosted as
`did.jsonl` in the world-readable `id` collection --
`did:webvh:<scid>:<host>:space:<spaceId>:id` resolves to the log's URL with no
server-side DID support needed. A `did:web` projection (`did.json`) is kept
alongside; the log is the single source of truth.

- **Document structure.** Each enrolled client contributes its Ed25519 key under
  all four relations (`authentication`, `assertionMethod`,
  `capabilityInvocation`, `capabilityDelegation`) plus its X25519 twin under
  `keyAgreement` -- the source of record for user-key wrap recipients. A
  recovery code's key appears under `keyAgreement` **only**, and the KMS-held
  convenience key under `authentication` only, so client listings keyed on
  `capabilityInvocation` exclude both structurally rather than by a filter
  someone must remember.
- **The controller marker.** A client's `keyAgreement` verification method is
  published with `controller: did:key:<its signing multibase>` -- the document's
  one statement of which signing key a published key-agreement key belongs to.
  Every other method carries the account's own controller: signing keys are
  never marked (a did:key controller on a proof key breaks controller-based
  proof verification), the KMS convenience key is never marked, and a recovery
  code's `keyAgreement` method is deliberately left unmarked so client listings
  and revocation removals never match it. That unmarkedness is what tells the
  two methods a recovery continuation publishes at once (the new client's and
  the replacement code's) apart. The read side hard-requires the marker: the
  listing pairs a client with its key-agreement keys by reading the document,
  never by deriving the canonical twin, and a client with no marked method
  reports an empty key-agreement set -- the same refuse-not-guess rule as
  update-key attribution, since a guessed key would make a revocation report
  success over a method that never left the document. A revocation removes EVERY
  method the marker claims (a set filter), so a client with several published
  key-agreement keys is fully revoked. The marker is a permanent document
  convention, applied in one place rather than remembered per site: every write
  site (genesis, enrollment, the recovery add-and-retire entry) builds the
  client's two methods through `markedVerificationMethodPair`, which refuses a
  key-agreement key that is not the signing key's canonical X25519 twin -- so no
  public entry point can publish a marker the account cannot back -- and nothing
  reads a key-agreement key any other way. The enrollment ceremony's
  `assertCanonicalEnrollmentKeys` remains the early half of the same rule,
  refusing a connect code before an approver ever sees it. The read side is
  likewise one loop: `webvh`'s dependency-light `keyAgreement.ts` leaf resolves
  the `keyAgreement` relation's references once (`resolvedKeyAgreementMethods`,
  over the shared `KeyAgreementDocument` shape), and the two consumers are
  filters over it -- the listing and revocation keep only marked methods, while
  the user key roster's recipient resolver deliberately keeps unmarked ones too,
  since a recovery code's method is unmarked by design and must keep its wrap.
- **Two genesis flavors.** `ensureDidWebvh`'s KMS key map (`didWebKeys`) is
  optional. A KMS-backed genesis (freewallet: the map comes from its did:web
  provisioning) adds the one server-held key, the KMS DIDAuth convenience key,
  under `authentication` only, and records the DID in `keys.json`. A
  client-keys-only genesis (dcw: no KMS anywhere in the path) supplies no map:
  the document holds client keys only, and no `keys.json` is written -- the
  record exists to bind relations to KMS keys, and there are none. Everything
  else is identical between the flavors, and every ceremony (enrollment,
  rotation, revocation, roster entry proofs) already anchors in client keys, so
  none of them cares which flavor minted the account. The heal path is a plain
  document edit: the first KMS-capable client adds the authentication
  convenience key with a later log entry.
- **Client keys only under `assertionMethod`.** Every relation except
  `authentication` lists client keys exclusively. `assertionMethod` membership
  is what entitles a key to issue assertions as the account and, under the App
  Connect Resource Log Profile, to append to the account's co-managed resource
  logs -- so no server-held key may ever appear there. Server-side issuance, if
  ever needed, signs under a separate issuer DID, not the account DID.
- **The current-key-set rule.** An invocation or delegation verifies iff its
  verification method is in the resolved document _now_. This is why client
  revocation is a single document edit with no per-collection revoke anywhere:
  the edit is the revoked client's pull axis everywhere.
- **Update keys are client-held**, one per enrolled client, never the KMS -- the
  server cannot extend the log, which is what makes it the one self-certifying
  artifact the server hosts.
- **Prerotation carry-over convention.** `nextKeyHashes` commits every client's
  staged key AND every active key's own hash; without the carry-over hashes no
  non-rotating entry (an enrollment, a document edit) could ever resolve under
  prerotation.
- **Log attribution.** The flat `updateKeys` set has no per-client grouping, so
  a client's active update key and enrollment moment are recovered by
  attributing log entries (the entry that published its verification methods
  revealed its initial key; an entry retiring the attributed key while revealing
  exactly one replacement is its self-rotation). Ambiguous attribution yields
  `undefined` / a refusal rather than a guess -- removing the wrong key would
  revoke a different client.
- **Revocation** (`revokeWebvhClient`) removes, in one entry: the signing
  method, every `keyAgreement` method the client's controller marker claims
  (read off the document, so a stale or absent key-agreement key in the caller's
  snapshot cannot leave a live method behind), the update key, and **both**
  standing `nextKeyHashes` commitments -- the staged hash removal is the subtle
  half, since a hash left committed is a standing re-seizure credential under
  the reveal mechanism.
- **Conditional publish.** Every ceremony publishes `did.jsonl` as a
  compare-and-swap on the ETag of the read its entry was built on (the initial
  provisioning as a create-if-absent), so two ceremonies racing on one log never
  silently erase each other. The loser gets a typed `WebvhLogConflictError` and
  re-runs itself from the top (`withLogConflictRetry`, three attempts) -- the
  re-run IS the rebase, since every ceremony re-reads the head and detects its
  own completion from durable state. The `did.json` projection PUT stays
  unconditional by design: it is serialized behind the won log CAS, the log is
  the source of truth, and `concludeWithPublishedLog` heals any lag. Against a
  backend without the `conditional-writes` feature no ETag is served and the
  publish degrades to an unconditional write.
- `verifyLog.ts` fetches the world-readable log unauthenticated on purpose (the
  hash chain is the trust, not the channel), resolves locally, and refuses a log
  resolving to a DID other than the account pointer's. Every ceremony runs this
  first; `listClients.ts` deliberately takes an already-verified log.
- **The account log's chain-head pin.** Resolution alone is one-shot: a valid
  PREFIX of the real log carries the same genesis, so the same SCID and the same
  DID, and a ceremony built on it republishes truncated-log-plus-one-entry as
  durable state -- erased enrollments and undone revocations. So the account log
  carries the same continuity guard the governed resource logs do, through
  literally the same seam and refusal class (`ResourceLogPinStore`,
  `ResourceLogContinuityError`): given a pin store, `verifyAccountLog` refuses a
  served log that is a `rollback`, a `fork` (served entries ride along as
  equivocation evidence), or an SCID/`method-switch`. The pin --
  `{ method, scid, head }`, from the genesis parameters and the latest
  `versionId` -- is persisted app-side beside the account-pointer pin,
  established at first contact (trust-on-first-use), and advanced only by a log
  verifying past it, never regressed. `rollback` is the one reason that may be
  nothing worse than replication lag, exactly as on a governed log: nothing
  rolled back is adopted, and a caller with a cached document view may carry on
  with what it has. The pin store is optional, so a caller that keeps none keeps
  one-shot verification.

  `ResourceLogPinStore` is keyed: `read` and `write` both take a `logId`, so one
  store instance serves the account log and every governed log a wallet holds
  without cross-pinning them. The library builds the key rather than leaving an
  app to choose one -- `resourceLogPinId({ spaceId, collectionId, resourceId })`
  in `@interop/vh-resource-log` is the generic builder, and
  `accountLogPinId({ spaceId })` in `webvh` names the account log's slot. The
  shape (`space/<spaceId>/...`) is deliberately host-free: the account's Space
  id is what stays stable across a claimed host move, so a log served from a new
  host still lands in the SAME pin slot and gets checked against the held pin,
  rather than opening a fresh trust-on-first-use slate. `verifyAccountLog`
  derives its own `logId` from the `spaceId` it is already given.

  `readPublishedLog` takes both halves of the same check: an optional
  `expectedDid` the ceremony's own read of `did.jsonl` must resolve to, passed
  wherever the account DID is in scope (including a ceremony's mid-flight
  re-read, which must land on the account its first read resolved), and an
  optional `pinStore` running the same continuity check -- under a held pin, an
  absent log refuses as a `rollback` too (a full truncation is never "not yet
  provisioned"). A supplied `pinStore` requires a supplied `logId` too; the
  ceremonies with a `spaceId` in scope (`ensureDidWebvh`) derive it via
  `accountLogPinId`, while `rotateWebvhUpdateKey` and `repairKeyBindings` have
  no `spaceId` in scope and so take an optional `logId` alongside their optional
  `pinStore`, built the same way by their caller. The ceremony paths thread
  both: `ensureDidWebvh` (expecting the caller's DID or, failing that, the
  `keys.json` webvh block's), `rotateWebvhUpdateKey` (its crash-recovery branch
  included), and `repairKeyBindings`, so a truncated-prefix log cannot reach any
  entry-building step. The one documented exemption is `ensureDidWebvh`'s
  first-contact adoption with no caller-supplied DID and no `keys.json` webvh
  block, which legitimately discovers the DID from the log itself. The write
  side keeps the pin fresh rather than leaving first contact to the next read:
  the create path establishes the pin from the log it just minted, and a
  successful rotation advances it to the head it just published.

## The user key roster: delivery, never source (`keys`)

The roster is **log-governed**: its resource is the resource log
`key-map/user-key.jsonl` (the Resource Log Profile), the log being the only
serving of the roster -- no point-state companion document exists.
`keys/rosterLogStore.ts` (`logGovernedDescriptorStore`, built for the roster by
`keys/rosterStore.ts`) exposes the log as an ordinary
`EncryptionDescriptorStore`: reads resolve to the VERIFIED head entry's state
(chain, proofs, external authorization, and the chain-head pin all checked by
the `@interop/vh-resource-log` verifier before any descriptor is handed out; a
head state whose `type` is not `WasEpochConfiguration` is refused), and writes
become signed log appends. Because the seam is unchanged, was-client's roster
machinery (`initRecipients` / `addRecipient` / `removeRecipient`, with their
compare-and-swap retry loops) drives the log without knowing it -- a CAS
conflict on the log (the library's `ResourceLogConflictError`, minted by the
store adapter) is translated back at this boundary to the
`PreconditionFailedError` those loops already rebase on, the class the
`EncryptionDescriptorStore` port documents. The controller view is resolved per
operation (never held), so a revoking client that just edited the account
document writes its roster rotation carrying the post-edit head -- the sealing
append. That post-edit versioning is an orchestrator guarantee, not a wiring
convention the app must remember: the store carries a controller floor
(`setControllerFloor` on the sealable store), the revocation cascade sets it
from the document edit's own post-edit log before any roster-side work, and an
injected controller resolution still serving a cached pre-edit view is
superseded by the floor (a resolved view at or past it wins), so the rotation
and the seal backstop can never carry a version before the removal they must
seal.

Client-side guards against a tampering host, layered:

1. **The resource log itself** -- roster state is adopted only from a verified
   log head: entry proofs must be signed by keys the independently verified
   did:webvh document lists under `assertionMethod` at the entry's controller
   versionId (`ResourceLogIntegrityError`), and the chain-head pin refuses
   rollbacks, forks, and SCID/method switches (`ResourceLogContinuityError`).
   The roster log's pin rides the same keyed `ResourceLogPinStore` as the
   account log, under its own slot (`userKeyRosterPinId({ spaceId })`), so one
   store instance still never confuses the two logs. This subsumed the retired
   detached `epochsSig`: the entry proof's controller versionId took over its
   job wholesale. (The `epochsMac` epoch-configuration MAC that sat beneath it
   as defense in depth is retired stack-wide: on a log-governed resource its
   coverage was a strict subset of chain verification, and its classic gaps --
   whole-configuration replay, fresh fabrication under a newly minted secret --
   were gaps with or without it.) The chain-head pin's `rollback` reason gets
   the same carve-out everywhere a pin is consulted (this is the one statement
   of that policy): it is reconcilable divergence, possibly replication lag, per
   the profile's log-pin rules -- nothing rolled back is adopted and the pin
   never regresses -- so the login policy (`clients/rosterPolicy.ts`) degrades
   it to the cached user key instead of refusing the session, exactly as
   `descriptors/acquire.ts` falls back to the cached descriptor and the
   account-log verifier's callers carry on with a cached document view. A `fork`
   or SCID/method switch stays a refusal.
2. **The epoch pin** -- the app pins the latest-seen roster epoch beside the
   account-pointer pin; a served roster that rolls back behind the pin is
   refused (`UserKeyRosterContinuityError`). Retained beside the chain-head pin:
   it still guards a client whose chain-head pin was lost with a reinstall. Its
   refusal is not softened by the rollback carve-out above: with no chain to
   compare, it cannot tell a rollback from a fork.
3. **The document-backed recipient resolver** -- recipient keys come from the
   locally verified did:webvh document, never from the roster itself; a roster
   entry with no matching `keyAgreement` verification method is dropped and
   never receives a wrap. The match has two branches: a method carrying the key
   verbatim matches on the multibase, and a method carrying only a hash
   commitment (`publicKeyCommitment` -- a low-entropy-derived standing unlock
   credential, whose key material the document withholds) backs an entry exactly
   when a published commitment commits to the entry's own key. The check decodes
   the commitment's multihash and compares digests, so an unsupported or
   malformed commitment backs nothing. A server-injected entry can neither meet
   a standing commitment nor add one.

Every consumer that dispatches on these refusal classes matches on `err.name`,
never `instanceof` (the rule `descriptors/acquire.ts` and
`StagedCommitmentAmbiguousError` document): the errors are raised inside
app-injected seams that can resolve to a different copy of this package (linked,
or duplicated through a dependency tree), and an `instanceof` miss would drop a
security refusal into a warn-and-proceed transport branch. Each class's `name`
is therefore a stable contract.

`rosterRecipientKid` is the one builder of a client's roster kid, shared by the
enrollment wrap and the read path. Retiring a client names no kid at all:
`convergeUserKeyRosterToDocument` rotates away from every recipient the document
no longer keys, so no caller has to pair a client with its key-agreement key.

**The sealing sweep.** After a document edit removes a client's
`assertionMethod` key, every governed log must gain an entry carrying a
controller version at or past the post-edit version -- the sealing append of the
profile's `#log-authorization` rule, proving the surviving writers extended the
log under the new membership. An ordinary post-edit rotation IS that append (the
per-operation controller view has it carry the head the revoker just verified);
the gap is a rotation that no-ops because the retiree held no current-epoch wrap
(an orphan client, or any re-run) -- was-client's `removeRecipient` then appends
nothing, and the log's head keeps carrying the pre-removal version. The
library's seal (`sealResourceLog` / `latestAssertionRemovalIndex`,
`@interop/vh-resource-log`) closes it from durable state alone, keeping the
no-checkpoint rule: "unsealed" is exactly "the verified head's controller
version index (`headControllerVersionIndex`) precedes the latest controller
version whose `assertionMethod` set lost a member", and the remedy is an
idempotent no-op append of the head state verbatim. The log-governed store
exposes the sweep through the descriptor-store seam (`seal()`,
`SealableEncryptionDescriptorStore` / `isSealableDescriptorStore`); the
revocation cascade runs it as a best-effort reported backstop (`rosterSeal`,
folded into `cascadeCompletion`), the login sweep
(`convergeUserKeyRosterToAccount`) converges it after recipient convergence, and
the collection cascade's no-op path seals sealable stores (outcome `sealed`). A
spent recovery code never registers as a removal -- its verification method was
`keyAgreement`-only, so its sealing is the mandatory post-spend rotation itself,
carrying the post-spend version like any other write.

**The ceremony-tail license.** The sealing check's structural twin, on the other
authority axis: what a LADDER-SIGNED append may do (clause B of the ladder VM's
authority clauses, app-connect-spec
`decisions/0003-ladder-authority-clauses.md`). The ladder VM sits under
`assertionMethod` during the ladder-anchored window, so without a bound it could
append a roster rotation rekeying the account to recipients of a credential
thief's choosing, silently. The license admits a ladder-signed append in exactly
two shapes: the log's first entry (creation, not extension), or a rotation
carrying an inventory-changing document version -- S(V), the `keyAgreement`
methods controlled by the account DID (`Multikey` and `MultikeyCommitment`
alike) union the ladder VMs, differs from S(V-1) in either direction; ordinary
client enroll/revoke is excluded structurally by the `did:key` controller marker
-- and one-shot: refused when the verified head already carries that version or
later (`headControllerVersionIndex >= indexOf(V)`, position in the verified
version history, exactly the sealing comparison). Both shapes carry a per-entry
rule: at most one of an entry's proofs may be by a ladder key, since every proof
of an entry shares one controller version and a co-signing ladder key would
otherwise spend it a second time. Proof order is not integrity-bound, so the
count is read as a set (`proofKeys`, the hook's entry-level view) and the
refusal lands on whichever ladder proof is admitted first. A ladder rotation
co-signed by an ordinary member stays licensed. A rotation against an unchanged
document (the silent-rekey shape) is thereby refused by every verifier, while a
torn ceremony's late-arriving tail still passes -- no entry carrying its
inventory-changing version exists yet. The refusal is its own class,
`ResourceLogLicenseError`: a write-time admission error, retryable after a
inventory-changing entry, so callers can tell an unlicensed append from the
integrity class's reject-the-whole-log corruption verdict. Enforced through one
predicate (`assertLadderAppendLicensed`) behind the controller port's
`admitAppend` admission hook that `webvhResourceLogController` supplies, which
the library consults per proof, after the entry's proofs verify, both on
read-back (every verifier handed the hook-carrying controller view refuses a
served unlicensed append) and pre-write (`verifyResourceLogAppend`, which the
log-governed store's `replace` calls, so a conformant writer is refused before
an unlicensed entry lands and poisons the served log; `create` runs the same
check over the genesis as a one-entry log). The library itself carries no
license, so a controller port over a document that can list ladder VMs, any
account did:webvh document, MUST supply the hook; and because the hook is now
consulted on entries that are never written, it is a side-effect-free function
of the view and its input. The wallet-core extension of the library's controller
port (`WebvhResourceLogController`) is inventory-aware for it: `inventoryAt`
exposes the per-version ladder keys (relation asymmetry) and inventory set that
are invisible through the `assertionMethod` accessor; the extension stays on the
store types because the resolver returns it and the hook lives on it. A refused
write surfaces before anything is written, so the accidental durable signal an
unlicensed append used to leave (the poisoned entry) no longer exists; WC-149,
which weighs making a license refusal a soft class, reasons about the pre-write
refusal alone.

## Standing unlock credentials (`unlock`)

Every unlock method -- a passphrase, a passkey PRF output, a recovery code -- is
a standing credential in the recovery-code configuration: a `keyAgreement` entry
in the account document, a user-key wrap in the roster escrowed into every epoch
and kept alive by rotation fan-out, and latent self-enrollment authority. A
fresh browser holding nothing but the credential self-enrolls as an ordinary
full client; no second party is involved, and the recovery code's spend-on-use
flow is the special case (`recovery` sits on top of this module).

The pieces, and where each secret lives:

- **The client identity** (`standingClient.ts`): the credential's client seed
  and binding MAC key expand from the method's 32-byte unlock seed under the
  permanent `freewallet/unlock/standing-client/v1` salt, so the expensive
  passphrase stretch runs once and each method's distinct unlock-KDF salt keeps
  identities apart. The identity assembly (agents, multibases, roster kid) is
  shared with the recovery-code derivation (`unlockClientIdentityFromSeed`).
- **The update-key ladder** (`ladder.ts`): latent-and-consumed did:webvh update
  authority. Rungs derive by HKDF from a RANDOM 32-byte ladder seed carried in
  the unlock record -- never from the unlock secret, since a revealed rung lives
  verbatim in world-readable `updateKeys` forever, where no commitment could
  protect a secret-derived key. Between uses only `hash(rung i)` stands in
  `nextKeyHashes`; there is no stored counter -- the current rung is recovered
  by re-derive-and-scan over the published parameters (`attributeLadderRung`),
  and ambiguity fails closed (`LadderAttributionError`), the clients-listing
  attribution precedent.
- **The ladder VM** (`ladderVmSeed` / `ladderVmKeyMultibase` in `ladder.ts`; the
  document builder `ladderVerificationMethod` and the recognition `ladderVmIds`
  in `webvh`): the STABLE SIBLING -- a dedicated Ed25519 key derived once from
  the ladder seed under the same salt with the fixed info label `vm`, published
  verbatim (the seed is random, so the hash-commitment rule permits it) and
  stable across rung spends. It exists only while the account has no enrolled
  durable client, listed under `assertionMethod` and `capabilityDelegation`
  ONLY; recognition is by that relation asymmetry (a `capabilityDelegation`
  member absent from `capabilityInvocation`), which also keeps it structurally
  out of every client listing. Ladder-anchored genesis
  (`createLadderAnchoredAccountLog`) anchors the log on the ladder alone --
  `updateKeys` = [rung 0], `nextKeyHashes` = [hash(rung 0), hash(rung 1)] (rung
  0's carry-over hash, which the first self-enrollment's reveal-and-commit entry
  requires, plus the staged rung; both genesis flavors build the pair with
  `genesisNextKeyHashes`), the credential's `keyAgreement` inventory folded into
  the genesis entry -- and the first durable self-enrollment's add entry closes
  the window atomically: client in, rung 0 retired, ladder VM out, no entry
  where the account has neither. Because the sibling is derived, removal is not
  permanent: a reinstall republishes the SAME key under the SAME id, and a
  still-unexpired delegation it signed resumes verifying the moment the method
  returns -- so delegation revocation, not VM removal, is the terminal remedy
  for ladder-signed delegations, and credential rotation is the remedy for a
  leaked ladder seed. The rotation reaches the sibling: a retirement run with
  the seed in hand (`removeUnlockKey`'s `ladderSeed`) strikes the seed's VM from
  the document in the same entry as the rest of the ladder's inventory, closing
  the window a last-client forget torn after its install entry leaves open,
  where the retired seed would otherwise keep signing governed-log appends and
  account delegations.
- **The unlock record** (`unlockRecord.ts`): the keyring-record frame extended
  with three members the proof also covers. The shell (`wrapped`: controller,
  optional email, pointer, bind timestamp) and the sealed `ladder` member are
  carried VERBATIM through re-mints; the sealed `bridge` member (the pre-minted
  PUT-on-`did.jsonl` delegation) is the one member a re-mint replaces
  (`remintUnlockRecordBridge` -- what the revocation cascade's delegation
  re-mint drives). The `binding` frame member is an HMAC under the
  credential-derived MAC key over controller, pointer, AND ladder seed, verified
  before the pointer is trusted, so a storage host can neither redirect login at
  another account nor substitute a ladder of its own. The mixed-signer policy is
  the recovery record's: bind-time records verify before decryption, re-minted
  ones come back pending for the caller to settle against the verified document.
- **The document inventory** (`unlock/standingWebvh.ts`): one merged add/remove
  edit (`publishUnlockKey` / `removeUnlockKey`, the recovery twins now thin
  wrappers over it) publishes the credential's `keyAgreement` entry and commits
  its current update key's hash. The REMOVE polarity treats the recorded update
  key as a ladder anchor, not truth: it resolves the ladder's current inventory
  from the log itself (`attributeLadderInventory` -- every standing committed
  hash, and any revealed rung a torn self-enrollment left in `updateKeys`
  together with the hashes its reveal entry committed) and strikes all of it in
  the one entry, since a removal trusting a stale bind-time rung would leave the
  live rung commitment standing as a latent re-seizure credential. A supplied
  ladder seed strengthens the attribution, and names the credential's ladder VM,
  which the entry strikes from `verificationMethod`, `assertionMethod`, and
  `capabilityDelegation` when it stands (the sibling is derived from the seed
  alone, so nothing in the log attributes it without one; a seedless removal
  leaves it, and is not settled by that); without one the log walk relies on the
  reveal entry's ratified hash append order
  (`decisions/0007-ladder-reveal-hash-order.md`) plus the credential's own
  verification-method id (`credentialVmId`), which the removal always passes.
  What a completing entry does not transfer to the enrolled client is
  ladder-owned only on POSITIVE attribution -- the seed derives the hash, or the
  credential comes out of the completing entry still standing, which is what
  makes the leftover its next rung's commitment. A spend leaves its SUCCESSOR's
  commitment in that position (the recovery continuation's third committed hash
  is the replacement code's), and a walk that could not attribute the leftover
  releases it rather than striking a credential that is not its own. The entry
  carries the key verbatim for a high-entropy credential, or, for a
  low-entropy-derived one, a `MultikeyCommitment` entry carrying only
  `publicKeyCommitment` (computed by `keyAgreementCommitment`: the bare sha2-256
  multihash of the key's decoded multikey bytes, base64url no-pad). The
  commitment withholds the key material and gives the roster resolver a
  document-anchored check; it does not reduce offline guessing exposure, which
  belongs to the standing-credential model and its KDF choice. Both entry
  flavors are deliberately unmarked, so client listings (keyed on
  `capabilityInvocation`) and revocation removals never see them.
- **Self-enrollment** (`selfEnrollWebvhClient`, composed end to end by
  `selfEnrollClientCore`): the recovery continuation generalized to a
  non-spending credential. Two entries through the delegated bridge -- a
  reveal-and-commit entry signed by rung `i` (committing the new ordinary
  client's hashes plus `hash(rung i + 1)`), then an add entry signed by the new
  client's update key that also retires the spent rung. The credential's
  inventory stands afterwards on rung `i + 1`, ready for the next
  self-enrollment; nothing is spent and no replacement exists. A lost
  compare-and-swap race re-runs, re-attributes, and climbs to the winner's
  committed rung (retry-up-the-ladder -- the winner's committed
  `hash(rung i + 1)` IS the loser's retry key by determinism). Both entries are
  built on reads under the caller's chain-head pin (`pinStore` + `logId`, the
  re-run's read included), advanced as each entry publishes, so a served
  truncated prefix is refused before the reveal entry lands rather than rebased
  under the new client's entries. Between the two entries sits a required
  persist seam (`onCommitted`, refused with a `TypeError` before any read when
  absent): it fires once per attempt, after the reveal-and-commit entry stands
  and before the add entry -- the ceremony's pivot -- is built, and a throw
  withholds the pivot. The caller durably writes the pending client-key record
  there (at the `selfEnrollClientCore` surface the hook also receives the
  minted-or-resumed client seed and update-key seeds, so the record can be
  written before the pivot names a client nothing else can re-derive), the
  pre-pivot persist half of the post-pivot derivability rule (`decisions/0010`).
  The returned `committed` flag says whether this call entered the seam (`false`
  on the idempotent already-complete branch, which enters no seam); a caller
  clears its pending record on the call returning, not on `committed`'s value,
  since the already-complete branch also means nothing is left to persist.
  `selfEnrollClientCore` also takes an optional `resume` (the pending record's
  seeds plus the head the pivot was built on): it skips the mint, re-derives the
  same key set, and republishes only the missing entries, refusing with
  `BuiltOnHeadNotReachedError` when the served log's SCID differs from the
  recorded head's or lacks an entry at its recorded version -- the fork guard
  for a resume whose chain-head pin write (non-atomic, after the pivot) never
  landed. The marker covers only the pre-pivot half of that gap; a log that
  contains the recorded head but is truncated behind the torn run's own add
  entry is mended by the client's own pin once written, or by another enrolled
  client's pinned read. A throwing hook leaves one accepted residue: the reveal
  entry's committed hashes for the never-persisted client stand as permanent
  inert orphans in `nextKeyHashes`. The composed core then verifies the account
  log under the same pin, performs the first roster read unwrapping the user key
  from the CREDENTIAL's standing wrap, and escrows the new client into the
  roster as its own recipient.

Loudness is the standing compensating control: a self-enrolled client extends
the same world-readable hash-chained log every other client's chain-head pin
checks, so takeover is visible and remediable rather than prevented by an
enrollment gate. What bounds the whole construction, standing: server-held key
material decryptable by an unlock credential is bounded only by that
credential's entropy against a malicious storage host, so the custodian of the
unlock credential must not be the storage host.

## Ceremonies and cascades

One principle underlies all of them: **every stage detects its own completion
from durable state alone** -- no checkpoint resources anywhere. Log entries are
idempotent; roster staleness is "does the current epoch still wrap to a
recipient the document no longer keys"; collection staleness is "does its
current epoch name a non-current user-key generation"; a governed log is
unsealed exactly when "its head's controller version predates the controller's
latest assertion-key removal" (the sealing sweep above). So any torn cascade is
resumable by a naive full re-run, backstopped by the login-time completion sweep
(`clients/rosterPolicy.ts`: `checkUserKeyRosterAtLogin`, then the best-effort
`convergeUserKeyRosterToAccount` plus collection fan-out). The collection
cascade is **rotation-only**: epoch[0] comes from provisioning, and a descriptor
met without epochs is refused fail-closed rather than seeded (no construction
anywhere installs a user-key secret as a collection epoch secret, so a
collection-epoch escrow can never hand an external grantee the user key). A
descriptor whose `currentEpoch` names no epoch in its own list is refused the
same way -- the shape the roster read refuses on the roster itself -- rather
than silently evaluated against the last epoch: collection descriptors arrive
host-served with no client-side authenticity, so a mismatched pair is a
configuration no enrolled client authenticated, and the refusal surfaces in the
fan-out's per-collection `failed` report instead of a `noop`.

Every ceremony also has a pivot: the first durable write after which the
ceremony is committed and cannot be rolled back, only rolled forward. The pivot
is almost always a hash-chained log entry, and that entry is the ceremony's one
commit record -- nothing else in the inventory plays checkpoint or intent
resource. Every other write in the ceremony sits on one side of the pivot:
before it, where the write must stay inert until the pivot lands (a pre-staged
record, wrap, or delegation grants nothing until the entry that licenses it
verifies), or after it, where the write must be re-derivable from the pivot
entry plus durable state, so any authorized party can finish the ceremony.
Persist-before-publish is the special case of the first half for key material.
`decisions/0010-post-pivot-derivability-rule.md` states the rule canonically and
is the per-write test a new or changed ceremony's stage order is checked against
at the design gate.

- **Account genesis** (`genesis/`): a brand-new account mints its complete key
  set locally (`mintAccountKeySet`: Space id, the founding client's identity
  seed, the user key, the did:webvh update keys; the caller persists the seeds
  durably before anything publishes), then `ensureAccountGenesis` provisions the
  account in the one stage order both apps must encode identically: Space
  provisioning, the optional KMS key-map acquisition (`provideDidWebKeys` --
  absent means the client-keys-only genesis), did:webvh genesis, user-key roster
  genesis strictly after DID publication (the roster log's entry proofs carry a
  versionId in the published document), epoch[0] on every encrypted roster
  collection, and Space-controller promotion. The keyring bind is deliberately
  not a stage (where and whether an app binds an unlock method stays app-side),
  and neither is the `userExists` probe (a passphrase-collision concern of the
  unlock layer). The essential identity chain -- Space provisioning and the
  did:webvh genesis -- throws on failure; the later stages are collected in
  `failed`, so a completed call with failures is a resumable success finished by
  a naive re-run. Promotion (`ensurePromotedSpaceController`, also exported
  standing alone) is a state machine over the Space Description -- promote,
  confirm, or heal a torn controller PUT through a did:key-signed client -- and
  is skippable (`promoteController: false`) for an app whose account pointer
  must durably name the DID before the controller PUT lands, which then runs it
  itself after that write (freewallet's keyring re-bind ordering).
- **Enrollment** (`enrollment/`): a new client mints its whole key set locally;
  only public halves travel, as a `freewallet-connect:` connect code carried
  point-to-point, and nothing travels back over the channel (the account pointer
  comes from the keyring; the user key comes back through the roster). Order is
  push-not-pull, decryption material before authorization: the user key is
  wrapped to the new client's KAK in the roster FIRST, then the two log entries
  land (a sparse **commit** entry extending `nextKeyHashes`, then the **add**
  entry publishing the verification methods and update key). No
  authorized-but-blind window exists; a tear between the log entries surfaces as
  `EnrollmentPendingError` and re-running with the same code converges. A code
  whose key-agreement key is not the canonical X25519 twin of its signing key is
  refused (`assertCanonicalEnrollmentKeys`, run both by the parse -- so the
  refusal reaches the approver's consent screen -- and by `approveEnrollment`,
  the seam every approval path funnels through). That refusal is what keeps the
  controller marker honest: the document states that the published key-agreement
  key belongs to the client's signing key, and this is what makes the statement
  true. Persisting the enrollee's key set under the app's unlock layer is the
  caller's job -- `completeEnrollmentCore` hands back the user key and the epoch
  to pin, and stops. `onboardingResponse.ts` adds only a transport around the
  same code: the `{ walletOnboarding: { v, code, label? } }` envelope an
  enrollee POSTs back to an exchange whose request carried a
  `WalletOnboardingQuery`. The code rides verbatim (the ceremony's validation
  and the connect-code version are untouched), and the optional label --
  attacker-adjacent text rendered on the approver's consent screen -- is
  control-character-stripped, trimmed, and refused rather than truncated when
  over its 64-character cap; its durable home is `key-map/client-labels.json`,
  which the approver writes. The inviter's side of that same exchange is generic
  transport and lives in `request/ephemeralExchange.ts`:
  `createEphemeralExchange` POSTs the query to the server's ephemeral-exchange
  route and hands back the exchange URL plus the interaction URL the QR code
  carries, and `pollEphemeralExchange` polls until the enrollee's envelope
  lands. What stays in `enrollment/onboardingInvite.ts` is the one policy
  constant, `ONBOARDING_INVITE_TTL_MS`: how long a wallet offers the invite for,
  inside the server's ten-minute exchange TTL. The routes are unauthenticated by
  design (a capability-URL access model -- the exchange URL is the secret,
  travelling point to point through the QR code), so nothing there signs a
  request; a `404` is the expired invite and raises the stable-named
  `EphemeralExchangeGoneError`, while every other failure is transient and
  retried. The poll takes an optional `timeoutMs` deadline that aborts the
  in-flight request and raises `EphemeralExchangeTimeoutError`, a separate class
  because the exchange may still be approvable and the requester just stopped
  waiting.
- **Client revocation** (`clients/revocation.ts`, `revokeAccountClient`) runs in
  dependency order: (1) the single document edit -- the pull axis everywhere;
  (2) the roster rotation, recipients resolved from the document the edit just
  produced -- the pairing-free convergence the login sweep already runs
  (`convergeUserKeyRosterToDocument`), which retires every current-epoch
  recipient the post-edit document no longer keys in one rotation, naming no
  client -- followed by the roster log's seal backstop (best-effort, reported in
  `rosterSeal` rather than thrown); before any of stage 2 runs, the orchestrator
  sets the roster store's controller floor from the edit's post-edit log,
  guaranteeing the rotation and the seal carry a version at or past the removal
  even under a stale injected controller resolution (the log-governed store
  section above); (3) the parallel per-collection re-epoch fan-out, failures
  collected, never aborting; (4) optional recovery-delegation re-mints; (5) the
  optional `remintGenerationDelegation` closure, run on the post-edit document
  in the rotated and the no-roster paths alike (its result rides the outcome as
  `generation`), so revoking the durable client that signed the current
  generation delegation replaces it in place instead of killing the transient
  entry path silently mid-generation. Then `onRotationAdopted` lets the revoking
  session adopt the fresh key in place. A cascade whose fan-out left failures
  behind is a **resumable success**, not an error (`cascadeCompletion`): the
  wallet IS disconnected once stage 1 lands, and the remainder is finished by a
  re-run or the login sweep. Disconnect eligibility is pure policy data
  (`clients/policy.ts`): `self`, `last-client`, and `unattributed-update-key`
  refusals, so both apps refuse the same rows for the same reasons.
- **Forget** (`clientAnnex/forget.ts`, `forgetDurableClient`): a remembered
  browser's durable client removes ITSELF through the standing credential's
  bridge -- self-enrollment in reverse, run before the app's local wipe. The
  stage order deliberately INVERTS the revocation cascade's document-edit-first
  rule, forced by the self-removal: after the removal entry the forgetting
  client can sign no roster append (entry-proof rule) and make no WAS request
  (current-key-set rule), and a ladder-signed append is licensed only at a
  inventory-changing version, which a not-last-client removal is not. So the
  roster rotates FIRST (the client's wrap retired by its kid explicitly, the
  fresh key read back through the credential's standing wrap), the collection
  fan-out runs second, and the removal entry lands last: ONE atomic
  ladder-signed entry (`forgetWebvhClient` in `clientAnnex/ladderAnchored.ts`)
  -- a removal reveals no new key, and a committed rung may reveal itself in the
  entry it signs, so no reveal-and-commit precursor exists and no torn
  revealed-rung-without-removal state can. The entry's removal set is the
  revocation edit's verbatim (`clientRemovalTarget` / `clientRemovalFields`,
  shared with `revokeWebvhClient`), with the ladder vouching its own rung hashes
  into the staged-hash attribution (a self-enrolled client's staged hash and the
  next rung's hash were committed in one reveal entry, indistinguishable without
  them). The honest residue: the acting rung stands REVEALED in `updateKeys`
  afterwards (no entry can remove its own signer) -- credential-held authority,
  consumed by the next self-enrollment and struck by credential retirement --
  and the roster log's head keeps carrying a version before the removal entry
  until another enrolled client's login sweep seals it. The last enrolled
  durable client refuses (`LastDurableClientForgetError`, fired before anything
  rotates): its forget is the ladder-anchored transition below.
- **The last-client forget** (`clientAnnex/forgetLast.ts`,
  `forgetLastDurableClient`): the two-entry transition (decision 0004's
  amendments) that takes an account from one enrolled durable client to the
  client-less, ladder-anchored state -- the third producer of that state, beside
  the credential-anchored genesis and the transient recovery. The order is
  forced twice over: the server's revocation endpoint verifies a to-be-revoked
  chain against the CURRENTLY resolved document, and the ladder VM carries no
  `capabilityInvocation`. So: (1) the **install entry** (`installLadderVmWebvh`,
  idempotent, rung-signed) publishes the ladder VM while the client's inventory
  stays -- the both-present transitional state, and the inventory-changing
  version the ceremony-tail license admits; (2) the **roster rotation**,
  ladder-VM-signed and carrying the install entry's version, HTTP-invoked under
  the still-standing client, ONE append retiring the client's wrap -- a
  ladder-signed head also means the roster log needs no seal repair afterwards,
  load-bearing where no login sweep will ever run again; (3) the collection
  fan-out; (4) the **generation stage**: a fresh ladder-signed generation
  delegation force-replaces the embedded one
  (`ensureGenerationDelegationCurrent` with `force`, keeping the account
  transient-login-reachable), then every still-unexpired delegation this ladder
  VM ever signed is revoked, the bytes recovered from the annex log's history
  (`generationDelegationHistory`; webvh restates full state per entry, and a
  renewal inside the 30-day window can leave two) -- closing the resurrection
  window a reinstalled derived-key VM reopens, with a re-POSTed revocation's 400
  already-revoked answer read as success; (5) the **other unlock methods' record
  re-mint** (the optional `unlockMethods` reach): the revocation cascade's
  re-mint pass (`remintRecoveryDelegations`) run with the ladder VM as the
  delegating key and the record-frame signer and the forgotten client named as
  retiring (`retiringKeyMultibases` -- the post-install document still lists it,
  so without that axis every bridge it signed would read as standing),
  re-sealing every other standing credential's and recovery code's record
  through its management zcap, HTTP-invoked under the still-standing client,
  every entry's fate reported (`RecordRemintOutcome`). On a client-less account
  no durable login's refresh block will ever heal these records, so unlike the
  revocation cascade this pass is not best-effort: a `failed` entry refuses the
  removal entry (`RecordRemintFailedError`, naming the records it could not
  reach), the client stays enrolled, and the re-run resumes at the re-mint; (6)
  the `onBeforeRemoval` seam (required), where the caller re-signs the LOGIN
  credential's bridge and `delegatedClients` sibling with the ladder VM and
  re-seals its record with the credential in hand (the removed client's
  signatures rot at the next entry). Stage 5 skips that credential, so the seam
  is the only thing that ever re-signs the login credential's own bridge; a call
  without it is refused before any read, since the removal entry would otherwise
  leave an account nothing can write to; (7) the **removal entry**
  (`forgetLastWebvhClient`), the plain forget's removal shape with the guard
  inverted -- it requires the installed ladder VM instead of refusing the last
  client. Every stage detects completion from durable state, so a run torn
  before the removal entry converges on re-run; torn after it is the
  finish-the-wipe state the app's next login maps. A reader settling a
  ladder-signed record's mixed-signer proof uses `currentAccountRecordSigners`
  (`clients/listing.ts`): the enrolled clients' key set widened by the
  document's ladder VMs, which the enrolled-client set alone would refuse on a
  client-less account.
- **Recovery** (`recovery/`): a code's inventory is deliberately split --
  **decryption stands** (its `keyAgreement` verification method is in the
  document, unmarked, and its user-key wrap stands in the roster, both
  maintained for free by rotation fan-out) while **authority stays latent** (its
  update key joins `updateKeys` nowhere; only its hash is committed, and the one
  bridge is a pre-minted PUT-on-`did.jsonl` delegation carried in the code's
  unlock record). Any use of a code must first extend the world-readable log --
  recovery is loud by construction. Spending a code is a two-entry
  self-enrolling continuation: **reveal-and-commit** (the pre-committed key
  reveals itself, commits the new client's and replacement code's hashes), then
  **add-and-retire** (new client fully in; the spent code's method, key, and
  hash out; the replacement code's inventory in), followed by mandatory user-key
  rotation off the spent code. Between the two entries sits a required
  `onCommitted` persist seam (`recoverWebvhClient`,
  `recovery/recoveryWebvh.ts`), refused with a `TypeError` before any read when
  absent: it fires after the reveal-and-commit entry stands and before the
  add-and-retire entry -- the ceremony's pivot -- is built, and a throw
  withholds the pivot, leaving the code unspent. The caller durably persists the
  new client's and replacement code's material there, the pre-pivot persist half
  of the post-pivot derivability rule (`decisions/0010`). The idempotent
  already-complete branch enters no seam and returns `committed: false`; a
  caller clears its pending state on the call returning, whatever `committed`
  says. A re-run after a tear at the seam must pass the SAME replacement halves
  back in, re-derived from the persisted replacement-code bytes: the reveal
  entry already committed that code's hash, and a fresh replacement would strand
  the first commitment with no `keyAgreement` method behind it. With the halves
  reused, the only torn-run residue is the never-published client's inert orphan
  hashes, as on the self-enrollment seam. Both entry builds run over the
  caller's pinned reads when a `pinStore` and `logId` are supplied, the pin
  advancing as each entry publishes. The delegation is a wire artifact both apps
  must mint byte-identically, so its builder (`delegateLogWrite`: PUT on the one
  `did.jsonl` resource, one-year TTL per NIST SP 800-57 cryptoperiod guidance)
  lives here rather than app-side -- and so does the **delegation re-mint** the
  revocation cascade runs (`remintRecoveryDelegations`): revoking a client
  kills, by the current-key-set rule, every recovery delegation that client
  signed, and a standing delegation eventually reaches its own expiry, so for
  each registry entry whose recorded delegation no longer chains
  (`delegationKeyInDocument`) or is expired or inside the renewal window
  (`zcapExpiring`), the acting client signs a fresh delegation to the code's
  signing DID, re-wraps the record to the code's unlock KAK public half with the
  code-authenticated `binding` carried forward verbatim, re-PUTs it through the
  entry's management zcap, and hands the entry back with the fresh
  `delegationKeyId` and `delegationExpires`. The skip policy (pre-re-mint
  entries, unreadable or binding-less records) is decided here once and every
  entry's fate is reported (`RecordRemintOutcome`: current, reminted,
  incomplete-entry, failed), so a record the pass could not reach is named
  rather than silently left; the app injects the seams (the management-zcap
  client factory, the storage URL, the registry read/record halves) and keeps
  its login-time health check as the backstop for skipped entries and for expiry
  between revocations. The last-client forget runs the same pass with the ladder
  VM as signer and the forgotten client named as retiring
  (`retiringKeyMultibases`), since the document it checks against still lists
  that client until the removal entry lands.

## The request pipeline (`request`)

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

Classification only -- no fetch, navigate, or store. Downstream: `parse.ts`
(deep links / JSON to typed messages), `classify.ts` (CHAPI events / VPRs to
typed requests, plus `appConnectRequestOf` -- the `AppConnectQuery` `app` block
is `{ name, appUrl }`, and the `appUrl` must parse as an absolute URL, carry no
fragment, and be same-origin with the attested requesting origin, else the query
is malformed; all storage and comparison uses the parsed URL's serialization),
`matching.ts` (QueryByExample -- **two matchers ship deliberately**, DCW's deep
matcher and freewallet's type/issuer matcher, since each wallet matches only its
own store and no cross-replica agreement is needed), `presentationSuite.ts`
(cryptosuite negotiation), `composeVp.ts` (grants ride inside the VP, added
before signing so the DIDAuth proof covers them), `appKey.ts` (the App Connect
app-key credential: the fixed two-entry type array and hosted context URL,
matching keyed on the `credentialSubject.appUrl` claim plus marker /
self-issuance / origin / seed-binds-subject with latest-first ranking over
`issuanceDate` instants, minting, the store-time refusal policy -- app keys are
wallet-minted, never imported -- and the legacy pre-`appUrl` re-issue that
preserves the seed and so the derived identity), `processRequest.ts` (pure;
consent and channel stay with the caller; zcap / App Connect processing injected
as `RequestProcessors`, the App Connect branch validated via
`appConnectRequestOf` before dispatch), `onboarding.ts` (the
`WalletOnboardingQuery` transport vocabulary: the inviter's compose helper and
the enrollee's classification, both running the query's members through one
shared validator -- the account's did:webvh `did`, a non-empty `spaceId`, a
`did:key:` `controller`, and a `host` that is an absolute http(s) URL with no
fragment, stored and compared as the parsed URL's serialization. The pointer and
controller are what let the enrollee join without the account passphrase, and
they name the account without authorizing anything; one mental model per
exchange, so it refuses to mix with `QueryByExample`, standalone capability
queries, or an `AppConnectQuery`, and `appConnectRequestOf` refuses the mixture
from its side too. The response half of that exchange is the onboarding-response
envelope in `enrollment/`, which is where the connect code it carries verbatim
already lives), `exchangeClient.ts` (VC-API exchanges, injected `FetchLike`;
handles the empty-CHAPI-body + `protocols.vcapi` redirect case),
`interactionUrl.ts` (VCALM indirection), `interactionRequest.ts`
(`openInteractionRequest`, the answering wallet's one-call entry point over an
interaction URL: resolve the protocols map, begin the named exchange, hand back
the VPR -- classification stays with the caller), `ephemeralExchange.ts` (the
requester's half of a WAS server's ephemeral exchange: create one carrying a
VPR, poll it until the wallet answers, bounded by the caller's `AbortSignal` or
the poll's own deadline; the routes are unauthenticated, so nothing there signs
a request), `capabilityRequest.ts` (`composeCapabilityRequest`, the zcap-only
VPR a requester stores on such an exchange: one `AuthorizationCapabilityQuery`
carrying the requested details verbatim, with no `DIDAuthentication` query and
no `domain`, since a requester without an attested origin has no domain a wallet
could check). The apps keep only their side of App Connect: consent UI,
credential storage, and the zcap delegation machinery.

The App Connect exchange this pipeline serves -- the `AppConnectQuery`, the
app-key credential, and the response presentation's `zcap` / `appConnect`
members `composeVp.ts` builds -- is specified in the App Connect companion spec
(<https://github.com/interop-alliance/app-connect-spec>; local checkout
`../app-connect-spec`, read `spec.md` there instead of fetching the rendered
version). The app-key identity is scoped to (user, origin, `appUrl`); the
derivation constants in `appKey.ts` (the `app-key` HMAC key name) are pinned
inputs of that spec's key-derivation rule.

## The sync engine (`sync`)

`SyncEngine` drives exactly **one `(replica, collection)` feed**: single-flight
(concurrent `sync()` calls coalesce), migrate-once (pull-before-migrate ordering
avoids server-side duplicates), exponential backoff with jitter -- every side
effect injected via `SyncEngineDeps`.

- The **wire contract and port** (`WasSyncPort`, `WireDoc`, `SyncCheckpoint`,
  `DocCipher`, the conflict/not-found errors) are defined in
  `@interop/was-client/sync` and re-exported here so an engine consumer imports
  one package. What this module owns is the replica side: the `SyncStore` seam,
  `runPull` / `runPush`, and the engine.
- The engine owns the `DocCipher` and **decrypts outside the store transaction**
  -- store methods never see key material.
- **Descriptor-before-first-content-push.** A collection's descriptor (with its
  epoch roster) is published before the collection's first content push, so no
  envelope reaches the feed sealed under an epoch the published descriptor does
  not carry. The engine enforces it structurally: `ensureProvisioned` -- which
  for an encrypted collection must include the descriptor publication (the
  provisioning two-step above) -- runs ahead of every cycle's migration sweep
  and push, so a lazy minter always mints under the settled descriptor. An eager
  minter (envelopes minted at local write time against a cached descriptor) that
  loses the descriptor create to another provisioner follows the
  **adopt-and-re-mint rule**: adopt the winner's descriptor (the create is CAS,
  never clobbering), then `remintPendingEnvelopes` re-encrypts every pending row
  the adopted cipher cannot route under the winner's current epoch before the
  next push -- legal because pending (never-acked) envelopes have no feed
  existence, so the re-mint may re-key them (`SyncStore.replacePending`, the
  optional seam only eager minters implement).
- `runPush` covers the **content sub-resource only**; the
  independently-versioned metadata half (`putMeta` / `metaVersion`) stays in
  freewallet's RxDB driver, since no wallet Space collection versions metadata
  independently. Content-addressed collections get create/delete only; mutable
  collections get create-then-`If-Match`-update with `412` settled by the
  injected `ResolveConflict`.
- `contactsConflict.ts` resolves the one mutable collection (`contacts`) by LWW.
  It lives here rather than in social-core because deciding requires decrypting
  both sides (the `updatedAt` / `writerId` pair is sealed in the envelope); the
  comparison itself is social-core's `remotePayloadWins`. It **fails safe to
  remote** on any unreachable field.
- `SyncedCollectionSpec<Tx, RefreshContext>` is **only a shape**, not a registry
  -- the concrete registry stays app-side because writers bind to the app's
  transaction handle (SQLite vs RxDB) and read-model refresh. `space`'s
  `SpaceCollectionSpec` is the strictly narrower _layout_ spec; this is the
  _drivable_ one.
- [docs/cross-replica-sync-compatibility.md](docs/cross-replica-sync-compatibility.md)
  records the cross-replica conformance results between DCW's `SyncEngine` and
  freewallet's RxDB adapter -- what is proven to converge, which divergences are
  tolerated by construction, and the harness notes. Read it before touching
  pull/push semantics.
- The module stays here by decision, not by cohabitation: `decisions/0009`
  records why the engine (replica policy, not transport) and the contacts
  resolver (the one file needing both a `DocCipher` and social-core's
  comparison) live in this package rather than in was-client, social-core, or a
  package of their own, and what would reopen the question.

## Descriptors and the unknown-epoch refresh (`descriptors`)

A collection's `CollectionEncryption` descriptor is its **key-epoch roster**:
which epoch it encrypts under. This module is the one shared implementation of
"which epoch, and when do we ask again" -- a drift here does not fail loudly; it
fails as a resource one replica cannot decrypt.

An epoch rotation emits **no change-feed entry**, so a cipher built from a
cached descriptor can meet envelopes stamped with an unseen epoch. The remedy is
one Collection-Description re-read + cipher rebuild + single retry, guarded to
**once per collection per session** so a genuinely foreign envelope cannot drive
a refetch loop. `acquireDescriptor` falls back to the cache on fetch failure
(offline keeps encrypting under the current epoch); a successful fetch with no
descriptor means an unencrypted collection -- the refreshing cipher, whose
caller has declared the collection encrypted, refuses fail-closed to build
without one.

For a collection whose descriptor is governed by a resource log,
`logGovernedDescriptorSource` is the `EncryptionDescriptorSource`: every
acquisition -- including the unknown-epoch refresh's re-read -- re-verifies the
log through the `@interop/vh-resource-log` verifier (chain, proofs, external
authorization, the chain-head pin) and resolves to its verified head state,
refusing a head that is not a `WasEpochConfiguration`. That governed read
boundary exists once (`readGovernedEpochConfiguration` in
`descriptors/logSource.ts`): the roster's log-governed descriptor store reads
through the same helper, so a hardening applied to the check reaches every
trusted descriptor read. It takes one keyed `pinStore` shared across every
collection it serves, plus a `logIdFor(collectionId)` mapping to that store's
per-collection slot -- the caller typically builds each slot with
`resourceLogPinId`, replacing what used to be a per-collection `pinStoreFor`
factory. `acquireDescriptor` treats the log refusal classes as security signals,
not outages: `ResourceLogIntegrityError` and `ResourceLogContinuityError`
rethrow past a warm cache (matched on `err.name`, keeping the file
dependency-light), EXCEPT a continuity `rollback` -- reconcilable divergence,
possibly replication lag, per the spec's `#log-pin` rules -- which falls back to
the cache like any transport hiccup: nothing rolled-back is adopted and the pin
never regresses. The refresh-guard policy and the cipher are untouched; a
governed collection simply plugs this source into them.

## Permanent wire-level constants

Byte-for-byte identical strings both replicas depend on. **None of these can
ever change** -- each is baked into every existing account's derivations or
stored artifacts:

| Constant                                     | Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Why permanent                                                                                                                                                         |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BOOTSTRAP_HANDLE` / `BOOTSTRAP_KEY_NAME`    | `'bootstrap'` / `'boostrap-key'`                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | every data identity derives through them; the typo in `boostrap-key` is load-bearing and can never be fixed                                                           |
| `KEYRING_KDF`                                | PBKDF2, 600k iterations, SHA-256, salt `freewallet/keyring/unlock/v1`                                                                                                                                                                                                                                                                                                                                                                                                                                   | every account's unlock identity                                                                                                                                       |
| `RECOVERY_KDF`                               | HKDF, SHA-256, salt `freewallet/keyring/recovery-code/v1`, info `freewallet/unlock-seed`                                                                                                                                                                                                                                                                                                                                                                                                                | every issued recovery code; a changed salt orphans them all                                                                                                           |
| `STANDING_CLIENT_SALT`                       | `freewallet/unlock/standing-client/v1` (infos `client-seed` / `binding-mac`)                                                                                                                                                                                                                                                                                                                                                                                                                            | every standing credential's client identity and binding MAC key                                                                                                       |
| The ladder derivation                        | HKDF salt `freewallet/unlock/update-ladder/v1`, infos `rung/<index>` (account rungs), `vm` (the stable sibling VM key), and `<segment>/rung/0` (a client-annex generation's static rung 0)                                                                                                                                                                                                                                                                                                              | both wallets must climb the same ladder from the same seed; the three info families stay disjoint under the one salt                                                  |
| The generation segment                       | `gen-` + 12 random bytes base64url no-pad (20 characters); it embeds in every annex DID string and is the HKDF label's generation half                                                                                                                                                                                                                                                                                                                                                                  | orphan discovery is a prefix match, and a reused segment would re-derive a prior generation's rung-0 key                                                              |
| The delegated-clients service entry          | `type` `https://w3id.org/byoe#DelegatedClients` (readers dispatch on the type IRI, never the fragment), `serviceEndpoint` = the annex DID string; the wallet mints the fragment `#delegated-clients`, non-semantic and preserved on re-point                                                                                                                                                                                                                                                            | the account document's pointer at the current annex generation; the server's inspector clause reads it                                                                |
| The generation delegation                    | `invocationTarget` = the account Space items subtree (Space URL + trailing slash), `allowedAction` `['GET','HEAD','POST','PUT','DELETE']`, `controller` = the bare annex DID string, `expires` 365 days, rooted in the account Space's root zcap; embedded in the annex document as `type` `https://w3id.org/byoe#GenerationDelegation`, `serviceEndpoint` = the delegated-zcap map verbatim, fragment `#generation-delegation` (non-semantic), installed with the first transient VM, never at genesis | the standing authority every transient visit invokes under and every visit-scoped App Connect grant chains through (depth 3: root id string, the embedded delegation) |
| The unlock binding context                   | `freewallet/unlock/binding/v2`                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | every bound credential's account-binding MAC                                                                                                                          |
| `MultikeyCommitment` / `publicKeyCommitment` | VM type + property; the value is the bare sha2-256 multihash of the key's decoded multikey bytes, base64url no-pad                                                                                                                                                                                                                                                                                                                                                                                      | the document convention for a low-entropy-derived key-agreement key                                                                                                   |
| `BYOE_CONTEXT_URL`                           | `https://w3id.org/byoe/v1`, in every account document's `@context`                                                                                                                                                                                                                                                                                                                                                                                                                                      | it defines the two commitment terms                                                                                                                                   |
| `CONNECT_CODE_PREFIX`                        | `freewallet-connect:`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | the one spelling of the connect-code grammar                                                                                                                          |
| Collection / resource names                  | see the Space layout tables above                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | the Space layout contract                                                                                                                                             |
| `WalletActivity` `type` / `summary` strings  | `space/activity.ts`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | byte-significant across replicas                                                                                                                                      |
| `KEYRING_RECORD_VERSION`                     | `2`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | the stored record envelope                                                                                                                                            |

Every unlock method's KDF carries a distinct salt so two methods can never
derive the same unlock identity.

## What lives elsewhere (do not reimplement here)

- **`@interop/vh-resource-log`** -- the Resource Log Profile's generic client
  side: the JSON Lines codec, the `ResourceLogStore` port and `confirmAppend`,
  `verifyResourceLog` with the `admitAppend` admission-hook seam on the
  controller port, the keyed chain-head pin store, the append/create path, and
  the sealing sweep. `resourceLog/` keeps only the did:webvh controller adapter
  and the ceremony-tail license the hook carries. Test fixtures come from its
  `./testing` subpath, restricted to test globs by the lint pass.
- **`@interop/was-client`** -- the sync wire contract and port (`/sync`), the
  EDV envelope cipher and epoch construction (`/edv`,
  `x25519RecipientFromDidKey`, `createEdvDocCipher`), the descriptor-store seam,
  the WAS binding of the resource-log store port (`/log`: `resourceLogStore`),
  and `deriveSpaceId`.
- **`@interop/social-core`** -- the contacts collection specs and the
  `remotePayloadWins` LWW comparison.
- **`@interop/vc-display`** -- pure VC display derivation and credential input
  parsing (the former `display` subpath: credential name, issuer / subject
  render info, validity, Open Badges v3 helpers, display fields, the
  verification checklist, `credentialsFromJSON`). Nothing in wallet-core depends
  on it; the apps import the package directly.
- **`@interop/data-integrity-core`** -- the VPR type vocabulary and the loose VC
  shape guards. Import them from the `/vpr` and `/guards` **subpaths**, not the
  package root (the vocabulary predates a version bump, and the root can dedupe
  onto an older cached build).
- **`@interop/did-method-webvh`** -- the webvh log primitives `webvh/` wraps and
  the hashing/proof kernel `@interop/vh-resource-log` verifies and signs with.
- **`@interop/webkms-client`** -- `CapabilityAgent`; **`@interop/ezcap`** --
  `ZcapClient`.
- App-side, per the apps' own ARCHITECTURE.md files: the concrete synced-
  collection registries, storage and session objects, consent UI, the App
  Connect query processing, and freewallet's RxDB replication driver.

## Glossary

The repo's ubiquitous language: one canonical term per concept, used the same
way in code, tests, docs, and conversation. Terms the sections above use without
restating; the consumer apps' glossaries have the app-side entries. An entry's
`Avoid:` line names the synonyms this repo does not use. The convention is
canonical in isomorphic-lib-template's ARCHITECTURE.md Glossary section.

- **WAS (Wallet Attached Storage)** -- the HTTP protocol for storing resources
  in user-owned Spaces, authorized via ZCap. Containment: **Space contains
  Collections contain Resources**.
- **User key** -- the account-wide key that is recipient zero of every encrypted
  collection's key-epoch roster (`keys/userKey.ts`); see "The key hierarchy".
  Avoid: PUK.
- **Vault KAK** -- the X25519 key-agreement key that opens EDV envelopes: the
  user key's key-agreement half, cached in the client key record.
- **Epoch** -- one generation of a collection's encryption key, with the epoch
  secret wrapped to each recipient; rotating adds an epoch rather than
  re-encrypting history (prior epochs stay openable via escrow wraps).
- **Account pointer** -- `{ did, spaceId, host }`, the keyring record's payload;
  locates the account without authorizing anything against it.
- **Client / `clientId`** -- the keyed, custodied, revocable identity of an
  (app, user) pair: a keypair that can be a zcap grantee, a delegation
  controller, or a roster recipient. Deliberately not called a "device": one
  machine hosts many clients (browser profiles, several apps, several accounts),
  and a client is not tied to hardware. Avoid: device, device id.
- **`writerId`** -- an unkeyed, clearable, unrecoverable attribution label
  saying which writing agent produced a revision; used only for history
  attribution and LWW tie-breaking, minted locally app-side, deliberately not
  derived from any secret. Never an identity, and not 1:1 with a replica (so not
  a `replicaId` either). Avoid: replicaId, device id, session id.
- **`clientAnnex` / the client annex** -- the sibling did:webvh log holding
  per-visit transient client keys in GC'd generations, published in the
  account's auxiliary annex Space. `clientAnnex` is the formal term and the
  symbol stem; "the annex" is the short form in running prose after a section's
  first mention, the way "the document" is short for the account document. The
  split to hold on to: enrolled clients live in the account document, and
  delegated and transient clients live in the client annex.
- **Inventory** -- a credential's or client's set of durable entries in the
  account document, the annex log, or the ladder: its `keyAgreement` entry or
  commitment, its ladder VMs, and its committed rung hashes. Ceremonies install
  it; retirement sweeps it out. The ceremony-tail license's predicate compares
  it per document version (an entry is inventory-changing iff the set differs
  from the previous version's, `ResourceLogController.inventoryAt`). A named
  arrangement of an inventory is a qualified "configuration" phrase (the split
  configuration, the carry-over configuration), never bare. Avoid: posture,
  inventory.
- **Ceremony** -- an ordered sequence of durable writes across the account's
  systems (the account log, the roster, the unlock records, collection epochs,
  the caller's local storage) whose stage order carries an invariant --
  persist-before-publish, document-edit-first,
  decryption-material-before-authorization. Every stage detects its own
  completion from durable state, and every tear point has a stated mender (see
  Tear mending). The shared stage orders are canonical in "Ceremonies and
  cascades" above; the consumer apps list their wrappers and app-only ceremonies
  in their own ceremony inventories. Avoid: flow, workflow, wizard.
- **Tear mending** -- the umbrella for how a ceremony interrupted mid-run (a
  torn ceremony) gets finished. Three menders exist: a converging re-run (the
  same ceremony retried; every stage detects its own completion), a standing
  sweep (a background login-time pass, e.g. the cascade-completion sweep in
  `clients/rosterPolicy.ts`), and a repair (below). A stated residue with no
  mender is an open gap, not a documented limitation. Avoid: tear closure.
- **Repair** -- the mender of last resort: code waiting at the one entry point
  where the authority a specific torn state needs reassembles, detecting that
  state from durable state alone and finishing the ceremony -- used exactly
  where neither a re-run nor a login sweep can fire (the recurring case is a
  client-less account, where no durable login ever runs a sweep). Always
  qualified by its torn state -- freewallet's torn-retirement repair
  (`repairTornPassphraseRetirement`) is the built example -- never bare. Avoid:
  completer, finisher, fixup.
- **Current-key-set rule** -- see "The did:webvh document is the client roster"
  above.
- **Connect code** -- the `freewallet-connect:<base64url(JSON)>` payload
  carrying an enrollment request's public halves point-to-point.
- **Recovery code** -- 16 bytes base58, a complete minimal client derivable from
  its bytes alone; see "Ceremonies and cascades".

## Testing notes

- `test/node/` is the Vitest suite (`pnpm run test:node`); files are named
  `<module>-<topic>.test.ts` (e.g. `keys-userKeyRoster.test.ts`), with shared
  fixtures in `test/node/fixtures/` (`memoryIdStore.ts`, `rosterClient.ts`,
  request fixtures).
- The Playwright browser suite is **scaffolding only**: `playwright.config.ts`
  and the `vite dev` server exist, but `test/browser/` currently holds no tests.
- `test/logs/` holds generated did:webvh log artifacts from test runs; it is
  gitignored and not source.
- `pnpm test` runs fix + lint + typecheck + the node suite; the browser suite is
  deliberately not part of it.
- The executable cross-replica conformance suite lives in the freewallet repo
  (`tests/conformance/crossReplica.test.ts`), driving both apps' engines against
  a real in-process WAS server; its results are recorded in
  [docs/cross-replica-sync-compatibility.md](docs/cross-replica-sync-compatibility.md).
