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
- **Pure derivation out, formatting and consent in the caller.** `display`
  returns raw values (ISO strings, `Date`, booleans) and never imports i18n or
  date-formatting libraries; `request`'s `processRequest` is pure and leaves
  consent and the response channel to the app.

## Module map and dependency direction

Modules by layer; a module may import from lower layers only. There are no
cycles.

```
layer 0 (no internal deps):  sync   space   identity   display   descriptors
layer 1:                     webvh (space)          keyring (space, identity)
layer 2:                     keys (webvh, space, identity)
layer 3:                     enrollment (webvh, keys, keyring, identity)
                             recovery (webvh, keyring, space, identity)
layer 4:                     clients (webvh, keys)
cross-cutting:               request (display/text, enrollment/connectCode --
                             both deliberately leaf files)
root barrel:                 src/index.ts re-exports sync + space, nothing else
```

| Subpath       | Role                                                                                                                                                                                                 | Internal deps                    |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| `sync`        | WAS replication engine core: `SyncEngine`, `runPull` / `runPush`, the `SyncStore` replica seam, contacts LWW conflict resolution                                                                     | --                               |
| `space`       | Wallet Space layout contract: collection ids/specs, `wallet-activity` wire shape and builders, `publicCredentialUrl`, the `was-link` QR payload                                                      | --                               |
| `identity`    | Byte-identical WAS identity derivation: `agentsFromSecret` / `agentsFromSeed`, `singleKeyResolver`                                                                                                   | --                               |
| `display`     | Pure VC display derivation and credential input parsing                                                                                                                                              | --                               |
| `descriptors` | Collection encryption-descriptor acquisition (fetch / cache / offline fallback) and the unknown-epoch refresh policy                                                                                 | --                               |
| `webvh`       | The account's did:webvh log: provisioning, per-client update-key rotation, enrollment/revocation entries, client listing, log verification, the WAS-backed store, zcap signing under the webvh keyId | space                            |
| `keyring`     | The unlock layer: unlock KDF, the keyring record codec, the unlock Space lifecycle                                                                                                                   | space, identity                  |
| `keys`        | The user key, its wrap-set roster, the rotation cascade's per-collection op, the provision-time collection epoch install, the client-key record codec, client display labels                         | webvh, space, identity           |
| `request`     | Wallet-request / exchange pipeline: input classification, parsing, QueryByExample matching, cryptosuite negotiation, VP composition, VC-API client                                                   | display, enrollment (leaf files) |
| `enrollment`  | The client enrollment ceremony: connect code, approval, completion                                                                                                                                   | webvh, keys, keyring, identity   |
| `recovery`    | Recovery codes as minimal always-enrolled wallet clients                                                                                                                                             | webvh, keyring, space, identity  |
| `clients`     | Enrolled-client management: listing, disconnect-eligibility policy, the revocation cascade orchestrator, the login-time roster policy                                                                | webvh, keys                      |

`sync`, `descriptors`, and `clients` are never imported by another `src/`
module; `sync` and `space` are the only modules the root barrel re-exports.

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
pasted code without pulling the ceremony graph, and `request/classify.ts`
imports only `display/text.ts`.

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

| Collection            | id derivation | mutable | encryption | public |
| --------------------- | ------------- | ------- | ---------- | ------ |
| `private-credentials` | content       | no      | EDV        | no     |
| `public-credentials`  | content       | no      | plaintext  | yes    |
| `wallet-activity`     | content       | no      | EDV        | no     |

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
descriptor-before-first-content-push invariant).

The system collections sit outside the synced set (never replicated; read and
written directly):

| Collection | Access                    | Resources                                                        |
| ---------- | ------------------------- | ---------------------------------------------------------------- |
| `id`       | world-readable            | `did.json` (did:web projection), `did.jsonl` (the did:webvh log) |
| `key-map`  | private, capability-gated | `keys.json`, `user-key.json` (the roster), `client-labels.json`  |
| `keyring`  | in the unlock Space only  | `keyring.json` (the wrapped account pointer)                     |

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
   `{ version: 1, encryption, wrapped }`) -- the unlock Space's one resource:
   account controller, bind-time email, and the **account pointer**
   `{ did, spaceId, host }`. Deliberately no key material of any kind. The
   envelope seals under the record's own one-epoch descriptor (`encryption`,
   epoch[0] wrapped to the unlock KAK), so the record stays self-contained under
   the everything-seals-to-an-epoch rule.
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
6. **The wrap-set roster** (`key-map/user-key.json`, `keys/userKeyRoster.ts`) --
   a `CollectionEncryption` descriptor stored verbatim whose current epoch IS
   the current user key, wrapped once per enrolled client to that client's own
   KAK. A delivery channel, never a source of authority (see below).
7. **Recovery code** (`recovery/`) -- 16 bytes base58, from which a complete
   minimal client derives deterministically: its own unlock identity (under a
   distinct HKDF salt), a client key set, and a pre-committed did:webvh update
   key. The key material exists nowhere until the code is typed.

Two ordering invariants the apps must honor around the client key record
(unenforceable here; both are crash-durability rules):

- the user key and the roster epoch pin persist **atomically** -- one write or
  none;
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
  recovery code's key appears under `keyAgreement` **only**, and KMS-held
  convenience keys under `authentication` / `assertionMethod` only, so client
  listings keyed on `capabilityInvocation` exclude both structurally rather than
  by a filter someone must remember.
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
- **Revocation** (`revokeWebvhClient`) removes, in one entry: both verification
  methods, the update key, and **both** standing `nextKeyHashes` commitments --
  the staged hash removal is the subtle half, since a hash left committed is a
  standing re-seizure credential under the reveal mechanism.
- `verifyLog.ts` fetches the world-readable log unauthenticated on purpose (the
  hash chain is the trust, not the channel), resolves locally, and refuses a log
  resolving to a DID other than the account pointer's. Every ceremony runs this
  first; `listClients.ts` deliberately takes an already-verified log.

## The user key roster: delivery, never source (`keys`)

All roster mutation goes through was-client's descriptor-store seam
(read-with-etag, compare-and-swap writes, guarded create). Because a
resource-hosted descriptor gets none of the server-side epoch invariants a
Collection Description enforces, four client-side guards are load-bearing alone
against a tampering host:

1. **`epochsMac`** -- the epoch configuration is MAC'd under the current epoch
   secret the server never holds; a fabricated configuration fails
   authentication (`UserKeyRosterIntegrityError`).
2. **The epoch pin** -- the app pins the latest-seen roster epoch beside the
   account-pointer pin; a served roster that rolls back behind the pin is
   refused (`UserKeyRosterContinuityError`).
3. **The document-backed recipient resolver** -- recipient keys come from the
   locally verified did:webvh document, never from the roster itself; a roster
   entry with no matching `keyAgreement` verification method is dropped and
   never receives a wrap.
4. **`epochsSig`** -- the configuration is additionally signed by the writing
   client's enrolled Ed25519 key and verified against the document on any read
   adopting an epoch this client did not vouch for (the MAC alone cannot catch a
   host that mints its own epoch and MACs under the minted secret).

`rosterRecipientKid` is the one builder of a client's roster kid, shared by the
enrollment wrap, the read path, and the retiring rotation.

## Ceremonies and cascades

One principle underlies all of them: **every stage detects its own completion
from durable state alone** -- no checkpoint resources anywhere. Log entries are
idempotent; roster staleness is "does the current epoch still wrap to a
recipient the document no longer keys"; collection staleness is "does its
current epoch name a non-current user-key generation". So any torn cascade is
resumable by a naive full re-run, backstopped by the login-time completion sweep
(`clients/rosterPolicy.ts`: `checkUserKeyRosterAtLogin`, then the best-effort
`convergeUserKeyRosterToAccount` plus collection fan-out). The collection
cascade is **rotation-only**: epoch[0] comes from provisioning, and a descriptor
met without epochs is refused fail-closed rather than seeded (no construction
anywhere installs a user-key secret as a collection epoch secret, so a
collection-epoch escrow can never hand an external grantee the user key).

- **Enrollment** (`enrollment/`): a new client mints its whole key set locally;
  only public halves travel, as a `freewallet-connect:` connect code carried
  point-to-point, and nothing travels back over the channel (the account pointer
  comes from the keyring; the user key comes back through the roster). Order is
  push-not-pull, decryption material before authorization: the user key is
  wrapped to the new client's KAK in the roster FIRST, then the two log entries
  land (a sparse **commit** entry extending `nextKeyHashes`, then the **add**
  entry publishing the verification methods and update key). No
  authorized-but-blind window exists; a tear between the log entries surfaces as
  `EnrollmentPendingError` and re-running with the same code converges.
  Persisting the enrollee's key set under the app's unlock layer is the caller's
  job -- `completeEnrollmentCore` hands back the user key and the epoch to pin,
  and stops.
- **Client revocation** (`clients/revocation.ts`, `revokeAccountClient`) runs in
  dependency order: (1) the single document edit -- the pull axis everywhere;
  (2) the roster rotation, recipients resolved from the document the edit just
  produced; (3) the parallel per-collection re-epoch fan-out, failures
  collected, never aborting; (4) optional recovery-delegation re-mints. Then
  `onRotationAdopted` lets the revoking session adopt the fresh key in place. A
  cascade whose fan-out left failures behind is a **resumable success**, not an
  error (`cascadeCompletion`): the wallet IS disconnected once stage 1 lands,
  and the remainder is finished by a re-run or the login sweep. Disconnect
  eligibility is pure policy data (`clients/policy.ts`): `self`, `last-client`,
  and `unattributed-update-key` refusals, so both apps refuse the same rows for
  the same reasons.
- **Recovery** (`recovery/`): a code's posture is deliberately split --
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
  hash out; the replacement code's posture in), followed by mandatory user-key
  rotation off the spent code.

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
typed requests), `matching.ts` (QueryByExample -- **two matchers ship
deliberately**, DCW's jsonpath deep matcher and freewallet's type/issuer
matcher, since each wallet matches only its own store and no cross-replica
agreement is needed), `presentationSuite.ts` (cryptosuite negotiation),
`composeVp.ts` (grants ride inside the VP, added before signing so the DIDAuth
proof covers them), `processRequest.ts` (pure; consent and channel stay with the
caller; zcap / App Connect processing injected as `RequestProcessors`),
`exchangeClient.ts` (VC-API exchanges, injected `FetchLike`; handles the
empty-CHAPI-body + `protocols.vcapi` redirect case), `interactionUrl.ts` (VCALM
indirection). freewallet's App Connect query kind stays app-side.

The App Connect exchange this pipeline serves -- the `AppConnectQuery`, the
app-key credential, and the response presentation's `zcap` / `appConnect`
members `composeVp.ts` builds -- is specified in the App Connect companion spec
(<https://github.com/interop-alliance/app-connect-spec>; local checkout
`../app-connect-spec`, read `spec.md` there instead of fetching the rendered
version).

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

## Permanent wire-level constants

Byte-for-byte identical strings both replicas depend on. **None of these can
ever change** -- each is baked into every existing account's derivations or
stored artifacts:

| Constant                                    | Value                                                                                    | Why permanent                                                                                               |
| ------------------------------------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `BOOTSTRAP_HANDLE` / `BOOTSTRAP_KEY_NAME`   | `'bootstrap'` / `'boostrap-key'`                                                         | every data identity derives through them; the typo in `boostrap-key` is load-bearing and can never be fixed |
| `KEYRING_KDF`                               | PBKDF2, 600k iterations, SHA-256, salt `freewallet/keyring/unlock/v1`                    | every account's unlock identity                                                                             |
| `RECOVERY_KDF`                              | HKDF, SHA-256, salt `freewallet/keyring/recovery-code/v1`, info `freewallet/unlock-seed` | every issued recovery code; a changed salt orphans them all                                                 |
| `CONNECT_CODE_PREFIX`                       | `freewallet-connect:`                                                                    | the one spelling of the connect-code grammar                                                                |
| Collection / resource names                 | see the Space layout tables above                                                        | the Space layout contract                                                                                   |
| `WalletActivity` `type` / `summary` strings | `space/activity.ts`                                                                      | byte-significant across replicas                                                                            |
| `KEYRING_RECORD_VERSION`                    | `1`                                                                                      | the stored record envelope                                                                                  |

Every unlock method's KDF carries a distinct salt so two methods can never
derive the same unlock identity.

## What lives elsewhere (do not reimplement here)

- **`@interop/was-client`** -- the sync wire contract and port (`/sync`), the
  EDV envelope cipher and epoch construction (`/edv`,
  `x25519RecipientFromDidKey`, `createEdvDocCipher`), the descriptor-store seam,
  and `deriveSpaceId`.
- **`@interop/social-core`** -- the contacts collection specs and the
  `remotePayloadWins` LWW comparison.
- **`@interop/data-integrity-core`** -- the VPR type vocabulary and the loose VC
  shape guards. Import them from the `/vpr` and `/guards` **subpaths**, not the
  package root (the vocabulary predates a version bump, and the root can dedupe
  onto an older cached build).
- **`@interop/did-method-webvh`** -- the webvh log primitives `webvh/` wraps.
- **`@interop/webkms-client`** -- `CapabilityAgent`; **`@interop/ezcap`** --
  `ZcapClient`.
- App-side, per the apps' own ARCHITECTURE.md files: the concrete synced-
  collection registries, storage and session objects, consent UI, the App
  Connect query processing, and freewallet's RxDB replication driver.

## Vocabulary

Terms the sections above use without restating; the consumer apps' glossaries
have the app-side entries.

- **WAS (Wallet Attached Storage)** -- the HTTP protocol for storing resources
  in user-owned Spaces, authorized via ZCap. Containment: **Space contains
  Collections contain Resources**.
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
  and a client is not tied to hardware.
- **`writerId`** -- an unkeyed, clearable, unrecoverable attribution label
  saying which writing agent produced a revision; used only for history
  attribution and LWW tie-breaking, minted locally app-side, deliberately not
  derived from any secret. Never an identity, and not 1:1 with a replica (so not
  a `replicaId` either).
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
  display and request fixtures).
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
