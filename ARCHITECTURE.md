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
  Nothing here owns storage or UI; network access goes through injected seams (a
  `WasSyncPort`, a was-client handle, a `FetchLike`). The pervasive pattern is
  injected side effects: `SyncEngineDeps`, `SyncStore`, `DocCipher`,
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
layer 1:                     webvh (space, identity, resourceLog)
                             keyring (space, identity)
                             descriptors (resourceLog)
layer 2:                     keys (webvh, space, identity, resourceLog,
                             descriptors/logSource -- a leaf file)
layer 3:                     enrollment (webvh, keys, keyring, identity,
                             resourceLog)
                             unlock (webvh, keys, keyring, identity,
                             resourceLog, clientAnnex/ladder -- a pinned
                             exception, see below)
                             genesis (webvh, keys, space, resourceLog)
layer 4:                     recovery (unlock, webvh, keyring, space, identity,
                             clientAnnex/ladder -- the second pinned
                             exception)
                             clients (webvh, keys, resourceLog)
top:                         clientAnnex (may import any base subpath;
                             nothing in the base imports from it)
top-level leaves:            src/log.ts, src/stages.ts (import-free; any
                             layer may take a name from either)
cross-cutting:               request (enrollment/connectCode,
                             webvh/did -- all deliberately leaf files)
root barrel:                 src/index.ts re-exports sync + space, nothing else
```

| Subpath       | Role                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Internal deps                                                                      |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `sync`        | WAS replication engine core: `SyncEngine`, `runPull` / `runPush`, the `SyncStore` replica seam, contacts LWW conflict resolution                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | --                                                                                 |
| `space`       | Wallet Space layout contract: collection ids/specs, `wallet-activity` wire shape and builders, `publicCredentialUrl`, the `was-link` QR payload, the capability-authorized Space DELETE                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | --                                                                                 |
| `identity`    | Byte-identical WAS identity derivation: `agentsFromSecret` / `agentsFromSeed`, `singleKeyResolver`, the shared `zcapClientForSigner`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | --                                                                                 |
| `descriptors` | Collection encryption-descriptor acquisition (fetch / cache / offline fallback), the log-governed descriptor source, and the unknown-epoch refresh policy                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | resourceLog                                                                        |
| `resourceLog` | The wallet-domain residue of the Resource Log Profile client side (the generic half -- verifier, handover check, keyed chain-head pin store, entry builders, read/append/create path, sealing sweep -- lives in `@interop/vh-resource-log`): the import-free account-document reader leaf (`document.ts` -- relation resolution, ladder-VM recognition, the credential class -- whose public home is `webvh`), the ceremony-tail license on ladder-signed appends, the one implementation of the rollback carve-out every reader shares (`isResourceLogRefusal`), and the inventory-aware `WebvhResourceLogController` extension of the library's controller port with its did:webvh adapter, supplying the library's `admitAppend` admission hook | --                                                                                 |
| `webvh`       | The account's did:webvh log: provisioning, per-client update-key rotation, enrollment/revocation entries, client listing (`ladderVmIds` recognition included), the public home of the shared account-document readers, log verification, the WAS-backed and delegated log stores, zcap signing under the webvh keyId, the standing-zcap staleness policy (`standingZcap.ts`, which `recovery` re-exports)                                                                                                                                                                                                                                                                                                                                          | space, identity, resourceLog                                                       |
| `keyring`     | The unlock layer: unlock KDF, the keyring record codec, the unlock Space lifecycle                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | space, identity                                                                    |
| `keys`        | The user key, its wrap-set roster (log-governed, sealable), the rotation cascade's per-collection op, the provision-time collection epoch install, the client-key record codec, client display labels                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | webvh, space, identity, resourceLog, descriptors (leaf)                            |
| `request`     | Wallet-request / exchange pipeline: input classification, parsing, QueryByExample matching, cryptosuite negotiation, VP composition, the App Connect app-key credential, the `WalletOnboardingQuery` vocabulary, VC-API client, the ephemeral-exchange requester side, the zcap-only VPR builder                                                                                                                                                                                                                                                                                                                                                                                                                                                   | enrollment, webvh (leaf files)                                                     |
| `enrollment`  | The client enrollment ceremony: connect code, approval, completion, the onboarding-response envelope                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | webvh, keys, keyring, identity, resourceLog                                        |
| `unlock`      | Standing unlock credentials: the credential-derived client identity, the unlock record codec (shell / bridge / ladder / binding, `LADDER_SEED_BYTES` included -- the record format owns its member sizes), the merged document-inventory edit (verbatim key or hash commitment), the retirement ceremony                                                                                                                                                                                                                                                                                                                                                                                                                                           | webvh, keys, keyring, identity, resourceLog, clientAnnex/ladder (pinned exception) |
| `recovery`    | Recovery codes as standing unlock credentials that retire on spend, over the `unlock` machinery (the code's key set and its ladder derived from the code bytes, the remembered recovery continuation); the pre-minted `did.jsonl` delegation builder and the revocation cascade's bridge re-mint core (the annex sibling's mint taken as an injected closure)                                                                                                                                                                                                                                                                                                                                                                                      | unlock, webvh, keyring, space, identity, clientAnnex/ladder (pinned exception)     |
| `genesis`     | The account-genesis ceremony: the new-account key set mint and the staged provisioning of a fresh account (Space layout, the optional KMS authentication binding, did:webvh genesis, roster genesis, epoch[0] install, controller promotion)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | webvh, keys, space, resourceLog                                                    |
| `clients`     | Enrolled-client management: listing, disconnect-eligibility policy, the revocation cascade orchestrator, the login-time roster policy                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | webvh, keys, resourceLog                                                           |
| `clientAnnex` | The client annex -- the authoring and maintenance surface of everything ladder-anchored: the ladder (rung/VM derivation and the shared attribution walks), the annex log and its GC, ladder-VM zcap signing, the ladder-anchored account-log ceremonies (genesis, self-enrollment, forget), the credential-anchored account genesis, the transient-recovery continuation, the single-verb Space capability mints and the capability-authorized Space delete                                                                                                                                                                                                                                                                                        | every base subpath it needs                                                        |

`sync`, `clients`, and `genesis` are never imported by another `src/` module
(`keys` imports exactly one `descriptors` leaf file, `logSource.ts`, for the
epoch-configuration state type it stamps onto governed log entries); `sync` and
`space` are the only modules the root barrel re-exports.

**The client-annex boundary.** `clientAnnex` sits on top: it may import from any
base subpath, and nothing in the base imports from it -- enforced by a
`no-restricted-imports` block in the lint pass (part of `pnpm test`/CI), so a
new base-to-annex edge is a build failure, not a review catch. Four files are
pinned exceptions, each importing `clientAnnex/ladder.js` and nothing else from
the annex: `unlock/standingWebvh.ts`, where `removeUnlockKey` resolves a retired
credential's current ladder inventory; `recovery/recoveryWebvh.ts`, where the
remembered recovery continuation's add-and-retire entry resolves the same thing;
`webvh/accountEntry.ts`, where the account-entry seam's ladder arm attributes
the acting rung; and `recovery/recoveryCode.ts`, where a code's rung 0 and
ladder VM derive from its ladder seed. All four are a deliberate base-side
dependency on the shared derivation and attribution helpers, never on the annex
log machinery. The base keeps the verify-side / wire-format halves every wallet
needs regardless of account configuration: the resource-log ladder-append
license and the `ControllerInventory` ladder-key computation, both over the
shared `ladderVmIds` recognition in `resourceLog/document.ts` (`webvh` is that
reader's public home), the unlock-record codec with its `ladder` and
`delegatedClients` members (`unlock`), `webvh/standingZcap.ts`, the generalized
`wasWebvhLogStore` / `delegatedWebvhLogStore` seams, and the `GenerationCollect`
activity builder (`space`). Two symbols stay defined in `webvh/didWebvh.ts` but
are surfaced by the `./clientAnnex` barrel (`ladderVerificationMethod`,
`createLadderAnchoredWebvhLog`): the genesis document builder's two-armed
clientKeys XOR ladderVm signature is base API and its ladder arm calls
`ladderVerificationMethod` internally, so moving them would re-open a
base-to-annex edge. The base orchestrators keep declaring their closure-result
types (`GenerationDelegationRemint` in `clients/revocation.ts`,
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

Every handle onto one of them -- and onto a client-annex generation's `gen-`
collection, which is the same case in the annex Space -- is built by
`plaintextCollection`, the one site stating the `{ encryption: 'plaintext' }`
override. Sharing it is load-bearing twice over: without the override the client
describes the collection to decide plaintext vs encrypted, so a Space that does
not exist yet (every keyring lookup for a fresh unlock secret) 404s into an
`EncryptionError` rather than a 404-shaped `null`; and on a collection the
client took as encrypted the EDV codec computes its own write preconditions,
which silently defeats the compare-and-swap guard the `did.jsonl` publish and
the resource-log append path depend on.

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
   standing credential derives deterministically: its own unlock identity (under
   a distinct HKDF salt), a client key set, a binding MAC key, and an update-key
   ladder seed (info `ladder-seed`, the sibling of `client-seed` under the
   recovery client salt). Rung 0 of that ladder is the code's pre-committed
   did:webvh update key, and the ladder VM is what signs the code's own bridge
   delegation. The key material exists nowhere until the code is typed. The 16
   uniform bytes are what admit a code-derived ladder, where a
   passphrase-derived one would be an offline grind oracle against a revealed
   rung.

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
  standing credential contributes its key under `keyAgreement` and its ladder VM
  under `assertionMethod` and `capabilityDelegation`, a recovery code included,
  and the KMS-held DIDAuth signing key stands under `authentication` only, so
  client listings keyed on `capabilityInvocation` exclude all of them
  structurally rather than by a filter someone must remember.
- **The controller marker.** A client's `keyAgreement` verification method is
  published with `controller: did:key:<its signing multibase>` -- the document's
  one statement of which signing key a published key-agreement key belongs to.
  Every other method carries the account's own controller: signing keys are
  never marked (a did:key controller on a proof key breaks controller-based
  proof verification), the KMS authentication key is never marked, and a
  recovery code's `keyAgreement` method is deliberately left unmarked so client
  listings and revocation removals never match it. That unmarkedness is what
  tells the two methods a recovery continuation publishes at once (the new
  client's and the replacement code's) apart. The read side hard-requires the
  marker: the listing pairs a client with its key-agreement keys by reading the
  document, never by deriving the canonical twin, and a client with no marked
  method reports an empty key-agreement set -- the same refuse-not-guess rule as
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
  likewise one loop: the import-free `resourceLog/document.ts` leaf resolves the
  `keyAgreement` relation's references once (`resolvedKeyAgreementMethods`, over
  the shared `KeyAgreementDocument` shape), surfaced through `webvh`, and the
  two consumers are filters over it -- the listing and revocation keep only
  marked methods, while the user key roster's recipient resolver deliberately
  keeps unmarked ones too, since a recovery code's method is unmarked by design
  and must keep its wrap.
- **Two genesis flavors.** `ensureDidWebvh`'s KMS key map (`didWebKeys`) is
  optional. A KMS-backed genesis (freewallet: the map comes from its
  KMS-authentication stage) adds the one server-held key, the KMS DIDAuth
  signing key, under `authentication` only, and records the DID in `keys.json`.
  A client-keys-only genesis (dcw: no KMS anywhere in the path) supplies no map:
  the document holds client keys only, and no `keys.json` is written -- the
  record exists to bind a relation to a KMS key, and there is none. Everything
  else is identical between the flavors, and every ceremony (enrollment,
  rotation, revocation, roster entry proofs) already anchors in client keys, so
  none of them cares which flavor minted the account. The ladder-anchored
  genesis carries the same optional map (`createLadderAnchoredAccountLog` /
  `ensureLadderAnchoredDidWebvh`, threaded from the credential-anchored
  ceremony's own `provideKmsAuthentication` stage): the keystore is created
  under the ladder VM's bare did:key, and the KMS authentication VM joins the
  genesis entry under `authentication` only, with the same exclusions --
  everything else on a ladder-anchored document stays non-invocable. The stage
  is best-effort (a failure is collected and the genesis proceeds
  keystore-less), and adoption of an already-published log never edits it. A
  document published with no `authentication` relation keeps none: no ceremony
  here adds the KMS key to a standing document, so an account whose KMS stage
  failed presents no did:web or did:webvh DIDAuth key for its whole life.
- **`keys.json`, and its two writes.** The map is
  `{ authentication: { vmId, kmsKeyId }, webvh: { did } }` -- the one KMS
  binding plus the account DID. It is written twice per KMS-backed signup, one
  stage apart, because the DID does not exist when the binding is recorded: the
  KMS stage's own create-if-absent write, then the genesis' rewrite adding the
  `webvh` block under an `If-Match` on the ETag that write returned
  (`writeKeysJson`, `decisions/0016`). The store carries no precondition of its
  own: one fixed there would refuse the rewrite on every signup and strand a map
  with no `webvh` block, which the `expectedDid` fallback readers need. The
  rewrite CONSTRUCTS the body from those two members rather than spreading the
  served map, so a legacy `keyAgreement` binding is dropped wherever a signup or
  an establishment re-run rewrites; on a promoted account in the steady state
  nothing rewrites, and readers ignore the member where it stands.
- **The rewrite's lost race converges.** The genesis entry has already published
  by the time the rewrite runs, so failing a ceremony over a bookkeeping
  resource would be the wrong trade. A failed precondition re-reads the served
  map through the store's `getKeyMapRaw`: a map already naming this DID under
  this binding is left alone, and anything else is rewritten once under the
  served ETag. A second failure propagates, and so does the first against a
  store that offers no read. The adoption arm carries the other half: a re-run
  that adopts a published log backfills the `webvh` block into a map that lacks
  it, taking the binding from the SERVED map, since the run that published the
  log recorded it and this run's own map may name a key that log never
  published. Together they make the tear a run torn between the entry and the
  rewrite leaves -- a map with the binding and no `webvh` block -- mendable by
  the next establishment re-run.
- **No server-held key under `assertionMethod`.** Apart from `authentication`,
  every relation lists the enrolled clients' keys beside the standing
  credentials' ladder VMs. A ladder VM stands under `assertionMethod` and
  `capabilityDelegation` for as long as its credential stands, so neither
  relation lists client keys exclusively. `assertionMethod` membership is what
  entitles a key to issue assertions as the account and, under the App Connect
  Resource Log Profile, to append to the account's co-managed resource logs --
  so no server-held key may ever appear there. Server-side issuance, if ever
  needed, signs under a separate issuer DID, not the account DID.
- **The current-key-set rule.** An invocation or delegation verifies iff its
  verification method is in the resolved document _now_, under the relation its
  purpose needs: `capabilityInvocation` for an invocation,
  `capabilityDelegation` for a delegation. A key kept under another relation
  alone authorizes nothing, which is what `delegationKeyInDocument` tests. This
  is why client revocation is a single document edit with no per-collection
  revoke anywhere: the edit is the revoked client's pull axis everywhere.
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
  unconditional by design: it is serialized behind the won log CAS, and the log
  is the source of truth. Against a backend without the `conditional-writes`
  feature no ETag is served and the publish degrades to an unconditional write.
- **The `did:web` projection's freshness.** `publishEntryPinned` writes the log
  alone, since a bridge-delegated caller is authorized for nothing else, so a
  ladder-signed entry does not republish `did.json` and the projection can name
  a client or a credential the log has since removed. The server never reads
  `did.json` (it resolves the controller out of `did.jsonl`), so WAS
  authorization is unaffected; a did:web verifier reading the stale document is
  not, which makes the lag a revocation bypass rather than a cosmetic one. Two
  writers close it. The removal ceremonies (`forgetEnrolledClient`,
  `forgetLastEnrolledClient`) PUT the POST-removal projection through a
  root-invoking store immediately BEFORE their ladder-signed removal entry,
  since the client's authority ends at that entry (`clientForgetEntryOnce`'s
  `beforePublish` seam). And `ensureDidWebProjection` re-derives the projection
  from a resolved log, compares it against what the host serves, and republishes
  only on a difference -- run by any caller holding an `id`-collection writer,
  which on a client-less account is a transient visit invoking under its
  generation delegation (that delegation targets the account Space's items
  subtree, so it covers `id/did.json` with no widened bridge and no server
  change). The idempotent already-forgotten path writes no projection: the
  removal entry landed on an earlier run, so the store handed in is authorized
  for nothing and its next transient visit's ensure is the mender.
  `concludeWithPublishedLog` stays the controller-invoking paths' unconditional
  republish. The ensure's own write is ordered twice over, since the caller's
  document was resolved earlier and a difference alone does not say which side
  is stale. On a difference it calls the caller's optional `refresh` -- a fresh
  resolution of the same log -- and writes only when the refreshed derivation
  still differs. And its PUT carries the served read's ETag as `ifMatch`
  (`ifNoneMatch` when the projection was absent), so a projection written in
  between stands and the outcome is `conflict` rather than a throw. The window
  that remains: between a ladder-signed entry (a transient recovery's
  add-and-retire, say) and the next visit that runs the ensure, the served
  projection is stale; and a removal run torn between its projection PUT and its
  entry leaves `did.json` omitting a client the log still lists, which is
  fail-closed for a did:web verifier and re-PUT by the re-run.
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
  `accountLogPinId`, while `rotateWebvhUpdateKey` has no `spaceId` in scope and
  so takes an optional `logId` alongside its optional `pinStore`, built the same
  way by its caller. The ceremony paths thread both: `ensureDidWebvh` (expecting
  the caller's DID or, failing that, the `keys.json` webvh block's) and
  `rotateWebvhUpdateKey` (its crash-recovery branch included), so a
  truncated-prefix log cannot reach any entry-building step. The one documented
  exemption is `ensureDidWebvh`'s first-contact adoption with no caller-supplied
  DID and no `keys.json` webvh block, which legitimately discovers the DID from
  the log itself. The write side keeps the pin fresh rather than leaving first
  contact to the next read: the create path establishes the pin from the log it
  just minted, and a successful rotation advances it to the head it just
  published. Both halves are shared: `readPublishedLogOrThrow` is the same read
  refusing an absent log with the caller's message, and `publishEntryPinned` is
  the conditional `did.jsonl` publish that advances the pin in the same call.
  Every ceremony that publishes through a narrow log store (unlock, recovery,
  the annex) reads and writes through that pair. A bare publish is the shape
  that leaves a pin standing behind an entry this client itself wrote, so none
  remains. `readPublishedLog` and its throwing twin are typed to
  `getIdResourceRaw` alone, so a store that lacks the rest of the seam needs no
  cast.

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
convention the app must remember: the store carries a minimum controller version
(`setMinimumControllerVersion` on the sealable store), the revocation cascade
sets it from the document edit's own post-edit log before any roster-side work,
and an injected controller resolution still serving a cached pre-edit view is
superseded by it (a resolved view at or past the minimum wins), so the rotation
and the seal backstop can never carry a version before the removal they must
seal. The ladder-signed enrollment approval sets the same minimum from its
post-add log before its escrow append, which the ceremony-tail license admits
only at the version the add entry mints.

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
   the same carve-out everywhere a pin is consulted, and the code says so once
   too: `isResourceLogRefusal` (`resourceLog/errors.ts`) is the one
   implementation, over the generic taxonomy, of which refusals a reader must
   not paper over with a cached copy. A rollback is reconcilable divergence,
   possibly replication lag, per the profile's log-pin rules -- nothing rolled
   back is adopted and the pin never regresses -- so the login policy
   (`clients/rosterPolicy.ts`) degrades it to the cached user key instead of
   refusing the session, exactly as `descriptors/acquire.ts` falls back to the
   cached descriptor and the account-log verifier's callers carry on with a
   cached document view. A `fork` or SCID/method switch stays a refusal. A
   caller adds only the names the generic taxonomy does not carry
   (`isRosterRefusal`'s three `UserKeyRoster*` classes) -- or declines the
   carve-out explicitly, as `clientAnnex/mend.ts`'s establishment probe does: it
   holds no cached copy to degrade to, and its only other branch re-runs a whole
   establishment over the served log, so every continuity reason rethrows there.

   `ResourceLogLicenseError` is deliberately not in that predicate, so a license
   refusal met on a READ lands in the soft transport class (warn, serve cached).
   Ratified behavior rather than omission: the log is not corrupt and the signer
   genuinely holds the credential, so the append is unlicensed rather than
   forged, and the class does its work pre-write, where a conformant writer is
   refused before an unlicensed entry can land. The two shapes that argue for
   hard-refusing -- a compromised but still-listed key holder, and a genuine
   unlicensed entry N masking a forged entry N+1 under whole-log first-failure
   semantics -- were weighed and accepted.

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
never `instanceof` (the rule `resourceLog/errors.ts` and
`StagedCommitmentAmbiguousError` document): the errors are raised inside
app-injected seams that can resolve to a different copy of this package (linked,
or duplicated through a dependency tree), and an `instanceof` miss would drop a
security refusal into a warn-and-proceed transport branch. Each class's `name`
is therefore a stable contract. The rule is not confined to the refusal classes:
the sync engine's three wire signals travel through app-injected seams in
exactly the same way, and are matched the same way (see "The sync engine"
below).

`rosterRecipientKid` is the one builder of a client's roster kid, shared by the
enrollment wrap and the read path. Retiring a client names no kid at all:
`convergeUserKeyRosterToDocument` rotates away from every recipient the document
no longer keys, so no caller has to pair a client with its key-agreement key.

That convergence runs in TWO directions. The retire direction is above. The
escrow direction is its mirror: an enrolled client the document keys that holds
no wrap in the current epoch is escrowed into every epoch
(`enrolledClientRosterRecipients` rebuilds its kid from the controller marker
and the key-agreement method the document carries between them). It is the
mender for a ceremony torn between the entry that published a client and the
append that was to wrap the user key to it -- the one-request window a
ladder-signed enrollment approval leaves, whose append is licensed only as the
tail of its own entry and so cannot precede it. A convergence needing both
directions rides one write; a pure escrow adds wraps without minting an epoch,
so a missing wrap never rotates the user key; a healthy roster writes nothing. A
standing unlock credential is not a candidate, because its roster kid names its
standing client's SIGNING key and the document publishes only its key-agreement
half (a passphrase publishes not even that, only a commitment), so no reader can
rebuild the kid its own reads look for. A credential's missing wrap is mended by
the ceremony that holds the credential. The escrow direction needs a key that
unwraps every epoch, so it runs for a caller that supplies one.

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
spent recovery code's removal does register as one, since a code's ladder VM
stands under `assertionMethod`; its sealing is the mandatory post-spend rotation
itself, carrying the post-spend version like any other write.

**The ceremony-tail license.** The sealing check's structural twin, on the other
authority axis: what a LADDER-SIGNED append may do (clause B of the ladder VM's
authority clauses, app-connect-spec
`decisions/0003-ladder-authority-clauses.md`). A ladder VM sits under
`assertionMethod` for as long as its credential stands, so without a bound it
could append a roster rotation rekeying the account to recipients of a
credential thief's choosing, silently. The license admits a ladder-signed append
in exactly three shapes. Shape 1 is the log's first entry (creation, not
extension). Shape 2 is a rotation carrying an inventory-changing document
version -- S(V), the `keyAgreement` methods controlled by the account DID
(`Multikey` and `MultikeyCommitment` alike) union the ladder VMs, differs from
S(V-1) in either direction; ordinary client enroll/revoke is excluded
structurally by the `did:key` controller marker. Shape 3 is a rotation carrying
a version whose ENROLLED-CLIENT set (the `capabilityInvocation` methods,
equivalently the marked `keyAgreement` twins) differs from V-1's, in either
direction, AND whose entry a rung of the appending ladder signed. Shapes 2 and 3
are one-shot: refused when the verified head already carries that version or
later (`headControllerVersionIndex >= indexOf(V)`, position in the verified
version history, exactly the sealing comparison). All three carry a per-entry
rule: at most one of an entry's proofs may be by a ladder key, since every proof
of an entry shares one controller version and a co-signing ladder key would
otherwise spend it a second time. Proof order is not integrity-bound, so the
count is read as a set (`proofKeys`, the hook's entry-level view) and the
refusal lands on whichever ladder proof is admitted first. A ladder rotation
co-signed by an ordinary member stays licensed. A rotation against an unchanged
document (the silent-rekey shape) is thereby refused by every verifier, while a
torn ceremony's late-arriving tail still passes -- no entry carrying its
inventory-changing version exists yet.

Shape 3's signer conjunct is what keeps it out of the any-`keyAgreement`-change
predicate the clause rejects. A client's own enrollment or revocation entry is
client-signed, so it mints no shot for any ladder, and the excluded class stays
excluded; only a ladder-signed enrollment or removal mints one, and only for the
ladder that signed it. Without the conjunct an owner's ordinary enrollment of a
phone from a remembered session would mint a shot a phished credential's ladder
could spend on a silent rekey. Whose rung signed a version is read from the log
alone (`resourceLog/ladderRungs.ts`, exposed as `ladderRungKeys` on the
controller inventory), since a verifier holds no ladder seed: a ladder is
anchored at the entry that introduces its VM, either by the rung that entry
reveals and is signed by, or by the single rung-0 hash that entry commits, taken
up when a later entry authorizes its pre-image. Which of the two an entry is
takes one question first, whose the revealed key already is: a key another
ladder holds anchors nothing, so a ladder-branch bind -- where the ACTING
credential's rung reveals itself in the very entry that introduces the
newcomer's VM and commits its rung-0 hash -- anchors the newcomer on that
commitment while the acting ladder climbs. An entry that also publishes an
enrolled client anchors no ladder either, since the one key it authorizes is
that client's; the remembered recovery spend's add-and-retire entry is that
shape. It then CLIMBS with the log, by the last-position rule of
`decisions/0007-ladder-reveal-hash-order.md` read forward: an entry authorizing
exactly one new update key that signed it is a prerotation reveal, and when that
key's hash was committed LAST among some earlier entry's additions, and that
earlier entry itself authorized exactly one key and was signed by it, the
revealed key is the next rung of that key's ladder. The step is taken only while
the ladder's own VM still stands in the revealing entry's document, which is
what keeps a recovery spend's handover out -- the spent credential's reveal
entry commits the REPLACEMENT's hash last, and the entry revealing that hash is
the one that strikes the spent credential's ladder VM. The climb is what a
self-enrollment needs: it retires the rung it spends, so without the climb the
ladder would be frozen at a key the account no longer authorizes and no later
ladder-signed enrollment or disconnect of that credential could satisfy shape 3.
A hash committed anywhere but last is never climbed, so an enrollment approval
-- which reuses its rung, authorizing no key of its own, and commits the
client's update-key hash first rather than last -- never has a client key read
as a rung. Every other shape leaves the ladder unattributed, and an unattributed
ladder never satisfies shape 3.

Shape 3 is a verifier-side rule on an append-only log, so its rollout is
verifier-first: every reader of a roster log ships shape 3 before any writer
emits an append that needs it. A reader without it refuses not the append but
the whole log, since the license throws from the admission hook and the verifier
propagates that throw.

The register of admitted appends, one row per ceremony -- what its append
anchors at, and which shape it spends:

| Ceremony                                 | Anchoring entry                                              | Shape           |
| ---------------------------------------- | ------------------------------------------------------------ | --------------- |
| Credential-anchored genesis              | genesis                                                      | 1 (first entry) |
| Roster mend arm                          | genesis (adopted)                                            | 1               |
| Transient recovery                       | add-and-retire                                               | 2               |
| Last-client transition                   | reinstall entry (strike-version shot accepted)               | 2               |
| Passphrase change                        | bind entry (the escrow), then strike entry (the convergence) | 2, twice        |
| Passphrase add, passkey add              | bind entry                                                   | 2               |
| Passkey remove, recovery-code revocation | strike entry                                                 | 2               |
| Recovery-code issuance                   | key entry                                                    | 2               |
| Enrollment approval                      | add entry                                                    | 3               |
| Client disconnect                        | removal entry                                                | 3               |

The refusal is its own class, `ResourceLogLicenseError`: a write-time admission
error, retryable after an inventory-changing entry, so callers can tell an
unlicensed append from the integrity class's reject-the-whole-log corruption
verdict. Enforced through one predicate (`assertLadderAppendLicensed`) behind
the controller port's `admitAppend` admission hook that
`webvhResourceLogController` supplies, which the library consults per proof,
after the entry's proofs verify, both on read-back (every verifier handed the
hook-carrying controller view refuses a served unlicensed append) and pre-write
(`verifyResourceLogAppend`, which the log-governed store's `replace` calls, so a
conformant writer is refused before an unlicensed entry lands and poisons the
served log; `create` runs the same check over the genesis as a one-entry log).
The library itself carries no license, so a controller port over a document that
can list ladder VMs -- any account did:webvh document -- MUST supply the hook;
and because the hook is now consulted on entries that are never written, it is a
side-effect-free function of the view and its input. The wallet-core extension
of the library's controller port (`WebvhResourceLogController`) is
inventory-aware for it: `inventoryAt` exposes the per-version ladder keys and
inventory set that are invisible through the `assertionMethod` accessor. It
reads both through the shared account-document leaf (`resourceLog/document.ts`),
so the relation asymmetry that names a ladder VM has one implementation here and
in the client listing. The extension stays on the store types because the
resolver returns it and the hook lives on it. A refused write surfaces before
anything is written, so the accidental durable signal an unlicensed append used
to leave (the poisoned entry) no longer exists; WC-149, which weighs making a
license refusal a soft class, reasons about the pre-write refusal alone.

The last-client transition's strike-and-reinstall pair leaves the predicate
unchanged. Ladder VM keys are inventory members, so the strike entry and the
reinstall entry are both inventory-changing versions, and the clause licenses
one ladder-signed roster append at each rather than the one the design budgeted.
That second shot is accepted. It adds no class, since the clause already
licenses every standing ladder VM against any inventory-changing version,
whoever published it. A sibling credential's ladder can spend the reinstall
version's shot in exactly the same window, and that shot is the one the
transition's own rotation needs. Narrowing the clause to versions that ADD an
inventory member would close the strike shot and leave the other open, taking
nothing from a thief while moving a normative predicate. The exposure is
bounded, and one premise of that bound has since ended: a credential-only
session can now add a passphrase or a passkey, so a second standing credential
no longer implies an enrolled client. What carries the bound is the rest. The
sibling's append is signed by that credential's ladder VM and stands in the
roster log, so it is attributable. A rotation wraps only to recipients the
verified document lists. The stolen credential's standing wrap already opens
every epoch, so a rekey hands its holder no ciphertext they could not read
already. And credential rotation is reachable from a credential-only session
itself, so the remedy no longer waits on an enrolled client. Both shots close at
the same point: in a healthy run when the transition's rotation lands at the
reinstall version, and in a torn run at the re-run.

**The delegation clause's locked property.** The other authority axis, clause A,
governs what a ladder-signed DELEGATION may authorize, and the storage server's
client-annex clause enforces it. The property the clause locks, restated here
because this library mints every delegation it admits: a ladder delegation
either needs a loud companion entry to resolve, or can only write a log, or is a
target-exact single-verb read or delete of one Space of the delegator's own
account. The third predicate is the newest, and it is what admits the
single-verb Space children (`clientAnnex/spaceCapability.ts`): a child whose
`invocationTarget` is one bare Space URL, unchanged from its parent's, and whose
action set is exactly `['DELETE']` or exactly `['GET']`. That delete is the one
ladder authority whose exercise leaves no record anywhere. Every other
ladder-signed authority is loud by construction, and a destroyed Space cannot
carry the entry that would have announced it. The trade is stated in the account
deletion design that asked for it.

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
  document builder `ladderVerificationMethod` in `webvh` and the recognition
  `ladderVmIds` in the shared account-document leaf, surfaced through `webvh`):
  the STABLE SIBLING -- a dedicated Ed25519 key derived once from the ladder
  seed under the same salt with the fixed info label `vm`, published verbatim
  (the seed is random, so the hash-commitment rule permits it) and stable across
  rung spends. Its life is keyed to its credential rather than to the account's
  client census: installed when the credential becomes standing, struck at that
  credential's retirement, and untouched by enrollment, on accounts with
  enrolled clients and without them alike. It is listed under `assertionMethod`
  and `capabilityDelegation` ONLY; recognition is by that relation asymmetry (a
  `capabilityDelegation` member absent from `capabilityInvocation`), which also
  keeps it structurally out of every client listing. The annex's per-visit
  transient VM holds BOTH relations (decision 0013), so it never matches the
  asymmetry. Ladder-anchored genesis (`createLadderAnchoredAccountLog`) anchors
  the log on the ladder alone -- `updateKeys` = [rung 0], `nextKeyHashes` =
  [hash(rung 0), hash(rung 1)] (rung 0's carry-over hash, which the first
  self-enrollment's reveal-and-commit entry requires, plus the staged rung; both
  genesis flavors build the pair with `genesisNextKeyHashes`), the credential's
  `keyAgreement` inventory folded into the genesis entry. The first
  self-enrollment's add entry leaves every VM where it is: client in, rung 0
  retired, no VM struck. An account always carries an enrolled client or a
  ladder VM. Because the sibling is derived, removal is not permanent: a
  reinstall republishes the SAME key under the SAME id, and a still-unexpired
  delegation it signed resumes verifying the moment the method returns -- so
  delegation revocation, not VM removal, is the terminal remedy for
  ladder-signed delegations, and credential rotation is the remedy for a leaked
  ladder seed. The rotation reaches the sibling: `removeUnlockKey` strikes the
  retiring credential's VM from the document in the same entry as the rest of
  the ladder's inventory, seed in hand or not. Otherwise the retired seed would
  keep signing governed-log appends and account delegations.
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
  wrappers over it) publishes the credential's `keyAgreement` entry, installs
  its ladder VM, and commits its current update key's hash. The ADD polarity
  takes the ladder seed from its caller rather than minting one, so a re-run
  tests presence against the same seed and publishes nothing on a completed
  stage; a self-minted seed would let a torn establishment publish a second VM
  that no anchor can later strike. The REMOVE polarity treats the recorded
  update key as a ladder anchor, not truth: it resolves the ladder's current
  inventory from the log itself (`attributeLadderInventory` -- every standing
  committed hash, and any revealed rung a torn self-enrollment left in
  `updateKeys` together with the hashes its reveal entry committed) and strikes
  all of it in the one entry, since a removal trusting a stale bind-time rung
  would leave the live rung commitment standing as a latent re-seizure
  credential. A supplied ladder seed strengthens the attribution, and names the
  credential's ladder VM, which the entry strikes from `verificationMethod`,
  `assertionMethod`, and `capabilityDelegation` when it stands. A removal
  holding no seed strikes the same VM by attribution over the log: VM_x belongs
  to the ladder that signed the entry that first published VM_x, that introduced
  this credential's member there, or that committed a hash the ladder knows a
  priori there. The walk is anchor-invariant across the shapes where each rung's
  hash was committed by an entry that also revealed the previous rung, or by a
  handover, since it first recovers the rungs behind the recorded anchor from
  the log's positional rules, and an ambiguous walk fails closed
  (`LadderAttributionError`). One reachable shape falls outside that: the
  last-client transition's strike-and-reinstall pair followed by a
  self-enrollment that spends the already-revealed rung. That reveal-and-commit
  entry authorizes no key, so the walk cannot name the rung that signed it. A
  seedless retirement there is refused rather than completed with the
  reinstalled VM left standing. That shape is what the retirement gate
  (`decisions/0015`, stated under "Credential retirement" below) turns into
  `UnclaimedLadderVmRetirementError`. A retry holding the credential's ladder
  seed gets past it. WC-158 still names the seedless attribution gap itself.
  Without a seed the log walk also relies on the reveal entry's ratified hash
  append order (`decisions/0007-ladder-reveal-hash-order.md`) plus the
  credential's own verification-method id (`credentialVmId`), which the removal
  always passes. What a completing entry does not transfer to the enrolled
  client is ladder-owned only on POSITIVE attribution -- the seed derives the
  hash, or the credential comes out of the completing entry still standing,
  which is what makes the leftover its next rung's commitment. A spend leaves
  its SUCCESSOR's commitment in that position (the recovery continuation's third
  committed hash is the replacement code's), and a walk that could not attribute
  the leftover releases it rather than striking a credential that is not its
  own. The entry carries the key verbatim for a high-entropy credential, or, for
  a low-entropy-derived one, a `MultikeyCommitment` entry carrying only
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

- **The account-log signer seam** (`webvh/accountEntry.ts`, `signAccountEntry`):
  who signs an account-log entry is a parameter of every ceremony body, not a
  fact about it. `AccountLogSigner` is the discriminated union
  `{ kind: 'client', updateKeys }` | `{ kind: 'ladder', ladderSeed }`, and one
  `build` callback describes the document delta once for both arms
  (`decisions/0018`). The client arm is what an enrolled client always wrote:
  the active key derived from the seed and checked against the published
  `updateKeys`, the carry-over precondition, the entry's own stated parameters,
  and `did.jsonl` published beside its `did:web` projection. The ladder arm is
  the standing credential's, signing through the record's bridge delegation: the
  rung attributed from the log (fail-closed), the acting rung unioned back into
  `updateKeys`, its carry-over hash before the build's own `commitHashes` in
  `decisions/0007` order, and `did.jsonl` alone -- the bridge's whole reach, so
  the projection is the ceremony's own pre-entry PUT or the next visit's ensure.
  Both arms take the caller's chain-head pin and advance it, publish
  conditionally on the read the entry was built on, and leave the conflict retry
  to the caller. Two rules follow from the ladder arm's self-reveal and are
  relied on across the ceremonies. An entry cannot remove its own signer, so a
  ceremony that retires a rung needs a second entry signed by the successor (the
  two-entry passphrase change, the recovery spend's reveal-then-retire pair).
  And a rung is reused rather than consumed: attribution prefers a revealed rung
  over a committed one, so rung 0 stands revealed in the world-readable
  `updateKeys` for the credential's life and prerotation protects it across none
  of the single-entry ceremonies -- an accepted cost, since the rung's private
  half exists only in tab memory and an attacker holding it holds the seed that
  yields every rung. `ladderSignedAccountEntry`
  (`clientAnnex/ladderAnchored.ts`) is the seam's ladder arm under the annex's
  own name, narrowed to the outcome the ladder-anchored ceremonies read.
  `rotateWebvhUpdateKey` is the one body that keeps `updateKeys` directly, since
  that key is its subject.
- **Account genesis** (`genesis/`): a brand-new account mints its complete key
  set locally (`mintAccountKeySet`: Space id, the founding client's identity
  seed, the user key, the did:webvh update keys; the caller persists the seeds
  durably before anything publishes), then `ensureAccountGenesis` provisions the
  account in the one stage order both apps must encode identically: Space
  provisioning, the optional KMS authentication binding
  (`provideKmsAuthentication` -- absent means the client-keys-only genesis),
  did:webvh genesis, user-key roster genesis strictly after DID publication (the
  roster log's entry proofs carry a versionId in the published document),
  epoch[0] on every encrypted roster collection, and Space-controller promotion.
  The keyring bind is deliberately not a stage (where and whether an app binds
  an unlock method stays app-side), and neither is the `userExists` probe (a
  passphrase-collision concern of the unlock layer). The KMS stage is the one
  that overlaps its neighbour: nothing in a keystore ensure or a key mint needs
  the Space, so the ceremony STARTS the thunk before it awaits Space
  provisioning and hands it that provisioning as `spaceReady`, which the thunk's
  own `keys.json` write orders itself behind. Both ceremonies join before the
  genesis entry, which carries the binding, and both mark
  `KMS_AUTHENTICATION_STAGE` at that join rather than inside the thunk -- a
  thunk that finished first would otherwise mark out of order. The essential
  identity chain -- Space provisioning and the did:webvh genesis -- throws on
  failure; the later stages are collected in `failed`, so a completed call with
  failures is a resumable success finished by a naive re-run. Promotion
  (`ensurePromotedSpaceController`, also exported standing alone) is a state
  machine over the Space Description -- promote, confirm, or heal a torn
  controller PUT through a did:key-signed client -- and is skippable
  (`promoteController: false`) for an app whose account pointer must durably
  name the DID before the controller PUT lands, which then runs it itself after
  that write (freewallet's keyring re-bind ordering).
- **The credential-anchored establishment** (`clientAnnex/establish.ts`,
  `establishCredentialAnchoredAccount`): everything between a derived unlock
  credential and an account a transient login can enter, no enrolled client
  minted anywhere -- the shared orchestrator over
  `ensureCredentialAnchoredAccountGenesis`, serving the fresh signup and the
  login-time re-run alike. Six stages, each an ensure, with the ordering rules
  the sequence carries: (1) the interim bridge and the FIRST bind through the
  required `bindRecord` hook -- the standing-layout unlock record (ladder seed
  sealed in, pointer DID-less, the bridge delegated by the ladder VM's bare
  did:key) is durably written BEFORE the Space is created and before rung 0
  publishes, the transposed persist-before-publish rule; a caller passing
  `priorCreatedAt` from a standing keyring hit SKIPS this stage, since a
  DID-less re-write could downgrade a sibling browser's completed re-bind. (2)
  The shared genesis under the bootstrap did:key, promotion deferred; its roster
  and epoch failures are FATAL here, before anything names the DID, so the tear
  stays the heal-able kind (a DID-less record) rather than a registry sealed
  under a key only one tab ever held. The epoch gate and the one-installer rule
  ride the genesis contract: collection epochs install only when the roster's
  current epoch IS the candidate this run minted; otherwise (2c) the
  adopted-roster arm is the one installer, through the shared mint-policy stage
  (`clientAnnex/rosterDeliveredEpochs.ts`, `ensureRosterDeliveredEpochs`) --
  epochs install under the key the roster DELIVERS after the ensure, never the
  minted candidate, with the lost roster-genesis race adopted and reported
  converged-elsewhere and a no-wrap adoption surfaced as its own outcome. (3)
  The annex generation block, gated on no `#DelegatedClients` pointer and
  exported standing alone as `ensurePointedClientAnnexGeneration` (the fold
  every separate-pointer-entry caller shares; a ceremony whose pointer move must
  ride another entry atomically -- the transient recovery's add-and-retire --
  keeps its inline fold, decision 0012): the annex Space resolves in the settled
  order (document pointer, else the record's sibling delegation's target, else
  mint fresh), the generation mints under the bootstrap identity, the
  ladder-VM-signed generation delegation embeds while the Space still answers to
  the bootstrap key, the controller flips (only an authorization-class refusal
  -- a concurrent run flipped first -- is tolerated; a transport failure aborts
  before the pointer entry, which would otherwise durably name a generation in a
  Space still answering to the bare ladder did:key), and the pointer entry lands
  strictly last -- signed by ladder attribution of the currently revealed rung,
  resolved before the re-bind, under the caller's chain-head pin. The sibling
  arm serves callers holding a standing invocation authority (the primitive's
  `invocation` pair; the add/change-method fold's shape) -- within the
  establishment itself the sibling is only written by the re-bind, after the
  pointer entry, so its own re-runs never converge onto a stranded Space, and a
  sibling-named Space the bootstrap key can no longer write falls back to a
  fresh mint. (4) The re-bind through the same hook: full pointer,
  ladder-VM-signed bridge and sibling (they must survive promotion; the interim
  did:key-signed bridge cannot), management delegation to the account DID --
  BEFORE promotion, so the next login signs under the promoted controller only
  once the record says to. (5) The caller's `beforePromotion` hook (freewallet:
  the unlock-methods registry write), in the last window where a root invocation
  under the bootstrap did:key works; the asymmetric fatality contract: a throw
  fails the establishment, and a hook that must be best-effort swallows its own
  failures. (6) Space-controller promotion, last, with the best-effort
  keystore-controller promotion beside it (`promoteKeystore`) when the caller's
  KMS stage bound a keystore this run. A torn run converges by re-running whole
  (the log adopted by ladder attribution, never re-created). Four stated
  residues. A tear inside stage 3 before the pointer entry orphans a live annex
  Space nothing durable names (the random Space id re-derives from nothing, and
  each torn establishment attempt orphans one more). A tear between the re-bind
  and the promotion on a KMS deployment strands the keystore's controller on the
  ladder's bare did:key, outside the current-key-set rule. The other two are the
  KMS stage's, and both are inert keys in the account's own keystore that no
  document names: a tear between the key mint and the `keys.json` write, and one
  orphan key per retry of a run whose Space provisioning failed fatally, which
  the stage's concurrency makes reachable (the mint now starts before the Space
  is awaited). None of the four has a mender built. The account log is read once
  per run. The genesis returns the head it adopted or minted (`published`,
  carrying the ETag the PUT answered with), the roster genesis resolves its
  controller from that log (`rosterStoreFor({ did, log })`), the stage-3
  preamble reuses it when this run minted it and it carries an ETag, and the
  pointer entry tries the threaded head once before its pinned conflict retry.
  The outcome's `accountLog` is the head the run ends on, for a caller's session
  memo to seed from. Reuse never crosses a writer. A log this run minted did not
  exist a moment earlier, so no other writer can hold it; an adopted log (the
  heal re-run) is read again at stage 3 as before, because the pointer
  completion test reads the document and no ETag protects it, and a stale "no
  pointer yet" would mint a generation the account already has. The checks are
  narrower than a served read's: `verifyAccountLog` given a head runs both the
  substituted-account refusal and the chain-head check-and-advance, the entry
  writers check the DID and advance the pin only after their entry publishes,
  and the stage-3 reuse and the roster seed run neither, which is why they take
  only a head this run minted. The annex generation's own log is never read. The
  mint hands back the head its genesis PUT wrote, ETag included, and the
  delegation install stands on that instead of re-reading a log this run wrote a
  moment ago. A backend serving no ETag leaves the install reading for itself,
  since the entry it publishes is a compare-and-swap; either way the install's
  own publish establishes the generation's pin slot.
- **The credential-anchored mend** (`clientAnnex/mend.ts`,
  `mendCredentialAnchoredAccount`): the sibling entry point that converges the
  establishment's tear states from any door into the account (a transient login,
  a remembered resume, a future step-up, another wallet app), so no login path
  carries the tear taxonomy itself. Its arms fire in order, each at most once
  per invocation, cascading within one invocation -- deliberately no repair-wide
  single shot. The ESTABLISHMENT arm fires on a DID-less pointer, probing
  durable state first: a log that already resolves, attributes to this
  credential's ladder, AND carries the delegated-clients pointer marks the
  record as DOWNGRADED (a concurrent or stale heal re-wrote it), and the mend is
  re-binding the record to the published DID -- never re-running stage 1, which
  would die on the promoted Space. A revealed rung with no pointer is the
  stage-3 tear and falls through, with every other probe outcome, to the whole
  establishment run, whose throw is caught into the report, never propagated raw
  -- except the probe's `ResourceLogContinuityError`, rethrown by name (a served
  rollback or fork must surface as the continuity refusal it is). Convergence
  returns immediately with `reenter: true`: the caller re-fetches the record
  through its own keyring fetcher and re-enters, carrying the single-shot
  re-entry marker on its own glue (a mend-internal counter would reset per
  invocation and let a host pinning a stale DID-less record drive an unbounded
  establish/re-fetch loop). A re-bind additionally reports
  `reenterRepairShaped: true` -- its root registry window is closed, so the
  re-entry must carry `repairShaped: true` for the registry arm to fire. The
  PROMOTION arm mends the re-bind-to-promotion tear under the ladder VM's bare
  did:key, on two triggers: a caller-supplied failed delegated read (mend, retry
  the read once, and on a still-failing attempt or retry RETHROW THE ORIGINAL
  error unchanged), or an authority-neutral probe that treats a null
  `describe()` under the bootstrap key as evidence of promotion (WAS masks
  refusals) and classifies the tear only on an authorized read showing a
  non-account controller; the probe direction's non-convergence is a report
  member, having no antecedent error. Only a promotion that WROTE marks the
  entry repair-shaped for the arms below; a `confirmed` outcome means the
  account was healthy and the failed read a flap. The ROSTER-AND-EPOCHS arm is
  gated on the completion test -- roster delivered AND every encrypted
  collection carries epoch[0], durable state alone, a present roster followed by
  the per-collection completion probe -- and runs the shared mint-policy stage
  (`ensureRosterDeliveredEpochs`, the policy's one home) under the
  caller-supplied post-promotion authority (the `invocation` triple and a
  delegated roster store; the bootstrap `rosterStoreFor` cannot serve a promoted
  Space). It mints a fresh user key ONLY when the shared stage's own decide-read
  observes the roster absent, and only under the mint preconditions, checked at
  that same mint decision through the stage's `beforeMint` seam (no client-local
  roster-epoch pin held -- the required `hasRosterEpochPin` port -- no other
  standing credential published in the verified document, no encrypted
  collection already epoch'd or unreadable), so a fabricated-absent roster
  cannot become a single-recipient genesis; a lost roster-genesis race adopts
  and reports converged-elsewhere, a no-wrap adoption is its own outcome, and a
  failed read is transport, never incompleteness. The REGISTRY arm re-fires the
  caller's read-first `beforePromotion` hook on a repair-shaped entry (an arm
  mended, or the caller's flag) under the post-promotion authority, with an
  establishment-shaped context synthesized from the caller's standing record and
  the log-attributed rung -- the mend knows nothing of the registry protocol.
  Caller obligations, stated as contract: the account core must come from a
  BINDING-VERIFIED record; every arm past the establishment arm presupposes the
  caller's loud entry; "converged" always means the durable state the arm gated
  on changed. The healthy fast path never invokes the mend at all.
- **The transient readiness ensure** (`clientAnnex/heal.ts`,
  `ensureCredentialClientAnnexGeneration`): the pass every transient visit runs
  before it enrolls, mending from durable state the six ways a visit holding
  nothing but the credential is cut off from the annex or from the account log
  -- no `#DelegatedClients` pointer, an auxiliary Space the server no longer
  has, a dead pointed generation, a stale embedded generation delegation, a
  stale or mis-targeted `delegatedClients` sibling, and a stale bridge
  delegation. A pointed Space that is gone is told apart from a dead generation
  inside a live one, by two reads rather than one. A storage server masks an
  unauthorized read as the same 404 an absent Space answers, so one 404 says
  only "absent, or no authority here". The visit reads the Space Description
  through a ladder-signed GET-only child of the Space's root and then, if that
  answers 404, through a root invocation as the ladder VM's bare did:key, the
  controller a torn establishment leaves behind. The Space is gone only when
  both answer a real 404. Status alone decides -- a 2xx is a present Space
  whatever its body says, and every other answer throws -- so neither a
  transport failure nor an unreadable body reads as absence. The first probe
  presupposes a server admitting the ladder delegation clause's single-verb
  predicate (was-teaching-server 0.25.0 or later); against an older one both
  reads are refused alike, a live Space reads as gone, and the visit re-points
  where the dead-generation arm used to heal inside the Space with no
  Space-level authority at all. The fresh-Space stage is controller-first past
  the create: the create itself must name the ladder VM's bare did:key, since a
  server authorizes a create against the controller the request body names, and
  the controller is flipped to the account DID in the next request, before
  anything publishes. The stranding window is one request wide --
  did:key-controlled inside it, which no server orphan sweep can reap, and
  account-controlled past the flip, which a sweep can. The flip precedes the
  generation mint because that mint rides the ladder-signed sibling delegation,
  whose chain the server admits only once the Space answers to the account DID.
  The bridge renewal precedes every arm: the bridge is the credential's one
  write path into the account log, and both minting arms end in a pointer entry
  riding it, so a stale one is replaced ladder-VM-signed and the caller's
  account-log store is built over the usable bridge (`idStoreFor`). An arm that
  moves the `#DelegatedClients` pointer reveals the credential's committed rung
  first, inside the conflict retry, since a self-enrollment consumes whichever
  rung stood revealed before it. That rung stands revealed in the account log's
  `updateKeys` afterwards, an accepted cost of the pointer move. Bridge and
  sibling ask ONE staleness predicate, the house policy's `standingZcapStale`
  (`webvh/standingZcap.ts`), and the required `onRebindRecord` seam receives
  both usable delegations whenever either was minted, so the caller re-seals the
  record from one pair. A failed re-seal is fatal only when the sibling was
  fresh; when only the bridge was, the failure is reported on the outcome
  (`bridgeResealError`), since that bridge already served the visit and the next
  visit re-mints. On a healthy account the whole stage reads the pointed
  generation's log ONCE: the head it reads to choose renew-versus-mint is handed
  to `ensureGenerationDelegationCurrent` as `published`, and, when that pass
  published nothing, back out on the outcome's `generationLog` for the
  enrollment (`enrollTransientClient`) to build its first attempt on. A threaded
  head is checked against `expectedDid` exactly as a fresh read would be, it
  never touches a chain-head pin, and it is the FIRST attempt's alone -- a lost
  compare-and-swap means the head is stale, so the conflict retry re-reads under
  the pin. That threaded attempt is extra rather than one of the retry's three,
  so saving a read costs no conflict budget. A renewal or a fresh mint leaves
  `generationLog` absent: the publish seam returns no ETag, so no
  compare-and-swap-capable head of the post-write log exists to pass on.
- **Enrollment** (`enrollment/`): a new client mints its whole key set locally;
  only public halves travel, as a `freewallet-connect:` connect code carried
  point-to-point, and nothing travels back over the channel (the account pointer
  comes from the keyring; the user key comes back through the roster). The two
  log entries are a sparse **commit** entry extending `nextKeyHashes`, then the
  **add** entry publishing the verification methods and update key. Where the
  escrow sits relative to them is decided by the signer kind (`decisions/0018`).
  A CLIENT signer keeps the push-not-pull order, decryption material before
  authorization: the user key is wrapped to the new client's KAK in the roster
  FIRST, so no authorized-but-blind window exists. A LADDER signer runs commit,
  add, then escrow, because a ladder-signed roster append is licensed only at an
  inventory-changing version its own ladder signed, which the add entry is what
  mints. The one-request window that leaves is the ladder branch's stated cost:
  a client the add entry published holds `assertionMethod` and its own update
  key while holding no wrap, bounded by a re-run with the same connect code, by
  the escrow-direction convergence of any later ladder-branch ceremony, and by
  the row it leaves in the connected-wallets listing. A tear between the log
  entries surfaces as `EnrollmentPendingError` and re-running with the same code
  converges. A code whose key-agreement key is not the canonical X25519 twin of
  its signing key is refused (`assertCanonicalEnrollmentKeys`, run both by the
  parse -- so the refusal reaches the approver's consent screen -- and by
  `approveEnrollment`, the seam every approval path funnels through). That
  refusal is what keeps the controller marker honest: the document states that
  the published key-agreement key belongs to the client's signing key, and this
  is what makes the statement true. Persisting the enrollee's key set under the
  app's unlock layer is the caller's job -- `completeEnrollmentCore` hands back
  the user key and the epoch to pin, and stops. `onboardingResponse.ts` adds
  only a transport around the same code: the
  `{ walletOnboarding: { v, code, label? } }` envelope an enrollee POSTs back to
  an exchange whose request carried a `WalletOnboardingQuery`. The code rides
  verbatim (the ceremony's validation and the connect-code version are
  untouched), and the optional label -- attacker-adjacent text rendered on the
  approver's consent screen -- is control-character-stripped, trimmed, and
  refused rather than truncated when over its 64-character cap; its durable home
  is `key-map/client-labels.json`, which the approver writes. The inviter's side
  of that same exchange is generic transport and lives in
  `request/ephemeralExchange.ts`: `createEphemeralExchange` POSTs the query to
  the server's ephemeral-exchange route and hands back the exchange URL plus the
  interaction URL the QR code carries, and `pollEphemeralExchange` polls until
  the enrollee's envelope lands. What stays in `enrollment/onboardingInvite.ts`
  is the one policy constant, `ONBOARDING_INVITE_TTL_MS`: how long a wallet
  offers the invite for, inside the server's ten-minute exchange TTL. The routes
  are unauthenticated by design (a capability-URL access model -- the exchange
  URL is the secret, travelling point to point through the QR code), so nothing
  there signs a request; a `404` is the expired invite and raises the
  stable-named `EphemeralExchangeGoneError`, while every other failure is
  transient and retried. The poll takes an optional `timeoutMs` deadline that
  aborts the in-flight request and raises `EphemeralExchangeTimeoutError`, a
  separate class because the exchange may still be approvable and the requester
  just stopped waiting.
- **Client revocation** (`clients/revocation.ts`, `revokeAccountClient`) runs in
  dependency order: (1) the single document edit -- the pull axis everywhere;
  (2) the roster rotation, recipients resolved from the document the edit just
  produced -- the pairing-free convergence the login sweep already runs
  (`convergeUserKeyRosterToDocument`), which retires every current-epoch
  recipient the post-edit document no longer keys in one rotation, naming no
  client -- followed by the roster log's seal backstop (best-effort, reported in
  `rosterSeal` rather than thrown); before any of stage 2 runs, the orchestrator
  sets the roster store's minimum controller version from the edit's post-edit
  log, guaranteeing the rotation and the seal carry a version at or past the
  removal even under a stale injected controller resolution (the log-governed
  store section above); (3) the parallel per-collection re-epoch fan-out,
  failures collected, never aborting; (4) optional recovery-delegation re-mints;
  (5) the optional `remintGenerationDelegation` closure, run on the post-edit
  document in the rotated and the no-roster paths alike (its result rides the
  outcome as `generation`), so revoking the enrolled client that signed the
  current generation delegation replaces it in place instead of killing the
  transient entry path silently mid-generation. Then `onRotationAdopted` lets
  the revoking session adopt the fresh key in place. A cascade whose fan-out
  left failures behind is a **resumable success**, not an error
  (`cascadeCompletion`): the wallet IS disconnected once stage 1 lands, and the
  remainder is finished by a re-run or the login sweep. Disconnect eligibility
  is pure policy data (`clients/policy.ts`): `self`, `last-client`, and
  `unattributed-update-key` refusals, so both apps refuse the same rows for the
  same reasons. Two of the three are properties of the acting signer rather than
  of the account, so `signerKind: 'ladder'` lifts them (`decisions/0017`): a
  standing credential's rung has no self, and removing the last client abandons
  no update authority -- the account lands ladder-anchored, the shape a
  credential-anchored signup produces, and the credential's own ladder extends
  the log from there. The document edit follows the same split: the
  self-revocation refusal inside `revokeWebvhClient` is a client-arm check on
  the signer's own active key, and the ladder arm has no self. The
  unattributed-update-key refusal stands on both arms, as does the staged-hash
  strike.
- **Credential retirement** (`unlock/retire.ts`, `retireUnlockCredential`): the
  ceremony behind "change my passphrase" and "remove this passkey", on either
  signer arm. On the LADDER arm the entry is signed by the ACTING credential's
  rung -- the successor's on a passphrase change, a surviving credential's on a
  passkey removal -- never the retired credential's own, since an entry keeps
  its own signer and a self-signed strike leaves the ladder it meant to end
  standing. Stage 0 below is the client arm's alone: every unlock record's
  bridge and sibling delegation are signed by that record's own credential's
  ladder VM (`decisions/0019`), so a ladder-branch strike rots no sibling record
  and there is nothing to re-mint. (0) The **sibling record re-mint**, over
  every OTHER standing credential's record and bridge, run BEFORE the document
  edit. The retiring credential's ladder VM may have signed those records. The
  last-client transition signs sibling records with one, and
  `currentAccountRecordSigners` accepts it. Striking that key rots proofs their
  owners cannot repair, since a sibling credential's own login dies at the proof
  check. The pass names the doomed VM through `remintRecoveryDelegations`'
  `retiringKeyMultibases` and re-signs while the key still stands. Running it
  after the edit would instead open a window in which every sibling record is
  unverifiable, and a run torn there would brick exactly what the stage
  protects. Before that pass writes anything, stage 0 runs the **retirement
  gate** (`decisions/0015`): a credential retired here carries a ladder, so its
  ladder VM must be claimed before the ceremony strikes anything. The predicate
  is narrow. The claim struck no ladder VM, the credential's own `keyAgreement`
  member still stands, and a ladder VM stands unclaimed that COULD BE THIS
  CREDENTIAL'S. That last conjunct is read off the log's entry shapes rather
  than off the attribution that already refused
  (`ladderVmIdsIntroducedWithCredential`): a standing VM qualifies when the
  entry that introduced it also introduced this credential's `keyAgreement`
  member, or newly committed or authorized its anchor, or introduced no
  credential-class member at all -- the split issuance's authority entry, which
  installs authority for a credential bound earlier. None qualifying is the
  positive answer that the credential never had a VM to leave behind, which is
  what lets a torn issuance's orphan (a `keyAgreement` member, no ladder VM, no
  committed rung) be removed at all beside a sibling's standing VM. That shape
  refuses with `UnclaimedLadderVmRetirementError`, which carries the qualifying
  unclaimed ids and a `retryableWithLadderSeed` hint. The gate fires only on a
  seedless claim: a seeded one either strikes the derived VM or proves it
  absent, as the last-client transition torn between its strike and reinstall
  entries leaves it, so the hint is true whenever the error is raised. Nothing
  is written and the credential stays standing. A sibling credential's unclaimed
  VM on a healthy multi-credential account does not trip the gate, since the
  claim struck something there, and its VM qualifies for nothing anyway. What
  the gate closes is a retired credential's leftover VM standing under
  `capabilityDelegation`, which can still sign a DELETE-only capability on the
  account Space. Nothing downstream tells such a leftover from a sibling's
  standing VM, so the retirement is the one place the state can be closed. A
  caller that establishes a replacement credential before retiring the old one
  runs `preflightUnlockCredentialRetirement` first -- the same gate over one
  pinned read, writing nothing -- so the refusal lands before establishment. A
  refusal after establishment would leave a pending-shaped registry entry the
  seedless repair can never clear. (1) The **document inventory edit**
  (`removeUnlockKey`): the credential's `keyAgreement` entry, its committed rung
  hashes, and its ladder VM leave in one log entry, which kills its latent
  self-enrollment authority. Stage 0's attribution and the edit's own are tied
  by `expectedLadderVmIds`: the edit refuses before writing when its own read
  resolves a different ladder-VM set (`LadderInventoryDriftError`), so a
  concurrent ceremony or a host serving different log versions cannot leave the
  edit diverging from what stage 0 acted on. The edit runs the gate again before
  its entry publishes, as defense in depth, under `removeUnlockKey`'s opt-in
  `requireLadderVmClaim` flag. `removeRecoveryKey` sets it too: a code carries a
  ladder now, so its removal claims that ladder's VM seedlessly from the rung-0
  multibase the registry recorded at issuance, and refuses with the same typed
  error when no attribution arm can claim it. The refusal names the anchor it
  walked from. (1b) The injected annex-inventory closure, strike-or-swap,
  best-effort by contract. (2) The **roster rotation and collection fan-out**,
  so writes stop landing under epochs the retired credential could open.
  Document-edit-first is load-bearing the other way: a run torn after it leaves
  the roster keying a recipient the document no longer backs, which is the state
  the login sweep detects and finishes.
- **Forget** (`clientAnnex/forget.ts`, `forgetEnrolledClient`): a remembered
  browser's enrolled client removes ITSELF through the standing credential's
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
  until another enrolled client's login sweep seals it. The last enrolled client
  refuses (`LastEnrolledClientForgetError`, fired before anything rotates): its
  forget is the ladder-anchored transition below.
- **The last-client forget** (`clientAnnex/forgetLast.ts`,
  `forgetLastEnrolledClient`): the transition (decision 0004's amendments) that
  takes an account from one enrolled client to the client-less, ladder-anchored
  state -- the third producer of that state, beside the credential-anchored
  genesis and the transient recovery. The order is forced twice over: the
  server's revocation endpoint verifies a to-be-revoked chain against the
  CURRENTLY resolved document, and the ladder VM carries no
  `capabilityInvocation`. So: (1) the **strike-and-reinstall pair**, both
  entries written while the client's inventory stays (the both-present state).
  The acting credential's own ladder VM leaves in the first entry, scoped by
  entry-signer attribution rather than struck account-wide, and the second
  reinstalls it under the same id (`installLadderVmWebvh`, idempotent,
  rung-signed). The reinstall entry is the inventory-changing version the
  ceremony-tail license admits, which is how the transition earns its rotation
  with no change to the license. The pair republishes an identical key and
  revokes nothing, so stage 4's revocation ordering is undisturbed. A run torn
  between the two entries leaves the account VM-less with the client still
  standing, and a re-run's idempotent reinstall converges. The one-shot compares
  the head's controller version index against the append's, so a sibling ladder
  spending the STRIKE version's shot leaves the rotation licensed at the
  reinstall version. Only a sibling spend at the reinstall version, landing
  between the pair and the rotation, refuses the run (`ResourceLogLicenseError`
  from the rotation append). That refusal is not a wedge. It leaves the same
  both-entries-published state a tear leaves, and the re-run converges. The pair
  runs under `if (wrapped || !vmStands)`, where `wrapped` is the forgotten
  client's kid in the pre-transition roster's current epoch. A sibling's rekey
  does not clear that gate, since the client still stands in the document and is
  a recipient of the sibling's new epoch. The re-run republishes the pair and
  mints a fresh inventory-changing version to anchor at. It burns no rung, since
  the reinstall signs with the currently attributed rung and keeps its own hash
  committed under the carry-over convention. The cost is two account-log entries
  per attempt, so a sibling racing every round is a livelock rather than a
  wedge. The pair publishes through the enrolled client's root-invoked
  `clientLogStore` rather than the credential's bridge: the bridge is often
  signed by the very VM the strike removes, so a bridge-invoked reinstall would
  be refused against the post-strike document under the current-key-set rule.
  (2) The **roster rotation**, ladder-VM-signed and carrying the reinstall
  entry's version, HTTP-invoked under the still-standing client, ONE append
  retiring the client's wrap -- a ladder-signed head also means the roster log
  needs no seal repair afterwards, load-bearing where no login sweep will ever
  run again; (3) the collection fan-out; (4) the **generation stage**: a fresh
  ladder-signed generation delegation replaces the embedded one
  (`ensureGenerationDelegationCurrent`, keeping the account
  transient-login-reachable), the staleness read against a projected post-edit
  document -- this credential's ladder VM and the forgotten client are both
  named retiring, so a delegation either of them signed is replaced while one a
  surviving sibling ladder signed stands -- then every still-unexpired
  delegation this ladder VM ever signed is revoked, the bytes recovered from the
  annex log's history (`generationDelegationHistory`; webvh restates full state
  per entry, and a renewal inside the 30-day window can leave two) -- closing
  the resurrection window a reinstalled derived-key VM reopens, with a re-POSTed
  revocation's 400 already-revoked answer read as success; (5) the **other
  unlock methods' record re-mint** (the optional `unlockMethods` reach): the
  revocation cascade's re-mint pass (`remintRecoveryDelegations`) run with the
  ladder VM as the delegating key and the record-frame signer and the forgotten
  client named as retiring (`retiringKeyMultibases` -- the post-reinstall
  document still lists it, so without that axis every bridge it signed would
  read as standing), re-sealing every other standing credential's and recovery
  code's record through its management zcap, HTTP-invoked under the
  still-standing client, every entry's fate reported (`RecordRemintOutcome`). On
  a client-less account no remembered login's refresh block will ever heal these
  records, so unlike the revocation cascade this pass is not best-effort: a
  `failed` entry refuses the removal entry (`RecordRemintFailedError`, naming
  the records it could not reach), the client stays enrolled, and the re-run
  resumes at the re-mint; (6) the `onBeforeRemoval` seam (required), where the
  caller re-signs the LOGIN credential's bridge and `delegatedClients` sibling
  with the ladder VM and re-seals its record with the credential in hand (the
  removed client's signatures rot at the next entry). Stage 5 skips that
  credential, so the seam is the only thing that ever re-signs the login
  credential's own bridge; a call without it is refused before any read, since
  the removal entry would otherwise leave an account nothing can write to; (7)
  the **removal entry** (`forgetLastWebvhClient`), the plain forget's removal
  shape with the guard inverted -- it requires the installed ladder VM instead
  of refusing the last client. Every stage detects completion from durable
  state, so a run torn before the removal entry converges on re-run; torn after
  it is the finish-the-wipe state the app's next login maps. A reader settling a
  ladder-signed record's mixed-signer proof uses `currentAccountRecordSigners`
  (`clients/listing.ts`): the enrolled clients' key set widened by the
  document's ladder VMs, which the enrolled-client set alone would refuse on a
  client-less account. One residue is the transition's own: an account running
  it while N standing credentials stand lands client-less carrying N standing
  ladder VMs, none of them retirable, since a retirement needs an enrolled
  client. Credential rotation stays the remedy for a leaked credential wherever
  it is reachable, and it is reachable on exactly the accounts where a VM is
  newly standing, since those have an enrolled client by construction. A
  client-less account can add no credential either, so N stays 1 on the other
  two producers of that state. One residue from review stays open: a ladder VM
  reinstalled by the transition can go unattributed seedlessly once the anchor
  advances past the acting rung (WC-158). The pair's second ceremony-tail
  license shot was the other, ruled on and accepted (see "The ceremony-tail
  license").
- **Recovery** (`recovery/`): a code is a standing credential that retires on
  spend, and its inventory is deliberately split -- **decryption and delegation
  stand** (its `keyAgreement` verification method is in the document, unmarked,
  its ladder VM stands under `assertionMethod` and `capabilityDelegation`, and
  its user-key wrap stands in the roster, all maintained for free by rotation
  fan-out) while **update authority stays latent** (rung 0 joins `updateKeys`
  nowhere; only its hash is committed, and the one bridge is a pre-minted
  PUT-on-`did.jsonl` delegation carried in the code's unlock record and signed
  by the code's OWN ladder VM). Any use of a code must first extend the
  world-readable log -- recovery is loud by construction. On the ladder branch
  the issuance splits its entry so the code's decryption material precedes its
  authority: a key entry carrying the `keyAgreement` member, then the escrow
  append, then an authority entry carrying the ladder VM and the rung-0 hash
  (`part`, `decisions/0018`). A tear before the authority entry leaves a dead
  code -- one that can neither spend nor sign -- rather than one that can spend
  and cannot decrypt, which the spend's own unwrap through the code's wrap would
  turn into account destruction. The enrolled branch escrows first and writes
  the merged entry. Spending a code is a two-entry self-enrolling continuation:
  **reveal-and-commit** (the pre-committed key reveals itself, commits the new
  client's and replacement code's hashes), then **add-and-retire** (new client
  fully in; the spent code's method, key, and hash out; the replacement code's
  inventory in), followed by mandatory user-key rotation off the spent code. The
  replacement's inventory is its whole inventory: its verbatim `keyAgreement`
  member AND its ladder VM, under `assertionMethod` and `capabilityDelegation`,
  beside the rung-0 hash the reveal entry committed. A replacement published
  without the VM could never spend, since the bridge delegation its record
  carries is signed by that VM (`decisions/0019`, `decisions/0020`). The
  transient continuation therefore publishes TWO ladder VMs in one entry, the
  fresh credential's and the replacement's, and nothing in the log pairs either
  with either credential -- a VM key and a rung key are independent expansions
  of a seed. The seedless walk claims neither, so the fresh credential's VM is
  named by its own ladder seed, which every retirement that can reach the seed
  holds; a seedless retirement of it refuses on the retirement gate instead of
  striking a VM it cannot tell from the code's. Both variants retire every
  PRE-RECOVERY standing credential outright in that same entry: its ladder VM
  and its `keyAgreement` member leave the document, and so does its whole
  update-key inventory -- the rung hashes it has standing in `nextKeyHashes`,
  plus any rung of its own left revealed in `updateKeys`
  (`attributeRetiredCredentialRungs`, `decisions/0014`). Striking the VM alone
  would rot only a LADDER-signed bridge. A bridge an enrolled client minted
  outlives the strike, and that client survives the entry, so a committed rung
  left standing would let a retired credential reveal it and republish its own
  inventory. Each credential is anchored from the log alone, since a cold
  browser can read no registry before the entry is written: the entry that first
  introduced the credential's `keyAgreement` member is its bind entry, and
  either the one key that entry revealed and signed with or the one hash it
  newly committed names rung 0 (`credentialLadderAnchor`). The walk runs from
  there. An entry that introduces more than one credential-class member, or that
  introduces an enrolled client, names no anchor, and neither does a key the log
  attributes to a listed client. Beside the anchor guards a structural one
  stands: every surviving enrolled client's active update key, its carry-over
  hash and its staged hash are protected whatever the walk claimed
  (`survivingClientKeyProtection`), so a mis-anchored walk can never end a
  client's ability to extend the account log. The credential walks run first and
  vouch for their own claims there, so a retiring rung cannot be protected as a
  client's staged hash; and a listed client whose active update key the log
  cannot attribute withholds the whole strike, since nothing of that client
  could be protected. A credential is reported on the outcome's
  `unclaimedCredentialVmIds` when no anchor or walk claims it, when it claims
  nothing, and when any single claim of its was withheld -- a partial retirement
  is reported rather than read as a whole one. Over-striking is silent and
  unhealable, under-striking is visible and re-runnable, so the bias is
  under-striking throughout. What was struck comes back on `struckRungHashes`,
  and the entry refuses to publish an empty `nextKeyHashes`
  (`NextKeyHashesEmptyError`), which would switch prerotation off. A resumed run
  re-runs that whole computation over the log as it stood just before the entry,
  located by the key the entry authorized, so both paths share one definition of
  what was struck and what was left. Two residues are accepted. A client-signed
  bridge delegation is not revoked, only made inert, since the transient variant
  holds no revoker authority and a bridge whose rung no longer stands committed
  can extend nothing. And the credentials an earlier recovery's own
  add-and-retire entry introduced cannot be anchored, so a second recovery
  leaves their rungs -- for a transient recovery's fresh credential that
  includes a rung 0 standing authorized in `updateKeys`, inert because its
  ladder VM is struck. WC-159 owns that gap. The roster side has no direct
  mapping from that: `retiredCredentialVmIds` are `keyAgreement`
  verification-method ids (a passphrase's fragment is a commitment, not a roster
  kid), so they cannot name roster recipients directly.
  `rosterRecipientsToRetire` (`keys/`) works by subtraction instead: the current
  epoch's kids minus the ones the caller names to keep, and the rotation's own
  document-backed resolver drops the rest regardless. A code is spent because
  the other credentials are lost or suspect, so half-retiring one would leave a
  credential that looks alive in the document and can reach nothing. The cost
  belongs in the app's recovery copy: a passkey that survived the loss is
  retired too and must be re-added. Between the two entries sits a required
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
  advancing as each entry publishes -- the transient continuation's
  `recoverWebvhLadderAnchored` takes the same optional pair over its own two
  entry builds. The delegation is a wire artifact both apps must mint
  byte-identically, so its builder (`delegateLogWrite`: PUT on the one
  `did.jsonl` resource, one-year TTL per NIST SP 800-57 cryptoperiod guidance)
  lives here rather than app-side -- and so does the **delegation re-mint** the
  revocation cascade runs (`remintRecoveryDelegations`): revoking a client
  kills, by the current-key-set rule, every recovery delegation that client
  signed, and a standing delegation eventually reaches its own expiry, so for
  each registry entry whose recorded delegation is stale under the house policy
  (`recordedZcapStale`, the scalar shape of the same predicate: no longer
  chaining under `delegationKeyInDocument`, expired or inside the renewal
  window, or signed by a key the caller names as retiring), the acting client
  signs a fresh delegation to the code's signing DID, re-wraps the record to the
  code's unlock KAK public half with the code-authenticated `binding` carried
  forward verbatim, re-PUTs it through the entry's management zcap, and hands
  the entry back with the fresh `delegationKeyId` and `delegationExpires`. The
  skip policy (pre-re-mint entries, unreadable or binding-less records) is
  decided here once and every entry's fate is reported (`RecordRemintOutcome`:
  current, reminted, incomplete-entry, failed), so a record the pass could not
  reach is named rather than silently left; the app injects the seams (the
  management-zcap client factory, the storage URL, the registry read/record
  halves) and keeps its login-time health check as the backstop for skipped
  entries and for expiry between revocations. The last-client forget runs the
  same pass with the ladder VM as signer and the forgotten client named as
  retiring (`retiringKeyMultibases`), since the document it checks against still
  lists that client until the removal entry lands.

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
- **The three wire signals are classified by `err.name`.** The refusal classes'
  rule (above) covers this module too, for the same reason and with the same
  stakes. `WasSyncConflictError` and `WasSyncNotFoundError` are raised inside
  the app's injected `WasSyncPort`, `UnknownEpochError` inside its `DocCipher`,
  and either seam can resolve to a second copy of `@interop/was-client` -- a
  `link:` dev setup, or a dedupe miss through a dependency tree. An `instanceof`
  miss is silent and expensive here: every push `412` becomes a fatal cycle
  error, and `remintPendingEnvelopes` rethrows instead of re-minting, which
  would push permanently unroutable envelopes onto a shared content-addressed
  feed. So `sync/types.ts` exports `isSyncConflictError` / `isSyncNotFoundError`
  / `isUnknownEpochError` beside the re-exported classes, `push.ts` and
  `remint.ts` dispatch through them, and both apps match the same way rather
  than each writing the `instanceof`.
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
factory. The same seam has a read-side classification of what the cipher itself
throws. A decrypt that finds no key fails in two distinguishable ways, and a
host scanning rows must tell them apart: `UnknownEpochError` (the envelope's
epoch is not on the descriptor this reader holds, so a re-read may fix it) and
`KeyUnwrapError` (the epoch IS listed, but this reader was never a recipient, or
was removed and the epoch rotated). Neither row is garbage. Both are matched on
`err.name` under the rule the sync signals follow, since the cipher is an
injected seam: `isKeyUnwrapError` (`descriptors/errors.ts`, import-free like
`resourceLog/errors.ts`) and its sibling `isUnknownEpochError`, which ships from
`sync` because the create-loss re-mint dispatches on it and `sync` imports
nothing else in this library. The stakes are why the pair exists rather than an
`instanceof` per site: a scan that misses `KeyUnwrapError` drops a real,
permanently-unreadable row into its undecryptable bucket, which a host is
entitled to purge. The one `instanceof` left is inside
`createRefreshingEdvDocCipher`, where the cipher being classified is built in
that same file from that same import, so no seam is crossed.

`acquireDescriptor` treats the log refusal classes as security signals, not
outages: `ResourceLogIntegrityError` and `ResourceLogContinuityError` rethrow
past a warm cache (matched on `err.name`, keeping the file dependency-light),
EXCEPT a continuity `rollback` -- reconcilable divergence, possibly replication
lag, per the spec's `#log-pin` rules -- which falls back to the cache like any
transport hiccup: nothing rolled-back is adopted and the pin never regresses.
The refresh-guard policy and the cipher are untouched; a governed collection
simply plugs this source into them.

## Delegation-proof signing

Every zcap this library delegates -- App Connect app grants, share grants, the
client annex generation delegation, the bridge delegations inside unlock and
recovery records -- is signed with `eddsa-jcs-2022` (`EddsaJcs2022` from
`@interop/ed25519-signature/eddsa-jcs-2022`). JCS canonicalization is plain
JSON, so minting a grant runs no JSON-LD canonicalization and needs no document
loader at signing time; the log entries and the HTTP-signature invocations
already canonicalize the same way, so one story covers the whole authorization
path. The suite is hard-coded rather than threaded as a caller option: every
signing wrapper builds its client internally, and a wrong setting would surface
only as an interop failure at the server. It is hard-coded once:
`identity/agents.ts`'s `zcapClientForSigner({ signer })` is the library's one
`ZcapClient` construction site, and the wrappers that sign under a different key
id (`webvh/zcap.ts`'s two, `clientAnnex/zcap.ts`'s ladder VM) build the signer
and hand it there, so a new wrapper inherits the setting instead of restating
it.

Two consequences the callers own. The storage server must verify both suites,
and it ships first: `eddsa-jcs-2022` before any client emits it, and
`Ed25519Signature2020` because grants minted before the switch stay recorded on
Login activities and are re-verified whenever an app or agent is revoked. And a
client that RE-delegates one of these grants must be on this suite too: an
`Ed25519Signature2020` client cannot re-delegate a JCS-signed parent on its
default loader, because URDNA2015 expands the parent embedded in
`proof.capabilityChain` and no such loader serves the data-integrity context.
That failure is at signing time on the re-delegating client, so a server
verifying both suites does not cover it. The VP and credential paths are a
separate axis and keep their own negotiation (`request/presentationSuite.ts`).

## Permanent wire-level constants

Byte-for-byte identical strings both replicas depend on. **None of these can
ever change** -- each is baked into every existing account's derivations or
stored artifacts:

| Constant                                     | Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Why permanent                                                                                                                                                                                |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BOOTSTRAP_HANDLE` / `BOOTSTRAP_KEY_NAME`    | `'bootstrap'` / `'boostrap-key'`                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | every data identity derives through them; the typo in `boostrap-key` is load-bearing and can never be fixed                                                                                  |
| `KEYRING_KDF`                                | PBKDF2, 600k iterations, SHA-256, salt `freewallet/keyring/unlock/v1`                                                                                                                                                                                                                                                                                                                                                                                                                                   | every account's unlock identity                                                                                                                                                              |
| `RECOVERY_KDF`                               | HKDF, SHA-256, salt `freewallet/keyring/recovery-code/v1`, info `freewallet/unlock-seed`                                                                                                                                                                                                                                                                                                                                                                                                                | every issued recovery code; a changed salt orphans them all                                                                                                                                  |
| `RECOVERY_CLIENT_SALT`                       | `freewallet/recovery/client-keys/v1` (infos `client-seed` / `ladder-seed`; the retired `update-key` info is never reused)                                                                                                                                                                                                                                                                                                                                                                               | every issued recovery code's client identity and update-key ladder                                                                                                                           |
| `STANDING_CLIENT_SALT`                       | `freewallet/unlock/standing-client/v1` (infos `client-seed` / `binding-mac`)                                                                                                                                                                                                                                                                                                                                                                                                                            | every standing credential's client identity and binding MAC key                                                                                                                              |
| The ladder derivation                        | HKDF salt `freewallet/unlock/update-ladder/v1`, infos `rung/<index>` (account rungs), `vm` (the stable sibling VM key), and `<segment>/rung/0` (a client-annex generation's static rung 0)                                                                                                                                                                                                                                                                                                              | both wallets must climb the same ladder from the same seed; the three info families stay disjoint under the one salt                                                                         |
| The generation segment                       | `gen-` + 12 random bytes base64url no-pad (20 characters); it embeds in every annex DID string and is the HKDF label's generation half                                                                                                                                                                                                                                                                                                                                                                  | orphan discovery is a prefix match, and a reused segment would re-derive a prior generation's rung-0 key                                                                                     |
| The delegated-clients service entry          | `type` `https://w3id.org/byoe#DelegatedClients` (readers dispatch on the type IRI, never the fragment), `serviceEndpoint` = the annex DID string; the wallet mints the fragment `#delegated-clients`, non-semantic and preserved on re-point                                                                                                                                                                                                                                                            | the account document's pointer at the current annex generation; the server's inspector clause reads it                                                                                       |
| The generation delegation                    | `invocationTarget` = the account Space items subtree (Space URL + trailing slash), `allowedAction` `['GET','HEAD','POST','PUT','DELETE']`, `controller` = the bare annex DID string, `expires` 365 days, rooted in the account Space's root zcap; embedded in the annex document as `type` `https://w3id.org/byoe#GenerationDelegation`, `serviceEndpoint` = the delegated-zcap map verbatim, fragment `#generation-delegation` (non-semantic), installed with the first transient VM, never at genesis | the standing authority every transient visit invokes under and every visit-scoped App Connect grant chains through (depth 3: root id string, the embedded delegation)                        |
| The single-verb Space capability             | `allowedAction` exactly `['DELETE']` or exactly `['GET']`, `invocationTarget` a bare Space URL (the stored parent's own bytes on the three-link shape, `spacePath` + `toUrl` on the two-link shape rooted in the Space's synthesized root), `expires` = `min(now + DELETION_ZCAP_TTL_MS, parent.expires)` with the TTL at ten minutes, `controller` the caller's delegatee; never stored                                                                                                                | a storage server admits it by that exact shape, so the target and the one-verb action set are the wire contract; the short life is what makes revocation moot on a torn run                  |
| The transient annex VM                       | `type` `Multikey`, `controller` = the annex DID, id `<annexDid>#<publicKeyMultibase>`; published under `capabilityInvocation` AND `capabilityDelegation` and under no other relation (decision 0013)                                                                                                                                                                                                                                                                                                    | the visit key invokes the generation delegation and delegates the visit's grants onward; the two-relation shape is also what keeps it out of the ladder-VM asymmetry every reader recognizes |
| The unlock binding context                   | `freewallet/unlock/binding/v2`                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | every bound credential's account-binding MAC                                                                                                                                                 |
| `MultikeyCommitment` / `publicKeyCommitment` | VM type + property; the value is the bare sha2-256 multihash of the key's decoded multikey bytes, base64url no-pad                                                                                                                                                                                                                                                                                                                                                                                      | the document convention for a low-entropy-derived key-agreement key                                                                                                                          |
| `BYOE_CONTEXT_URL`                           | `https://w3id.org/byoe/v1`, in every account document's `@context`                                                                                                                                                                                                                                                                                                                                                                                                                                      | it defines the two commitment terms                                                                                                                                                          |
| `CONNECT_CODE_PREFIX`                        | `freewallet-connect:`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | the one spelling of the connect-code grammar                                                                                                                                                 |
| Collection / resource names                  | see the Space layout tables above                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | the Space layout contract                                                                                                                                                                    |
| `WalletActivity` `type` / `summary` strings  | `space/activity.ts`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | byte-significant across replicas                                                                                                                                                             |
| `KEYRING_RECORD_VERSION`                     | `2`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | the stored record envelope                                                                                                                                                                   |

Every unlock method's KDF carries a distinct salt so two methods can never
derive the same unlock identity.

## What lives elsewhere (do not reimplement here)

- **`@interop/vh-resource-log`** -- the Resource Log Profile's generic client
  side: the JSON Lines codec, the `ResourceLogStore` port and `confirmAppend`,
  `verifyResourceLog` with the `admitAppend` admission-hook seam on the
  controller port, the keyed chain-head pin store, the append/create path, and
  the sealing sweep. `resourceLog/` keeps only the did:webvh controller adapter,
  the ceremony-tail license the hook carries, the shared account-document reader
  leaf both are built on (`document.ts`, surfaced through `webvh`), and the
  shared read-side classification of the library's refusal taxonomy
  (`isResourceLogRefusal`). Test fixtures come from its `./testing` subpath,
  restricted to test globs by the lint pass.
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
  and a client is not tied to hardware. A client is a cache rather than an
  account's state. What persists is the unlock credential, the account log, and
  the server-held roster and records; an **enrolled client** (one published in
  the account document, keyed on `capabilityInvocation`) is an optimization over
  those, saving a self-enrollment. Contrast the **transient client**, a
  per-visit key recorded in a client annex generation. Avoid: device, device id,
  durable client, permanent client.
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
- **Durable** -- persisted server-side on the WAS host: the account log, the
  annex log, the user key roster, the unlock records, the Collection
  Descriptions and their key epochs. Durable state survives a cleared client and
  a lost machine, which is why a ceremony stage may detect its own completion
  from it. The word names this tier alone, and neither a client, a session, nor
  a login is ever called durable (freewallet's `decisions/0011`). Avoid: durable
  client, durable session, durable login.
- **Client-local** -- persisted by the client itself: a browser's IndexedDB and
  localStorage, a mobile app's keychain and tables. The client key record, the
  keyring cache, the descriptor caches, the caller-persisted update-key seeds,
  the replica database. Semi-durable -- it survives a restart but not an
  eviction, a cleared profile, or a lost machine -- so it is a cache of what the
  host holds. Freewallet's browser-local is this tier's app-side name. Avoid:
  durable local state, disk, persistent storage.
- **In-memory** -- held in process memory and gone when the tab or app closes: a
  transient visit's whole store family, unlocked key material, the pin stores a
  caller chooses to keep in memory. The third storage tier.
- **Remembered** -- of a client's local state, of a login, and of the session a
  login builds: a client holding a client key record for an unlock credential is
  a **remembered** one, so a login on it proceeds as (or self-enrolls into) an
  enrolled client. The default on a **non-remembered** client is the transient
  login. Remembering is a deliberate opt-in, undone by the forget ceremony and
  lost with a cleared profile: it is client-local state, not a property of the
  account. A background pass that only a remembered login runs is a
  **remembered-login sweep** wherever it is offered as a mender. Avoid: durable
  login, durable session, trusted client, persistent login.
- **Inventory** -- a credential's or client's set of durable entries in the
  account document, the annex log, or the ladder: its `keyAgreement` entry or
  commitment, its ladder VMs, and its committed rung hashes. Ceremonies install
  it; retirement sweeps it out. The ceremony-tail license's predicate compares
  it per document version (an entry is inventory-changing iff the set differs
  from the previous version's, `ResourceLogController.inventoryAt`). A named
  arrangement of an inventory is a qualified "configuration" phrase (the split
  configuration, the carry-over configuration), never bare. Avoid: posture,
  inventory.
- **Ceremony** -- an ordered sequence of writes across the account's systems
  (the account log, the roster, the unlock records, collection epochs) and the
  caller's own storage, whose stage order carries an invariant --
  persist-before-publish, document-edit-first,
  decryption-material-before-authorization. Every stage detects its own
  completion from durable state, and every tear point has a stated mender (see
  Tear mending). Every write before a ceremony's pivot names the storage tier it
  lands in: a client-local pre-pivot write owes an answer for a cleared or
  evicted client, not only for a crash. The other side of the pivot is
  `decisions/0010`'s derivability rule. The shared stage orders are canonical in
  "Ceremonies and cascades" above; the consumer apps list their wrappers and
  app-only ceremonies in their own ceremony inventories. Avoid: flow, workflow,
  wizard.
- **Tear mending** -- the umbrella for how a ceremony interrupted mid-run (a
  torn ceremony) gets finished. Three menders exist: a converging re-run (the
  same ceremony retried; every stage detects its own completion), a standing
  sweep (a remembered-login pass, e.g. the cascade-completion sweep in
  `clients/rosterPolicy.ts`), and a repair (below). A stated residue with no
  mender is an open gap, not a documented limitation. Avoid: tear closure.
- **Repair** -- the mender of last resort: code waiting at the one entry point
  where the authority a specific torn state needs reassembles, detecting that
  state from durable state alone and finishing the ceremony -- used exactly
  where neither a re-run nor a remembered-login sweep can fire (the recurring
  case is a client-less account, where no remembered login ever runs a sweep).
  Always qualified by its torn state -- freewallet's torn-retirement repair
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
