# Architecture

The codebase map for `@interop/wallet-core`: what the library is, the module
layers and their dependency direction, a short overview per area, the key
hierarchy, the ceremony inventory, the permanent wire-level constants, where
neighboring logic lives, and the Glossary. Each area's full account (every
ceremony's stage order, refusals, tear points, and menders) lives in one topic
doc under `docs/architecture/` (see "Topic docs"). For toolchain rules (pnpm,
build, tsconfigs, tests) see [AGENTS.md](AGENTS.md); for code conventions see
[CONTRIBUTING.md](CONTRIBUTING.md). The [README](README.md) carries a
one-paragraph blurb per subpath plus install/usage; this document goes deeper
(dependency direction, flows, invariants) rather than restating those blurbs.

## What this library is

`@interop/wallet-core` is the shared, correctness-critical wallet logic two
WAS-enabled wallet apps hold in common:

- **DCW** -- the React Native mobile wallet (SQLite-backed), and
- **freewallet** -- the browser wallet (RxDB/IndexedDB-backed).

Each app's own ARCHITECTURE.md (`../dcw`, `../freewallet`) covers the app-side
half.

The two apps are replicas of the same account. They must derive the same
identity from the same secret, lay out the same Space, produce byte-identical
wire artifacts, and converge when both write. The selection rule for what lives
here is therefore **cross-replica agreement**: code where a drift between the
apps corrupts an account or splits a sync feed. Code that only needs to be
correct within one app stays app-side.

Two properties hold everywhere in `src/`:

- **Isomorphic, no I/O of its own.** Runs in browser, Node.js, and React Native.
  Nothing here owns storage or UI. Network access goes through injected seams (a
  `WasSyncPort`, a was-client handle, a `FetchLike`), and the pervasive pattern
  is injected side effects, down to `schedule` / `random` / `backoff`.
- **Pure derivation out, formatting and consent in the caller.** The VC display
  derivation follows this rule and lives in `@interop/vc-display`. The request
  pipeline lives in `@interop/wallet-request`, where consent and the response
  channel stay with the app the same way.

## Module map and dependency direction

Modules by layer; a module may import from lower layers only. There are no
cycles between modules. One file-level cycle stands inside the pinned annex
exception: `clientAnnex/ladder.ts` takes the surviving-client protection from
`webvh/revokeClient.ts`, which takes the standing-credential walk from it.
Neither touches the other at module evaluation.

```
layer 0 (no internal deps):  sync   space   resourceLog
                             (resourceLog sits over the external
                             @interop/vh-resource-log, the profile's
                             generic client side)
layer 1:                     webvh (space, resourceLog)
                             keyring (space)
                             descriptors (resourceLog, space)
layer 2:                     keys (webvh, space, resourceLog)
layer 3:                     enrollment (webvh, keys, keyring, resourceLog)
                             unlock (webvh, keys, keyring, resourceLog,
                             clientAnnex/ladder -- a pinned exception, see
                             below)
                             genesis (webvh, keys, space, resourceLog)
layer 4:                     recovery (unlock, webvh, keyring, space,
                             clientAnnex/ladder -- the second pinned
                             exception)
                             clients (webvh, keys, resourceLog)
top:                         clientAnnex (may import any base subpath;
                             nothing in the base imports from it)
top-level leaves:            src/log.ts, src/stages.ts (import-free; any
                             layer may take a name from either)
                             menders (imports nothing internal; a wallet's
                             registry over its own table, read by no other
                             module)
root barrel:                 src/index.ts re-exports sync + space, nothing else
```

| Subpath       | Role                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Internal deps                                                            |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `sync`        | WAS replication engine core: `SyncEngine`, `runPull` / `runPush`, the `SyncStore` replica seam, contacts LWW conflict resolution                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | --                                                                       |
| `space`       | Wallet Space layout contract: collection ids/specs, `wallet-activity` wire shape and builders, `publicCredentialUrl`, the `was-link` QR payload, the capability-authorized Space DELETE                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | --                                                                       |
| `descriptors` | The log-governed descriptor source: the wallet's implementation of was-client's `EncryptionDescriptorSource` seam over a collection's governing resource log, and the pin-slot name each collection's log pins under                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | resourceLog, space                                                       |
| `resourceLog` | The wallet-domain residue of the Resource Log Profile client side (the generic half -- verifier, handover check, keyed chain-head pin store, entry builders, read/append/create path, sealing sweep -- lives in `@interop/vh-resource-log`): the import-free account-document reader leaf (`document.ts` -- relation resolution, ladder-VM recognition, the credential class -- whose public home is `webvh`), the ceremony-tail license on ladder-signed appends and the log-class dispatch that says which log it binds (`ResourceLogClass` / `controllerForLogClass`), the re-export of the library's rollback carve-out every reader shares (`isResourceLogRefusal`), and the inventory-aware `WebvhResourceLogController` extension of the library's controller port with its did:webvh adapter, supplying the library's `admitAppend` admission hook | --                                                                       |
| `webvh`       | The account's did:webvh log: provisioning, per-client update-key rotation, enrollment/revocation entries, client listing (`ladderVmIds` recognition included), the public home of the shared account-document readers, log verification, the WAS-backed and delegated log stores, zcap signing under the webvh keyId, the standing-zcap staleness policy (`standingZcap.ts`, which `recovery` re-exports)                                                                                                                                                                                                                                                                                                                                                                                                                                                  | space, resourceLog                                                       |
| `keyring`     | The unlock layer: unlock KDF, the keyring record codec, the unlock Space lifecycle                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | space                                                                    |
| `keys`        | The user key, its wrap-set roster (log-governed, sealable), the per-collection encryption descriptor logs' store builder, the rotation cascade's per-collection op, the provision-time collection epoch install, the client-key record codec, client display labels                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | webvh, space, resourceLog, descriptors (leaf)                            |
| `enrollment`  | The client enrollment ceremony: connect code, approval, completion, the onboarding-response envelope                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | webvh, keys, keyring, resourceLog                                        |
| `unlock`      | Standing unlock credentials: the credential-derived client identity, the unlock record codec (shell / bridge / ladder / binding, `LADDER_SEED_BYTES` included -- the record format owns its member sizes), the merged document-inventory edit (verbatim key or hash commitment), the retirement ceremony                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | webvh, keys, keyring, resourceLog, clientAnnex/ladder (pinned exception) |
| `recovery`    | Recovery codes as standing unlock credentials that retire on spend, over the `unlock` machinery (the code's key set and its ladder derived from the code bytes, the remembered recovery continuation); the pre-minted `did.jsonl` delegation builder                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | unlock, webvh, keyring, space, clientAnnex/ladder (pinned exception)     |
| `genesis`     | The account-genesis ceremony: the new-account key set mint and the staged provisioning of a fresh account (Space layout, the optional KMS authentication binding, did:webvh genesis, roster genesis, epoch[0] install, controller promotion)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | webvh, keys, space, resourceLog                                          |
| `clients`     | Enrolled-client management: listing, disconnect-eligibility policy, the revocation cascade orchestrator, the login-time roster policy                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | webvh, keys, resourceLog                                                 |
| `clientAnnex` | The client annex -- the authoring and maintenance surface of everything ladder-anchored: the ladder (rung/VM derivation and the shared attribution walks), the annex log and its GC, ladder-VM zcap signing, the ladder-anchored account-log ceremonies (genesis, self-enrollment, forget), the credential-anchored account genesis, the transient-recovery continuation, the single-verb Space capability mints and the capability-authorized Space delete                                                                                                                                                                                                                                                                                                                                                                                                | every base subpath it needs                                              |
| `menders`     | The mender registry keyed by invariant: the declaration and registration types, the closed vocabularies, the invariant-id census, the `menderRegistry` readers, the derived-set helpers a wallet's audit tests pin, and the runner (`runMenderBlock`, `mendReportAccumulator`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | --                                                                       |

`sync`, `clients`, and `genesis` are never imported by another `src/` module;
`sync` and `space` are the only modules the root barrel re-exports.

**The mender runner's discipline.** `runMenderBlock` (`menders/runner.ts`) is
the one try, warn, and skip discipline over a login chain. It runs the
registrations `dueAt` one chain trigger in list order, admitting each only when
the session holds every reported invariant's declared authority and every
reported declaration's `when(route)` predicate admits this login route. An
optional seed registration runs first, and its failure aborts the block: nothing
behind it runs. Past the seed, a registration that throws warns once per
reported invariant with that declaration's own `warn` string, through the
`Logger` the wallet supplies for the block, and the block continues; the report
carries `err.name` alone, since a thrown message can name a DID or a Space id.
`onOutcome` is the single place an entry is reported, so a wallet's mend report
and a later event channel read the same values. A `ceremony-tail` entry has no
registration, so nothing here can fire one outside its ceremony's own order.

**The client-annex boundary.** `clientAnnex` sits on top: it may import from any
base subpath, and nothing in the base imports from it. A `no-restricted-imports`
block in the lint pass (part of `pnpm test`/CI) enforces it, so a new
base-to-annex edge is a build failure. Five files are pinned exceptions, each
importing `clientAnnex/ladder.js` and nothing else from the annex:
`unlock/standingWebvh.ts`, `recovery/continuation.ts`, `webvh/accountEntry.ts`,
`recovery/recoveryCode.ts`, and `webvh/revokeClient.ts`. All five depend on the
shared derivation and attribution helpers, not on the annex log machinery.

The base keeps the verify-side and wire-format halves every wallet needs
whatever its account configuration: the resource-log ladder-append license and
the `ControllerInventory` ladder-key computation, both over the shared
`ladderVmIds` recognition in `resourceLog/document.ts` (`webvh` is that reader's
public home); the unlock-record codec with its `ladder` and `delegatedClients`
members (`unlock`); `webvh/standingZcap.ts`; the generalized `wasWebvhLogStore`
/ `delegatedWebvhLogStore` seams; and the `GenerationCollect` activity builder
(`space`). The delegated store's read mode -- an unauthenticated fetch or an
invocation of the same delegation -- is read off the wallet Space roster's
`isPublic`, so no caller chooses it. `ladderVerificationMethod` and
`createLadderAnchoredWebvhLog` stay defined in `webvh/didWebvh.ts` and are
surfaced by the `./clientAnnex` barrel, since the genesis document builder's
two-armed clientKeys XOR ladderVm signature is base API and moving them would
re-open a base-to-annex edge. The base orchestrators keep declaring their
closure-result types (`GenerationDelegationRemint` in `clients/revocation.ts`,
`ClientAnnexInventoryRetirement` in `unlock/retire.ts`), and the annex supplies
implementations through injected closures. The subpath's reading list is
`decisions/0002`, `0003`, `0005`, `0006`, and `0007`.

## Subpath isolation

The root export re-exports only `sync` + `space`, so plaintext consumers of the
root never pull the signing / KMS / document-loader dependency graph. Every
other subpath is **import-directly-only**. Each module has a four-key entry
(`types` / `react-native` / `import` / `default`) in the `package.json`
`exports` map -- a new module means a new entry there.

Two extra **leaf subpaths** exist for dependency isolation and must stay
dependency-light:

- `./keys/clientKeyRecord` -- the client-key record codec alone, importing only
  a base64url codec (its key types are type-only imports, erased at compile
  time), so a wallet's storage tests load without the crypto/EDV graph.

The same trick serves a cross-package hand-off. `enrollment/connectCode.ts`
holds only the connect-code prefix and predicate, so a wallet can hand it to
`@interop/wallet-request`'s input classifier as a recognizer, beside
`space/wasLink.ts`'s `isWasLinkPayload`, without either wallet-core module
pulling in the classifier's own dependency graph. `webvh/did.ts` holds only the
did:webvh shape check, so wallet-core's own internal consumers can validate an
account DID without the zcap signing graph (`webvh/zcap.ts` re-exports it and
remains its public home).

## The wallet Space layout (`space`)

A Space is a WAS container, addressed as
`https://<host>/space/<spaceId>/<collection>/<resource>`. An account has two: a
data Space for credentials, activity, identity and key-map, and a minimal unlock
Space holding one keyring resource. `space/collections.ts` is the layout
contract for the four synced collections. Both replicas must lay them out
field-for-field identically, since a drift splits the feed and never converges.
The `shareable` column there is the share-surface allowlist, and the encrypted
sets still follow `encryption`. The contacts specs live in
`@interop/social-core` instead.

Every `wallet-activity` payload either app writes comes from a builder in
`space/activity.ts`. The apps never build an activity literal inline, since the
`type` strings and `summary` phrasings are byte-significant across replicas and
a literal is where they drift. A new event means a new builder here first, and
the app repoints to it. Events the did:webvh account log already records
(enrollment, self-enrollment, credential rotation, revocation, forget) get no
activity builder: the verified log is their history, and writing an activity per
visit would fill the feed on a default-transient login.

Provisioning is a two-step. `provisionWalletSpace` creates the collections
create-if-absent, and `ensureWalletSpaceEpochs` installs each encrypted
collection's key epoch[0]. An encrypted collection is created bare, with
`encryption: 'governed'`, so the epoch install is also its declaration and the
genesis of the collection's own governing history log. Three rules ride on that
order. Both steps run before a collection's first content push. Both adopt
rather than overwrite what an earlier provisioner landed, so a torn signup heals
by re-running. And the install's mint gate refuses the fan-out whole (`skipped`,
reported by both genesis ceremonies as `epochsSkipped`) unless the roster's
current epoch is the user key handed in. Content is re-provisioned rather than
migrated, and a re-run over a collection born with a client-written descriptor
is refused with was-client's `ValidationError`.

Every handle onto a system collection (`id`, `key-map`, `unlock-methods`,
`keyring`) is built by `plaintextCollection`. Without that override a Space that
does not exist yet 404s into an `EncryptionError`, and the EDV codec's own write
preconditions defeat the compare-and-swap guard the `did.jsonl` publish depends
on.

Full account:
[The wallet Space layout (`space`)](docs/architecture/space-layout.md).

## The key hierarchy

Top to bottom; each level's custody rule is load-bearing:

1. **Unlock secret** (passphrase or passkey PRF output) -- derives, via Argon2id
   (`keyring/kdf.ts`), the **unlock identity**: it addresses the unlock Space
   and holds the KAK the keyring record is wrapped to. It carries no authority
   over the account, and nothing about the account is derivable from it.
2. **Keyring record** (`keyring/record.ts`,
   `{ version: 2, encryption, wrapped, proof }`) -- the unlock Space's one
   resource: account controller, bind-time email, bind timestamp, and the
   **account pointer** `{ did, spaceId, host }`. Deliberately no key material of
   any kind. The envelope seals under the record's own one-epoch descriptor
   (`encryption`, epoch[0] wrapped to the unlock KAK), so the record stays
   self-contained under the everything-seals-to-an-epoch rule. The unlock KAK's
   public half is derivable from the unlock did:key the server stores as the
   Space's controller, so confidentiality alone would let a hostile host seal a
   substitute that decrypts perfectly. The `proof` (eddsa-jcs-2022 over the
   sibling members, by the unlock identity's Ed25519 key) is the authenticity
   layer, verified before any decryption. The recovery record shares the frame
   under a mixed-signer rule, which the reader marks pending for checking
   against the verified did:webvh document (`currentAccountRecordSigners`).
   Every record bound under `decisions/0019` is signed by its own credential's
   unlock identity key, so no ceremony writes a sibling record; the mixed-signer
   arm survives only for records bound before that rule.
3. **Data identity** (`@interop/was-client/identity`'s `agentsFromSecret` /
   `agentsFromSeed`) -- controller secret or 32-byte seed, expanded under the
   fixed `'bootstrap'` / `'boostrap-key'` handles to the did:key
   `CapabilityAgent`, `ZcapClient`, and X25519 vault KAK. Fully deterministic;
   both apps must derive it byte-for-byte identically.
4. **Client key record** (`keys/clientKeyRecord.ts`) -- the local record each
   wallet client keeps its own material in: the client's 32-byte seed (behind
   its Ed25519 signing key and X25519 twin), its did:webvh update-key seeds, the
   cached user key, and the account controller it was bound for. Only the codec
   lives here; where the record is stored and what wraps it stay app-side.
5. **User key** (`keys/userKey.ts`) -- the account-wide key that is **recipient
   zero** of every encrypted collection's key-epoch roster. Random,
   client-side-minted, never server-held, and not derivable from any passphrase
   or seed.
6. **The wrap-set roster** (`key-map/user-key.jsonl`, `keys/userKeyRoster.ts`)
   -- a `CollectionEncryption` descriptor stored verbatim whose current epoch IS
   the current user key, wrapped once per enrolled client to that client's own
   KAK. A delivery channel rather than a source of authority (see below).
7. **Recovery code** (`recovery/`) -- 16 bytes base58, from which a complete
   standing credential derives deterministically: its own unlock identity (under
   a distinct HKDF salt), a client key set, a binding MAC key, and an update-key
   ladder seed (info `ladder-seed`, the sibling of `client-seed` under the
   recovery client salt). Rung 0 of that ladder is the code's pre-committed
   did:webvh update key, and the ladder VM signs the code's own bridge
   delegation. The key material exists nowhere until the code is typed. The 16
   uniform bytes are what admit a code-derived ladder, where a
   passphrase-derived one would be an offline grind oracle against a revealed
   rung.

Two ordering invariants the apps must honor around the client key record
(unenforceable here; both are crash-durability rules):

- the user key and the roster epoch pin persist **atomically** -- one write or
  none. A failed persist must surface rather than degrade: the login policy's
  adoption callback (`checkUserKeyRosterAtLogin`'s `onRosterRead`) propagates a
  throw to the caller verbatim instead of treating it as the offline
  warn-and-carry-on class, since a session that silently proceeds on the retired
  cached key with the pin never advanced weakens the rollback guard on the next
  start;
- rolled update-key seeds persist **before** the log entry that publishes them
  (a tear after persist costs an unused staged key; a tear after publish strands
  a log this client can no longer extend).

## The did:webvh account log (`webvh`)

The account's stable id is a `did:webvh` whose hash-chained log is hosted as
`did.jsonl` in the world-readable `id` collection. The log is the single source
of truth, and a `did:web` projection is kept alongside it. That document is the
client roster. An enrolled client contributes its Ed25519 key under all four
relations plus its X25519 twin under `keyAgreement`, while a standing credential
contributes a `keyAgreement` key and a ladder VM under `assertionMethod` and
`capabilityDelegation`. Listings keyed on `capabilityInvocation` therefore
exclude credentials structurally.

Three rules carry most of the weight. The controller marker is the document's
one statement of which signing key a published key-agreement key belongs to.
`markedVerificationMethodPair` is the write site and
`resolvedKeyAgreementMethods` the read; a client with no marked method reports
an empty key-agreement set, and ambiguous log attribution yields a refusal
rather than a guess. The current-key-set rule says an invocation or delegation
verifies only while its method stands in the resolved document under the
relation its purpose needs, which is why client revocation is a single document
edit. And every ceremony publishes as a compare-and-swap on the ETag of the read
its entry was built on. The loser gets `WebvhLogConflictError` and re-runs
itself through `withLogConflictRetry`.

Reads run under a chain-head pin that refuses a rollback, a fork, or an SCID
switch with `ResourceLogContinuityError`. The pin is a property of the store
rather than a ceremony argument: `WebvhIdStore` carries it, and each constructor
derives the slot from the collection it serves. Callers meet `ensureDidWebvh`,
`verifyAccountLog`, `revokeWebvhClient`, `ensureDidWebProjection`, and the
`signAccountEntry` seam, whose client and ladder arms decide who signs an entry.

Full account:
[The did:webvh account log (`webvh`)](docs/architecture/did-webvh-account-log.md).

## The user key roster and the descriptor logs (`keys`, `descriptors`)

The user key roster is log-governed. Its resource is the resource log
`key-map/user-key.jsonl`, and `logGovernedDescriptorStore` exposes that log as
an ordinary `EncryptionDescriptorStore`, so was-client's roster machinery drives
it without knowing it. Reads resolve to the verified head state, and writes
become signed log appends. Every encrypted collection's `encryption` descriptor
is governed the same way, by a per-collection descriptor log at the collection's
`meta/log` sub-resource, built with `collectionDescriptorLogStore`.

Three layered guards stand against a tampering host: the verified log head with
its chain-head pin (`ResourceLogIntegrityError`, `ResourceLogContinuityError`),
the client-held epoch pin (`UserKeyRosterContinuityError`), and a recipient
resolver that takes keys from the locally verified did:webvh document rather
than from the roster. Every consumer dispatches on `err.name`, since these
errors are raised inside app-injected seams.

Two rules a change most often breaks. The sealing sweep: after a document edit
removes an `assertionMethod` key, every governed log needs an entry at or past
the post-edit version, so a cascade sets each store's minimum controller version
before that store's first append. And the ceremony-tail license, which admits a
ladder-signed roster append in exactly three shapes, two of them one-shot per
document version. `assertLadderAppendLicensed` enforces it pre-write and on
read-back, refusing with `ResourceLogLicenseError`. A per-collection descriptor
log carries the narrower rule instead, `assertionMethod` membership at the
anchored version, with no shape check and no one-shot.

On the read path `logGovernedDescriptorSource` is the wallet's
`EncryptionDescriptorSource`, re-verifying the log on every acquisition. A
decrypt that finds no key raises `UnknownEpochError` or `KeyUnwrapError`, and
the two mean different things to a scanner.

Full account:
[The user key roster and the descriptor logs (`keys`, `descriptors`)](docs/architecture/keys-and-descriptor-logs.md).

## Standing unlock credentials (`unlock`)

Every unlock method -- a passphrase, a passkey PRF output, a recovery code -- is
a standing credential: a `keyAgreement` entry in the account document, a
user-key wrap escrowed into every roster epoch and kept alive by rotation
fan-out, and latent self-enrollment authority. A fresh browser holding nothing
but the credential self-enrolls as an ordinary full client, with no second party
involved.

Three pieces carry the invariants. The update-key ladder derives by HKDF from a
random 32-byte ladder seed carried in the unlock record rather than from the
unlock secret, because a revealed rung lives verbatim in world-readable
`updateKeys` forever. The ladder VM is the stable sibling derived from that same
seed, listed under `assertionMethod` and `capabilityDelegation` only;
recognition is by that relation asymmetry, which keeps it out of every client
listing. The unlock record's `binding` HMAC covers controller, pointer, and
ladder seed, and is verified before the pointer is trusted.

The document inventory is one merged add/remove edit (`publishUnlockKey` /
`removeUnlockKey`). The ADD polarity takes the ladder seed from its caller
instead of minting one, so a converging re-run publishes nothing on a completed
stage. The REMOVE polarity treats the recorded update key as an anchor rather
than truth: it resolves the ladder's current inventory from the log and strikes
all of it in one entry, since a stale bind-time rung would leave a live rung
commitment standing as a latent re-seizure credential.

Self-enrollment (`selfEnrollWebvhClient`, composed by `selfEnrollClientCore`) is
two entries with a required `onCommitted` persist seam between them, at the
ceremony's pivot.

Callers meet `LadderAttributionError` on an ambiguous walk or a mismatched
rung-0 commitment, `UnclaimedLadderVmRetirementError` at the retirement gate,
`BuiltOnHeadNotReachedError` on an unreachable resume head, and a `TypeError`
when `onCommitted` is absent.

Full account:
[Standing unlock credentials (`unlock`)](docs/architecture/standing-unlock-credentials.md).

## Ceremonies and cascades

One principle underlies all of them: **every stage detects its own completion
from durable state alone** -- no checkpoint resources anywhere. Log entries are
idempotent. Roster staleness is "does the current epoch still wrap to a
recipient the document no longer keys". Collection staleness is "does its
current epoch name a non-current user-key generation". A governed log is
unsealed exactly when its head's controller version predates the controller's
latest assertion-key removal. Any torn cascade is resumable by a naive full
re-run, backstopped by the login-time completion sweep
(`clients/rosterPolicy.ts`: `checkUserKeyRosterAtLogin`, then the best-effort
`convergeUserKeyRosterToAccount` plus collection fan-out). Its per-collection
writes are signed appends carrying the post-edit controller view (see
"Per-collection descriptor logs"). The collection cascade is **rotation-only**:
epoch[0] comes from provisioning, and a descriptor met without epochs is refused
fail-closed rather than seeded. No construction anywhere installs a user-key
secret as a collection epoch secret, so a collection-epoch escrow can never hand
an external grantee the user key. A descriptor whose `currentEpoch` names no
epoch in its own list is refused the same way rather than evaluated against the
last epoch, descriptors being host-served and unauthenticated. That refusal
surfaces in the per-collection `failed` report instead of a `noop`.

Every ceremony also has a pivot: the first durable write after which it is
committed and can only be rolled forward. The pivot is almost always a
hash-chained log entry, and that entry is the ceremony's one commit record.
Every other write sits on one side of it. Before the pivot a write must stay
inert until the pivot lands: a pre-staged record, wrap, or delegation grants
nothing until the entry that licenses it verifies. After the pivot a write must
be re-derivable from the pivot entry plus durable state, so any authorized party
can finish the ceremony. Persist-before-publish is the special case of the first
half for key material. `decisions/0010-post-pivot-derivability-rule.md` states
the rule, and a ceremony's stage order is checked against it per write.

The inventory. Each ceremony's stage order, its pivot, its refusals, and its
tear states are canonical in the topic doc named in the last column. Every topic
doc states the ceremony's pivot write, which of its other writes sit on each
side of it, and the invariants a torn run can leave violated, by census number
(`INVARIANT_IDS`, `menders/ids.ts`); the entry point is the one function a
caller runs. Every row carries its `CeremonyId` from `CEREMONY_IDS`
(`space/ceremony.ts`), the code-only vocabulary a mender declaration uses to
name the ceremonies whose torn runs can violate it. The four menders own no
pivot and live in the registry subsection below instead.

| Ceremony                               | `CeremonyId`                  | Entry point                                                      | Module                    | Topic doc                                                                          |
| -------------------------------------- | ----------------------------- | ---------------------------------------------------------------- | ------------------------- | ---------------------------------------------------------------------------------- |
| Account genesis                        | `account-genesis`             | `ensureAccountGenesis` (after `mintAccountKeySet`)               | `genesis`                 | [account-genesis.md](docs/architecture/account-genesis.md)                         |
| Credential-anchored establishment      | `credential-anchored-genesis` | `establishCredentialAnchoredAccount`                             | `clientAnnex`             | [account-genesis.md](docs/architecture/account-genesis.md)                         |
| Enrollment (approve, complete)         | `client-enrollment`           | `approveEnrollment`, `completeEnrollmentCore`                    | `enrollment`              | [client-enrollment.md](docs/architecture/client-enrollment.md)                     |
| Self-enrollment                        | `self-enrollment`             | `selfEnrollWebvhClient` (`selfEnrollClientCore`)                 | `clientAnnex`             | [standing-unlock-credentials.md](docs/architecture/standing-unlock-credentials.md) |
| Update-key rotation                    | `update-key-rotation`         | `rotateWebvhUpdateKey`                                           | `webvh`                   | [did-webvh-account-log.md](docs/architecture/did-webvh-account-log.md)             |
| Client revocation                      | `client-revocation`           | `revokeAccountClient`                                            | `clients`                 | [client-revocation.md](docs/architecture/client-revocation.md)                     |
| Credential retirement                  | `unlock-credential-rotation`  | `retireUnlockCredential` (`preflightUnlockCredentialRetirement`) | `unlock`                  | [client-revocation.md](docs/architecture/client-revocation.md)                     |
| Forget                                 | `forget-client`               | `forgetEnrolledClient`                                           | `clientAnnex`             | [client-revocation.md](docs/architecture/client-revocation.md)                     |
| Last-client forget                     | `last-client-transition`      | `forgetLastEnrolledClient`                                       | `clientAnnex`             | [client-revocation.md](docs/architecture/client-revocation.md)                     |
| Recovery-code issuance                 | `recovery-code-issuance`      | `publishRecoveryKey` (after `recoveryClientFromCode`)            | `recovery`                | [recovery-codes.md](docs/architecture/recovery-codes.md)                           |
| Recovery spend (remembered, transient) | `recovery-code-spend`         | `recoverWebvhClient`, `recoverWebvhLadderAnchored`               | `recovery`, `clientAnnex` | [recovery-codes.md](docs/architecture/recovery-codes.md)                           |
| Recovery-code revocation               | `recovery-code-revocation`    | `removeRecoveryKey`                                              | `recovery`                | [recovery-codes.md](docs/architecture/recovery-codes.md)                           |

The account-log signer seam every ceremony body signs through
(`signAccountEntry`, the client and ladder arms) is described in
[did-webvh-account-log.md](docs/architecture/did-webvh-account-log.md).

### The mender registry (`menders`)

A mender is what finishes a torn ceremony or converges ordinary drift, and it
owns no pivot of its own: it detects one violated invariant from durable state
and makes the invariant hold again. The `menders` subpath is the registry that
describes the menders from the outside, keyed by invariant rather than by
ceremony or by login stage. Its unit is the invariant, a present-tense predicate
over the account's server-held state (for a few entries, over the client's local
state) that must hold between ceremonies. Each wallet declares its own table of
invariants against the shared `INVARIANT_IDS` census (`menders/ids.ts`, numbered
in the order the design table assigned them) and registers its own convergers;
wallet-core carries the structure, the vocabularies, the readers, and the
runner, and executes no ceremony itself.

Two closed vocabularies carry the registry (`menders/vocabulary.ts`):

- The authority a converger needs, one of `none` (no account authority: local
  cleanup, reads, writes the visit's own generation delegation covers),
  `account` (either account-authority kind converges it), `enrolled` (an
  enrolled client's key), or `ladder` (a standing credential's ladder). At the
  two chain triggers it is a runtime filter against the held set the session's
  account-ceremony context derives (`heldAuthorities`); everywhere else it is a
  declaration-time claim the entry's own call site checks.
- The trigger, where an invariant is checked today, one of
  `remembered-login-chain` and `transient-login-chain` (the two login chains a
  runner batches registrations for), `login-routing` (invoked by name at a
  routing call site before or during session assembly, and allowed to refuse the
  login), or `ceremony-tail` (executed inside a ceremony's own sequenced code,
  reporting through the registry only).

The menders wallet-core builds, with the invariants each reports, by number in
the census. Their full accounts stay in the topic docs the entries name.

| Mender                     | Entry point                                                   | Module        | Invariants     | Topic doc                                                                    |
| -------------------------- | ------------------------------------------------------------- | ------------- | -------------- | ---------------------------------------------------------------------------- |
| Space-controller promotion | `ensurePromotedSpaceController`                               | `genesis`     | 12             | [account-genesis.md](docs/architecture/account-genesis.md)                   |
| Credential-anchored mend   | `mendCredentialAnchoredAccount`                               | `clientAnnex` | 10, 12, 13, 14 | [account-genesis.md](docs/architecture/account-genesis.md)                   |
| Transient readiness ensure | `ensureCredentialClientAnnexGeneration`                       | `clientAnnex` | 15             | [account-genesis.md](docs/architecture/account-genesis.md)                   |
| Login-time roster sweep    | `checkUserKeyRosterAtLogin`, `convergeUserKeyRosterToAccount` | `clients`     | 1, 2, 3        | [keys-and-descriptor-logs.md](docs/architecture/keys-and-descriptor-logs.md) |

The runner's discipline (`runMenderBlock`) is stated under "Module map and
dependency direction". The derived sets a wallet's audit tests pin
(`transientReachableInvariants`, `deriveGaps`, `undeclaredGaps`,
`undeclaredInvariants`) are what turn a stated residue with no mender into a
declared gap rather than an undocumented one.

## The sync engine (`sync`)

`SyncEngine` drives exactly one `(replica, collection)` feed: single-flight
(concurrent `sync()` calls coalesce), migrate-once (pull-before-migrate ordering
avoids server-side duplicates), and exponential backoff with jitter, with every
side effect injected via `SyncEngineDeps`. The wire contract and port are
defined in `@interop/was-client/sync` and re-exported here, so an engine
consumer imports one package. This module owns the replica side: the `SyncStore`
seam, `runPull` / `runPush`, and the engine.

Three invariants carry the module. The server's `ETag` is opaque and echoed back
verbatim rather than synthesized from a bare revision number. Every conditional
write's `ifMatch` comes from a stored string: a push's acked `etag`, a pulled
`WireDoc`'s `etag`, or the re-read `MasterState.etag`. The three wire signals
are classified by `err.name` through was-client's `isSyncConflictError` /
`isSyncNotFoundError` / `isUnknownEpochError`, because both seams that raise
them can resolve to a second copy of the package and an `instanceof` miss is
silent and expensive. And a collection's descriptor is published before its
first content push: `ensureProvisioned` runs ahead of every cycle's migration
sweep and push, memoized only once a call resolves, and the caller invalidates
that memo with `SyncEngine.invalidateProvisioning` whenever the account's
provisioning state can have changed.

An eager minter that loses the descriptor create adopts the winner's descriptor
and re-mints its pending rows through `SyncStore.replacePending` before the next
push. The engine decrypts outside the store transaction, so store methods never
see key material, and `contactsConflict.ts` fails safe to remote on any
unreachable field.

Callers meet `WasSyncConflictError`, `WasSyncNotFoundError`,
`UnknownEpochError`, and `WalletSpaceProvisioningError` from
`walletSpaceProvisioner`.

Full account: [The sync engine (`sync`)](docs/architecture/sync-engine.md).

## Delegation-proof signing

Every zcap this library delegates -- App Connect app grants, share grants, the
client annex generation delegation, the bridge delegations inside unlock and
recovery records -- is signed with `eddsa-jcs-2022` (`EddsaJcs2022` from
`@interop/ed25519-signature/eddsa-jcs-2022`). JCS canonicalization is plain
JSON, so minting a grant runs no JSON-LD canonicalization and needs no document
loader at signing time. The log entries and the HTTP-signature invocations
canonicalize the same way. The suite is hard-coded rather than threaded as a
caller option, since a wrong setting would surface only as an interop failure at
the server. Wallet-core states no suite of its own: `@interop/was-client`'s
`zcapClientForSigner({ signer })` is the one `ZcapClient` construction site, and
the wrappers that sign under a different key id (`webvh/zcap.ts`'s two,
`clientAnnex/zcap.ts`'s ladder VM) build the signer and hand it there.

Two consequences the callers own. The storage server must verify both suites,
and it ships first: `eddsa-jcs-2022` before any client emits it, and
`Ed25519Signature2020` because grants minted under it stay recorded on Login
activities and are re-verified whenever an app or agent is revoked. And a client
that RE-delegates one of these grants must be on this suite too. An
`Ed25519Signature2020` client cannot re-delegate a JCS-signed parent on its
default loader, because URDNA2015 expands the parent embedded in
`proof.capabilityChain` and no such loader serves the data-integrity context.
That failure is at signing time on the re-delegating client, so a server
verifying both suites does not cover it. The VP and credential paths are a
separate axis and keep their own negotiation in `@interop/wallet-request`.

## Permanent wire-level constants

Byte-for-byte identical strings both replicas depend on. **None of these can
ever change** -- each is baked into every existing account's derivations or
stored artifacts:

| Constant                                     | Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Why permanent                                                                                                                                                                                |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BOOTSTRAP_HANDLE` / `BOOTSTRAP_KEY_NAME`    | `'bootstrap'` / `'boostrap-key'`, defined in `@interop/was-client/identity`                                                                                                                                                                                                                                                                                                                                                                                                                             | every data identity derives through them; the typo in `boostrap-key` is load-bearing and can never be fixed                                                                                  |
| `KEYRING_KDF`                                | Argon2id, 64 MiB memory, 3 passes, parallelism 1, salt `freewallet/keyring/unlock/argon2id/v1` (version 2; version 1's PBKDF2-600k set under `freewallet/keyring/unlock/v1` was replaced outright)                                                                                                                                                                                                                                                                                                      | every account's unlock identity                                                                                                                                                              |
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
| `ladderCommitment`                           | a property on every credential-class `keyAgreement` member, `Multikey` and `MultikeyCommitment` alike; the value is `hash(rung 0)` of the credential's ladder in the multihash form `nextKeyHashes` carries; a plain JSON member with no JSON-LD term, absent from an enrolled client's marked twin                                                                                                                                                                                                     | every seedless reader anchors the credential's ladder walk on it, and a member without it is unclaimable                                                                                     |
| `BYOE_CONTEXT_URL`                           | `https://w3id.org/byoe/v1`, in every account document's `@context`                                                                                                                                                                                                                                                                                                                                                                                                                                      | it defines the two commitment terms                                                                                                                                                          |
| `CONNECT_CODE_PREFIX`                        | `freewallet-connect:`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | the one spelling of the connect-code grammar                                                                                                                                                 |
| Collection / resource names                  | see the Space layout tables above                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | the Space layout contract                                                                                                                                                                    |
| `COLLECTION_HISTORY_LOG_SUBRESOURCE`         | `meta/log`, the Collection sub-resource every encrypted collection's governing history log is served at                                                                                                                                                                                                                                                                                                                                                                                                 | every governed collection's log is addressed there, and every reader derives its chain-head pin slot (`space/<spaceId>/<collectionId>/meta/log`) from it                                     |
| The epoch-configuration state type           | `WasEpochConfiguration` (was-client's `EPOCH_CONFIGURATION_STATE_TYPE`), the `state.type` of every entry in a roster or collection descriptor log                                                                                                                                                                                                                                                                                                                                                       | a verified head of any other type is refused fail-closed, so every entry ever written carries it                                                                                             |
| The resource-log format identifier           | `resource-log:0.1`, the genesis `parameters.method` and the `history.method` a governed descriptor names                                                                                                                                                                                                                                                                                                                                                                                                | a log's genesis parameters are hashed into its SCID, and a reader refuses a log naming another format                                                                                        |
| `WalletActivity` `type` / `summary` strings  | `space/activity.ts`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | byte-significant across replicas                                                                                                                                                             |
| `KEYRING_RECORD_VERSION`                     | `2`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | the stored record envelope                                                                                                                                                                   |

Every unlock method's KDF carries a distinct salt so two methods can never
derive the same unlock identity.

## What lives elsewhere (do not reimplement here)

- **`@interop/vh-resource-log`** -- the Resource Log Profile's generic client
  side: the JSON Lines codec, the `ResourceLogStore` port and `confirmAppend`,
  `verifyResourceLog` with the `admitAppend` admission-hook seam on the
  controller port, the keyed chain-head pin store, the append/create path, and
  the sealing sweep. It also owns the read-side classification of its refusal
  taxonomy, `isResourceLogRefusal`, which `resourceLog/errors.ts` re-exports
  beside the license class. `resourceLog/` keeps only the did:webvh controller
  adapter, the ceremony-tail license the hook carries, and the shared
  account-document reader leaf both are built on (`document.ts`, surfaced
  through `webvh`). Test fixtures come from its `./testing` subpath, restricted
  to test globs by the lint pass.
- **`@interop/was-client`** -- the sync wire contract and port (`/sync`), the
  EDV envelope cipher and epoch construction (`/edv`,
  `x25519RecipientFromDidKey`, `createEdvDocCipher`), the descriptor acquisition
  and unknown-epoch refresh policy (`acquireDescriptor`,
  `DescriptorRefreshPolicy`, `createRefreshingEdvDocCipher`, the
  `isKeyUnwrapError` matcher), the descriptor-store seam, the WAS binding of the
  resource-log store port (`/log`: `resourceLogStore`), `deriveSpaceId`, the
  did:key data-identity derivation (`/identity`: `agentsFromSecret` /
  `agentsFromSeed` / `agentsFromKeyAgent`, `singleKeyResolver`, the bootstrap
  handles), and `zcapClientForSigner`.
- **`@interop/social-core`** -- the contacts collection specs and the
  `remotePayloadWins` LWW comparison.
- **`@interop/vc-display`** -- pure VC display derivation and credential input
  parsing: credential name, issuer / subject render info, validity, Open Badges
  v3 helpers, display fields, the verification checklist, `credentialsFromJSON`.
  Nothing in wallet-core depends on it; the apps import the package directly.
- **`@interop/wallet-request`** -- the request pipeline: input classification,
  VPR parsing, QueryByExample matching, cryptosuite negotiation, VP composition,
  the App Connect app-key credential, the VC-API and ephemeral-exchange clients,
  and the `WalletOnboardingQuery` vocabulary. Wallet-core hands it two
  recognizers, `isWasLinkPayload` (`space`) and `isConnectCode` (`enrollment`);
  nothing in wallet-core depends on it.
- **`@interop/data-integrity-core`** -- the VPR type vocabulary and the loose VC
  shape guards. Import them from the `/vpr` and `/guards` **subpaths**, not the
  package root, which can dedupe onto an older cached build.
- **`@interop/did-method-webvh`** -- the webvh log primitives `webvh/` wraps and
  the hashing/proof kernel `@interop/vh-resource-log` verifies and signs with.
- **`@interop/capability-agent`** -- `CapabilityAgent`; **`@interop/ezcap`** --
  `ZcapClient`.
- App-side, per the apps' own ARCHITECTURE.md files: the concrete synced-
  collection registries, storage and session objects, consent UI, and the App
  Connect query processing. The RxDB replication driver both browser consumers
  run is `@interop/was-sync`'s.

## Topic docs

The topic docs under `docs/architecture/` carry the mechanism in full. Open the
one covering the area before changing it.

- [The wallet Space layout (`space`)](docs/architecture/space-layout.md) --
  before changing a collection spec, the system collections, Space provisioning,
  or the `WalletActivity` and `was-link` wire shapes.
- [The did:webvh account log (`webvh`)](docs/architecture/did-webvh-account-log.md)
  -- before changing the account document's verification methods, update-key
  attribution, the chain-head pin, the `did:web` projection, or the account-log
  signer seam.
- [The user key roster and the descriptor logs (`keys`, `descriptors`)](docs/architecture/keys-and-descriptor-logs.md)
  -- before changing the user key, a key epoch, the sealing sweep, the
  ceremony-tail license, a collection's governing history log, or the
  unknown-epoch refresh.
- [Standing unlock credentials (`unlock`)](docs/architecture/standing-unlock-credentials.md)
  -- before changing the update-key ladder, the ladder VM, the unlock record,
  the document inventory edit, or self-enrollment.
- [Account genesis and the credential-anchored establishment](docs/architecture/account-genesis.md)
  -- before changing the genesis stage order, the credential-anchored
  establishment, its mend, or the transient readiness ensure.
- [The client enrollment ceremony (`enrollment`)](docs/architecture/client-enrollment.md)
  -- before changing the connect code, the approval seam, or the
  onboarding-response envelope and its invite transport.
- [Client revocation, credential retirement, and forget](docs/architecture/client-revocation.md)
  -- before changing the revocation cascade, disconnect eligibility, credential
  retirement and its gate, or either forget ceremony.
- [Recovery codes (`recovery`)](docs/architecture/recovery-codes.md) -- before
  changing code issuance, a spend continuation, or code revocation.
- [The sync engine (`sync`)](docs/architecture/sync-engine.md) -- before
  changing pull/push semantics, the `SyncStore` seam, the provisioning ordering,
  or the contacts conflict resolution.

## Glossary

The repo's ubiquitous language: one canonical term per concept, used the same
way in code, tests, docs, and conversation. The consumer apps' glossaries carry
the app-side entries. An entry's `Avoid:` line names the synonyms this repo does
not use.

- **WAS (Wallet Attached Storage)** -- the HTTP protocol for storing resources
  in user-owned Spaces, authorized via ZCap. Containment: **Space contains
  Collections contain Resources**.
- **User key** -- the account-wide key that is recipient zero of every encrypted
  collection's key-epoch roster (`keys/userKey.ts`); see "The key hierarchy".
  Avoid: PUK.
- **Vault KAK** -- the X25519 key-agreement key that opens EDV envelopes: the
  user key's key-agreement half, cached in the client key record.
- **Epoch** -- one generation of a collection's encryption key, its secret
  wrapped to each recipient. Rotating adds an epoch rather than re-encrypting
  history, and prior epochs stay openable via escrow wraps.
- **Account pointer** -- `{ did, spaceId, host }`, the keyring record's payload;
  locates the account without authorizing anything against it.
- **Client / `clientId`** -- the keyed, custodied, revocable identity of an
  (app, user) pair, and a cache rather than an account's state: a keypair that
  can be a zcap grantee, a delegation controller, or a roster recipient.
  Deliberately not called a "device", since one machine hosts many clients and a
  client is not tied to hardware. An **enrolled client** (published in the
  account document, keyed on `capabilityInvocation`) saves a self-enrollment; a
  **transient client** is a per-visit key recorded in a client annex generation.
  Avoid: device, device id, durable client, permanent client.
- **`writerId`** -- an unkeyed, clearable, unrecoverable attribution label
  saying which writing agent produced a revision, minted locally app-side and
  not derived from any secret. Used only for history attribution and LWW
  tie-breaking; it is not an identity, and not 1:1 with a replica. Avoid:
  replicaId, device id, session id.
- **`clientAnnex` / the client annex** -- the sibling did:webvh log holding
  per-visit transient client keys in GC'd generations, published in the
  account's auxiliary annex Space. Enrolled clients live in the account
  document; delegated and transient clients live in the client annex.
- **Durable** -- persisted server-side on the WAS host: the account log, the
  annex log, the user key roster, the unlock records, the Collection
  Descriptions and their key epochs. It survives a cleared client and a lost
  machine, which is why a ceremony stage may detect its own completion from it,
  and the word names this tier alone (freewallet's `decisions/0011`). Avoid:
  durable client, durable session, durable login.
- **Client-local** -- persisted by the client itself: a browser's IndexedDB and
  localStorage, a mobile app's keychain and tables, the client key record, the
  keyring cache, the descriptor caches, the replica database. It survives a
  restart but not an eviction, a cleared profile, or a lost machine, so it is a
  cache of what the host holds. Avoid: durable local state, disk, persistent
  storage.
- **In-memory** -- held in process memory and gone when the tab or app closes: a
  transient visit's whole store family, unlocked key material, the pin stores a
  caller chooses to keep in memory. The third storage tier.
- **Remembered** -- a client holding a client key record for an unlock
  credential is a **remembered** one, so a login on it proceeds as (or
  self-enrolls into) an enrolled client; the default on a **non-remembered**
  client is the transient login. Remembering is client-local opt-in state,
  undone by the forget ceremony and lost with a cleared profile. A background
  pass that only a remembered login runs is a **remembered-login sweep**. Avoid:
  durable login, durable session, trusted client, persistent login.
- **Inventory** -- a credential's or client's set of durable entries in the
  account document, the annex log, or the ladder: its `keyAgreement` entry or
  commitment, its ladder VMs, and its committed rung hashes. Ceremonies install
  it, retirement sweeps it out, and an entry is inventory-changing iff the set
  differs from the previous document version's
  (`ResourceLogController.inventoryAt`). A named arrangement of an inventory is
  a qualified "configuration" phrase rather than a bare one. Avoid: posture.
- **Ceremony** -- an ordered sequence of writes across the account's systems
  (the account log, the roster, the unlock records, collection epochs) and the
  caller's own storage, whose stage order carries an invariant:
  persist-before-publish, document-edit-first,
  decryption-material-before-authorization. Every stage detects its own
  completion from durable state, and every tear point has a stated mender. Every
  write before the pivot names the storage tier it lands in, so a client-local
  pre-pivot write owes an answer for a cleared or evicted client and not only
  for a crash; the other side of the pivot is `decisions/0010`'s derivability
  rule. Avoid: flow, workflow, wizard.
- **Tear mending** -- how a ceremony interrupted mid-run (a torn ceremony) gets
  finished. Three menders exist: a converging re-run, a standing sweep (a
  remembered-login pass, e.g. the cascade-completion sweep in
  `clients/rosterPolicy.ts`), and a repair. A stated residue with no mender is
  an open gap rather than a documented limitation. Avoid: tear closure.
- **Repair** -- the mender of last resort: code detecting one specific torn
  state from durable state alone and finishing the ceremony, waiting at the
  entry point where the authority that state needs reassembles. Used where
  neither a re-run nor a remembered-login sweep can fire, the recurring case
  being a client-less account. Always qualified by its torn state rather than
  used bare; freewallet's torn-retirement repair
  (`repairTornPassphraseRetirement`) is the built example. Avoid: completer,
  finisher, fixup.
- **Current-key-set rule** -- see "The did:webvh document is the client roster"
  in docs/architecture/did-webvh-account-log.md.
- **Connect code** -- the `freewallet-connect:<base64url(JSON)>` payload
  carrying an enrollment request's public halves point-to-point.
- **Recovery code** -- 16 bytes base58, a complete minimal client derivable from
  its bytes alone; see "Ceremonies and cascades".

## Testing notes

- `test/node/` is the Vitest suite (`pnpm run test:node`); files are named
  `<module>-<topic>.test.ts` (e.g. `keys-userKeyRoster.test.ts`), with shared
  fixtures in `test/node/fixtures/` (`memoryIdStore.ts`, `rosterClient.ts`).
- The Playwright browser suite is **scaffolding only**: `playwright.config.ts`
  and the `vite dev` server exist, but `test/browser/` holds no tests.
- `test/logs/` holds generated did:webvh log artifacts from test runs; it is
  gitignored and not source.
- `pnpm test` runs fix + lint + typecheck + the node suite; the browser suite is
  deliberately not part of it.
- The executable cross-replica conformance suite lives in the freewallet repo
  (`tests/conformance/crossReplica.test.ts`), driving both apps' engines against
  a real in-process WAS server; its results are recorded in
  [docs/cross-replica-sync-compatibility.md](docs/cross-replica-sync-compatibility.md).
