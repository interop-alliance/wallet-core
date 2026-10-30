# Architecture

The codebase map for `@interop/wallet-core`: what the library is, the module
layers and their dependency direction, a short overview per area, the key
hierarchy, the ceremony inventory, where neighboring logic lives, and the
Glossary. Each area's full account (every ceremony's stage order, refusals, tear
points, and menders) lives in one topic doc under `docs/architecture/` (see
"Topic docs"), as do the permanent wire-level constants, the mender registry,
and subpath isolation. For toolchain rules (pnpm, build, tsconfigs, tests) see
[AGENTS.md](AGENTS.md); for code conventions see
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
  `PwsSyncPort`, a pws-client handle, a `FetchLike`), and the pervasive pattern
  is injected side effects, down to `schedule` / `random` / `backoff`.
- **Pure derivation out, formatting and consent in the caller.** The VC display
  derivation follows this rule and lives in `@interop/vc-display`. The request
  pipeline lives in `@interop/wallet-request`, where consent and the response
  channel stay with the app the same way.

## Module map and dependency direction

Modules by layer; a module may import from lower layers only. There are no
cycles between modules. One file-level cycle stands inside `webvh`:
`webvh/ladder.ts` takes the surviving-client protection from
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
                             audiences (space, type-only)
layer 2:                     keys (webvh, keyring, space, resourceLog)
layer 3:                     enrollment (webvh, keys, keyring, resourceLog)
                             connections (space, webvh, the import-free
                             keys/rosterRecipientKid.ts leaf)
                             unlock (webvh, keys, keyring, resourceLog)
                             genesis (webvh, keys, space, resourceLog)
layer 4:                     recovery (unlock, webvh, keyring, space)
                             clients (webvh, keys, resourceLog,
                             connections)
top:                         clientAnnex (may import any base subpath,
                             clients included; nothing in the base imports
                             from it)
top-level leaves:            src/log.ts, src/stages.ts, src/errorName.ts,
                             src/labelText.ts, src/jsonObject.ts
                             (import-free; any layer may take a name from
                             any of them)
                             src/ceremonyEvents.ts (the ceremony event
                             channel: type-only imports of the vocabularies
                             it names, plus errorName and labelText; any
                             layer may emit through it)
                             menders (imports only the root-level leaves; a
                             wallet's registry over its own table, read by no
                             other module)
root barrel:                 src/index.ts re-exports sync + space, plus
                             the log.ts and ceremonyEvents.ts leaves
```

- **`sync`** (deps: --) -- WAS replication engine core: `SyncEngine`, `runPull`
  / `runPush`, the `SyncStore` replica seam, contacts LWW conflict resolution.
- **`space`** (deps: --) -- Wallet Space layout contract: collection ids/specs,
  `wallet-activity` wire shape and builders, `publicCredentialUrl`, the
  `pws-link` QR payload, the `inbox` spec and the inbox Grant envelope codec,
  the capability-authorized Space DELETE.
- **`descriptors`** (deps: resourceLog, space) -- The log-governed descriptor
  source: the wallet's implementation of pws-client's
  `EncryptionDescriptorSource` seam over a collection's governing resource log,
  and the pin-slot name each collection's log pins under.
- **`audiences`** (deps: space (types)) -- The audience collection, a plaintext
  collection whose posts are its Resources: its provisioning attributes
  (`AUDIENCE_PROVISION_ATTRIBUTES`) and the member grant
  (`delegateAudienceGrant`, GET and HEAD on the container, no escrow).
- **`resourceLog`** (deps: --) -- The wallet-domain residue of the Resource Log
  Profile client side: the account-document reader leaf, the ceremony-tail
  license, and the did:webvh controller adapter..
- **`webvh`** (deps: space, resourceLog) -- The account's did:webvh log:
  provisioning, rotation, enrollment and revocation entries, verification, log
  stores, zcap signing, and the update-key ladder..
- **`keyring`** (deps: space) -- The unlock layer: unlock KDF, the keyring
  record codec, the unlock Space lifecycle.
- **`connections`** (deps: space, webvh, keys (the kid leaf)) -- The
  `connections` directory, one encrypted entry per party, with its codec, store,
  upserts, writer arm, agent connection surface, and the replica-server entry's
  replica Spaces..
- **`keys`** (deps: webvh, keyring, space, resourceLog, descriptors (leaf)) --
  The user key (its derived Ed25519 signing half included), its wrap-set roster
  (log-governed, sealable), the per-collection encryption descriptor logs' store
  builder, the rotation cascade's per-collection op, the provision-time
  collection epoch install, the client-key record codec.
- **`enrollment`** (deps: webvh, keys, keyring, resourceLog) -- The client
  enrollment ceremony: connect code, approval, completion, the
  onboarding-response envelope.
- **`unlock`** (deps: webvh, keys, keyring, resourceLog) -- Standing unlock
  credentials: the credential-derived client identity, the unlock record codec
  (shell / bridge / ladder / binding, `LADDER_SEED_BYTES` and the ladder seed
  mint included -- the record format owns its member sizes), the merged
  document-inventory edit (verbatim key or hash commitment), the retirement
  ceremony.
- **`recovery`** (deps: unlock, webvh, keyring, space) -- Recovery codes as
  standing unlock credentials that retire on spend, over the `unlock` machinery
  (the code's key set and its ladder derived from the code bytes, the remembered
  recovery continuation); the pre-minted `did.jsonl` delegation builder.
- **`genesis`** (deps: webvh, keys, space, resourceLog) -- The account-genesis
  ceremony: the new-account key set mint and the staged provisioning of a fresh
  account (Space layout, the optional KMS authentication binding, did:webvh
  genesis, roster genesis, epoch[0] install, controller promotion).
- **`clients`** (deps: webvh, keys, resourceLog, connections) -- Enrolled-client
  management: listing (names joined from the directory's wallet-client entries),
  disconnect-eligibility policy, the revocation cascade orchestrator, the
  login-time roster policy.
- **`clientAnnex`** (deps: every base subpath it needs) -- The client annex: the
  authoring and maintenance surface of everything ladder-anchored, from the
  annex log to the credential-anchored ceremonies..
- **`menders`** (deps: --) -- The mender registry keyed by invariant, with its
  vocabularies, readers, and runner. See
  [menders.md](docs/architecture/menders.md)..
- **`ceremonyEvents.ts`** (root) (deps: menders (types), space (type),
  errorName, labelText) -- The ceremony event channel over the `Logger` seam:
  the per-run emitter, the mender event, and the served-identifier sanitizer.
  See [menders.md](docs/architecture/menders.md)..

No other `src/` module imports `sync`, `genesis`, or `audiences`. `connections`
has one importer, `clients/listing.ts`, which joins the account document's
clients with the directory's wallet-client entries. `clients` has one importer,
`clientAnnex/grantRevocation.ts`, which takes the grant-signer reading from
`clients/grantState.ts`; the annex may import any base subpath, so that edge is
within the layering rule. `sync` and `space` are the only modules the root
barrel re-exports. Beside them it exports the logging port from `log.ts` and the
event helpers from `ceremonyEvents.ts`, both root-level leaves.

The mender runner (`runMenderRegistration`, `runMenderBlock`) applies one try,
warn, and skip discipline over a registration. Its account is in
[menders.md](docs/architecture/menders.md).

**The client-annex boundary.** `clientAnnex` sits on top: it may import from any
base subpath, and nothing in the base imports from it. A `no-restricted-imports`
block in the lint pass (part of `pnpm test`/CI) enforces it, so a new
base-to-annex edge is a build failure, and no file is exempt. The ladder is base
code in `webvh`: the pure rung and ladder-VM derivation in
`webvh/ladderDerivation.ts`, and the shared attribution walks in
`webvh/ladder.ts`, which `webvh/accountEntry.ts`, `webvh/revokeClient.ts`,
`unlock/standingWebvh.ts`, `recovery/continuation.ts`, and the annex all take
from there. The annex DID's shape (the generation id convention,
`parseClientAnnexDid`, with `clientAnnexDidParts` and `isClientAnnexDid` over
it) is base code too, on the import-free `webvh/clientAnnexDid.ts` leaf, so
`connections` can tell a generation delegation's controller from any other; the
annex re-exports it. The annex keeps only a credential's static annex rung
(`clientAnnex/generationRung.ts`), minted through the derivation leaf's one HKDF
call.

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

The root export re-exports only the `sync` and `space` modules, plus the
root-level leaves `log.ts` and `ceremonyEvents.ts`. Every other subpath is
import-directly-only, with a four-key `exports` entry (`types` / `react-native`
/ `import` / `default`) in `package.json`. Leaf subpaths exist for dependency
isolation and must stay dependency-light. They are checked by
`test/node/import-graph.test.ts` and `test/probe/leafClosure.mjs`. The leaves
are:

- `./keys/clientKeyRecord`
- `./keyring/kdf`
- `./keyring/recordEnvelope`
- `./keys/userKey`
- `./keys/userKeyGenerations`
- `./unlock/standingClient`
- `./webvh/ladderDerivation`
- `./recovery/recoveryCode`
- `./space/collections`

Why each is isolated, and what each may import, is in
[subpath-isolation.md](docs/architecture/subpath-isolation.md).

## The wallet Space layout (`space`)

A Space is a WAS container, addressed as
`<baseServerUrl>space/<spaceId>/<collection>/<resource>`, where the base server
URL is the one locator a wallet holds for a server (see the Glossary). An
account has two: a data Space for credentials, activity, identity and key-map,
and a minimal unlock Space holding one keyring resource. `space/collections.ts`
is the layout contract for the four synced collections. Both replicas must lay
them out field-for-field identically, since a drift splits the feed and never
converges. The `shareable` column there is the share-surface allowlist, and the
encrypted sets still follow `encryption`. The `grantable` column covers every
roster entry, system collections included. It decides whether a requester's
grant may name the collection at all. A key- or seed-bearing collection is
`grantable: false`, which today means `app-keys`, `key-map` and
`unlock-methods`. The `connections` directory is `grantable: false` too, since
it is the account's grant index and party list. The contacts specs live in
`@interop/social-core` instead.

The `connections` directory sits in the provision roster outside the synced
specs: one encrypted entry per party, read and written directly, with no local
replica. Full account:
[The `connections` directory (`connections`)](docs/architecture/connections-directory.md).
The `inbox` collection follows it in the roster. It is the plaintext, non-public
mailbox a connected agent posts into, also with no local replica. It is
`grantable: false`. The agent's POST capability on its container comes through
the dedicated `inbox` target class, the one carve-out of `grantable`.

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
is refused with pws-client's `ValidationError`.

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
   (`keyring/kdf.ts`), the **unlock identity** (`keyring/unlockIdentity.ts`): it
   addresses the unlock Space and holds the KAK the keyring record is wrapped
   to. It carries no authority over the account, and nothing about the account
   is derivable from it.
2. **Keyring record** (`keyring/record.ts` over `keyring/recordEnvelope.ts`,
   `{ version: 2, encryption, wrapped, proof }`) -- the unlock Space's one
   resource: account controller, bind-time email, bind timestamp, and the
   **account pointer** `{ did?, spaceUrl }`. Deliberately no key material of any
   kind. The envelope seals under the record's own one-epoch descriptor
   (`encryption`, epoch[0] wrapped to the unlock KAK), so the record stays
   self-contained under the everything-seals-to-an-epoch rule. The unlock KAK's
   public half is derivable from the unlock did:key the server stores as the
   Space's controller, so confidentiality alone would let a hostile host seal a
   substitute that decrypts perfectly. The `proof` (eddsa-jcs-2022 over the
   sibling members, by the unlock identity's Ed25519 key) is the authenticity
   layer, verified before any decryption. Every member also decrypts under the
   addressed id the codec stamped onto it at seal time (`recordEnvelopeId`), but
   that check is inert as a security boundary: the cipher runs in
   content-derived id mode, so a substituted envelope carries a matching stamp
   and the check catches corruption rather than substitution. The `proof` is
   what catches substitution. The recovery record shares the frame under a
   mixed-signer rule, which the reader marks pending for checking against the
   verified did:webvh document (`currentAccountRecordSigners`). Every record
   bound under `decisions/0019` is signed by its own credential's unlock
   identity key, so no ceremony writes a sibling record; the mixed-signer arm
   survives only for records bound before that rule.
3. **Data identity** (`@interop/pws-client/identity`'s `agentsFromSecret` /
   `agentsFromSeed`) -- controller secret or 32-byte seed, expanded under the
   pinned `'bootstrap'` / `'bootstrap-key'` names to the did:key
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
   or seed. Its X25519 key-agreement half is the whole of the stored material;
   its Ed25519 signing half (`keys/userKeySigning.ts`) derives from that half's
   raw secret (HKDF-SHA256, `USER_KEY_SALT`, info `signing`), so it needs no
   delivery channel of its own and every holder of the user key can both sign
   and verify. That signing key is what puts a `proof` on an app-side record
   sealed to the vault KAK, which decrypting alone would not authenticate:
   `userKeyRecordSigner` signs, and `userKeySigningKeyMultibase` is the reader's
   allowlist.
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
   rung. A spend's transient continuation (`recoverWebvhLadderAnchored`) resumes
   the way a self-enrollment does: the caller persists the fresh credential's
   ladder seed before the reveal entry and hands it back with the seam's
   recorded head (`resume.builtOnHead`), so the re-run finds its reveal entry
   standing, and an unreached head refuses with `BuiltOnHeadNotReachedError`.
   The two-addition reveal entry a re-run with a freshly minted seed wrote is
   historical; the ladder readers keep recognizing it.

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
`did.jsonl` in the world-readable `id` collection. The identifier is
self-locating: its segments after the SCID are the server's host, the base
server URL's path prefix, `space`, the Space id and the collection, so
`didWebvhLogLocation` reads the log URL, the Space URL and the base server URL
off the DID alone, and the location check every reader runs compares the URL a
log was fetched from against the one its resolved DID encodes. The log is the
single source of truth, and a `did:web` projection is kept alongside it. That
document is the client roster. An enrolled client contributes its Ed25519 key
under all four relations plus its X25519 twin under `keyAgreement`, while a
standing credential contributes a `keyAgreement` key and a ladder VM under
`assertionMethod` and `capabilityDelegation`. Listings keyed on
`capabilityInvocation` therefore exclude credentials structurally.

Three rules carry most of the weight. The controller marker is the document's
one statement of which signing key a published key-agreement key belongs to.
`markedVerificationMethodPair` is the write site and
`resolvedKeyAgreementMethods` the read; a client with no marked method reports
an empty key-agreement set, and ambiguous log attribution yields a refusal
rather than a guess. The two key classes the document publishes, the enrolled
clients' signing keys and the ladder VMs' keys, are read by one reader each
(`enrolledClientKeyMultibases`, `ladderVmKeyMultibases`), so the ladder-rung
attribution and the did:key census name the same keys over the same document. A
member's key is the `publicKeyMultibase` its method publishes; its id fragment
is an opaque selector, so a reference nothing backs names no key. The
current-key-set rule says an invocation or delegation verifies only while its
method stands in the resolved document under the relation its purpose needs,
which is why client revocation is a single document edit. And every ceremony
publishes as a compare-and-swap on the ETag of the read its entry was built on.
The loser gets `WebvhLogConflictError` and re-runs itself through
`withLogConflictRetry`.

Reads run under a chain-head pin that refuses a rollback, a fork, or an SCID
switch with `ResourceLogContinuityError`. The pin is a property of the store
rather than a ceremony argument: `WebvhIdStore` carries it, and each constructor
derives the slot from the collection it serves. Callers meet `ensureDidWebvh`,
`verifyAccountLog` (and its discovery twin `discoverAccountLog`, for a reader
holding a Space URL and no DID), `revokeWebvhClient`, `ensureDidWebProjection`
(and its compare alone, `didWebProjectionCurrent`), and the `signAccountEntry`
seam, whose client and ladder arms decide who signs an entry.

Full account:
[The did:webvh account log (`webvh`)](docs/architecture/did-webvh-account-log.md).

## The user key roster and the descriptor logs (`keys`, `descriptors`)

The user key roster is log-governed. Its resource is the resource log
`key-map/user-key.jsonl`, and `logGovernedDescriptorStore` exposes that log as
an ordinary `EncryptionDescriptorStore`, so pws-client's roster machinery drives
it without knowing it. Reads resolve to the verified head state, and writes
become signed log appends. Every encrypted collection's `encryption` descriptor
is governed the same way, by a per-collection descriptor log at the collection's
`meta/log` sub-resource, built with `collectionDescriptorLogStore`. The
`(collectionId) => store` lookup every installer, genesis, and cascade takes has
two builders beside the roster's `userKeyRosterDescriptorStore`:
`collectionDescriptorStores` takes the collection reach and the controller
resolver as functions (a session's handle and verified-log memo), and
`accountCollectionStores` takes the roster store's bare parts plus the account
DID, resolving the controller through `webvh`'s memoized
`accountControllerResolver`. Neither wallet writes that wiring itself.

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
`EncryptionDescriptorSource`, resolving every acquisition to the log's verified
head and, on a repeat acquisition, verifying only the entries added since. A
decrypt that finds no key raises `UnknownEpochError` or `KeyUnwrapError`, and
the two mean different things to a scanner.

Each converger's decision is a pure predicate beside it. `userKeyRosterDrift` is
the decide-half of `convergeUserKeyRosterToDocument`: it reports the stale
recipients, the enrolled clients with no wrap, and the credential-class methods
with no wrap. `collectionEpochsCurrent` is the decide-half of
`rotateCollectionEpochsToUserKey`: it returns `'current'` or the reason a
collection is not. Each converger calls its predicate, and a wallet's invariant
auditor calls the same one, so the two cannot disagree on the rule.

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
commitment standing as a latent re-seizure credential. Whatever that walk claims
is held against every surviving enrolled client's active update key, carry-over
hash, and staged hash first (`survivingClientKeyProtection`), and a reading
naming one of them refuses with nothing written.

Self-enrollment (`selfEnrollWebvhClient`, composed by `selfEnrollClientCore`) is
two entries with a required `onCommitted` persist seam between them, at the
ceremony's pivot.

Callers meet `LadderAttributionError` on an ambiguous walk or a mismatched
rung-0 commitment, `NextKeyHashesEmptyError` when an entry would commit no next
key hash and so switch prerotation off (refused before any publish),
`UnclaimedLadderVmRetirementError` at the retirement gate,
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
surfaces in the per-collection `failed` report instead of a `noop`. A fresh
client-annex generation restates what the superseded one carried: its standing
rung set in the genesis, and its replica pointers in the entry that installs the
generation delegation. The caller supplies the pointer list from the connections
directory, and a transient visit that cannot read the directory carries the
superseded document's pointers forward instead.

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
name the ceremonies whose torn runs can violate it. Code-only means no stored
record and no account or annex log entry carries an id. The ceremony event
channel below is a separate diagnostics surface, and its events carry them. The
four menders own no pivot and live in the registry subsection below instead.

`CEREMONY_IDS` also names six ceremonies with no shared half yet:
`account-deletion`, `wallet-wipe` (the shared wipe executor the deletion-shaped
ceremonies consume), `content-migration`, `backup-export`, `request-consent`
(recording and escrowing the grants a CHAPI or interaction-URL request is
approved for), and `grant-revocation` (revoking a recorded app or agent grant,
or one reader's share). A wallet that runs one names it with that id. Their
implementations live in the app for now, so they have no entry in the list
above. `revokeRecordedGrant` (`clientAnnex`) and the `connections` helpers are
primitives the last two call, not shared halves.

- **Account genesis** -- `account-genesis`; entry point `ensureAccountGenesis`
  (after `mintAccountKeySet`); module `genesis`;
  [account-genesis.md](docs/architecture/account-genesis.md).
- **Credential-anchored establishment** -- `credential-anchored-genesis`; entry
  point `establishCredentialAnchoredAccount`; module `clientAnnex`;
  [account-genesis.md](docs/architecture/account-genesis.md).
- **Enrollment (approve, complete)** -- `client-enrollment`; entry point
  `approveEnrollment`, `completeEnrollmentCore`; module `enrollment`;
  [client-enrollment.md](docs/architecture/client-enrollment.md).
- **Self-enrollment** -- `self-enrollment`; entry point `selfEnrollWebvhClient`
  (`selfEnrollClientCore`); module `clientAnnex`;
  [standing-unlock-credentials.md](docs/architecture/standing-unlock-credentials.md).
- **Update-key rotation** -- `update-key-rotation`; entry point
  `rotateWebvhUpdateKey`; module `webvh`;
  [did-webvh-account-log.md](docs/architecture/did-webvh-account-log.md).
- **Client revocation** -- `client-revocation`; entry point
  `revokeAccountClient`; module `clients`;
  [client-revocation.md](docs/architecture/client-revocation.md).
- **Credential retirement** -- `unlock-credential-rotation`; entry point
  `retireUnlockCredential` (`preflightUnlockCredentialRetirement`); module
  `unlock`; [client-revocation.md](docs/architecture/client-revocation.md).
- **Forget** -- `forget-client`; entry point `forgetEnrolledClient`; module
  `clientAnnex`; [client-revocation.md](docs/architecture/client-revocation.md).
- **Last-client forget** -- `last-client-transition`; entry point
  `forgetLastEnrolledClient`; module `clientAnnex`;
  [client-revocation.md](docs/architecture/client-revocation.md).
- **Recovery-code issuance** -- `recovery-code-issuance`; entry point
  `publishRecoveryKey` (after `recoveryClientFromCode`); module `recovery`;
  [recovery-codes.md](docs/architecture/recovery-codes.md).
- **Recovery spend (remembered, transient)** -- `recovery-code-spend`; entry
  point `recoverWebvhClient`, `recoverWebvhLadderAnchored`; module `recovery`,
  `clientAnnex`; [recovery-codes.md](docs/architecture/recovery-codes.md).
- **Recovery-code revocation** -- `recovery-code-revocation`; entry point
  `removeRecoveryKey`; module `recovery`;
  [recovery-codes.md](docs/architecture/recovery-codes.md).

The ceremony event channel (`ceremonyEvents.ts`) is the diagnostics twin of
these outcome objects. Each entry point in the inventory but
`rotateWebvhUpdateKey` mints one emitter per run, and reports a debug
`'ceremony stage'` event per stage and one `'ceremony outcome'` event per run
through the module's `Logger`. No production code branches on an event. The
vocabulary, the levels, and where events are emitted from are in
[menders.md](docs/architecture/menders.md) and `decisions/0022` through `0024`.

The account-log signer seam every ceremony body signs through
(`signAccountEntry`, the client and ladder arms) is described in
[did-webvh-account-log.md](docs/architecture/did-webvh-account-log.md).

### The mender registry (`menders`)

A mender is what finishes a torn ceremony or converges ordinary drift, and it
owns no pivot of its own. The `menders` subpath is the registry that describes
the menders from the outside. Its unit is the invariant, a present-tense
predicate over the account's server-held state that must hold between
ceremonies, and each wallet declares its own table of them against the shared
`INVARIANT_IDS` census (`menders/ids.ts`). Two closed vocabularies carry the
registry: the authority a converger needs and the trigger where an invariant is
checked. The vocabularies, the six menders wallet-core builds, the derived gap
sets, and the runner's discipline are in
[menders.md](docs/architecture/menders.md).

## The sync engine (`sync`)

`SyncEngine` drives exactly one `(replica, collection)` feed: single-flight
(concurrent `sync()` calls coalesce), migrate-once (pull-before-migrate ordering
avoids server-side duplicates), and exponential backoff with jitter, with every
side effect injected via `SyncEngineDeps`. The wire contract and port are
defined in `@interop/pws-client/sync` and re-exported here, so an engine
consumer imports one package. This module owns the replica side: the `SyncStore`
seam, `runPull` / `runPush`, and the engine.

Three invariants carry the module. The server's `ETag` is opaque and echoed back
verbatim; the wire carries no revision number, and the engine reads nothing out
of a record's write stamp. Every conditional write's `ifMatch` comes from a
stored string: a push's acked `etag`, a pulled `WireDoc`'s `etag`, or the
re-read `MasterState.etag`. Whether a replica has ever been acked is its own
`acked` flag on `SyncedResourceReplica`, since a server that hides the `ETag`
header acks with no validator. The three wire signals are classified by
`err.name` through pws-client's `isSyncConflictError` / `isSyncNotFoundError` /
`isUnknownEpochError`, because both seams that raise them can resolve to a
second copy of the package and an `instanceof` miss is silent and expensive. And
a collection's descriptor is published before its first content push:
`ensureProvisioned` runs ahead of every cycle's migration sweep and push,
memoized only once a call resolves, and the caller invalidates that memo with
`SyncEngine.invalidateProvisioning` whenever the account's provisioning state
can have changed.

An eager minter that loses the descriptor create adopts the winner's descriptor
and re-mints its pending resource replicas through `SyncStore.replacePending`
before the next push. The engine decrypts outside the store transaction, so
store methods never see key material, and `contactsConflict.ts` fails safe to
remote on any unreachable field, except the cipher's integrity refusal, which it
rethrows. Under a cipher, a plaintext head counts as unreachable, so a valid
envelope on the other side wins over it.

Every decrypt the engine runs is addressed: `decryptDoc` and the
`contactsConflict` decrypt helpers take the feed document's own resource `id`
alongside its envelope. A document whose envelope was sealed under another
resource's id is refused by the cipher with `IntegrityError`, classified apart
from an ordinary undecryptable document so a host can count it. Its body still
lands in the store and the checkpoint still advances past it, and the re-mint
skips such a resource replica rather than aborting its pass, so one of them
cannot wedge the feed. The contacts conflict resolver answers that refusal the
other way and rethrows, since a side the binding check refused must not settle a
conflict under the fail-safe default; a side the replica merely holds no key for
stays unreachable. Both directions fail the cycle, and the resolver's optional
`onIntegrityRefusal({ side, err })` callback names the refused side for the
caller's log.

The engine stamps every push with an injected `writerId` (the WAS `Writer-Id`
header) and never mints, persists, or derives one; the app owns the label and
may withhold it. On pull, a live document carrying that label skips its decrypt
only when the optional `SyncStore.heldRevisions` seam confirms the replica holds
that exact `etag`. The label is host-writable plaintext and licenses nothing on
its own, so suppression never changes what converges.

Callers meet `PwsSyncConflictError`, `PwsSyncNotFoundError`,
`UnknownEpochError`, `IntegrityError`, and `WalletSpaceProvisioningError` from
`walletSpaceProvisioner`.

Full account: [The sync engine (`sync`)](docs/architecture/sync-engine.md).

## Delegation-proof signing

Every zcap this library delegates -- App Connect app grants, share grants, the
client annex generation delegation, the replica pull delegation and the
replicas-route maintenance grant, the bridge delegations inside unlock and
recovery records -- is signed with `eddsa-jcs-2022` (`EddsaJcs2022` from
`@interop/ed25519-signature/eddsa-jcs-2022`). JCS canonicalization is plain
JSON, so minting a grant runs no JSON-LD canonicalization and needs no document
loader at signing time. The log entries and the HTTP-signature invocations
canonicalize the same way. The suite is hard-coded rather than threaded as a
caller option, since a wrong setting would surface only as an interop failure at
the server. Wallet-core states no suite of its own: `@interop/pws-client`'s
`zcapClientForSigner({ signer })` is the one `ZcapClient` construction site, and
the wrappers that sign under a different key id (`webvh/zcap.ts`'s two,
`clientAnnex/zcap.ts`'s ladder VM) build the signer and hand it there. The one
verify site is `verifyRecordedGrantProof` (`connections/grantProof.ts`), which
checks a recorded grant's delegation proof under the same suite's verify
cryptosuite before the grant is renewed; it accepts no other suite.

Two consequences the callers own. The storage server must verify both suites,
and it ships first: `eddsa-jcs-2022` before any client emits it, and
`Ed25519Signature2020` because grants minted under it stay recorded on their
party's `connections` entry and are re-verified whenever an app or agent is
revoked. And a client that RE-delegates one of these grants must be on this
suite too. An `Ed25519Signature2020` client cannot re-delegate a JCS-signed
parent on its default loader, because URDNA2015 expands the parent embedded in
`proof.capabilityChain` and no such loader serves the data-integrity context.
That failure is at signing time on the re-delegating client, so a server
verifying both suites does not cover it. The VP and credential paths are a
separate axis and keep their own negotiation in `@interop/wallet-request`.

## Permanent wire-level constants

The byte-for-byte identical strings both replicas depend on: KDF salts and
infos, the unlock binding context, the shapes of the document and annex entries,
the `connections` entry members, the inbox Grant envelope, and the single-verb
capability shapes. **None of them can ever change**, since each is baked into
every existing account's derivations or stored artifacts. Several are
transcribed from the specs that own them, the Portable Wallet Profile among them
(the Space role types and the backup credential's KDF), and the list links each
such row to its normative section. The full list, with the reason each is
permanent, is in [wire-constants.md](docs/architecture/wire-constants.md). It
also states the known gap on the `*` subtree marker (WASS-58).

## What lives elsewhere (do not reimplement here)

- **`@interop/vh-resource-log`** -- the Resource Log Profile's generic client
  side: the JSON Lines codec, the `ResourceLogStore` port and `confirmAppend`,
  `verifyResourceLog` with the `admitAppend` admission-hook seam on the
  controller port, the keyed chain-head pin store, the append/create path, the
  sealing sweep, and the controller-document readers (`relationMembers`,
  `resolvedRelationMethods`, `relationIds`, and the one key-multibase rule a
  relation member is read under, `memberKeyMultibase` /
  `relationKeyMultibases`). It also owns the read-side classification of its
  refusal taxonomy, `isResourceLogRefusal`, which `resourceLog/errors.ts`
  re-exports beside the license class. `resourceLog/` keeps only the did:webvh
  controller adapter, the ceremony-tail license the hook carries, and the shared
  account-document reader leaf both are built on (`document.ts`, surfaced
  through `webvh`). Test fixtures come from its `./testing` subpath, restricted
  to test globs by the lint pass.
- **`@interop/pws-client`** -- the sync wire contract and port (`/sync`), the
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
  recognizers, `isPwsLinkPayload` (`space`) and `isConnectCode` (`enrollment`);
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
  run is `@interop/pws-sync`'s.

## Topic docs

The topic docs under `docs/architecture/` carry the mechanism in full. Open the
one covering the area before changing it.

- [The wallet Space layout (`space`)](docs/architecture/space-layout.md) --
  before changing a collection spec, the system collections, Space provisioning,
  or the `WalletActivity` and `pws-link` wire shapes.
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
  establishment, its mend, the transient readiness ensure, or the annex GC pass.
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
- [The mender registry and the ceremony event channel](docs/architecture/menders.md)
  -- before changing the mender registry's vocabularies or readers, the runner's
  discipline, or the ceremony event vocabulary and its emit sites.
- [Subpath isolation](docs/architecture/subpath-isolation.md) -- before adding a
  subpath, a leaf subpath, or an import to a pure derivation leaf.
- [Permanent wire-level constants](docs/architecture/wire-constants.md) --
  before touching any KDF salt, info string, context label, or stored or wire
  shape, and before adding a new permanent constant.
- [The `connections` directory (`connections`)](docs/architecture/connections-directory.md)
  -- before changing the entry shape, its resource id, the upsert helpers, the
  grant checks, the writer arm (registration, the touch, the sweep), or the
  agent connection members (the seed and its tag, the received grants, the
  outbox, the decline marker, renewal).

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
- **Account pointer** -- `{ did?, spaceUrl }`, the keyring record's payload;
  locates the account without authorizing anything against it. The DID is
  self-locating, so once it is present the Space URL is a cache of what the DID
  resolves to; it is absent only on the credential-anchored establishment's
  interim record, bound before genesis.
- **`baseServerUrl`** -- the one name for a server in every signature: the
  absolute URL under which a server serves `service`, `spaces/` and
  `space/<spaceId>/` as peers (pws-client decision 0003). Every WAS client is
  built from it, and no caller appends or strips a segment of it. A wallet
  stores none: the account's did:webvh encodes the host and the base's path
  prefix (`did:webvh:<scid>:<host>:<prefix...>:space:<spaceId>:id`), and
  `didWebvhLogLocation` reads the log URL, the Space URL and the base back off
  the DID; a Space URL in hand gives it through pws-client's `baseServerUrlOf`.
  Avoid: host, serverUrl, storageServerUrl, wasServerUrl.
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
  tie-breaking; it is not an identity, and not 1:1 with a replica. A `writerId`
  that is encountered in a second session may become a registered writer; most
  are not. Avoid: replicaId, device id, session id.
- **Registered writer** -- a `writerId` that was encountered in a second session
  under the same account and so earned a member in the `writers` list of its
  wallet client's `connections` entry: a platform label and its liveness state.
  Entirely advisory. Nothing checks it beyond shape, and it is never an input to
  any authorization decision. It links to a client's row only through the
  entry's did:key `id`, and only while the verified account document lists that
  key. An unregistered `writerId` renders as a fallback label. Avoid: known
  writer, trusted writer.
- **Pairwise did:key** -- a DID the wallet holds toward one party, derived from
  the `seed` stored on that party's `connections` entry (`connectionDidKey`). It
  is not a client, since it is no (app, user) keypair, appears in no roster, and
  signs nothing in the owner's Space. It is not an agent either, since the agent
  is the other party. It is durable, because its seed is server-held on the
  entry. It is a grantee on another party's server. It gives the party
  continuity across the owner's clients. It does not give the owner
  unlinkability. Avoid: connection key, pairwise client, agent key.
- **Audience** -- a plaintext collection in the owner's Space whose posts are
  its Resources. Membership is a GET and HEAD capability on its container.
  Nothing marks a collection as an audience on the wire. Avoid: group, circle,
  channel.
- **Inbox** -- the plaintext `inbox` collection a connected agent POSTs into,
  read and drained by the owner's clients. One mailbox serves the whole wallet,
  rather than one per connection. Avoid: mailbox collection, per-connection
  inbox.
- **Connections directory** -- the `connections` collection, one encrypted entry
  per party the wallet has dealt with (an app, an agent, a wallet client, a
  contact, a replica server), written by the wallet alone. Each entry holds the
  party's names, its grants (the revocation index), for a wallet client its
  registered writers, and for a replica server the replica Spaces on that
  server. An entry is retired when the relationship ends, and it is not deleted
  while the account stands.
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
- **Resource replica** -- a replica's local copy of one WAS Resource, the unit
  the sync engine pushes and pulls (`SyncedResourceReplica`). A store may keep
  it in a table row, but the seam names the copy, not the row. Avoid: synced
  row, dirty row.
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
  being a credential-anchored account. Always qualified by its torn state rather
  than used bare; freewallet's torn-retirement repair
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
- `test/integration/` runs the package's ceremonies against the real
  `@interop/web-spaces-server`, booted in process (`pnpm run test:integration`,
  its own config `vitest.integration.config.ts`, run by `pnpm test` after the
  node suite and as a CI step of its own). It is a contract tier: it pins what a
  real server serves and admits (a second provisioning run writes nothing, a
  re-run of a mender block reports `noop` throughout, the WAS v0.5 single-verb
  Space capability and the `meta` probe), not branch coverage. CONTRIBUTING.md
  ("Choosing a test tier") says which tier a new test belongs in.
- `src/testing/` is the `./testing` subpath, test fixtures only and never
  imported by production code (each consumer lint-restricts it to test globs).
  It holds the recorded-grant signer fixture, `FAST_KDF`, and the shared account
  builder (`accountBuilder.ts`): given a booted WAS server's URL it runs the
  package's own ceremonies, with no fake store, to produce the four named shapes
  (`buildPassphraseAccount`, `buildSecondCredentialAccount`,
  `buildRecoveryCodeAccount`, `buildEnrolledClientAccount`). It imports no
  server package; the integration tier's `bootServer` fixture is the one place
  `@interop/web-spaces-server/testing` is loaded. The unlock records it binds
  stay in memory, so a shape returns the bridge and sibling delegations instead.
  Both wallets build their test accounts through it so they cannot drift on
  which ceremony mints what.
- The Playwright browser suite is **scaffolding only**: `playwright.config.ts`
  and the `vite dev` server exist, but `test/browser/` holds no tests.
- `test/logs/` holds generated did:webvh log artifacts from test runs; it is
  gitignored and not source.
- `pnpm test` runs fix + lint + typecheck + the node suite, then ends with
  `test:dist`, which builds `dist/` and runs `test/probe/leafClosure.mjs`, the
  runtime half of the pure-leaf isolation check. The browser suite is
  deliberately not part of it.
- The executable cross-replica conformance suite lives in the freewallet repo
  (`tests/conformance/crossReplica.test.ts`), driving both apps' engines against
  a real in-process WAS server; its results are recorded in
  [docs/cross-replica-sync-compatibility.md](docs/cross-replica-sync-compatibility.md).
