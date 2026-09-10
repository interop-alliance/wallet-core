<!-- Part of wallet-core's architecture docs. The map, the key hierarchy,
     the ceremony inventory, the permanent wire-level constants, and the
     glossary are in ../../ARCHITECTURE.md; this file holds one topic in full. -->

# The did:webvh account log (`webvh`)

## The did:webvh document is the client roster

The account's stable id is a `did:webvh` whose hash-chained log is hosted as
`did.jsonl` in the world-readable `id` collection --
`did:webvh:<scid>:<host>:space:<spaceId>:id` resolves to the log's URL with no
server-side DID support needed. A `did:web` projection (`did.json`) is kept
alongside; the log is the single source of truth.

- **Document structure.** Each enrolled client contributes its Ed25519 key under
  all four relations (`authentication`, `assertionMethod`,
  `capabilityInvocation`, `capabilityDelegation`) plus its X25519 twin under
  `keyAgreement`, the source of record for user-key wrap recipients. A standing
  credential, a recovery code included, contributes its key under `keyAgreement`
  and its ladder VM under `assertionMethod` and `capabilityDelegation`. The
  KMS-held DIDAuth signing key stands under `authentication` only. Client
  listings keyed on `capabilityInvocation` therefore exclude all of them
  structurally rather than by a filter someone must remember. That read has one
  site, `enrolledClientVmIds` (`webvh/listClients.ts`): the listing enumerates
  it, and `isLastEnrolledClient` decides the last-client rule over it for the
  plain forget (which refuses when it holds) and the last-client transition
  (which refuses when it does not). A convention that put another key under
  `capabilityInvocation` would be corrected there once, where the two
  ceremonies' opposite failures would otherwise need two separate fixes.
- **The controller marker.** A client's `keyAgreement` verification method is
  published with `controller: did:key:<its signing multibase>`, the document's
  one statement of which signing key a published key-agreement key belongs to.
  Every other method carries the account's own controller. Signing keys stay
  unmarked, since a did:key controller on a proof key breaks controller-based
  proof verification. The KMS authentication key stays unmarked as well. A
  recovery code's `keyAgreement` method is deliberately unmarked, so client
  listings and revocation removals do not match it, and so the two methods a
  recovery continuation publishes at once are told apart. The read side
  hard-requires the marker. The listing pairs a client with its key-agreement
  keys by reading the document rather than by deriving the canonical twin, and a
  client with no marked method reports an empty key-agreement set: a guessed key
  would report revocation success over a method still in the document. A
  revocation removes EVERY method the marker claims (a set filter), so a client
  with several published key-agreement keys is fully revoked. Every write site
  (genesis, enrollment, the recovery add-and-retire entry) builds the client's
  two methods through `markedVerificationMethodPair`, which refuses a
  key-agreement key that is not the signing key's canonical X25519 twin, so no
  public entry point can publish a marker the account cannot back. The pair
  travels with the relation membership every enrolled client publishes (its
  signing method under all four signing relations, its twin under
  `keyAgreement`) as one bundle, `clientAdditionFields`, the add-side twin of
  `clientRemovalFields`; a site that composed the five relations by hand could
  miss one, and a client missing `assertionMethod` or `capabilityInvocation`
  fails only later, at the server. Every entry that ADDS methods merges them in
  through `mergeVerificationMethods`, which replaces a same-id method, dedupes
  each relation, and runs a retirement predicate over the existing document
  alone. `assertCanonicalEnrollmentKeys` is the early half of the same rule,
  refusing a connect code before an approver sees it. The read side is one loop:
  the import-free `resourceLog/document.ts` leaf resolves the `keyAgreement`
  references once (`resolvedKeyAgreementMethods`, over the shared
  `KeyAgreementDocument` shape), surfaced through `webvh`, and nothing reads a
  key-agreement key any other way. The listing and revocation filter it to
  marked methods. The roster's recipient resolver keeps unmarked ones too, since
  a recovery code's method must keep its wrap.
- **Two genesis flavors.** `ensureDidWebvh`'s KMS key map (`didWebKeys`) is
  optional. A KMS-backed genesis adds the one server-held key, the KMS DIDAuth
  signing key, under `authentication` only, and records the DID in `keys.json`.
  A client-keys-only genesis supplies no map and writes no `keys.json`, since
  that record exists to bind a relation to a KMS key. Everything else is
  identical between the flavors, and every ceremony (enrollment, rotation,
  revocation, roster entry proofs) anchors in client keys, so none of them cares
  which flavor minted the account. The ladder-anchored genesis carries the same
  optional map (`createLadderAnchoredAccountLog` /
  `ensureLadderAnchoredDidWebvh`, threaded from the credential-anchored
  ceremony's `provideKmsAuthentication` stage): the keystore is created under
  the ladder VM's bare did:key, and the KMS authentication VM joins the genesis
  entry under `authentication` only. Everything else on a ladder-anchored
  document stays non-invocable. The stage is best-effort, so a failure is
  collected and the genesis proceeds keystore-less, and adoption of an
  already-published log does not edit it. A document published with no
  `authentication` relation keeps none, since no ceremony here adds the KMS key
  to a standing document. An account whose KMS stage failed presents no DIDAuth
  key for its whole life.
- **`keys.json`, and its two writes.** The map is
  `{ authentication: { vmId, kmsKeyId }, webvh: { did } }`, the one KMS binding
  plus the account DID. It is written twice per KMS-backed signup, one stage
  apart, because the DID does not exist when the binding is recorded: the KMS
  stage's create-if-absent write, then the genesis' rewrite adding the `webvh`
  block under an `If-Match` on the ETag that write returned (`writeKeysJson`,
  `decisions/0016`). The store carries no precondition of its own, since one
  fixed there would refuse the rewrite on every signup and strand a map with no
  `webvh` block, which the `expectedDid` fallback readers need. The rewrite
  CONSTRUCTS the body from those two members rather than spreading the served
  map, so any other served binding is dropped wherever a signup or an
  establishment re-run rewrites; readers ignore such a member where it stands.
- **The rewrite's lost race converges.** The genesis entry has already published
  by the time the rewrite runs, so failing a ceremony over a bookkeeping
  resource would be the wrong trade. A failed precondition re-reads the served
  map through the store's `getKeyMapRaw`: a map already naming this DID under
  this binding is left alone, and anything else is rewritten once under the
  served ETag. A second failure propagates, and so does the first against a
  store that offers no read. The adoption arm carries the other half: a re-run
  adopting a published log backfills the `webvh` block from the SERVED map's
  binding, since this run's own map may name a key that log never published. The
  tear a torn run leaves -- a map with the binding and no `webvh` block -- is
  mendable by the next establishment re-run.
- **No server-held key under `assertionMethod`.** Apart from `authentication`,
  every relation lists the enrolled clients' keys beside the standing
  credentials' ladder VMs, so no relation lists client keys exclusively.
  `assertionMethod` membership entitles a key to issue assertions as the account
  and, under the App Connect Resource Log Profile, to append to the account's
  co-managed resource logs. So no server-held key may appear there. Server-side
  issuance, if ever needed, signs under a separate issuer DID rather than the
  account DID.
- **The current-key-set rule.** An invocation or delegation verifies iff its
  verification method is in the resolved document _now_, under the relation its
  purpose needs: `capabilityInvocation` for an invocation,
  `capabilityDelegation` for a delegation. A key kept under another relation
  alone authorizes nothing, which is what `delegationKeyInDocument` tests. This
  is why client revocation is a single document edit with no per-collection
  revoke anywhere: the edit is the revoked client's pull axis everywhere.
- **Update keys are client-held**, one per enrolled client, and not the KMS's --
  the server cannot extend the log, which is what makes it the one
  self-certifying artifact the server hosts.
- **Prerotation carry-over convention.** `nextKeyHashes` commits every client's
  staged key AND every active key's own hash; without the carry-over hashes no
  non-rotating entry (an enrollment, a document edit) could ever resolve under
  prerotation.
- **Log attribution.** The flat `updateKeys` set has no per-client grouping, so
  a client's active update key and enrollment moment are recovered by
  attributing log entries: the entry that published its verification methods
  revealed its initial key, and an entry retiring the attributed key while
  revealing exactly one replacement is its self-rotation. Ambiguous attribution
  yields `undefined` or a refusal rather than a guess, since removing the wrong
  key would revoke a different client.
- **Revocation** (`revokeWebvhClient`) removes, in one entry: the signing
  method, every `keyAgreement` method the client's controller marker claims
  (read off the document, so a stale or absent key-agreement key in the caller's
  snapshot cannot leave a live method behind), the update key, and **both**
  standing `nextKeyHashes` commitments. The staged hash removal is the subtle
  half, since a hash left committed is a standing re-seizure credential under
  the reveal mechanism. The latent commitments a staged-hash attribution must
  exclude (a standing credential's own committed rungs) are derived from the log
  itself, by walking every standing credential's ladder from its bind entry
  (`standingCredentialLatentHashes`). A caller's own list is excluded beside
  them as a cross-check rather than trusted alone, and a credential whose walk
  could not be read is logged instead of being read as having no latent hashes.
  The derived set never removes the candidate the `decisions/0007` position
  names: the seedless walk can over-claim a torn self-enrollment's orphan hashes
  as rungs, and an exclusion that ate the positional answer would leave the
  removed client's staged commitment standing.
- **Conditional publish.** Every ceremony publishes `did.jsonl` as a
  compare-and-swap on the ETag of the read its entry was built on, the initial
  provisioning as a create-if-absent, so two ceremonies racing on one log cannot
  silently erase each other. The loser gets a typed `WebvhLogConflictError` and
  re-runs itself from the top (`withLogConflictRetry`, three attempts). The
  re-run IS the rebase, since every ceremony re-reads the head and detects its
  own completion from durable state. The `did.json` PUT stays unconditional by
  design: it is serialized behind the won log CAS, and the log is the source of
  truth. Against a backend without the `conditional-writes` feature no ETag is
  served and the publish degrades to an unconditional write.
- **The `did:web` projection's freshness.** `publishEntryPinned` writes the log
  alone, since a bridge-delegated caller is authorized for nothing else. So a
  ladder-signed entry does not republish `did.json`, and the projection can name
  a client or a credential the log has since removed. The server resolves the
  controller out of `did.jsonl`, so WAS authorization is unaffected. A did:web
  verifier reading the stale document is not, which makes the lag a revocation
  bypass. Two writers close it. The removal ceremonies (`forgetEnrolledClient`,
  `forgetLastEnrolledClient`) PUT the POST-removal projection through a
  root-invoking store immediately BEFORE their ladder-signed removal entry,
  since the client's authority ends at that entry (`clientForgetEntryOnce`'s
  `beforePublish` seam). And `ensureDidWebProjection` re-derives the projection
  from a resolved log, compares it against what the host serves, and republishes
  only on a difference. Any `id`-collection writer runs it. On a client-less
  account that is a transient visit under its generation delegation, which
  covers `id/did.json` through the account Space's items subtree with no widened
  bridge and no server change. The idempotent already-forgotten path writes no
  projection, since the store handed in is authorized for nothing, and the next
  transient visit's ensure is the mender. `concludeWithPublishedLog` stays the
  controller-invoking paths' unconditional republish. Since a difference alone
  does not say which side is stale, the ensure calls the caller's optional
  `refresh`, a fresh resolution of the same log, and writes only when the
  refreshed derivation still differs. Its PUT carries the served read's ETag as
  `ifMatch`, or `ifNoneMatch` when the projection was absent, so a projection
  written in between stands and the outcome is `conflict` rather than a throw.
  Two windows remain. Between a ladder-signed entry and the next visit that runs
  the ensure, the served projection is stale. And a removal run torn between its
  projection PUT and its entry leaves `did.json` omitting a client the log still
  lists, fail-closed for a did:web verifier and re-PUT by the re-run.
- `verifyLog.ts` fetches the world-readable log unauthenticated on purpose (the
  hash chain is the trust, not the channel), resolves locally, and refuses a log
  resolving to a DID other than the account pointer's. Every ceremony runs this
  first; `listClients.ts` deliberately takes an already-verified log.
- **The account log's chain-head pin.** Resolution alone is one-shot. A valid
  PREFIX of the real log carries the same genesis, so the same SCID and DID, and
  a ceremony built on it republishes truncated-log-plus-one-entry as durable
  state: erased enrollments and undone revocations. So the account log takes the
  governed resource logs' continuity guard, through the same seam and refusal
  class (`ResourceLogPinStore`, `ResourceLogContinuityError`). Its reads refuse
  a served `rollback`, a `fork` (served entries ride along as equivocation
  evidence), or an SCID/`method-switch`. The pin `{ method, scid, head }` comes
  from the genesis parameters and the latest `versionId`. It is persisted
  app-side beside the account-pointer pin, established at first contact
  (trust-on-first-use), and advanced only by a log verifying past it. It does
  not regress. `rollback` is the one reason that may be mere replication lag:
  nothing rolled back is adopted, and a caller with a cached document view may
  carry on with what it has.

  The pin is a property of the store, not a ceremony argument. `WebvhIdStore`
  carries a required `pin: { store, logId }` member. Each constructor takes the
  pin store and derives the slot from the collection it serves
  (`wasWebvhIdStore` and `delegatedWebvhLogStore` over the account log,
  `wasWebvhLogStore` and `clientAnnexLogStore` over an annex generation's), so
  no ceremony signature names the pin and no caller pairs a store with the wrong
  slot. Every read through the seam (`readPublishedLog`,
  `readPublishedLogOrThrow`) checks the served log against the pin and advances
  it. Every publish (`putLogResource`, so `publishEntryPinned` and the
  account-entry seam's publish tail too) advances it to the log just written. So
  no ceremony can read the log unpinned or leave a pin standing behind an entry
  this client wrote. A defaulted in-memory pin store belongs to the test fixture
  alone. `verifyAccountLog` is the only reader still taking a `pinStore`
  argument, since it fetches the world-readable log by URL and holds no store; a
  ceremony that holds a store hands it that store's pin store. The annex is the
  one carve-out: a generation is deleted by design, so reads that must tell a
  dead or absent generation from a live one go through
  `readClientAnnexLogOrAbsent`, the pinned read's absence-tolerant mode
  (`absentUnderPin: 'absent'`), where a genuinely absent log reads as absence
  with the pin standing and a served prefix stays refused. Annex logs pin in the
  account-log store's pin store (`idStore.pin.store`), so one client cannot
  split its two log families across two stores.

  `ResourceLogPinStore` is keyed: `read` and `write` both take a `logId`, so one
  instance serves the account log and every governed log a wallet holds without
  cross-pinning them. Every log store derives its slot through the one
  `logResourcePinId` builder in `webvh`, and the library builds the key.
  `resourceLogPinId({ spaceId, collectionId, resourceId })` in
  `@interop/vh-resource-log` is the generic builder,
  `accountLogPinId({ spaceId })` in `webvh` names the account log's slot, and
  `collectionDescriptorLogPinId({ spaceId, collectionId })` in `descriptors`
  names a collection descriptor log's slot over the library's
  `collectionLogPinId`, resolving to `space/<spaceId>/<collectionId>/meta/log`,
  the log's own home inside the collection it governs. The shape is host-free by
  design: the Space id stays stable across a claimed host move, so a log served
  from a new host lands in the SAME slot and is checked against the held pin,
  rather than opening a fresh trust-on-first-use slate. `verifyAccountLog`
  derives its `logId` from the `spaceId` it is given.

  `readPublishedLog` carries the other half of the check beside the pin: an
  optional `expectedDid` the ceremony's own read of `did.jsonl` must resolve to,
  passed wherever the account DID is in scope, a mid-flight re-read included. It
  stays a per-ceremony argument, since which DID a read must land on is ceremony
  semantics. Under a held pin an absent log refuses as a `rollback` too, since a
  full truncation is not "not yet provisioned". The one documented exemption
  from the DID check is `ensureDidWebvh`'s first-contact adoption with no
  caller-supplied DID and no `keys.json` webvh block, which legitimately
  discovers the DID from the log itself and establishes the pin. The create path
  pins the log it just minted, so first contact is not left to the next read.
  `readPublishedLog` and its throwing twin are typed to `getIdResourceRaw` and
  `pin` alone, so a store lacking the rest of the seam needs no cast.

## Update-key rotation (`webvh/didWebvh.ts`, `rotateWebvhUpdateKey`)

The user-triggered rotation of one enrolled client's did:webvh update key. The
staged key reveals itself to sign its own activation and becomes the client's
sole active update key, a freshly minted staged key's hash is committed as the
new `nextKeyHashes` entry, and the caller's persisted seeds roll forward. The
published DID does not change, and no KMS or `keys.json` is involved. Divergence
is refused before anything is persisted or published: the log must still
authorize this client's active key and commit its staged key's hash. The
ceremony has one arm, since it keeps `updateKeys` directly rather than signing
through `signAccountEntry`.

The pivot is the rotation entry. The new staged seed is persisted through
`persistUpdateKeys` before it, the persist-before-publish rule, and the finalize
after it is re-derived on the next run from the published log alone: a log
already sitting at the staged key has its seeds rolled forward locally without
another entry. A lost compare-and-swap re-runs from the top and mints a fresh
staged seed, so the cost of a torn rotation is one unused staged key. No
invariant in the census names this ceremony; its mender is the converging
re-run.

## The account-log signer seam (`webvh/accountEntry.ts`, `signAccountEntry`)

who signs an account-log entry is a parameter of every ceremony body, not a fact
about it. `AccountLogSigner` is the discriminated union
`{ kind: 'client', updateKeys }` | `{ kind: 'ladder', ladderSeed }`, and one
`build` callback describes the document delta once for both arms
(`decisions/0018`). The seam signs under one more arm no ceremony body accepts,
`AccountEntrySigner`'s `{ kind: 'committed', updateSeed }`: a bare update key
the published log commits or already authorizes, revealing itself with the
ladder arm's unions and no attribution first. The recovery continuation's two
entries are that arm. The client arm carries the active key derived from the
seed and checked against the published `updateKeys`, the carry-over
precondition, the entry's own stated parameters, and `did.jsonl` published
beside its `did:web` projection. The ladder arm signs through the record's
bridge delegation: the rung attributed from the log (fail-closed), the acting
rung unioned back into `updateKeys`, its carry-over hash before the build's own
`commitHashes` in `decisions/0007` order, and `did.jsonl` alone. That is the
bridge's whole reach, so the projection is the ceremony's own pre-entry PUT or
the next visit's ensure. Both arms take the caller's chain-head pin and advance
it, publish conditionally on the read the entry was built on, and leave the
conflict retry to the caller. Two rules follow from the arm's self-reveal. An
entry cannot remove its own signer, so a ceremony that retires a rung needs a
second entry signed by the successor. And a rung is reused rather than consumed:
attribution prefers a revealed rung over a committed one, so rung 0 stands
revealed in the world-readable `updateKeys` for the credential's life and no
single-entry ceremony gets prerotation over it. That is an accepted cost: an
attacker holding a rung's private half already holds the seed that yields every
rung. `ladderSignedAccountEntry` (`clientAnnex/ladderAnchored.ts`) is the seam's
ladder arm under the annex's own name. `rotateWebvhUpdateKey` keeps `updateKeys`
directly, since that key is its subject.
