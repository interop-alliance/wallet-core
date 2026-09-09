<!-- Part of wallet-core's architecture docs. The map, the key hierarchy,
     the ceremony inventory, the permanent wire-level constants, and the
     glossary are in ../../ARCHITECTURE.md; this file holds one topic in full. -->

# The user key roster and the descriptor logs (`keys`, `descriptors`)

## The user key roster: delivery, never source

The roster is **log-governed**: its resource is the resource log
`key-map/user-key.jsonl` (the Resource Log Profile), the log being the roster's
only serving. `keys/rosterLogStore.ts` (`logGovernedDescriptorStore`, built for
the roster by `keys/rosterStore.ts`) wraps `@interop/was-client/edv`'s generic
store of the same name with the post-edit minimum controller version, and
exposes the log as an ordinary `EncryptionDescriptorStore`. Reads resolve to the
VERIFIED head entry's state, with chain, proofs, external authorization, and the
chain-head pin checked by the `@interop/vh-resource-log` verifier first; a head
state whose `type` is not `WasEpochConfiguration` is refused. Writes become
signed log appends. The seam is unchanged, so was-client's roster machinery
(`initRecipients` / `addRecipient` / `removeRecipient` and their
compare-and-swap retry loops) drives the log without knowing it. A CAS conflict
on the log (`ResourceLogConflictError`, minted by the store adapter) is
translated at this boundary to the `PreconditionFailedError` those loops already
rebase on.

The controller view is resolved per operation rather than held, so a revoking
client that just edited the account document writes its roster rotation carrying
the post-edit head -- the sealing append. The store also carries a minimum
controller version (`setMinimumControllerVersion` on the sealable store), and a
resolved view at or past it supersedes a cached pre-edit one, so the rotation
and the seal backstop cannot carry a version before the removal they must seal.
The revocation cascade sets that minimum from its document edit's post-edit log,
the ladder-signed enrollment approval from its post-add log before its escrow
append, and the two forget ceremonies through the shared recipient-retiring
cascade tail (`retireRosterRecipientAndCascade`), which is how the last-client
transition anchors its roster append at the reinstall version.

Client-side guards against a tampering host, layered:

1. **The resource log itself** -- roster state is adopted only from a verified
   log head. Entry proofs must be signed by keys the independently verified
   did:webvh document lists under `assertionMethod` at the entry's controller
   versionId (`ResourceLogIntegrityError`), and the chain-head pin refuses
   rollbacks, forks, and SCID/method switches (`ResourceLogContinuityError`).
   The roster log's pin rides the same keyed `ResourceLogPinStore` as the
   account log, under its own slot (`userKeyRosterPinId({ spaceId })`).
   `isResourceLogRefusal` (`@interop/vh-resource-log`'s, re-exported by
   `resourceLog/errors.ts`) is the one implementation of which refusals a reader
   must not paper over with a cached copy. The pin's `rollback` reason gets a
   carve-out everywhere a pin is consulted: it is reconcilable divergence,
   possibly replication lag, nothing rolled back is adopted, and the pin does
   not regress. So the login policy (`clients/rosterPolicy.ts`) degrades it to
   the cached user key instead of refusing the session. A `fork` or SCID/method
   switch stays a refusal. A caller adds only the names the generic taxonomy
   lacks (`isRosterRefusal`'s three `UserKeyRoster*` classes), or declines the
   carve-out explicitly, as `clientAnnex/mend.ts`'s establishment probe does: it
   holds no cached copy to degrade to, so every continuity reason rethrows
   there.

   `ResourceLogLicenseError` is deliberately not in that predicate, so a license
   refusal met on a READ lands in the soft transport class (warn, serve cached).
   The log is not corrupt and the signer genuinely holds the credential, so the
   append is unlicensed rather than forged, and the class does its work
   pre-write. Two shapes arguing for hard-refusing were weighed and accepted: a
   compromised but still-listed key holder, and a genuine unlicensed entry N
   masking a forged entry N+1 under whole-log first-failure semantics.

2. **The epoch pin** -- the app pins the latest-seen roster epoch beside the
   account-pointer pin; a served roster that rolls back behind the pin is
   refused (`UserKeyRosterContinuityError`). It still guards a client whose
   chain-head pin was lost with a reinstall. Its refusal is not softened by the
   rollback carve-out above: with no chain to compare, it cannot tell a rollback
   from a fork.
3. **The document-backed recipient resolver** -- recipient keys come from the
   locally verified did:webvh document rather than from the roster itself. A
   roster entry with no matching `keyAgreement` verification method is dropped
   and receives no wrap. A method carrying the key verbatim matches on the
   multibase. A method carrying only a hash commitment (`publicKeyCommitment`, a
   low-entropy-derived standing unlock credential whose key material the
   document withholds) backs an entry exactly when a published commitment
   commits to the entry's own key. The check decodes the commitment's multihash
   and compares digests, so an unsupported or malformed commitment backs
   nothing. A server-injected entry can neither meet a standing commitment nor
   add one.

Every consumer that dispatches on these refusal classes matches on `err.name`
rather than `instanceof` (the rule `resourceLog/errors.ts` and
`StagedCommitmentAmbiguousError` document): the errors are raised inside
app-injected seams that can resolve to a different copy of this package, so an
`instanceof` miss would drop a security refusal into a warn-and-proceed
transport branch. Each class's `name` is a stable contract. The sync engine's
three wire signals are matched the same way (see "The sync engine" in
sync-engine.md).

`rosterRecipientKid` is the one builder of a client's roster kid, shared by the
enrollment wrap and the read path. Retiring a client names no kid at all:
`convergeUserKeyRosterToDocument` rotates away from every recipient the document
no longer keys, so no caller has to pair a client with its key-agreement key.

That convergence runs in TWO directions. The escrow direction is the retire
direction's mirror: an enrolled client the document keys that holds no wrap in
the current epoch is escrowed into every epoch (`enrolledClientRosterRecipients`
rebuilds its kid from the controller marker and the key-agreement method the
document carries). It mends a ceremony torn between the entry that published a
client and the append that was to wrap the user key to it, the one-request
window a ladder-signed enrollment approval leaves. A convergence needing both
directions rides one write. A pure escrow adds wraps without minting an epoch,
so a missing wrap does not rotate the user key, and a healthy roster writes
nothing. A standing unlock credential is not a candidate: its roster kid names
its standing client's SIGNING key while the document publishes only its
key-agreement half, so no reader can rebuild the kid. Its missing wrap is mended
by the ceremony that holds the credential. The escrow direction runs for a
caller supplying a key that unwraps every epoch.

**The sealing sweep.** After a document edit removes a client's
`assertionMethod` key, every governed log must gain an entry carrying a
controller version at or past the post-edit version -- the sealing append of the
profile's `#log-authorization` rule, proving the surviving writers extended the
log under the new membership. An ordinary post-edit rotation IS that append. The
gap is a rotation that no-ops because the retiree held no current-epoch wrap:
`removeRecipient` appends nothing, and the head keeps carrying the pre-removal
version. The library's seal (`sealResourceLog` / `latestAssertionRemovalIndex`,
`@interop/vh-resource-log`) closes it from durable state alone. "Unsealed" is
exactly "the verified head's controller version index
(`headControllerVersionIndex`) precedes the latest controller version whose
`assertionMethod` set lost a member", and the remedy is an idempotent no-op
append of the head state verbatim. The store exposes the sweep through the
descriptor-store seam (`seal()`, `SealableEncryptionDescriptorStore` /
`isSealableDescriptorStore`). The revocation cascade runs it as a best-effort
reported backstop (`rosterSeal`, in `cascadeCompletion`), the login sweep
(`convergeUserKeyRosterToAccount`) converges it after recipient convergence, and
the collection cascade's no-op path seals sealable stores (outcome `sealed`). A
spent recovery code's removal registers as one, since a code's ladder VM stands
under `assertionMethod`, and its mandatory post-spend rotation is that seal.

**The ceremony-tail license.** What a LADDER-SIGNED append may do (clause B of
the ladder VM's authority clauses, app-connect-spec
`decisions/0003-ladder-authority-clauses.md`). It binds ONE class of log, the
user key roster's. A per-collection encryption descriptor log carries the other
class, admitting a ladder-signed append on `assertionMethod` membership alone
(`decisions/0013`). Without a bound, a ladder VM standing under
`assertionMethod` for its credential's life could silently append a roster
rotation rekeying the account to a credential thief's recipients. The license
admits a ladder-signed append in exactly three shapes. Shape 1 is the log's
first entry. Shape 2 is a rotation carrying an inventory-changing document
version: S(V), the `keyAgreement` methods controlled by the account DID
(`Multikey` and `MultikeyCommitment` alike) union the ladder VMs, differs from
S(V-1) in either direction. Ordinary client enroll/revoke is excluded
structurally by the `did:key` controller marker. Shape 3 is a rotation carrying
a version whose ENROLLED-CLIENT set (the `capabilityInvocation` methods,
equivalently the marked `keyAgreement` twins) differs from V-1's, in either
direction, AND whose entry a rung of the appending ladder signed. Shapes 2 and 3
are one-shot: refused when the verified head already carries that version or
later (`headControllerVersionIndex >= indexOf(V)`, position in the verified
version history, exactly the sealing comparison). All three carry a per-entry
rule: at most one of an entry's proofs may be by a ladder key, since every proof
of an entry shares one controller version and a co-signing ladder key would
spend it a second time. Proof order is not integrity-bound, so the count is read
as a set (`proofKeys`, the hook's entry-level view) and the refusal lands on
whichever ladder proof is admitted first. A ladder rotation co-signed by an
ordinary member stays licensed. So a rotation against an unchanged document (the
silent-rekey shape) is refused by every verifier, while a torn ceremony's
late-arriving tail still passes.

Shape 3's signer conjunct keeps it out of the any-`keyAgreement`-change
predicate the clause rejects. A client's own enrollment or revocation entry is
client-signed, so it mints no shot for any ladder. Only a ladder-signed
enrollment or removal mints one, and only for the ladder that signed it.
Otherwise an owner's ordinary enrollment of a phone from a remembered session
would mint a shot a phished credential's ladder could spend on a silent rekey.
Whose rung signed a version is read from the log alone
(`resourceLog/ladderRungs.ts`, exposed as `ladderRungKeys` on the controller
inventory), since a verifier holds no ladder seed. A ladder is anchored at the
entry that introduces its VM, either by the rung that entry reveals and is
signed by, or by the single rung-0 hash that entry commits, taken up when a
later entry authorizes its pre-image. A key another ladder already holds anchors
nothing, so a ladder-branch bind anchors the newcomer on its committed rung-0
hash while the acting ladder climbs. An entry that also publishes an enrolled
client anchors no ladder, since the one key it authorizes is that client's. The
ladder then CLIMBS with the log, by the last-position rule of
`decisions/0007-ladder-reveal-hash-order.md` read forward: an entry authorizing
exactly one new update key that signed it is a prerotation reveal, and when that
key's hash was committed LAST among some earlier entry's additions, and that
earlier entry itself authorized exactly one key and was signed by it, the
revealed key is the next rung of that key's ladder. The step is taken only while
the ladder's own VM still stands in the revealing entry's document, which keeps
a recovery spend's handover out: the spent credential's reveal entry commits the
REPLACEMENT's hash last, and the entry revealing that hash is the one that
strikes the spent credential's ladder VM. The climb is what a self-enrollment
needs, since it retires the rung it spends. Without it the ladder would freeze
at a key the account no longer authorizes, and no later ladder-signed enrollment
or disconnect of that credential could satisfy shape 3. A hash committed
anywhere but last is never climbed, so an enrollment approval -- which reuses
its rung and commits the client's update-key hash first -- has no client key
read as a rung. Every other shape leaves the ladder unattributed, and an
unattributed ladder does not satisfy shape 3.

Shape 3 is a verifier-side rule on an append-only log, so its rollout is
verifier-first: every reader of a roster log ships shape 3 before any writer
emits an append that needs it. A reader without it refuses the whole log rather
than the append, since the license throws from the admission hook and the
verifier propagates that throw.

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
unlicensed append from the integrity class's reject-the-whole-log verdict. One
predicate (`assertLadderAppendLicensed`) enforces it, behind the controller
port's `admitAppend` admission hook that `webvhResourceLogController` supplies,
consulted per proof after the entry's proofs verify. It runs on read-back and
pre-write alike (`verifyResourceLogAppend`, which the log-governed store's
`replace` calls, so a conformant writer is refused before an unlicensed entry
lands and poisons the served log; `create` runs the same check over the genesis
as a one-entry log). The library carries no license of its own, so a controller
port over a document that can list ladder VMs -- any account did:webvh document
-- MUST supply the hook, and the hook is a side-effect-free function of the view
and its input. The wallet-core extension (`WebvhResourceLogController`) is
inventory-aware for it: `inventoryAt` exposes the per-version ladder keys and
inventory set the `assertionMethod` accessor cannot show, read through the
shared account-document leaf (`resourceLog/document.ts`), so the relation
asymmetry that names a ladder VM has one implementation here and in the client
listing. The extension stays on the store types because the resolver returns it
and the hook lives on it. Whether a license refusal should become a soft class
is an open question, over the pre-write refusal alone.

The last-client transition's strike-and-reinstall pair leaves the predicate
unchanged. Ladder VM keys are inventory members, so both entries are
inventory-changing versions, and the clause licenses one ladder-signed roster
append at each rather than the one the design budgeted. That second shot is
accepted. It adds no class, since the clause already licenses every standing
ladder VM against any inventory-changing version, whoever published it, and the
reinstall version's shot is the one the transition's own rotation needs.
Narrowing the clause to versions that ADD an inventory member would close the
strike shot and leave the other open, taking nothing from a thief while moving a
normative predicate. The exposure is bounded by the rest. A sibling's append is
signed by that credential's ladder VM and stands in the roster log, so it is
attributable. A rotation wraps only to recipients the verified document lists.
The stolen credential's standing wrap already opens every epoch, so a rekey
hands its holder no ciphertext they could read already. And credential rotation
is reachable from a credential-only session, so the remedy does not wait on an
enrolled client. Both shots close when the transition's rotation lands at the
reinstall version, or at the re-run.

**Per-collection descriptor logs.** Every encrypted wallet collection's
`encryption` descriptor is governed by a resource log of its own, at the
collection's `meta/log` sub-resource (`COLLECTION_HISTORY_LOG_SUBRESOURCE`, the
WAS spec's Collection Governing History Log). `keys/collectionLogStore.ts`
builds `collectionDescriptorLogStore` over it, the roster builder's sibling over
the same wrapped `logGovernedDescriptorStore`: reads resolve to the verified
head, writes are signed appends, `create` is the guarded genesis, and the store
is sealable.

The placement buys the reader's authority for free. A share grantee or a
connected app already holds a read capability over the collection's URL subtree,
so the grant that lets them read the collection lets them verify its
descriptor's history, with no second grant and no capability over the account's
`key-map` collection. A sub-resource under the reserved `meta` segment is not a
Resource of the collection, so it is absent from listings and from the changes
feed and replication never ships it, and it is exempt from the envelope rule, so
the log stays plaintext JSON Lines rather than being refused as a non-envelope
body.

The server derives the Collection Description's `encryption` member from the log
head, so the wallet writes the log alone. That is why an encrypted collection is
created bare: a Description already carrying a client-written descriptor cannot
be governed, and the server refuses a direct `encryption` write on a governed
collection's Description. Provisioning creates such a collection with
`encryption: 'governed'`, and the epoch[0] install is the guarded create
(`If-None-Match: *`) that both declares the collection governed and lands its
first epoch as the log's genesis entry. A re-run over an existing log adopts its
head untouched, and a lost create race resolves the winner's descriptor the same
way, so exactly one epoch[0] ever exists per collection.

The store states its log class at construction (`collection-descriptor`) and
applies it to every controller view it resolves (`controllerForLogClass`), so
read-side verification and write-side admission run under one rule:
`assertionMethod` membership at the anchored version, with no shape check and no
one-shot. A descriptor append escrows one recipient into one collection and
lands as a hash-chained entry attributable to the credential that signed it, so
it needs no silent-rekey bound. A reader that inherited the roster's rule would
refuse a served log its own wallet wrote, so the narrowing runs on the read path
too (`logGovernedDescriptorSource`). The signer is the same `ResourceLogSigner`
seam the roster takes: an enrolled client's account key
(`userKeyRosterLogSigner`), or a standing credential's ladder VM on a
credential-anchored account. Each log pins in its own slot of the one keyed
`ResourceLogPinStore` a client holds (`collectionDescriptorLogPinId`), derived
from the collection handle, so no two logs cross-pin.

The rotation cascade is these logs' sealing pass, since a collection's log owes
an entry at or past a post-edit version exactly as the roster's does.
`anchorRosterStoreAt` returns the view it built from the ceremony's own
post-edit log, both cascade entry points thread it into the fan-out, and
`cascadeCollectionsToUserKey` sets it as each sealable collection store's
minimum controller version before that collection's first append. A store
resolving a stale cached view would otherwise anchor its rotation before the
edit, sealing nothing, and a ladder-signed append there would be refused for
naming a version the edit is not in. The no-op path seals such a store rather
than leaving the log unsealed (outcome `sealed`).

What a consumer owes. Build each collection's store with
`collectionDescriptorLogStore`, and hand the lookup to whatever installs or
rotates epochs: `storeFor` on `ensureWalletSpaceEpochs`,
`walletSpaceProvisioner`, and `ensureRosterDeliveredEpochs`, and
`collectionStoreFor` on the two geneses and the mend. Do not carry the served
`encryption` member back to the server: `Collection.configure` merges every
current field forward, so a `configure({ name })` on a governed collection would
PUT the derived descriptor and be refused.

**The delegation clause's locked property.** The other authority axis, clause A,
governs what a ladder-signed DELEGATION may authorize, and the storage server's
client-annex clause enforces it. The property the clause locks: a ladder
delegation either needs a loud companion entry to resolve, or can only write a
log, or is a target-exact single-verb read or delete of one Space of the
delegator's own account. That third predicate admits the single-verb Space
children (`clientAnnex/spaceCapability.ts`): a child whose `invocationTarget` is
one bare Space URL, unchanged from its parent's, and whose action set is exactly
`['DELETE']` or exactly `['GET']`. That delete is the one ladder authority whose
exercise leaves no record anywhere. Every other ladder-signed authority is loud
by construction, and a destroyed Space cannot carry the entry that would have
announced it. The trade is stated in the account deletion design that asked for
it.

## Descriptors and the unknown-epoch refresh

A collection's `CollectionEncryption` descriptor is its **key-epoch roster**:
which epoch it encrypts under. The one shared implementation of "which epoch,
and when do we ask again" lives in `@interop/was-client/edv`, since every
consumer of an encrypted collection needs it: the `EncryptionDescriptorSource` /
`EncryptionDescriptorCache` seams, `acquireDescriptor` (fetch, cache the
success, fall back to the cache whenever the fetch yields no descriptor, so
offline keeps encrypting under the current epoch), `DescriptorRefreshPolicy`
(the once-per-collection-per-session unknown-epoch refresh guard, since an epoch
rotation emits no change-feed entry and a genuinely foreign envelope must not
drive a refetch loop), and `createRefreshingEdvDocCipher` (the cipher bound to
both, refusing fail-closed to build without a descriptor). `acquireDescriptor`
treats the resource-log refusal classes as security signals rather than outages,
rethrowing them past a warm cache through the library's `isResourceLogRefusal`,
with the continuity `rollback` as the one carve-out. This module re-exports none
of that: one owner per name (see "The sync engine" in sync-engine.md).

What stays here is the wallet's implementation of the source seam. For a
collection whose descriptor is governed by a resource log,
`logGovernedDescriptorSource` is the `EncryptionDescriptorSource`. Every
acquisition, the unknown-epoch refresh's re-read included, re-verifies the log
through the `@interop/vh-resource-log` verifier (chain, proofs, external
authorization, the chain-head pin) and resolves to its verified head state,
refusing a head that is not a `WasEpochConfiguration`. That governed read
boundary exists once, in `@interop/was-client/edv`
(`readGovernedEpochConfiguration`, re-exported by `descriptors/logSource.ts`):
the roster's log-governed descriptor store and was-client's own
pointer-following collection store read through the same helper, so a hardening
reaches every trusted descriptor read. The source takes one keyed `pinStore`
shared across every collection it serves, plus the Space id. Each collection's
slot is `collectionDescriptorLogPinId({ spaceId, collectionId })`, resolving to
`space/<spaceId>/<collectionId>/meta/log` -- host-free like the account and
roster log slots, and following the log's own home, the `meta/log` sub-resource
of the collection it governs. A sub-resource under the reserved `meta` segment
is outside the collection's Resources, so it is neither sealed by the
collection's own encryption nor replicated with it. Every read here runs under
the `collection-descriptor` log class (`controllerForLogClass`), so a
ladder-signed append verifies on `assertionMethod` membership alone and a reader
does not inherit the roster's ceremony-tail license. A governed collection plugs
this source into the refresh-guard policy and the cipher, both untouched.

A decrypt that finds no key fails in two distinguishable ways, and a host
scanning rows must tell them apart: `UnknownEpochError` (the envelope's epoch is
not on the descriptor this reader holds, so a re-read may fix it) and
`KeyUnwrapError` (the epoch IS listed, but this reader was never a recipient, or
was removed and the epoch rotated). Neither row is garbage. Both are matched on
`err.name`, since the cipher is an injected seam, and both matchers ship from
was-client beside the classes whose names they compare: `isKeyUnwrapError` (on
`./edv` and `./sync`) and `isUnknownEpochError`. A scan that misses
`KeyUnwrapError` drops a real, permanently-unreadable row into its undecryptable
bucket, which a host is entitled to purge.
