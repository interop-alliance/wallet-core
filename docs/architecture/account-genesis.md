<!-- Part of wallet-core's architecture docs. The map, the key hierarchy,
     the ceremony inventory, the permanent wire-level constants, and the
     glossary are in ../../ARCHITECTURE.md; this file holds one topic in full. -->

# Account genesis and the credential-anchored establishment

## Account genesis (`genesis/`)

A brand-new account mints its complete key set locally (`mintAccountKeySet`:
Space id, the founding client's identity seed, the user key, the did:webvh
update keys), and the caller persists those seeds durably before anything
publishes. `ensureAccountGenesis` provisions the account in the one stage order
both apps must encode identically: Space provisioning, the optional KMS
authentication binding (`provideKmsAuthentication` -- absent means the
client-keys-only genesis), did:webvh genesis, user-key roster genesis strictly
after DID publication (the roster log's entry proofs carry a versionId in the
published document), epoch[0] on every encrypted roster collection, and
Space-controller promotion. On a governed collection that epoch install is also
its declaration, the genesis of the collection's own history log, landed through
the caller's `collectionStoreFor` store. The keyring bind is deliberately not a
stage (where and whether an app binds an unlock method stays app-side), and
neither is the `userExists` probe. The KMS stage overlaps its neighbour: the
ceremony STARTS the thunk before it awaits Space provisioning and hands it that
provisioning as `spaceReady`, which the thunk's own `keys.json` write orders
itself behind. Both join before the genesis entry, which carries the binding,
and both mark `KMS_AUTHENTICATION_STAGE` at that join rather than inside the
thunk. The essential identity chain -- Space provisioning and the did:webvh
genesis -- throws on failure. Later stages are collected in `failed`, so a
completed call with failures is a resumable success a naive re-run finishes.
Promotion (`ensurePromotedSpaceController`, also exported standing alone) is a
state machine over the Space Description: promote, confirm, or heal a torn
controller PUT through a did:key-signed client. It is skippable
(`promoteController: false`) for an app whose account pointer must durably name
the DID before the controller PUT lands; that app runs promotion itself after
the write.

## The credential-anchored establishment (`clientAnnex/establish.ts`, `establishCredentialAnchoredAccount`)

Everything between a derived unlock credential and an account a transient login
can enter, with no enrolled client minted anywhere -- the shared orchestrator
over `ensureCredentialAnchoredAccountGenesis`, serving the fresh signup and the
login-time re-run alike. Six stages, each an ensure. (1) The interim bridge and
the FIRST bind through the required `bindRecord` hook. The standing-layout
unlock record (ladder seed sealed in, pointer DID-less, the bridge delegated by
the ladder VM's bare did:key) is durably written BEFORE the Space is created and
before rung 0 publishes, the transposed persist-before-publish rule. A caller
passing `priorCreatedAt` from a standing keyring hit SKIPS this stage: a
DID-less re-write could downgrade a sibling browser's completed re-bind. (2) The
shared genesis under the bootstrap did:key, promotion deferred. Its roster and
epoch failures are FATAL here, before anything names the DID, so the tear stays
the heal-able kind, a DID-less record. Collection epochs install only when the
roster's current epoch IS the candidate this run minted, the install's own mint
gate fed the landed roster. Otherwise (2c) the adopted-roster arm is the one
installer, through the shared mint-policy stage
(`clientAnnex/rosterDeliveredEpochs.ts`, `ensureRosterDeliveredEpochs`), where
epochs install under the key the roster DELIVERS rather than the minted
candidate. Both arms land epochs through the caller's `collectionStoreFor`
stores, so on a governed collection each install is that collection's log
genesis, signed by the ladder VM. The `beforeMint` seam is required, so every
caller states what licenses installing the candidate as epoch[0] on a served
absent roster; the establishment's arm refuses outright, its genesis having
adopted a present roster one read earlier. (3) The annex generation block, gated
on no `#DelegatedClients` pointer and exported standing alone as
`ensurePointedClientAnnexGeneration` for callers holding only the bootstrap
identity. Its inner mint-install-point block,
`mintPointedClientAnnexGeneration`, is shared with the transient readiness
ensure with the pointer write injected; a ceremony whose pointer move must ride
another entry atomically, the transient recovery's add-and-retire, keeps its own
inline copy (decision 0012). The annex Space resolves in the settled order:
document pointer, else the record's sibling delegation's target, else mint
fresh. The generation then mints under the bootstrap identity, the
ladder-VM-signed generation delegation embeds while the Space still answers to
the bootstrap key, the controller flips, and the pointer entry lands strictly
last. The flip tolerates only an authorization-class refusal, meaning a
concurrent run flipped first: a sibling-named Space admits that, a freshly
minted one cannot. A transport failure aborts before the pointer entry, which
would otherwise durably name a generation in a Space still answering to the bare
ladder did:key. The pointer moves as the ladder (`movePointerAsLadder`: one
ladder-signed pointer entry through the account-entry seam's ladder arm, the
transient readiness pass's shape too). Every conflict-retry attempt attributes
the ladder's current rung from the head it builds on under the caller's
chain-head pin, the rung reveals itself in the entry it signs, and a rung that
stood only committed gets the next rung's hash committed beside it. A sibling
self-enrollment spending the rung between the read and the PUT is climbed past
rather than refused after the Space and generation were minted. The rung is
attributed before anything is minted, so an account whose document no longer
anchors the ladder refuses with no Space or generation minted and before the
re-bind. The registry records the signing rung, or the ladder's currently
attributed rung when the document already pointed. The sibling arm serves
callers holding a standing invocation authority (the primitive's `invocation`
pair). Within the establishment the sibling is written only by the re-bind,
after the pointer entry, so its re-runs never converge onto a stranded Space,
and a sibling-named Space the bootstrap key can no longer write falls back to a
fresh mint. (4) The re-bind through the same hook: full pointer,
ladder-VM-signed bridge and sibling (they must survive promotion, which the
interim did:key-signed bridge cannot), and a management delegation to the
account DID -- BEFORE promotion, so the next login signs under the promoted
controller only once the record says to. (5) The caller's `beforePromotion`
hook, in the last window where a root invocation under the bootstrap did:key
works, under an asymmetric fatality contract: a throw fails the establishment,
and a best-effort hook swallows its own failures. (6) Space-controller
promotion, last, with the best-effort keystore promotion beside it
(`promoteKeystore`) when the caller's KMS stage bound a keystore this run. A
torn run converges by re-running whole, the log adopted by ladder attribution
rather than re-created. Four stated residues. A tear inside stage 3 before the
pointer entry orphans a live annex Space nothing durable names, one more per
torn attempt, the random Space id re-deriving from nothing. A tear between the
re-bind and the promotion on a KMS deployment strands the keystore's controller
on the ladder's bare did:key, outside the current-key-set rule. The other two
are the KMS stage's, both inert keys in the account's own keystore that no
document names: a tear between the key mint and the `keys.json` write, and one
orphan key per retry of a run whose Space provisioning failed fatally, which the
stage's concurrency makes reachable. None of the four has a mender built. The
account log is read once per run. The genesis returns the head it adopted or
minted (`published`, with the ETag the PUT answered with), the roster genesis
resolves its controller from that log (`rosterStoreFor({ did, log })`), the
stage-3 preamble reuses it when this run minted it and it carries an ETag, and
the pointer entry tries the threaded head once before its pinned conflict retry.
The outcome's `accountLog` is the head the run ends on, for a caller's session
memo. Reuse never crosses a writer. A log this run minted did not exist a moment
earlier, while an adopted log (the heal re-run) is read again at stage 3, since
the pointer completion test reads the document under no ETag and a stale "no
pointer yet" would mint a generation the account already has. A reused head runs
neither `verifyAccountLog`'s substituted-account refusal and chain-head
check-and-advance nor an entry writer's post-publish DID check and pin advance,
which is why only a head this run minted may be reused. The annex generation's
own log is never read: the mint hands back the head its genesis PUT wrote, ETag
included, and the delegation install stands on that. A backend serving no ETag
leaves the install reading for itself, its own entry being a compare-and-swap;
either way that publish establishes the generation's pin slot.

## The credential-anchored mend (`clientAnnex/mend.ts`, `mendCredentialAnchoredAccount`)

The sibling entry point that converges the establishment's tear states from any
door into the account, so no login path carries the tear taxonomy itself. Its
arms fire in order, each at most once per invocation, cascading within one
invocation, with deliberately no repair-wide single shot. The ESTABLISHMENT arm
fires on a DID-less pointer and probes durable state first. A log that already
resolves, attributes to this credential's ladder, AND carries the
delegated-clients pointer marks the record DOWNGRADED, and the mend re-binds it
to the published DID rather than re-running stage 1, which would die on the
promoted Space. A revealed rung with no pointer is the stage-3 tear and falls
through, with every other probe outcome, to the whole establishment run, whose
throw is caught into the report rather than propagated raw. The exception is the
probe's `ResourceLogContinuityError`, rethrown by name: a served rollback or
fork must surface as the continuity refusal it is. Convergence returns
immediately with `reenter: true`: the caller re-fetches the record through its
own keyring fetcher and re-enters, carrying the single-shot re-entry marker on
its own glue, since a mend-internal counter would reset per invocation and let a
host pinning a stale DID-less record drive an unbounded loop. A re-bind
additionally reports `reenterRepairShaped: true`, its root registry window being
closed: the re-entry must carry `repairShaped: true` for the registry arm to
fire. The PROMOTION arm mends the re-bind-to-promotion tear under the ladder
VM's bare did:key, on two triggers. One is a caller-supplied failed delegated
read: mend, retry the read once, and on a still-failing attempt or retry RETHROW
THE ORIGINAL error unchanged. The other is an authority-neutral probe treating a
null `describe()` under the bootstrap key as evidence of promotion (WAS masks
refusals), which classifies the tear only on an authorized read showing a
non-account controller. The probe direction's non-convergence is a report
member, having no antecedent error. Only a promotion that WROTE marks the entry
repair-shaped for the arms below; a `confirmed` outcome means the account was
healthy and the failed read a flap. The ROSTER-AND-EPOCHS arm is gated on the
completion test -- roster delivered AND every encrypted collection carries
epoch[0], from durable state alone, a present roster followed by the
per-collection completion probe. It runs the shared mint-policy stage
(`ensureRosterDeliveredEpochs`, the policy's one home) under the caller-supplied
post-promotion authority (the `invocation` triple and a delegated roster store,
the bootstrap `rosterStoreFor` being unable to serve a promoted Space). It mints
a fresh user key ONLY when that stage's own decide-read observes the roster
absent, and only under the mint preconditions, checked at the same mint decision
through its `beforeMint` seam: no client-local roster-epoch pin held (the
required `hasRosterEpochPin` port), no other standing credential published in
the verified document, and no encrypted collection already epoch'd or
unreadable. A fabricated-absent roster therefore cannot become a
single-recipient genesis. A lost roster-genesis race adopts and reports
converged-elsewhere, a no-wrap adoption is its own outcome, and a failed read is
transport rather than incompleteness. The REGISTRY arm re-fires the caller's
read-first `beforePromotion` hook on a repair-shaped entry (an arm mended, or
the caller's flag) under the post-promotion authority, with an
establishment-shaped context synthesized from the caller's standing record and
the log-attributed rung; the mend knows nothing of the registry protocol. Caller
obligations, as contract: the account core must come from a BINDING-VERIFIED
record, every arm past the establishment arm presupposes the caller's loud
entry, and "converged" always means the durable state the arm gated on changed.
The healthy fast path never invokes the mend at all.

## The transient readiness ensure (`clientAnnex/heal.ts`, `ensureCredentialClientAnnexGeneration`)

The pass every transient visit runs before it enrolls, mending from durable
state the six ways a visit holding nothing but the credential is cut off from
the annex or from the account log -- no `#DelegatedClients` pointer, an
auxiliary Space the server no longer has, a dead pointed generation, a stale
embedded generation delegation, a stale or mis-targeted `delegatedClients`
sibling, and a stale bridge delegation. A pointed Space that is gone is told
apart from a dead generation inside a live one by two reads rather than one, a
storage server masking an unauthorized read as the same 404 an absent Space
answers. The visit reads the Space Description through a ladder-signed GET-only
child of the Space's root and then, if that answers 404, through a root
invocation as the ladder VM's bare did:key, the controller a torn establishment
leaves behind. The Space is gone only when both answer a real 404. Status alone
decides: a 2xx is a present Space whatever its body says, and every other answer
throws, so neither a transport failure nor an unreadable body reads as absence.
The first probe presupposes a server admitting the ladder delegation clause's
single-verb predicate (was-teaching-server 0.25.0 or later). Against an older
one both reads are refused alike, a live Space reads as gone, and the visit
re-points rather than healing the dead generation inside the Space. The
fresh-Space stage is controller-first past the create. The create itself must
name the ladder VM's bare did:key, a server authorizing a create against the
controller the request body names, and the controller is flipped to the account
DID in the next request, before anything publishes. The stranding window is one
request wide, did:key-controlled inside it, which no server orphan sweep can
reap, and account-controlled past the flip, which a sweep can. The flip precedes
the generation mint because that mint rides the ladder-signed sibling
delegation, whose chain the server admits only once the Space answers to the
account DID. The bridge renewal precedes every arm. The bridge is the
credential's one write path into the account log and both minting arms end in a
pointer entry riding it, so a stale one is replaced ladder-VM-signed and the
caller's account-log store is built over the usable bridge (`idStoreFor`). An
arm that moves the `#DelegatedClients` pointer signs the pointer entry as the
ladder, attributed inside the conflict retry as `movePointerAsLadder` does
above; a self-enrollment consumes whichever rung stood revealed before it, and
the rung this entry reveals stands revealed in `updateKeys` afterwards, an
accepted cost of the pointer move. Bridge and sibling ask ONE staleness
predicate, the house policy's `standingZcapStale` (`webvh/standingZcap.ts`), and
the required `onRebindRecord` seam receives both usable delegations whenever
either was minted, so the caller re-seals the record from one pair. A failed
re-seal is fatal only when the sibling was fresh; when only the bridge was, the
failure is reported on the outcome (`bridgeResealError`), since that bridge
already served the visit and the next visit re-mints. On a healthy account the
whole stage reads the pointed generation's log ONCE: the head it reads to choose
renew-versus-mint goes to `ensureGenerationDelegationCurrent` as `published`,
and, when that pass published nothing, comes back out on the outcome's
`generationLog` for the enrollment (`enrollTransientClient`) to build its first
attempt on. A threaded head is checked against `expectedDid` as a fresh read
would be, it never touches a chain-head pin, and it is the FIRST attempt's
alone: a lost compare-and-swap means the head is stale, so the conflict retry
re-reads under the pin. That attempt is extra rather than one of the retry's
three, so it costs no conflict budget. A renewal or a fresh mint leaves
`generationLog` absent, the publish seam returning no ETag and leaving no
compare-and-swap-capable head to pass on.
