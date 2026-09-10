<!-- Part of wallet-core's architecture docs. The map, the key hierarchy,
     the ceremony inventory, the permanent wire-level constants, and the
     glossary are in ../../ARCHITECTURE.md; this file holds one topic in full. -->

# Client revocation, credential retirement, and forget

## Client revocation (`clients/revocation.ts`, `revokeAccountClient`)

Runs in dependency order. (1) The single document edit, the pull axis
everywhere. (2) The roster rotation (`convergeUserKeyRosterToDocument`): one
rotation retiring every current-epoch recipient the post-edit document no longer
keys, naming no client. Then the roster log's seal backstop, best-effort,
reported in `rosterSeal` rather than thrown. Before any of stage 2 runs, the
orchestrator sets the roster store's minimum controller version from the edit's
post-edit log, so the rotation and the seal carry a version at or past the
removal even under a stale injected controller resolution, and threads that view
into stage 3. (3) The parallel per-collection re-epoch fan-out, each
log-governed collection store anchored at that post-edit view before its first
append, failures collected without aborting. (4) The optional
`remintGenerationDelegation` closure, run on the post-edit document in the
rotated and the no-roster paths alike, its result riding the outcome as
`generation`, so revoking the client that signed the current generation
delegation replaces it in place instead of killing the transient entry path
silently mid-generation. Then `onRotationAdopted` lets the revoking session
adopt the fresh key in place. The cascade writes no unlock record, since each is
signed by its own credential (`decisions/0019`). A cascade whose fan-out left
failures behind is a resumable success rather than an error
(`cascadeCompletion`): the wallet IS disconnected once stage 1 lands, and a
re-run or the login sweep finishes the remainder. Disconnect eligibility is pure
policy data (`clients/policy.ts`): `self`, `last-client`, and
`unattributed-update-key` refusals. `signerKind: 'ladder'` lifts the first two,
which are properties of the acting signer rather than of the account
(`decisions/0017`): a standing credential's rung has no self, and removing the
last client abandons no update authority, since the account lands
ladder-anchored and the credential's own ladder extends the log from there. The
document edit splits the same way. The self-revocation refusal inside
`revokeWebvhClient` is a client-arm check on the signer's own active key, and
the ladder arm has no self. The unattributed-update-key refusal stands on both
arms, as does the staged-hash strike.

The pivot is the removal entry, stage 1, on both signer arms (`decisions/0017`).
Stages 2 through 4 are post-pivot and re-derivable from the post-edit document,
the generation remint included, which runs after the strike rather than before
it. The one pre-pivot server write is the ladder arm's `did:web` projection PUT.
It under-lists authority until the entry lands and `ensureDidWebProjection`
re-derives it, so a tear there costs nothing. Invariants a torn run can leave
violated (numbered as in `INVARIANT_IDS`, `menders/ids.ts`): 1
`roster-wraps-exactly-the-document-key-set`, 2
`governed-log-heads-anchor-past-the-membership-change`, 3
`collection-epochs-name-the-current-user-key`, 4
`unlock-registry-opens-under-the-current-user-key`, 8
`standing-delegations-verify-under-the-current-document`, 16
`generation-delegation-is-current`, 18 `did-web-projection-matches-the-log`, 22
`this-browser-is-still-an-enrolled-client`, and 23
`no-client-key-record-stays-pending`.

## Credential retirement (`unlock/retire.ts`, `retireUnlockCredential`)

The ceremony behind "change my passphrase" and "remove this passkey", on either
signer arm. On the LADDER arm the entry is signed by the ACTING credential's
rung -- the successor's on a passphrase change, a surviving credential's on a
passkey removal. The retired credential's own rung cannot sign it, since a
self-signed strike would leave the ladder it meant to end standing. The ceremony
writes no unlock record. Every record is signed by its own credential
(`decisions/0019`), so this strike rots no sibling record and there is nothing
to re-seal. The only record it can rot is the retired credential's own, which
dies with the unlock Space the caller deletes. The edit runs the **retirement
gate** (`decisions/0015`) before it writes anything: a credential retired here
carries a ladder, so its ladder VM must be claimed first. The predicate is
narrow. The claim struck no ladder VM, the credential's own `keyAgreement`
member still stands, and a ladder VM stands unclaimed that COULD BE THIS
CREDENTIAL'S. That last conjunct is read off the log's entry shapes
(`ladderVmIdsIntroducedWithCredential`): a standing VM qualifies when the entry
that introduced it also introduced this credential's `keyAgreement` member, or
newly committed or authorized its anchor, or introduced no credential-class
member at all (the split issuance's authority entry, which installs authority
for a credential bound earlier). None qualifying is the positive answer that the
credential never had a VM to leave behind, which is what lets a torn issuance's
orphan -- a `keyAgreement` member, no ladder VM, no committed rung -- be removed
beside a sibling's standing VM. That shape refuses with
`UnclaimedLadderVmRetirementError`, carrying the qualifying unclaimed ids and a
`retryableWithLadderSeed` hint. Nothing is written and the credential stays
standing. The gate fires only on a seedless claim, since a seeded one either
strikes the derived VM or proves it absent, so the hint is true whenever the
error is raised. A sibling credential's unclaimed VM on a healthy
multi-credential account does not trip the gate, since the claim struck
something there and its VM qualifies for nothing. What the gate closes is a
retired credential's leftover VM standing under `capabilityDelegation`, which
can still sign a DELETE-only capability on the account Space and which nothing
downstream tells from a sibling's standing VM. A caller establishing a
replacement credential before retiring the old one runs
`preflightUnlockCredentialRetirement` first, the same gate over one pinned read,
writing nothing, so the refusal lands before establishment rather than leaving a
pending-shaped registry entry the seedless repair can never clear. (1) The
**document inventory edit** (`removeUnlockKey`): the credential's `keyAgreement`
entry, its committed rung hashes, and its ladder VM leave in one log entry,
which kills its latent self-enrollment authority. It is the ceremony's only
account-log read, checked against the caller's pinned head, and it runs the gate
unconditionally before publishing. `removeRecoveryKey` is covered the same way:
a code carries a ladder, so its removal claims that ladder's VM seedlessly from
the rung-0 multibase the registry recorded at issuance, and refuses with the
same typed error, naming the anchor it walked from, when no attribution arm can
claim it. (1b) The injected annex-inventory closure, strike-or-swap, best-effort
by contract. (2) The **roster rotation and collection fan-out**, so writes stop
landing under epochs the retired credential could open. Document-edit-first is
load-bearing the other way: a run torn after it leaves the roster keying a
recipient the document no longer backs, the state the login sweep detects and
finishes.

The pivot is the document inventory edit, stage 1. `retireUnlockCredential`
writes one entry on either arm. On a passphrase change the enclosing change
ceremony publishes the successor's bind entry first (`decisions/0018`), and
relative to the retirement that entry is pre-pivot and inert, since it grants
only the successor. Stages 1b and 2 are post-pivot. Invariants a torn run can
leave violated (numbered as in `INVARIANT_IDS`, `menders/ids.ts`): 1
`roster-wraps-exactly-the-document-key-set`, 2
`governed-log-heads-anchor-past-the-membership-change`, 3
`collection-epochs-name-the-current-user-key`, 4
`unlock-registry-opens-under-the-current-user-key`, 5
`registry-passphrase-entry-names-the-standing-credential`, 6
`passkey-entry-carries-its-standing-configuration`, 8
`standing-delegations-verify-under-the-current-document`, 16
`generation-delegation-is-current`, 18 `did-web-projection-matches-the-log`, 25
`retired-credential-leaves-no-annex-inventory`, 26
`document-lists-the-acting-credential`, 29
`every-document-key-agreement-entry-has-a-locatable-credential`, 30
`no-unlock-space-outlives-its-credential`, and 32
`saved-recovery-codes-locate-their-account`.

## Forget (`clientAnnex/forget.ts`, `forgetEnrolledClient`)

A remembered browser's enrolled client removes ITSELF through the standing
credential's bridge, self-enrollment in reverse, run before the app's local
wipe. The stage order deliberately INVERTS the revocation cascade's
document-edit-first rule, forced by the self-removal. After the removal entry
the forgetting client can sign no roster append (entry-proof rule) and make no
WAS request (current-key-set rule), and a ladder-signed append is licensed only
at an inventory-changing version, which a not-last-client removal is not. So the
roster rotates FIRST (the client's wrap retired by its kid explicitly, the fresh
key read back through the credential's standing wrap) and the collection fan-out
runs second -- stages 1 and 2 are the shared recipient-retiring cascade tail
(`retireRosterRecipientAndCascade`) -- and the removal entry lands last: ONE
atomic ladder-signed entry (`forgetWebvhClient` in
`clientAnnex/ladderAnchored.ts`). A removal reveals no new key, and a committed
rung may reveal itself in the entry it signs, so no reveal-and-commit precursor
exists and no torn revealed-rung-without-removal state can. The entry's removal
set is the revocation edit's verbatim (`clientRemovalTarget` /
`clientRemovalFields`, shared with `revokeWebvhClient`), with the ladder
vouching its own rung hashes into the staged-hash attribution, since a
self-enrolled client's staged hash and the next rung's hash were committed in
one reveal entry and are indistinguishable without them. The honest residue: the
acting rung stands REVEALED in `updateKeys` afterwards. That is credential-held
authority, consumed by the next self-enrollment and struck by credential
retirement. The roster log's head also keeps carrying a version before the
removal entry until another enrolled client's login sweep seals it. The last
enrolled client refuses (`LastEnrolledClientForgetError`, fired before anything
rotates): its forget is the ladder-anchored transition below.

The pivot is the removal entry, and it lands last. The roster rotation and the
collection fan-out before it are durable and not inert, the exception the
inverted order forces: a run torn before the entry has moved the account onto a
fresh key the forgetting client still holds, and converges by re-running.
Invariants a torn run can leave violated (numbered as in `INVARIANT_IDS`,
`menders/ids.ts`): 1 `roster-wraps-exactly-the-document-key-set`, 2
`governed-log-heads-anchor-past-the-membership-change`, 3
`collection-epochs-name-the-current-user-key`, 4
`unlock-registry-opens-under-the-current-user-key`, 18
`did-web-projection-matches-the-log`, 22
`this-browser-is-still-an-enrolled-client`, and 23
`no-client-key-record-stays-pending`.

## The last-client forget (`clientAnnex/forgetLast.ts`, `forgetLastEnrolledClient`)

The transition (decision 0004's amendments) taking an account from one enrolled
client to the client-less, ladder-anchored state, the third producer of that
state beside the credential-anchored genesis and the transient recovery. The
order is forced twice over: the server's revocation endpoint verifies a
to-be-revoked chain against the CURRENTLY resolved document, and the ladder VM
carries no `capabilityInvocation`. So: (1) the **strike-and-reinstall pair**,
both entries written while the client's inventory stays (the both-present
state). The acting credential's own ladder VM leaves in the first entry, scoped
by entry-signer attribution rather than struck account-wide, and the second
reinstalls it under the same id (`installLadderVmWebvh`, idempotent,
rung-signed). The reinstall entry is the inventory-changing version the
ceremony-tail license admits, which is how the transition earns its rotation
with no change to the license. The pair republishes an identical key and revokes
nothing. A run torn between the two entries leaves the account VM-less with the
client still standing, and a re-run's idempotent reinstall converges. A sibling
ladder spending the STRIKE version's shot leaves the rotation licensed at the
reinstall version. Only a sibling spend at the reinstall version, landing
between the pair and the rotation, refuses the run (`ResourceLogLicenseError`
from the rotation append). That refusal leaves the same both-entries-published
state a tear leaves, and the re-run converges. The pair runs under
`if (wrapped || !vmStands)`, where `wrapped` is the forgotten client's kid in
the pre-transition roster's current epoch. A sibling's rekey does not clear that
gate, since the client still stands in the document and is a recipient of the
sibling's new epoch. The re-run republishes the pair and mints a fresh
inventory-changing version to anchor at, burning no rung. The cost is two
account-log entries per attempt, so a sibling racing every round is a livelock
rather than a wedge. The pair publishes through the enrolled client's
root-invoked `clientLogStore` rather than the credential's bridge: the bridge is
often signed by the very VM the strike removes, so a bridge-invoked reinstall
would be refused against the post-strike document under the current-key-set
rule. (2) The **roster rotation**, ladder-VM-signed and carrying the reinstall
entry's version, HTTP-invoked under the still-standing client, ONE append
retiring the client's wrap. The orchestrator anchors it at that version itself,
through the roster store's minimum controller version, so an app-wired store
still serving a cached pre-transition view cannot land the append before the
reinstall entry. A ladder-signed head also means the roster log needs no seal
repair afterwards, load-bearing where no login sweep will ever run again. (3)
The collection fan-out. (4) The **generation stage**: every delegation this
ladder VM ever signed is revoked, the bytes recovered from the annex log's
history (`generationDelegationHistory`; webvh restates full state per entry, and
a renewal inside the 30-day window can leave two), closing the resurrection
window a reinstalled derived-key VM reopens, and a fresh ladder-signed
generation delegation replaces the embedded one
(`ensureGenerationDelegationCurrent`, keeping the account
transient-login-reachable), the staleness read against a projected post-edit
document -- this credential's ladder VM and the forgotten client are both named
retiring, so a delegation either of them signed is replaced while one a
surviving sibling ladder signed stands. The order inside the stage is: revoke
the historical doomed delegations (everything but the embedded one), replace,
then revoke the one replaced. Replace-before-revoke for the embedded delegation
keeps a torn run from stranding the generation delegation-less;
revoke-before-mint for the historical ones keeps a revocation the server
persistently refuses from adding a fresh doomed delegation per re-run, since
every re-run halts before minting (the first run mints once before the embedded
delegation's refusal is seen, the one bounded residue). Each revocation skips
the POST only when the delegation's own `expires` is past by more than the
revocation clock-skew margin, otherwise POSTs and reads the server's answer:
was-client's genuine `AlreadyRevokedError` is success (a resumed ceremony's
blind re-POST), a plain `ValidationError` inside the skew band around `expires`
reads as expired, and every other failure is not swallowed. A doomed delegation
here is signed by this credential's own ladder VM, which stage 1 just
reinstalled into the document, so a refusal is never read as signer death.
`revoked` lists the revoked and already-revoked ids; an expired one is skipped
and not listed. The revocations run under `Promise.allSettled` rather than
`Promise.all`, so one failure does not abort the others, but the stage rethrows
the first failed revocation's error verbatim, its name intact and not wrapped,
once every revocation has settled if any failed, halting the ceremony before the
stage-6 removal entry rather than declaring the resurrection window closed while
a delegation still stands. (5) The `onBeforeRemoval` seam (required), where the
caller re-signs the LOGIN credential's bridge and `delegatedClients` sibling
with the ladder VM and re-seals its record with the credential in hand, since
the removed client's signatures rot at the next entry. It is the only unlock
record the transition writes, every OTHER credential's record being signed by
its own credential, which this transition does not strike (`decisions/0019`). A
call without the seam is refused before any read, since the removal entry would
otherwise leave an account nothing can write to. (6) The **removal entry**
(`forgetLastWebvhClient`), the plain forget's removal shape with the guard
inverted: it requires the installed ladder VM instead of refusing the last
client. Every stage detects completion from durable state, so a run torn before
the removal entry converges on re-run; torn after it is the finish-the-wipe
state the app's next login maps. A reader settling a ladder-signed record's
mixed-signer proof uses `currentAccountRecordSigners` (`clients/listing.ts`):
the enrolled clients' key set widened by the document's ladder VMs, which the
enrolled-client set alone would refuse on a client-less account. One residue is
the transition's own: an account running it while N standing credentials stand
lands client-less carrying N standing ladder VMs, none of them retirable, since
a retirement needs an enrolled client. N stays 1 on the other two producers of
that state, since a client-less account can add no credential. Credential
rotation stays the remedy for a leaked credential wherever it is reachable. A
ladder VM reinstalled by the transition goes unattributed by the
registry-anchored backward walk once the anchor advances past the acting rung;
the removal paths read it off the member-anchored walk instead. The pair's
second ceremony-tail license shot was ruled on and accepted (see "The
ceremony-tail license" in keys-and-descriptor-logs.md).

The pivot is the stage-6 removal entry. Everything before it is durable and
re-runnable but not inert: the strike-and-reinstall pair, the rotation, the
fan-out, and the stage-4 delegation revocations all stand whether or not the
entry lands, since the client's authority ends at that entry and nothing can be
ordered behind it. A stage-4 revocation failure halts the ceremony the same way
a tear does: the caller sees the thrown error, and a re-run resumes, since the
doomed-delegation filter (this ladder VM's signature) recomputes cleanly against
whatever the annex log holds and revokes only what still needs it. Invariants a
torn run can leave violated (numbered as in `INVARIANT_IDS`, `menders/ids.ts`):
1 `roster-wraps-exactly-the-document-key-set`, 2
`governed-log-heads-anchor-past-the-membership-change`, 3
`collection-epochs-name-the-current-user-key`, 4
`unlock-registry-opens-under-the-current-user-key`, 18
`did-web-projection-matches-the-log`, and 22
`this-browser-is-still-an-enrolled-client`.
