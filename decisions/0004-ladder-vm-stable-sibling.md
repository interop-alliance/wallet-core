# 0004: The ladder verification method is a stable sibling key

- Status: accepted
- Date: 2026-08-19
- Terminology note (2026-08-21): "companion" was since renamed to
  `clientAnnex` ("the client annex"); this record keeps the original
  term. See freewallet roadmap item FW-222.
- Terminology note (2026-08-28): passages rewritten on that date use
  "enrolled client", the current term; passages left as written keep the
  original "durable client". The vocabulary sweep is separate work.
- Driving work: the public-computer login redesign for the browser
  wallet -- accounts must stay operable with zero enrolled durable
  clients (credential-anchored signup, transient recovery), which needs a
  document-visible key the standing credential alone can derive
- Affects: wallet-core `unlock` (the ladder derivations) and `webvh`
  (the ladder-anchored document assembly and the enrollment/removal
  ceremonies); @interop/zcap consumers of ladder-signed delegations
  (was-teaching-server's chain verification); every account did:webvh
  document freewallet and dcw publish; the
  companion profile's spec text

## Context

A visit holding nothing but a standing unlock credential needs two
things a document verification method provides: an `assertionMethod`
anchor for roster-log entry proofs, and a `capabilityDelegation` signer
for the generation delegation. That holds on an account with no enrolled
client, which has no other signer at all, and equally on an account whose
enrolled clients sit on other browsers and can sign nothing for this
visit. The ladder seed (random, carried in the unlock
record) is the only material a bare credential can re-derive. But the
ladder's rungs are update keys: republishing the current rung as a VM
would force a VM swap and a generation-delegation re-mint at every
rung spend. The VM also has to survive round trips through
@interop/zcap's flat string compares, which fixes several of its
fields outright.

## Decision

The ladder VM is a dedicated Ed25519 key -- the stable sibling --
derived once from the credential's random ladder seed under
`LADDER_SALT` with the fixed HKDF info label `vm`, published verbatim
(the seed is random, so the hash-commitment rule permits a verbatim
key) and stable across rung spends.

Published shape:

```
{ id: '<accountDid>#<publicKeyMultibase>', type: 'Multikey',
  controller: '<accountDid>', publicKeyMultibase }
```

listed as id-reference strings under `assertionMethod` and
`capabilityDelegation` only -- no `authentication`, no
`capabilityInvocation`, no `keyAgreement` twin, no marker property.
The `controller` value and the fragment spelling are forced, not
preferred: @interop/zcap's `isController` flat-compares the delegating
VM's `controller` string against the parent capability's controller
(which the server synthesizes as the account did:webvh), and only an
`<accountDid>#<fragment>` spelling dereferences through the server's
fragment resolver.

Recognition is by relation asymmetry: a `capabilityDelegation` member
absent from `capabilityInvocation` is the ladder VM. The asymmetry is
load-bearing -- zcap's `delegator.id` cannot identify the signer, so
verifiers classify the VM from the resolved document they already hold
-- and it structurally excludes the VM from every client listing
(those key on `capabilityInvocation`).

A ladder VM's life is keyed to its credential, not to the account's
client census. It is installed when the credential becomes standing --
the establishment's own document entry, and the ladder-anchored genesis
for the credential that establishes the account -- and it stands for as
long as that credential stands. This holds on accounts with enrolled
clients and on accounts without them alike.

It is struck only at the credential's retirement
(`retireUnlockCredential`). The transient recovery's add-and-retire entry
strikes one too, as part of a full retirement of every pre-recovery
standing credential: ladder VM and `keyAgreement` member out of the
document, roster wrap retired in the same append, registry entry dropped,
unlock Space deleted. Self-enrollment strikes no ladder VM. Its add entry
publishes the client and drops the spent rung from `updateKeys`, and
leaves every VM in the document.

Which ladder owns a given VM is settled by entry signer: VM_x belongs to
the ladder that signed the entry that first published VM_x. Every install
shape is ladder-signed, so the rule holds on all of them. Nothing in the
document marks the ownership, and nothing needs to -- recognition and
attribution are different questions, and only recognition is answered
from the document alone (see Rejected Alternatives).

An account always carries an enrolled client or a ladder VM. No window
exists where it has neither.

Ladder-anchored genesis parameters: `updateKeys` = [rung 0's key], signed
by rung 0; `nextKeyHashes` = [hash(rung 1), hash(rung 0)] -- the
staged rung plus the active rung's own carry-over hash; `portable`
stays true (the account log's standing value). The genesis
`keyAgreement` array holds only the credential's inventory entry
(commitment or verbatim); this ladder-anchored variant of the VM assembly
exists in no code path today and must be built.

Because the sibling is derived, removal is not permanent: a later
reinstall publishes the same key under the same id, and any
still-unexpired ladder-signed delegation resumes verifying the moment
the VM returns. The forget ceremony therefore revokes outstanding
ladder-signed generation delegations at the server's revocation
endpoint before its removal entry lands. (Amended 2026-08-19, the
public-computer login design's delta-review resolution -- the
revoke ordering was conditional on a
server spike, answered the same day from server source: the
revocation endpoint fully verifies the to-be-revoked capability's
delegation chain against the currently resolved document before
storing anything (`verifyRevocationChain`; an unverifiable chain is
the 400 InvalidRevocationError), so a revocation POSTed while the
ladder VM is absent from the document cannot land -- and the naive
flipped order deadlocks the other way, because the atomic removal
entry that installs the ladder VM also removes the forget client's
own verification method, leaving nothing that can sign the
invocation (the ladder VM carries no `capabilityInvocation`).
Decided: the last-client forget puts two entries ahead of its removal
entry, both written while the client still stands (a both-present state
the no-neither invariant permits). Because the acting credential's VM
already stands, those two are a strike of that VM and a reinstall of it
under the same id, which is what supplies a fresh inventory-changing
version for the roster rotation. Then the revocation POSTs, when both sides verify (the ladder-signed
chains resolve and the client is still a valid invoker), then the
removal entry. Two owed mechanics adopted with it: the delegation
bytes come from a companion-log history walk (webvh restates full
state per entry, readable under controller authority), and the
ceremony revokes every still-unexpired ladder-signed generation
delegation -- a renewal inside the 30-day window can leave two. The
resurrection window shrinks to the gap between the reinstall entry and
the revocations; a run torn after the reinstall entry converges on
re-run: idempotent reinstall, a re-POSTed revocation's 400
already-revoked answer read as success per the GC resume contract,
then the removal.)

(Amended 2026-08-21, the build's stage mechanics, signed off. The
ceremony's mandatory roster rotation runs BETWEEN the reinstall entry
and the removal entry: ladder-VM-signed, anchored at the reinstall
entry -- the reinstall entry is the inventory-changing version the
ceremony-tail license admits, not the removal entry, which changes no
inventory -- and HTTP-invoked under the
still-standing client. A ladder-signed head also leaves the roster
log's newest entry signed by a key the post-removal document still
lists, so the transition needs no seal completer -- load-bearing on an
account where no enrolled client's login sweep will ever run again.
Between the revocations and the removal entry the ceremony also
force-replaces the generation delegation with a fresh ladder-signed
one (new zcap id, untouched by the revocations; replace-before-revoke
in the implementation, so a tear never strands the generation
delegation-less), keeping the account transient-login-reachable, and
runs a pre-removal seam in which the caller re-signs the login
credential's bridge and `delegatedClients` sibling with the ladder VM
and re-seals its record -- the removed client's signatures rot at the
removal entry, and no durable login's refresh block will ever heal
them. Other unlock methods' records -- the other standing credentials'
and the recovery codes' -- ride the same pre-removal window as a
ladder-signed run of the revocation cascade's record re-mint pass,
the forgotten client named as retiring since the post-install
document still lists it; their re-sealed records' proofs settle
against the post-removal document through an allowlist widened by
the ladder VM. Best-effort per record, every record's fate reported.)

## Rejected Alternatives

- Republishing the current rung's key per spend: every ladder advance
  would force a VM swap and a generation-delegation re-mint.
- An explicit marker type or property for recognition: a new permanent
  vocabulary term that can drift from the relations actually carrying
  the authority.
- A dedicated `ladder-vm` salt: cryptographically equivalent to the
  `vm` info label, one more permanent constant.
- A dedicated removal entry after the add entry: a torn window where
  the durable client exists and the ladder VM still carries delegation
  authority, plus one more resumability predicate. Moot since the
  2026-08-28 rewrite -- self-enrollment removes no VM at all.
- Dropping the VM in the reveal entry instead: kills the live visit's
  authority before the durable client exists. Moot for the same reason.
- Committing rung 1 alone at genesis: the resolver would refuse the
  add entry's re-stated `updateKeys` without rung 0's carry-over hash.
- An annex-scoped ladder VM -- one whose delegation authority reaches
  only the annex Space, on the reasoning that a credential should be
  able to renew its own transient infrastructure and nothing more. It
  does not work in either direction. The generation delegation targets
  the ACCOUNT Space's items subtree with the full verb set, so an
  annex-scoped signer cannot mint the very thing that needs renewing.
  And the credential already holds annex-Space authority through the
  `delegatedClients` sibling delegation in its unlock record, so the
  scoping grants nothing it did not have. Do not reopen, on the shape
  rather than on the goal: a scope-based bound on the VM is the wrong
  axis. The right one is a server-side narrowing of the delegation
  clause's grantee-keyed predicate, taken as its own work in the
  storage server.
- Publishing the `keyAgreement` twin: no consumer needs it (the
  credential's decryption path is exclusively its standing roster
  wrap), a published twin would enter the roster resolver's recipient
  universe and need a new controller-marker convention, and the regret
  asymmetry favors omission -- adding an entry later is one log entry,
  removing one leaves epochs wrapped to it.

## Consequences

- Verifiers gain an inventory-aware read of the document: the relation
  asymmetry must be recognizable through the log-controller seam,
  which today exposes `assertionMethod` only.
- For as long as a credential stands, its ladder VM holds
  document-visible authority; what that authority may sign is bounded
  by the server-side delegation clause and the ceremony-tail license,
  recorded in the companion profile's decisions, not here. That bound
  now applies for the account's life rather than for a window, and to
  every standing credential rather than to one.
- An account carries one ladder VM per standing credential, co-resident
  with the enrolled clients' keys. So `assertionMethod` and
  `capabilityDelegation` hold credential-derived keys beside client
  keys; neither relation lists client keys exclusively. Client listings
  are unaffected, since they key on `capabilityInvocation` and the
  relation asymmetry keeps ladder VMs out of it.
- Same-key reinstatement means delegation revocation, rather than VM
  removal, is the terminal remedy for ladder-signed delegations. It is
  also what lets the last-client transition strike its own ladder VM and
  reinstall it in the next entry: the identical key republishes under
  the identical id, a zcap delegation proof carries no version anchor,
  and every unexpired ladder-signed delegation resumes verifying. That
  pair is how the transition earns an inventory-changing version for its
  roster rotation with no change to the ceremony-tail license.
- The stable sibling is itself a static ladder-seed-derived key that
  outlives rung spends; compromise of the seed compromises it for as
  long as the credential stands (credential rotation is the remedy).

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A consumer is named that needs the ladder VM's `keyAgreement`
   twin; publish it then as a new document entry with an explicit
   roster inventory, never retroactively.
2. @interop/zcap gains controller-document traversal (so `controller`
   need not be the account DID string); the forced fields could then
   be relaxed in a new profile version, with published documents left
   intact.
3. The relation-asymmetry recognition misclassifies a legitimate new
   VM class (some future member of `capabilityDelegation` that is not
   the ladder VM); recognition would then need the explicit marker
   this decision declined, added alongside, not instead.

## Changelog

- 2026-08-28: the lifecycle rule was REVERSED, not refined. It previously
  read that the ladder-anchored configuration is transitional and that the
  VM exists only while the account has no enrolled client, removed inside
  the first self-enrollment's add entry. It now reads that a VM's life is
  keyed to its credential: installed when the credential becomes standing,
  struck only at its retirement, and untouched by enrollment. Read the
  prior version for the superseded wording. Attribution by entry signer,
  the do-not-reopen rejection of an annex-scoped ladder VM, and the
  strike-then-reinstall consequence for the last-client transition landed
  in the same rewrite; the marker-property rejection was not reopened,
  since it answered recognition rather than attribution.
