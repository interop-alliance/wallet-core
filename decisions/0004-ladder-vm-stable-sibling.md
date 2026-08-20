# 0004: The ladder verification method is a stable sibling key

- Status: accepted
- Date: 2026-08-19
- Driving work: the public-computer posture redesign for the browser
  wallet -- accounts must stay operable with zero enrolled durable
  clients (credential-anchored signup, transient recovery), which needs a
  document-visible key the standing credential alone can derive
- Affects: wallet-core `unlock` (the ladder derivations) and `webvh`
  (the ladder-anchored document assembly and the enrollment/removal
  ceremonies); @interop/zcap consumers of ladder-signed delegations
  (was-teaching-server's chain verification); every account did:webvh
  document freewallet and dcw publish during a ladder-anchored window; the
  companion profile's spec text

## Context

An account with no enrolled durable client still needs two things a
document verification method provides: an `assertionMethod` anchor for
roster-log entry proofs, and a `capabilityDelegation` signer for the
generation delegation. The ladder seed (random, carried in the unlock
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

The posture is transitional. The VM exists only while the account has
no enrolled durable client: installed by ladder-anchored genesis, by
recovery's add-and-retire entry, or by the last-durable-client
forget's install entry (per the 2026-08-19 amendment below, one
entry ahead of its removal entry); removed folded into the first durable
self-enrollment's add entry -- one atomic entry that publishes the
client, drops rung 0 from `updateKeys`, and filters the ladder VM out
of `verificationMethod`, `assertionMethod`, and
`capabilityDelegation`. No window exists where the account has neither
a durable client nor the ladder VM.

Ladder-anchored genesis parameters: `updateKeys` = [rung 0's key], signed
by rung 0; `nextKeyHashes` = [hash(rung 1), hash(rung 0)] -- the
staged rung plus the active rung's own carry-over hash; `portable`
stays true (the account log's standing value). The genesis
`keyAgreement` array holds only the credential's posture entry
(commitment or verbatim); this ladder-anchored variant of the VM assembly
exists in no code path today and must be built.

Because the sibling is derived, removal is not permanent: a later
reinstall publishes the same key under the same id, and any
still-unexpired ladder-signed delegation resumes verifying the moment
the VM returns. The forget ceremony therefore revokes outstanding
ladder-signed generation delegations at the server's revocation
endpoint before its removal entry lands. (Amended 2026-08-19, the
public-computer posture design's delta-review resolution -- the
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
Decided: the last-durable-client forget is two entries -- an install
entry publishing the ladder VM while keeping the client (the
both-present transitional state the no-neither invariant permits),
then the revocation POSTs, when both sides verify (the ladder-signed
chains resolve and the client is still a valid invoker), then the
removal entry. Two owed mechanics adopted with it: the delegation
bytes come from a companion-log history walk (webvh restates full
state per entry, readable under controller authority), and the
ceremony revokes every still-unexpired ladder-signed generation
delegation -- a renewal inside the 30-day window can leave two. The
resurrection window shrinks to the gap between the install entry and
the revocations; a run torn after the install entry converges on
re-run: idempotent install, a re-POSTed revocation's 400
already-revoked answer read as success per the GC resume contract,
then the removal.)

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
  authority, plus one more resumability predicate.
- Dropping the VM in the reveal entry instead: kills the live visit's
  authority before the durable client exists.
- Committing rung 1 alone at genesis: the resolver would refuse the
  add entry's re-stated `updateKeys` without rung 0's carry-over hash.
- Publishing the `keyAgreement` twin: no consumer needs it (the
  credential's decryption path is exclusively its standing roster
  wrap), a published twin would enter the roster resolver's recipient
  universe and need a new controller-marker convention, and the regret
  asymmetry favors omission -- adding an entry later is one log entry,
  removing one leaves epochs wrapped to it.

## Consequences

- Verifiers gain a posture-aware read of the document: the relation
  asymmetry must be recognizable through the log-controller seam,
  which today exposes `assertionMethod` only.
- During the ladder-anchored window the credential's ladder VM holds
  document-visible authority; what that authority may sign is bounded
  by the server-side delegation clause and the ceremony-tail license,
  recorded in the companion profile's decisions, not here.
- Same-key reinstatement means delegation revocation, not VM removal,
  is the terminal remedy for ladder-signed delegations.
- The stable sibling is itself a static ladder-seed-derived key that
  outlives rung spends; compromise of the seed compromises it for as
  long as the credential stands (credential rotation is the remedy).

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A consumer is named that needs the ladder VM's `keyAgreement`
   twin; publish it then as a new document entry with an explicit
   roster posture, never retroactively.
2. @interop/zcap gains controller-document traversal (so `controller`
   need not be the account DID string); the forced fields could then
   be relaxed in a new profile version, with published documents left
   intact.
3. The relation-asymmetry recognition misclassifies a legitimate new
   VM class (some future member of `capabilityDelegation` that is not
   the ladder VM); recognition would then need the explicit marker
   this decision declined, added alongside, not instead.
