# 0017: A standing unlock credential may strike an enrolled client

- Status: accepted
- Date: 2026-09-03
- Driving work: the browser wallet's design for running the
  account-management ceremonies from a credential-only transient session.
  Client disconnect was one of the ceremonies that could not run there,
  because its document edit was signed by an enrolled client's update key
  and a transient session holds none.
- Affects: wallet-core `/webvh` (`revokeWebvhClient` on the ladder arm),
  `/clientAnnex` (the ladder-signed account entry), `/clients`
  (`disconnectEligibility` and the revocation cascade orchestrator);
  both wallets' Connected wallets surfaces; every account did:webvh log
  freewallet and dcw publish.

## Context

An account's enrolled clients live in its did:webvh document. Removing
one is a single log entry. Until now that entry was always signed by
another enrolled client's update key, which made the ceremony
unreachable from a session holding only a standing unlock credential.
Two consequences followed. On a credential-anchored account there was no
enrolled client to sign at all, so a client enrolled onto such an account
could never be disconnected from a transient session. And the eligibility
policy refused the last enrolled client outright, routing that case to
the last-client transition, which itself needs a remembered session.

The default session is transient and the default account is
credential-anchored, so the population that could not disconnect a client
was most of the population.

## Decision

A ladder-signed removal entry, published through the acting credential's
bridge delegation, may remove an enrolled client from the account
document. The last enrolled client is included. After a last-client
removal the account is ladder-anchored, the same shape a
credential-anchored signup produces and a transient recovery returns an
account to. On the ladder branch `disconnectEligibility` drops both the
self refusal and the last-client refusal.

Loudness is the guard. The removal is a world-readable, hash-chained
entry signed by a rung of the acting credential's ladder, and the
transient session that publishes it has already extended the annex log
with its own per-visit entry. The removed client's holder sees the
removal in a log they can read without any capability.

Three refusals run before the pivot. They are the set the last-client
transition already used, run now on every ladder-branch disconnect:

- a registry this session cannot read;
- a pending-shaped passphrase entry, whose only mender is the
  torn-retirement repair and which must run first so that the
  disconnect's own registry re-seal does not rewrite a half-retired
  entry;
- a standing credential the registry does not name, which survives for
  records bound before the self-signed-record rule (decision 0019) and
  whose bridge this entry would leave with no verifying signer.

The struck-signer rule applies to the entry. A ceremony that strikes any
signer of a delegation the visit rides re-mints that delegation before
its pivot, and adopts it before the strike lands. On a disconnect the
removed client's account key may be the signer of the generation
delegation the visit invokes under. The replacement is signed by the
acting ladder VM, which stands throughout, so it verifies at once. A
replacement whose signer is in no document yet is not an option, because
it swaps a verifying delegation for one that verifies nowhere.

The pivot is the removal entry. The rotation append that follows it is
ladder-signed and anchors at that entry's version under clause B shape 3
of the ceremony-tail license (app-connect-spec `decisions/0003`, amended
the same day).

The threat model is unchanged. A credential holder could already reach
this outcome by self-enrolling with `rememberBrowser: true` and running
the enrolled-branch revocation cascade. This decision removes a detour.
It removes no control. Credential rotation remains the remedy for a
leaked standing unlock credential.

## Rejected Alternatives

- **Keep client disconnect on the enrolled branch only.** The account
  shape this work exists for is the one with no enrolled client, so the
  restriction lands hardest exactly where the ceremony is needed. A
  user whose only enrolled browser is lost would have no way to remove
  it.
- **The step-up ceremony.** A loud in-memory self-enrollment bracketing
  the unchanged ceremony code, closed by a ladder-signed retire entry. It
  costs three world-readable entries per ceremony, puts a root-tier
  invoking key in tab memory, and leaves an authorization-live orphan
  when the enroll step crashes on an account with no cleanup actor. The
  browser wallet repo carries the record that closes it for the whole
  class; this record notes only that the disconnect does not need it.
- **A strike-and-reinstall pair of the ladder VM, to mint a licensed
  version for the rotation append.** From a transient session this is
  self-lockout. The struck VM signed both the generation delegation and
  the bridge the visit invokes under, so the reinstall entry cannot be
  published by the visit that just lost both. It also costs two permanent
  entries per disconnect. The last-client transition keeps the pair,
  because a still-standing enrolled client publishes its reinstall.

## Consequences

- A disconnect torn after its removal entry, on the account it leaves
  client-less, has no re-run entry point and no sweep. The row is gone
  from the listing, so there is nothing to click again, and the
  remembered-login sweep never runs on such an account. The roster keeps
  wrapping the current user key to the removed client until the
  retire-direction convergence of some later ladder-branch ceremony
  mends it, and the user may never run one. This is an open gap of the
  same class as the transient recovery's roster-append residue, recorded
  in both wallets' ceremony inventories.
- Every App Connect grant a transient session minted chains under the
  generation delegation. A disconnect that re-mints that delegation ends
  every such grant. That is the mid-generation death an ordinary
  disconnect already caused; the disconnect copy states it.
- The rotation append needs clause B shape 3, which is a verifier-side
  rule. Every reader of the user key roster log must ship shape 3 before
  any writer emits an append that relies on it, or the reader refuses the
  whole log.
- The last enrolled client's row now offers a disconnect from a
  transient session as well as the last-client transition from a
  remembered one. Both land the account in the same ladder-anchored
  shape.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. Loudness stops being the guard. If a ladder-signed removal can be
   published without a world-readable entry the removed client's holder
   can read, the argument above collapses and the ceremony needs a
   different control.
2. A standing unlock credential gains authority that a self-enrollment
   plus the enrolled branch cannot reach. The "widens nothing" argument
   is what carries this record, and it rests on self-enrollment staying
   available to any credential holder.
3. A mender for the torn last-client disconnect ships, or the open gap
   is judged too sharp to keep. Either changes the consequence this
   record accepts.
