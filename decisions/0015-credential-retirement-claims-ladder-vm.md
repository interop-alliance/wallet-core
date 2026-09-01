# 0015: Credential retirement must claim the retired credential's ladder VM

- Status: accepted
- Date: 2026-09-01
- Driving work: the browser wallet's transient account-deletion design
  gate. A DELETE-only capability on a bare Space URL is now inside what
  a ladder VM may delegate, which turns a retired credential's leftover
  ladder VM into whole-account destruction by a credential the user
  believes is gone. Extracted at that design's approval; sits beside
  `decisions/0004` (the ladder VM's stable-sibling shape) rather than
  amending it.
- Affects: wallet-core `/unlock` (`retireUnlockCredential` over
  `removeUnlockKey`), `/recovery` (`removeRecoveryKey`, carved out);
  both wallets' retirement callers (passphrase change, passkey removal,
  the torn-retirement repair).

## Context

A seedless retirement whose ladder attribution cannot claim the retired
credential's ladder VM used to complete anyway: it struck the
credential's committed rung hash and its `keyAgreement` entry and left
the VM standing as a stated shape. A credential retired into that state
can neither write the account log nor self-enroll; the only authority
the leftover VM confers is delegation. Delegation now includes a
DELETE-only capability on the account Space, so the leftover is a
standing kill switch held by a supposedly retired credential. No marker,
log signal, or server view distinguishes a claimed ladder VM from an
unclaimed leftover, so nothing downstream can detect the state; closing
it at the retirement is the only place it can be closed.

## Decision

A retirement that cannot claim its credential's ladder VM refuses
rather than completing, with nothing written. The predicate is the
seedless strike claiming nothing: the remove polarity ending with an
empty `struckLadderVmIds` while ladder VMs stand unclaimed in the
resolved document. It is deliberately narrower than "the report's
`unclaimed` is non-empty", which a healthy multi-credential account
produces on every retirement (a sibling credential's standing ladder VM
is unclaimed by the walk and has no business being claimed by it).

The refusal is typed and name-stable:
`UnclaimedLadderVmRetirementError`, carrying two members that are the
build contract -- the ids of the ladder VMs the walk left unclaimed,
and a retryability hint saying whether supplying the credential's
ladder seed can let attribution succeed. The passphrase change and a
tap-confirmed passkey removal hold the seed; a seedless passkey removal
does not, and its hint says so.

The gate sits in `retireUnlockCredential`'s path, not inside
`removeUnlockKey` itself, or it carries a discriminator for an
inventory with no ladder VM to claim: `removeRecoveryKey` (the
recovery-code revocation's document edit) passes no ladder seed because
a code carries no ladder, and it matches the refusal shape exactly, so
a gate at the shared helper would kill recovery-code revocation on
every credential-anchored account.

The caller contract: callers that establish before they retire (the
establish-first passphrase change, the tap-confirmed passkey removal)
run the gate's attribution read-only as a pre-flight, before
establishment and before any write, refusing the way an invalid-input
check refuses. A gate refusal never writes a pending-shaped registry
entry; the in-retirement refusal stays as defense in depth. Without
the pre-flight, a refusal after establishment writes a pending entry
the seedless torn-retirement repair can never clear, permanently
locking the passphrase change, the last-client transition, and the
deletion ceremony.

## Rejected Alternatives

- **A document marker distinguishing a ladder VM.** Already rejected by
  `decisions/0004`; nothing in this design changes that reasoning, and
  a marker minted for one gate's convenience would be a permanent wire
  member.
- **Gating at `removeUnlockKey`.** Kills recovery-code revocation on
  every credential-anchored account (above).
- **No gate.** Leaves each retired credential's leftover VM a standing
  whole-account kill switch with no detector anywhere.

## Consequences

- The gate's sufficiency rests on every client that ever retires a
  credential on the account running it. A wallet pinned to an older
  wallet-core, a cached PWA build, or a second wallet implementation
  re-creates the population the gate closes, and there is no detector
  for the resulting state. Version skew therefore joins the greenfield
  boundary alongside accounts damaged before the gate lands.
- The gate does not reach ladder VMs that are never retired: a
  client-less account carries one standing VM per standing credential,
  each bounded only by its credential's entropy.
- A seedless passkey removal can refuse where it used to complete; the
  user-facing retry that supplies the seed is the wallets' own work,
  reading the error's two members.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A detector or document marker distinguishing a claimed ladder VM
   from an unclaimed leftover ships (this reopens `decisions/0004`'s
   marker rejection with it).
2. Ladder attribution gains a reliable seedless path (for example,
   richer entry attribution or witnessed logs), making the refusal
   unnecessary because the seedless walk can claim the VM.
