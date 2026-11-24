# 0033: The elimination arm of ladder attribution

- Status: accepted
- Date: 2026-11-23
- Driving work: freewallet roadmap item FW-276 (a completer for a transient
  recovery spend torn inside its roster append), implemented as wallet-core
  roadmap item WC-320. Extracted at that design's approval. Amends 0020 (its
  revisit criterion 3).
- Affects: wallet-core (`/webvh`: `attributeLadderInventory`; `/unlock`:
  `removeUnlockKey` and the retirement gate it runs; `/recovery`:
  `recoverySpendRetirementFromLog` and a reader for the add-and-retire entry's
  position); freewallet (the torn-recovery completer, the one caller)

## Context

The transient recovery continuation publishes one add-and-retire entry, signed
by the fresh ladder's rung 0. It adds the fresh credential's `keyAgreement`
member and ladder VM. Then it adds the replacement code's member and ladder VM.
Nothing in the log pairs either VM with either credential. A VM key and a rung
key are independent expansions of one seed, so there is no pairing to read
(0020's 2026-09-04 amendment).

`attributeLadderInventory` (`src/webvh/ladder.ts`) claims a ladder VM on one of
three arms. Each is asked at the entry that published the VM. The signer arm
needs a rung of this ladder to have signed that entry. The co-introduction arm
needs the entry to have introduced this credential's own member. The commitment
arm needs the entry to have committed a hash this ladder knows a priori. All
three also need the entry to have introduced exactly one ladder VM. The
add-and-retire entry introduced two, so no arm claims either VM. A seedless
retirement of either credential then strikes no VM. The retirement gate
(`assertLadderVmClaimed`, decision 0015) refuses it with
`UnclaimedLadderVmRetirementError`, because a VM that could be the credential's
stands unclaimed.

That refusal is right for an ordinary seedless retirement. One caller cannot
live with it. A transient spend can tear inside the roster append that follows
the add-and-retire entry. The replacement code is then an orphan. Its member,
its committed rung-0 hash, and its ladder VM stand in the document. Nobody was
shown the code, and nobody holds its bytes or its seed. A completer of that
spend holds the fresh credential's ladder seed, read from the fresh credential's
unlock record. It must strike the orphan's whole inventory in one ladder-signed
entry. The member and the hash anchor seedlessly through the member's
`ladderCommitment`. No arm reaches the VM.

## Decision

Ladder attribution gains a fourth arm, the elimination arm. The caller supplies
the acting credential's ladder seed as an input of its own, distinct from the
existing ladder seed input, which names the retired credential's.

The arm claims a ladder VM for the retired credential only when the entry that
introduced the retired credential's `keyAgreement` member meets every condition
below. Each one fails closed.

- The entry introduced exactly two ladder VMs.
- One of them is the VM the supplied seed derives.
- The entry introduced exactly two credential-class `keyAgreement` members, and
  one of them is the acting credential's own.

The VM claimed is the other one of the two. The arm is seeded on the acting side
and seedless on the retired side. It claims nothing for the acting credential,
whose own seed already names its VM. The three existing arms are unchanged, and
each keeps its one-VM guard.

The same work needs three additive inputs beside the arm. None of them changes
what an existing caller passes.

- The retirement document half (`removeUnlockKey`,
  `src/unlock/standingWebvh.ts`) gains an anchor-by-commitment input. It names
  the retired member by its `ladderCommitment` hash in place of
  `StandingUnlockKeys.updateKeyMultibase`, which is required today. The
  completer holds no update key for the orphan.
- `recoverySpendRetirementFromLog` (`src/recovery/continuation.ts`) accepts the
  replacement's protected commitment by its rung-0 hash, in place of
  `replacementUpdateKeyMultibase`. The completer reads that hash off the
  replacement member at the add-and-retire entry.
- A reader returns the add-and-retire entry's position for a successor key. It
  lives in `src/recovery/continuation.ts` and is re-exported from
  `src/recovery/index.ts`. Today `recoverySpendRetirementFromLog` and
  `retiredCredentialVmIdsFromLog` each locate that entry inline, and no reader
  of the position is exported through `/recovery`.

The parameter and function names are settled at implementation, with the
maintainer's sign-off.

## Rejected Alternatives

- Strike the orphan's member and hash, and leave its ladder VM standing behind a
  retirement-gate exception. A VM whose seed nobody holds is inert. But the gate
  exists to refuse exactly a seedless strike that leaves a VM behind. An
  exception keyed on "two VMs introduced together" also matches a completed
  transient recovery, where the replacement code is live. There the exception
  would let a seedless retirement of either credential complete with its VM
  standing, and a retired credential would keep a delegation signer.
- Name the ladder VM on every `keyAgreement` member (roadmap item WC-211). That
  is a new permanent wire property on every member, and every bind path changes
  to write it. It also does not help a log already torn, since the orphan's
  member was written without it. Not chosen now. If it is promoted later, this
  arm can be deleted.
- Claim both VMs. Already rejected by 0020's 2026-09-04 amendment. A retirement
  of the fresh credential would strike the replacement code's VM and rot the
  bridge delegation that code's record carries.

## Consequences

- No wire change. No stored field, label, or log entry shape is added. The
  completer's strike entry is the ordinary retirement entry.
- The arm fires for one caller shape: a retirement that holds the acting
  credential's ladder seed, of a credential introduced beside the acting one in
  a single two-VM entry. The transient add-and-retire entry is the one emitter
  of that shape, and the torn-recovery completer is the one caller.
- Existing callers pass no acting seed, so their readings are unchanged. A
  seedless retirement of either credential a transient recovery introduced still
  refuses on the retirement gate.
- Over-claiming needs two things. One is an entry of the arm's shape, which only
  an authorized update key can sign. The other is the acting credential's ladder
  seed. A party holding both already controls the account.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. WC-211 is promoted, so each member names its own ladder VM. The arm can then
   be deleted.
2. An entry shape other than the transient add-and-retire entry comes to
   introduce two ladder VMs. The arm's guards are calibrated to that one
   emitter.
3. A caller wants the arm without holding the acting credential's seed. The
   arm's safety rests on the seed telling the two VMs apart.
