# 0007: A reveal-and-commit entry appends the next rung's hash last

- Status: accepted
- Date: 2026-08-20
- Driving work: fixing unlock-credential retirement so it strikes the ladder's
  CURRENT inventory (a removal targeting the recorded bind-time rung leaves the
  live rung commitment standing after any self-enrollment -- a latent re-seizure
  credential via the reveal mechanism)
- Affects: wallet-core `unlock` (`selfEnrollWebvhClient`'s reveal entry
  assembly, `attributeLadderInventory`'s completion transfer); every account
  did:webvh log freewallet and dcw publish; any future independent reader
  attributing a ladder from a log alone

## Context

A self-enrollment's reveal-and-commit entry commits three new hashes under the
rung's authority: the new client's update-key hash, the new client's staged-key
hash, and `hash(rung i + 1)` -- the credential's next standing commitment. Once
the add entry completes the enrollment, the first is identified from the log
(the add entry authorizes the key it hashes), but the other two are structurally
indistinguishable: both are opaque standing commitments that may never be
revealed. A seed-less retirement (the manage-capability removal of a passkey
that cannot be tapped) has to know which of the two is the ladder's, because
striking the client's staged hash would degrade an innocent enrolled client
while leaving the rung hash standing keeps the retired credential re-enrollable.

## Decision

The order the shipped emitter already produces is ratified as a convention of
the log format: a reveal-and-commit entry appends its newly committed hashes in
the order

```
[new client's update-key hash, new client's staged-key hash,
 hash(rung i + 1)]
```

so the next rung's commitment is LAST among the entry's additions, and the
staged-key hash immediately follows the update-key hash. (When the next rung's
hash is already committed -- the ladder-anchored window's first enrollment,
where genesis pre-committed it -- the deduplicated append simply omits it; the
update/staged adjacency still holds.)

A log reader may rely on this: `attributeLadderInventory` resolves a completed
enrollment by transferring the claim matching the add entry's authorized key
plus the claim committed immediately after it (the staged hash) to the client,
leaving the residue ladder-owned. Revocation's staged-hash attribution
(`attributeStagedHash` in `webvh/revokeClient.ts`) relies on the same rule as
its conservative fallback: when more than one candidate survives the
known-latent-hash prune, the staged hash is the addition immediately after the
revoked client's update-key hash in the entry's append order.

Amended 2026-08-21: the append order says where a credential's own next
commitment sits; it does not say that whatever sits there is the credential's.
The recovery continuation writes the same three-hash shape with a different
meaning, because a spend hands the credential's standing to a successor rather
than climbing:

```
[new client's update-key hash, new client's staged-key hash,
 the REPLACEMENT code's update-key hash]
```

and the transient-recovery variant commits three hashes of which none is the
spent code's. The two shapes are indistinguishable in `updateKeys` /
`nextKeyHashes` alone. They differ in the document: a climb's completing entry
leaves the credential's own `keyAgreement` verification method standing, while a
spend's retires it and publishes the successor's. So `attributeLadderInventory`
keeps what a completion did not transfer only on POSITIVE attribution -- the
hash derives from a supplied ladder seed, or the credential survives the
completing entry (the `credentialVmId` option, which `removeUnlockKey` always
passes). A walk holding neither releases the leftover instead of claiming it:
retirement then strikes what the recorded inventory names and nothing more. That
direction is chosen deliberately. Under-claiming leaves a retired credential's
commitment standing, which the credential's holder could reveal; over-claiming
strikes a live credential's commitment, and that failure is silent -- the struck
credential keeps its verification method and its roster wrap, unlocks and
decrypts normally, and only fails when someone finally types it, with nothing in
the system able to heal it.

Amended 2026-08-22: the transient-recovery continuation commits the FRESH
credential's `hash(rung 0)` and `hash(rung 1)` in the reveal-and-commit entry
the spent code signs, adjacently and in that order, and reveals rung 0 only in
the add-and-retire entry that strikes the code. A seed-less walk sees neither a
ladder reveal nor a ladder-signed commit there, so nothing above admits
`hash(rung 1)`, and the seed is exactly what the retiring party lacks when an
enrolled client retires another unlock method. The adjacency is ratified as the
second positional rule of the format, with the handover as its reading:

```
[hash(rung 0), hash(rung 1), the replacement code's update-key hash]
```

When an entry reveals a rung whose hash an EARLIER entry committed, and the
revealing entry retires a key that signed that earlier entry, the committer was
handing its standing over rather than committing for itself, and the hash
appended immediately after the rung's among that entry's additions is the
ladder's next commitment, provided it is not the entry's LAST addition: what an
entry hands to a successor credential comes last, the position the replacement
code's hash takes above. The retire-the-committer condition alone is not what
keeps the rule inert elsewhere. The ordinary forget entry reveals the acting
rung while retiring the forgotten client, which is often the very client that
signed the credential's bind, so the condition holds on a plain account. What
keeps it inert there is that a bind commits exactly one hash, last. A rung
revealing itself in a self-enrollment retires nothing, and a walk anchored on a
refreshed later rung (whose hash sits right before the replacement code's in the
same entry) reveals it in such an entry, so neither can claim a neighbor. The
claim is then subject to the same test as every other reveal-time claim:
released at the completion unless positively attributed.

## Consequences

- Seed-less retirement is fully deterministic on every log the shipped emitter
  produced; no refusal path or collateral staged-hash strike is needed.
- Seed-less determinism now rests on the credential's verification-method id as
  well as on the append order. Every production removal passes it, so the
  unattributed case is reached only by a direct caller of the walk that supplies
  neither the seed nor the id.
- A future ceremony that commits hashes under a rung's authority inherits the
  rule rather than a new convention: leave the credential standing and its
  leftovers stay ladder-owned; retire the credential in the completing entry and
  they are released to whatever succeeded it.
- The append order in `selfEnrollWebvhClient` (and the ladder-anchored genesis's
  `genesisNextKeyHashes` role order, and the transient-recovery continuation's
  rung-pair order in `recoverWebvhLadderAnchored`) is load-bearing wire
  behavior: reordering those arrays is a breaking change to the log format, not
  a refactor.
- A third load-bearing rule follows: an entry signed by a key that a later
  rung-revealing entry may retire commits a ladder's rung hash only last among
  its additions, or followed by that ladder's own next rung and then the hash of
  whatever it hands standing to. A ceremony that batches a bind with another
  credential's commitment, or re-commits a struck rung hash in a new position,
  reopens the over-claim with nothing to catch it.
- `nextKeyHashes` remains a set semantically for verification purposes (the
  did:webvh resolver checks membership only); the order carries attribution
  metadata, nothing else.
- Added 2026-08-29: both positional rules are now read BACKWARDS as well as
  forwards. A seedless walk recovers the rungs behind its anchor by asking where
  the anchor's hash was committed and which rule put it there. Last position
  means the entry's own signer is the rung before it (a climb); any earlier
  position means the neighbour before it is a rung a later entry reveals while
  retiring the committer (a handover). Both steps are taken only where the
  credential's own `keyAgreement` member stands, which is what stops the walk at
  a plain genesis, at an enrolled-client bind, and at a spent recovery code
  beside the replacement's hash. So the batching rule above binds the backward
  reader too: a ceremony that batches a bind with another credential's
  commitment, or re-commits a struck rung hash in a new position, now mis-seeds
  an attribution as well as mis-releasing one. The backward reader also needs
  the committing entry to have authorized a key. One reachable history denies
  it: the last-client transition's strike-and-reinstall pair, followed by a
  self-enrollment that spends the already-revealed rung, so the entry
  committing the next rung's hash reveals nothing. The walk then cannot name
  the rung behind the anchor, and a seedless retirement leaves the reinstalled
  ladder VM standing (tracked as WC-158).
