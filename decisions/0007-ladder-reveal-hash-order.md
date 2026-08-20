# 0007: A reveal-and-commit entry appends the next rung's hash last

- Status: accepted
- Date: 2026-08-20
- Driving work: fixing unlock-credential retirement so it strikes the ladder's
  CURRENT footprint (a removal targeting the recorded bind-time rung leaves the
  live rung commitment standing after any self-enrollment -- a latent re-seizure
  credential via the reveal mechanism)
- Affects: wallet-core `unlock` (`selfEnrollWebvhClient`'s reveal entry
  assembly, `attributeLadderPosture`'s completion transfer); every account
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

A log reader may rely on this: `attributeLadderPosture` resolves a completed
enrollment by transferring the claim matching the add entry's authorized key
plus the claim committed immediately after it (the staged hash) to the client,
leaving the residue ladder-owned.

## Consequences

- Seed-less retirement is fully deterministic on every log the shipped emitter
  produced; no refusal path or collateral staged-hash strike is needed.
- The append order in `selfEnrollWebvhClient` (and the ladder-anchored genesis's
  `genesisNextKeyHashes` role order) is load-bearing wire behavior: reordering
  those arrays is a breaking change to the log format, not a refactor.
- `nextKeyHashes` remains a set semantically for verification purposes (the
  did:webvh resolver checks membership only); the order carries attribution
  metadata, nothing else.
