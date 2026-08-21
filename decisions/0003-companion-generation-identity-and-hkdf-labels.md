# 0003: Companion generation identity and the ladder HKDF label family

- Status: accepted
- Date: 2026-08-19
- Amended: 2026-08-20 -- Renamed: the identifier is now called the
  generation id (`generationId`) module-wide; formerly "segment".
- Terminology note (2026-08-21): "companion" was since renamed to
  `clientAnnex` ("the client annex"); this record keeps the original
  term. See freewallet roadmap item FW-222.
- Driving work: the public-computer posture redesign for the browser
  wallet -- transient per-visit clients recorded in a disposable
  companion did:webvh, one generation per flat collection inside a
  stable auxiliary companion Space
- Affects: wallet-core `unlock` (`LADDER_SALT` and the ladder
  derivations) and the companion provisioning/GC ceremonies; every
  companion DID string freewallet and dcw publish (the Space id and
  the generation id embed in it permanently); the companion
  profile's spec text

## Context

A companion generation needs a durable identity that three things can
agree on: the collection holding its `did.jsonl`, the companion DID
string (which embeds the Space id and generation id), and the
HKDF derivation of the generation's rung-0 update keys. The identity
must be derivable with no log read (GC deletes the old generation's
log, and replacement must be self-healing) and must be structurally
never-reused (a reused identity would re-derive the same rung-0 key
for a new generation). The auxiliary companion Space's id additionally
embeds in the sibling delegation's `invocationTarget`, which is sealed
into the unlock record before the account DID exists -- so no
derivation over the account identity is possible at bind time.

## Decision

- The generation collection's name -- the generation id -- is
  `gen-<random>`: the literal
  prefix `gen-` plus 12 random bytes encoded base64url-no-pad (a
  16-character suffix, 20 characters total, e.g.
  `gen-Ux3v0kQf9aPmB2hZ`; amended 2026-08-19 -- the record
  originally said "16 characters total", an arithmetic slip
  against its own example, caught by the public-computer posture
  design's delta review).
  Every character is
  inside the server's `[A-Za-z0-9._~-]+` id allowlist, so
  `encodeURIComponent` is the identity on it.
- The auxiliary companion Space's id is minted by the same independent
  random `mintSpaceId` convention as the account Space (32 random
  bytes, base64url-no-pad, 43 characters).
- Everything ladder-seed-derived uses the one existing `LADDER_SALT`
  (`freewallet/unlock/update-ladder/v1`), with the HKDF info label
  doing the separation:
  - `rung/<n>` -- account-log rungs (the shipped convention);
  - `vm` -- the stable sibling ladder verification-method key;
  - `<generationId>/rung/<k>` -- companion rungs, where
    `<generationId>` is the generation collection's name (e.g.
    `gen-Ux3v0kQf9aPmB2hZ/rung/0`).
- The generation-identifying half of the label is defined as the
  companion collection's generation id. There is exactly one spelling
  of a generation's identity -- the one the companion DID string
  already embeds -- and the label is derivable with no log read.

Randomness rather than a counter is what makes never-reuse structural:
a monotone counter has no durable carrier (GC deletes the old
collection, the pointer can be reset, and the only backstop would be a
log-history scan -- exactly the machinery the static-rung-0 decision
removed). The random Space id is also deliberate on a second axis:
hash-derived addressing would import the unlock Spaces'
existence-oracle posture, unwanted here.

## Rejected Alternatives

- A bare `gen/<n>` index prefix for the HKDF label: a second spelling
  of the generation identity, kept in lockstep with the collection
  name forever.
- A dedicated companion salt: cryptographically equivalent to the info
  namespace, at the price of one more permanent constant.
- `gen-<n>` monotone decimal collection names, and the older
  `id-companion-<n>` sketch: both have the counter-carrier problem
  (nothing durable survives GC to hold the counter), the latter with
  longer strings.
- Parameterizing the derivation by the companion's SCID: recorded as
  an impossibility, not merely rejected -- rung 0's key sits inside
  the genesis document the SCID hashes, so rung 0's derivation cannot
  take the SCID as input.

## Consequences

- Orphan discovery is a plain `gen-` prefix match over the Space's
  collection listing; no registry of generations exists anywhere.
- GC replacement is self-healing: a fresh generation needs only fresh
  random bytes, and no state from the deleted log.
- The generation id and Space id are permanent substrings of every
  companion DID string ever published (the generation id is the final
  path segment of the companion DID); the shapes cannot change without a new
  profile version.
- The 12-byte generation id suffix makes accidental reuse negligible rather
  than impossible; the never-reuse guarantee is probabilistic, at the
  same order as every other random-id convention in the system.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The server's collection-id allowlist changes such that the
   `gen-<random>` spelling no longer round-trips the DID path
   encoding.
2. A consumer appears that needs to enumerate or order generations
   chronologically from their names alone; ordering would then need a
   sortable component, added as a new naming convention beside this
   one, never a reinterpretation of existing generation ids.
