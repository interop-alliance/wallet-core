# 0002: Companion log update authority is static rung 0

- Status: accepted
- Date: 2026-08-19
- Terminology note (2026-08-21): "companion" was since renamed to
  `clientAnnex` ("the client annex"); this record keeps the original
  term. See freewallet roadmap item FW-222.
- Driving work: the public-computer login redesign for the browser
  wallet -- transient per-visit clients recorded in a disposable
  companion did:webvh (the delegated-clients sidecar) instead of the
  account's identity log, with generation-scoped delegations
- Affects: wallet-core `unlock` (the ladder machinery) and the
  companion-log ceremonies built on `webvh`; every companion
  (delegated-clients) did:webvh log freewallet and dcw publish; the
  companion profile's spec text

## Context

The companion did:webvh holds transient per-visit verification methods
and is written through the standing unlock credential's bridge
delegation, so its update keys must be derivable from the credential
alone -- no durable client key can be assumed to exist. The account
log's ladder mechanism (one-time rungs, reveal-and-commit, one entry
per spend) was the obvious transplant, but the companion is
capability-gated and private: public-log use-unlinkability, the
ratchet's one real benefit, does not apply to a log whose only readers
are the host and the account. The ratchet's costs are all real
machinery -- rung attribution scans with a scan bound, a per-GC-cycle
visit cap, and a CAS retry that must re-derive and re-sign with an
advanced rung, a retry shape the shared conflict-retry loop never
needed.

## Decision

The companion log's update authority is each standing credential's
static rung 0.

- Each standing unlock credential's companion update key is rung 0 of
  its per-generation HKDF sequence. The chain has length one; the rung
  index never advances.
- Update authority is credential rung-0 keys only. Durable clients
  hold no companion update keys; a durable session writes with its
  login credential's rung 0 (every session holds a ladder seed from
  its unlock-record read).
- `updateKeys` carries each credential's rung-0 key once revealed (a
  credential's key reveals at its first companion write).
  `nextKeyHashes` holds every standing credential's rung-0 hash -- a
  commitment for a not-yet-revealed key, the carry-over hash for a
  revealed one -- restated explicitly on every entry, never inherited.
- Companion entries commit ladder rungs only, never per-client staged
  hashes.
- Every companion entry is one atomic entry -- the
  first-VM/delegation-install entry, per-visit VM adds, the re-mint
  entry alike. There is no two-entry reveal/add split, and a CAS loser
  re-signs with the same key (an ordinary `withLogConflictRetry`
  re-run).
- Genesis parameters: prerotation on (the rung-0 hashes are the
  commitment chain under the carry-over configuration), no witnesses,
  portability off (a companion is generation-scoped and host-bound;
  replacement is a GC swap, never a portability move).
- Transient VM shape: `capabilityInvocation` only, with relations
  stated explicitly on every companion VM. No `authentication`, no
  `assertionMethod`, no `keyAgreement` twin -- so the client
  controller-marker convention does not arise in the companion at all.
- A delegated companion PUT through the bridge carries the same
  CAS/ETag conditional-publish discipline as controller-signed log
  writes: a lost race surfaces as the conflict error and the ceremony
  re-runs on the new head, never an unconditional overwrite.

## Rejected Alternatives

- The per-entry ratchet (the account log's mechanism transplanted).
  Its one defensible benefit is unlinkability of successive credential
  uses in a world-readable log, which is nil for the private
  companion; it buys no forward security (seed and rungs cohabit one
  sealed record). Its costs are all new machinery: the attribution
  scan generalized to a second log, a per-GC-cycle visit cap from the
  scan bound, and an advanced-rung CAS retry shape.
- The two-entry account-ceremony transplant (reveal entry, then add
  entry). The second entry has no handoff purpose on the companion --
  there is no durable client to hand off to -- and it reimports the
  torn-window residue class, where a revealed rung with no follow-up
  entry strands recoverable authority.

## Consequences

- Resumability reduces to the published document's own state (the VM
  or service entry present or not). No attribution scan, no counter,
  and no scan bound exist on the companion.
- A credential bound mid-generation has no committed key and cannot
  write the companion until an existing writer commits its rung-0 hash
  or the next GC swap does. (Amended 2026-08-19, the public-computer
  login design's delta-review resolution: signed off before the
  quarterly GC cadence was, this
  residue had grown to a ~90-day worst case -- indefinite when
  nothing else writes the companion -- and the transient-recovery
  continuation hit the same lockout. Closed by a hybrid whose halves
  are each forced by mechanics. The bind ceremony (passkey add,
  passphrase change) runs from a logged-in session whose own login
  credential's rung 0 is already committed, so it appends one atomic
  hash-restating entry adding the new credential's rung-0 hash. The
  transient-recovery continuation cannot take that shape -- companion
  entries verify against the log's own hash-commitment chain, and the
  continuation holds no committed key (the spent code had no
  companion inventory; the replacement credential's rung 0 is by
  definition uncommitted) -- so it instead mints a fresh generation
  (genesis is self-authorizing and commits the replacement
  credential's rung 0) and re-points the delegated-clients service
  entry under the account-log update authority the ceremony is
  already exercising; the abandoned old generation authorizes nothing
  once unpointed and falls to the standing orphan-discovery cleanup
  at the next durable login.)
- A retired credential's revealed key and standing hash are dropped by
  the next entry.
- The account log keeps its shipped one-entry ratchet; its honest
  rationale (public-log use-unlinkability plus the inherited
  genealogy, explicitly not forward security) is recorded separately.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The companion log becomes world-readable, or gains a reader class
   beyond the host and the account -- use-unlinkability would then
   have value on it, and the ratchet trade re-opens.
2. A key-compromise class is demonstrated where rung advancement on
   the companion would have contained an attacker that static rung 0
   did not (the seed-and-rungs-cohabit argument failing in practice).

If revisited, the change is a new companion-profile version, not an
in-place reinterpretation of published companion logs.
