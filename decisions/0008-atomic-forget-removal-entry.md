# 0008: The forget removal is one atomic ladder-signed entry, rotation-first

- Status: accepted
- Date: 2026-08-21
- Driving work: the forget ceremony (a remembered browser's durable client
  removing itself through the standing credential's bridge before the local
  wipe)
- Affects: wallet-core `unlock` (`forgetWebvhClient`, `forgetDurableClient`)
  and `webvh` (the removal-edit computation shared with `revokeWebvhClient`);
  every account did:webvh log freewallet and dcw publish; the wallet apps'
  forget flows

## Context

The design prose described the forget removal as self-enrollment's silhouette:
a reveal-and-commit rung entry, then a removal entry. But a removal reveals no
NEW key -- the acting rung's hash already stands committed by the credential's
inventory, and under prerotation a committed key may reveal itself in the entry
it signs -- so nothing forces a second entry. The surrounding ceremony also
inherited the revocation cascade's document-edit-first ordering, which a
SELF-removal cannot satisfy: once the removal entry lands, the forgetting
client's key is out of `assertionMethod` at the post-edit head (no roster
append it signs verifies), its WAS invocations stop verifying under the
current-key-set rule (no collection fan-out), and the ceremony-tail license
admits a ladder-signed append only at a inventory-changing document version,
which a not-last-client removal is not.

## Decision

Three points, ratified together:

1. **One atomic entry.** The forget removal is a single ladder-signed entry:
   `updateKeys` restates the published set minus the forgotten client's key,
   union the acting rung; `nextKeyHashes` drops the client's carry-over and
   staged hashes and keeps the rung's own hash (the carry-over convention);
   the document members are exactly the revocation removal's. The entry
   commits no new hash. Atomicity removes the torn
   revealed-rung-without-removal state entirely, at one entry and one rung of
   cost.
2. **Rotation before the edit.** The ceremony runs the roster rotation (the
   client's wrap retired by its roster kid explicitly, since document
   convergence cannot drop a client the document still lists) and the
   collection fan-out BEFORE the removal entry, under the client's
   still-standing authority; the fresh user key is read back through the
   credential's standing wrap. A run torn after the rotation reads as
   not-forgotten and a re-run converges. The roster log's head consequently
   stays anchored before the removal entry -- the unsealed state another
   enrolled client's login sweep detects and seals.
3. **The rung residue is accepted.** No entry can remove its own signing key,
   so the acting rung stands REVEALED in `updateKeys` after the forget. That
   is credential-held authority (only the ladder seed derives it), consumed
   and retired by the credential's next self-enrollment, and struck by
   credential retirement's full-inventory walk. The design's "no residual
   update authority" reads as the FORGOTTEN CLIENT's authority, which the
   entry fully removes.

Forgetting the LAST enrolled durable client refuses with the name-stable
`LastDurableClientForgetError`: that transition -- to the client-less,
ladder-anchored state -- is the two-entry install-revoke-remove ceremony
recorded in decision 0004's 2026-08-19 amendment, not this entry.

## Rejected

- The two-entry reveal-then-remove shape: same end state (the final entry's
  signer rung still cannot retire itself), one more entry, one more spent
  rung, and a torn window where the rung is revealed and the client still
  stands.
- Widening the ceremony-tail license to admit a ladder-signed roster append
  after a non-inventory-changing removal entry, to preserve
  document-edit-first: it admits exactly the ordinary enroll/revoke class the
  license exists to exclude.
- A retirement sweep for the revealed rung: new machinery for a residue the
  next self-enrollment consumes anyway.
