# 0029: Three shapes the key layer for audiences does not take

- Status: accepted
- Date: 2026-10-05
- Driving work: the design of cleartext audiences, whose considerations
  note also records the deferred key layer (sealed posts per audience)
  so it is not re-derived. The cleartext layer was approved; the key
  layer is not designed. These three rejections bind that later design.
  Extracted at the cleartext design's approval.
- Affects: wallet-core (`/keys`, `/descriptors`, the user-key cascade,
  and the audience module a key layer would add), encrypted-collections-
  spec (the profile edits a key layer would need), was-teaching-server
  (its KMS facet), freewallet and dcw (the owner-side ceremonies).

## Context

Sealing posts per audience means each audience has a key with epochs,
members hold wraps of those epochs, and a rotation redistributes them.
At the scale the use case names, a dozen friends to millions of
subscribers, any per-person scheme pays N signatures or N wraps and any
shared-secret scheme pays N redistributions. The walk of late September
settled the shape that scales: an audience is a collection of keys whose
governed log carries the epochs, members pull their own wrap Resource,
and only the owner's clients rotate. Three shapes were considered on the
way and rejected for reasons that do not depend on scale, so they stay
rejected whatever the later design chooses elsewhere.

## Decision

A key layer for audiences does not take any of these three shapes:

1. **The KMS facet as the key broker.** Members do not obtain an
   audience key by invoking `deriveSecret` (or any operation) on a
   KMS-held key. The KMS is operational key custody for the account's
   own keys, and it stays off the critical path of the WAS and social
   profiles' read path. A member's read must be satisfiable by a WAS
   server and a wrap alone.
2. **Per-envelope recipient wraps.** A post's envelope is not sealed to
   its audience's members individually. Friending would rewrite every
   friends-only post and unfriending the same, and the member set would
   leave the descriptor for the envelopes.
3. **The agent's key under the account document's `assertionMethod`.**
   The agent never gains the authority that signs a descriptor-log
   append. That relation is account-wide append authority over every
   descriptor log the account governs, not one audience's. Only the
   owner's clients rotate; on the large tier the pull axis enforces
   removal (an expired child, a deleted membership Resource), and
   rotation is hygiene an owner client runs on its next visit.

## Rejected Alternatives

The three shapes above are the rejected alternatives; this record
exists to keep them rejected. The shape they lost to, recorded in the
considerations note and not yet designed: an audience as a collection
of keys with a governed `meta/log` whose recipients are the user key and
the agent, per-member wrap Resources each readable by that member's
Resource-depth capability, friending as a wrap covering the backlog and
unfriending as a delete plus a rotation, the agent re-wrapping lazily on
inbox requests, and the envelope naming its audience in the AEAD-bound
parameter so a member routes a decrypt by the wraps it holds.

Two more shapes were set aside on the same walk without the same
finality: a shared roster per audience, which leaks member count and
churn even blinded, and wraps pushed to each member's own inbox, which
costs N writes to N hosts per rotation. Either may be re-weighed if the
pull shape fails in practice.

## Consequences

- A later key-layer design starts from the pull shape, and a review of
  it may not spend time on the three rejected shapes.
- A per-log controller document listing the owner and the agent, which
  would let the agent append to one audience's log without
  `assertionMethod`, is deferred, not rejected.
- The cleartext layer's agent, which holds GET and HEAD grants and no
  signing authority, already conforms to the third rule.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. For the first shape: the WAS or encrypted-collections profile itself
   adopts a server-side key-agreement operation as a normative read
   path, so the KMS would no longer be an extra dependency.
2. For the third shape: the account document gains a per-relation or
   per-log scoping of `assertionMethod`, so an agent's key could sign
   one audience's log and nothing else. The per-log controller document
   is the deferred form of that.

The second shape has no revisit criterion; mutable posts make a
per-envelope member set a rewrite per membership change at any scale.
