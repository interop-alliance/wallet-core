# 0016: `keys.json` carries the authentication binding and the webvh DID, written under preconditions

- Status: accepted
- Date: 2026-09-03
- Driving work: the browser wallet's FW-344 design gate, which retires
  its standalone did:web document mint and leaves the KMS
  authentication key as the only thing the key map records. Extracted at
  that design's approval.
- Affects: wallet-core `/webvh` (`DidWebKeyMap`, `DidWebKeyMapV2`,
  `writeKeysJson`, the key-map store's PUT, `repairKeyBindings`) and
  `/clientAnnex` (the ladder-anchored genesis' second write); both
  wallets' genesis stages; the `key-map/keys.json` resource on every
  WAS deployment.

## Context

`key-map/keys.json` recorded a key map built for a standalone did:web
identity: an `authentication` binding, a `keyAgreement` binding, and,
once the account DID exists, a `webvh: { did }` block. The
`keyAgreement` member names a server-held X25519 key the account
document excludes on purpose, because no server-held key may be a wrap
target, so nothing may address it.

The resource is written twice per signup, one stage apart: the KMS stage
records the authentication binding, and the ladder-anchored genesis
rewrites the map with the `webvh` block added. Both writes were bare
PUTs. Two concurrent establishments could therefore leave the stored map
naming one key while the published genesis entry carried another, with
no failure to notice it. The genesis takes the served `vmId` verbatim
into the world-readable document after a type check that confirms only
that two string fields are present, so a served map is not evidence of
anything on its own.

## Decision

The layout is `{ authentication: { vmId, kmsKeyId }, webvh: { did } }`.
The `keyAgreement` member is no longer written. Readers ignore a legacy
member; there is no migration, so a map rewritten by a signup or an
establishment re-run drops it, and one on a promoted account in the
steady state keeps it unread.

Each write carries its own precondition. The KMS stage's write is
create-if-absent (`If-None-Match: *`). The genesis' rewrite, which adds
the `webvh` block, is an `If-Match` on the ETag the first write
returned. Applying one precondition at the store instead of per call
site would refuse the second write on every signup and strand a map with
no `webvh` block, which the `expectedDid` fallback readers need.

A lost race adopts the served map rather than retrying against it. That
adoption is conditional: a served map is adopted only when the multibase
in its `vmId` matches a key the session's own keystore lists. On a
mismatch, or when the keystore cannot be listed, the run mints instead
of adopting.

`repairKeyBindings` is removed. It has no production callers in any
wallet, and it is already unreachable on a promoted account, since it
requires a keystore-backed `keyAgreement` verification method in
`did.json` that the projection deliberately excludes.

The standing rule about server-held keys is restated as an exclusion:
no server-held key may appear under `assertionMethod` in an account
document, because membership in that relation confers resource-log
append authority as the account. It is not "the relation lists client
signing keys only", which is false on the default account shape, where
a standing credential's ladder VM stands under `assertionMethod` for as
long as its credential stands. No KMS `assertionMethod` key is minted;
that rejection is not reopened.

## Rejected Alternatives

- No precondition on either write, relying on the served-`vmId` check
  alone to keep a wrong key out of the document. It leaves the stored
  map and the published entry free to disagree, silently and durably.
- One write at the join instead of two, carrying both the authentication
  binding and the `webvh` block. Fewer requests, and it would remove the
  double write, but it moves the authentication binding's persistence to
  after the genesis entry, which changes what a run torn between them
  leaves behind.
- Preserving an existing `keyAgreement` member on rewrite. It records a
  binding for a key no document may name, so a rewrite that keeps it
  records something nothing may use.

## Consequences

- The map narrowing and the removed export are surface removals, so both
  take a BREAKING label at a minor bump, matching this package's
  practice for the same class of change.
- A wallet that writes the map on a path where the account DID does not
  yet exist still writes twice per signup; this decision preconditions
  the pair rather than collapsing it.
- A run torn between the two writes leaves a map with the authentication
  binding and no `webvh` block. That is the state the fallback readers
  already handle, and the next establishment re-run rewrites it.
- The served-`vmId` check is the one place the keystore is listed
  despite a present map. That is the fail-closed direction: a malicious
  host serving a map with an attacker's multibase gets a mint rather
  than a publication.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The KMS authentication key is retired outright, at which point the
   map's remaining content is the `webvh` block and the resource may not
   be worth keeping.
2. The two writes are collapsed into one at the join for a reason other
   than tidiness (a measured cost, or a tear state the split creates),
   which changes which precondition each carries.
3. The Resource Log Profile stops authorizing log appends by
   `assertionMethod` membership, which is the whole basis of the
   server-held-key exclusion above.
