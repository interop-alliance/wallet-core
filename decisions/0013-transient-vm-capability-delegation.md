# 0013: The transient annex VM also publishes under capabilityDelegation

- Status: accepted
- Date: 2026-08-28
- Driving work: the public-computer login path for the browser wallet. A
  visit-scoped client recorded in the annex signs the app-connect and share
  grants that visit mints, and those grants were refused by the storage server
  because the key was published under `capabilityInvocation` alone.
- Affects: wallet-core `/clientAnnex` (`enrollClientAnnexTransientClient` and
  the annex document layout it writes); the browser wallet's grant-minting paths
  as consumers; the storage server's client-annex clause, which the shape must
  not collide with.

## Context

Decision 0002 fixed the transient VM's shape:

> Transient VM shape: `capabilityInvocation` only, with relations stated
> explicitly on every companion VM. No `authentication`, no `assertionMethod`,
> no `keyAgreement` twin -- so the client controller-marker convention does not
> arise in the companion at all.

The bullet argued three exclusions and did not mention the fourth.
`capabilityDelegation` was passed through unchanged rather than excluded on a
reason.

A transient session signs its own storage requests with that key and also
delegates onward with it: an app-connect grant, and a shared collection grant.
Both are `CapabilityDelegation` proofs whose verification method is the
transient VM. The storage server verifies each delegation link by loading the
delegator's document and asserting membership in `capabilityDelegation`. Every
such grant was refused, and the refusal is masked as a 404, so a public-terminal
visit produced a consent screen, a provisioned collection, and an app that could
read nothing.

## Decision

The per-visit transient verification method publishes under
`capabilityInvocation` and `capabilityDelegation`, and under no other relation.
All five relationship arrays stay stated explicitly, because the library
defaults a purpose-less method into `authentication` at normalization.

The three remaining exclusions keep their reasons. `authentication`: the DIDAuth
path signs as the bare did:key. `assertionMethod`: the annex log is not an
assertion venue for a per-visit key. The `keyAgreement` twin: the client
controller-marker convention does not arise in the annex.

This narrows one bullet of decision 0002. That record stays accepted and carries
an amendment line pointing here.

## Rejected Alternatives

- **Sign a transient session's grants with the ladder VM, root-parented.** The
  ladder VM already stands under `capabilityDelegation` in the account document
  and its seed is in session memory. Rejected on three counts. It gives up the
  per-hop expiry clamp that ties a visit's grant to its generation. It covers
  ladder-anchored accounts only, since an account with enrolled clients anchors
  no ladder VM. And it puts a ladder-signed, root-parented grant in front of the
  storage server's client-annex clause, which admits a ladder-signed link only
  on grantee identity, on a `did.jsonl` PUT, or on a delegated-clients Space
  target -- the grant matches none of them, and it also falls outside the
  narrowing that clause is expected to receive. Do not reopen.
- **Refuse app-connect from a transient session outright.** Named for
  completeness. It retires the public-computer flow the wallet shipped
  deliberately. Do not reopen.
- **Record each minted delegation in a hash-chained log, to make the grant as
  loud as the key.** Unreachable by the granting key: a transient VM holds no
  update key, so it cannot extend a `did:webvh` log, and it is excluded from
  `assertionMethod`, so it cannot append to a resource log. The remaining
  signers are the ladder into the world-readable account log, which would
  publish grantee DIDs permanently and burn a rung per grant, or the ladder into
  a new resource log, which the ceremony-tail license refuses absent an
  inventory change. Independently, no post-hoc record binds an attacker who
  holds the key, because delegation is offline signing with no chokepoint to sit
  on. The wallet's existing activity record already meets the App Connect spec's
  grant-recording obligation.
- **Publish the transient VM under `capabilityDelegation` only.** It would
  satisfy the delegation purpose check and break something else: a method in
  `capabilityDelegation` and absent from `capabilityInvocation` is precisely how
  both the wallet library and the storage server recognize a ladder VM. The
  transient VM would be judged by the client-annex clause and refused, and the
  visit's own storage requests would lose their invocation authority.

## Consequences

- A grant minted in a visit-scoped session outlives that session's tab. Its
  lifetime depends on the account's shape. On an account that never remembers a
  browser -- the default -- no garbage collection runs, so the bound is the
  minimum of the grant's own expiry and the generation delegation's expiry. On
  an account with enrolled clients the pointer swap becomes reachable for a
  ladder-signed generation delegation; for a client-signed one it does not apply
  at all, and the bounds are annex log deletion, explicit revocation, and
  expiry. Granting an app long-lived access is what the flow exists for, and the
  consent surface owes the user a statement of the real bound.
- Every capability a transient session delegates is bounded to the Space items
  subtree, because that is the generation delegation's `invocationTarget`. A
  grant naming the Space itself is refused by target attenuation, so the wallet
  refuses that class at grant resolution rather than minting a capability that
  verifies nowhere. The bound is deliberate: widening the generation
  delegation's target to the bare Space URL was considered and rejected, because
  it would reopen the exclusion of Space Description PUT and Space DELETE from
  the capability's bytes.
- The delegator's relation is re-checked at every invocation against the current
  annex document. Retiring the generation retires a grant chained under it only
  by pointer equality, only for a ladder-signed generation delegation, only on a
  conforming server, and only outside the server's document-cache window. It is
  not a substitute for per-grant revocation in the other cases.
- The grantee may sub-delegate onward within the remaining chain budget. The
  sub-tree dies with the generation, which is a better bound than a
  root-parented remembered grant's sub-tree has.
- The two-relation shape is what keeps the transient VM out of the ladder-VM
  recognition rule in all three implementations: the wallet library's
  `ladderVmIds`, its `inventoryOf` (which feeds the ceremony-tail license), and
  the storage server's client-annex clause. Any future narrowing of that shape
  has to preserve the non-collision in all three.
- The completion predicate is verification-method presence, so a re-run over an
  existing generation does not backfill the relation. Visit keys published
  before this decision never gain it. Harmless: every visit mints a fresh key.
- Each invocation of a transient-minted grant makes the server verify the annex
  log beside the account log, a cost class that did not exist before, incurred
  by background apps on their own cadence and bounded only where garbage
  collection is reachable.
- No storage-server change. The resolver already serves the annex document to
  the purpose check.

## Revisit Criteria

1. The client-annex clause narrows in a way that judges a link whose proof
   method carries both relations, or `inventoryOf`'s copy of the asymmetry
   changes. The shape would then need a different distinguisher than relation
   asymmetry. The rule's normative home is app-connect-spec
   `decisions/0003-ladder-authority-clauses.md`.
2. A transient session needs to delegate something the generation delegation
   does not parent, which would mean the grant no longer inherits the
   generation's lifetime and this record's bound stops holding.
3. Garbage collection becomes reachable from a credential-only visit, or the
   generation delegation's TTL changes. Either would move the per-shape lifetime
   statement above, which today rests on GC running from the remembered-login
   chain alone -- and the same reachability is what bounds the per-invocation
   verification cost the widened grants add to the server.
4. A visit-scoped key acquires a second delegation venue (a second annex, or an
   account-document entry), at which point publishing the relation in the annex
   alone stops being sufficient.
