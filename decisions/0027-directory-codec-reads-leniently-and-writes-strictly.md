# 0027: The directory codec reads leniently and writes strictly

- Status: accepted
- Date: 2026-10-01
- Driving work: the design of the `connections` directory (0025), whose
  entries two wallets on different release schedules read and write, and
  whose writer the storage host can impersonate. Extracted at that
  design's approval.
- Affects: wallet-core (`parseConnectionEntry`, the upsert helpers
  `recordGrants`, `removeGrants`, `retireConnection`,
  `setConnectionLabel`, the shared name normalizer, the
  `ConnectionKindMismatchError` class); freewallet and dcw (every
  listing and every consent-time write).

## Context

Mixed builds are the norm: a mobile wallet lags the app store, the two
wallets sit on different wallet-core ranges, and a long-lived browser tab
runs yesterday's deploy. The retired writer roster's loop treated a body
it could not parse as absent and wrote a fresh entry under the read
ETag, which on this collection would wipe a newer build's grants.

An EDV envelope does not authenticate its writer. The host can seal an
envelope to the epoch's public key and plant an entry, replace one, or
serve an older version. It also holds every capability a party ever
invoked, so a planted grant can be a genuine one.

Two producers write `name`: an agent's or app's request, bounded by
wallet-request's request check, and an enrollee's suggested label,
bounded by the onboarding label rule. The two rules measured length
differently, so an approver could write a body the codec refused, and
every listing then skipped it forever.

## Decision

Reading:

- A reader preserves every top-level member and every grant-wrapper
  member it does not know, verbatim.
- A well-formed body whose `version` is above this build's is read for
  display from the members this build knows. A body that fails the shape
  check on a known member is unparseable and skipped by every listing.
- Every reader drops a grant whose `zcap.controller` is not the entry's
  `id`, or whose `zcap.invocationTarget` is not under this Space's
  container URL.
- A disconnect reads the Resource `appKey` names and requires the app
  key's seed to re-derive the entry's `id` before deleting it.

Writing:

- Every write is a read-modify-write under `ifMatch` or a create under
  `ifNoneMatch`, changing only the members its helper owns.
- A helper that finds a body it cannot parse, or whose `version` is above
  its own, refuses to write and does not treat the body as absent.
- `recordGrants` and the wallet-client writes take the `kind` their flow
  writes and refuse an entry of another kind with
  `ConnectionKindMismatchError`, matched by `err.name`.
- `retireConnection` takes the zcap ids the revocation handled and throws
  if its re-read finds a grant outside that set, since a concurrent
  consent merged it.
- `name` is bounded by the onboarding label rule: 64 code points after
  the control and bidi character set is stripped and the result trimmed.
  One wallet-core function implements it, and the codec and every
  producer call it before writing.

## Rejected Alternatives

- **Skip a higher-version body as unparseable.** The party drops off
  every listing on the older build while its grants and epoch membership
  stay live, which is the lost-row shape the directory exists to close.
- **Treat an unparseable body as absent and overwrite it.** The writer
  roster's rule; it wipes a newer build's grants.
- **The codec takes the request-side bound (UTF-16 units, control
  characters refused).** It tightens a shipped enrollment rule, and a
  40-emoji label that enrollment accepts would still be refused.
- **Two separate name rules, kept in step by convention.** The drift that
  produced the skipped-forever entry.
- **Signing each entry, or pinning each entry's ETag per visit.** Not in
  the first build. The reader checks above bound what a planted entry
  steers to a stale listing row and a harmless re-disconnect; neither
  guard changes what authority a party holds. Tracked for a later build.

## Consequences

- An older build shows a party a newer build wrote, and its disconnect
  fails with a message until the build updates. A rotation that reads
  the directory fails closed while such a body stands.
- The host can make a departed party reappear as a listing row. It
  cannot steer a revocation at another party, delete another party's
  seed, or re-admit a party whose rotation landed.
- wallet-request's request-side name check stays as the requester's
  contract; the entry write normalizes the accepted name again.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. Entries gain an authorship proof the host cannot forge, verified
   before decrypt. The controller and seed checks then become second
   checks rather than the only ones.
2. A `version` bump changes the meaning of a member this rule reads for
   display, so lenient reading would show a wrong value.
