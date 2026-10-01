# 0025: The `connections` directory entry contract

- Status: accepted
- Date: 2026-10-01
- Driving work: the design of a single wallet-side record of every known third
  party, replacing the writer roster, the client-labels file, and the
  history-log grant index. Extracted at that design's approval.
- Affects: wallet-core (`/space` collection roster, the directory entry codec
  and its upsert helpers, the writer policy constants, the ARCHITECTURE.md
  permanent-constants table); freewallet and dcw (every reader and writer of the
  directory); wallet-backup (the survey's roster set);
  encrypted-collections-spec (a second use of the blinded-index key, recorded in
  0026).

## Context

A wallet records a third party it has dealt with in several unrelated places: an
app's seed in its own collection, its grants in history rows, its DID on a
Collection Metadata `generator` stamp and in key-epoch rosters; an agent in
history rows and rosters only; an enrolled wallet client in the account
document, the user key roster, a labels file, and a revocation row; a writer's
`writerId` in a roster no wallet reads. The history log was the only index of
which grants a party holds, so losing one row lost the revocation hook.

Every value stored in such a record is permanent once an account holds it, and
two wallets on different release schedules read and write it.

## Decision

One encrypted, mutable Space collection, `connections` (display name
`Connections`), joins the wallet Space provision roster. It is
`shareable: false` and `grantable: false`, and its only key-epoch recipient is
the user key. No party ever writes it; the wallet writes every entry, and a
wallet client touches only the writer member on its own entry.

The unit is the party, keyed by DID. One entry per party, with these members:

- `version`, the integer `1`.
- `kind`, the party's self-description:
  `'app' | 'agent' | 'wallet-client' | 'contact'`. An unknown value reads as an
  unclassified party.
- `id`, the party's DID. Absent only on a keyless writer entry.
- `name`, the latest self-declared name, and `label`, the user's own name for
  the party, optional. Two fields, never merged.
- `origin`, the attested Web origin, and `url`, the canonical app URL, for an
  App Connect app only. `url` matches `generator.url`.
- `appKey`, the app-key Resource id in the app-key collection, present only
  while the wallet holds the key it minted. Its presence is the one statement of
  custody.
- `firstSeen`, `lastSeen`, `retired`, ISO 8601 UTC. `retired` is present once
  the relationship ended. An entry is retired and never deleted.
- `grants`, an array of `{ zcap, grantKind, grantedAt }`. `zcap` is the
  delegated capability document verbatim. `grantKind` is `'grant' | 'share'`,
  always present; an unknown value reads as a plain grant. `grantedAt` is the
  time of the consent that wrote the grant.
- `writers`, an array of `{ writerId, label, lastSeen, active }`, the retired
  writer roster's members minus `version` and `signingKeyMultibase`. Policy:
  `active: false` after 90 days unseen, `lastSeen` touched at most once a day,
  at most 8 members per entry with the oldest `lastSeen` dropped beyond it. The
  values are not stored but are shared constants, since every wallet that sweeps
  must agree.

No `signingKeyMultibase`: a wallet client's `id` is its did:key, whose
method-specific part is the multibase the account document carries. Joins derive
it from `id`.

## Rejected Alternatives

- **OAuth's public and confidential client kinds.** "Public" already means
  world-readable in these repos, and "confidential" implies a vouched identity a
  self-minted did:key does not give.
- **`web-app` and `mobile-app` kinds.** Web versus native is whether `origin` is
  present. A kind would duplicate it and could disagree.
- **A custody enum, or a custody value derived from other fields.** Whether the
  wallet holds the party's key is whether `appKey` is present. A derived value
  could drift from the pointer revocation uses.
- **One `label` for both names.** A later self-declaration would overwrite the
  user's rename, or the rename would freeze the self-declaration. The user's
  label also stays out of `generator.name`, which the host reads in plaintext.
- **Deleting an entry at revocation, or retire then sweep.** A departed party's
  `generator.id`, `createdBy`, and old `writerId`s would stop resolving.
  Retirement costs one small Resource per party, paced by user consent. A later
  sweep adds an invariant and a mender for little.
- **Letting parties write their own entries.** A party sealing an envelope into
  the directory must be an epoch recipient, and could then read every other
  party's grants.
- **Bare zcap ids, or `{ id, target, expires }`, as a grant.** Revocation POSTs
  the full capability, so either shape sends revocation back to the history log.
  Ids alone also cannot show an expired grant.
- **The Grant activity's summary shape
  (`{ id, target, allowedActions, expires, zcap }`).** Two copies of one value
  that can disagree; a decision reads the capability, not a summary.
- **The bare capability with no wrapper.** A later per-grant member would then
  need a `version` bump.
- **A share told by shape** (a read-only Collection-URL zcap on a shareable
  collection). It misfires on a plain read grant of the same shape, so an
  unshare could revoke the wrong grant.
- **A share-only marker, absent on other grants.** Absence would not tell a
  plain grant from an older build's write.
- **`grantKind` split by writing flow (`'app' | 'agent'`).** The entry's `kind`
  already names the holder.

## Consequences

- The directory is the revocation index. Grants are recorded on the entry at
  consent, before escrow and delivery, so a failed entry write fails the request
  closed. The history log becomes audit trail only.
- A stored grant with its embedded chain runs to a few kilobytes, and an app
  that reconnects often accumulates grants until a disconnect empties them.
  Pruning expired grants is deferred.
- The writer roster collection `registered-writers`, its entry shape and label
  constant, and `key-map/client-labels.json` are retired as breaking changes. No
  account stored a writer entry; every Space provisioned since the roster
  shipped holds an empty collection under that id, which nothing reads or
  deletes.
- The permanent-constants table gains rows for the collection id, the entry
  members, the `kind` and `grantKind` vocabularies, and the writer policy
  values.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A party kind appears that the four values cannot describe and `appKey` plus
   `origin` cannot distinguish. Add a value; do not reinterpret an existing one.
2. A per-grant fact the wrapper cannot carry is needed by a decision, not only
   by display. Add an optional member; readers already preserve unknown ones.
3. A storage format change lets a party authenticate its own write without
   becoming an epoch recipient.

Any change is a new `version` value with the reading rules of 0027, not an
in-place reinterpretation of a stored member.
