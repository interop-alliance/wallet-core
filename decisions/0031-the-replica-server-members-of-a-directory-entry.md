# 0031: The replica-server members of a directory entry

- Status: accepted
- Date: 2026-10-26
- Driving work: the design of replica registration for every session kind, which
  copies an account's Spaces to a second storage server chosen by the user and
  keeps that copy current from any session, remembered or transient. Extracted
  at that design's approval. Extends 0025 and 0028.
- Affects: wallet-core (`/connections`: `CONNECTION_KINDS`, the entry codec,
  the upsert helpers, `connectionGrants`, `connectionDidKey`; `/genesis`:
  `mintSpaceId` is the id mint; `/webvh`: the standing zcap constants; the
  ARCHITECTURE.md permanent-constants table); freewallet (the registration
  ceremony, the login-time replica pass, the Storage page, the ceremonies that
  withdraw signing authority); dcw (every listing that reads the directory);
  web-spaces-server (the registration record the `replicas` item mirrors)

## Context

A user can register a replica of the account on a second storage server, the
replica server. The source server is the one that hosts the account today. The
replica server pulls from the source under a read capability the wallet
delegates to the replica server's DID. Two Spaces are copied to each replica
server: the account Space and the client-annex auxiliary Space. Each copy is a
replica Space on the replica server, with its own registration there.

Every session kind must be able to maintain that copy. A transient session on a
credential-anchored account is often the only session the account ever has. So
the facts a session needs live in durable state: which server, which replica
Spaces, which registrations, which grants, and which user intents are still
outstanding. The connections directory already holds one entry per party and is
the grant index, and the replica server is a grantee. Two wallets on different
release schedules read and write the entry.

The replica server creates a Space only under a did:key. A credential-anchored
account has no enrolled client key, and a ladder VM's key is per credential. The
replica Space needs a controller key that every session can derive, whichever
credential it entered on, until the Space is promoted to the account did:webvh.

## Decision

A `replica-server` entry is one replica server. It uses these members, on
`version` `1`:

- `kind`, `'replica-server'`.
- `id`, the replica server's `serverDid`: a did:webvh whose path is
  `space:server:id`, read from the server's service description.
- `url`, the replica server's base URL.
- `name`, absent or the replica server's host name. `label` is the user's, as
  on every entry.
- `seed` and `seedTag`, the bootstrap seed, with the tag rule and the
  write-once rule of 0028. The bootstrap key K is `connectionDidKey` over them,
  the same derivation as an agent's pairwise did:key, with no label of its own.
  K creates each replica Space, registers it, and promotes it to the account
  did:webvh after the first pull. After promotion K controls nothing.
- `grants`, the pull grants, each with `grantKind: 'grant'`. A pull grant's
  `controller` is the entry's `id`, its `invocationTarget` is one replica's
  `fromSpace`, its `allowedAction` is `['GET']`, and its parent is that Space's
  root. Its `expires` is `STANDING_ZCAP_TTL_MS` (365 days) from the mint, and
  it is renewed inside `ZCAP_RENEWAL_WINDOW_MS` (30 days). A renewal appends
  the successor and keeps the superseded record, as 0028 rules, so each
  replica Space has one current pull grant.
- `replicas`, a list with one item per replica Space on this replica server:
  `{ fromSpace, spaceId, registrationId?, pendingRegistrationId?,
  collections?, stoppedAt?, restartedAt?, lostAt? }`.
  - `fromSpace`, the source Space's container URL, as the registration body
    carries it.
  - `spaceId`, the replica Space's id on the replica server.
  - `registrationId`, the id of the item's registration, present once its
    first registration landed. An in-place replacement of the registration's
    capability keeps it.
  - `pendingRegistrationId`, present only between the mint of a first
    registration's id and the landing of its POST, then moved to
    `registrationId`.
  - `collections`, the registration's collection list. The wallet omits it,
    so the replica server copies every live Collection.
  - `stoppedAt`, written first by the user's Stop and cleared by a completed
    re-start. It marks a stopped snapshot.
  - `restartedAt`, written first by a re-start and cleared last.
  - `lostAt`, written when the replica Space reads absent under the account's
    own authority.
- `declined`, the owner's decline, as on an agent entry (0028).

Each marker is an ISO 8601 UTC time. A re-start writes `restartedAt` and clears
`declined` in one compare-and-swap.

Ids are fresh. A replica Space id and a registration id are each 32 random
bytes, base64url with no padding, minted as `mintSpaceId` mints a Space id. A
replica Space never reuses its source Space's id. Both replica Space ids are
recorded on the entry before either Space is created, and a first
registration's id is recorded before its POST.

The entry is retired only once its `replicas` list is empty. Delete removes an
item after its replica Space is gone. Retirement keeps the names and the seed,
so a later registration with the same server derives the same K.

The reader's target check takes the account's own container URLs. On a
`replica-server` entry those are the recorded `replicas[].fromSpace` values, so
a grant on an auxiliary Space the account no longer points at stays visible
until it is revoked. The codec checks the `replicas` items strictly, as a known
member (0027).

## Rejected Alternatives

- **A `state` enum on the item** (`live | stopping | stopped | restarting |
  lost`). Each timestamp records one intent and when it was taken, as
  `declined` and `retired` do on the entry. A writer sets or clears its own
  marker without deciding a combined state, and no unset value is read as an
  intent.
- **A deletion marker.** It would let the login pass finish a torn Delete with
  no user present. A delete that meets a 404 counts as done, so the user's
  re-run of Delete converges a torn one.
- **`registrationId` as an object** (a current and a pending id). A replacement
  is in place and keeps its id, so the only second id is a first
  registration's pending one. One optional sibling member says that.
- **The same Space id on both hosts.** A replica is not a Space-to-Space copy:
  collections can be excluded, and replication can be one-way or conditional.
  Do not reopen for the account Space or the auxiliary Space.
- **A ladder VM's bare did:key, or an enrolled client's did:key, as the replica
  Space's creating controller.** The ladder key is per credential, so a replica
  left unpromoted by a torn run is stranded once that credential retires. A
  credential-anchored account has no enrolled key.
- **A separate seed member for K.** The entry already carries one seed, its
  tag, and a derivation every directory reader runs.
- **One entry per replica Space.** One party has one entry, and the account
  Space and the auxiliary Space are two replicas on one server.

## Consequences

- Every past holder of the user key can derive K. While a replica Space is
  unpromoted, K is its root controller. A revoked client keeps K until a seed
  rotation exists.
- A directory reader can register a recorded pull capability under its own
  did:key in a tear between the record and the wallet's POST, and win the
  replica server's mapping check. Such a reader already holds the user key and
  K, so this is the same party's reach.
- A malformed `replicas` item makes the entry unparseable, so a rotation that
  reads the directory fails closed while it stands.
- An older build keeps the new members verbatim, shows the entry as an
  unclassified party, and its single-Space reader drops the auxiliary Space's
  grant.
- The entry grows by one grant record per renewal per replica Space, bounded by
  pruning.
- The permanent-constants table gains `'replica-server'`, the `replicas` item
  members, and the marker semantics.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A seed rotation design ships. The bootstrap key cannot be rotated today, and
   the rotation must state what happens to K on an unpromoted replica Space.
2. A content-addressed Space needs a replica, such as an unlock Space located by
   a hash of its did:key. Its replica must keep the source's id, which the
   fresh-id rule does not allow. Add a rule for that Space kind; do not
   reinterpret `spaceId`.
3. A replica Space needs a lifecycle fact the markers cannot record. Add a
   marker; do not reinterpret one.

Any change is a new `version` value with the reading rules of 0027, not an
in-place reinterpretation of a stored member.
