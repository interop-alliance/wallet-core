# 0028: The agent-connection members of a directory entry, and the renewal rules

- Status: accepted
- Date: 2026-10-05
- Driving work: the design of cleartext audiences, which connects a
  subscription agent to the wallet through the connections directory
  and renews the agent's grants without a prompt. Extracted at that
  design's approval. Extends 0025.
- Affects: wallet-core (`/connections`: the entry codec, `receivedGrants`,
  `recordReceivedGrants`, `recordRenewedGrants`, `settleOutboxItem`,
  `markDeclined`, `retireConnection`, `connectionDidKey`,
  `agentGrantDue`, `pruneSupersededGrants`; `/space`: the message
  envelope codec; the ARCHITECTURE.md permanent-constants table);
  was-client (`agentsFromSeed` is the derivation); freewallet and dcw
  (every reader and writer of an agent entry).

## Context

Record 0025 gave a directory entry one direction: the grants the wallet
delegated to the party. Connecting an agent needs the other direction
too. The wallet must present a stable key of its own toward the agent,
hold the capability the agent handed it to reach the agent's inbox, and
queue what it owes the agent. Every client of the account, remembered,
transient, or the mobile wallet, must derive the same key from the same
stored seed and renew the same grants, so the members and their rules
are a shared contract rather than one wallet's choice. Two wallets on
different release schedules read and write them.

The renewal pass also found a trap in its own first draft: a record
renewed at one login stayed due at the next, so every login appended a
record until the entry's one Resource hit the upload bound and every
write to it failed, consents included.

## Decision

An agent entry gains five optional members. `version` stays `1`; the
members are additive, a writer keeps every member it does not know, and
an older build's retirement leaves the new ones in place.

- `seed`, 32 bytes, base64url with no padding, the wallet's pairwise
  key toward this party. Written once; a write that finds a different
  `seed` already on the entry refuses. The did:key is derived by
  was-client's `agentsFromSeed` under the existing bootstrap handle and
  key name (`'bootstrap-key'`), with no derivation label of its own, so
  every client derives the same did:key (`connectionDidKey`).
- `seedTag`, the full 32-byte `HMAC-SHA-256(key, utf8('connections/v1'
  + '|' + 'seed:') || seedBytes)`, base64url with no padding, keyed by
  the directory's blinded-index key. The `seed:` arm joins the resource
  id's `did:` and `writer:` arms under `CONNECTIONS_ID_PREFIX`. Written
  with the seed in the same write. The codec refuses a seed with no tag,
  and every site that turns a seed into a key verifies the tag first and
  fails closed on a mismatch.
- `grantsReceived`, a list of `{ zcap, grantKind, receivedAt }` mirroring
  `grants`: the capabilities the party handed the wallet. `grantKind` is
  `'inbox'` for the party's POST capability on its own inbox; an unknown
  value is kept as stored. `receivedGrants` keeps a record only when
  `zcap.controller` is the entry's pairwise did:key and
  `invocationTarget` lies outside this Space, and an `inbox` record must
  allow POST. `recordReceivedGrants` replaces a record with the same
  `grantKind` and target when the new `expires` is later, treats an
  equal zcap id as a no-op, drops a record past `expires` plus the
  revocation clock skew, and refuses a retired entry. A reader treats a
  record as lapsed at the earlier of its `expires` and `receivedAt` plus
  the share lifetime. A push goes through the live `inbox` record with
  the latest `expires`. A push the party's server refuses (a 401, a 403,
  or a WAS host's masked 404) drops that one record (`dropReceivedGrant`)
  and keeps the outbox, so the replacement channel the party hands over
  is stored whatever its `expires` and the queued envelopes wait for it.
- `outbox`, a list of `{ message, createdAt }`: a pending envelope
  verbatim and its queueing time, ISO 8601 UTC, with no channel member.
  `recordRenewedGrants` writes the renewed grant records and the pending
  envelope in one compare-and-swap. An item is removed on a successful
  push (`settleOutboxItem`), kept on a network error or a 5xx, and
  discarded once every zcap it carries is past `expires`. A same-scope
  renewal replaces the pending envelope of that scope and removes the
  superseded zcap from an older envelope carrying several scopes.
- `declined`, ISO 8601 UTC, present while the owner's decline of this
  agent's offer stands. `markDeclined` writes it; `recordGrants` deletes
  it on a fresh consent. Validated like `retired`.

Retirement empties `grantsReceived` and `outbox`, keeps `seed` and
`seedTag`, and leaves `declined` as stored. `retireConnection`'s no-op
short-circuit includes the two lists, so a re-retire empties both. Every
reader ignores the received list and the outbox on a retired entry.

On `grants`, the agent's audience and inbox grants carry `grantKind:
'grant'`; the renewal pass finds the inbox grant by its target. A
renewed record carries `renewedAt`, ISO 8601 UTC, beside the kept
`grantedAt`, which stays the time of the consent.

The renewal rules:

- A renewed grant is appended as a new record; the superseded record's
  body is never replaced, since a replaced body would strand a still-live
  zcap past every revoke. The superseded record stays until its `expires`
  plus the clock skew, when `pruneSupersededGrants` drops it, or sooner
  once its chain is dead and the outbox item carrying its successor was
  removed on success.
- The renewal candidate per scope is the latest record: same
  `invocationTarget` and `allowedAction`, greatest `expires`. A record
  with a later same-scope successor is superseded and never a candidate.
- The renewal scope is the grants a connection request's consent
  produced: GET and HEAD on an audience collection, and POST on this
  Space's `inbox`. A grant is in scope when its `grantedAt` equals that
  of an `inbox` grant record on the same entry and its actions are one
  of those two. A write grant, and any grant from a later request that
  was not a connection request, is never silently renewed.
- `agentGrantDue` reads a grant as due inside the agent renewal window,
  or when its chain is dead by replacement while the parent's signer is
  still listed. A root-anchored grant is due only by its window. A grant
  whose recorded `expires` is already past is not due.
- A grant is renewed only when its delegation proof verifies as this
  account's (`verifyRecordedGrantProof`): the signature is verified under
  a key the current document lists under `capabilityDelegation`, the
  grant's own on the root arm and the embedded generation delegation's on
  the annex arm, where the parent must be delegated to an annex DID in the
  account's auxiliary Space. Matching the proof's `verificationMethod`
  against the document alone would let a host plant grants whose proofs
  name a current key.

The message envelope a push carries is `{ type: 'Grant', actor,
object: { zcaps } }`, built and parsed on `/space` by
`inboxGrantMessage` and `parseInboxGrantMessage`, so every wallet and
any agent built on this package share one shape.

## Rejected Alternatives

- **A `version` bump.** The members are additive and optional, and 0027's
  lenient reading already preserves them; a bump would fail every older
  wallet's write for nothing it needs to know.
- **`held` and `grantsHeld`** for the received list. A list that keeps
  stale records should not claim liveness. **`pairwiseSeed`**, **`key`**,
  and **a single `inbox` zcap member**: the seed is the entry's one seed,
  and an agent that moves its inbox holds two live records for a while.
- **The app-key names, or a new key name, for the derivation.** Every
  client must derive the same did:key, and the bootstrap constants
  already exist and yield the X25519 twin a later key layer would use.
- **A bare-bytes tag input, or a 16-byte truncation.** One key over two
  unseparated input kinds; nothing gained by truncating a member stored
  once per entry.
- **A new `grantKind` for the agent's grants.** The target already says
  what the grant is.
- **Overwriting `grantedAt` at renewal.** Loses the consent time the
  Applications page shows and the renewal scope keys on.
- **Replacing the renewed grant's body on the entry.** Strands the
  superseded zcap past every revoke.
- **Renewing every record `connectionGrants` keeps.** The unbounded
  growth above.
- **A `channel` member or a `pushedAt` member** (freewallet's record on
  the outbox).

## Consequences

- An agent entry holds the wallet's own secret toward the agent. A
  revoked client that held the directory keeps that seed, bounded by the
  POST-only channel it reaches, until a seed rotation message exists.
- A lost directory loses every seed; a reconnect mints a new one and the
  agent recognizes the owner by other means.
- The entry's one Resource now grows by one record per renewal per
  scope plus one pending envelope per unpushed scope, bounded by pruning
  and by the number of scopes.
- The permanent-constants table gains the five members, the `seed:`
  arm, `'inbox'` as a received grant kind, `renewedAt`, and the envelope.
- Nothing here verifies a received zcap's delegation chain; the agent's
  server verifies at invocation.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A message kind needs a member the outbox item or the envelope cannot
   carry. Add an optional member; readers preserve unknown ones.
2. Account did:webvh identities become usable across hosts, so the
   pairwise did:key could be replaced by the account DID. The seed and
   its tag then become one option rather than the rule.
3. A seed rotation ships, which must state what happens to `seedTag`,
   `grantsReceived`, and the pending outbox across the rotation.

Any change is a new `version` value with the reading rules of 0027, not
an in-place reinterpretation of a stored member.
