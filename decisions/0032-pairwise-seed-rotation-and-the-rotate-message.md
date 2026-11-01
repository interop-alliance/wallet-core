# 0032: Pairwise seed rotation and the `Rotate` message

- Status: accepted
- Date: 2026-10-31
- Driving work: moving the App Connect response's holder onto the wallet's
  pairwise did:key toward the app, which makes the seed behind that key the
  wallet's standing identity toward every connected party, and so makes its
  custody after a withdrawal of authority a bound worth closing. Extends 0028
  (its revisit criterion 3).
- Affects: wallet-core (`/connections`: the entry codec gains `nextSeed` and
  `nextSeedTag`, the kinds a seed may sit on widen to `app`, the rotation
  helpers, `receivedGrants`, `retireConnection`; `/space`: the `Rotate`
  envelope codec beside `inboxGrantMessage`; the permanent-constants table);
  freewallet and dcw (the ceremonies that withdraw signing authority, the
  outbox push, the drain's handling of an agent's reply); app-connect-spec
  (the agent's obligations in the agent connect section); any agent built on
  the inbox contract.

## Context

Record 0028 gave an agent's connection entry a pairwise `seed`, written once,
from which every client of the account derives the same did:key toward that
agent. The wallet presents as that key, and the agent hands it a POST
capability on the agent's own inbox, whose `controller` is that key. 0028's
consequences stated the residue: a party whose authority the account withdrew
may have read the directory, and so holds the seed and the channel capability
until a rotation exists.

Three kinds of party hold such a seed: a revoked wallet client, a past
transient visit on a credential the account has since retired, and a past
transient visit whose annex generation the GC struck. The first two are locked
out by the ceremony that cut them. The third is not: its credential still
stands, so it can visit again and read whatever the directory holds now.

The holder change widens the set of parties the seed matters to. An app that
connects through App Connect now sees the pairwise did:key as the wallet's
identity for the connection, so an app entry carries a seed too, and a
revoked client can present as the wallet to every connected app, not only post
into an agent's inbox.

Two constraints shape the rotation. The ceremonies order their writes
persist-before-publish, so the successor key must be durable before the agent
is told of it, or a tear leaves the agent knowing a key the wallet lost. And
the successor cannot be derived: the only key the wallet could derive it under
is the directory's blinded-index key, which the party being cut out held while
it was still a client. The successor is random, and therefore stored before it
is announced.

## Decision

### The entry members

`seed` and `seedTag` may sit on an `app` entry under 0028's rules, written at
the App Connect consent by the same resolver a connection request uses: a
stored seed is taken once its tag verifies, an absent one is minted with its
tag, and a stored seed whose tag fails refuses the consent. Retirement keeps
both, on an app entry as on an agent entry.

Two optional members are added, additive under `version: 1`:

- `nextSeed`, 32 bytes, base64url with no padding, the successor seed a
  rotation has minted and not yet promoted.
- `nextSeedTag`, the tag over `nextSeed` under the same `seed:` arm and the
  same key as `seedTag`.

The codec refuses one without the other, refuses a `nextSeed` equal to `seed`,
and holds both to `seed`'s length rule. Every reader that derives the entry's
did:key reads `seed` alone. `nextSeed` is read only by the rotation.

A `replica-server` entry's seed is the replica Space's bootstrap controller
(0031), not a presentation key toward a party. It is never rotated by this
mechanism.

### The rotation sequence

A rotation runs over every entry that carries a `seed`, of kind `agent` or
`app`, retired or not. For each entry:

1. Mint 32 random bytes. Write `nextSeed` and `nextSeedTag` in one
   compare-and-swap. An entry already carrying a `nextSeed` keeps it, so a
   re-run names the same successor.
2. If the entry has a live channel (an `inbox` record in `grantsReceived`
   that `receivedGrants` keeps, on an entry that is not retired), queue a
   `Rotate` message at the head of the `outbox`, ahead of any pending
   renewal, and push it under the key `seed` derives. The message's `actor`
   is that key, and its `object.successor` is the key `nextSeed` derives.
3. Promote: `seed` and `seedTag` take the values of `nextSeed` and
   `nextSeedTag`, the two pending members are deleted, `grantsReceived` is
   emptied (every record there names the retired key as controller), and the
   `outbox` is kept, so its remaining items wait for the channel the agent
   hands the successor.

The promote runs on the push's success, and also on a push the agent's server
refuses (a 401, a 403, or a masked 404) while a `nextSeed` stands, since the
agent has already retired the old key. A network error or a 5xx keeps the
pending state, and the next pass re-pushes the same successor, which the agent
treats as a no-op. An entry with no live channel (every app entry, a retired
entry, a lapsed channel) promotes in the same pass as step 1, with no message.
A connected app learns the new holder at its next connect.

### The `Rotate` message

The second envelope kind on the inbox channel, beside `Grant`:

```
{ type: 'Rotate', actor: <did:key>, object: { successor?: <did:key> } }
```

as `application/json`, built and parsed on `/space` beside `inboxGrantMessage`
and `parseInboxGrantMessage`. `type` is the bare string `'Rotate'`. `actor` is
the key the message retires, and must equal the key the channel's controller
names. `object.successor`, when present, is the key that replaces it. An
absent `successor` is the farewell form: the actor's key retires with no
replacement, and the connection ends. The parser refuses an `object` that is
not an object, and a `successor` that is present and not a did:key.

The agent's obligations: on a `Rotate` with a successor, delegate a fresh POST
capability on its inbox to the successor, post it into the owner's inbox as a
`Grant`, and stop attributing mail to the retired key. On a farewell, treat
the connection as ended: let the owner's grants lapse and revoke the children
it delegated to subscribers at its own discretion. The wallet's drain stores
the fresh capability under 0028's `receivedGrants` rule, which admits it only
when its controller equals the key the promoted `seed` derives.

### What authenticates a `Rotate`

The channel alone. The agent adopts the first `Rotate` that arrives through
the live channel from the key the channel's controller names. The message
carries no proof beyond that, so a party that holds the old seed and the old
channel can post its own `Rotate` naming a successor of its choosing, and the
first to arrive wins.

The bound: the pairwise key carries no authority in the owner's Space. It
signs nothing there, it is in no roster, and the agent's server verifies every
grant at invocation against the owner's account document, so a grant posted
under a hijacked key fails when used. A hijack denies the owner's renewals,
and the wallet detects it: the agent's next channel capability names the
hijacker's key as controller, which `receivedGrants` refuses. The remedy is a
fresh connection request, which mints a fresh seed.

### The triggers

A rotation runs in the ceremonies that withdraw signing authority and lock the
withdrawn party out: client revocation, the forget ceremony, the last-client
transition, a passphrase change, a passkey or backup-credential removal, and a
recovery spend. The annex GC is not a trigger. A struck generation's visitor
entered on a credential that still stands and can visit again, so a rotation
at GC would cost one message per connected agent per sweep and lock nobody
out. The ceremony that locks such a visitor out is the credential rotation,
which is a trigger.

## Rejected Alternatives

- **A proof by a current account-document key on the message.** The wallet
  would sign the body with the enrolled client's key or the ladder VM, and
  the agent would verify against the owner's did:webvh document, fetched from
  the world-readable log. It closes the race, but every agent implementation
  gains a did:webvh log verification, and the enrolled client's key is
  published under `capabilityInvocation` alone, so the document would need an
  `assertionMethod` listing for it. The pairwise key gives no authority today,
  so the cost lands on every agent for a race whose outcome is a detected
  denial of renewal. The optional `proof` member can be added later; readers
  preserve unknown members.
- **No silent rotation.** The old channel carries only a farewell and the
  owner re-consents per agent. One re-consent per agent per trigger.
- **Promote first, with a retiring slot.** `seed` flips at once and the old
  seed sits in a retiring member that signs the one push. Every reader that
  compares a controller against the entry's key would learn a second key for
  the push path, and the retiring key's channel records would need their own
  lifetime rule.
- **Atomic replace, message first.** No new member, but the successor is
  announced before it is durable, and a tear leaves a dead connection whose
  only mender is the reconnect.
- **A derived successor** (an HMAC under the blinded-index key over the old
  seed). Deterministic across re-runs, and computable by the party being cut
  out, who held that key as a client.
- **The annex GC as a trigger.** Above.
- **Two kinds, `Rotate` and a separate farewell.** One more permanent string
  for a form the optional `successor` already expresses.
- **`'Move'`** as the type. The Activity Streams verb implies a destination
  and would want `target` in place of `object`.
- **`pendingSeed` and `successorSeed`** for the pending member. `next` is the
  word the ladder already uses for a key committed ahead of use.

## Consequences

- Between the push and the agent's processing of it, the old key is still
  accepted at the agent. Between the promote and the agent's reply, the
  wallet has no channel toward the agent, and every pending renewal waits on
  the outbox. An agent that never replies leaves the connection to lapse,
  and the owner's remedy is a reconnect.
- Every reader of `seed` and `grantsReceived` is unchanged. The two pending
  members are read by the rotation alone.
- A connected app sees one holder change per rotation, with no message. An
  app that binds state to the holder DID re-binds at the next connect.
- A rotation is one entry write per party plus one push per live channel,
  inside ceremonies that already run the user-key cascade.
- A hijacked rotation is a denial of renewal, detected at the wallet when the
  agent's next channel capability fails the controller check.
- The farewell form has no sender until the account deletion ceremony gains a
  best-effort stage before the directory is destroyed. That stage amends the
  deletion ceremony's design and is its own item in the browser wallet.
- The permanent-constants table gains `nextSeed`, `nextSeedTag`, and the
  `Rotate` envelope.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The pairwise key becomes a recipient of anything confidential, such as the
   X25519 twin receiving audience key wraps in a key layer. The race then
   becomes a compromise, and the message gains a proof by a current
   account-document key, as an additive member.
2. Account did:webvh identities become usable across hosts, so the pairwise
   key could be replaced by the account DID and the rotation retires with it.
3. A party kind other than `agent` and `app` needs a presentation key toward
   a third party.

Any change is an additive member or a new `version` value with the reading
rules of 0027, not an in-place reinterpretation of a stored member.
