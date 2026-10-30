<!-- Part of wallet-core's architecture docs. The map, the key hierarchy,
     the ceremony inventory, and the glossary are in ../../ARCHITECTURE.md;
     the permanent wire-level constants are in wire-constants.md; this file
     holds one topic in full. -->

# The `connections` directory (`connections`)

The directory is one record per party the wallet has dealt with: an app, an
agent, a wallet client, a contact, or a replica server. It is the wallet's
revocation index, since each entry carries the capabilities delegated to its
party. It is also where a party's names live, and where a wallet client's
`writerId`s are recorded. The wallet writes every entry. No party ever writes
one, since a party that could seal an envelope into the directory would be an
epoch recipient and could read every other party's grants.

The contract is `decisions/0025` (the entry), `0026` (the resource id), `0027`
(the reading and writing rules), `0028` (the agent connection members and the
renewal rules), and `0031` (the replica-server members).

## Public surface

The `connections` directory holds one encrypted entry per party (app, agent,
wallet client, contact, replica server). Its surface is the entry codec (lenient
reads, unknown members kept), the resource id keyed by the collection's
blinded-index key, the store seam and its WAS adapter over the documents feed,
the grant index with the reader checks a revocation reads, the compare-and-swap
upsert helpers and their kind refusal, and the writer arm on a wallet client's
entry (lazy registration, the throttled touch, the per-entry sweep,
`resolveWriter`). An agent's entry adds the agent connection surface: the
pairwise seed and its tag (`connectionDidKey`), the received grants and the
inbox channel, the outbox, the decline marker, and the renewal readers and
writers (`agentGrantDue`, `recordRenewedGrants`, `pruneSupersededGrants`,
`dropReceivedGrant`), and the proof check a renewal runs over a recorded grant
(`verifyRecordedGrantProof`, which verifies the delegation signature under a key
the current document lists). A replica server's entry adds the `replicas` list
and its six helpers.

## The collection

The directory lives in the `connections` collection
(`CONNECTIONS_COLLECTION_SPEC` in `space/collections.ts`): EDV-encrypted,
mutable, `idDerivation: 'random'`, not public, not shareable, and not grantable.
A read grant would hand a requester every party, its names and origins, and
every capability delegated to it. The stored capabilities are bound to their
controllers, so a reader could neither invoke nor revoke them, but the
disclosure alone rules the grant out.

It sits in `WALLET_SPACE_PROVISION_ROSTER` between the synced feeds and the
system collections, so `provisionWalletSpace` creates it and
`ensureWalletSpaceEpochs` installs its epoch[0] and its blinded-index key. Its
only key-epoch recipient is the user key. Unlike the synced collections it has
no local replica and no sync feed. A wallet reads and writes it directly against
the server.

An account provisioned before the directory existed has none, and nothing adds
one. The same holds for a Space already at the server's collection cap.

## The entry

```
{
  version: 1,
  kind: 'app' | 'agent' | 'wallet-client' | 'contact' | 'replica-server',
  id?: string,          // the party's DID; absent only on a keyless writer
  name?: string,        // the latest self-declared name
  label?: string,       // the user's own name for the party
  origin?: string,      // the attested Web origin (App Connect)
  url?: string,         // the canonical app URL (App Connect)
  appKey?: string,      // the app-key Resource id, while the wallet holds it
  firstSeen: string,    // ISO 8601 UTC
  lastSeen: string,     // ISO 8601 UTC
  retired?: string,     // ISO 8601 UTC, once the relationship ended
  grants: [{ zcap, grantKind: 'grant' | 'share', grantedAt, renewedAt? }],
  writers: [{ writerId, label, lastSeen, active }],
  seed?: string,        // the wallet's pairwise seed toward the party
  seedTag?: string,     // the seed's MAC under the blinded-index key
  grantsReceived?: [{ zcap, grantKind: 'inbox', receivedAt }],
  outbox?: [{ message, createdAt }],
  declined?: string,    // ISO 8601 UTC, while the owner's decline stands
  replicas?: [{ fromSpace, spaceId, registrationId?, pendingRegistrationId?,
                collections?, stoppedAt?, restartedAt?, lostAt? }]
}
```

`name` and `label` are two members on purpose. A later self-declaration would
otherwise overwrite the user's rename. `zcap` is the delegated capability stored
verbatim, proof and chain included, since a revocation POSTs it as it stands.
`grantKind` is always written. A reader treats a value it does not know as a
plain grant. `'share'` marks a grant the shared-wallet-collection flow wrote,
which the unshare and the shares dialog pick by it.

The five members before `replicas` belong to an agent's entry and are described
under "The agent connection members". `replicas` belongs to a replica server's
entry and is described under "The replica-server members". `version` stays `1`,
since they are optional and an older build keeps them as unknown members.

There is no signing-key member. A wallet client's `id` is its did:key, whose
method-specific part is the multibase the account document carries.
`signingKeyMultibaseOfDid` (`connections/didKey.ts`) is the one join between a
client's entry and the account document's listing.

## The resource id

One resource holds one party's entry. Its id is the first 16 bytes of
`HMAC-SHA-256(hmacKey, utf8('connections/v1' + '|' + armInput))`, formatted with
pws-client's `edvIdFromBytes` (`connectionResourceId` in
`connections/resourceId.ts`). `hmacKey` is the collection's blinded-index key.
`armInput` is `'did:' + did` for a party with a DID and `'writer:' + writerId`
for a keyless writer, which has no producer yet. The account DID is not an
input. A third arm, `seed:`, keys the seed tag (see "The seed and its tag").

The derivation takes the key as its raw secret or as the resolved key
pws-client's `resolveHmacKey` returns. Both give the same id.

The key stops the storage host from computing the id of a guessed DID and
probing for it, which for a `contact` entry would reveal whether a DID is one of
the user's contacts. The protection lasts only while reads keep it. Outside
consent, a wallet does not GET the id a DID derives to. It reads the listing
once (`readConnections`) and matches the DID in memory (`findConnection`). The
only direct GET at a derived id is at consent, for the party about to be
granted. A read that surfaces a party does not touch the party's entry either.

The key never rotates and is wrapped to the user key, so every revoked client,
retired credential, and backup bundle holds it. Such a holder, working with the
host, can probe for entries created after it lost access.

## Reading

`parseConnectionEntry` (`connections/entry.ts`) is the codec every reader runs.
It checks the shape of every member this build knows, and a body that fails is
unparseable and skipped. Every display string a view renders, the entry's `name`
and `label` and a writer member's `label`, is bounded by the one display-name
rule (`normalizeDisplayName` in `labelText.ts`): 1 to 64 code points once the
control and bidi characters are stripped and the result trimmed. The onboarding
response's suggested label is held to the same rule, so an enrollee's label is
always a name the approver can store. An unknown `kind` reads as an unclassified
party. An absent `replicas` reads as empty, and each item is checked strictly
(see "The replica-server members"). Unknown members are ignored, at the top
level and on a grant wrapper. A well-formed body whose `version` is above this
build's is read for display from the members this build knows
(`isWritableConnectionEntry` says it cannot be written).

`readConnections` (`connections/read.ts`) reads the whole directory once. It
keeps only a body that sits at the id its own `id` (or its one writer's
`writerId`) derives to, so a copied or planted body labels nothing. It reports
what it could not open (`unreadable`) and a body at its own id it could not
parse (`unparseable`), so a caller that decides anything about a party can fail
closed. An absent collection reads as `null`, not as an empty directory.

### The grant checks

An EDV envelope does not authenticate its writer: the host can seal one to the
epoch's public key, and it already holds every capability a party invoked.
`connectionGrants` (`connections/grants.ts`) therefore drops a grant whose
`zcap.controller` is not the entry's `id`, and one whose `zcap.invocationTarget`
is not under one of the account's own container URLs. That set is read off the
entry by `accountContainerUrls`: the account Space's container URL and, on a
`replica-server` entry, each recorded `replicas[].fromSpace`. Every other kind
records no replica, so its set is the account Space alone. The set does not come
from the account document's pointer. After a heal or a transient recovery spend
mints a fresh auxiliary Space, the pull grant on the superseded one stays
visible, and revocable, while its item stands; a reader keyed on the pointer
would drop it, and `retireConnection` would then refuse on it or empty it
unrevoked. `isTargetInSpace` stays the per-URL test, and `isTargetInAnySpace`
runs it over a set. The codec bounds a `fromSpace` to a container URL and no
further, so `accountContainerUrls` leaves out one on another base server
(pws-client's `baseServerUrlOf`): every Space of the account lives on the server
its did:webvh names, so a planted item elsewhere adds nothing to the set, and a
grant on it is not the party's. On a planted `replica-server` entry the target
check therefore admits any Space on the account's own server, as a planted
`fromSpace` there can name one. What still holds is the controller check, and
that a revocation is signed by this account and POSTed to the grant's chain
root, which refuses a capability this account never delegated. No grant-index
reader verifies a grant's proof; the renewal and the restate predicate
(`hasVerifiedPullGrant`) do. A planted grant that fails there can hold
`retireConnection` as unhandled, which is a loud refusal the host can cause by
other means.

Every reader applies both checks over the same set, so a planted entry at one
party's id cannot steer a revocation at another party's capabilities, and the
writers check what they store the same way: `recordGrants` checks a grant's
target inside its read-modify-write against the stored entry's set (a create
admits the account Space alone, and when the writing kind is `replica-server`
every grant must allow `GET` and nothing else), `recordReplicaGrant` checks a
pull grant against its item's `fromSpace`, and `retireConnection` counts an
unrevoked grant on any URL of the set as unhandled (and then refuses a non-empty
`replicas` list). The
same module carries the other grant-index readers the revocation orchestrators
share: the targets (`grantTargets`), the live and expired split
(`splitGrantsByExpiry`), and the recipient kid a grant's controller derives
(`grantRecipientKid`, through pws-client's X25519 twin and the roster kid
builder).

## The store

`ConnectionsStore` (`connections/store.ts`) is the seam: `list`, `get` with its
ETag, and a conditional `put`. It has no delete, because an entry is retired and
never deleted while the account stands. `wasConnectionsStore` builds it over the
collection's Collection handle and its document cipher. A listing walks the
collection's documents feed, bodies and ETags, one request per page, and opens
each envelope with the cipher under the id the feed served it at. A `get` and a
`put` go through the handle. A `put` at an id with no resource yet creates it
there, sealed under the current epoch, as a guarded create (`ifNoneMatch`).

The store reports what it cannot read. A listing names a resource it could not
open, an unknown epoch included, and a `get` that cannot open throws. Reading
either as an absent body could evict a party at the next rotation, or write over
a body the reader never saw.

## Writing

Every write goes through a helper in `connections/upsert.ts`, each a bounded
compare-and-swap loop at the party's own id. It reads the entry, applies its
change to the stored body, and writes under `ifMatch`, or creates under
`ifNoneMatch`. A lost race (`PreconditionFailedError`, matched by name) re-reads
and re-applies, up to three attempts. A helper changes only the members it owns,
so every other member, known or not, is written back verbatim. A helper that
finds a body it cannot parse, a newer `version`, or a body that does not belong
at the id refuses to write. It does not treat that body as absent, which would
wipe a newer build's grants.

- `recordGrants` -- the consent-time write. Creates the entry or merges into it:
  each new grant by capability id, `name` when it passes the rule, `origin`,
  `url`, and `appKey` when given, `retired` and `declined` cleared, `lastSeen`
  moved. Every grant of one call carries the same `grantedAt`. It also writes a
  `seed` and `seedTag` when given and the entry carries none. A different seed
  already on the entry is refused. A `message` is queued on `outbox` in the same
  write, so a restore that records fresh grants and owes the party their
  envelope has no tear between the two. The envelope must carry exactly the
  grants of the call. Each of those zcaps is first removed from any pending
  envelope that carries it, and an envelope left with none is dropped, so no two
  pending envelopes name one zcap id and a torn consent's re-run leaves one
  envelope. `firstSeen` is set only on create, and `label` is never touched. A
  zero-grant consent writes too. Each grant must be delegated to the party and
  target this Space, the same checks every reader applies, so a stored grant is
  one the revocation index sees; one that fails is refused before anything is
  written. `spaceUrl` is optional. A session with no Space (a guest, a no-WAS
  login) delegates nothing and omits it, so only a zero-grant write proceeds
  there, and a call carrying any grant is refused.
- `removeGrants` -- removes grants by capability id, whatever the entry's kind:
  an unshare after its revocation, or a torn consent's rollback.
- `retireConnection` -- empties `grants`, `grantsReceived`, and `outbox`, drops
  `appKey`, and stamps `retired`, on an entry of any kind. Everything else
  stays, `seed`, `seedTag`, and `declined` included, so a departed party keeps
  resolving. Its no-op check reads both new lists, so a re-retire empties them.
  It takes the capability ids the revocation handled, and throws when a read
  finds a grant (one that passes the grant checks) outside that set: a
  concurrent consent merged it, and the revocation must run again. `spaceUrl` is
  optional here too. Without it no grant passes the checks, so none counts as
  unhandled and the retirement empties them all. A `replica-server` entry whose
  `replicas` list is not empty is refused with an `Error`. Entries are never
  deleted while the account stands.
- `setConnectionLabel` -- sets or clears the user's `label`, and `name` when
  given. A `label` outside the display-name rule is refused, since the user
  typed it and can shorten it, while a `name` outside it is ignored. It creates
  an absent entry only for a wallet client the verified account document lists.
  The enrollment approval writes the code's suggested label as `name`, and
  `label` only when the approver edited it.

The agent connection writers are listed under "The agent connection members".
The replica-server writers are listed under "The replica-server members".

`recordGrants` and the wallet-client writes take the kind their flow writes, and
refuse an entry of another kind with `ConnectionKindMismatchError`, matched by
`err.name`.

## The writer arm

A wallet client's entry carries `writers`, one member per `writerId` the client
has written under. A client normally has one. A second appears when the client's
`writerId` is cleared while its client-key record survives.

Every writer field is advisory. A pulled revision's `writerId` is not verified,
so a host can replay a registered one and keep its member active. No writer
field is an input to an authorization decision.

### Lazy registration

A writer earns a member only once it is encountered in a second session under
the same account (`registerConnectionWriter` in `connections/writers.ts`). A
one-shot writer, an incognito window or a profile cleared right after use, never
gets one. The second session is detected through a single-slot writer first-seen
record (`WriterFirstSeenRecord`) the wallet keeps beside its `writerId`, on the
session's persistence. The first call with no record, or a record for another
account or `writerId`, writes a fresh record and returns `'deferred'`. Only a
later call, from a session that started after the record's `firstSessionAt`,
proceeds.

Registration writes this client's own entry. An absent entry is created
(`kind: 'wallet-client'`, `id` the client's did:key, `name` the platform label)
while the verified document lists the client, which converges a lost
enrollment-time write. A retired entry is un-retired while the document still
lists the client, which converges a forget torn after its retirement, and left
alone otherwise. An entry of another kind, a newer version, or an unparseable
body is not written. A new member first makes room under the per-entry cap.

After registration the member's `lastSeen` moves at most once per touch
interval, and a call inside the interval costs no I/O (`'fresh'`). The interval
runs from the last settled call whatever its outcome, so an entry the client
cannot write (unlisted, retired, another kind, a newer version) is re-read once
per interval and not on every sync. A write that loses every attempt returns
`'raced'`, and the next call retries at once.

### The pull-path touch

`touchConnectionWriter` moves a registered writer's `lastSeen` from a pulled
revision's `writerId`, throttled the same way, finding the writer in a listing
already read. An unregistered `writerId` is ignored, and so is a writer on a
retired entry, so a replayed revision cannot keep a departed client's writer
alive.

### The sweep

`sweepConnectionWriters` runs over a listing already read, at the directory
listing read on both session kinds. It is safe from any replica and concurrently
with itself: every write is conditional on the ETag the listing read, and a lost
race is skipped. Any other failed write is skipped the same way and reported in
`failed`, so one unreachable entry does not fail the listing read the sweep
rides on, and the next sweep converges it. Per entry, over its `writers` sorted
newest-`lastSeen` first (ties broken by `writerId`, so every sweeper picks the
same ones):

1. Past the cap, the oldest-`lastSeen` members are dropped.
2. Among the members kept, one still `active` whose `lastSeen` is older than the
   inactivity window is marked `active: false`. Its next touch sets it back.

An entry this build cannot write, or one read without an ETag, is left alone. A
`lastSeen` later than the sweeper's own clock reads as its `now`, so a writer
whose clock runs fast cannot keep its member ahead of every eviction.

### The policy

```
CONNECTION_WRITER_POLICY = {
  inactiveAfterMs: 90 days,
  maxWriters: 8,          // per entry
  touchIntervalMs: 1 day
}
```

The values are not stored, but every wallet that sweeps must use the same ones,
or two sweepers disagree about which members to drop.

### Resolving a writer for display

`resolveWriter` takes a revision's `writerId`, the listed entries, and the
enrolled clients' signing keys read from the verified account document. It
returns the entry's display name (`label`, then `name`, then the member's
platform label), the member's `active`, whether the entry is retired, and
`clientSigningKeyMultibase` when the document lists the key the entry's `id`
carries. `undefined` means no entry carries the writer, and the caller renders
its own fallback label.

## The agent connection members

An entry records one direction by default: the grants the wallet delegated to
the party. An agent connection needs the other direction too. The wallet
presents a stable key of its own toward the agent. It holds the capability the
agent handed it to reach the agent's inbox, and it queues what it owes the
agent. Every client of the account must derive the same key and renew the same
grants, so these members are a shared contract (`decisions/0028`).

### The seed and its tag

`seed` is 32 random bytes, base64url with no padding (43 characters). It is the
wallet's pairwise key toward this party. It is written once, by `recordGrants`
at the consent that connects the agent, and a write that finds a different seed
on the entry refuses.

`connectionDidKey` derives the pairwise did:key and its signer from it, through
pws-client's `agentsFromSeed` under the pinned bootstrap names. It has no
derivation label of its own, so every client derives the same did:key. The
pairwise did:key is a grantee on the agent's server. It is not a client, since
it appears in no roster and signs nothing in the owner's Space. It gives the
agent continuity across the owner's clients. It does not give the owner
unlinkability.

`seedTag` is the full 32-byte
`HMAC-SHA-256(hmacKey, utf8('connections/v1' + '|' + 'seed:') || seedBytes)`,
base64url with no padding, under the directory's blinded-index key
(`connectionSeedTag` in `connections/resourceId.ts`). The `seed:` arm sits
beside the resource id's `did:` and `writer:` arms, so one key never MACs two
unseparated input kinds. The tag is written in the same write as the seed. The
codec refuses a seed with no tag. Every site that turns a seed into a key checks
the tag first (`verifyConnectionSeedTag`) and fails closed on a mismatch, since
an EDV envelope does not authenticate its writer and a host could plant a seed
of its own.

### Received grants and the channel

`grantsReceived` lists the capabilities the party handed the wallet, as
`{ zcap, grantKind, receivedAt }`. `grantKind` is `'inbox'` for the party's POST
capability on its own inbox (`RECEIVED_GRANT_KINDS`). An unknown value is kept
as stored. An absent list reads as empty.

`receivedGrants` applies the opposite checks to the grant index. It keeps a
record only when `zcap.controller` is the entry's pairwise did:key and the
target lies outside this Space. An `'inbox'` record must also allow POST. A
record lapses at the earlier of its `expires` and `receivedAt` plus a lifetime
the app supplies (`receivedGrantLapsed`). `liveInboxChannel` picks the live
inbox record with the latest `expires`, and a push goes through it.

`recordReceivedGrants` merges new records. A record with an equal zcap id is
left as stored, so the drain's re-run writes nothing. One with the same
`grantKind` and target replaces the held record when its `expires` is later, or
when the held record has lapsed under the caller's `channelMaxLifetimeMs`, so a
channel the agent re-issues after the wallet's lifetime limit is adopted. Every
record past `expires` plus the revocation clock skew is dropped. An incoming
record must carry an `expires`, in strict ISO 8601 with any number of fractional
second digits, since a looser form one JavaScript engine parses and another
refuses would make the entry unreadable on the other wallet. A retired entry is
refused.

`dropReceivedGrant` removes one record by its capability id in a
compare-and-swap and leaves `outbox` as it is. It is what a push refused by the
party's server (a 401, a 403, or a WAS host's masked 404) does with the channel
it went through, since the refusal says the capability is expired or revoked.
The queued envelopes wait for the party's next invitation, and because the
dropped record is gone, `recordReceivedGrants` stores the replacement channel
the party then hands over whatever its `expires`. A record not held writes
nothing. `clearReceivedGrants` keeps emptying both lists.

### The outbox

`outbox` lists the messages the wallet owes the party, as
`{ message, createdAt }`. `message` is the pending envelope verbatim, and
`createdAt` is its queueing time, ISO 8601 UTC. There is no channel member. A
push reads the live channel at push time. An absent list reads as empty.

The envelope is the inbox Grant message (`inboxGrantMessage` and
`parseInboxGrantMessage` on `/space`). `settleOutboxItem` removes an item by its
`createdAt` after a successful push. A network error or a 5xx keeps it.

### The decline marker

`declined` is an ISO 8601 UTC time, present while the owner's decline of this
agent's offer stands. `markDeclined` writes it, and a fresh consent through
`recordGrants` clears it. It is validated like `retired`.

### Retirement

Retirement empties `grantsReceived` and `outbox` with `grants`. It keeps `seed`
and `seedTag`, so a reconnect presents the same did:key. It leaves `declined` as
stored. Every reader ignores the received list and the outbox on a retired
entry.

An agent revoke runs `clearReceivedGrants` as its first write, which empties
both lists before the delegated grants are revoked and the entry retires. A torn
revoke therefore leaves no channel to push a renewal through.

### Renewal

An agent's grants are renewed without a prompt, through the inbox channel. The
rules keep the entry bounded and keep every live zcap revocable.

- A renewed grant is appended as a new record carrying `renewedAt`. `grantedAt`
  stays the consent time. The superseded record's body is not replaced, since a
  replaced body would strand a still-live zcap past every revoke.
- A scope is the triple of `controller`, `invocationTarget` (compared verbatim,
  a `*` marker included), and `allowedAction`. The renewal candidate per scope
  is its latest record, the one with the greatest `expires`
  (`latestGrantsPerScope`). A superseded record is not a candidate.
- The renewal scope is what a connection request's consent produced
  (`renewalScopeGrants`). A grant is in it when its `grantedAt` equals that of
  an inbox grant on the same entry, and its actions are GET and HEAD on a
  collection or POST on `inbox`. A write grant, or a grant from a later request
  that was not a connection request, is not renewed silently.
- `agentGrantDue` reads a grant as due inside the agent renewal window
  (`AGENT_GRANT_RENEWAL_WINDOW_MS`, 90 days). It is also due when its chain is
  dead by replacement: its embedded parent is not the generation delegation the
  account points at, while the parent's signer is still listed. A root-anchored
  grant is due only by its window. A grant already past its `expires` is not
  due, since a fresh consent replaces it.
- A grant is renewed only when `verifyRecordedGrantProof` verifies its
  delegation proof as this account's. Only the host can plant an entry, and a
  host colluding with a withdrawn party that kept the directory's blinded-index
  key can write an agent entry at a valid id with its own seed and tag, forged
  grants whose proofs name a current key, and a channel to its own inbox. So the
  check verifies the signature, not the signer's name alone. On the root arm the
  grant's own proof is checked: its `verificationMethod` resolves through
  `delegationSignerKey` (`webvh`, the one reader of a delegation signer's
  published key) to a `capabilityDelegation` member of the current document (or
  is the did:key form of a key that relation publishes), and the
  `eddsa-jcs-2022` signature verifies over the capability under the key that
  member publishes. The fragment is an opaque selector that names no key, the
  same rule the library's log verifier applies, so a member publishing no key
  lists nothing. On the annex arm the embedded parent is checked instead: its
  `controller` is an annex DID in the account's auxiliary Space, compared by
  host and Space id, and its own proof verifies under a key or ladder VM the
  document lists. The leaf is then verified the same way against the annex
  document of the parent's generation, which the wallet resolves through the
  signer check's `annexDocument` member under that log's chain-head pin: the
  per-visit VM that signed the leaf must stand under `capabilityDelegation`
  there, and the signature must verify under the key it publishes. The parent
  alone would not do, since it is genuine, long-lived, and host-held (it sits in
  the annex `did.jsonl` and in every grant the generation minted), so a host
  could copy it under a leaf of its own naming a planted party. A generation a
  GC collected has no document to resolve, so a grant minted under it is refused
  (`leaf-generation-collected`) and lapses into a re-consent; the collect of a
  superseded generation runs at every remembered login, so in practice a
  transient-minted grant is renewable until the quarterly swap. `connections`
  sits below the annex and cannot read the log itself, which is why the resolver
  is injected and required. The check memoizes the resolver on the `signerCheck`
  object, one read per generation however many grants a pass checks under it,
  concurrently or not, and a rejected read is evicted rather than kept. A wallet
  builds one `signerCheck` per renewal pass, since a longer-lived one would keep
  serving a generation's document after a GC collected it. A refusal names its
  reason (`GrantProofRefusal`), and a caller whose signer-check resolution or
  annex read throws renews nothing. One residue stands. The check proves only
  that the account's keys signed the grant at some point, so a host replaying an
  entry body from before a revocation passes it too; it has no freshness anchor.
  That is an open gap until the renewal pass compares against state the host
  cannot roll back.

`recordRenewedGrants` is the renewal's pivot. In one compare-and-swap it appends
the renewed records and queues the envelope that carries them. A pending
envelope of the same scope is replaced, and the superseded zcap is removed from
an older envelope carrying several scopes. It writes nothing and refuses when
any of these holds:

1. the entry is retired (its `retired` stays);
2. no live inbox record stands on `grantsReceived`, read through
   `receivedGrants` with the caller's `pairwiseDid` and `liveInboxChannel`;
3. the source record is gone;
4. the source is no longer the latest record of its scope, since a concurrent
   renewal ran;
5. the renewal's `expires` is not later than its source's, which is what keeps a
   renewal minted under a short-lived parent from being appended at every login.

The envelope must carry exactly the renewed zcaps, so a reused message cannot
queue a zcap that was not recorded. A renewal copies its source's
`invocationTarget` as stored, since the scope compares it verbatim.

### Pruning

`pruneSupersededGrants` drops a superseded record once its `expires` is past by
more than the revocation clock skew. It drops one sooner when the caller reports
its chain dead and the outbox item carrying its successor was settled. The
latest record of a scope always stays. An outbox item is discarded once every
zcap its envelope carries is past `expires` plus the skew.

### The signer reader

`agentConnectionsSignedBy` returns the unretired agent entries holding a grant a
given key or ladder VM signed. A root-anchored grant counts by its own proof's
signer. A grant with an embedded parent counts by the parent's minter. It is an
attribution read and works on either side of the withdrawing edit: a grant
counts when its proof's method id and the given `keyId` name one signer
(`sameSigner`, `webvh`: the same id verbatim, or the same key under
`signerKeyNamed`, which reads a bare multibase, a did:key id's own key, or the
key the verified document publishes for an id under the account DID). A key the
document already struck still names the grants signed under its exact id, which
is what a torn ceremony's post-edit sweep holds.

## Invariants

`no-registered-writer-outlives-its-expiry` (35 in `INVARIANT_IDS`,
`menders/ids.ts`) keeps its id, re-targeted at the directory: no `writers`
member of any entry stays `active` past the inactivity window, and no entry
holds more than the writer cap once a sweep has run over it. The converger is
`sweepConnectionWriters`, which a wallet registers under the `encounter` trigger
at its listing read, reached by both session kinds, with authority `none`, since
a directory write is a content write the visit makes under its own authority.

`every-grantee-of-the-wallet-has-a-connection-entry` (36) is the directory's
completeness predicate: every party holding a live grant the wallet delegated,
or listed in an unprotected collection's current epoch, has an unretired entry.
It was renamed from `every-party-with-authority-has-a-connection-entry` with no
alias. The narrower statement leaves out a subscriber, which holds a child of an
agent's grant and has no entry of its own. The owner reaches it through the
agent's entry. No mender converges it. A wallet declares it as a `none` gap,
whose torn states are a directory deleted and re-created empty, and a party that
connected before the directory existed.

`inbox-is-drained` (38) says no message older than the start of the last
completed drain stays in a trusted `inbox`. Its authority is `none`, since the
drain reads and deletes the owner's own mail. A wallet registers it on the two
login chains and at `encounter`.

`agent-grants-are-current` (39) says every unretired agent entry holding a live
inbox record has no latest record per scope that is due, in the renewal scope,
and passing the proof check. Its authority is `none`. A wallet registers it on
the two login chains and at `encounter`.

`no-withdrawn-party-holds-a-live-pairwise-channel` (40) says no party whose
authority the account withdrew (a revoked client, a retired credential, a struck
annex generation) holds a live pairwise channel capability. Such a party kept
the directory key, and with it every seed. What it can reach is the POST-only
channel on the agent's inbox. The invariant is declared with no trigger and no
converger until a seed rotation ships.

## The replica-server members

A replica server is a second storage server the user chose to hold a copy of the
account's Spaces. The source server is the one that hosts the account. The
replica server pulls from the source under a read capability the wallet
delegates to the replica server's DID. Two Spaces are copied to each replica
server, the account Space and the client-annex auxiliary Space. Each copy is a
replica Space on the replica server. One entry holds the server and all its
replica Spaces (`decisions/0031`).

### The entry

A `replica-server` entry uses these members on `version` `1`:

- `id` is the replica server's `serverDid`, a did:webvh read from the server's
  service description.
- `url` is the server's base URL. `name` is its host name, or absent. `label` is
  the user's own name, as on every entry.
- `seed` and `seedTag` are the bootstrap seed, under the tag rule and the
  write-once rule of `decisions/0028`. `connectionDidKey` derives the bootstrap
  key from them, the same derivation as an agent's pairwise did:key. That key
  creates each replica Space, registers it, and promotes it to the account
  did:webvh after the first pull. After promotion it controls nothing.
- `grants` are the pull grants, each with `grantKind: 'grant'`. A pull grant's
  `controller` is the entry's `id`, its `invocationTarget` is one replica's
  `fromSpace`, and its `allowedAction` is `['GET']`. A renewal appends the
  successor and keeps the superseded record, under the rules of "Renewal".
- `declined` is the owner's decline, as on an agent entry.

### The replicas list

`replicas` has one item per replica Space on this server:
`{ fromSpace, spaceId, registrationId?, pendingRegistrationId?, collections?, stoppedAt?, restartedAt?, lostAt? }`.

- `fromSpace` is the source Space's container URL, with its trailing slash, as
  the registration body carries it. The helpers store and match it in its
  URL-parsed, re-serialized form, the same normalization the grant target check
  applies, so one Space under two forms of its URL is one item.
- `spaceId` is the replica Space's id on the replica server. It is distinct from
  the source Space's id.
- `registrationId` is the id of the item's registration, present once the first
  registration landed. An in-place replacement of the registration's capability
  keeps it.
- `pendingRegistrationId` is present only between the mint of a first
  registration's id and the landing of its POST. It then moves to
  `registrationId`.
- `collections` is the registration's collection list, not empty when present.
  The wallet omits it, so the replica server copies every live Collection.
- `stoppedAt` is written first by the user's Stop and cleared by a completed
  re-start. It marks a stopped snapshot.
- `restartedAt` is written first by a re-start and cleared last.
- `lostAt` is written when the replica Space reads absent under the account's
  own authority.

Each marker is an ISO 8601 UTC time, written by one intent and cleared by its
completion. No unset marker reads as an intent, so a writer sets or clears its
own marker without deciding a combined state.

Ids are fresh. A replica Space id and a registration id are each 32 random
bytes, base64url with no padding (43 characters, `isConnectionFreshId`). Both
replica Space ids are recorded on the entry before either Space is created, and
a first registration's id is recorded before its POST.

The codec checks the items strictly. `fromSpace` must be a container URL,
`spaceId` and both registration ids fresh ids, `collections` a non-empty list of
non-empty strings (an empty list would have no reading beside the absent one),
and each marker a timestamp. One malformed item makes the whole body
unparseable, so a rotation that reads the directory fails closed while it
stands. Unknown item members are kept verbatim. An absent `replicas` reads as
empty. A non-empty list on an entry of any other kind makes the body unparseable
too, so no writer carries a stray list forward.

### The writers

Each helper is in `connections/replicas.ts`, runs the same compare-and-swap loop
as the others, and changes only the members it owns. Each refuses an entry of
another kind with `ConnectionKindMismatchError`. Each, except `recordReplicas`,
writes nothing for an absent entry.

- `recordReplicas` -- the registration's entry write, before anything touches
  the replica server. Creates the entry or merges into it: `url`, `name` when it
  passes the rule, `lastSeen` moved, and each item added by its `fromSpace` with
  its freshly minted `spaceId`. An item already listed for that source Space is
  left as stored, so a re-run adopts the ids an earlier run persisted. An item
  already listed that carries `lostAt` is refused with an `Error`, since
  adopting its id would register under a lost Space while the item kept reading
  as lost; Delete removes it first. It writes a `seed` and `seedTag` (both or
  neither) when the entry carries none, and refuses a different seed with an
  `Error`. It clears `retired` and `declined`, since the registration is a fresh
  consent toward the server. A `fromSpace` that is not a container URL, a
  `spaceId` that is not a fresh id, or two items naming one source Space is
  refused with a `TypeError`.
- `recordReplicaGrant` -- appends one pull grant as a `'grant'` record, and with
  it a first registration's `pendingRegistrationId`, in one write. A grant
  already recorded by capability id is left as stored. With `renews`, the id of
  the recorded grant the capability renews, the record is a renewal under the
  rules of "Renewal": it keeps the source's `grantKind` and `grantedAt`, carries
  `renewedAt`, and must share the source's scope and expire strictly later; a
  source gone from the entry or no longer the latest of its scope is refused
  with an `Error`. It refuses a retired entry, an entry with no item for
  `fromSpace`, a pending id on an item that already has a `registrationId`, and
  a pending id on an item pending under another id (the first id's POST may have
  landed), each with an `Error`. It refuses a capability not delegated to the
  server's DID, one not targeting `fromSpace`, one allowing any action but
  `GET`, a pending id that is not fresh, and a pending id beside `renews`, each
  with a `TypeError`. It touches neither `declined` nor `retired`.
- `settleReplicaRegistration` -- moves a landed id from `pendingRegistrationId`
  to `registrationId`. An item already settled on that id writes nothing. An
  item whose pending id is another, or that has none, is refused with an
  `Error`, as is an entry with no item for `fromSpace`.
- `setReplicaMarker` -- sets `stoppedAt`, `restartedAt`, or `lostAt` to now on
  each named item, or on every item when none is named. An item already carrying
  the marker keeps its time. Setting `restartedAt` also clears the entry's
  `declined` in the same write. A named source Space with no item is refused
  with an `Error`, and an empty list of names with a `TypeError`, since it would
  mark nothing while the decline clearing still ran.
- `clearReplicaMarker` -- clears one marker on each named item, or on every
  item. An item without it is left as stored. A named source Space with no item
  is refused with an `Error`, and an empty list of names with a `TypeError`.
- `removeReplica` -- removes the item for `fromSpace` once its replica Space is
  gone. An entry with no such item writes nothing. It refuses, with an `Error`,
  an item whose source Space a recorded grant still targets. Stop revokes and
  removes the pull grants first, so a grant left recorded means a Stop torn
  before its last step, and removing the item would hide it from the readers
  that finish it.

`recordReplicaGrant` does not clear `declined`, since the login pass records a
renewal through it and a declined entry must stay declined. Only
`setReplicaMarker` with `restartedAt` clears it, and so does `recordGrants`, a
fresh consent.

### Retirement

`retireConnection` refuses an entry whose `replicas` list is not empty (only a
`replica-server` entry parses with one). Delete removes an item
(`removeReplica`) after its replica Space is gone, and the entry retires after
the last one. Retirement keeps the names and the seed, so a later registration
with the same server derives the same bootstrap key.
