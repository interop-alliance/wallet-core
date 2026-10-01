<!-- Part of wallet-core's architecture docs. The map, the key hierarchy,
     the ceremony inventory, the permanent wire-level constants, and the
     glossary are in ../../ARCHITECTURE.md; this file holds one topic in full. -->

# The `connections` directory (`connections`)

The directory is one record per party the wallet has dealt with: an app, an
agent, a wallet client, or a contact. It is the wallet's revocation index, since
each entry carries the capabilities delegated to its party. It is also where a
party's names live, and where a wallet client's `writerId`s are recorded. The
wallet writes every entry. No party ever writes one, since a party that could
seal an envelope into the directory would be an epoch recipient and could read
every other party's grants.

The contract is `decisions/0025` (the entry), `0026` (the resource id), and
`0027` (the reading and writing rules).

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
  kind: 'app' | 'agent' | 'wallet-client' | 'contact',
  id?: string,          // the party's DID; absent only on a keyless writer
  name?: string,        // the latest self-declared name
  label?: string,       // the user's own name for the party
  origin?: string,      // the attested Web origin (App Connect)
  url?: string,         // the canonical app URL (App Connect)
  appKey?: string,      // the app-key Resource id, while the wallet holds it
  firstSeen: string,    // ISO 8601 UTC
  lastSeen: string,     // ISO 8601 UTC
  retired?: string,     // ISO 8601 UTC, once the relationship ended
  grants: [{ zcap, grantKind: 'grant' | 'share', grantedAt }],
  writers: [{ writerId, label, lastSeen, active }]
}
```

`name` and `label` are two members on purpose. A later self-declaration would
otherwise overwrite the user's rename. `zcap` is the delegated capability stored
verbatim, proof and chain included, since a revocation POSTs it as it stands.
`grantKind` is always written. A reader treats a value it does not know as a
plain grant. `'share'` marks a grant the shared-wallet-collection flow wrote,
which the unshare and the shares dialog pick by it.

There is no signing-key member. A wallet client's `id` is its did:key, whose
method-specific part is the multibase the account document carries.
`signingKeyMultibaseOfDid` (`connections/didKey.ts`) is the one join between a
client's entry and the account document's listing.

## The resource id

One resource holds one party's entry. Its id is the first 16 bytes of
`HMAC-SHA-256(hmacKey, utf8('connections/v1' + '|' + armInput))`, formatted with
was-client's `edvIdFromBytes` (`connectionResourceId` in
`connections/resourceId.ts`). `hmacKey` is the collection's blinded-index key.
`armInput` is `'did:' + did` for a party with a DID and `'writer:' + writerId`
for a keyless writer, which has no producer yet. The account DID is not an
input.

The derivation takes the key as its raw secret or as the resolved key
was-client's `resolveHmacKey` returns. Both give the same id.

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
party. Unknown members are ignored, at the top level and on a grant wrapper. A
well-formed body whose `version` is above this build's is read for display from
the members this build knows (`isWritableConnectionEntry` says it cannot be
written).

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
is not under this Space's container URL. Every reader applies both checks, so a
planted entry at one party's id cannot steer a revocation at another party's
capabilities. The same module carries the other grant-index readers the
revocation orchestrators share: the targets (`grantTargets`), the live and
expired split (`splitGrantsByExpiry`), and the recipient kid a grant's
controller derives (`grantRecipientKid`, through was-client's X25519 twin and
the roster kid builder).

## The store

`ConnectionsStore` (`connections/store.ts`) is the seam: `list`, `get` with its
ETag, a conditional `put`, and a conditional `delete`. `wasConnectionsStore`
builds it over the collection's Collection handle and its document cipher. A
listing walks the collection's documents feed, bodies and ETags, one request per
page, and opens each envelope with the cipher under the id the feed served it
at. A `get`, a `put`, and a `delete` go through the handle. A `put` at an id
with no resource yet creates it there, sealed under the current epoch, as a
guarded create (`ifNoneMatch`).

The store reports what it cannot read. A listing names a resource it could not
open, an unknown epoch included, and a `get` that cannot open throws. Reading
either as an absent body could evict a party at the next rotation, or write over
a body the reader never saw.

## Writing

Every write goes through one of four helpers (`connections/upsert.ts`), each a
bounded compare-and-swap loop at the party's own id. It reads the entry, applies
its change to the stored body, and writes under `ifMatch`, or creates under
`ifNoneMatch`. A lost race (`PreconditionFailedError`, matched by name) re-reads
and re-applies, up to three attempts. A helper changes only the members it owns,
so every other member, known or not, is written back verbatim. A helper that
finds a body it cannot parse, a newer `version`, or a body that does not belong
at the id refuses to write. It does not treat that body as absent, which would
wipe a newer build's grants.

- `recordGrants` -- the consent-time write. Creates the entry or merges into it:
  each new grant by capability id, `name` when it passes the rule, `origin`,
  `url`, and `appKey` when given, `retired` cleared, `lastSeen` moved.
  `firstSeen` is set only on create, and `label` is never touched. A zero-grant
  consent writes too. Each grant must be delegated to the party and target this
  Space, the same checks every reader applies, so a stored grant is one the
  revocation index sees; one that fails is refused before anything is written.
  `spaceUrl` is optional. A session with no Space (a guest, a no-WAS login)
  delegates nothing and omits it, so only a zero-grant write proceeds there,
  and a call carrying any grant is refused.
- `removeGrants` -- removes grants by capability id, whatever the entry's kind:
  an unshare after its revocation, or a torn consent's rollback.
- `retireConnection` -- empties `grants`, drops `appKey`, and stamps `retired`,
  on an entry of any kind. Everything else stays, so a departed party keeps
  resolving. It takes the capability ids the revocation handled, and throws when
  a read finds a grant (one that passes the grant checks) outside that set: a
  concurrent consent merged it, and the revocation must run again. `spaceUrl`
  is optional here too. Without it no grant passes the checks, so none counts
  as unhandled and the retirement empties them all. Entries are
  never deleted while the account stands.
- `setConnectionLabel` -- sets or clears the user's `label`, and `name` when
  given. A `label` outside the display-name rule is refused, since the user
  typed it and can shorten it, while a `name` outside it is ignored. It creates
  an absent entry only for a wallet client the verified account document lists.
  The enrollment approval writes the code's suggested label as `name`, and
  `label` only when the approver edited it.

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

## Invariants

`no-registered-writer-outlives-its-expiry` (35 in `INVARIANT_IDS`,
`menders/ids.ts`) keeps its id, re-targeted at the directory: no `writers`
member of any entry stays `active` past the inactivity window, and no entry
holds more than the writer cap once a sweep has run over it. The converger is
`sweepConnectionWriters`, which a wallet registers under the `encounter` trigger
at its listing read, reached by both session kinds, with authority `none`, since
a directory write is a content write the visit makes under its own authority.

`every-party-with-authority-has-a-connection-entry` (36) is the directory's
completeness predicate: every party holding a live grant, or listed in an
unprotected collection's current epoch, has an unretired entry. No mender
converges it. A wallet declares it as a `none` gap, whose torn states are a
directory deleted and re-created empty, and a party that connected before the
directory existed.
