<!-- Part of wallet-core's architecture docs. The map, the key hierarchy,
     the ceremony inventory, the permanent wire-level constants, and the
     glossary are in ../../ARCHITECTURE.md; this file holds one topic in full. -->

# The writer roster (`writers`)

The writer roster turns a bare `writerId` on a revision into a display label a
history view can show a person. Every field it stores is advisory. A writer
asserts its own label and liveness, nothing checks those claims beyond shape,
and no field here is ever an input to an authorization decision.

## The collection

The roster lives in the `registered-writers` collection
(`REGISTERED_WRITERS_COLLECTION_SPEC` in `space/collections.ts`): EDV-encrypted,
mutable, `idDerivation: 'random'`, not public, and not shareable. It annotates
the contacts history with labels, but it stays off the share surface for now, so
a grantee of the contacts history sees every revision under the fallback label.
Unlike the four synced collections it has no local replica and no sync feed.
Both wallets read and write it directly against the server.

It sits in `WALLET_SPACE_PROVISION_ROSTER` between the synced feeds and the
system collections, so `ensureWalletSpaceEpochs`'s epoch install covers it the
same as any other encrypted wallet collection. A roster entry cannot be written,
or read, before the collection's own epoch[0] lands.

## The resource id

One resource holds one writer's entry. Its id is the EDV document id of the
first 16 bytes of
`sha256(utf8('registered-writers/v1|' + accountDid + '|' + writerId))`, computed
with was-client's `edvIdFromBytes` (`registeredWriterResourceId` in
`writers/entry.ts`). The derivation is deterministic, so registering twice and
touching are both idempotent upserts at the same id.

Hashing the `writerId` into the id, rather than using it directly, does two
things. It hides the `writerId` from the storage host, which otherwise reads
every resource id in a listing. And it stops the same `writerId` from producing
the same resource id under a different account, since the account DID is folded
into the hash: no cross-account linkage.

## The entry

```
{
  version: 1,
  writerId: string,
  signingKeyMultibase?: string,
  label: string,
  lastSeen: string,   // ISO 8601 UTC
  active: boolean
}
```

All of it is self-asserted display data. `signingKeyMultibase`, when present,
names an enrolled wallet client's own signing key. A reader treats it as a link
to that client's row only when the verified did:webvh account document still
lists that key; the entry's own claim proves nothing by itself
(`resolveRegisteredWriter`, below). `label` is a coarse platform
self-description, or the user's rename of it. `lastSeen` and `active` are the
liveness state the sweep maintains.

`parseRegisteredWriterEntry` is the one shape check every reader runs. A body
that fails it -- wrong version, a missing or malformed field -- is skipped, not
repaired: an entry is easy to reconstruct and not worth patching in place.
Readers also check that a stored body sits at the resource id its own `writerId`
derives to (`boundEntry` in `writers/roster.ts`). A resource under any other id
is left alone and never counted, whether that is a copy, a misplaced write, or a
resource sealed under an epoch this reader does not hold yet.

## Lazy registration

A writer earns a roster entry only after it is encountered in a second session
under the same account (`registerWriterOnSecondSession`). A one-shot writer --
an incognito window, a profile cleared right after use -- never gets one.

The second session is detected through a client-local, single-slot writer
first-seen record (`WriterFirstSeenRecord`): the account and `writerId` this
client's writer first appeared under, and when it last touched its entry. The
first call with no record, or with a record for another account or `writerId`,
writes a fresh record and returns `'deferred'`, without touching the roster.
Only a later call, from a session that started after the record's
`firstSessionAt`, proceeds to register or touch. Moving to another account, or
clearing the record, starts over; there is no credit carried across accounts.

Once a writer is registered, its entry's `lastSeen` is advanced at most once per
touch interval (`touchIntervalMs` in the policy, below); a call inside the
interval costs no I/O and returns `'fresh'`. A write that lands returns
`'registered'` for a new entry or `'touched'` for an existing one. A write that
loses every conditional-write attempt returns `'raced'`, and the caller's next
call retries.

Registering a new entry first makes room under the entry cap
(`REGISTERED_WRITER_POLICY.maxEntries`), running the same two-phase expiry the
sweep runs. Two writers registering at once can each find room and push the
roster one past the cap. The next sweep deletes the extra entry.

## Renaming

`renameRegisteredWriter` overwrites the stored `label` on an existing entry.
Before registration there is nothing to rename, and the call reports that rather
than creating an entry. A blank label is refused.

## Sweep-on-read

`sweepRegisteredWriters` is safe to call from any replica, at any time, and
concurrently with itself. There is no coordinator: every write it makes is
conditional on the ETag it read, and a write that loses that race is skipped
rather than retried or escalated. Two sweepers racing the same entry converge on
whichever wrote first; the loser's view is simply stale until its next sweep.

The expiry is two-phase, applied over the entries sorted newest-`lastSeen` first
(ties broken by resource id, so every sweeper picks the same ones):

1. Past `maxEntries`, the oldest-`lastSeen` entries beyond the cap are deleted.
2. Among the entries kept, one still `active` whose `lastSeen` is older than
   `inactiveAfterMs` is marked `active: false`. Its next touch sets `active`
   back to `true`.

A resource that does not parse as a bound entry (see "The entry") is left alone
by the sweep as by every other reader, and does not count against the cap.

A resource read without an ETag is never written by the sweep, since the write
would go out unconditionally and could overwrite a newer touch. A touch or a
rename over such a read is refused with `NotSupportedError`. A browser client
needs `ETag` in the server's `Access-Control-Expose-Headers`.

The sweep and the sort read a `lastSeen` later than the sweeper's own clock as
the sweeper's `now`. A writer whose clock runs fast therefore cannot keep its
entry ahead of every eviction.

## The policy

```
REGISTERED_WRITER_POLICY = {
  inactiveAfterMs: 90 days,
  maxEntries: 64,
  touchIntervalMs: 1 day
}
```

Every entry point (`registerWriterOnSecondSession`, `sweepRegisteredWriters`)
takes a `policy` override. A wallet may surface these as configuration, but
every replica sweeping the same account must use the same values: two sweepers
running different thresholds disagree about which entries are expired or over
the cap, and diverge on what they delete.

## Resolving a writer for display

`resolveRegisteredWriter` takes a revision's `writerId`, a sweep's `entries`,
and the enrolled clients' signing keys read from the verified account document,
and returns a `ResolvedWriter` (`label`, `active`, and
`clientSigningKeyMultibase` when the entry's key is one of them) or `undefined`.
`undefined` means no entry: the caller renders its own fallback label, such as
"another session".

## Invariant 35

`no-registered-writer-outlives-its-expiry` (`INVARIANT_IDS`, `menders/ids.ts`)
is the roster's one declared invariant: no entry stands past its inactivity
window, and the roster holds no more than `maxEntries` entries once a sweep has
run. `sweepRegisteredWriters` is the converger a wallet registers against it
under the `read-path` trigger, since it runs on the history view's read rather
than on a login chain.
