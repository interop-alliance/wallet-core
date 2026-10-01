# 0026: Directory resource ids are keyed by the blinded-index key

- Status: accepted
- Date: 2026-10-01
- Driving work: the design of the `connections` directory (0025), which needs a
  deterministic resource id per party so a consent can find or create the
  party's entry without a listing. Extracted at that design's approval.
- Affects: wallet-core (the directory id derivation and the directory binding's
  descriptor check); freewallet and dcw (every directory read and write, and the
  local descriptor mint on a session with no Space); encrypted-collections-spec
  (the blinded-index key gains a second use); the account-move design (ids
  survive a move that carries the key).

## Context

A mutable collection with one entry per party needs each entry at an address the
wallet can compute from the party alone. The retired writer roster derived its
ids as `sha256('registered-writers/v1' + '|' + accountDid + '|' + writerId)`.
Every input to that form is public: the account's did:webvh is world-readable
and a party's DID is in every capability it invokes. So the host could compute
the id for a guessed DID and probe the collection for it. For an app, an agent,
or a wallet client that reveals nothing the host does not already see. For a
`contact` entry it would reveal whether a DID is one of the user's contacts,
which otherwise lives only inside encrypted records.

Changing a derivation later rewrites every id, so the form is settled before the
first entry exists. The directory's descriptor already carries a blinded-index
HMAC key, minted with epoch[0], never rotated, and wrapped to the collection's
recipients, which for this collection is the user key alone.

## Decision

A directory entry's resource id is the first 16 bytes of
`HMAC-SHA-256(hmacKey, utf8('connections/v1' + '|' + armInput))`, formatted with
was-client's `edvIdFromBytes`. `hmacKey` is the collection's blinded-index key.
`armInput` is `'did:' + did` for a party with a DID and `'writer:' + writerId`
for a keyless writer entry. The account DID is not an input.

A `connections` collection whose descriptor declares no blinded-index key cannot
derive any id, and the directory binding refuses it. A session with no Space
mints its local directory descriptor with the same blinded-index mint the remote
path uses, so the rule holds on every session kind.

The keyed id protects only if reads keep it. Outside consent, the wallet does
not GET an id derived from a DID the host or a request supplied; it matches such
a DID against the listing in memory. A read that surfaces a party does not touch
the party's entry.

## Rejected Alternatives

- **`sha256('connections/v1' + '|' + accountDid + '|' + armInput)`**, the writer
  roster's form. It allows the membership probe, ties every id to the account
  DID, and changes every id on an account move.
- **A random id with a lookup index.** The lookup is the listing, which a
  consent would then have to read in full before every write.

## Consequences

- Computing an id needs the unwrapped key, which every directory reader holds
  already, since it reads the descriptor to decrypt.
- The probe protection holds against the host alone. The key never rotates and
  is wrapped to the user key, so every revoked client, every retired credential,
  and every backup bundle holds it for good. Such a holder, working with the
  host, can probe for entries created after it lost access.
- A session whose unlock pointer still names the signup-time did:key derives the
  same ids as one on the verified did:webvh. An account move that carries the
  collection's descriptor keeps every id.
- encrypted-collections-spec defines the blinded-index key for index tokens
  only. This is a second use, and the spec is a party to it.
- Tagging both arms (`did:`, `writer:`) is redundant, since a DID always begins
  with `did:`; it is kept for symmetry.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The blinded-index key gains a rotation, so an id would no longer be stable
   across the collection's life.
2. A storage format authenticates a Resource's writer, so a probe no longer
   tells the host anything a signed listing would not.

Any new derivation is a new prefix (`connections/v2`) on new entries, not a
rewrite of stored ids.
