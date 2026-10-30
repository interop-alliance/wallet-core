<!-- Part of wallet-core's architecture docs. The map, the key hierarchy,
     the ceremony inventory, and the glossary are in ../../ARCHITECTURE.md;
     the permanent wire-level constants are in wire-constants.md; this file
     holds one topic in full. -->

# Permanent wire-level constants

Byte-for-byte identical strings both replicas depend on. **None of these can
ever change** -- each is baked into every existing account's derivations or
stored artifacts:

- **`BOOTSTRAP_HANDLE` / `BOOTSTRAP_KEY_NAME`** -- `'bootstrap'` /
  `'bootstrap-key'`, defined in `@interop/was-client/identity`. Why permanent:
  every data identity derives through them; both names are HMAC inputs to the
  client key, so a change renames every account.
- **`KEYRING_KDF`** -- Argon2id, 64 MiB memory, 3 passes, parallelism 1, salt
  `freewallet/keyring/unlock/argon2id/v1` (version 2; version 1's PBKDF2-600k
  set under `freewallet/keyring/unlock/v1` was replaced outright). Why
  permanent: every account's unlock identity.
- **`RECOVERY_KDF`** -- HKDF, SHA-256, salt
  `freewallet/keyring/recovery-code/v1`, info `freewallet/unlock-seed`. Why
  permanent: every issued recovery code; a changed salt orphans them all.
- **`BACKUP_CREDENTIAL_KDF`** -- HKDF, SHA-256, salt
  `freewallet/keyring/backup-credential/v1`, info `freewallet/unlock-seed`. Why
  permanent: every backup credential a bundle packs; a changed salt orphans them
  all.
- **`RECOVERY_CLIENT_SALT`** -- `freewallet/recovery/client-keys/v1` (infos
  `client-seed` / `ladder-seed`; the retired `update-key` info is never reused).
  Why permanent: every issued recovery code's client identity and update-key
  ladder.
- **`STANDING_CLIENT_SALT`** -- `freewallet/unlock/standing-client/v1` (infos
  `client-seed` / `binding-mac`). Why permanent: every standing credential's
  client identity and binding MAC key.
- **`USER_KEY_SALT`** -- `freewallet/keys/user-key/v1` (info `signing`) Why
  permanent: every account's user key signs its unlock-methods registry record;
  both wallets must derive the same signing key.
- **The ladder derivation**
  - Value: `webvh/ladderDerivation.ts`: HKDF salt
    `freewallet/unlock/update-ladder/v1`, infos `rung/<index>` (account rungs)
    and `vm` (the stable sibling VM key); `clientAnnex/generationRung.ts` mints
    `annex/rung/0` (a credential's static annex rung, the same key on every
    generation) through the same HKDF call.
  - Why permanent: both wallets must climb the same ladder from the same seed;
    the three info families stay disjoint under the one salt.
- **The generation segment** -- `gen-` + 12 random bytes base64url no-pad (20
  characters); it embeds in every annex DID string. Why permanent: orphan
  discovery is a prefix match, and the segment is a permanent substring of every
  annex DID.
- **The delegated-clients service entry**
  - Value: `type` `https://w3id.org/byoe#DelegatedClients` (readers dispatch on
    the type IRI and ignore the fragment), `serviceEndpoint` = the annex DID
    string; the wallet mints the fragment `#delegated-clients`, non-semantic and
    preserved on re-point.
  - Why permanent: the account document's pointer at the current annex
    generation; the server's inspector clause reads it.
- **The generation delegation**
  - Value: `invocationTarget` = the account Space's canonical container URL
    (trailing slash), `allowedAction` `['GET','HEAD','POST','PUT','DELETE']`,
    `controller` = the bare annex DID string, `expires` 365 days, rooted in the
    account Space's root zcap; embedded in the annex document as `type`
    `https://w3id.org/byoe#GenerationDelegation`, `serviceEndpoint` = the
    delegated-zcap map verbatim, fragment `#generation-delegation`
    (non-semantic), installed with the first transient VM rather than at
    genesis.
  - Why permanent: the standing authority every transient visit invokes under
    and every visit-scoped App Connect grant chains through (depth 3: root id
    string, the embedded delegation)
- **The replica pointer entry**
  - Value: one annex-document service entry per replica server, `type`
    `https://w3id.org/pws#ReplicaServer`, `serviceEndpoint` = the replica
    server's bare DID string, fragment `#replica-<multihash>` where
    `<multihash>` is the SHA-256 multihash of that DID string's UTF-8 bytes,
    base64url with no padding (`replicaServerServiceFragment`). Written by the
    entry that installs the generation delegation, and genesis carries none. A
    reader counts only a string endpoint and matches a server by the endpoint
    alone (the fragment is a selector and names no server), and a writer
    refuses a server DID that is not a did:webvh with the path
    `space:server:id`.
  - Why permanent: the source server gates a ladder-signed replica pull on it,
    and the derived fragment is what keeps one server's entry the same id across
    every restate.
- **The single-verb Space capability**
  - Value: `allowedAction` exactly `['DELETE']` or exactly `['GET']`, paired
    with the target that verb addresses: `DELETE` names the Space's canonical
    container URL (trailing slash), `GET` names the Space Metadata object at its
    `meta` sub-resource, and a `GET` given a `resource` names that one
    Resource's URL. The three-link shape takes the stored parent's own bytes --
    unchanged for `DELETE`, plus a `meta` segment for `GET`, plus
    `<collectionId>/<resourceId>` for the Resource read (three-link only) -- and
    the two-link shape builds them with `spacePath` / `spaceMeta` + `toUrl` over
    the Space's synthesized root. `expires` =
    `min(now + DELETION_ZCAP_TTL_MS, parent.expires)` with the TTL at ten
    minutes, `controller` the caller's delegatee; it is minted per use and not
    stored.
  - Why permanent: a storage server admits it by that exact verb-and-target
    pair, so both halves are the wire contract; the one-verb action set is what
    keeps a `DELETE` on the Space URL from reading as the broad subtree grant
    that URL would otherwise be, and the short life is what makes revocation
    moot on a torn run.
- **The transient annex VM**
  - Value: `type` `Multikey`, `controller` = the annex DID, id
    `<annexDid>#<publicKeyMultibase>`; published under `capabilityInvocation`
    AND `capabilityDelegation` and under no other relation (decision 0013)
  - Why permanent: the visit key invokes the generation delegation and delegates
    the visit's grants onward; the two-relation shape is also what keeps it out
    of the ladder-VM asymmetry every reader recognizes.
- **The unlock binding context** -- `freewallet/unlock/binding/v3`, over the
  JSON array `[context, controller, did or '', spaceUrl, ladderSeed or '']`. Why
  permanent: every bound credential's account-binding MAC. (`v2` bound a Space
  id and a host in place of the Space URL; no record under it survives.)
- **The did:webvh controller template** --
  `did:webvh:{SCID}:<host>:<prefix...>:space:<spaceId>:<collectionId>`, the host
  segment with a port as `%3A`, one segment per path segment of the base server
  URL (none for an origin-root base), as did-method-webvh's own address
  normalization produces them; `id` for the account log, a `gen-` generation id
  for an annex log. Why permanent: every account's identifier, and the location
  check every reader runs by inverting it.
- **`MultikeyCommitment` / `publicKeyCommitment`** -- VM type + property; the
  value is the bare sha2-256 multihash of the key's decoded multikey bytes,
  base64url no-pad. Why permanent: the document convention for a
  low-entropy-derived key-agreement key.
- **`ladderCommitment`**
  - Value: a property on every credential-class `keyAgreement` member,
    `Multikey` and `MultikeyCommitment` alike; the value is `hash(rung 0)` of
    the credential's ladder in the multihash form `nextKeyHashes` carries; a
    plain JSON member with no JSON-LD term, absent from an enrolled client's
    marked twin.
  - Why permanent: every seedless reader anchors the credential's ladder walk on
    it, and a member without it is unclaimable.
- **`BYOE_CONTEXT_URL`** -- `https://w3id.org/byoe/v1`, in every account
  document's `@context`. Why permanent: it defines the two commitment terms.
- **`CONNECT_CODE_PREFIX`** -- `freewallet-connect:`. Why permanent: the one
  spelling of the connect-code grammar.
- **Collection / resource names** -- see the Space layout tables in
  [space-layout.md](space-layout.md). Why permanent: the Space layout contract.
- **`COLLECTION_HISTORY_LOG_SUBRESOURCE`** -- `meta/log`, the Collection
  sub-resource every encrypted collection's governing history log is served at.
  Why permanent: every governed collection's log is addressed there, and every
  reader derives its chain-head pin slot
  (`space/<spaceId>/<collectionId>/meta/log`) from it.
- **`CLIENT_ANNEX_PROFILE_IDENTIFIER`**
  - Value: `https://w3id.org/pws/client-annex`, the `specs` key of the client
    annex profile's service description entry; the entry carries `version`
    (`0.1` today) and an optional `url`, unknown members are ignored, and a
    non-string `url` makes it read as absent.
  - Why permanent: every server that claims the profile lists it under this key,
    and a wallet signs up only on a host whose description carries it, and
    checks it once per account, at signup.
- **The epoch-configuration state type** -- `WasEpochConfiguration`
  (was-client's `EPOCH_CONFIGURATION_STATE_TYPE`), the `state.type` of every
  entry in a roster or collection descriptor log. Why permanent: a verified head
  of any other type is refused fail-closed, so every entry ever written carries
  it.
- **The resource-log format identifier** -- `resource-log:0.1`, the genesis
  `parameters.method` and the `history.method` a governed descriptor names. Why
  permanent: a log's genesis parameters are hashed into its SCID, and a reader
  refuses a log naming another format.
- **`WalletActivity` `type` / `summary` strings** -- `space/activity.ts`. Why
  permanent: byte-significant across replicas.
- **`KEYRING_RECORD_VERSION`** -- `2`. Why permanent: the stored record
  envelope.
- **`UNLOCK_SPACE_TYPE`** -- `['AuxiliarySpace', 'Space', 'UnlockSpace']`, the
  Space Description `type` of every unlock Space (passphrase, passkey, recovery
  code). Why permanent: the server treats a Space's `type` as immutable after
  creation, and it is how an unlock Space is recognized from its Space Metadata
  object.
- **`CONNECTIONS_COLLECTION`** -- `connections`, display name `Connections`;
  `idDerivation: 'random'`, `mutable: true`, `encryption: 'edv'`,
  `isPublic: false`, `shareable: false`, `grantable: false`, in the provision
  roster outside the synced specs. Why permanent: every wallet reads and writes
  the one directory; a second id splits it.
- **`CONNECTIONS_ID_PREFIX` and the id arms**
  - Value: the directory resource id: the first 16 bytes of
    `HMAC-SHA-256(hmacKey, utf8('connections/v1' + '|' + armInput))`, formatted
    with was-client's `edvIdFromBytes`; `hmacKey` is the collection's
    blinded-index key, `armInput` is `'did:' + did` or `'writer:' + writerId`;
    the account DID is not an input. A third arm, `'seed:'`, keys the seed tag.
  - Why permanent: both wallets must find a party's entry at the same id, and
    the key is what keeps the host from probing for a guessed DID.
- **The `connections` entry shape**
  - Value:
    `{ version: 1, kind, id?, name?, label?, origin?, url?, appKey?, firstSeen, lastSeen, retired?, grants, writers, seed?, seedTag?, grantsReceived?, outbox?, declined?, replicas? }`;
    `url` carries an app's canonical URL or a replica server's base URL;
    timestamps ISO 8601 UTC; `name`, `label`, and each writer member's `label`
    bounded at 1 to 64 code points after the control and bidi characters are
    stripped and the result trimmed; `writers` members
    `{ writerId, label, lastSeen, active }`; no signing-key member (a wallet
    client's `id` is its did:key)
  - Why permanent: every reader must parse the same members; readers keep
    unknown members and a writer writes them back verbatim (`decisions/0025`,
    `0027`)
- **`CONNECTION_KINDS`** --
  `'app' | 'agent' | 'wallet-client' | 'contact' | 'replica-server'`; an unknown
  value reads as an unclassified party. Why permanent: a kind decides which
  flows may write an entry. A `replica-server` entry's `id` is the server's
  `serverDid` (`decisions/0031`).
- **The `grants` member and `GRANT_KINDS`**
  - Value: each member `{ zcap, grantKind, grantedAt }`: `zcap` the delegated
    capability verbatim (its `expires` required; a capability with none is
    refused by the codec), `grantKind` `'grant' | 'share'` (always written; an
    unknown value reads as a plain grant), `grantedAt` ISO 8601 UTC.
  - Why permanent: revocation POSTs the stored capability, and the unshare picks
    the share grants by `grantKind`.
- **`CONNECTION_WRITER_POLICY`** -- a writer member goes `active: false` after
  90 days unseen, `lastSeen` is touched at most once a day, at most 8 members
  per entry with the oldest `lastSeen` dropped beyond it. Why permanent: not
  stored, but every wallet that sweeps must agree on which members to drop.
- **`INBOX_COLLECTION`**
  - Value: `inbox`, display name `Inbox`; `encryption: 'plaintext'`,
    `isPublic: false`, `grantable: false`, in the provision roster after
    `connections`, with no replica and no sync feed; a connected agent holds a
    POST capability on the container alone through the `inbox` target class, and
    that grant's target carries no `*` marker.
  - Why permanent: every wallet drains the one inbox, and every agent posts to
    it.
- **The `seed` member** -- 32 random bytes, base64url no-pad (43 characters),
  the wallet's pairwise key toward the party; written once, and a different
  `seed` already on the entry refuses (`decisions/0028`). Why permanent: every
  client derives the same pairwise did:key from it.
- **The `seedTag` member**
  - Value: the full 32-byte
    `HMAC-SHA-256(hmacKey, utf8('connections/v1' + '|' + 'seed:') || seedBytes)`,
    base64url no-pad, under the directory's blinded-index key; written with the
    seed, the codec refuses a seed with no tag, and every site that turns a seed
    into a key verifies it first and fails closed.
  - Why permanent: the check that a host did not plant the seed.
- **The `grantsReceived` member and `RECEIVED_GRANT_KINDS`** -- each member
  `{ zcap, grantKind, receivedAt }`; `RECEIVED_GRANT_KINDS` is `['inbox']`, the
  party's POST capability on its own inbox; an unknown kind is kept as stored,
  and an absent list reads as empty. Why permanent: every wallet pushes to the
  party through the same records.
- **The `outbox` member** -- each member `{ message, createdAt }`: the pending
  envelope verbatim and its queueing time, ISO 8601 UTC, with no channel member;
  an absent list reads as empty. Why permanent: every client settles and prunes
  the same pending messages.
- **The `declined` member** -- ISO 8601 UTC, present while the owner's decline
  of the party's offer stands; cleared by a fresh consent, validated like
  `retired`. Why permanent: every wallet must honor the same decline.
- **The `replicas` member** -- a list on a `replica-server` entry, one item per
  replica Space:
  `{ fromSpace, spaceId, registrationId?, pendingRegistrationId?, collections?, stoppedAt?, restartedAt?, lostAt? }`.
  `fromSpace` is the source Space's container URL, with its trailing slash.
  `spaceId`, `registrationId`, and `pendingRegistrationId` are each 32 random
  bytes, base64url with no padding (43 characters). `collections` is a non-empty
  list of collection ids, absent when every live Collection is copied. An absent
  `replicas` reads as empty, a non-empty one parses on a `replica-server` entry
  alone, and unknown item members are kept verbatim. Why permanent: both wallets
  must parse the same items, and a malformed item makes the entry unparseable
  (`decisions/0031`).
- **The replica markers** -- `stoppedAt`, `restartedAt`, and `lostAt`, each an
  ISO 8601 UTC time. Each is written by one intent and cleared by its
  completion, and no unset marker reads as an intent. `restartedAt` is written
  first by a re-start and cleared last, and writing it clears the entry's
  `declined`. Why permanent: every wallet must read the same outstanding
  intents, and a new lifecycle fact is a new marker rather than a changed one.
- **`renewedAt`** -- an optional ISO 8601 UTC member on a renewed `grants`
  record, beside the kept `grantedAt`, which stays the consent time. Why
  permanent: the renewal scope keys on `grantedAt`, so renewal must not
  overwrite it.
- **The inbox Grant envelope**
  - Value: `{ type: 'Grant', actor, object: { zcaps } }`: a bare-string `type`,
    `actor` a did:key, content type `application/json`, no `@context`, unknown
    members ignored; one message kind, an invitation and a renewal told apart by
    the zcap target (`inboxGrantMessage` / `parseInboxGrantMessage`)
  - Why permanent: every wallet and every agent built on this package read and
    write the one shape.
- **The pairwise did:key derivation** -- was-client's `agentsFromSeed` over the
  entry's `seed` under the pinned bootstrap names, with no derivation label of
  its own, after the seed tag verifies (`connectionDidKey`). Why permanent:
  every client must present the same did:key to the agent.
- **The audience grant** -- `allowedAction` `['GET','HEAD']` on the audience
  collection's container URL, no key epoch escrowed (`delegateAudienceGrant`);
  the target is the bare container URL until the subtree marker ships (see the
  known gap below). Why permanent: a storage server admits a member's read by
  this verb-and-target pair.
- **The pws-link `t` discriminator** -- the string `'pws-link'` on the QR
  hand-off payload (`PWS_LINK_TYPE`). Why permanent: every printed or scanned
  code carries it, and the recognizer matches on it.

Every unlock method's KDF carries a distinct salt so two methods can never
derive the same unlock identity.

One known gap touches two of these shapes. The authorization profile is adding
an explicit `*` subtree marker on `invocationTarget` (WASS-58). Until it ships,
`mintGenerationDelegation` and `delegateAudienceGrant` mint the bare container
URL, which the current server reads as covering the subtree. Both mint sites
carry a comment marking where the target flips.
