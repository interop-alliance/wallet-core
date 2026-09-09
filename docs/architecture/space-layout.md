<!-- Part of wallet-core's architecture docs. The map, the key hierarchy,
     the ceremony inventory, the permanent wire-level constants, and the
     glossary are in ../../ARCHITECTURE.md; this file holds one topic in full. -->

# The wallet Space layout (`space`)

A **Space** is a WAS container, addressed as
`https://<host>/space/<spaceId>/<collection>/<resource>`. An account has **two**
Spaces:

- the **data Space** -- credentials, activity, identity, key-map (its `spaceId`
  is an independent random id minted at signup, carried in the account pointer),
  and
- a minimal **unlock Space** -- one keyring resource, controlled by the unlock
  identity, addressed by `hash(unlock did:key)` as a discovery convention (see
  "The key hierarchy" in ../../ARCHITECTURE.md).

The synced collections both replicas must lay out field-for-field identically
(`space/collections.ts`; a drift splits the feed and never converges):

| Collection            | id derivation | mutable | encryption | public | shareable |
| --------------------- | ------------- | ------- | ---------- | ------ | --------- |
| `private-credentials` | content       | no      | EDV        | no     | yes       |
| `public-credentials`  | content       | no      | plaintext  | yes    | no        |
| `wallet-activity`     | content       | no      | EDV        | no     | yes       |
| `app-connections`     | content       | no      | EDV        | no     | no        |

`shareable` is the share-surface allowlist, not an encryption attribute: the
encrypted sets (cipher build, key epochs, the user-key cascade) still follow
`encryption`. `app-connections` holds the app-key credentials, seeds and all, so
it is encrypted and not offered for sharing.

Contacts (`contacts`, `contacts-history`) are deliberately **not** here -- their
specs live in `@interop/social-core`.

Provisioning is a two-step. `provisionWalletSpace` (in `space`, crypto-free so
the root barrel stays so) creates the roster's collections create-if-absent, and
`ensureWalletSpaceEpochs` (in `keys`, EDV-bearing) installs each encrypted
collection's key epoch[0] -- a fresh random epoch key wrapped to the user key,
rather than a user-key generation itself. An encrypted collection is created
BARE, with `encryption: 'governed'` and no client-written descriptor member: the
epoch install is also its declaration, landing as the genesis of the
collection's own governing history log (see "Per-collection descriptor logs" in
keys-and-descriptor-logs.md). Every encrypted collection's descriptor carries an
epoch roster from birth, was-client refuses reads and writes fail-closed until
the install lands, and both steps adopt rather than overwrite what an earlier
provisioner landed, so a torn signup heals by re-running. Both steps run before
a collection's first content push (the sync engine's `ensureProvisioned` seam;
see "The sync engine" in sync-engine.md). The epoch install reports per
collection rather than failing the whole fan-out: the settled descriptor,
whether this call installed it, and the collections that failed. The install
also carries the mint gate. A caller holding the settled user-key roster passes
its descriptor, and the fan-out is refused whole (`skipped`, nothing written)
unless the roster's current epoch IS the user key handed in, since a collection
installed under a key the roster does not deliver is keyed to nothing for good.
Both genesis ceremonies pass it and report the refusal as `epochsSkipped`. The
sync engine's provisioner holds no roster and runs ungated under the key login
adopted from it.

**Content is re-provisioned, not migrated**: the install puts a fresh epoch[0]
onto ANY epoch-less descriptor with no check for content already in the
collection. Anything sealed straight to the user key's key-agreement key stops
being routable the moment epoch[0] lands, and nothing re-seals it.
Re-provisioning from scratch is the supported answer, and it covers a collection
born with a client-written descriptor too: the server holds a declared
descriptor immutable and derives a governed one from the history log, so the two
are exclusive and no conversion exists. Every provisioning re-run over such a
collection is refused (was-client's early `ValidationError` in place of the
server's 409) rather than adopting it.

The system collections sit outside the synced set (not replicated; read and
written directly):

| Collection       | Access                    | Resources                                                            |
| ---------------- | ------------------------- | -------------------------------------------------------------------- |
| `id`             | world-readable            | `did.json` (did:web projection), `did.jsonl` (the did:webvh log)     |
| `key-map`        | private, capability-gated | `keys.json`, `user-key.jsonl` (the roster log), `client-labels.json` |
| `unlock-methods` | private, capability-gated | `methods.json` (the account's unlock-method registry)                |
| `keyring`        | in the unlock Space only  | `keyring.json` (the wrapped account pointer)                         |

`id` and `key-map` are split exactly so `id` can be world-readable without
exposing key material.

Every handle onto one of them, and onto a client-annex generation's `gen-`
collection in the annex Space, is built by `plaintextCollection`, the one site
stating the `{ encryption: 'plaintext' }` override. Sharing it is load-bearing
twice over. Without the override the client describes the collection to decide
plaintext vs encrypted, so a Space that does not exist yet (every keyring lookup
for a fresh unlock secret) 404s into an `EncryptionError` rather than a
404-shaped `null`. And on a collection the client took as encrypted, the EDV
codec computes its own write preconditions, silently defeating the
compare-and-swap guard the `did.jsonl` publish and the resource-log append path
depend on.

`space/activity.ts` defines the `WalletActivity` wire shape and its pure
`addHistory*` builders; the `type` strings and `summary` phrasings are
byte-significant across replicas. `space/wasLink.ts` defines the `was-link` QR
hand-off payload -- a non-URL JSON blob on purpose, so no OS deep-link handler
routes it and it cannot leak into history or link-preview fetchers.
