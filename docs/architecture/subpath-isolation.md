<!-- Part of wallet-core's architecture docs. The map, the key hierarchy,
     the ceremony inventory, and the glossary are in ../../ARCHITECTURE.md;
     the permanent wire-level constants are in wire-constants.md; this file
     holds one topic in full. -->

# Subpath isolation

The root export re-exports only the `sync` and `space` modules, plus the
root-level leaves `log.ts` and `ceremonyEvents.ts`. `ceremonyEvents.ts` takes
its vocabularies as type-only imports and loads only the import-free
`errorName.ts` and `labelText.ts` at runtime. So plaintext consumers of the root
never pull the signing / KMS / document-loader dependency graph. Every other
subpath is **import-directly-only**. Each module has a four-key entry (`types` /
`react-native` / `import` / `default`) in the `package.json` `exports` map -- a
new module means a new entry there.

Extra **leaf subpaths** exist for dependency isolation and must stay
dependency-light. Each is a single file with its own `exports` entry, so a
consumer loads it without the module barrel beside it:

- `./keys/clientKeyRecord` -- the client-key record codec alone, importing only
  a base64url codec (its key types are type-only imports, erased at compile
  time), so a wallet's storage tests load without the crypto/EDV graph.
- The pure derivations, for an offline consumer such as `@interop/wallet-backup`
  that derives clients and opens records without ever touching the account log:
  - `./keyring/kdf` -- the unlock KDF (`deriveUnlockSeed`, `KEYRING_KDF`).
  - `./keyring/recordEnvelope` -- the record envelope's descriptor mint,
    ciphers, addressed id, and frame parsers.
  - `./keys/userKey` -- the user key's key-agreement half (`mintUserKey`,
    `userKeyVaultKeys`).
  - `./keys/userKeyGenerations` -- `userKeyAsRecipient` and
    `unwrapUserKeyGenerations`.
  - `./unlock/standingClient` -- the standing client derivation.
  - `./webvh/ladderDerivation` -- the rung and ladder-VM derivation.
  - `./recovery/recoveryCode` -- the recovery code codec and
    `recoveryClientFromCode`.
- `./space/collections` -- the wallet Space collection ids, specs and resource
  names alone, importing `@interop/social-core` and
  `space/systemCollections.ts`, so an offline consumer names a collection
  without the `./space` barrel, which loads the pws-client transport graph
  (`provisioning.ts`, `deleteSpace.ts`).

  None of the derivation leaves may reach `webvh/` (past the
  `updateKeyMultibase` and `ladderDerivation` leaves), `resourceLog/`,
  `clientAnnex/`, `@interop/did-method-webvh`, or `@interop/vh-resource-log`.
  The module barrels keep re-exporting the same names.
  `keyring/recordEnvelope.ts`, `keys/userKey.ts`, and
  `keys/userKeyGenerations.ts` take their EDV names from
  `@interop/pws-client/edv/cipher`, a log-free entry that carries everything
  `edv/core` does except the log-governed descriptor stores; every non-leaf file
  keeps reading `edv/core`. `keyring/recordEnvelope.ts` takes the system
  collection names it needs (`KEYRING_COLLECTION`) from
  `space/systemCollections.ts` rather than `space/collections.ts`: an
  import-free file holding the `id`, `key-map`, `unlock-methods`, and `keyring`
  collection constants, which `space/collections.ts` re-exports.

The same trick serves a cross-package hand-off. `enrollment/connectCode.ts`
holds only the connect-code prefix and predicate, so a wallet can hand it to
`@interop/wallet-request`'s input classifier as a recognizer, beside
`space/pwsLink.ts`'s `isPwsLinkPayload`, without either wallet-core module
pulling in the classifier's own dependency graph. `webvh/did.ts` holds only the
did:webvh shape check, so wallet-core's own internal consumers can validate an
account DID without the zcap signing graph (`webvh/zcap.ts` re-exports it and
remains its public home).

Three `keys` files are kept import-light for an offline consumer that derives a
standing client and unwraps user key generations. `keys/rosterRecipientKid.ts`
has no imports. `keys/userKeyGenerations.ts` (`userKeyAsRecipient`,
`unwrapUserKeyGenerations`) imports `@interop/pws-client/edv/cipher` alone.
`keys/userKey.ts` holds the key-agreement half, and the signing half lives in
`keys/userKeySigning.ts`, which is the one that loads the keyring proof code. As
a result `unlock/standingClient.ts` evaluates no `webvh/` or `resourceLog/`
module. `keys/rosterRecipientKid.ts` and `keys/userKeySigning.ts` are files
rather than `exports` entries, surfaced through the `./keys` barrel.

The recovery client derivation follows the same rule.
`webvh/ladderDerivation.ts` holds the rung and ladder-VM derivation, and its
runtime imports are `@noble/hashes` and `webvh/updateKeyMultibase.ts`, a leaf
over `@interop/ed25519-verification-key` that `webvh/didWebvh.ts` re-exports. So
`recovery/recoveryCode.ts` (`recoveryClientFromCode`) evaluates no
`clientAnnex/`, `resourceLog/`, or did:webvh log module.

The isolation is checked in two places. `test/node/import-graph.test.ts` parses
each module with the TypeScript compiler API and walks the runtime import graph
of every leaf subpath listed in `test/probe/leafSubpaths.json` as written in
`src/`, failing on a reach into a forbidden directory or package; it also
asserts the exact closures of `keyring/kdf.ts` and `webvh/ladderDerivation.ts`,
that `keyring/recordEnvelope.ts` reaches neither `space/collections.ts` nor
`@interop/social-core`, and that each entry carries a four-key `exports` entry.
`test/probe/leafClosure.mjs` is the runtime counterpart: it imports each of the
same nine built leaf subpaths (the seven pure derivations plus
`./keys/clientKeyRecord` and `./space/collections`) under a Node resolve hook
and fails if any resolved module reaches `@interop/vh-resource-log`,
`@interop/did-method-webvh`, or wallet-core's own `resourceLog/`,
`clientAnnex/`, or `webvh/` modules (past `updateKeyMultibase` and
`ladderDerivation`). It runs against `dist/`, as part of `pnpm run test:dist`,
and catches what the `src/` walk cannot see: what a dependency package loads on
its own. Two reaches pass both checks by design and are not violations:
`edv/cipher` itself loads `@interop/storage-core` for pws-client's problem
types, and `./unlock/standingClient` loads `@interop/pws-client/identity`, which
brings in `@interop/ezcap` and `@interop/capability-agent`.
