# Wallet Core _(@interop/wallet-core)_

[![Node.js CI](https://github.com/interop-alliance/wallet-core/workflows/CI/badge.svg)](https://github.com/interop-alliance/wallet-core/actions?query=workflow%3A%22CI%22)
[![NPM Version](https://img.shields.io/npm/v/@interop/wallet-core.svg)](https://npm.im/@interop/wallet-core)

> Shared wallet-domain logic (WAS sync engine core and wallet Space layout
> contracts) for Interop wallet apps.

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [License](#license)

## Background

`@interop/wallet-core` is the shared, correctness-critical code two WAS-enabled
wallet apps (a React Native mobile wallet and a browser wallet) hold in common:
the cross-replica byte-compatibility surface both must agree on to converge on
identical bytes. It is isomorphic (browser, Node.js, React Native) and has no UI
or storage dependencies -- side effects are injected, and the dep-heavier
protocol subpaths are import-directly-only.

The subpaths:

- **`@interop/wallet-core/sync`** -- the Wallet Attached Storage (WAS)
  replication engine core: the `SyncEngine` orchestration (single-flight,
  migrate-once, backoff), the `runPull` / `runPush` algorithms, the replica-side
  `SyncStore` seam, and the generic `SyncedCollectionSpec` shape. The wire
  contract and port (`WasSyncPort`, `WireDoc`, `DocCipher`, ...) are re-exported
  from [`@interop/was-client`](https://npm.im/@interop/was-client) so an engine
  consumer imports one package.

- **`@interop/wallet-core/space`** -- the wallet Space layout contract: the
  shared collection ids and descriptive specs (`private-credentials`,
  `public-credentials`, `wallet-activity`, `app-connections`), the
  `wallet-activity` wire shape with its pure `addHistory*` payload builders, the
  `publicCredentialUrl` derivation, and the `was-link` QR hand-off contract.
  Contacts collection specs live in
  [`@interop/social-core`](https://npm.im/@interop/social-core).

- **`@interop/wallet-core/identity`** -- the WAS identity derivation both wallet
  apps must perform byte-for-byte identically: `agentsFromSecret` /
  `agentsFromSeed` (controller secret or 32-byte seed to the did:key
  `CapabilityAgent`, `ZcapClient`, X25519 key agreement key, and single-key
  resolver, under the fixed bootstrap handle / key name), `agentsFromKeyAgent`
  (the same assembly from a `CapabilityAgent` an app derived itself), and
  `singleKeyResolver`.

- **`@interop/wallet-core/request`** -- wallet-request / exchange protocol
  handling: request classification and parsing (CHAPI get/store events,
  wallet-api messages and URLs), QueryByExample matching, cryptosuite
  negotiation, `composeVp` (signer and holder injected), the pure
  `processRequest` (consent runs in the caller; zcap / App Connect processing
  injected), the App Connect app-key credential module (query validation,
  matching, minting, store-time refusal, legacy re-issue), the
  `WalletOnboardingQuery` transport vocabulary (compose and classification), the
  VC-API exchange client, VCALM `interaction:` URL handling, the requester's
  half of a server's ephemeral exchange (`createEphemeralExchange` /
  `pollEphemeralExchange`, the poll bounded by a caller signal or its own
  deadline), and `composeCapabilityRequest`, the zcap-only VPR a requester
  stores on such an exchange. The VPR type vocabulary lives in
  [`@interop/data-integrity-core`](https://npm.im/@interop/data-integrity-core)
  and is re-exported here.

- **`@interop/wallet-core/webvh`** -- the account's did:webvh identity: the
  hosted DID log, its per-client update-key rotation, the client enrollment
  entries, the one-entry client-revocation edit (verification methods, update
  key, and standing commitments out in a single entry, the staged commitment
  recovered by log attribution), the enrolled-client listing over a
  caller-verified log (for a "your wallets" surface), the
  fetch-and-verify-the-published-log step those ceremonies share, the WAS-backed
  store they write through, and ZCap signing under the did:webvh
  verification-method id.

- **`@interop/wallet-core/resourceLog`** -- the wallet-domain half of the
  Resource Log Profile, the hash-linked log format governing key resources
  co-managed between a wallet's clients and the storage server. Three pieces.
  The did:webvh controller adapter, which answers which keys could have signed a
  given entry at a given document version, and supplies the admission hook every
  verifier consults. The ceremony-tail license that hook carries, which bounds
  what a standing credential's ladder key may append -- above all refusing a
  silent rekey against an unchanged document. And `isResourceLogRefusal`, the
  shared reading of the refusal taxonomy: which refusals a reader must not paper
  over with a cached copy, and which one it may (a chain-head rollback,
  reconcilable divergence). The adapter and the license read the account
  document through one import-free leaf beside them: relation resolution,
  ladder-VM recognition, and the credential class. They therefore answer exactly
  as the client listing does. That leaf's public home is the `webvh` subpath.
  The generic half lives in
  [`@interop/vh-resource-log`](https://npm.im/@interop/vh-resource-log) -- chain
  verification against an adversarial host, the chain-head pin, the entry
  builders, the read/append/create path, and the sealing sweep. Transport is in
  [`@interop/was-client`](https://npm.im/@interop/was-client)'s `/log` subpath,
  and the hashing and proof kernel in
  [`@interop/did-method-webvh`](https://npm.im/@interop/did-method-webvh).

- **`@interop/wallet-core/keys`** -- the user key and its wrap-set roster,
  governed by the `key-map/user-key.jsonl` resource log: minting, the roster's
  init/read/rotate primitives with their client-side guards (the verified log
  itself, the latest-seen epoch pin, the document-backed recipient resolver),
  the log-governed (and sealable) descriptor store those primitives drive, and
  the user key rotation cascade's per-collection op (re-epoch a collection onto
  the roster's current user key, staleness detected from durable state alone,
  history escrowed -- also the completion sweep's building block), plus the
  detector that converges a roster left wrapping the current key to a recipient
  the account document no longer keys. Also `ensureWalletSpaceEpochs`, the
  provision-time install of each encrypted wallet collection's key epoch[0] (a
  fresh random epoch key wrapped to the user key) -- the EDV-bearing second step
  of `provisionWalletSpace`. Also the enrolled-client display labels
  (`key-map/client-labels.json`) and their WAS-backed store. Also the client-key
  record codec: the contents and strict validation of the local record each
  wallet client keeps its own key material in (storage and wrapping stay
  app-side).

- **`@interop/wallet-core/clients`** -- the enrolled-client management surface:
  the listing over the locally verified did:webvh log with display labels
  merged, the disconnect-eligibility policy as pure functions, the revocation
  cascade orchestrator (document edit, roster rotation with its seal backstop,
  collection fan-out, optional recovery re-mints), and the login-time roster
  policy (which now also seals a converged roster's governing log).

- **`@interop/wallet-core/descriptors`** -- collection encryption-descriptor
  acquisition (fetch / cache / offline fallback), the log-governed descriptor
  source (every read re-verifies the governing resource log), and the
  unknown-epoch refresh policy, including a self-refreshing EDV document cipher.

- **`@interop/wallet-core/keyring`** -- the unlock layer: the unlock derivation,
  the signed `{ version, encryption, wrapped, proof }` account-pointer record
  codec (the proof is verified before the record is decrypted), and the unlock
  Space lifecycle.

- **`@interop/wallet-core/enrollment`** -- the client enrollment ceremony
  (connect code, approval, completion) plus the onboarding-response envelope
  that carries a connect code back over an exchange.

- **`@interop/wallet-core/genesis`** -- the account-genesis ceremony: the local
  mint of a brand-new account's complete key set (`mintAccountKeySet`: Space id,
  client identity seed, user key, did:webvh update keys) and the staged
  provisioning both apps must encode identically (`ensureAccountGenesis`: Space
  provisioning, the optional KMS key-map acquisition, did:webvh genesis,
  user-key roster genesis after DID publication, epoch[0] on every encrypted
  roster collection, and the Space-controller promotion, also exported standing
  alone as `ensurePromotedSpaceController`). Idempotent end to end: a torn run
  heals by re-running. The keyring bind is deliberately not a stage, so a wallet
  with no unlock method bound at creation drives the same ceremony.

- **`@interop/wallet-core/unlock`** -- standing unlock credentials: every unlock
  method (passphrase, passkey PRF, recovery code) as a standing credential in
  the recovery-code configuration, with self-enrolling login. The
  credential-derived client identity and binding MAC key, the update-key ladder
  (latent-and-consumed did:webvh update authority from a random seed carried in
  the unlock record, the current rung recovered from the log itself), the unlock
  record codec (shell / bridge delegation / ladder members under a
  credential-authenticated binding, with the bridge-only re-mint), the merged
  document-inventory edit (a verbatim `keyAgreement` entry or a
  `publicKeyCommitment` entry for a low-entropy-derived key), and the
  self-enrolling continuation with its composed completion.

- **`@interop/wallet-core/recovery`** -- recovery codes on the roster identity
  model, over the `unlock` machinery: a code as a minimal always-enrolled wallet
  client (format and derivation, the document half of issuance / revocation /
  recovery with its spend-on-use continuation, the pre-minted `did.jsonl`
  delegation builder and the revocation cascade's bridge re-mint core; the
  record codec is the `unlock` subpath's, re-exported here).

- **`@interop/wallet-core/clientAnnex`** -- the client annex, the sibling
  did:webvh log holding per-visit transient client keys in garbage-collected
  generations, published in the account's auxiliary annex Space. This is the
  authoring and maintenance surface of everything anchored on an unlock
  credential's update-key ladder: the ladder itself (rung and VM derivation, the
  shared attribution walks), the annex log and its GC, ZCap signing under a
  ladder VM, the ladder-anchored account-log ceremonies (genesis,
  self-enrollment, forget, and the last-client transition to a client-less
  account), the credential-anchored account genesis with its mend and its
  per-visit readiness ensure, and the transient-recovery continuation. It sits
  on top of the other subpaths and none of them import from it.

## Install

- Node.js 24+ is recommended.

```
pnpm install @interop/wallet-core
```

### Development

```
git clone https://github.com/interop-alliance/wallet-core.git
cd wallet-core
pnpm install
```

## Usage

```ts
import { SyncEngine, runPull, runPush } from '@interop/wallet-core/sync'
import {
  PRIVATE_CREDENTIALS_COLLECTION,
  publicCredentialUrl,
  buildWasLinkPayload,
  parseWasLinkPayload,
  addHistoryCredentialCreated
} from '@interop/wallet-core/space'
```

The `sync` and `space` subpaths are re-exported from the package root as well.
Every other subpath (`identity`, `request`, `webvh`, `resourceLog`, `keys`,
`clients`, `descriptors`, `keyring`, `enrollment`, `genesis`, `unlock`,
`recovery`, `clientAnnex`) is import-directly-only, so consumers of the root
never pull the signing / KMS / document-loader dependency graph.

Two further exports are leaves of that same isolation, carved out to stay
dependency-light: `keys/clientKeyRecord` is the client-key record codec alone,
so a wallet's storage tests load without the crypto graph, and
`request/matching` is the QueryByExample matchers alone.

## Contribute

PRs accepted. See [CONTRIBUTING.md](CONTRIBUTING.md) for editor setup (Prettier,
ESLint, and EditorConfig) and how it maps to CI.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[MIT License](LICENSE.md) © 2026 Interop Alliance.
