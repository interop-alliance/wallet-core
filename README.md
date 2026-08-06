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
  `public-credentials`, `wallet-activity`), the `wallet-activity` wire shape
  with its pure `addHistory*` payload builders, the `publicCredentialUrl`
  derivation, and the `was-link` QR hand-off contract. Contacts collection specs
  live in [`@interop/social-core`](https://npm.im/@interop/social-core).

- **`@interop/wallet-core/identity`** -- the WAS identity derivation both wallet
  apps must perform byte-for-byte identically: `agentsFromSecret` /
  `agentsFromSeed` (controller secret or 32-byte seed to the did:key
  `CapabilityAgent`, `ZcapClient`, X25519 key agreement key, and single-key
  resolver, under the fixed bootstrap handle / key name) and
  `singleKeyResolver`.

- **`@interop/wallet-core/request`** -- wallet-request / exchange protocol
  handling: request classification and parsing (CHAPI get/store events,
  wallet-api messages and URLs), QueryByExample matching, cryptosuite
  negotiation, `composeVp` (signer and holder injected), the pure
  `processRequest` (consent runs in the caller; zcap / App Connect processing
  injected), the VC-API exchange client, and VCALM `interaction:` URL handling.
  The VPR type vocabulary lives in
  [`@interop/data-integrity-core`](https://npm.im/@interop/data-integrity-core)
  and is re-exported here.

- **`@interop/wallet-core/display`** -- pure verifiable-credential derivation /
  display helpers and credential input parsing. Raw values out (ISO strings,
  `Date`, booleans); date formatting, i18n, and UI concerns stay in the app.

- **`@interop/wallet-core/webvh`** -- the account's did:webvh identity: the
  hosted DID log, its per-client update-key rotation, the client enrollment
  entries, the one-entry client-revocation edit (verification methods, update
  key, and standing commitments out in a single entry, the staged commitment
  recovered by log attribution), the enrolled-client listing over a
  caller-verified log (for a "your wallets" surface), the
  fetch-and-verify-the-published-log step those ceremonies share, the WAS-backed
  store they write through, and ZCap signing under the did:webvh
  verification-method id.

- **`@interop/wallet-core/keys`** -- the user key and its
  `key-map/user-key.json` wrap-set roster: minting, the roster's
  init/read/rotate primitives with their client-side guards (`epochsMac`, the
  latest-seen epoch pin, the document-backed recipient resolver), the roster's
  compare-and-swap descriptor store, and the user key rotation cascade's
  per-collection op (re-epoch a collection onto the roster's current user key,
  staleness detected from durable state alone, history escrowed -- also the
  completion sweep's building block), plus the detector that converges a roster
  left wrapping the current key to a recipient the account document no longer
  keys. Also the enrolled-client display labels (`key-map/client-labels.json`)
  and their WAS-backed store. Also the client-key record codec: the contents and
  strict validation of the local record each wallet client keeps its own key
  material in (storage and wrapping stay app-side).

- **`@interop/wallet-core/clients`** -- the enrolled-client management surface:
  the listing over the locally verified did:webvh log with display labels
  merged, the disconnect-eligibility policy as pure functions, the revocation
  cascade orchestrator (document edit, roster rotation, collection fan-out,
  optional recovery re-mints), and the login-time roster policy.

- **`@interop/wallet-core/descriptors`** -- collection encryption-descriptor
  acquisition (fetch / cache / offline fallback) and the unknown-epoch refresh
  policy, including a self-refreshing EDV document cipher.

- **`@interop/wallet-core/keyring`** -- the unlock layer: the unlock derivation,
  the `{ version, wrapped }` account-pointer record codec, and the unlock Space
  lifecycle.

- **`@interop/wallet-core/enrollment`** -- the client enrollment ceremony
  (connect code, approval, completion).

- **`@interop/wallet-core/recovery`** -- recovery codes on the roster identity
  model: a code as a minimal always-enrolled wallet client (format and
  derivation, the recovery record, the document half of issuance / revocation /
  recovery).

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
Every other subpath (`identity`, `request`, `display`, `webvh`, `keys`,
`clients`, `descriptors`, `keyring`, `enrollment`, `recovery`) is
import-directly-only, so consumers of the root never pull the signing / KMS /
document-loader dependency graph.

## Contribute

PRs accepted. See [CONTRIBUTING.md](CONTRIBUTING.md) for editor setup (Prettier,
ESLint, and EditorConfig) and how it maps to CI.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[MIT License](LICENSE.md) © 2026 Interop Alliance.
