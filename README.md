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

Five subpaths:

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
`identity`, `request`, and `display` are import-directly-only, so consumers of
the root never pull the signing / KMS / document-loader dependency graph.

## Contribute

PRs accepted. See [CONTRIBUTING.md](CONTRIBUTING.md) for editor setup (Prettier,
ESLint, and EditorConfig) and how it maps to CI.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

[MIT License](LICENSE.md) © 2026 Interop Alliance.
