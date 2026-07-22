# @interop/wallet-core Changelog

## 0.0.1 - TBD

### Added

- Initial release. Shared wallet-domain logic extracted from two WAS-enabled
  wallet apps, as two subpaths:
  - `@interop/wallet-core/sync` -- the WAS replication engine core: `SyncEngine`
    (single-flight coalescing, migrate-once ordering, exponential backoff with
    jitter, abort), the `runPull` / `projectionForDoc` and `runPush` algorithms
    (change-feed pagination, empty-page checkpoint rule, decrypt-outside-
    transaction, poison-doc skip, and the content-addressed conflict settlement
    table), the replica-side `SyncStore` / `SyncedRow` / `ProjectionAction` /
    `ResolveConflict` seam, and the generic `SyncedCollectionSpec` shape. The
    wire contract and port (`WasSyncPort`, `WireDoc`, `DocCipher`,
    `SyncCheckpoint`, `MasterState`, `Json`, and the conflict / not-found error
    classes) are re-exported from `@interop/was-client`.
  - `@interop/wallet-core/space` -- the wallet Space layout contract: the shared
    collection ids and descriptive specs (`private-credentials`,
    `public-credentials`, `wallet-activity`), the `WalletActivity` wire shape
    with pure `addHistory*` payload builders, `publicCredentialUrl`, and the
    `was-link` QR hand-off contract (`buildWasLinkPayload` /
    `parseWasLinkPayload` / `encodeWasLinkSecret`) with server-URL validation.
