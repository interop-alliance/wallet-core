/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/resourceLog` entry: the wallet-domain residue of
 * the Resource Log Profile's client side after the generic half moved to
 * `@interop/vh-resource-log` -- the did:webvh controller adapter (the
 * library's controller port extended with the per-version
 * credential-inventory view, supplying the mandatory `admitAppend` admission
 * hook), the ceremony-tail license the hook carries
 * (`assertLadderAppendLicensed`, refusing with `ResourceLogLicenseError`),
 * and the import-free account-document leaf both are built on (`document.ts`
 * -- relation resolution, ladder-VM recognition, the credential class),
 * whose public home is `webvh`, which re-exports it.
 * Everything generic -- the JSON Lines codec, the store port and
 * `confirmAppend`, chain verification, the chain-head pin
 * (`ResourceLogPinStore` and `resourceLogPinId`; the named slot-key builders
 * stay on their owning subpaths: `accountLogPinId` in `webvh`,
 * `userKeyRosterPinId` in `keys`, `clientAnnexLogPinId` in `clientAnnex`),
 * the append path, and the sealing sweep -- lives in the library, and this
 * subpath re-exports none of it: one owner per name. Kept out of the root
 * export: this subpath pulls the did:webvh and ed25519 dependency graph.
 */
export {
  webvhResourceLogController,
  type ControllerInventory,
  type WebvhResourceLogController
} from './controller.js'
export { isResourceLogRefusal, ResourceLogLicenseError } from './errors.js'
export {
  attributeLadderRungsPerVersion,
  type LadderRungKeys
} from './ladderRungs.js'
export { assertLadderAppendLicensed } from './license.js'
