/**
 * Shared fixtures for the resource-log suites that stayed in wallet-core
 * after the generic client side moved to `@interop/vh-resource-log`. The
 * base fakes come from the library's `./testing` subpath (one reference
 * implementation of the ports, never re-derived); this file wraps its
 * `fakeController` into the wallet-core EXTENDED controller view -- the
 * per-version credential-inventory accessor plus the `admitAppend` hook
 * carrying the ceremony-tail license, exactly as `webvhResourceLogController`
 * supplies them -- keeps the terminal handover-entry builder (nothing in
 * `src/` emits terminal entries yet, so the seal suite constructs them from
 * the kernel primitives directly), and carries a co-signing helper ported
 * from the library suite, for the multi-proof entries the per-entry ladder
 * rule is about.
 */
import {
  buildVersionId,
  createDataIntegrityProofTemplate,
  deriveHash,
  signDataIntegrityProof,
  signerFromExternalKey
} from '@interop/did-method-webvh'
import type { ResourceLogEntry } from '@interop/storage-core'
import type {
  ResourceLogController,
  ResourceLogSigner
} from '@interop/vh-resource-log'
import {
  CONTROLLER_DID,
  fakeController as libFakeController,
  memoryLogStore
} from '@interop/vh-resource-log/testing'
import {
  assertLadderAppendLicensed,
  type ControllerInventory,
  type WebvhResourceLogController
} from '../../../src/resourceLog/index.js'

export { CONTROLLER_DID, memoryLogStore }

/**
 * A fake extended controller view: the library's `fakeController` (an ordered
 * controller-log version list with per-version `assertionMethod` key-multibase
 * sets; an empty `versions` list models an unversioned static controller, with
 * `currentKeys` supplying the current-document set) plus the per-version
 * inventory view the ceremony-tail license reads (`ladderKeys`, the ladder VM
 * multibases, and `inventoryKeys`, the S(V) member set -- both default empty,
 * and ladder keys always count into the inventory set as the real adapter's
 * do) and the `admitAppend` hook carrying the license, mirroring
 * `webvhResourceLogController`.
 *
 * @param options {object}
 * @param [options.did] {string}
 * @param options.versions {Array<{ versionId: string, keys: string[],
 *   ladderKeys?: string[], inventoryKeys?: string[] }>}
 * @param [options.currentKeys] {string[]}   unversioned controllers only
 * @returns {WebvhResourceLogController}
 */
export function fakeController({
  did = CONTROLLER_DID,
  versions,
  currentKeys
}: {
  did?: string
  versions: Array<{
    versionId: string
    keys: string[]
    ladderKeys?: string[]
    inventoryKeys?: string[]
  }>
  currentKeys?: string[]
}): WebvhResourceLogController {
  const base = libFakeController({
    did,
    versions: versions.map(({ versionId, keys }) => ({ versionId, keys })),
    ...(currentKeys === undefined ? {} : { currentKeys })
  })
  function versionAt(versionId?: string) {
    if (versionId === undefined) {
      return versions[versions.length - 1]
    }
    const version = versions.find(entry => entry.versionId === versionId)
    if (!version) {
      throw new Error(`fake controller has no version "${versionId}"`)
    }
    return version
  }
  const view: WebvhResourceLogController = {
    ...base,
    async inventoryAt(versionId?: string): Promise<ControllerInventory> {
      const version =
        versionId === undefined && versions.length === 0
          ? undefined
          : versionAt(versionId)
      const ladderKeys = new Set(version?.ladderKeys ?? [])
      const inventoryKeys = new Set([
        ...ladderKeys,
        ...(version?.inventoryKeys ?? [])
      ])
      return { ladderKeys, inventoryKeys }
    },
    async admitAppend({
      keyMultibase,
      controllerVersionId,
      controllerVersionIndex,
      headControllerVersionIndex,
      proofKeys
    }) {
      const inventory = await view.inventoryAt(controllerVersionId)
      if (inventory.ladderKeys.has(keyMultibase)) {
        await assertLadderAppendLicensed({
          controller: view,
          controllerVersionIndex,
          headControllerVersionIndex,
          proofKeys
        })
      }
    }
  }
  return view
}

/**
 * The writer's verification-method DID URL, exactly as the entry builders
 * construct it: it carries the controller's verified head versionId
 * (omitted for an unversioned controller).
 *
 * @param options {object}
 * @param options.controller {ResourceLogController}
 * @param options.keyMultibase {string}
 * @returns {string}
 */
export function versionedVm({
  controller,
  keyMultibase
}: {
  controller: ResourceLogController
  keyMultibase: string
}): string {
  const controllerVersionId =
    controller.versionIds[controller.versionIds.length - 1]
  const query =
    controllerVersionId === undefined ? '' : `?versionId=${controllerVersionId}`
  return `${controller.did}${query}#${keyMultibase}`
}

/**
 * Co-signs an already-signed entry: returns it with one more proof appended,
 * signed by `signer` under its versioned verification method and carrying the
 * entry's own `versionTime` as the proof's `created` time. Multi-proof
 * entries are legal in the profile, and the added proof sits in a later array
 * position -- the placement a per-entry admission hook would never see. Ported
 * from the library suite's fixture of the same name.
 *
 * @param options {object}
 * @param options.entry {ResourceLogEntry}
 * @param options.controller {ResourceLogController}
 * @param options.signer {ResourceLogSigner}
 * @returns {Promise<ResourceLogEntry>}
 */
export async function coSignEntry({
  entry,
  controller,
  signer
}: {
  entry: ResourceLogEntry
  controller: ResourceLogController
  signer: ResourceLogSigner
}): Promise<ResourceLogEntry> {
  const { proof: _omitted, ...unsigned } = entry
  const coSignature = await signDataIntegrityProof(
    unsigned,
    createDataIntegrityProofTemplate({
      verificationMethod: versionedVm({
        controller,
        keyMultibase: signer.keyMultibase
      }),
      created: entry.versionTime
    }),
    signerFromExternalKey({
      publicKeyMultibase: signer.keyMultibase,
      sign: signer.sign
    })
  )
  return {
    ...entry,
    proof: [...entry.proof, coSignature as ResourceLogEntry['proof'][number]]
  }
}

/**
 * Builds and signs a terminal handover entry against a verified head: the
 * profile's `{ nextLog }` parameters, the predecessor's state verbatim (a
 * handover changes no resource state), hash chained off the head.
 *
 * @param options {object}
 * @param options.head {ResourceLogEntry}
 * @param options.nextLog {{ method: string, scid: string }}
 * @param options.controller {ResourceLogController}
 * @param options.signer {ResourceLogSigner}
 * @param [options.versionTime] {string}
 * @returns {Promise<ResourceLogEntry>}
 */
export async function buildTerminalEntry({
  head,
  nextLog,
  controller,
  signer,
  versionTime
}: {
  head: ResourceLogEntry
  nextLog: { method: string; scid: string }
  controller: ResourceLogController
  signer: ResourceLogSigner
  versionTime?: string
}): Promise<ResourceLogEntry> {
  const time = versionTime ?? new Date().toISOString()
  const ordinal = Number.parseInt(head.versionId, 10) + 1
  const parameters = { nextLog }
  const entryHash = await deriveHash({
    versionId: head.versionId,
    versionTime: time,
    parameters,
    state: head.state
  })
  const entry = {
    versionId: buildVersionId(ordinal, entryHash),
    versionTime: time,
    parameters,
    state: head.state
  }
  const proof = await signDataIntegrityProof(
    entry,
    createDataIntegrityProofTemplate({
      verificationMethod: versionedVm({
        controller,
        keyMultibase: signer.keyMultibase
      }),
      created: time
    }),
    signerFromExternalKey({
      publicKeyMultibase: signer.keyMultibase,
      sign: signer.sign
    })
  )
  return {
    ...entry,
    proof: [proof as ResourceLogEntry['proof'][number]]
  }
}
