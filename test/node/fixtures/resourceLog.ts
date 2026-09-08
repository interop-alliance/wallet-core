/**
 * Shared fixtures for the resource-log suites that stayed in wallet-core
 * after the generic client side moved to `@interop/vh-resource-log`. The
 * base fakes come from the library's `./testing` subpath (one reference
 * implementation of the ports, never re-derived); this file wraps its
 * `fakeController` into the wallet-core EXTENDED controller view -- the
 * per-version credential-inventory accessor plus the `admitAppend` hook
 * carrying the ceremony-tail license, exactly as `webvhResourceLogController`
 * supplies them, and carries a co-signing helper ported from the library
 * suite, for the multi-proof entries the per-entry ladder rule is about.
 */
import {
  createDataIntegrityProofTemplate,
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
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import type { CollectionEncryption } from '@interop/was-client'
import { logGovernedDescriptorStore } from '../../../src/keys/rosterLogStore.js'
import { makeRosterClient } from './rosterClient.js'
import {
  assertLadderAppendLicensed,
  type ControllerInventory,
  type ResourceLogClass,
  type LadderRungKeys,
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
 * do), the three members the license's third shape reads (`enrolledClientKeys`,
 * `entrySignerKeys`, and `ladderRungKeys`, a ladder VM multibase to its
 * attributed rung keys), and the `admitAppend` hook carrying the license,
 * mirroring `webvhResourceLogController`.
 *
 * @param options {object}
 * @param [options.did] {string}
 * @param options.versions {Array<{ versionId: string, keys: string[],
 *   ladderKeys?: string[], inventoryKeys?: string[],
 *   enrolledClientKeys?: string[], entrySignerKeys?: string[],
 *   ladderRungKeys?: Record<string, string[]> }>}
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
    enrolledClientKeys?: string[]
    entrySignerKeys?: string[]
    ladderRungKeys?: Record<string, string[]>
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
      const ladderRungKeys: LadderRungKeys = new Map()
      for (const [ladderKey, rungs] of Object.entries(
        version?.ladderRungKeys ?? {}
      )) {
        ladderRungKeys.set(ladderKey, new Set(rungs))
      }
      return {
        ladderKeys,
        inventoryKeys,
        enrolledClientKeys: new Set(version?.enrolledClientKeys ?? []),
        entrySignerKeys: new Set(version?.entrySignerKeys ?? []),
        ladderRungKeys
      }
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
 * An account whose document backs one enrolled client (alice) and one ladder
 * VM across two versions, the second of which changed nothing: a
 * ladder-signed append anchored at it is exactly the silent-rekey shape the
 * ceremony-tail license refuses.
 *
 * @returns {Promise<object>}   the two clients and the controller views
 *   before and after the unchanged edit
 */
export async function accountWithUnchangedEdit() {
  const alice = await makeRosterClient()
  const ladder = await makeRosterClient()
  const version = (versionId: string) => ({
    versionId,
    keys: [alice.signingKeyMultibase, ladder.signingKeyMultibase],
    ladderKeys: [ladder.signingKeyMultibase],
    inventoryKeys: ['credA']
  })
  return {
    alice,
    ladder,
    beforeEdit: fakeController({ versions: [version('1-v1')] }),
    unchangedEdit: fakeController({
      versions: [version('1-v1'), version('2-v2')]
    })
  }
}

/**
 * An epoch-configuration descriptor, the state type the governed store
 * writes into its log entries.
 *
 * @param currentEpoch {string}
 * @returns {CollectionEncryption}
 */
export function descriptorFor(currentEpoch: string): CollectionEncryption {
  return { scheme: 'edv', currentEpoch, epochs: [] }
}

/**
 * A ladder-signing log-governed store over a fresh in-memory log, plus the
 * mutable controller view it resolves and a second view carrying a later
 * document version. Version `1-v1` backs the ladder VM and the credential
 * `credA`; what `2-v2` carries as its inventory is the caller's, so the
 * second view is either an unchanged edit (the silent-rekey shape the
 * ceremony-tail license refuses) or an inventory-changing one.
 *
 * @param options {object}
 * @param options.logId {string}
 * @param options.logClass {ResourceLogClass}
 * @param options.editedInventoryKeys {string[]}   version `2-v2`'s inventory
 * @returns {Promise<object>}
 */
export async function ladderDescriptorStore({
  logId,
  logClass,
  editedInventoryKeys
}: {
  logId: string
  logClass: ResourceLogClass
  editedInventoryKeys: string[]
}) {
  const ladder = await makeRosterClient()
  const version = (versionId: string, inventoryKeys: string[]) => ({
    versionId,
    keys: [ladder.signingKeyMultibase],
    ladderKeys: [ladder.signingKeyMultibase],
    inventoryKeys
  })
  const controllerRef: { current: WebvhResourceLogController } = {
    current: fakeController({ versions: [version('1-v1', ['credA'])] })
  }
  const afterEdit = fakeController({
    versions: [version('1-v1', ['credA']), version('2-v2', editedInventoryKeys)]
  })
  const log = memoryLogStore()
  const store = logGovernedDescriptorStore({
    log,
    resolveController: async () => controllerRef.current,
    pinStore: memoryResourceLogPinStore(),
    logId,
    signer: ladder.logSigner,
    logClass
  })
  return { ladder, controllerRef, afterEdit, log, store }
}
