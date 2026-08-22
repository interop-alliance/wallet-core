/**
 * Shared fixtures for the resource-log adversarial suites: a fake
 * `ResourceLogController` (the seam makes did:webvh resolution unnecessary --
 * verification consumes only the DID, the ordered version list, and
 * per-version assertionMethod membership), an in-memory `ResourceLogStore`
 * modeling the transport contract (etag counter, `PreconditionFailedError` on
 * a stale validator or a lost guarded create) with a control seam for
 * simulating a tampering host, and a terminal handover-entry builder (nothing
 * in `src/` emits terminal entries yet, so the suite constructs them from the
 * kernel primitives directly).
 */
import {
  buildVersionId,
  createDataIntegrityProofTemplate,
  deriveHash,
  signDataIntegrityProof,
  signerFromExternalKey
} from '@interop/did-method-webvh'
import { PreconditionFailedError } from '@interop/was-client'
import type {
  ResourceLogEntry,
  ResourceLogStore
} from '@interop/was-client/log'
import type {
  ResourceLogController,
  ResourceLogSigner
} from '../../../src/resourceLog/index.js'

/**
 * The account DID the fake controller answers for.
 */
export const CONTROLLER_DID = 'did:webvh:QmScid:example.com:space:abc:id'

/**
 * A fake `ResourceLogController`: an ordered controller-log version list with
 * per-version `assertionMethod` key-multibase sets, plus the optional
 * per-version inventory view the ceremony-tail license reads (`ladderKeys`,
 * the ladder VM multibases, and `inventoryKeys`, the S(V) member set --
 * both default empty, and ladder keys always count into the inventory set as
 * the real adapter's do). An empty `versions` list models an unversioned
 * static controller; `currentKeys` then supplies the current-document set
 * (for a versioned controller the last version is the current document).
 *
 * @param options {object}
 * @param [options.did] {string}
 * @param options.versions {Array<{ versionId: string, keys: string[],
 *   ladderKeys?: string[], inventoryKeys?: string[] }>}
 * @param [options.currentKeys] {string[]}   unversioned controllers only
 * @returns {ResourceLogController}
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
}): ResourceLogController {
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
  return {
    did,
    versionIds: versions.map(version => version.versionId),
    async assertionKeysAt(versionId?: string): Promise<Set<string>> {
      if (versionId === undefined && versions.length === 0) {
        return new Set(currentKeys ?? [])
      }
      return new Set(versionAt(versionId)?.keys ?? [])
    },
    async inventoryAt(versionId?: string) {
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
    }
  }
}

/**
 * An in-memory `ResourceLogStore` with a monotonic version counter as the
 * compare-and-swap etag, plus control seams so tests can play a tampering or
 * replaying host (`_setEntries`) and a backend that versions nothing
 * (`_withholdEtag`).
 *
 * @returns {ResourceLogStore & object}
 */
export function memoryLogStore(): ResourceLogStore & {
  _getEntries(): ResourceLogEntry[] | null
  _setEntries(entries: ResourceLogEntry[] | null): void
  _withholdEtag(withhold: boolean): void
} {
  let entries: ResourceLogEntry[] | null = null
  let version = 0
  let withholdEtag = false
  return {
    async read() {
      if (entries === null) {
        return null
      }
      return withholdEtag
        ? { entries: structuredClone(entries) }
        : { entries: structuredClone(entries), etag: `v${version}` }
    },
    async append(entry, { ifMatch }: { ifMatch: string }) {
      if (entries === null || ifMatch !== `v${version}`) {
        throw new PreconditionFailedError('stale log etag')
      }
      entries = [...entries, structuredClone(entry)]
      version++
    },
    async create(entry) {
      if (entries !== null) {
        throw new PreconditionFailedError('log already exists')
      }
      entries = [structuredClone(entry)]
      version++
    },
    _getEntries() {
      return entries ? structuredClone(entries) : null
    },
    _setEntries(next) {
      entries = next ? structuredClone(next) : null
      version++
    },
    _withholdEtag(withhold: boolean) {
      withholdEtag = withhold
    }
  }
}

/**
 * The writer's anchored verification-method DID URL, exactly as the entry
 * builders construct it: the anchor is the controller's verified head (omitted
 * for an unversioned controller).
 *
 * @param options {object}
 * @param options.controller {ResourceLogController}
 * @param options.keyMultibase {string}
 * @returns {string}
 */
export function anchoredVm({
  controller,
  keyMultibase
}: {
  controller: ResourceLogController
  keyMultibase: string
}): string {
  const anchor = controller.versionIds[controller.versionIds.length - 1]
  const query = anchor === undefined ? '' : `?versionId=${anchor}`
  return `${controller.did}${query}#${keyMultibase}`
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
      verificationMethod: anchoredVm({
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
