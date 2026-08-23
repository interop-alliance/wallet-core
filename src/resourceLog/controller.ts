/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The did:webvh side of `@interop/vh-resource-log`'s controller port: the
 * wallet-core EXTENDED controller view -- the library's generic port plus the
 * per-version credential-inventory accessor the ceremony-tail license reads,
 * plus the library's `admitAppend` admission hook made mandatory and
 * carrying that license -- and the adapter that builds it from an
 * already-verified account log (the `verifyAccountLog` output), answering
 * version lookups from that verified history rather than from any wire
 * fetch. Handing the verifier a view instead of a resolver is what
 * enforces the profile's rule that controller-document material never comes
 * from the channel the log came from; supplying the hook is the obligation
 * the library's port states for any controller document that can list
 * ladder-shaped verification methods -- a bare view does not lack ladder
 * keys, it lacks the ability to recognize them.
 */
import type { DIDLog } from '@interop/did-method-webvh'
import {
  ResourceLogIntegrityError,
  type ResourceLogController
} from '@interop/vh-resource-log'
import { assertLadderAppendLicensed } from './license.js'

/**
 * The credential-inventory view at one controller-log version, consumed by the
 * ceremony-tail license on ladder-signed appends (clause B of the ladder
 * VM's authority clauses). `ladderKeys` holds the ladder VMs' signing-key
 * multibases, recognized by relation asymmetry -- a `capabilityDelegation`
 * member absent from `capabilityInvocation` is the ladder VM -- and is how a
 * verifier tells a ladder-signed proof from an enrolled client's.
 * `inventoryKeys` is S(V), the credential-inventory key set: the `keyAgreement`
 * methods whose `controller` is the account DID (the deliberately unmarked
 * credential entries -- verbatim `Multikey` keys and `MultikeyCommitment`
 * commitments alike, keyed by their key material), union the ladder VMs. A
 * document entry is inventory-changing iff S(V) differs from S(V-1) in either
 * direction; ordinary client enrollment and revocation are excluded
 * structurally, because a client's `keyAgreement` twin carries the `did:key`
 * controller marker rather than the account DID.
 */
export interface ControllerInventory {
  ladderKeys: Set<string>
  inventoryKeys: Set<string>
}

/**
 * The wallet-core extended controller view: the library's generic port plus
 * the credential-inventory accessor at a given version, which is what
 * evaluating the ceremony-tail license and recognizing a ladder-signed
 * append require (both invisible through the `assertionMethod` accessor
 * alone), plus the library's optional `admitAppend` admission hook made
 * mandatory -- an account did:webvh document can list ladder VMs, so a view
 * over one must carry the license (the port's stated obligation). The
 * pre-append license check in the log-governed descriptor store calls
 * `inventoryAt` directly, which is why the accessor stays on the type
 * beside the hook: a verify-time refusal alone would poison the served log
 * for every reader.
 */
export interface WebvhResourceLogController extends ResourceLogController {
  /**
   * Resolves the credential-inventory view at a controller-log version
   * (`undefined`: the current document): the ladder VM key multibases and
   * the inventory set S(V) the ceremony-tail license compares across
   * versions.
   *
   * @param [versionId] {string}
   * @returns {Promise<ControllerInventory>}
   */
  inventoryAt(versionId?: string): Promise<ControllerInventory>
  admitAppend: NonNullable<ResourceLogController['admitAppend']>
}

/**
 * The verification-method subset the controller view reads.
 */
interface ControllerVerificationMethod {
  id?: string
  controller?: string
  publicKeyMultibase?: string
  publicKeyCommitment?: string
}

/**
 * The subset of a resolved DID document the controller view reads: the
 * relations as id references or embedded methods, resolved against
 * `verificationMethod`.
 */
interface ControllerDocument {
  assertionMethod?: Array<string | ControllerVerificationMethod>
  keyAgreement?: Array<string | ControllerVerificationMethod>
  capabilityInvocation?: Array<string | ControllerVerificationMethod>
  capabilityDelegation?: Array<string | ControllerVerificationMethod>
  verificationMethod?: ControllerVerificationMethod[]
}

/**
 * Resolves one relation entry: an embedded verification method verbatim, a
 * string reference through the given `verificationMethod` index.
 *
 * @param entry {string | ControllerVerificationMethod}
 * @param byId {Map<string, ControllerVerificationMethod>}
 * @returns {ControllerVerificationMethod | undefined}
 */
function resolveMethod(
  entry: string | ControllerVerificationMethod,
  byId: Map<string, ControllerVerificationMethod>
): ControllerVerificationMethod | undefined {
  return typeof entry === 'string' ? byId.get(entry) : entry
}

/**
 * Indexes a document's `verificationMethod` array by id.
 *
 * @param doc {ControllerDocument}
 * @returns {Map<string, ControllerVerificationMethod>}
 */
function methodsById(
  doc: ControllerDocument
): Map<string, ControllerVerificationMethod> {
  const byId = new Map<string, ControllerVerificationMethod>()
  for (const method of doc.verificationMethod ?? []) {
    if (typeof method?.id === 'string') {
      byId.set(method.id, method)
    }
  }
  return byId
}

/**
 * A relation entry's verification-method id: the string reference itself, or
 * an embedded method's `id`.
 *
 * @param entry {string | ControllerVerificationMethod}
 * @returns {string | undefined}
 */
function relationIdOf(
  entry: string | ControllerVerificationMethod
): string | undefined {
  return typeof entry === 'string' ? entry : entry?.id
}

/**
 * Collects a document's `assertionMethod` key multibases: embedded
 * verification methods verbatim, string references resolved against
 * `verificationMethod`.
 *
 * @param doc {ControllerDocument}
 * @returns {Set<string>}
 */
function assertionKeysOf(doc: ControllerDocument): Set<string> {
  const byId = methodsById(doc)
  const keys = new Set<string>()
  for (const entry of doc.assertionMethod ?? []) {
    const method = resolveMethod(entry, byId)
    if (method && typeof method.publicKeyMultibase === 'string') {
      keys.add(method.publicKeyMultibase)
    }
  }
  return keys
}

/**
 * Collects a document's credential-inventory view (see
 * {@link ControllerInventory}): the ladder VMs by relation asymmetry
 * (`capabilityDelegation` members absent from `capabilityInvocation`,
 * compared by verification-method id), and S(V) as the account-controlled
 * `keyAgreement` methods' key material -- `publicKeyCommitment` where the
 * entry is a commitment, `publicKeyMultibase` where it is verbatim (the two
 * value spaces are disjoint) -- union the ladder keys. A `keyAgreement`
 * method carrying neither is skipped: an unidentifiable entry must not make
 * two distinct inventories compare equal.
 *
 * @param doc {ControllerDocument}
 * @param did {string}   the account DID inventory entries are controlled by
 * @returns {ControllerInventory}
 */
function inventoryOf(
  doc: ControllerDocument,
  did: string
): ControllerInventory {
  const byId = methodsById(doc)
  const invocable = new Set<string>()
  for (const entry of doc.capabilityInvocation ?? []) {
    const id = relationIdOf(entry)
    if (id !== undefined) {
      invocable.add(id)
    }
  }
  const ladderKeys = new Set<string>()
  for (const entry of doc.capabilityDelegation ?? []) {
    const id = relationIdOf(entry)
    if (id !== undefined && invocable.has(id)) {
      continue
    }
    const method = resolveMethod(entry, byId)
    if (method && typeof method.publicKeyMultibase === 'string') {
      ladderKeys.add(method.publicKeyMultibase)
    }
  }
  const inventoryKeys = new Set(ladderKeys)
  for (const entry of doc.keyAgreement ?? []) {
    const method = resolveMethod(entry, byId)
    if (!method || method.controller !== did) {
      continue
    }
    if (typeof method.publicKeyCommitment === 'string') {
      inventoryKeys.add(method.publicKeyCommitment)
    } else if (typeof method.publicKeyMultibase === 'string') {
      inventoryKeys.add(method.publicKeyMultibase)
    }
  }
  return { ladderKeys, inventoryKeys }
}

/**
 * Builds the controller view over an already-verified did:webvh account log
 * (the `verifyAccountLog` output -- callers never hand this a log they have
 * not verified against the account pointer). Because every verified entry
 * carries its resolved document in `state`, the per-version `assertionMethod`
 * sets are read straight off those entries in one linear pass over the log
 * rather than replaying resolution once per version. A lookup at a version
 * the log does not carry refuses instead of guessing, and `undefined`
 * answers from the last entry (the current document).
 *
 * The returned view carries the `admitAppend` hook: it resolves the
 * inventory at the proof's controller versionId, and where the signing key
 * is a ladder VM there it runs the ceremony-tail license
 * (`assertLadderAppendLicensed`) --
 * so ordinary client-signed appends admit untouched, and a ladder-signed
 * append outside the license refuses with `ResourceLogLicenseError`,
 * propagated with its class intact by the library's verifier.
 *
 * @param options {object}
 * @param options.did {string}   the account's did:webvh, as verified
 * @param options.log {DIDLog}   the verified account log
 * @returns {WebvhResourceLogController}
 */
export function webvhResourceLogController({
  did,
  log
}: {
  did: string
  log: DIDLog
}): WebvhResourceLogController {
  const versionIds = log.map(entry => entry.versionId)
  const keysByVersion = new Map<string, Set<string>>()
  const inventoryByVersion = new Map<string, ControllerInventory>()
  for (const entry of log) {
    const doc = entry.state as ControllerDocument
    keysByVersion.set(entry.versionId, assertionKeysOf(doc))
    inventoryByVersion.set(entry.versionId, inventoryOf(doc, did))
  }
  const head = log.length === 0 ? undefined : log[log.length - 1]
  function versionRefusal(versionId?: string): ResourceLogIntegrityError {
    return new ResourceLogIntegrityError(
      `The controller document did not resolve at version ` +
        `"${versionId ?? '<head>'}" (no document returned).`
    )
  }
  const view: WebvhResourceLogController = {
    did,
    versionIds,
    assertionKeysAt(versionId?: string): Promise<Set<string>> {
      const resolved =
        versionId === undefined
          ? head && keysByVersion.get(head.versionId)
          : keysByVersion.get(versionId)
      if (!resolved) {
        return Promise.reject(versionRefusal(versionId))
      }
      return Promise.resolve(resolved)
    },
    inventoryAt(versionId?: string): Promise<ControllerInventory> {
      const resolved =
        versionId === undefined
          ? head && inventoryByVersion.get(head.versionId)
          : inventoryByVersion.get(versionId)
      if (!resolved) {
        return Promise.reject(versionRefusal(versionId))
      }
      return Promise.resolve(resolved)
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
