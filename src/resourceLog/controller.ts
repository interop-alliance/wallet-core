/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The controller-document view a resource-log verifier authorizes against:
 * the profile's root of authority, resolved and verified by the reader
 * independently of the host serving the log. The interface is the seam --
 * verification consumes only the account DID, the ordered controller-log
 * version list, per-version `assertionMethod` membership, and the
 * per-version credential-posture view the ceremony-tail license reads -- and
 * the
 * did:webvh adapter builds it from an already-verified account log (the
 * `verifyAccountLog` output), answering anchored-version lookups from that
 * verified history rather than from any wire fetch. Handing the verifier a
 * view instead of a resolver is what enforces the profile's rule that
 * controller-document material never comes from the channel the log came
 * from.
 */
import type { DIDLog } from '@interop/did-method-webvh'
import { ResourceLogIntegrityError } from './errors.js'

/**
 * The credential-posture view at one controller-log version, consumed by the
 * ceremony-tail license on ladder-signed appends (clause B of the ladder
 * VM's authority clauses). `ladderKeys` holds the ladder VMs' signing-key
 * multibases, recognized by relation asymmetry -- a `capabilityDelegation`
 * member absent from `capabilityInvocation` is the ladder VM -- and is how a
 * verifier tells a ladder-signed proof from an enrolled client's.
 * `postureKeys` is S(V), the credential-posture key set: the `keyAgreement`
 * methods whose `controller` is the account DID (the deliberately unmarked
 * credential entries -- verbatim `Multikey` keys and `MultikeyCommitment`
 * commitments alike, keyed by their key material), union the ladder VMs. A
 * document entry is posture-changing iff S(V) differs from S(V-1) in either
 * direction; ordinary client enrollment and revocation are excluded
 * structurally, because a client's `keyAgreement` twin carries the `did:key`
 * controller marker rather than the account DID.
 */
export interface ControllerPosture {
  ladderKeys: Set<string>
  postureKeys: Set<string>
}

/**
 * What log verification consumes of the independently verified controller
 * document: the DID the entry proofs must sign under, the verified controller
 * log's `versionId` list in order (empty for an unversioned static
 * controller, degrading every anchor rule to current-document verification),
 * the set of `assertionMethod` key multibases at a given version --
 * membership there is the whole authorization rule, so `keyAgreement`-only
 * recovery keys and `authentication`-only convenience keys are excluded
 * structurally -- and the credential-posture view at a given version, which
 * is what evaluating the ceremony-tail license and recognizing a
 * ladder-signed append require (both invisible through the
 * `assertionMethod` accessor alone).
 */
export interface ResourceLogController {
  did: string
  versionIds: string[]
  /**
   * Resolves the `assertionMethod` public-key multibases at a controller-log
   * version (`undefined`: the current document, the unversioned-controller
   * degradation).
   *
   * @param [versionId] {string}
   * @returns {Promise<Set<string>>}
   */
  assertionKeysAt(versionId?: string): Promise<Set<string>>
  /**
   * Resolves the credential-posture view at a controller-log version
   * (`undefined`: the current document): the ladder VM key multibases and
   * the posture set S(V) the ceremony-tail license compares across
   * versions.
   *
   * @param [versionId] {string}
   * @returns {Promise<ControllerPosture>}
   */
  postureAt(versionId?: string): Promise<ControllerPosture>
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
 * Collects a document's credential-posture view (see
 * {@link ControllerPosture}): the ladder VMs by relation asymmetry
 * (`capabilityDelegation` members absent from `capabilityInvocation`,
 * compared by verification-method id), and S(V) as the account-controlled
 * `keyAgreement` methods' key material -- `publicKeyCommitment` where the
 * entry is a commitment, `publicKeyMultibase` where it is verbatim (the two
 * value spaces are disjoint) -- union the ladder keys. A `keyAgreement`
 * method carrying neither is skipped: an unidentifiable entry must not make
 * two distinct postures compare equal.
 *
 * @param doc {ControllerDocument}
 * @param did {string}   the account DID posture entries are controlled by
 * @returns {ControllerPosture}
 */
function postureOf(doc: ControllerDocument, did: string): ControllerPosture {
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
  const postureKeys = new Set(ladderKeys)
  for (const entry of doc.keyAgreement ?? []) {
    const method = resolveMethod(entry, byId)
    if (!method || method.controller !== did) {
      continue
    }
    if (typeof method.publicKeyCommitment === 'string') {
      postureKeys.add(method.publicKeyCommitment)
    } else if (typeof method.publicKeyMultibase === 'string') {
      postureKeys.add(method.publicKeyMultibase)
    }
  }
  return { ladderKeys, postureKeys }
}

/**
 * Builds the controller view over an already-verified did:webvh account log
 * (the `verifyAccountLog` output -- callers never hand this a log they have
 * not verified against the account pointer). Because every verified entry
 * carries its resolved document in `state`, the per-version `assertionMethod`
 * sets are read straight off those entries in one linear pass over the log
 * rather than replaying resolution once per version. An anchored lookup at a
 * version the log does not carry refuses instead of guessing, and `undefined`
 * answers from the last entry (the current document).
 *
 * @param options {object}
 * @param options.did {string}   the account's did:webvh, as verified
 * @param options.log {DIDLog}   the verified account log
 * @returns {ResourceLogController}
 */
export function webvhResourceLogController({
  did,
  log
}: {
  did: string
  log: DIDLog
}): ResourceLogController {
  const versionIds = log.map(entry => entry.versionId)
  const keysByVersion = new Map<string, Set<string>>()
  const postureByVersion = new Map<string, ControllerPosture>()
  for (const entry of log) {
    const doc = entry.state as ControllerDocument
    keysByVersion.set(entry.versionId, assertionKeysOf(doc))
    postureByVersion.set(entry.versionId, postureOf(doc, did))
  }
  const head = log.length === 0 ? undefined : log[log.length - 1]
  function versionRefusal(versionId?: string): ResourceLogIntegrityError {
    return new ResourceLogIntegrityError(
      `The controller document did not resolve at version ` +
        `"${versionId ?? '<head>'}" (no document returned).`
    )
  }
  return {
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
    postureAt(versionId?: string): Promise<ControllerPosture> {
      const resolved =
        versionId === undefined
          ? head && postureByVersion.get(head.versionId)
          : postureByVersion.get(versionId)
      if (!resolved) {
        return Promise.reject(versionRefusal(versionId))
      }
      return Promise.resolve(resolved)
    }
  }
}
