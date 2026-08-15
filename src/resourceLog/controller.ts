/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The controller-document view a resource-log verifier authorizes against:
 * the profile's root of authority, resolved and verified by the reader
 * independently of the host serving the log. The interface is the seam --
 * verification consumes only the account DID, the ordered controller-log
 * version list, and per-version `assertionMethod` membership -- and the
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
 * What log verification consumes of the independently verified controller
 * document: the DID the entry proofs must sign under, the verified controller
 * log's `versionId` list in order (empty for an unversioned static
 * controller, degrading every anchor rule to current-document verification),
 * and the set of `assertionMethod` key multibases at a given version --
 * membership there is the whole authorization rule, so `keyAgreement`-only
 * recovery keys and `authentication`-only convenience keys are excluded
 * structurally.
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
}

/**
 * The subset of a resolved DID document assertion-key extraction reads.
 */
interface AssertionDocument {
  assertionMethod?: Array<string | { id?: string; publicKeyMultibase?: string }>
  verificationMethod?: Array<{ id?: string; publicKeyMultibase?: string }>
}

/**
 * Collects a document's `assertionMethod` key multibases: embedded
 * verification methods verbatim, string references resolved against
 * `verificationMethod`.
 *
 * @param doc {AssertionDocument}
 * @returns {Set<string>}
 */
function assertionKeysOf(doc: AssertionDocument): Set<string> {
  const byId = new Map<string, { publicKeyMultibase?: string }>()
  for (const method of doc.verificationMethod ?? []) {
    if (typeof method?.id === 'string') {
      byId.set(method.id, method)
    }
  }
  const keys = new Set<string>()
  for (const entry of doc.assertionMethod ?? []) {
    const method = typeof entry === 'string' ? byId.get(entry) : entry
    if (method && typeof method.publicKeyMultibase === 'string') {
      keys.add(method.publicKeyMultibase)
    }
  }
  return keys
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
  for (const entry of log) {
    keysByVersion.set(
      entry.versionId,
      assertionKeysOf(entry.state as AssertionDocument)
    )
  }
  const head = log.length === 0 ? undefined : log[log.length - 1]
  return {
    did,
    versionIds,
    assertionKeysAt(versionId?: string): Promise<Set<string>> {
      const resolved =
        versionId === undefined
          ? head && keysByVersion.get(head.versionId)
          : keysByVersion.get(versionId)
      if (!resolved) {
        return Promise.reject(
          new ResourceLogIntegrityError(
            `The controller document did not resolve at version ` +
              `"${versionId ?? '<head>'}" (no document returned).`
          )
        )
      }
      return Promise.resolve(resolved)
    }
  }
}
