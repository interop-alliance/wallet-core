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
 *
 * The document reading itself is not restated here: the relation resolver,
 * the ladder-VM recognition, and the credential class all come from
 * `document.ts` beside this file, so this view and every other reader of an
 * account document answer identically over the same bytes.
 */
import type { DIDLog, DIDLogEntry } from '@interop/did-method-webvh'
import {
  ResourceLogIntegrityError,
  type ResourceLogController
} from '@interop/vh-resource-log'
import {
  credentialKeyAgreementMethods,
  ladderVmMethods,
  resolvedRelationMethods,
  type AccountDocument
} from './document.js'
import {
  attributeLadderRungsPerVersion,
  entrySignerKeysOf,
  type LadderRungKeys
} from './ladderRungs.js'
import { assertLadderAppendLicensed } from './license.js'

/**
 * The credential-inventory view at one controller-log version, consumed by the
 * ceremony-tail license on ladder-signed appends (clause B of the ladder
 * VM's authority clauses). Both members come from the shared
 * account-document readers beside this file (`ladderVmMethods` and
 * `credentialKeyAgreementMethods` in `document.ts`), so the license reads the
 * document exactly as the client listing and the roster's recipient resolver
 * do. `ladderKeys` holds the ladder VMs' signing-key multibases, which is how
 * a verifier tells a ladder-signed proof from an enrolled client's.
 * `inventoryKeys` is S(V), the credential-inventory key set: the
 * credential-class `keyAgreement` methods keyed by their key material,
 * verbatim `Multikey` keys and `MultikeyCommitment` commitments alike, union
 * the ladder VMs. A document entry is inventory-changing iff S(V) differs
 * from S(V-1) in either direction; ordinary client enrollment and revocation
 * are excluded structurally, because a client's `keyAgreement` twin carries
 * the `did:key` controller marker rather than the account DID.
 *
 * Three members serve the license's third shape, which admits a ladder-signed
 * append at a version whose ENROLLED-CLIENT set changed and whose entry a rung
 * of the appending ladder signed. `enrolledClientKeys` is that set, the
 * version's `capabilityInvocation` key multibases -- the census the client
 * listing keys on, and the structural complement of `inventoryKeys`.
 * `entrySignerKeys` names the update keys that signed the version's own entry,
 * which is what tells a ladder-signed enrollment or removal from a
 * client-signed one. `ladderRungKeys` maps each attributed ladder VM to its
 * rung keys as the log itself names them, so the signer test is answered with
 * no ladder seed in hand; a ladder the log does not attribute is absent from
 * the map and its appends refuse (`ladderRungs.ts` states the walk's bounds).
 */
export interface ControllerInventory {
  ladderKeys: Set<string>
  inventoryKeys: Set<string>
  enrolledClientKeys: Set<string>
  entrySignerKeys: Set<string>
  ladderRungKeys: LadderRungKeys
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
 * Collects a document's `assertionMethod` key multibases, over the shared
 * relation reader (embedded verification methods verbatim, string references
 * resolved against `verificationMethod`).
 *
 * @param doc {AccountDocument}
 * @returns {Set<string>}
 */
function assertionKeysOf(doc: AccountDocument): Set<string> {
  const keys = new Set<string>()
  for (const method of resolvedRelationMethods({
    doc,
    relation: 'assertionMethod'
  })) {
    if (typeof method.publicKeyMultibase === 'string') {
      keys.add(method.publicKeyMultibase)
    }
  }
  return keys
}

/**
 * Collects a document's credential-inventory view (see
 * {@link ControllerInventory}) over the shared account-document readers, so
 * ladder recognition and the credential class have one definition here and in
 * every other reader: `ladderVmMethods` names the ladder VMs by relation
 * asymmetry, and `credentialKeyAgreementMethods` names the account-controlled
 * `keyAgreement` methods. S(V) is those methods' key material --
 * `publicKeyCommitment` where the entry is a commitment,
 * `publicKeyMultibase` where it is verbatim (the two value spaces are
 * disjoint) -- union the ladder keys. A `keyAgreement` method carrying
 * neither is skipped: an unidentifiable entry must not make two distinct
 * inventories compare equal.
 *
 * The enrolled-client set the license's third shape compares across versions
 * is read from the same document in the same pass: the `capabilityInvocation`
 * methods' key multibases. That relation is the client census by definition --
 * a ladder VM is absent from it by the recognition asymmetry, and a
 * credential's `keyAgreement` entry was never in it -- so the two sets this
 * function returns cannot overlap by construction.
 *
 * @param options {object}
 * @param options.doc {AccountDocument}
 * @param options.did {string}   the account DID inventory entries are
 *   controlled by
 * @param options.entry {DIDLogEntry}   the version's own log entry, read for
 *   the update keys that signed it
 * @returns {Omit<ControllerInventory, 'ladderRungKeys'>}
 */
function inventoryOf({
  doc,
  did,
  entry
}: {
  doc: AccountDocument
  did: string
  entry: DIDLogEntry
}): Omit<ControllerInventory, 'ladderRungKeys'> {
  const ladderKeys = new Set<string>()
  for (const method of ladderVmMethods({ doc })) {
    if (typeof method.publicKeyMultibase === 'string') {
      ladderKeys.add(method.publicKeyMultibase)
    }
  }
  const inventoryKeys = new Set(ladderKeys)
  for (const method of credentialKeyAgreementMethods({ doc, did })) {
    if (typeof method.publicKeyCommitment === 'string') {
      inventoryKeys.add(method.publicKeyCommitment)
    } else if (typeof method.publicKeyMultibase === 'string') {
      inventoryKeys.add(method.publicKeyMultibase)
    }
  }
  const enrolledClientKeys = new Set<string>()
  for (const method of resolvedRelationMethods({
    doc,
    relation: 'capabilityInvocation'
  })) {
    if (typeof method.publicKeyMultibase === 'string') {
      enrolledClientKeys.add(method.publicKeyMultibase)
    }
  }
  return {
    ladderKeys,
    inventoryKeys,
    enrolledClientKeys,
    entrySignerKeys: entrySignerKeysOf(entry)
  }
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
  const inventoryByVersion = new Map<
    string,
    Omit<ControllerInventory, 'ladderRungKeys'>
  >()
  const positionByVersion = new Map<string, number>()
  for (const [position, entry] of log.entries()) {
    const doc = entry.state as AccountDocument
    keysByVersion.set(entry.versionId, assertionKeysOf(doc))
    inventoryByVersion.set(entry.versionId, inventoryOf({ doc, did, entry }))
    positionByVersion.set(entry.versionId, position)
  }
  // The rung attribution hashes committed keys, so it cannot run in the sync
  // pass above. It is computed once on the first inventory read and shared by
  // every later one: the walk is a pure function of the log, and a log is read
  // fresh and never mutated in place.
  let rungSnapshots: Promise<LadderRungKeys[]> | undefined
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
    async inventoryAt(versionId?: string): Promise<ControllerInventory> {
      const resolvedVersionId =
        versionId === undefined ? head?.versionId : versionId
      const resolved =
        resolvedVersionId === undefined
          ? undefined
          : inventoryByVersion.get(resolvedVersionId)
      const position =
        resolvedVersionId === undefined
          ? undefined
          : positionByVersion.get(resolvedVersionId)
      if (!resolved || position === undefined) {
        throw versionRefusal(versionId)
      }
      rungSnapshots ??= attributeLadderRungsPerVersion(log)
      const snapshots = await rungSnapshots
      return {
        ...resolved,
        ladderRungKeys: snapshots[position] ?? new Map()
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
