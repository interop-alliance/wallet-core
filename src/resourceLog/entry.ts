/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Resource-log entry construction: the two-pass SCID genesis build and the
 * ordinary next-entry build, both signed under the writer's enrolled Ed25519
 * key with the entry anchor riding as a `versionId` DID parameter on the
 * proof's `verificationMethod` -- the writer anchors at the head of the
 * controller document as it last verified it. All hashing and proof
 * construction comes from the did:webvh log kernel; nothing is re-derived
 * here.
 */
import {
  buildVersionId,
  createDataIntegrityProofTemplate,
  deriveHash,
  parseAndValidateVersionId,
  SCID_PLACEHOLDER,
  signDataIntegrityProof,
  signerFromExternalKey
} from '@interop/did-method-webvh'
import type { ResourceLogEntry } from '@interop/was-client/log'
import type { ResourceLogController } from './controller.js'

/**
 * The writer's signing seam: its enrolled Ed25519 signing key's multibase
 * (the fragment of its verification method in the controller document) and a
 * raw detached-signature hook over it. The multibase names the key in the
 * proof's `verificationMethod`; membership under `assertionMethod` at the
 * anchored version is what authorizes the append.
 */
export interface ResourceLogSigner {
  keyMultibase: string
  sign(input: { data: Uint8Array }): Promise<Uint8Array>
}

/**
 * The writer's anchored verification-method DID URL: the controller DID, the
 * anchor at the controller's verified head as a `versionId` DID parameter
 * (omitted for an unversioned controller), and the signing key's multibase as
 * the fragment.
 *
 * @param options {object}
 * @param options.controller {ResourceLogController}
 * @param options.keyMultibase {string}
 * @returns {string}
 */
function anchoredVerificationMethod({
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
 * Refuses a state document the profile forbids in an entry: one without a
 * `type` schema identifier, or one carrying the projection-only `history`
 * member.
 *
 * @param state {ResourceLogEntry['state']}
 */
function checkState(state: ResourceLogEntry['state']): void {
  if (typeof (state as { type?: unknown }).type !== 'string') {
    throw new Error(
      'A resource log entry state must carry a type schema identifier.'
    )
  }
  if ('history' in state) {
    throw new Error(
      'A resource log entry state must not carry a history member (it ' +
        'belongs to the point-state projection only).'
    )
  }
}

/**
 * Signs a fully version-identified entry under the profile's fixed proof
 * shape.
 *
 * @param options {object}
 * @param options.entry {object}   the entry, `proof` absent
 * @param options.signer {ResourceLogSigner}
 * @param options.verificationMethod {string}   the anchored DID URL
 * @param options.created {string}   the proof timestamp
 * @returns {Promise<ResourceLogEntry>}
 */
async function signEntry({
  entry,
  signer,
  verificationMethod,
  created
}: {
  entry: Omit<ResourceLogEntry, 'proof'>
  signer: ResourceLogSigner
  verificationMethod: string
  created: string
}): Promise<ResourceLogEntry> {
  const proofTemplate = createDataIntegrityProofTemplate({
    verificationMethod,
    created
  })
  const proof = await signDataIntegrityProof(
    entry,
    proofTemplate,
    signerFromExternalKey({
      publicKeyMultibase: signer.keyMultibase,
      sign: signer.sign
    })
  )
  // The kernel's proof type keeps proofPurpose as the full union; the
  // template fixed it to the profile's assertionMethod shape.
  return { ...entry, proof: [proof as ResourceLogEntry['proof'][number]] }
}

/**
 * Builds and signs a genesis entry by the profile's two-pass SCID procedure:
 * the preliminary entry carries the `{SCID}` placeholder as `versionId` and
 * `parameters.scid`, its hash is the SCID, and the final entry substitutes it
 * back in before the ordinary entry hash is computed (`versionId` input
 * value: the SCID).
 *
 * @param options {object}
 * @param options.state {ResourceLogEntry['state']}   the full initial state
 *   (with its `type`)
 * @param options.method {string}   the format identifier
 *   (`WAS_RESOURCE_LOG_METHOD`)
 * @param options.controller {ResourceLogController}   the verified controller
 *   view -- the anchor source
 * @param options.signer {ResourceLogSigner}
 * @param [options.previousLog] {object}   handover successors only: the prior
 *   log's SCID and the `versionId` of its terminal entry's predecessor
 * @param [options.versionTime] {string}   RFC3339 UTC; defaults to now
 * @returns {Promise<ResourceLogEntry>}
 */
export async function buildResourceLogGenesis({
  state,
  method,
  controller,
  signer,
  previousLog,
  versionTime
}: {
  state: ResourceLogEntry['state']
  method: string
  controller: ResourceLogController
  signer: ResourceLogSigner
  previousLog?: { scid: string; head: string }
  versionTime?: string
}): Promise<ResourceLogEntry> {
  checkState(state)
  const time = versionTime ?? new Date().toISOString()
  const parametersOf = (scid: string) => ({
    method,
    scid,
    ...(previousLog === undefined ? {} : { previousLog })
  })
  const scid = await deriveHash({
    versionId: SCID_PLACEHOLDER,
    versionTime: time,
    parameters: parametersOf(SCID_PLACEHOLDER),
    state
  })
  const parameters = parametersOf(scid)
  const entryHash = await deriveHash({
    versionId: scid,
    versionTime: time,
    parameters,
    state
  })
  return signEntry({
    entry: {
      versionId: buildVersionId(1, entryHash),
      versionTime: time,
      parameters,
      state
    },
    signer,
    verificationMethod: anchoredVerificationMethod({
      controller,
      keyMultibase: signer.keyMultibase
    }),
    created: time
  })
}

/**
 * Builds and signs the next ordinary entry against a verified head: full
 * state, empty `parameters`, hash chained off the head's `versionId`, proof
 * anchored at the controller's verified head. Callers hold a verified head
 * by construction (an entry is never built on an unverified one).
 *
 * @param options {object}
 * @param options.head {ResourceLogEntry}   the verified head entry
 * @param options.state {ResourceLogEntry['state']}   the full next state
 * @param options.controller {ResourceLogController}
 * @param options.signer {ResourceLogSigner}
 * @param [options.versionTime] {string}   RFC3339 UTC; defaults to now
 * @returns {Promise<ResourceLogEntry>}
 */
export async function buildResourceLogEntry({
  head,
  state,
  controller,
  signer,
  versionTime
}: {
  head: ResourceLogEntry
  state: ResourceLogEntry['state']
  controller: ResourceLogController
  signer: ResourceLogSigner
  versionTime?: string
}): Promise<ResourceLogEntry> {
  checkState(state)
  const time = versionTime ?? new Date().toISOString()
  const headOrdinal = Number.parseInt(head.versionId, 10)
  const ordinal = headOrdinal + 1
  parseAndValidateVersionId(head.versionId, headOrdinal)
  const entryHash = await deriveHash({
    versionId: head.versionId,
    versionTime: time,
    parameters: {},
    state
  })
  return signEntry({
    entry: {
      versionId: buildVersionId(ordinal, entryHash),
      versionTime: time,
      parameters: {},
      state
    },
    signer,
    verificationMethod: anchoredVerificationMethod({
      controller,
      keyMultibase: signer.keyMultibase
    }),
    created: time
  })
}
