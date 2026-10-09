/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The proof check a recorded grant passes before the wallet renews it under
 * the account's authority: whether the grant's delegation proof was signed
 * by a key the locally verified account document lists now, with the
 * signature verified over the capability rather than the signer's name
 * matched alone.
 *
 * The check exists because only the host can plant a directory entry, and a
 * host colluding with a withdrawn party that kept the directory's
 * blinded-index key can write an agent entry at a valid id carrying forged
 * grants whose proofs name a current key. A renewal pass that matched the
 * proof's `verificationMethod` against the document and verified no
 * signature would then sign real account delegations for the planted party.
 *
 * Two arms, by how the grant was delegated. A grant delegated straight under
 * the Space root is signed by an enrolled client's key or a ladder VM, and
 * its own proof is verified: the signer must stand under
 * `capabilityDelegation` in the current document, and the signature must
 * verify over the capability under that key. A grant a transient session
 * minted chains under the generation delegation embedded as the last link
 * of its `proof.capabilityChain`, and the parent is what is verified: it
 * must be delegated to an annex DID in the account's auxiliary Space (the
 * Space the account's delegated-clients pointer names, compared by host and
 * Space id, so a grant minted under a generation a later GC collected still
 * passes), and its own proof must verify under a key or ladder VM the
 * current document lists. The leaf's per-visit annex VM is not verified:
 * once its generation is collected its method is gone, and the account
 * document never listed it.
 */
import { DataIntegrityProof } from '@interop/data-integrity-proof'
import { createVerifyCryptosuite } from '@interop/ed25519-signature/eddsa-jcs-2022'
import {
  memberKeyMultibase,
  relationKeyMultibases,
  relationMemberNamed,
  vmFragmentOf
} from '@interop/vh-resource-log'
import type { IZcap } from '@interop/data-integrity-core'
import type { ConnectionZcap } from './entry.js'
import {
  embeddedParentCapability,
  firstDelegationProof
} from '../webvh/index.js'
import type { PublishedKeyDocument } from '../webvh/index.js'
import { parseClientAnnexDid } from '../webvh/clientAnnexDid.js'

/**
 * Why a recorded grant's proof does not verify as this account's. On the
 * root arm the reasons describe the grant's own proof; on the annex arm they
 * describe the embedded parent's, since that is the proof verified there.
 *
 * - `unsigned` -- the proof is absent or names no `verificationMethod`.
 * - `unsupported-suite` -- the proof is not an `eddsa-jcs-2022`
 *   `DataIntegrityProof` for `capabilityDelegation`, the one suite every
 *   delegation this library mints carries.
 * - `signer-unlisted` -- the proof's `verificationMethod` dereferences to no
 *   `capabilityDelegation` member of the current document that publishes a
 *   key (`relationMemberNamed`, then `memberKeyMultibase`: the fragment is an
 *   opaque selector, never read as the key), and it is not the did:key form
 *   of a key the relation publishes: the current-key-set rule.
 * - `signature-invalid` -- the signer is listed, and the signature does not
 *   verify over the capability under the key the document publishes for it.
 * - `parent-not-annex` -- the grant embeds a parent whose `controller` is
 *   not an annex DID in the account's auxiliary Space, or the account points
 *   at no annex generation.
 */
export type GrantProofRefusal =
  | 'unsigned'
  | 'unsupported-suite'
  | 'signer-unlisted'
  | 'signature-invalid'
  | 'parent-not-annex'

/**
 * The outcome of {@link verifyRecordedGrantProof}: verified, with the id of
 * the verification method whose signature was checked (the grant's own
 * signer on the root arm, the parent's on the annex arm), or refused with
 * the reason.
 */
export type GrantProofResult =
  | { verified: true; signerKeyId: string }
  | { verified: false; reason: GrantProofRefusal }

/**
 * The suite every delegation proof this library mints carries, and the one
 * this check verifies.
 */
const DELEGATION_PROOF_SHAPE = {
  type: 'DataIntegrityProof',
  cryptosuite: 'eddsa-jcs-2022',
  proofPurpose: 'capabilityDelegation'
} as const

/**
 * Verifies one capability's delegation proof against the current document:
 * the signer must stand under `capabilityDelegation`, and the signature must
 * verify over the capability under that key. The key material is what the
 * document publishes for the signer, so no resolver is consulted. A proof
 * naming a `capabilityDelegation` member of the document (`${did}#${fragment}`
 * dereferenced through the library's `relationMemberNamed`) verifies under
 * that member's `publicKeyMultibase`; the fragment is an opaque selector and
 * is never read as the key, the rule the library's own log verifier applies.
 * A proof naming the did:key form of a key (`did:key:<key>#<key>`, the form a
 * client signs under) verifies under that key when the relation publishes it.
 * A proof set is read by its first proof, as every other reader of a
 * delegation does.
 *
 * @param options {object}
 * @param options.zcap {IZcap}   the capability, proof included
 * @param options.doc {PublishedKeyDocument}   the locally verified account
 *   document
 * @returns {Promise<GrantProofResult>}
 */
async function verifyDelegationProof({
  zcap,
  doc
}: {
  zcap: IZcap
  doc: PublishedKeyDocument
}): Promise<GrantProofResult> {
  const { proof: _proof, ...document } = zcap as { proof?: unknown }
  const single = firstDelegationProof(zcap)
  if (single === undefined || typeof single.verificationMethod !== 'string') {
    return { verified: false, reason: 'unsigned' }
  }
  if (
    single.type !== DELEGATION_PROOF_SHAPE.type ||
    single.cryptosuite !== DELEGATION_PROOF_SHAPE.cryptosuite ||
    single.proofPurpose !== DELEGATION_PROOF_SHAPE.proofPurpose
  ) {
    return { verified: false, reason: 'unsupported-suite' }
  }
  const signerKeyId = single.verificationMethod
  const keyMultibase = listedSignerKey({ doc, signerKeyId })
  if (keyMultibase === undefined) {
    return { verified: false, reason: 'signer-unlisted' }
  }
  const suite = new DataIntegrityProof({
    cryptosuite: createVerifyCryptosuite()
  })
  // The suite's verify step edits the document's `@context` in place and
  // the proof's copy is read beside it, so both are handed over as copies.
  const result = await suite.verifyProof({
    proof: structuredClone(single),
    document: structuredClone(document),
    documentLoader: async (url: string) => {
      if (url !== signerKeyId) {
        throw new Error(`No document is served for "${url}".`)
      }
      return {
        documentUrl: url,
        document: {
          id: signerKeyId,
          type: 'Multikey',
          controller: signerKeyId.slice(0, signerKeyId.indexOf('#')),
          publicKeyMultibase: keyMultibase
        }
      }
    }
  })
  if (!result.verified) {
    return { verified: false, reason: 'signature-invalid' }
  }
  return { verified: true, signerKeyId }
}

/**
 * The key the document publishes under `capabilityDelegation` for a proof's
 * `verificationMethod` DID URL, or `undefined` when the URL names no listed
 * key. A URL under the document's DID dereferences to the member it names
 * and takes that member's published key. A did:key URL carries its key in
 * the DID itself and must name a key the relation publishes.
 *
 * @param options {object}
 * @param options.doc {PublishedKeyDocument}
 * @param options.signerKeyId {string}   the proof's `verificationMethod`
 * @returns {string | undefined}
 */
function listedSignerKey({
  doc,
  signerKeyId
}: {
  doc: PublishedKeyDocument
  signerKeyId: string
}): string | undefined {
  const hash = signerKeyId.indexOf('#')
  const fragment = vmFragmentOf(signerKeyId)
  if (hash === -1 || fragment === undefined) {
    return undefined
  }
  const did = signerKeyId.slice(0, hash)
  const relation = 'capabilityDelegation'
  const member = relationMemberNamed({ doc, relation, did, fragment })
  if (member !== undefined) {
    return memberKeyMultibase(member)
  }
  if (
    did === `did:key:${fragment}` &&
    relationKeyMultibases({ doc, relation }).has(fragment)
  ) {
    return fragment
  }
  return undefined
}

/**
 * Whether two annex DIDs name the same auxiliary Space: the same host and
 * the same Space id, whatever their generations. A string that is not an
 * annex DID names no Space.
 *
 * @param options {object}
 * @param options.did {string}
 * @param options.other {string}
 * @returns {boolean}
 */
function sameAuxiliarySpace({
  did,
  other
}: {
  did: string
  other: string
}): boolean {
  const parts = parseClientAnnexDid(did)
  const otherParts = parseClientAnnexDid(other)
  return (
    parts !== undefined &&
    otherParts !== undefined &&
    parts.host === otherParts.host &&
    parts.spaceId === otherParts.spaceId
  )
}

/**
 * Whether a recorded grant's delegation proof verifies as this account's,
 * against the locally verified account document. A grant with no embedded
 * parent is verified by its own proof (the root arm); a grant embedding its
 * parent delegation as the last link of its `proof.capabilityChain` is
 * verified by that parent's proof, after the parent's `controller` is found
 * to be an annex DID in the account's auxiliary Space (the annex arm). A
 * refusal says why. The check reads the current document alone, with no log
 * history and no network.
 *
 * @param options {object}
 * @param options.zcap {ConnectionZcap}   the recorded capability, verbatim
 * @param options.signerCheck {object}   what the grant is read against
 * @param options.signerCheck.doc {PublishedKeyDocument}   the locally
 *   verified account document
 * @param [options.signerCheck.clientAnnexDid] {string}   the annex DID the
 *   document's delegated-clients pointer currently names; absent when it
 *   names none, which refuses every annex-arm grant
 * @returns {Promise<GrantProofResult>}
 */
export async function verifyRecordedGrantProof({
  zcap,
  signerCheck
}: {
  zcap: ConnectionZcap
  signerCheck: { doc: PublishedKeyDocument; clientAnnexDid?: string }
}): Promise<GrantProofResult> {
  const parent = embeddedParentCapability(zcap as unknown as IZcap)
  if (parent === undefined) {
    return verifyDelegationProof({
      zcap: zcap as unknown as IZcap,
      doc: signerCheck.doc
    })
  }
  const { controller } = parent as { controller?: unknown }
  if (
    typeof controller !== 'string' ||
    signerCheck.clientAnnexDid === undefined ||
    !sameAuxiliarySpace({ did: controller, other: signerCheck.clientAnnexDid })
  ) {
    return { verified: false, reason: 'parent-not-annex' }
  }
  return verifyDelegationProof({ zcap: parent, doc: signerCheck.doc })
}
