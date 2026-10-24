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
 * of its `proof.capabilityChain`, and both links are verified. The parent
 * must be delegated to an annex DID in the account's auxiliary Space (the
 * Space the account's delegated-clients pointer names, compared by host and
 * Space id), and its own proof must verify under a key or ladder VM the
 * current document lists. The leaf is then verified the same way against
 * the annex document of the parent's generation. The parent alone would not
 * do: it is genuine and host-held, so a host could copy it under a leaf of
 * its own naming a planted party. The caller resolves that annex document
 * (`signerCheck.annexDocument`), since `connections` sits below the annex
 * and cannot read the log itself; a collected generation resolves to none,
 * and a grant minted under it is refused.
 */
import { DataIntegrityProof } from '@interop/data-integrity-proof'
import { createVerifyCryptosuite } from '@interop/ed25519-signature/eddsa-jcs-2022'
import type { IZcap } from '@interop/data-integrity-core'
import type { ConnectionZcap } from './entry.js'
import {
  delegationSignerKey,
  embeddedParentCapability,
  firstDelegationProof
} from '../webvh/index.js'
import type { PublishedKeyDocument } from '../webvh/index.js'
import { parseClientAnnexDid } from '../webvh/clientAnnexDid.js'

/**
 * Why a recorded grant's proof does not verify as this account's. On the
 * root arm the unprefixed reasons describe the grant's own proof; on the
 * annex arm they describe the embedded parent's, and the `leaf-` reasons
 * describe the grant's own proof against the generation's annex document.
 *
 * - `unsigned` -- the proof is absent or names no `verificationMethod`.
 * - `unsupported-suite` -- the proof is not an `eddsa-jcs-2022`
 *   `DataIntegrityProof` for `capabilityDelegation`, the one suite every
 *   delegation this library mints carries.
 * - `signer-unlisted` -- the proof's `verificationMethod` names no key the
 *   current document publishes under `capabilityDelegation`
 *   (`delegationSignerKey`, the one reader every delegation-signer check
 *   shares: the member's `publicKeyMultibase`, or the did:key form of a key
 *   the relation publishes): the current-key-set rule.
 * - `signature-invalid` -- the signer is listed, and the signature does not
 *   verify over the capability under the key the document publishes for it.
 * - `parent-not-annex` -- the grant embeds a parent whose `controller` is
 *   not an annex DID in the account's auxiliary Space, or the account points
 *   at no annex generation.
 * - `leaf-generation-collected` -- the parent verified, and no annex
 *   document resolves for its generation: the generation was collected.
 * - `leaf-unsigned`, `leaf-unsupported-suite`, `leaf-signer-unlisted`,
 *   `leaf-signature-invalid` -- the parent verified, and the leaf's own
 *   proof fails the same check, read against the generation's annex
 *   document instead of the account's.
 */
export type GrantProofRefusal =
  | DelegationProofRefusal
  | 'parent-not-annex'
  | 'leaf-generation-collected'
  | `leaf-${DelegationProofRefusal}`

/**
 * Why one capability's own delegation proof does not verify against the
 * document it is read under; the unprefixed half of {@link GrantProofRefusal}.
 */
type DelegationProofRefusal =
  'unsigned' | 'unsupported-suite' | 'signer-unlisted' | 'signature-invalid'

/**
 * Resolves the verified annex document of the generation an annex DID names,
 * read under that log's chain-head pin, or `undefined` when the generation's
 * log is absent (collected). The wallet supplies it. The proof check calls
 * it once per generation per `signerCheck` object, whatever the number of
 * grants checked under that object, concurrently or not; a wallet therefore
 * builds one `signerCheck` per renewal pass, since a longer-lived one would
 * keep serving a generation's document after a GC collected it.
 */
export type AnnexDocumentResolver = (options: {
  clientAnnexDid: string
}) => Promise<PublishedKeyDocument | undefined>

/**
 * The outcome of {@link verifyRecordedGrantProof}: verified, with the id of
 * the account-listed verification method whose signature was checked (the
 * grant's own signer on the root arm, the parent's on the annex arm), or
 * refused with the reason. The annex arm checks the leaf's per-visit signer
 * too, but only the annex document lists it.
 */
export type GrantProofResult =
  | { verified: true; signerKeyId: string }
  | { verified: false; reason: GrantProofRefusal }

/**
 * The annex documents resolved under each `signerCheck` object, one promise
 * per generation, so a renewal pass's concurrent grant checks under one
 * generation share one read of its log. A rejected read is evicted, so a
 * later check under the same object asks again; the checks in flight share
 * the rejection.
 */
const resolvedAnnexDocuments = new WeakMap<
  object,
  Map<string, Promise<PublishedKeyDocument | undefined>>
>()

/**
 * The generation's annex document through the `signerCheck`'s resolver,
 * memoized on the `signerCheck` object.
 *
 * @param options {object}
 * @param options.signerCheck {object}   the object the memo is keyed on
 * @param options.signerCheck.annexDocument {AnnexDocumentResolver}
 * @param options.clientAnnexDid {string}   the generation's annex DID
 * @returns {Promise<PublishedKeyDocument | undefined>}
 */
function resolveAnnexDocument({
  signerCheck,
  clientAnnexDid
}: {
  signerCheck: { annexDocument: AnnexDocumentResolver }
  clientAnnexDid: string
}): Promise<PublishedKeyDocument | undefined> {
  let byGeneration = resolvedAnnexDocuments.get(signerCheck)
  if (byGeneration === undefined) {
    byGeneration = new Map()
    resolvedAnnexDocuments.set(signerCheck, byGeneration)
  }
  const pending = byGeneration.get(clientAnnexDid)
  if (pending !== undefined) {
    return pending
  }
  const resolving = signerCheck.annexDocument({ clientAnnexDid })
  byGeneration.set(clientAnnexDid, resolving)
  resolving.catch(() => byGeneration.delete(clientAnnexDid))
  return resolving
}

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
 * Verifies one capability's delegation proof against the document its signer
 * is listed in (the account document, or a generation's annex document for
 * an annex-arm leaf): the signer must stand under `capabilityDelegation`, and
 * the signature must
 * verify over the capability under that key. The key material is what the
 * document publishes for the signer, read through `delegationSignerKey`
 * (`webvh`), so no resolver is consulted and the renewal check cannot drift
 * from the revocation and staleness readers over the same document. A proof
 * set is read by its first proof, as every other reader of a delegation
 * does.
 *
 * @param options {object}
 * @param options.zcap {IZcap}   the capability, proof included
 * @param options.doc {PublishedKeyDocument}   the locally verified document
 *   the signer is listed in
 * @returns {Promise<{ verified: true, signerKeyId: string } | { verified:
 *   false, reason: DelegationProofRefusal }>}
 */
async function verifyDelegationProof({
  zcap,
  doc
}: {
  zcap: IZcap
  doc: PublishedKeyDocument
}): Promise<
  | { verified: true; signerKeyId: string }
  | { verified: false; reason: DelegationProofRefusal }
> {
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
  const keyMultibase = delegationSignerKey({ doc, signerKeyId })
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
 * to be an annex DID in the account's auxiliary Space, and then by its own
 * proof against the annex document the caller resolves for that generation
 * (the annex arm). A refusal says why. The root arm reads the current
 * document alone, with no log history and no network; the annex arm's one
 * read beyond it is the resolver's, made once per generation under one
 * `signerCheck` object, and what the resolver throws propagates, so a caller
 * whose annex read fails renews nothing.
 *
 * @param options {object}
 * @param options.zcap {ConnectionZcap}   the recorded capability, verbatim
 * @param options.signerCheck {object}   what the grant is read against
 * @param options.signerCheck.doc {PublishedKeyDocument}   the locally
 *   verified account document
 * @param [options.signerCheck.clientAnnexDid] {string}   the annex DID the
 *   document's delegated-clients pointer currently names; absent when it
 *   names none, which refuses every annex-arm grant
 * @param options.signerCheck.annexDocument {AnnexDocumentResolver}   the
 *   generation's annex document, for an annex-arm grant's leaf
 * @returns {Promise<GrantProofResult>}
 */
export async function verifyRecordedGrantProof({
  zcap,
  signerCheck
}: {
  zcap: ConnectionZcap
  signerCheck: {
    doc: PublishedKeyDocument
    clientAnnexDid?: string
    annexDocument: AnnexDocumentResolver
  }
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
  const parentResult = await verifyDelegationProof({
    zcap: parent,
    doc: signerCheck.doc
  })
  if (!parentResult.verified) {
    return parentResult
  }
  const generationDoc = await resolveAnnexDocument({
    signerCheck,
    clientAnnexDid: controller
  })
  if (generationDoc === undefined) {
    return { verified: false, reason: 'leaf-generation-collected' }
  }
  const leaf = await verifyDelegationProof({
    zcap: zcap as unknown as IZcap,
    doc: generationDoc
  })
  if (leaf.verified) {
    return parentResult
  }
  return { verified: false, reason: `leaf-${leaf.reason}` }
}
