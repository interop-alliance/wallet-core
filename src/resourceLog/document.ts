/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The account-document reading conventions every reader shares, in one place:
 * which `capabilityDelegation` members are ladder VMs, which `keyAgreement`
 * methods are the account's credential inventory, and which key multibases
 * the two account-document key classes (the enrolled clients' signing keys,
 * the ladder VMs' keys) publish. How a verification relation resolves, and
 * which key multibase a relation member names, are the generic rules every
 * consumer of the stack shares; they come from `@interop/vh-resource-log`
 * and are re-exported here under the names this module always had.
 *
 * Each of those rules is a wire-level convention of the account document, so
 * a second implementation of one is a place the readers can disagree: the
 * ceremony-tail license's inventory comparison and the client listing's
 * ladder-VM recognition must answer identically over the same document, and
 * so must the roster's recipient resolver and the client listing's marker
 * filter, and so must the ladder-rung attribution and the account's did:key
 * census. They are consumers of the readers here rather than re-readings of
 * the document.
 *
 * Deliberately dependency-light -- it imports only the resource-log library
 * the layer beside it already sits over -- so both the layer-0 controller
 * adapter and the `webvh` and `keys` layers above can share the readers
 * without pulling the ceremony or signing graph. Its public home is
 * `@interop/wallet-core/webvh`, which re-exports the `keyAgreement` readers,
 * the ladder recognition, and the two key-class readers; this subpath
 * exports none of them, so each name has one owner.
 */
import {
  memberKeyMultibase,
  relationIds,
  relationKeyMultibases,
  relationMembers,
  resolvedRelationMethods,
  type ControllerDocument,
  type VerificationRelation
} from '@interop/vh-resource-log'

export { relationIds, resolvedRelationMethods }

/**
 * The materialized shape the relation readers return: a verification method
 * carrying either the key itself (`publicKeyMultibase`) or, for a
 * low-entropy-derived standing unlock credential, its hash commitment
 * (`publicKeyCommitment`). The `type` rides along so a consumer can tell the
 * two published flavors apart (`Multikey` vs `MultikeyCommitment`) instead of
 * inferring the flavor from which property happens to be present.
 *
 * A credential-class member of either flavor also names its ladder's rung-0
 * commitment (`ladderCommitment`): `hash(rung 0)` in the multihash form
 * `nextKeyHashes` carries, the value a seedless reader anchors the
 * credential's ladder walk on. It is a plain JSON member with no JSON-LD
 * term: nothing processes the account document as JSON-LD, and every
 * signature over it is JCS-canonicalized. An enrolled client's marked twin
 * never carries it.
 */
export interface ResolvedKeyAgreementMethod {
  id?: string
  type?: string
  controller?: string
  publicKeyMultibase?: string
  publicKeyCommitment?: string
  ladderCommitment?: string
}

/**
 * A locally verified did:webvh document, read for the verification relations
 * it publishes and the methods they resolve to: the library's
 * `ControllerDocument` over this module's method shape. Structural on
 * purpose: a resolved `DIDDoc` satisfies it, and so does any narrower
 * document shape a wallet already holds.
 */
export type AccountDocument = ControllerDocument<ResolvedKeyAgreementMethod>

/**
 * The document shape the `keyAgreement` readers take, kept as the published
 * name the `webvh` and `keys` subpaths surface. It is {@link AccountDocument}
 * itself: every member is optional, so a caller holding only the
 * `keyAgreement` half satisfies it unchanged.
 */
export type KeyAgreementDocument = AccountDocument

/**
 * The verification relations a document reader may resolve.
 */
export type DocumentRelation = VerificationRelation

/**
 * The `keyAgreement` verification methods a document publishes, materialized:
 * string references resolved against `verificationMethod` (a reference nothing
 * backs is dropped), embedded methods taken verbatim. Document order is
 * preserved, and nothing is filtered -- deciding which of these methods belongs
 * to whom is each caller's own rule.
 *
 * @param options {object}
 * @param options.doc {KeyAgreementDocument}   a locally verified document
 * @returns {ResolvedKeyAgreementMethod[]}
 */
export function resolvedKeyAgreementMethods({
  doc
}: {
  doc: KeyAgreementDocument
}): ResolvedKeyAgreementMethod[] {
  return resolvedRelationMethods({ doc, relation: 'keyAgreement' })
}

/**
 * The CREDENTIAL-CLASS `keyAgreement` methods a document publishes: those the
 * account DID itself controls. The rule is structural, and it is the exact
 * complement of the client marker: an enrolled client's key-agreement method
 * carries `controller: did:key:<its signing multibase>`
 * (`clientKeyAgreementController`), while a standing unlock credential's
 * carries the account DID. Both published flavors match -- a passphrase's
 * `MultikeyCommitment` and the verbatim `Multikey` a passkey or a recovery
 * code publishes -- because the class is decided by the controller alone.
 *
 * Nothing here tells one credential from another. A recovery code's entry is
 * indistinguishable from a passkey's by construction (both are unmarked and
 * verbatim), so a caller retiring this class retires every credential the
 * account stands on, which is what the transient and remembered recovery
 * continuations want.
 *
 * @param options {object}
 * @param options.doc {KeyAgreementDocument}   a locally verified document
 * @param options.did {string}   the account DID the document resolves to
 * @returns {ResolvedKeyAgreementMethod[]}   in document order
 */
export function credentialKeyAgreementMethods({
  doc,
  did
}: {
  doc: KeyAgreementDocument
  did: string
}): ResolvedKeyAgreementMethod[] {
  return resolvedKeyAgreementMethods({ doc }).filter(
    method => method.controller === did
  )
}

/**
 * The credential-class `keyAgreement` verification-method ids an entry
 * INTRODUCES: those its document publishes and the previous entry's document
 * did not. Credential-class means account-controlled
 * (`credentialKeyAgreementMethods`), so an enrolled client's marked twin
 * never counts. The co-introduction arm of the ladder-VM attribution reads
 * this and refuses to act unless the answer is exactly this credential.
 *
 * @param options {object}
 * @param options.doc {KeyAgreementDocument}   the entry's document
 * @param [options.prevDoc] {KeyAgreementDocument}   the previous entry's
 * @param options.did {string}   the account DID
 * @returns {string[]}   in document order
 */
export function introducedCredentialKeys({
  doc,
  prevDoc,
  did
}: {
  doc: KeyAgreementDocument
  prevDoc: KeyAgreementDocument | undefined
  did: string
}): string[] {
  const before = new Set(
    (prevDoc ? credentialKeyAgreementMethods({ doc: prevDoc, did }) : []).map(
      method => method.id
    )
  )
  return credentialKeyAgreementMethods({ doc, did })
    .map(method => method.id)
    .filter((id): id is string => id !== undefined && !before.has(id))
}

/**
 * The credential-class `keyAgreement` verification-method ids an entry
 * RETIRES: those the previous entry's document published and this one does
 * not. The mirror of {@link introducedCredentialKeys}. The handover anchor
 * arm requires one, since only a spend strikes a member in the entry that
 * authorizes its successor, and the resumed spend's report of what its entry
 * retired is this less the spent code's own id.
 *
 * @param options {object}
 * @param options.doc {KeyAgreementDocument}   the entry's document
 * @param [options.prevDoc] {KeyAgreementDocument}   the previous entry's
 * @param options.did {string}   the account DID
 * @returns {string[]}
 */
export function retiredCredentialKeys({
  doc,
  prevDoc,
  did
}: {
  doc: KeyAgreementDocument
  prevDoc: KeyAgreementDocument | undefined
  did: string
}): string[] {
  const after = new Set(
    credentialKeyAgreementMethods({ doc, did }).map(method => method.id)
  )
  return (prevDoc ? credentialKeyAgreementMethods({ doc: prevDoc, did }) : [])
    .map(method => method.id)
    .filter((id): id is string => id !== undefined && !after.has(id))
}

/**
 * The ladder-VM recognition convention: a `capabilityDelegation` member
 * absent from `capabilityInvocation` is a ladder VM -- the stable sibling key
 * a standing credential publishes for as long as it stands
 * (`ladderVerificationMethod` is the one write-side builder). The
 * asymmetry is the convention rather than a marker property because it is
 * what actually carries the authority: zcap's `delegator.id` cannot identify
 * the signer, so a verifier classifies the VM from the resolved document it
 * already holds -- a zero-I/O read -- and the same asymmetry is what keeps
 * the VM structurally out of every client listing (those key on
 * `capabilityInvocation`). An enrolled client publishes its signing key under
 * both relations, so it can never match.
 *
 * Returns every matching verification-method id, in document order. A ladder
 * VM's life is keyed to its credential rather than to the account's client
 * census: the standing establishment installs it, the credential's retirement
 * strikes it, and enrollment leaves it alone. So the count is one per
 * standing credential, co-resident with however many clients the account has
 * enrolled, and a stale third-party VM can stand beside them.
 *
 * @param options {object}
 * @param options.doc {object}   a locally verified document
 * @returns {string[]}   the ladder VMs' verification-method ids
 */
export function ladderVmIds({
  doc
}: {
  doc: {
    capabilityInvocation?: Array<string | { id?: string }>
    capabilityDelegation?: Array<string | { id?: string }>
  }
}): string[] {
  const invocable = new Set(relationIds(doc.capabilityInvocation))
  return relationIds(doc.capabilityDelegation).filter(id => !invocable.has(id))
}

/**
 * The ladder VMs' verification methods, materialized: the
 * `capabilityDelegation` methods {@link ladderVmIds} names, resolved the way
 * every other relation read resolves. Recognition therefore has exactly one
 * definition -- a reader needing the ladder VMs' resolved methods asks here
 * rather than re-deriving the asymmetry. A reader needing the ladder KEYS
 * asks {@link ladderVmKeyMultibases} instead, which applies the library's one
 * key-multibase rule; this reader hands back the methods as resolved, with no
 * fragment check.
 *
 * A method the recognition cannot name -- an embedded `capabilityDelegation`
 * entry carrying no `id`, or a reference nothing backs -- has no resolved
 * method here, the same refuse-not-guess answer the id-keyed recognition
 * gives. (The key reader names such a reference's key by fragment alone.)
 *
 * @param options {object}
 * @param options.doc {AccountDocument}   a locally verified document
 * @returns {ResolvedKeyAgreementMethod[]}   in document order
 */
export function ladderVmMethods({
  doc
}: {
  doc: AccountDocument
}): ResolvedKeyAgreementMethod[] {
  const ids = new Set(ladderVmIds({ doc }))
  return resolvedRelationMethods({
    doc,
    relation: 'capabilityDelegation'
  }).filter(method => typeof method.id === 'string' && ids.has(method.id))
}

/**
 * The enrolled clients' signing-key multibases a document publishes: the
 * keys of its `capabilityInvocation` members, which is the relation an
 * enrolled client publishes its signing key under and a ladder VM, a
 * credential's key-agreement key, a transient annex VM, and the KMS
 * convenience key deliberately do not (`enrolledClientVmIds` is the same
 * convention read as ids). Each member is read under the library's one
 * key-multibase rule (`memberKeyMultibase`): its id fragment and its
 * resolved method's `publicKeyMultibase` must agree when both are present,
 * either alone is the key, and a member whose two readings disagree names no
 * key. The ladder-rung attribution and the account's did:key census both read
 * this set, so a malformed member drops out of both rather than naming a
 * different key in each.
 *
 * @param options {object}
 * @param options.doc {AccountDocument}   a locally verified document
 * @returns {Set<string>}
 */
export function enrolledClientKeyMultibases({
  doc
}: {
  doc: AccountDocument
}): Set<string> {
  return relationKeyMultibases({ doc, relation: 'capabilityInvocation' })
}

/**
 * The ladder VMs' key multibases a document publishes: the keys of the
 * `capabilityDelegation` members {@link ladderVmIds} recognizes, each read
 * under the same one key-multibase rule as
 * {@link enrolledClientKeyMultibases}. Recognition stays id-keyed, so an
 * id-less embedded delegation member is not a ladder VM here either; a
 * recognized member that is a reference nothing backs names its key by
 * fragment alone.
 *
 * @param options {object}
 * @param options.doc {AccountDocument}   a locally verified document
 * @returns {Set<string>}
 */
export function ladderVmKeyMultibases({
  doc
}: {
  doc: AccountDocument
}): Set<string> {
  const ids = new Set(ladderVmIds({ doc }))
  const keys = new Set<string>()
  for (const member of relationMembers({
    doc,
    relation: 'capabilityDelegation'
  })) {
    if (member.id === undefined || !ids.has(member.id)) {
      continue
    }
    const key = memberKeyMultibase(member)
    if (key !== undefined) {
      keys.add(key)
    }
  }
  return keys
}
