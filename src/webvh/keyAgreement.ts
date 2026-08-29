/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The ONE reference-resolving reader for a did:webvh document's `keyAgreement`
 * relation, and the document shape it reads.
 *
 * The relation may carry either form the DID Core data model allows -- a string
 * reference into `verificationMethod`, or an embedded method -- so every
 * consumer that asks "which key-agreement methods does this document publish"
 * must resolve references first. That resolution lives here once, and the
 * consumers are plain filters over its result: the client listing and the
 * revocation removal keep only the methods carrying a client's controller
 * marker, while the user key roster's recipient resolver deliberately keeps
 * unmarked methods too.
 *
 * Deliberately dependency-light -- it imports nothing at all -- so the `keys`
 * layer can share the reader without pulling the ceremony or signing graph.
 */

/**
 * A locally verified did:webvh document, read for the `keyAgreement` methods it
 * publishes and the controller each one carries. Structural on purpose: a
 * resolved `DIDDoc` satisfies it, and so does any narrower document shape a
 * wallet already holds.
 */
export interface KeyAgreementDocument {
  verificationMethod?: Array<{
    id?: string
    type?: string
    controller?: string
    publicKeyMultibase?: string
    publicKeyCommitment?: string
  }>
  keyAgreement?: Array<
    | string
    | {
        id?: string
        type?: string
        controller?: string
        publicKeyMultibase?: string
        publicKeyCommitment?: string
      }
  >
}

/**
 * The materialized shape {@link resolvedKeyAgreementMethods} returns: a
 * `keyAgreement` verification method carrying either the key itself
 * (`publicKeyMultibase`) or, for a low-entropy-derived standing unlock
 * credential, its hash commitment (`publicKeyCommitment`). The `type` rides
 * along so a consumer can tell the two published flavors apart (`Multikey` vs
 * `MultikeyCommitment`) instead of inferring the flavor from which property
 * happens to be present.
 */
export interface ResolvedKeyAgreementMethod {
  id?: string
  type?: string
  controller?: string
  publicKeyMultibase?: string
  publicKeyCommitment?: string
}

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
  const byId = new Map<string, ResolvedKeyAgreementMethod>()
  for (const method of doc.verificationMethod ?? []) {
    if (typeof method?.id === 'string') {
      byId.set(method.id, method)
    }
  }
  const methods: ResolvedKeyAgreementMethod[] = []
  for (const entry of doc.keyAgreement ?? []) {
    const method = typeof entry === 'string' ? byId.get(entry) : entry
    if (method) {
      methods.push(method)
    }
  }
  return methods
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
