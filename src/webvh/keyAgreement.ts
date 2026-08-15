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
    controller?: string
    publicKeyMultibase?: string
  }>
  keyAgreement?: Array<
    string | { id?: string; controller?: string; publicKeyMultibase?: string }
  >
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
 * @returns {Array<{ id?: string, controller?: string, publicKeyMultibase?: string }>}
 */
export function resolvedKeyAgreementMethods({
  doc
}: {
  doc: KeyAgreementDocument
}): Array<{ id?: string; controller?: string; publicKeyMultibase?: string }> {
  const byId = new Map<
    string,
    { id?: string; controller?: string; publicKeyMultibase?: string }
  >()
  for (const method of doc.verificationMethod ?? []) {
    if (typeof method?.id === 'string') {
      byId.set(method.id, method)
    }
  }
  const methods: Array<{
    id?: string
    controller?: string
    publicKeyMultibase?: string
  }> = []
  for (const entry of doc.keyAgreement ?? []) {
    const method = typeof entry === 'string' ? byId.get(entry) : entry
    if (method) {
      methods.push(method)
    }
  }
  return methods
}
