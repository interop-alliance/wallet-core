/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The one merge of new verification methods into a published account
 * document, shared by every entry builder that ADDS methods: the enrollment
 * add entry, the self-enrollment add entry, and the recovery continuation's
 * add-and-retire entry. Each site hands over its methods and the ids each
 * relation gains; the merge replaces a method already published under the
 * same id, dedupes each relation's references, and applies one optional
 * retirement predicate over the EXISTING document alone.
 *
 * Shared because a drift here is silent: a relation missed at one site or a
 * filter run in a different order publishes a document the other replica
 * would not have written, and nothing refuses it. Deliberately dependency-
 * light -- the relation reader and the method type only -- so the layers
 * that build entries can take it without the ceremony graph.
 */
import type { VerificationMethod } from '@interop/did-method-webvh'
import { relationIds } from '../resourceLog/document.js'

/**
 * The ids a merge adds to each verification relation. Order is load-bearing
 * on the wire: each relation gains the ids in the order given, after the
 * references the document already carries.
 */
export interface RelationMembership {
  authentication?: string[]
  assertionMethod?: string[]
  keyAgreement?: string[]
  capabilityInvocation?: string[]
  capabilityDelegation?: string[]
}

/**
 * Merges verification methods into a published document across the five
 * relations. `verificationMethod` keeps every existing method the predicate
 * does not retire and that no added method replaces by id, then the added
 * methods in order; each relation keeps its existing references (retired ones
 * dropped) and then the ids `relations` names for it, deduped.
 *
 * The retirement predicate runs over the existing document only, and the
 * added ids join afterwards: a method this entry publishes may already stand
 * in a relation (a reinstalled ladder VM, say), and filtering the union would
 * strike the very method being published.
 *
 * @param options {object}
 * @param options.doc {object}   the published document the entry extends
 * @param options.methods {VerificationMethod[]}   the methods to publish, in
 *   the order they land in `verificationMethod`
 * @param options.relations {RelationMembership}   the ids each relation gains
 * @param [options.retire] {(id: string) => boolean}   which existing method
 *   ids and relation references leave the document in the same entry
 * @returns {object}   the merged `verificationMethods` and the five relations,
 *   as the account-entry seam takes them
 */
export function mergeVerificationMethods({
  doc,
  methods,
  relations,
  retire = () => false
}: {
  doc: {
    verificationMethod?: VerificationMethod[]
    authentication?: Array<string | { id?: string }>
    assertionMethod?: Array<string | { id?: string }>
    keyAgreement?: Array<string | { id?: string }>
    capabilityInvocation?: Array<string | { id?: string }>
    capabilityDelegation?: Array<string | { id?: string }>
  }
  methods: VerificationMethod[]
  relations: RelationMembership
  retire?: (id: string) => boolean
}): {
  verificationMethods: VerificationMethod[]
  authentication: string[]
  assertionMethod: string[]
  keyAgreement: string[]
  capabilityInvocation: string[]
  capabilityDelegation: string[]
} {
  const retired = (id: string | undefined): boolean =>
    id !== undefined && retire(id)
  const existingMethods = doc.verificationMethod ?? []
  const verificationMethods = [
    ...existingMethods.filter(
      method =>
        !retired(method.id) && !methods.some(added => added.id === method.id)
    ),
    ...methods
  ]
  const withReferences = (
    relation: Array<string | { id?: string }> | undefined,
    ids: string[] | undefined
  ) => [
    ...new Set([
      ...relationIds(relation).filter(id => !retired(id)),
      ...(ids ?? [])
    ])
  ]
  return {
    verificationMethods,
    authentication: withReferences(
      doc.authentication,
      relations.authentication
    ),
    assertionMethod: withReferences(
      doc.assertionMethod,
      relations.assertionMethod
    ),
    keyAgreement: withReferences(doc.keyAgreement, relations.keyAgreement),
    capabilityInvocation: withReferences(
      doc.capabilityInvocation,
      relations.capabilityInvocation
    ),
    capabilityDelegation: withReferences(
      doc.capabilityDelegation,
      relations.capabilityDelegation
    )
  }
}
