/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The enrolled-client listing: enumerates the wallet clients a verified
 * did:webvh log currently enrolls, for a "your wallets" management surface.
 *
 * The document is the roster, so the listing is a pure read over it, keyed on
 * `capabilityInvocation`: every enrolled client publishes its Ed25519 signing
 * key there, while a recovery code's key appears only under `keyAgreement`
 * (deliberately unmarked) and the KMS-held convenience key only under
 * `authentication` -- so neither can ever surface in the listing,
 * structurally rather than by filtering.
 *
 * Two members are not readable off the current document alone and come from
 * the log:
 *
 * - `updateKeyMultibase` -- the client's ACTIVE update key, which
 *   {@link RevokedClientKeys} needs to disconnect the client. `updateKeys` is
 *   a flat set with no per-client grouping, so the key is recovered by
 *   attribution: the entry that published the client's verification methods
 *   also revealed its initial update key, and each later entry that retired
 *   the attributed key while revealing exactly one replacement is that
 *   client's self-rotation. An attribution that cannot isolate a single key
 *   leaves the member `undefined` (the caller disables disconnect for that
 *   row) rather than guessing -- removing a wrong update key would revoke a
 *   different client's authority.
 * - `addedAt` -- the `versionTime` of the entry that published the client's
 *   verification methods (its enrollment moment, as the log states it).
 *
 * The X25519 `keyAgreementKeyMultibases` set is READ from the document, not
 * derived: it is every `keyAgreement` method published under the client's
 * controller marker (`controller: did:key:<signing multibase>`, the write-side
 * convention every enrollment follows). The marker is what tells a client's
 * key-agreement methods apart from the deliberately unmarked ones a recovery
 * continuation publishes beside them. It is hard-required -- a client with no
 * marked method reports an EMPTY set, the same refuse-not-guess rule the
 * update-key attribution follows, since a guessed key-agreement key would make
 * a revocation report success over a method that never left the document. The
 * whole set is built in a single pass over the document's resolved
 * key-agreement methods, grouped by controller once and looked up per client,
 * rather than a per-client rescan.
 *
 * Verification is the CALLER's job: pass a log that was resolved and checked
 * against the account pointer (the wallet's ordinary
 * verify-the-published-log step); this module only enumerates it.
 *
 * Beside the listing lives the current-key-set rule as one predicate,
 * `delegationKeyInDocument`: given a recorded delegation's key id, does the
 * document still publish that key? It is the same read the listing performs,
 * reduced to a yes/no about one recorded grant, so every surface that has to
 * decide "does this delegation still chain" decides it in one place.
 */
import type { DIDLog } from '@interop/did-method-webvh'
import { vmFragmentOf } from '../resourceLog/vmFragment.js'
import {
  clientKeyAgreementController,
  effectiveParameters,
  relationIds
} from './didWebvh.js'
import { resolvedKeyAgreementMethods } from './keyAgreement.js'
import type { KeyAgreementDocument } from './keyAgreement.js'

/**
 * One enrolled wallet client as the log states it. `keyAgreementKeyMultibases`
 * is REQUIRED and set-valued: every key-agreement method the client's
 * controller marker claims, in document order, deduplicated. An EMPTY array is
 * the refuse-not-guess state -- the document carries no marked method for the
 * client. `updateKeyMultibase` and `addedAt` are absent when the log
 * attribution cannot recover them (see the module doc).
 *
 * A client that published several marked key-agreement methods surfaces the
 * full set here; revoking it removes them all regardless, because the removal
 * filters the document by the marker rather than by this member.
 */
export interface EnrolledWebvhClient {
  signingKeyMultibase: string
  keyAgreementKeyMultibases: string[]
  updateKeyMultibase?: string
  addedAt?: string
}

/**
 * A locally verified did:webvh document, read only for the key multibases it
 * publishes. Structural on purpose: a resolved `DIDDoc` satisfies it, and so
 * does any narrower document shape a wallet already holds.
 */
export interface PublishedKeyDocument {
  verificationMethod?: Array<{ id?: string; publicKeyMultibase?: string }>
}

/**
 * The key multibases the document currently publishes: every verification
 * method's `publicKeyMultibase`, plus the fragment of its id (for a did:webvh
 * document the two agree, and taking both is what makes the did:key and
 * did:webvh spellings of one key match).
 *
 * @param options {object}
 * @param options.doc {PublishedKeyDocument}   a locally verified document
 * @returns {Set<string>}
 */
export function documentKeyMultibases({
  doc
}: {
  doc: PublishedKeyDocument
}): Set<string> {
  const multibases = new Set<string>()
  for (const method of doc.verificationMethod ?? []) {
    if (method.publicKeyMultibase) {
      multibases.add(method.publicKeyMultibase)
    }
    const fragment = method.id ? vmFragmentOf(method.id) : undefined
    if (fragment) {
      multibases.add(fragment)
    }
  }
  return multibases
}

/**
 * The current-key-set rule for a recorded delegation: is the verification
 * method that signed it still published by the document? A delegation whose
 * signing key has left the document stops verifying the moment it does, so a
 * `false` here is exactly "this recorded grant has rotted" -- the signal
 * behind a re-mint or a health nudge.
 *
 * Matching is on the key multibase, not the whole id, so the did:key and
 * did:webvh spellings of one key agree (a delegation signed before the
 * account's controller was promoted names the same key under a different
 * DID).
 *
 * An ABSENT `delegationKeyId` reports `false`: a record that does not say
 * which key signed it cannot be checked against the document, and the
 * conservative reading of an uncheckable grant is that it does not stand.
 * That is the one decision here, taken once so no caller re-decides it -- a
 * record predating the field is flagged rather than assumed healthy.
 *
 * @param options {object}
 * @param options.doc {PublishedKeyDocument}   a locally verified document
 * @param [options.delegationKeyId] {string}   the recorded delegation's
 *   verification-method id, in either DID spelling
 * @returns {boolean}
 */
export function delegationKeyInDocument({
  doc,
  delegationKeyId
}: {
  doc: PublishedKeyDocument
  delegationKeyId?: string
}): boolean {
  const multibase = delegationKeyId ? vmFragmentOf(delegationKeyId) : undefined
  if (!multibase) {
    return false
  }
  return documentKeyMultibases({ doc }).has(multibase)
}

/**
 * The ladder-VM recognition convention: a `capabilityDelegation` member
 * absent from `capabilityInvocation` is a ladder VM -- the stable sibling key
 * a standing credential publishes while the account has no enrolled durable
 * client (`ladderVerificationMethod` is the one write-side builder). The
 * asymmetry is the convention rather than a marker property because it is
 * what actually carries the authority: zcap's `delegator.id` cannot identify
 * the signer, so a verifier classifies the VM from the resolved document it
 * already holds -- a zero-I/O read -- and the same asymmetry is what keeps
 * the VM structurally out of every client listing (those key on
 * `capabilityInvocation`). An enrolled client publishes its signing key under
 * both relations, so it can never match.
 *
 * Returns every matching verification-method id, in document order: the
 * ordinary shape is one (the minting credential's) or none (any durable
 * client enrolled), but a stale third-party ladder VM can stand beside the
 * live one, and the first durable self-enrollment's add entry has to remove
 * them all.
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
 * The `keyAgreement` verification methods one client's controller marker
 * claims: the document's resolved key-agreement methods
 * ({@link resolvedKeyAgreementMethods}) filtered to those whose `controller` is
 * the client's did:key (see `clientKeyAgreementController`).
 *
 * The marker is HARD-REQUIRED here, and that is where this predicate parts
 * company with the user key roster's recipient resolver, which filters the same
 * reader's result by nothing more than "carries a public key multibase".
 * Listing and revocation are refuse-not-guess surfaces: an unmarked method
 * matched by proximity would make a revocation report success over a method
 * that never left the document. The roster resolver's job is the opposite --
 * it must keep wrapping the user key to the deliberately unmarked
 * key-agreement methods a recovery code publishes, so it matches them too.
 *
 * The ordinary shape is exactly one method, but the result is a SET rather
 * than a first match on purpose: a revocation has to remove every method the
 * marker claims, or a client with a second published key-agreement key would
 * keep a standing wrap target after a revocation reported success.
 *
 * @param options {object}
 * @param options.doc {KeyAgreementDocument}   a locally verified document
 * @param options.signingKeyMultibase {string}   the client's Ed25519 signing
 *   key, as the document publishes it
 * @returns {Array<{ id?: string, publicKeyMultibase?: string }>}
 */
export function markedKeyAgreementMethods({
  doc,
  signingKeyMultibase
}: {
  doc: KeyAgreementDocument
  signingKeyMultibase: string
}): Array<{ id?: string; publicKeyMultibase?: string }> {
  const marker = clientKeyAgreementController({ signingKeyMultibase })
  return resolvedKeyAgreementMethods({ doc }).filter(
    method => method.controller === marker
  )
}

/**
 * The key multibases of the `keyAgreement` methods one client's controller
 * marker claims -- {@link markedKeyAgreementMethods}, reduced to the
 * multibases a roster wrap and a listing row speak in. A method carrying no
 * `publicKeyMultibase` falls back to the fragment of its id (for a did:webvh
 * document the two agree).
 *
 * @param options {object}
 * @param options.doc {KeyAgreementDocument}   a locally verified document
 * @param options.signingKeyMultibase {string}
 * @returns {string[]}
 */
export function markedKeyAgreementMultibases({
  doc,
  signingKeyMultibase
}: {
  doc: KeyAgreementDocument
  signingKeyMultibase: string
}): string[] {
  const multibases: string[] = []
  for (const method of markedKeyAgreementMethods({
    doc,
    signingKeyMultibase
  })) {
    const multibase =
      method.publicKeyMultibase ??
      (method.id ? vmFragmentOf(method.id) : undefined)
    if (multibase) {
      multibases.push(multibase)
    }
  }
  return [...new Set(multibases)]
}

/**
 * Every `keyAgreement` method the document publishes, grouped by its
 * `controller` in one pass -- the listing's batch counterpart to
 * {@link markedKeyAgreementMultibases}, which resolves and rescans the whole
 * relation per client. A method carrying no `publicKeyMultibase` falls back to
 * the fragment of its id (for a did:webvh document the two agree), and a
 * method with no `controller` at all, or that yields no multibase, is
 * dropped: it can never be a client's marked method.
 *
 * Keying by controller string is what keeps this MARKED-only without an extra
 * filter: only a client's own methods carry a `did:key:<signing multibase>`
 * controller marker, while the deliberately unmarked methods a recovery
 * continuation publishes carry the account DID as controller instead, so their
 * group is simply never looked up by {@link listEnrolledWebvhClients}.
 *
 * Multibases within a group are deduplicated, first-seen order preserved.
 *
 * @param options {object}
 * @param options.doc {KeyAgreementDocument}   a locally verified document
 * @returns {Map<string, string[]>}
 */
function markedKeyAgreementIndex({
  doc
}: {
  doc: KeyAgreementDocument
}): Map<string, string[]> {
  const index = new Map<string, string[]>()
  for (const method of resolvedKeyAgreementMethods({ doc })) {
    if (!method.controller) {
      continue
    }
    const multibase =
      method.publicKeyMultibase ??
      (method.id ? vmFragmentOf(method.id) : undefined)
    if (!multibase) {
      continue
    }
    const group = index.get(method.controller)
    if (group) {
      if (!group.includes(multibase)) {
        group.push(multibase)
      }
    } else {
      index.set(method.controller, [multibase])
    }
  }
  return index
}

/**
 * The update keys an entry newly revealed: the effective `updateKeys` at
 * `index` minus the previous entry's.
 *
 * @param params {Array<{ updateKeys: string[] }>}
 * @param index {number}
 * @returns {string[]}
 */
function addedUpdateKeys(
  params: Array<{ updateKeys: string[] }>,
  index: number
): string[] {
  const previous = new Set(index > 0 ? params[index - 1]!.updateKeys : [])
  return params[index]!.updateKeys.filter(key => !previous.has(key))
}

/**
 * Attributes one client's ACTIVE update key from the log: its initial key is
 * whatever the entry publishing its verification methods revealed, and each
 * later entry that retired the attributed key while revealing exactly one
 * replacement is that client's self-rotation. Returns `undefined` on any
 * ambiguity (an entry revealing several keys beside the client's methods, a
 * retirement with several candidate replacements) or when the attributed key
 * is not authorized by the final entry.
 *
 * @param options {object}
 * @param options.params {Array<{ updateKeys: string[]; nextKeyHashes: string[] }>}
 *   the log's effective parameters, one entry per log entry
 * @param options.addIndex {number}   the entry that published the client's
 *   verification methods
 * @returns {string | undefined}
 */
function attributeActiveUpdateKey({
  params,
  addIndex
}: {
  params: Array<{ updateKeys: string[]; nextKeyHashes: string[] }>
  addIndex: number
}): string | undefined {
  const initial = addedUpdateKeys(params, addIndex)
  if (initial.length !== 1) {
    return undefined
  }
  let active = initial[0]!
  for (let index = addIndex + 1; index < params.length; index++) {
    const stillPresent = params[index]!.updateKeys.includes(active)
    if (stillPresent) {
      continue
    }
    const revealed = addedUpdateKeys(params, index)
    if (revealed.length !== 1) {
      return undefined
    }
    active = revealed[0]!
  }
  return params[params.length - 1]!.updateKeys.includes(active)
    ? active
    : undefined
}

/**
 * The index of the entry that published a client's verification methods (its
 * enrollment moment, and the attribution anchor for its update key), or `-1`
 * when the log never published them. Keyed on the signing key's multibase, the
 * fragment of the `capabilityInvocation` reference every enrolled client
 * publishes.
 *
 * @param options {object}
 * @param options.log {DIDLog}
 * @param options.signingKeyMultibase {string}
 * @returns {number}
 */
function clientAddIndex({
  log,
  signingKeyMultibase
}: {
  log: DIDLog
  signingKeyMultibase: string
}): number {
  return log.findIndex(entry =>
    relationIds(entry.state.capabilityInvocation).some(
      vmId => vmFragmentOf(vmId) === signingKeyMultibase
    )
  )
}

/**
 * One enrolled client's ACTIVE update key as the log states it, keyed on the
 * signing key the document publishes for it -- the same attribution the
 * listing performs, for a caller that already knows which client it means (the
 * revocation edit, re-deriving a target whose key rotated since the listing).
 * `undefined` when the log never published the client's verification methods,
 * or when the attribution cannot isolate a single key (see the module doc: a
 * wrong update key would revoke a different client's authority).
 *
 * @param options {object}
 * @param options.log {DIDLog}   a resolved, caller-verified log
 * @param options.signingKeyMultibase {string}   the client's Ed25519 signing
 *   key, as the document publishes it
 * @returns {string | undefined}
 */
export function attributeClientUpdateKey({
  log,
  signingKeyMultibase
}: {
  log: DIDLog
  signingKeyMultibase: string
}): string | undefined {
  const addIndex = clientAddIndex({ log, signingKeyMultibase })
  return addIndex === -1
    ? undefined
    : attributeActiveUpdateKey({ params: effectiveParameters(log), addIndex })
}

/**
 * A map from an enrolled client's signing-key multibase to the index of the
 * FIRST entry that published it under `capabilityInvocation` -- the whole log's
 * enrollment moments in one forward pass, so a listing attributes every client
 * without rescanning. A multibase the log never published is absent from the
 * map.
 *
 * @param options {object}
 * @param options.log {DIDLog}
 * @returns {Map<string, number>}
 */
function clientAddIndexes({ log }: { log: DIDLog }): Map<string, number> {
  const addIndexes = new Map<string, number>()
  for (const [index, entry] of log.entries()) {
    for (const vmId of relationIds(entry.state.capabilityInvocation)) {
      const signingKeyMultibase = vmFragmentOf(vmId)
      if (signingKeyMultibase && !addIndexes.has(signingKeyMultibase)) {
        addIndexes.set(signingKeyMultibase, index)
      }
    }
  }
  return addIndexes
}

/**
 * Lists the enrolled wallet clients of a VERIFIED did:webvh log (see the
 * module doc: enumeration keyed on the final document's
 * `capabilityInvocation`, update keys and enrollment times recovered by log
 * attribution). Order follows the document's `capabilityInvocation` array --
 * enrollment order, since every roster edit appends.
 *
 * @param options {object}
 * @param options.log {DIDLog}   a resolved, caller-verified log
 * @returns {EnrolledWebvhClient[]}
 */
export function listEnrolledWebvhClients({
  log
}: {
  log: DIDLog
}): EnrolledWebvhClient[] {
  if (log.length === 0) {
    return []
  }
  const doc = log[log.length - 1]!.state
  const params = effectiveParameters(log)
  // The entry that published each client's verification methods -- its
  // enrollment moment, and the attribution anchor for its update key.
  const addIndexes = clientAddIndexes({ log })
  // Every keyAgreement method, grouped by controller, in one pass -- keying by
  // controller string picks up only MARKED methods (a client's own), since the
  // account DID controller a recovery code's unmarked method carries is never
  // looked up below.
  const keyAgreementIndex = markedKeyAgreementIndex({ doc })
  const clients: EnrolledWebvhClient[] = []
  for (const vmId of relationIds(doc.capabilityInvocation)) {
    const signingKeyMultibase = vmFragmentOf(vmId)
    if (!signingKeyMultibase) {
      continue
    }
    const addIndex = addIndexes.get(signingKeyMultibase)
    clients.push({
      signingKeyMultibase,
      keyAgreementKeyMultibases:
        keyAgreementIndex.get(
          clientKeyAgreementController({ signingKeyMultibase })
        ) ?? [],
      updateKeyMultibase:
        addIndex === undefined
          ? undefined
          : attributeActiveUpdateKey({ params, addIndex }),
      addedAt: addIndex === undefined ? undefined : log[addIndex]!.versionTime
    })
  }
  return clients
}
