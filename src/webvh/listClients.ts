/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The enrolled-client listing: enumerates the wallet clients a verified
 * did:webvh log currently enrolls, for a "your wallets" management surface.
 *
 * The document is the roster, so the listing is a pure read over it, keyed on
 * `capabilityInvocation`: every enrolled client publishes its Ed25519 signing
 * key there (each client's `signingKeyMultibase` is the key its member
 * publishes, the same read as `enrolledClientKeyMultibases`), while a
 * recovery code's key appears only under `keyAgreement` (deliberately unmarked) and the KMS-held convenience key only under
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
 * Beside the listing lives the current-key-set rule as one reader,
 * `delegationSignerKey`: given a recorded delegation's signer id, which key
 * does the document publish for it under `capabilityDelegation`? The relation
 * is the whole question -- a delegation proof verifies only against a method
 * the document publishes for that purpose now -- so a key surviving under
 * `authentication` or `keyAgreement` alone does not keep a grant chaining.
 * The key is the resolved member's `publicKeyMultibase` and the id fragment
 * is an opaque selector (the DID Core reading, the one the library's log
 * verifier applies); only a did:key signer id carries its key in the id,
 * by that method's spec. Every surface that has to decide "does this
 * delegation still chain" reads through it (`delegationKeyInDocument` is
 * the yes/no over it), so no two readers can name different keys over one
 * document.
 */
import type { DIDLog } from '@interop/did-method-webvh'
import {
  memberKeyMultibase,
  parseVersionedVm,
  relationKeyMultibases,
  relationMemberNamed,
  vmFragmentOf
} from '@interop/vh-resource-log'
import {
  clientKeyAgreementController,
  effectiveParameters
} from './didWebvh.js'
import {
  enrolledClientKeyMultibases,
  relationIds,
  resolvedKeyAgreementMethods
} from '../resourceLog/document.js'
import type { KeyAgreementDocument } from '../resourceLog/document.js'

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
  id?: string
  verificationMethod?: Array<{ id?: string; publicKeyMultibase?: string }>
  capabilityDelegation?: Array<
    string | { id?: string; publicKeyMultibase?: string }
  >
}

/**
 * The key multibases the document currently publishes: every verification
 * method's `publicKeyMultibase`, plus the fragment of its id (for a did:webvh
 * document the two agree, and taking both is what makes the did:key and
 * did:webvh forms of one key match).
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
 * The key a did:key DID URL carries: `did:key:<key>` or `did:key:<key>#<key>`,
 * the forms a client signs under before the account's controller is
 * promoted. By that method's spec the DID itself is the key, so the reading
 * needs no document. A did:key URL whose fragment names another key is
 * malformed and names none, and any other DID names none here.
 *
 * @param id {string}   a DID or DID URL
 * @returns {string | undefined}   the key multibase
 */
export function didKeyMultibase(id: string): string | undefined {
  const hash = id.indexOf('#')
  const did = hash === -1 ? id : id.slice(0, hash)
  if (!did.startsWith('did:key:')) {
    return undefined
  }
  const key = did.slice('did:key:'.length)
  if (key === '' || key.includes('?')) {
    return undefined
  }
  return hash === -1 || id.slice(hash + 1) === key ? key : undefined
}

/**
 * A reader of delegation signers over one document:
 * `(signerKeyId) => key`, the published key
 * {@link delegationSignerKey} names for the id. Built once per document by
 * a caller that reads many signers against it (a directory scan, a row of
 * recorded grants), so the relation's key set is computed once and each
 * id's dereference once.
 */
export type DelegationSignerReader = (signerKeyId: string) => string | undefined

/**
 * Builds the {@link DelegationSignerReader} over a document. The rule is
 * {@link delegationSignerKey}'s; this is the memoized form.
 *
 * @param options {object}
 * @param options.doc {PublishedKeyDocument}   a locally verified document
 * @returns {DelegationSignerReader}
 */
export function delegationSignerKeyReader({
  doc
}: {
  doc: PublishedKeyDocument
}): DelegationSignerReader {
  const relation = 'capabilityDelegation'
  let published: Set<string> | undefined
  const resolved = new Map<string, string | undefined>()
  const resolve = (signerKeyId: string): string | undefined => {
    const parsed = parseVersionedVm(signerKeyId)
    if (parsed === undefined) {
      return undefined
    }
    const { did, fragment } = parsed
    if (did.startsWith('did:key:')) {
      // A did:key signer is read by its method's spec: the DID is the key,
      // named while the relation publishes it.
      const key = didKeyMultibase(signerKeyId)
      published ??= relationKeyMultibases({ doc, relation })
      return key !== undefined && published.has(key) ? key : undefined
    }
    const member = relationMemberNamed({ doc, relation, did, fragment })
    return member === undefined ? undefined : memberKeyMultibase(member)
  }
  return signerKeyId => {
    if (!resolved.has(signerKeyId)) {
      resolved.set(signerKeyId, resolve(signerKeyId))
    }
    return resolved.get(signerKeyId)
  }
}

/**
 * The key the document publishes under `capabilityDelegation` for a
 * delegation's signer id (a proof's `verificationMethod` DID URL), or
 * `undefined` when the id names no listed key: the one reader every
 * delegation-signer check in this library goes through. A URL under the
 * document's DID dereferences to the member it names
 * (`relationMemberNamed`) and takes that member's `publicKeyMultibase`
 * (`memberKeyMultibase`); its fragment is an opaque selector that names no
 * key of its own. The URL is split the way the resource-log verifier splits
 * a proof's method id (`parseVersionedVm`), so a `versionId` DID parameter
 * is dropped and the dereference runs against the current document, which
 * is the current-key-set rule. A did:key URL carries its key in the DID
 * itself, by that method's spec, and names it only while the relation
 * publishes that key. A relative member id resolves against the document's
 * own `id` alone, so a document handed without one lists its absolute
 * members only. Any other DID (a client annex's, say) is one the document
 * does not list, so it names no key here.
 *
 * @param options {object}
 * @param options.doc {PublishedKeyDocument}   a locally verified document
 * @param options.signerKeyId {string}   the delegation's verification-method
 *   id, in either DID form
 * @returns {string | undefined}   the published key multibase
 */
export function delegationSignerKey({
  doc,
  signerKeyId
}: {
  doc: PublishedKeyDocument
  signerKeyId: string
}): string | undefined {
  return delegationSignerKeyReader({ doc })(signerKeyId)
}

/**
 * The key a signer id names for attribution, as opposed to authorization: a
 * bare multibase is the key itself, a did:key id carries its key by that
 * method's spec whether or not the document still lists it, and an id under
 * the account DID names the key the document publishes for it, through the
 * reader when one is given. An id under the account DID that the document no
 * longer publishes (a key the edit already struck) names no key, and a caller
 * attributing by it falls back to comparing ids verbatim. This is what lets
 * a post-edit sweep still find what a withdrawn key signed.
 *
 * @param options {object}
 * @param options.id {string}   a verification-method id in either DID form,
 *   or a bare multibase
 * @param [options.signerKey] {DelegationSignerReader}   the reader over the
 *   verified document, when one is in hand
 * @returns {string | undefined}
 */
export function signerKeyNamed({
  id,
  signerKey
}: {
  id: string
  signerKey?: DelegationSignerReader
}): string | undefined {
  if (!id.startsWith('did:')) {
    return id
  }
  return didKeyMultibase(id) ?? signerKey?.(id)
}

/**
 * Whether two signer ids name one signer for attribution: the same id
 * verbatim, or two ids that each name a key ({@link signerKeyNamed}) and
 * name the same one. The verbatim arm is what keeps a key the document
 * already struck attributable by its exact id, which a torn ceremony's
 * post-edit sweep depends on.
 *
 * @param options {object}
 * @param options.signerId {string}   a verification-method id in either DID
 *   form, or a bare multibase
 * @param options.otherId {string}   the id to compare it with, in the same
 *   forms
 * @param [options.signerKey] {DelegationSignerReader}   the reader over the
 *   verified document, when one is in hand
 * @returns {boolean}
 */
export function sameSigner({
  signerId,
  otherId,
  signerKey
}: {
  signerId: string
  otherId: string
  signerKey?: DelegationSignerReader
}): boolean {
  if (signerId === otherId) {
    return true
  }
  const key = signerKeyNamed({ id: signerId, signerKey })
  return key !== undefined && signerKeyNamed({ id: otherId, signerKey }) === key
}

/**
 * The current-key-set rule for a recorded delegation: does the document still
 * publish a key under `capabilityDelegation` for the method that signed it?
 * That relation is the test rather than mere membership in the document,
 * because a delegation proof verifies only against a method published for the
 * delegation purpose as the document resolves NOW. A key kept under
 * `authentication` or `keyAgreement` but dropped from `capabilityDelegation`
 * signs nothing the server will accept, so it must read as rotted here too.
 * A `false` is exactly "this recorded grant has rotted" -- the signal behind a
 * re-mint or a health nudge.
 *
 * The read is {@link delegationSignerKey}'s, so the did:key and did:webvh
 * forms of one key agree (a delegation signed before the account's
 * controller was promoted names the same key under a different DID), and a
 * member whose id fragment and `publicKeyMultibase` disagree is known by the
 * key it publishes.
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
 *   verification-method id, in either DID form
 * @returns {boolean}
 */
export function delegationKeyInDocument({
  doc,
  delegationKeyId
}: {
  doc: PublishedKeyDocument
  delegationKeyId?: string
}): boolean {
  return (
    delegationKeyId !== undefined &&
    delegationSignerKey({ doc, signerKeyId: delegationKeyId }) !== undefined
  )
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
 * Attributes every listed client's ACTIVE update key from the log in ONE
 * forward pass -- the single-pass twin of {@link clientAddIndexes}, so a
 * listing never walks the log tail once per client. A client's initial key is
 * whatever the entry publishing its verification methods revealed, and each
 * later entry that retired the attributed key while revealing exactly one
 * replacement is that client's self-rotation. A client attributes to
 * `undefined` on any ambiguity (an entry revealing several keys beside the
 * client's methods, a retirement with several candidate replacements) or when
 * the attributed key is not authorized by the final entry.
 *
 * Each entry's revealed set is computed once and applied to every client
 * whose key that entry retired, which is what the per-client walk recomputed
 * per client. The pass starts at the earliest enrollment it is asked about
 * and, for one client, is the tail walk from that client's add entry.
 *
 * @param options {object}
 * @param options.params {Array<{ updateKeys: string[]; nextKeyHashes: string[] }>}
 *   the log's effective parameters, one entry per log entry
 * @param options.addIndexes {Map<string, number>}   each client's
 *   signing-key multibase to the entry that published its verification
 *   methods
 * @returns {Map<string, string | undefined>}   each client's signing-key
 *   multibase to its attributed active update key, `undefined` where the
 *   attribution cannot isolate a single key
 */
function attributeActiveUpdateKeys({
  params,
  addIndexes
}: {
  params: Array<{ updateKeys: string[]; nextKeyHashes: string[] }>
  addIndexes: Map<string, number>
}): Map<string, string | undefined> {
  const active = new Map<string, string | undefined>()
  // Clients grouped by the entry that added them, so each entry's pass picks
  // up its own newcomers without rescanning the map.
  const addedAt = new Map<number, string[]>()
  for (const [signingKeyMultibase, addIndex] of addIndexes) {
    const group = addedAt.get(addIndex)
    if (group) {
      group.push(signingKeyMultibase)
    } else {
      addedAt.set(addIndex, [signingKeyMultibase])
    }
  }
  if (addedAt.size === 0) {
    return active
  }
  // Nothing before the earliest enrollment can touch a listed client.
  const first = Math.min(...addedAt.keys())
  for (let index = first; index < params.length; index++) {
    // An entry's `updateKeys` is a handful of keys, so membership is a scan
    // rather than a Set built per entry.
    const authorized = params[index]!.updateKeys
    // Lazily computed: most entries retire nobody's key.
    let revealed: string[] | undefined
    for (const [signingKeyMultibase, key] of active) {
      if (key === undefined || authorized.includes(key)) {
        continue
      }
      revealed ??= addedUpdateKeys(params, index)
      active.set(
        signingKeyMultibase,
        revealed.length === 1 ? revealed[0] : undefined
      )
    }
    for (const signingKeyMultibase of addedAt.get(index) ?? []) {
      revealed ??= addedUpdateKeys(params, index)
      active.set(
        signingKeyMultibase,
        revealed.length === 1 ? revealed[0] : undefined
      )
    }
  }
  const final = params[params.length - 1]!.updateKeys
  for (const [signingKeyMultibase, key] of active) {
    if (key !== undefined && !final.includes(key)) {
      active.set(signingKeyMultibase, undefined)
    }
  }
  return active
}

/**
 * The index of the entry that published a client's verification methods (its
 * enrollment moment, and the attribution anchor for its update key), or `-1`
 * when the log never published them. Keyed on the signing key's multibase as
 * the entry's document publishes it under `capabilityInvocation`
 * (`relationKeyMultibases`, the same read as `enrolledClientKeyMultibases`).
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
    relationKeyMultibases({
      doc: entry.state,
      relation: 'capabilityInvocation'
    }).has(signingKeyMultibase)
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
    : attributeActiveUpdateKeys({
        params: effectiveParameters(log),
        addIndexes: new Map([[signingKeyMultibase, addIndex]])
      }).get(signingKeyMultibase)
}

/**
 * A map from each LISTED client's signing-key multibase to the index of the
 * FIRST entry that published it under `capabilityInvocation` -- the listed
 * clients' enrollment moments in one forward pass, so a listing attributes
 * every client without rescanning. Clients the final document no longer lists
 * (revoked ones) are never entered, so the attribution pass that follows never
 * tracks them. A multibase the log never published is absent from the map.
 *
 * @param options {object}
 * @param options.log {DIDLog}
 * @param options.signingKeyMultibases {Set<string>}   the listed clients
 * @returns {Map<string, number>}
 */
function clientAddIndexes({
  log,
  signingKeyMultibases
}: {
  log: DIDLog
  signingKeyMultibases: Set<string>
}): Map<string, number> {
  const addIndexes = new Map<string, number>()
  for (const [index, entry] of log.entries()) {
    if (addIndexes.size === signingKeyMultibases.size) {
      break
    }
    for (const signingKeyMultibase of relationKeyMultibases({
      doc: entry.state,
      relation: 'capabilityInvocation'
    })) {
      if (
        signingKeyMultibases.has(signingKeyMultibase) &&
        !addIndexes.has(signingKeyMultibase)
      ) {
        addIndexes.set(signingKeyMultibase, index)
      }
    }
  }
  return addIndexes
}

/**
 * The enrolled clients' signing verification-method ids, in document order:
 * the one read of "which methods are enrolled clients" the listing and the
 * last-client rule share. The convention is `capabilityInvocation`
 * membership (see the module doc) -- an enrolled client publishes its
 * signing key there, while a credential's key-agreement key, its ladder VM,
 * a transient annex VM, and the KMS convenience key never appear under it.
 * A future convention that put a non-client key under `capabilityInvocation`
 * would be corrected here, once, instead of at each decider: a plain forget
 * counting that key would strand an account, and the last-client transition
 * would refuse an account it should transition.
 *
 * @param options {object}
 * @param options.doc {object}   a locally verified account document
 * @returns {string[]}
 */
export function enrolledClientVmIds({
  doc
}: {
  doc: { capabilityInvocation?: Array<string | { id?: string }> }
}): string[] {
  return relationIds(doc.capabilityInvocation)
}

/**
 * Whether a verification method is the account's LAST enrolled client: the
 * document lists this method as an enrolled client
 * ({@link enrolledClientVmIds}) and no other. A document that does not list
 * it at all is not this client standing alone, which is why membership is
 * asked alongside exclusivity. The plain forget refuses on `true` (removing
 * the client would strand the account), and the last-client transition
 * refuses on `false` (another client remains, so the ordinary forget
 * applies) -- opposite failures decided by one predicate.
 *
 * @param options {object}
 * @param options.doc {object}   a locally verified account document
 * @param options.signingVmId {string}   the client's signing
 *   verification-method id
 * @returns {boolean}
 */
export function isLastEnrolledClient({
  doc,
  signingVmId
}: {
  doc: { capabilityInvocation?: Array<string | { id?: string }> }
  signingVmId: string
}): boolean {
  const enrolled = enrolledClientVmIds({ doc })
  return (
    enrolled.includes(signingVmId) && enrolled.every(id => id === signingVmId)
  )
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
  // Each enrolled client's signing key is the key its `capabilityInvocation`
  // member publishes, in document order, deduplicated: the same read as
  // `enrolledClientKeyMultibases`, so the listing and the key census name
  // the same keys. A member publishing no key lists no client.
  const signingKeyMultibases = [...enrolledClientKeyMultibases({ doc })]
  // The entry that published each client's verification methods -- its
  // enrollment moment, and the attribution anchor for its update key.
  const addIndexes = clientAddIndexes({
    log,
    signingKeyMultibases: new Set(signingKeyMultibases)
  })
  // Every client's active update key, attributed in one forward pass.
  const updateKeys = attributeActiveUpdateKeys({ params, addIndexes })
  // Every keyAgreement method, grouped by controller, in one pass -- keying by
  // controller string picks up only MARKED methods (a client's own), since the
  // account DID controller a recovery code's unmarked method carries is never
  // looked up below.
  const keyAgreementIndex = markedKeyAgreementIndex({ doc })
  const clients: EnrolledWebvhClient[] = []
  for (const signingKeyMultibase of signingKeyMultibases) {
    const addIndex = addIndexes.get(signingKeyMultibase)
    clients.push({
      signingKeyMultibase,
      keyAgreementKeyMultibases:
        keyAgreementIndex.get(
          clientKeyAgreementController({ signingKeyMultibase })
        ) ?? [],
      updateKeyMultibase: updateKeys.get(signingKeyMultibase),
      addedAt: addIndex === undefined ? undefined : log[addIndex]!.versionTime
    })
  }
  return clients
}
