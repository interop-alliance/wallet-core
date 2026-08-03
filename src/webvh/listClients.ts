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
 * (deliberately unmarked) and the KMS-held conveniences only under
 * `authentication` / `assertionMethod` -- so neither can ever surface in the
 * listing, structurally rather than by filtering.
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
 * The X25519 `keyAgreementKeyMultibase` is derived from the signing key (the
 * canonical Montgomery twin -- the same derivation every roster wrap uses)
 * rather than paired from the document, because a recovery continuation's
 * add-and-retire entry publishes two `keyAgreement` methods at once (the new
 * client's and the replacement code's) and the document deliberately carries
 * no marker to tell them apart.
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
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { effectiveParameters, relationIds } from './didWebvh.js'
import type { WebvhClientKeys } from './didWebvh.js'

/**
 * One enrolled wallet client as the log states it. `updateKeyMultibase` and
 * `addedAt` are absent when the log attribution cannot recover them (see the
 * module doc); a client with all three key members present is exactly a
 * `RevokedClientKeys`.
 */
export interface EnrolledWebvhClient extends WebvhClientKeys {
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
    const fragment = method.id?.split('#').pop()
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
  const multibase = delegationKeyId?.split('#').pop()
  if (!multibase) {
    return false
  }
  return documentKeyMultibases({ doc }).has(multibase)
}

/**
 * The multibase of an Ed25519 signing key's canonical X25519 twin -- the
 * key-agreement key the client's enrollment published and its roster wraps
 * are minted to.
 *
 * @param options {object}
 * @param options.signingKeyMultibase {string}
 * @returns {string}
 */
export function keyAgreementTwinMultibase({
  signingKeyMultibase
}: {
  signingKeyMultibase: string
}): string {
  const keyPair = new Ed25519VerificationKey({
    controller: `did:key:${signingKeyMultibase}`,
    publicKeyMultibase: signingKeyMultibase
  })
  const twin = X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
    keyPair
  })
  if (typeof twin.publicKeyMultibase !== 'string') {
    throw new Error(
      'did:webvh: converting the signing key to its X25519 twin produced no ' +
        'publicKeyMultibase.'
    )
  }
  return twin.publicKeyMultibase
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
 * @param options.log {DIDLog}
 * @param options.addIndex {number}   the entry that published the client's
 *   verification methods
 * @returns {string | undefined}
 */
function attributeActiveUpdateKey({
  log,
  addIndex
}: {
  log: DIDLog
  addIndex: number
}): string | undefined {
  const params = effectiveParameters(log)
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
      vmId => vmId.split('#')[1] === signingKeyMultibase
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
    : attributeActiveUpdateKey({ log, addIndex })
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
  const clients: EnrolledWebvhClient[] = []
  for (const vmId of relationIds(doc.capabilityInvocation)) {
    const signingKeyMultibase = vmId.split('#')[1]
    if (!signingKeyMultibase) {
      continue
    }
    // The entry that published this client's verification methods -- its
    // enrollment moment, and the attribution anchor for its update key.
    const addIndex = clientAddIndex({ log, signingKeyMultibase })
    clients.push({
      signingKeyMultibase,
      keyAgreementKeyMultibase: keyAgreementTwinMultibase({
        signingKeyMultibase
      }),
      updateKeyMultibase:
        addIndex === -1
          ? undefined
          : attributeActiveUpdateKey({ log, addIndex }),
      addedAt: addIndex === -1 ? undefined : log[addIndex]!.versionTime
    })
  }
  return clients
}
