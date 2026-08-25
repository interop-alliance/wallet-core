/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The client-key record: the contents codec and validation for the local
 * record every wallet client keeps its own key material in -- the random
 * 32-byte client seed behind its Ed25519 signing key and X25519 twin, the
 * cached user key delivered through the wrap-set roster, this
 * client's own did:webvh update-key seeds, the account controller the record
 * was bound for, (when the app stores it beside the keys) the account's
 * did:webvh pointer, and (while a self-enrollment or recovery-spend ceremony
 * is mid-flight) its pending-state group.
 *
 * Only the CONTENTS live here. Where the record is stored, and what wraps it,
 * stay with the app: a browser wallet wraps it under its unlock layer and puts
 * it in local storage, a mobile wallet puts the encoded JSON in an encrypted
 * database column. Both encode and validate identically, so a record one
 * wallet writes is a record the other accepts.
 *
 * Byte fields travel as base64url without padding; most are 32-byte secrets,
 * length-checked on the way back in (the pending group's `replacementCode` is
 * the one 16-byte exception, a recovery code's own length). Validation is
 * strict on purpose: an absent optional member is a record written before
 * that member existed, but a present-and-malformed one throws, because the
 * members that can be malformed are load-bearing -- the account's encrypted
 * collections are keyed on the user key, and the account's identity log can
 * only be extended with the update-key seeds, so proceeding without either
 * would silently orphan data or strand update authority.
 *
 * The optional `pending` member holds a self-enrollment or recovery-spend
 * ceremony's local pending state: written by the ceremony's required persist
 * hook after the reveal-and-commit entry and before the pivot (add /
 * add-and-retire) entry, sealed under the app's unlock layer with the rest of
 * the record, absent on enrolled records, and cleared at ceremony completion.
 *
 * Two ordering invariants govern how an app persists what this codec encodes.
 * Neither is enforceable here (the writes are the app's), and both are
 * durability rules a crash must not be able to break:
 *
 * 1. **The user key and the roster epoch pin persist atomically.** The pin is
 *    what
 *    refuses a rolled-back roster, so it must never advance without the key
 *    that authenticated the roster it advanced to -- and the key must never be
 *    adopted without the pin moving with it. One write, or none.
 * 2. **Rolled update-key seeds persist BEFORE the log entry that publishes
 *    them.** A did:webvh rotation writes `pendingStagedSeed` (and the rolled
 *    `updateSeed` / `stagedSeed`) first and publishes second: a tear after the
 *    persist costs an unused staged key, while a tear after the publish would
 *    strand the log with an update key this client no longer holds -- an
 *    account that can never be updated again.
 *
 * This module is a LEAF, exported as `@interop/wallet-core/keys/clientKeyRecord`
 * as well as through the `keys` subpath. Encoding a record is something the
 * storage layer does, far from any key operation, so it imports only a base64url
 * codec (its two key types are type-only imports, erased at compile time) and
 * reaches nothing in the crypto / EDV graph. A wallet whose storage tests run
 * without that graph loaded imports the leaf path directly.
 */
import { base64urlnopad } from '@scure/base'
import type { ClientWebvhUpdateKeys } from '../webvh/didWebvh.js'
import type { UserKey } from './userKey.js'

/**
 * The number of bytes every secret in the record carries, with one exception
 * (`pending.replacementCode`, a recovery code's own length -- see
 * `RECOVERY_CODE_BYTES`).
 */
const SECRET_BYTES = 32

/**
 * The number of bytes a recovery code carries, per the recovery-code member's
 * own definition. Restated here (rather than imported) because this module is
 * a dependency-light leaf and must not import from `recovery/`.
 */
const RECOVERY_CODE_BYTES = 16

/**
 * A ceremony's local pending state, decoded: written by a self-enrollment or
 * recovery-spend ceremony's required persist hook between its reveal-and-commit
 * entry and its pivot (add / add-and-retire) entry. See the module doc.
 *
 * `ceremony` says which ceremony wrote the pending record, so a spend-written
 * record is never mistaken for a seeded self-enrollment. `builtOnHead` is the
 * account-log head (SCID plus versionId) the ceremony's pivot entry was built
 * on, so a resume refuses to rebuild over a served log that has not reached
 * that head, or that swapped genesis. `unwrapKey` and `replacementCode` belong
 * to the recovery spend alone: `unwrapKey` carries the spent recovery code's
 * key-agreement secret so the first post-pivot roster escrow stays
 * re-derivable, and `replacementCode` carries the once-per-ceremony
 * replacement recovery code's bytes so a re-run reuses the same unlock Space
 * address.
 */
export interface ClientKeyRecordPending {
  ceremony: 'recovery-spend' | 'self-enrollment'
  builtOnHead: { scid: string; versionId: string }
  unwrapKey?: Uint8Array
  replacementCode?: Uint8Array
}

/**
 * A client-key record's contents, decoded.
 *
 * `clientSeed` is the only always-present member: the rest are absent on
 * records written before that member existed (a user-key-less account, a record
 * written before the update keys became client-held, a first client whose own
 * did:key IS the account controller), or simply not stored by the app.
 */
export interface ClientKeyRecord {
  clientSeed: Uint8Array
  userKey?: UserKey
  webvhUpdateKeys?: ClientWebvhUpdateKeys
  controller?: string
  pointerDid?: string
  pending?: ClientKeyRecordPending
}

/**
 * A client-key record's contents as they are stored: plain JSON, every byte
 * field base64url-encoded without padding. This is what an app wraps, seals,
 * or stringifies -- the codec never decides where it goes.
 */
export interface ClientKeyRecordJson {
  clientSeed: string
  userKey?: { id: string; secret: string; signingSeed?: string }
  webvh?: {
    updateSeed: string
    stagedSeed: string
    pendingStagedSeed?: string
  }
  controller?: string
  pointerDid?: string
  pending?: {
    ceremony: 'recovery-spend' | 'self-enrollment'
    builtOnHead: { scid: string; versionId: string }
    unwrapKey?: string
    replacementCode?: string
  }
  createdAt?: string
}

/**
 * A record whose every member is present: what an ENROLLED client holds once
 * the enrollment ceremony has landed (a key set, a delivered user key, its own
 * update-key seeds, and the account it belongs to).
 */
export interface EnrolledClientKeyRecord extends ClientKeyRecord {
  userKey: UserKey
  webvhUpdateKeys: ClientWebvhUpdateKeys
  controller: string
  pointerDid: string
}

/**
 * Decodes one base64url byte field, checking its length.
 *
 * @param options {object}
 * @param options.value {unknown}   the encoded member
 * @param options.name {string}   the member's name, for the error message
 * @param [options.length] {number}   the required decoded length; defaults to
 *   `SECRET_BYTES`
 * @returns {Uint8Array}
 */
function decodeSecret({
  value,
  name,
  length = SECRET_BYTES
}: {
  value: unknown
  name: string
  length?: number
}): Uint8Array {
  if (typeof value !== 'string') {
    throw new Error(`Client-key record ${name} is missing.`)
  }
  let bytes: Uint8Array
  try {
    bytes = base64urlnopad.decode(value)
  } catch (err) {
    throw new Error(`Client-key record ${name} is not base64url.`, {
      cause: err
    })
  }
  if (bytes.length !== length) {
    throw new Error(`Client-key record ${name} is not ${length} bytes.`)
  }
  return bytes
}

/**
 * Parses and validates the optional `userKey` member. An absent member resolves
 * to `undefined` (a record written for an account minted before the user key);
 * a present-but-malformed one throws.
 *
 * The signing seed is absent on a user key adopted from a roster rotation (the
 * roster wraps the key-agreement secret alone); when present it must be
 * well-formed.
 *
 * @param value {unknown}   the record's `userKey` member
 * @returns {UserKey | undefined}
 */
export function parseClientRecordUserKey(value: unknown): UserKey | undefined {
  if (value === undefined) {
    return undefined
  }
  if (value === null || typeof value !== 'object') {
    throw new Error('Client-key record has a malformed user key.')
  }
  const { id, secret, signingSeed } = value as {
    id?: unknown
    secret?: unknown
    signingSeed?: unknown
  }
  if (typeof id !== 'string' || !id) {
    throw new Error('Client-key record user key is missing its key id.')
  }
  const secretBytes = decodeSecret({
    value: secret,
    name: 'user key material'
  })
  if (signingSeed === undefined) {
    return { id, secret: secretBytes }
  }
  return {
    id,
    secret: secretBytes,
    signingSeed: decodeSecret({
      value: signingSeed,
      name: 'user key signing seed'
    })
  }
}

/**
 * Parses and validates the optional `webvh` member: this client's did:webvh
 * update-key seeds. An absent member resolves to `undefined` (a record written
 * before the update keys became client-held); a present-but-malformed one
 * throws.
 *
 * @param value {unknown}   the record's `webvh` member
 * @returns {ClientWebvhUpdateKeys | undefined}
 */
export function parseClientRecordWebvhKeys(
  value: unknown
): ClientWebvhUpdateKeys | undefined {
  if (value === undefined) {
    return undefined
  }
  if (value === null || typeof value !== 'object') {
    throw new Error('Client-key record has malformed did:webvh update keys.')
  }
  const { updateSeed, stagedSeed, pendingStagedSeed } = value as {
    updateSeed?: unknown
    stagedSeed?: unknown
    pendingStagedSeed?: unknown
  }
  return {
    updateSeed: decodeSecret({
      value: updateSeed,
      name: 'did:webvh update seed'
    }),
    stagedSeed: decodeSecret({
      value: stagedSeed,
      name: 'did:webvh staged seed'
    }),
    ...(pendingStagedSeed !== undefined
      ? {
          pendingStagedSeed: decodeSecret({
            value: pendingStagedSeed,
            name: 'did:webvh pending staged seed'
          })
        }
      : {})
  }
}

/**
 * Parses and validates the optional `pending` member: a self-enrollment or
 * recovery-spend ceremony's local pending state. An absent member resolves to
 * `undefined` (an enrolled record, or a completed ceremony); a
 * present-but-malformed one throws.
 *
 * `unwrapKey` and `replacementCode` belong to the recovery spend alone --
 * present under `ceremony: 'self-enrollment'`, either throws.
 *
 * @param value {unknown}   the record's `pending` member
 * @returns {ClientKeyRecordPending | undefined}
 */
export function parseClientRecordPending(
  value: unknown
): ClientKeyRecordPending | undefined {
  if (value === undefined) {
    return undefined
  }
  if (value === null || typeof value !== 'object') {
    throw new Error('Client-key record pending state is malformed.')
  }
  const { ceremony, builtOnHead, unwrapKey, replacementCode } = value as {
    ceremony?: unknown
    builtOnHead?: unknown
    unwrapKey?: unknown
    replacementCode?: unknown
  }
  if (ceremony !== 'recovery-spend' && ceremony !== 'self-enrollment') {
    throw new Error('Client-key record pending state has an unknown ceremony.')
  }
  if (builtOnHead === null || typeof builtOnHead !== 'object') {
    throw new Error(
      'Client-key record pending state has a malformed built-on head.'
    )
  }
  const { scid, versionId } = builtOnHead as {
    scid?: unknown
    versionId?: unknown
  }
  if (typeof scid !== 'string' || !scid) {
    throw new Error(
      'Client-key record pending state has a malformed built-on head.'
    )
  }
  if (typeof versionId !== 'string' || !versionId) {
    throw new Error(
      'Client-key record pending state has a malformed built-on head.'
    )
  }
  if (ceremony === 'self-enrollment') {
    if (unwrapKey !== undefined || replacementCode !== undefined) {
      throw new Error(
        'Client-key record pending state carries recovery-spend members under self-enrollment.'
      )
    }
    return { ceremony, builtOnHead: { scid, versionId } }
  }
  return {
    ceremony,
    builtOnHead: { scid, versionId },
    ...(unwrapKey !== undefined
      ? {
          unwrapKey: decodeSecret({
            value: unwrapKey,
            name: 'pending unwrap key'
          })
        }
      : {}),
    ...(replacementCode !== undefined
      ? {
          replacementCode: decodeSecret({
            value: replacementCode,
            name: 'pending replacement code',
            length: RECOVERY_CODE_BYTES
          })
        }
      : {})
  }
}

/**
 * Encodes one byte field, checking its length -- the encode-side twin of
 * {@link decodeSecret}, so a record this codec writes is always a record it
 * can read back.
 *
 * @param options {object}
 * @param options.value {Uint8Array}   the secret
 * @param options.name {string}   the member's name, for the error message
 * @param [options.length] {number}   the required length; defaults to
 *   `SECRET_BYTES`
 * @returns {string}
 */
function encodeSecret({
  value,
  name,
  length = SECRET_BYTES
}: {
  value: Uint8Array
  name: string
  length?: number
}): string {
  if (value.length !== length) {
    throw new Error(`Client-key record ${name} is not ${length} bytes.`)
  }
  return base64urlnopad.encode(value)
}

/**
 * Encodes a client-key record's contents for storage: base64url byte fields,
 * optional members omitted rather than written as null. Every secret is
 * length-checked on the way out, exactly as the decoder checks it on the way
 * back in -- an undecodable stored record is a lost account.
 *
 * @param options {object}
 * @param options.clientSeed {Uint8Array}   this client's 32-byte seed
 * @param [options.userKey] {UserKey}   the cached user key
 * @param [options.webvhUpdateKeys] {ClientWebvhUpdateKeys}   this client's
 *   did:webvh update-key seeds
 * @param [options.controller] {string}   the account controller this key set
 *   was bound for -- on an enrolled (non-first) client it differs from the
 *   client's own did:key
 * @param [options.pointerDid] {string}   the account's did:webvh
 * @param [options.pending] {ClientKeyRecordPending}   a self-enrollment or
 *   recovery-spend ceremony's local pending state
 * @param [options.createdAt] {string}   when the record was written; defaults
 *   to now
 * @returns {ClientKeyRecordJson}
 */
export function encodeClientKeyRecord({
  clientSeed,
  userKey,
  webvhUpdateKeys,
  controller,
  pointerDid,
  pending,
  createdAt = new Date().toISOString()
}: {
  clientSeed: Uint8Array
  userKey?: UserKey
  webvhUpdateKeys?: ClientWebvhUpdateKeys
  controller?: string
  pointerDid?: string
  pending?: ClientKeyRecordPending
  createdAt?: string
}): ClientKeyRecordJson {
  if (
    pending?.ceremony === 'self-enrollment' &&
    (pending.unwrapKey !== undefined || pending.replacementCode !== undefined)
  ) {
    throw new Error(
      'Client-key record pending state carries recovery-spend members under self-enrollment.'
    )
  }
  return {
    clientSeed: encodeSecret({ value: clientSeed, name: 'client seed' }),
    ...(userKey
      ? {
          userKey: {
            id: userKey.id,
            secret: encodeSecret({
              value: userKey.secret,
              name: 'user key material'
            }),
            ...(userKey.signingSeed
              ? {
                  signingSeed: encodeSecret({
                    value: userKey.signingSeed,
                    name: 'user key signing seed'
                  })
                }
              : {})
          }
        }
      : {}),
    ...(webvhUpdateKeys
      ? {
          webvh: {
            updateSeed: encodeSecret({
              value: webvhUpdateKeys.updateSeed,
              name: 'did:webvh update seed'
            }),
            stagedSeed: encodeSecret({
              value: webvhUpdateKeys.stagedSeed,
              name: 'did:webvh staged seed'
            }),
            ...(webvhUpdateKeys.pendingStagedSeed
              ? {
                  pendingStagedSeed: encodeSecret({
                    value: webvhUpdateKeys.pendingStagedSeed,
                    name: 'did:webvh pending staged seed'
                  })
                }
              : {})
          }
        }
      : {}),
    ...(controller ? { controller } : {}),
    ...(pointerDid ? { pointerDid } : {}),
    ...(pending
      ? {
          pending: {
            ceremony: pending.ceremony,
            builtOnHead: { ...pending.builtOnHead },
            ...(pending.unwrapKey !== undefined
              ? {
                  unwrapKey: encodeSecret({
                    value: pending.unwrapKey,
                    name: 'pending unwrap key'
                  })
                }
              : {}),
            ...(pending.replacementCode !== undefined
              ? {
                  replacementCode: encodeSecret({
                    value: pending.replacementCode,
                    name: 'pending replacement code',
                    length: RECOVERY_CODE_BYTES
                  })
                }
              : {})
          }
        }
      : {}),
    createdAt
  }
}

/**
 * Decodes and validates a stored client-key record's contents. Throws on any
 * malformed member -- see the module doc for why nothing here is tolerated
 * into a degraded record.
 *
 * @param options {object}
 * @param options.contents {unknown}   the stored JSON contents (an app that
 *   stores a string parses it first)
 * @returns {ClientKeyRecord}
 */
export function decodeClientKeyRecord({
  contents
}: {
  contents: unknown
}): ClientKeyRecord {
  if (contents === null || typeof contents !== 'object') {
    throw new Error('Malformed client-key record.')
  }
  const { clientSeed, userKey, webvh, controller, pointerDid, pending } =
    contents as {
      clientSeed?: unknown
      userKey?: unknown
      webvh?: unknown
      controller?: unknown
      pointerDid?: unknown
      pending?: unknown
    }
  const seed = decodeSecret({ value: clientSeed, name: 'client seed' })
  if (
    controller !== undefined &&
    (typeof controller !== 'string' || !controller)
  ) {
    throw new Error('Client-key record has a malformed controller.')
  }
  if (
    pointerDid !== undefined &&
    (typeof pointerDid !== 'string' || !pointerDid)
  ) {
    throw new Error('Client-key record has a malformed account pointer DID.')
  }
  const parsedUserKey = parseClientRecordUserKey(userKey)
  const webvhUpdateKeys = parseClientRecordWebvhKeys(webvh)
  const parsedPending = parseClientRecordPending(pending)
  return {
    clientSeed: seed,
    ...(parsedUserKey ? { userKey: parsedUserKey } : {}),
    ...(webvhUpdateKeys ? { webvhUpdateKeys } : {}),
    ...(controller ? { controller } : {}),
    ...(pointerDid ? { pointerDid } : {}),
    ...(parsedPending ? { pending: parsedPending } : {})
  }
}

/**
 * Narrows a decoded record to a complete enrolled-client key set, throwing
 * when any member an enrolled client needs is absent. For an app whose stored
 * records are only ever written by the enrollment ceremony, this turns "the
 * codec tolerates older records" into a single checked boundary.
 *
 * @param options {object}
 * @param options.record {ClientKeyRecord}
 * @returns {EnrolledClientKeyRecord}
 */
export function assertEnrolledClientKeyRecord({
  record
}: {
  record: ClientKeyRecord
}): EnrolledClientKeyRecord {
  const { userKey, webvhUpdateKeys, controller, pointerDid } = record
  if (!userKey) {
    throw new Error('Client-key record carries no user key.')
  }
  if (!webvhUpdateKeys) {
    throw new Error('Client-key record carries no did:webvh update keys.')
  }
  if (!controller) {
    throw new Error('Client-key record carries no account controller.')
  }
  if (!pointerDid) {
    throw new Error('Client-key record carries no account pointer DID.')
  }
  return { ...record, userKey, webvhUpdateKeys, controller, pointerDid }
}

/**
 * The non-throwing twin of {@link assertEnrolledClientKeyRecord}: the same
 * four-member test (userKey, webvhUpdateKeys, controller, pointerDid all
 * present), deliberately only those four -- a `pending` member does not affect
 * the result, since the pending discriminator apps route on stays the absence
 * of `userKey`. Where the assert is a checked boundary that throws naming the
 * missing member, this guard is for an app that needs to ROUTE on the record's
 * shape (enrolled / pending / absent) rather than fail on it.
 *
 * Takes the record bare (like the per-member parsers above) so the predicate
 * narrows the caller's own variable.
 *
 * @param record {ClientKeyRecord}
 * @returns {boolean}
 */
export function isEnrolledClientKeyRecord(
  record: ClientKeyRecord
): record is EnrolledClientKeyRecord {
  return Boolean(
    record.userKey &&
    record.webvhUpdateKeys &&
    record.controller &&
    record.pointerDid
  )
}
