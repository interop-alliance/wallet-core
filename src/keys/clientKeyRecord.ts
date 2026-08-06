/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The client-key record: the contents codec and validation for the local
 * record every wallet client keeps its own key material in -- the random
 * 32-byte client seed behind its Ed25519 signing key and X25519 twin, the
 * cached user key delivered through the wrap-set roster, this
 * client's own did:webvh update-key seeds, the account controller the record
 * was bound for, and (when the app stores it beside the keys) the account's
 * did:webvh pointer.
 *
 * Only the CONTENTS live here. Where the record is stored, and what wraps it,
 * stay with the app: a browser wallet wraps it under its unlock layer and puts
 * it in local storage, a mobile wallet puts the encoded JSON in an encrypted
 * database column. Both encode and validate identically, so a record one
 * wallet writes is a record the other accepts.
 *
 * Byte fields travel as base64url without padding; every one of them is a
 * 32-byte secret and is length-checked on the way back in. Validation is strict
 * on purpose: an absent optional member is a record written before that member
 * existed, but a present-and-malformed one throws, because both of the members
 * that can be malformed are load-bearing -- the account's encrypted collections
 * are keyed on the user key, and the account's identity log can only be
 * extended with the update-key seeds, so proceeding without either would
 * silently orphan data or strand update authority.
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
 * The number of bytes every secret in the record carries.
 */
const SECRET_BYTES = 32

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
 * @returns {Uint8Array}
 */
function decodeSecret({
  value,
  name
}: {
  value: unknown
  name: string
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
  if (bytes.length !== SECRET_BYTES) {
    throw new Error(`Client-key record ${name} is not ${SECRET_BYTES} bytes.`)
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
 * Encodes one byte field, checking its length -- the encode-side twin of
 * {@link decodeSecret}, so a record this codec writes is always a record it
 * can read back.
 *
 * @param options {object}
 * @param options.value {Uint8Array}   the secret
 * @param options.name {string}   the member's name, for the error message
 * @returns {string}
 */
function encodeSecret({
  value,
  name
}: {
  value: Uint8Array
  name: string
}): string {
  if (value.length !== SECRET_BYTES) {
    throw new Error(`Client-key record ${name} is not ${SECRET_BYTES} bytes.`)
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
  createdAt = new Date().toISOString()
}: {
  clientSeed: Uint8Array
  userKey?: UserKey
  webvhUpdateKeys?: ClientWebvhUpdateKeys
  controller?: string
  pointerDid?: string
  createdAt?: string
}): ClientKeyRecordJson {
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
  const { clientSeed, userKey, webvh, controller, pointerDid } = contents as {
    clientSeed?: unknown
    userKey?: unknown
    webvh?: unknown
    controller?: unknown
    pointerDid?: unknown
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
  return {
    clientSeed: seed,
    ...(parsedUserKey ? { userKey: parsedUserKey } : {}),
    ...(webvhUpdateKeys ? { webvhUpdateKeys } : {}),
    ...(controller ? { controller } : {}),
    ...(pointerDid ? { pointerDid } : {})
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
