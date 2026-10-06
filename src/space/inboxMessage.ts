/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The inbox message envelope: the one message kind a party POSTs to a
 * wallet's `inbox` collection, or a wallet POSTs to a party's inbox. Shape:
 * `{ type: 'Grant', actor: <did:key>, object: { zcaps: [ <zcap>, ... ] } }`,
 * content type `application/json`, with no `@context`.
 *
 * There is one message kind. An invitation and a renewal are told apart by
 * the zcap target. A zcap targeting the sender's own inbox is a channel
 * capability, and one targeting the recipient's Space is a renewed grant.
 * Every wallet and any agent built on this package share the shape.
 */
import { ACTIVITY_TYPE } from './activity.js'

/**
 * A delegated zcap carried in an inbox message, verbatim. The parser checks
 * the members named here and keeps every other member as it arrived.
 */
export interface InboxMessageZcap {
  id: string
  controller: string
  invocationTarget: string
  proof: Record<string, unknown> | Record<string, unknown>[]
  [member: string]: unknown
}

/**
 * The inbox message envelope. `type` is the bare string `'Grant'` (the
 * history Grant activity row carries a one-member array instead).
 */
export interface InboxGrantMessage {
  type: 'Grant'
  actor: string
  object: { zcaps: InboxMessageZcap[] }
}

function isDidKey(value: unknown): value is string {
  return typeof value === 'string' && value.startsWith('did:key:')
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isInboxMessageZcap(value: unknown): value is InboxMessageZcap {
  if (!isJsonObject(value)) {
    return false
  }
  const { id, controller, invocationTarget, proof } = value
  if (
    typeof id !== 'string' ||
    id.length === 0 ||
    typeof controller !== 'string' ||
    typeof invocationTarget !== 'string'
  ) {
    return false
  }
  if (Array.isArray(proof)) {
    return proof.length > 0 && proof.every(isJsonObject)
  }
  return isJsonObject(proof)
}

/**
 * Builds an inbox Grant message carrying the given zcaps verbatim.
 *
 * @param options {object}
 * @param options.actor {string}   the sender's did:key
 * @param options.zcaps {InboxMessageZcap[]}   the delegated zcaps, at least
 *   one
 * @returns {InboxGrantMessage}
 */
export function inboxGrantMessage({
  actor,
  zcaps
}: {
  actor: string
  zcaps: InboxMessageZcap[]
}): InboxGrantMessage {
  if (!isDidKey(actor)) {
    throw new TypeError('inbox message: `actor` must be a did:key DID.')
  }
  if (zcaps.length === 0) {
    throw new TypeError('inbox message: `zcaps` must not be empty.')
  }
  return { type: ACTIVITY_TYPE.Grant, actor, object: { zcaps } }
}

/**
 * Reads an inbox Grant message. Returns `undefined` for a body that is not
 * one: a non-object body, a `type` other than the bare string `'Grant'`, an
 * `actor` that is not a did:key, or an `object.zcaps` that is not a non-empty
 * array of zcaps each carrying `id`, `controller`, `invocationTarget`, and a
 * `proof`. Unknown members at any level are ignored and kept verbatim.
 *
 * @param body {unknown}   the parsed JSON body
 * @returns {InboxGrantMessage | undefined}
 */
export function parseInboxGrantMessage(
  body: unknown
): InboxGrantMessage | undefined {
  if (!isJsonObject(body)) {
    return undefined
  }
  const { type, actor, object } = body
  if (type !== ACTIVITY_TYPE.Grant) {
    return undefined
  }
  if (!isDidKey(actor)) {
    return undefined
  }
  if (!isJsonObject(object)) {
    return undefined
  }
  const { zcaps } = object
  if (
    !Array.isArray(zcaps) ||
    zcaps.length === 0 ||
    !zcaps.every(isInboxMessageZcap)
  ) {
    return undefined
  }
  return body as unknown as InboxGrantMessage
}
