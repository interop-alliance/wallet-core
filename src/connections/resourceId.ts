/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The directory's resource id: where one party's entry lives.
 *
 * The id is the first 16 bytes of
 * `HMAC-SHA-256(hmacKey, utf8('connections/v1' + '|' + armInput))`, formatted
 * with was-client's `edvIdFromBytes`. `hmacKey` is the collection's
 * blinded-index key. `armInput` is `'did:' + did` for a party with a DID and
 * `'writer:' + writerId` for a keyless writer. The account DID is not an
 * input.
 *
 * Keying the id stops the storage host from computing the id of a guessed
 * DID and probing for it. The protection lasts only while reads keep it: a
 * wallet does not GET an id derived from a DID the host or a request
 * supplied, except at consent for the party it is about to grant.
 */
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { edvIdFromBytes } from '@interop/was-client/edv/cipher'

/**
 * The domain prefix of every directory resource id.
 */
export const CONNECTIONS_ID_PREFIX = 'connections/v1'

/**
 * The collection's blinded-index key, in either form a wallet holds it: the
 * raw 32-byte secret, or the resolved key whose `sign` is HMAC-SHA-256 over
 * that secret (was-client's `BlindingKey`, as `resolveHmacKey` returns it).
 * Both derive the same ids.
 */
export type ConnectionIdKey =
  Uint8Array | { sign(options: { data: Uint8Array }): Promise<Uint8Array> }

/**
 * The resource id of a party's entry (`did`) or of a keyless writer's entry
 * (`writerId`). Exactly one of the two is given.
 *
 * @param options {object}
 * @param options.hmacKey {ConnectionIdKey}   the collection's blinded-index
 *   key
 * @param [options.did] {string}   the party's DID
 * @param [options.writerId] {string}   a keyless writer's `writerId`
 * @returns {Promise<string>}
 */
export async function connectionResourceId(
  options:
    | { hmacKey: ConnectionIdKey; did: string; writerId?: undefined }
    | { hmacKey: ConnectionIdKey; writerId: string; did?: undefined }
): Promise<string> {
  const { hmacKey, did, writerId } = options
  if ((did === undefined) === (writerId === undefined)) {
    throw new TypeError(
      'A connection resource id takes exactly one of "did" and "writerId".'
    )
  }
  const armInput = did !== undefined ? `did:${did}` : `writer:${writerId}`
  const data = new TextEncoder().encode(`${CONNECTIONS_ID_PREFIX}|${armInput}`)
  const mac =
    hmacKey instanceof Uint8Array
      ? hmac(sha256, hmacKey, data)
      : await hmacKey.sign({ data })
  return edvIdFromBytes(mac.subarray(0, 16))
}
