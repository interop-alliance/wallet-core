/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The directory's two keyed values: the resource id where one party's entry
 * lives, and the tag over an entry's pairwise seed. Both are HMAC-SHA-256
 * under the collection's blinded-index key, domain-separated by the
 * `connections/v1` prefix and an arm name, so one key signs no two kinds of
 * input under the same bytes.
 *
 * The id is the first 16 bytes of
 * `HMAC-SHA-256(hmacKey, utf8('connections/v1' + '|' + armInput))`, formatted
 * with was-client's `edvIdFromBytes`. `armInput` is `'did:' + did` for a
 * party with a DID and `'writer:' + writerId` for a keyless writer. The
 * account DID is not an input.
 *
 * The seed tag is the full 32 bytes of
 * `HMAC-SHA-256(hmacKey, utf8('connections/v1' + '|' + 'seed:') || seedBytes)`,
 * base64url with no padding. The blinded-index key is wrapped to the user
 * key's KAK in the descriptor and the descriptor is log-governed, so the host
 * lacks it: a seed the host planted on an entry carries no tag that verifies,
 * and every site that turns a seed into a key checks the tag first.
 *
 * Keying the id stops the storage host from computing the id of a guessed
 * DID and probing for it. The protection lasts only while reads keep it: a
 * wallet does not GET an id derived from a DID the host or a request
 * supplied, except at consent for the party it is about to grant.
 */
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { equalBytes } from '@noble/ciphers/utils.js'
import { base64urlnopad } from '@scure/base'
import { edvIdFromBytes } from '@interop/was-client/edv/cipher'
import { decodeConnectionSeed } from './entry.js'

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
 * HMAC-SHA-256 under the blinded-index key, in either form.
 *
 * @param options {object}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.data {Uint8Array}
 * @returns {Promise<Uint8Array>}
 */
async function keyedMac({
  hmacKey,
  data
}: {
  hmacKey: ConnectionIdKey
  data: Uint8Array
}): Promise<Uint8Array> {
  return hmacKey instanceof Uint8Array
    ? hmac(sha256, hmacKey, data)
    : hmacKey.sign({ data })
}

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
  const mac = await keyedMac({ hmacKey, data })
  return edvIdFromBytes(mac.subarray(0, 16))
}

/**
 * The tag bytes over a seed: the full MAC over the `seed:` arm's prefix
 * followed by the raw seed bytes.
 *
 * @param options {object}
 * @param options.hmacKey {ConnectionIdKey}
 * @param options.seedBytes {Uint8Array}
 * @returns {Promise<Uint8Array>}
 */
async function seedTagBytes({
  hmacKey,
  seedBytes
}: {
  hmacKey: ConnectionIdKey
  seedBytes: Uint8Array
}): Promise<Uint8Array> {
  const prefix = new TextEncoder().encode(`${CONNECTIONS_ID_PREFIX}|seed:`)
  const data = new Uint8Array(prefix.length + seedBytes.length)
  data.set(prefix)
  data.set(seedBytes, prefix.length)
  return keyedMac({ hmacKey, data })
}

/**
 * The tag an entry stores beside its pairwise `seed`: {@link seedTagBytes}
 * in the seed's own encoding. A seed that is not 32 bytes of base64url is
 * refused with a `TypeError`.
 *
 * @param options {object}
 * @param options.hmacKey {ConnectionIdKey}   the collection's blinded-index
 *   key
 * @param options.seed {string}   the seed, base64url with no padding
 * @returns {Promise<string>}
 */
export async function connectionSeedTag({
  hmacKey,
  seed
}: {
  hmacKey: ConnectionIdKey
  seed: string
}): Promise<string> {
  const seedBytes = decodeConnectionSeed(seed)
  if (seedBytes === undefined) {
    throw new TypeError(
      'A connection seed is 43 characters of base64url with no padding, ' +
        'decoding to 32 bytes.'
    )
  }
  return base64urlnopad.encode(await seedTagBytes({ hmacKey, seedBytes }))
}

/**
 * Whether a stored `seedTag` is the tag of a stored `seed` under this
 * directory's blinded-index key. A malformed seed or tag reads as `false`.
 * Every site that turns a seed into a key asks this first and fails closed
 * on `false`.
 *
 * @param options {object}
 * @param options.hmacKey {ConnectionIdKey}   the collection's blinded-index
 *   key
 * @param options.seed {string}   the stored seed
 * @param options.seedTag {string}   the stored tag
 * @returns {Promise<boolean>}
 */
export async function verifyConnectionSeedTag({
  hmacKey,
  seed,
  seedTag
}: {
  hmacKey: ConnectionIdKey
  seed: string
  seedTag: string
}): Promise<boolean> {
  const seedBytes = decodeConnectionSeed(seed)
  const tagBytes = decodeConnectionSeed(seedTag)
  if (seedBytes === undefined || tagBytes === undefined) {
    return false
  }
  return equalBytes(await seedTagBytes({ hmacKey, seedBytes }), tagBytes)
}
