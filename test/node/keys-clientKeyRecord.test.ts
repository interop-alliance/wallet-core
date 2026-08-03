/**
 * Unit tests for the client-key record codec (`src/keys/clientKeyRecord.ts`):
 * the encode/decode round trip, the omit-rather-than-null encoding of absent
 * members, the tolerance of records written before an optional member existed,
 * the strict refusal of every malformed member, and the enrolled-record
 * narrowing.
 */
import { describe, expect, it } from 'vitest'
import { base64urlnopad } from '@scure/base'
import {
  assertEnrolledClientKeyRecord,
  decodeClientKeyRecord,
  encodeClientKeyRecord
} from '../../src/keys/clientKeyRecord.js'

/**
 * A deterministic 32-byte secret.
 *
 * @param fill {number}
 * @returns {Uint8Array}
 */
function secret(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill)
}

const fullRecord = {
  clientSeed: secret(1),
  puk: { id: 'did:key:zPuk', secret: secret(2), signingSeed: secret(3) },
  webvhUpdateKeys: {
    updateSeed: secret(4),
    stagedSeed: secret(5),
    pendingStagedSeed: secret(6)
  },
  controller: 'did:key:zController',
  pointerDid: 'did:webvh:scid:example.com'
}

describe('encodeClientKeyRecord / decodeClientKeyRecord', () => {
  it('round-trips a complete record', () => {
    const contents = encodeClientKeyRecord(fullRecord)
    expect(decodeClientKeyRecord({ contents })).toEqual(fullRecord)
  })

  it('omits absent optional members rather than writing null', () => {
    const contents = encodeClientKeyRecord({ clientSeed: secret(1) })
    expect(Object.keys(contents).sort()).toEqual(['clientSeed', 'createdAt'])
    expect(decodeClientKeyRecord({ contents })).toEqual({
      clientSeed: secret(1)
    })
  })

  it('omits a PUK signing seed a rotation did not deliver', () => {
    const contents = encodeClientKeyRecord({
      clientSeed: secret(1),
      puk: { id: 'did:key:zPuk', secret: secret(2) }
    })
    expect(contents.puk?.signingSeed).toBeUndefined()
    expect(decodeClientKeyRecord({ contents }).puk).toEqual({
      id: 'did:key:zPuk',
      secret: secret(2)
    })
  })

  it('stamps createdAt, and carries a supplied one through', () => {
    const createdAt = '2026-08-03T00:00:00.000Z'
    expect(
      encodeClientKeyRecord({ clientSeed: secret(1), createdAt }).createdAt
    ).toBe(createdAt)
    expect(
      encodeClientKeyRecord({ clientSeed: secret(1) }).createdAt
    ).toBeTypeOf('string')
  })

  it('refuses to encode a client seed of the wrong length', () => {
    expect(() =>
      encodeClientKeyRecord({ clientSeed: new Uint8Array(16) })
    ).toThrow(/32 bytes/)
  })
})

describe('decodeClientKeyRecord validation', () => {
  it('refuses a non-object record', () => {
    expect(() => decodeClientKeyRecord({ contents: null })).toThrow(
      /Malformed client-key record/
    )
    expect(() => decodeClientKeyRecord({ contents: 'nope' })).toThrow(
      /Malformed client-key record/
    )
  })

  it('refuses a missing, mis-encoded, or short client seed', () => {
    expect(() => decodeClientKeyRecord({ contents: {} })).toThrow(
      /client seed is missing/
    )
    expect(() =>
      decodeClientKeyRecord({ contents: { clientSeed: 'not base64url!!' } })
    ).toThrow(/client seed/)
    expect(() =>
      decodeClientKeyRecord({
        contents: { clientSeed: base64urlnopad.encode(new Uint8Array(16)) }
      })
    ).toThrow(/32 bytes/)
  })

  it('tolerates a record with no PUK, update keys, or controller', () => {
    const contents = {
      clientSeed: base64urlnopad.encode(secret(1))
    }
    expect(decodeClientKeyRecord({ contents })).toEqual({
      clientSeed: secret(1)
    })
  })

  it('refuses a present-but-malformed PUK', () => {
    const clientSeed = base64urlnopad.encode(secret(1))
    expect(() =>
      decodeClientKeyRecord({ contents: { clientSeed, puk: 'nope' } })
    ).toThrow(/malformed PUK/)
    expect(() =>
      decodeClientKeyRecord({
        contents: {
          clientSeed,
          puk: { secret: base64urlnopad.encode(secret(2)) }
        }
      })
    ).toThrow(/missing its key id/)
    expect(() =>
      decodeClientKeyRecord({
        contents: {
          clientSeed,
          puk: {
            id: 'did:key:zPuk',
            secret: base64urlnopad.encode(new Uint8Array(8))
          }
        }
      })
    ).toThrow(/PUK key material is not 32 bytes/)
  })

  it('refuses present-but-malformed did:webvh update keys', () => {
    const clientSeed = base64urlnopad.encode(secret(1))
    expect(() =>
      decodeClientKeyRecord({ contents: { clientSeed, webvh: 3 } })
    ).toThrow(/malformed did:webvh update keys/)
    expect(() =>
      decodeClientKeyRecord({
        contents: {
          clientSeed,
          webvh: { updateSeed: base64urlnopad.encode(secret(4)) }
        }
      })
    ).toThrow(/staged seed is missing/)
  })

  it('refuses a malformed controller or pointer DID', () => {
    const clientSeed = base64urlnopad.encode(secret(1))
    expect(() =>
      decodeClientKeyRecord({ contents: { clientSeed, controller: '' } })
    ).toThrow(/malformed controller/)
    expect(() =>
      decodeClientKeyRecord({ contents: { clientSeed, pointerDid: 42 } })
    ).toThrow(/malformed account pointer DID/)
  })
})

describe('assertEnrolledClientKeyRecord', () => {
  it('narrows a complete record', () => {
    const record = decodeClientKeyRecord({
      contents: encodeClientKeyRecord(fullRecord)
    })
    expect(assertEnrolledClientKeyRecord({ record }).pointerDid).toBe(
      fullRecord.pointerDid
    )
  })

  it('names the member an incomplete record is missing', () => {
    expect(() =>
      assertEnrolledClientKeyRecord({ record: { clientSeed: secret(1) } })
    ).toThrow(/per-user key/)
    expect(() =>
      assertEnrolledClientKeyRecord({
        record: { clientSeed: secret(1), puk: fullRecord.puk }
      })
    ).toThrow(/did:webvh update keys/)
  })
})
