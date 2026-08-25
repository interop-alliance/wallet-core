/**
 * Unit tests for the client-key record codec (`src/keys/clientKeyRecord.ts`):
 * the encode/decode round trip, the omit-rather-than-null encoding of absent
 * members, the tolerance of records written before an optional member existed
 * (including a user key stored under its former member name), the strict
 * refusal of every malformed member, and the enrolled-record narrowing.
 */
import { describe, expect, it } from 'vitest'
import { base64urlnopad } from '@scure/base'
import {
  assertEnrolledClientKeyRecord,
  decodeClientKeyRecord,
  encodeClientKeyRecord,
  isEnrolledClientKeyRecord
} from '../../src/keys/clientKeyRecord.js'
import type { ClientKeyRecord } from '../../src/keys/clientKeyRecord.js'

/**
 * A deterministic 32-byte secret.
 *
 * @param fill {number}
 * @returns {Uint8Array}
 */
function secret(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill)
}

/**
 * A deterministic 16-byte recovery code.
 *
 * @param fill {number}
 * @returns {Uint8Array}
 */
function code(fill: number): Uint8Array {
  return new Uint8Array(16).fill(fill)
}

const fullRecord = {
  clientSeed: secret(1),
  userKey: {
    id: 'did:key:zUserKey',
    secret: secret(2),
    signingSeed: secret(3)
  },
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

  it('omits a user key signing seed a rotation did not deliver', () => {
    const contents = encodeClientKeyRecord({
      clientSeed: secret(1),
      userKey: { id: 'did:key:zUserKey', secret: secret(2) }
    })
    expect(contents.userKey?.signingSeed).toBeUndefined()
    expect(decodeClientKeyRecord({ contents }).userKey).toEqual({
      id: 'did:key:zUserKey',
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

  it('refuses to encode any other secret of the wrong length', () => {
    // Every case below would otherwise produce a stored record the decoder
    // refuses -- an account whose keys are durably unreadable.
    expect(() =>
      encodeClientKeyRecord({
        ...fullRecord,
        userKey: { id: 'did:key:zUserKey', secret: new Uint8Array(31) }
      })
    ).toThrow(/user key material is not 32 bytes/)
    expect(() =>
      encodeClientKeyRecord({
        ...fullRecord,
        userKey: {
          id: 'did:key:zUserKey',
          secret: secret(2),
          signingSeed: new Uint8Array(64)
        }
      })
    ).toThrow(/user key signing seed is not 32 bytes/)
    expect(() =>
      encodeClientKeyRecord({
        ...fullRecord,
        webvhUpdateKeys: {
          updateSeed: new Uint8Array(1),
          stagedSeed: secret(5)
        }
      })
    ).toThrow(/update seed is not 32 bytes/)
    expect(() =>
      encodeClientKeyRecord({
        ...fullRecord,
        webvhUpdateKeys: {
          updateSeed: secret(4),
          stagedSeed: new Uint8Array(0)
        }
      })
    ).toThrow(/staged seed is not 32 bytes/)
    expect(() =>
      encodeClientKeyRecord({
        ...fullRecord,
        webvhUpdateKeys: {
          updateSeed: secret(4),
          stagedSeed: secret(5),
          pendingStagedSeed: new Uint8Array(33)
        }
      })
    ).toThrow(/pending staged seed is not 32 bytes/)
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

  it('tolerates a record with no user key, update keys, or controller', () => {
    const contents = {
      clientSeed: base64urlnopad.encode(secret(1))
    }
    expect(decodeClientKeyRecord({ contents })).toEqual({
      clientSeed: secret(1)
    })
  })

  it('parses a record whose user key is stored under the current name', () => {
    const contents = encodeClientKeyRecord({
      clientSeed: secret(1),
      userKey: { id: 'did:key:zUserKey', secret: secret(2) }
    })
    expect(Object.keys(contents)).toContain('userKey')
    expect(decodeClientKeyRecord({ contents }).userKey).toEqual({
      id: 'did:key:zUserKey',
      secret: secret(2)
    })
  })

  it('refuses a present-but-malformed user key', () => {
    const clientSeed = base64urlnopad.encode(secret(1))
    expect(() =>
      decodeClientKeyRecord({ contents: { clientSeed, userKey: 'nope' } })
    ).toThrow(/malformed user key/)
    expect(() =>
      decodeClientKeyRecord({
        contents: {
          clientSeed,
          userKey: { secret: base64urlnopad.encode(secret(2)) }
        }
      })
    ).toThrow(/missing its key id/)
    expect(() =>
      decodeClientKeyRecord({
        contents: {
          clientSeed,
          userKey: {
            id: 'did:key:zUserKey',
            secret: base64urlnopad.encode(new Uint8Array(8))
          }
        }
      })
    ).toThrow(/user key material is not 32 bytes/)
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
    ).toThrow(/user key/)
    expect(() =>
      assertEnrolledClientKeyRecord({
        record: { clientSeed: secret(1), userKey: fullRecord.userKey }
      })
    ).toThrow(/did:webvh update keys/)
  })
})

const builtOnHead = { scid: 'exampleScid', versionId: '3-abc' }

describe('encodeClientKeyRecord / decodeClientKeyRecord: pending state', () => {
  it('round-trips a full recovery-spend pending group', () => {
    const record = {
      ...fullRecord,
      pending: {
        ceremony: 'recovery-spend' as const,
        builtOnHead,
        unwrapKey: secret(7),
        replacementCode: code(8)
      }
    }
    const contents = encodeClientKeyRecord(record)
    expect(decodeClientKeyRecord({ contents })).toEqual(record)
  })

  it('round-trips a self-enrollment pending group (discriminator plus built-on head only)', () => {
    const record = {
      ...fullRecord,
      pending: {
        ceremony: 'self-enrollment' as const,
        builtOnHead
      }
    }
    const contents = encodeClientKeyRecord(record)
    expect(decodeClientKeyRecord({ contents })).toEqual(record)
  })

  it('decodes older stored records with no pending member', () => {
    const contents = encodeClientKeyRecord(fullRecord)
    expect(contents.pending).toBeUndefined()
    const decoded = decodeClientKeyRecord({ contents })
    expect(decoded.pending).toBeUndefined()
    expect(decoded).toEqual(fullRecord)
  })

  it('refuses a non-object pending member', () => {
    const clientSeed = base64urlnopad.encode(secret(1))
    expect(() =>
      decodeClientKeyRecord({ contents: { clientSeed, pending: 'nope' } })
    ).toThrow(/pending state is malformed/)
  })

  it('refuses an unknown ceremony value', () => {
    const clientSeed = base64urlnopad.encode(secret(1))
    expect(() =>
      decodeClientKeyRecord({
        contents: {
          clientSeed,
          pending: { ceremony: 'something-else', builtOnHead }
        }
      })
    ).toThrow(/unknown ceremony/)
  })

  it('refuses a missing or malformed built-on head', () => {
    const clientSeed = base64urlnopad.encode(secret(1))
    expect(() =>
      decodeClientKeyRecord({
        contents: { clientSeed, pending: { ceremony: 'self-enrollment' } }
      })
    ).toThrow(/malformed built-on head/)
    expect(() =>
      decodeClientKeyRecord({
        contents: {
          clientSeed,
          pending: {
            ceremony: 'self-enrollment',
            builtOnHead: { versionId: '3-abc' }
          }
        }
      })
    ).toThrow(/malformed built-on head/)
    expect(() =>
      decodeClientKeyRecord({
        contents: {
          clientSeed,
          pending: {
            ceremony: 'self-enrollment',
            builtOnHead: { scid: 'exampleScid', versionId: '' }
          }
        }
      })
    ).toThrow(/malformed built-on head/)
    expect(() =>
      decodeClientKeyRecord({
        contents: {
          clientSeed,
          pending: { ceremony: 'self-enrollment', builtOnHead: 'nope' }
        }
      })
    ).toThrow(/malformed built-on head/)
  })

  it('refuses an unwrap key of the wrong length or non-base64url', () => {
    const clientSeed = base64urlnopad.encode(secret(1))
    expect(() =>
      decodeClientKeyRecord({
        contents: {
          clientSeed,
          pending: {
            ceremony: 'recovery-spend',
            builtOnHead,
            unwrapKey: base64urlnopad.encode(new Uint8Array(8))
          }
        }
      })
    ).toThrow(/pending unwrap key is not 32 bytes/)
    expect(() =>
      decodeClientKeyRecord({
        contents: {
          clientSeed,
          pending: {
            ceremony: 'recovery-spend',
            builtOnHead,
            unwrapKey: 'not base64url!!'
          }
        }
      })
    ).toThrow(/pending unwrap key/)
  })

  it('refuses a replacement code of the wrong length', () => {
    const clientSeed = base64urlnopad.encode(secret(1))
    expect(() =>
      decodeClientKeyRecord({
        contents: {
          clientSeed,
          pending: {
            ceremony: 'recovery-spend',
            builtOnHead,
            replacementCode: base64urlnopad.encode(secret(9))
          }
        }
      })
    ).toThrow(/pending replacement code is not 16 bytes/)
  })

  it('refuses recovery-spend byte members under self-enrollment on decode', () => {
    const clientSeed = base64urlnopad.encode(secret(1))
    expect(() =>
      decodeClientKeyRecord({
        contents: {
          clientSeed,
          pending: {
            ceremony: 'self-enrollment',
            builtOnHead,
            unwrapKey: base64urlnopad.encode(secret(7))
          }
        }
      })
    ).toThrow(/recovery-spend members under self-enrollment/)
    expect(() =>
      decodeClientKeyRecord({
        contents: {
          clientSeed,
          pending: {
            ceremony: 'self-enrollment',
            builtOnHead,
            replacementCode: base64urlnopad.encode(code(8))
          }
        }
      })
    ).toThrow(/recovery-spend members under self-enrollment/)
  })

  it('refuses recovery-spend byte members under self-enrollment on encode', () => {
    expect(() =>
      encodeClientKeyRecord({
        ...fullRecord,
        pending: {
          ceremony: 'self-enrollment',
          builtOnHead,
          unwrapKey: secret(7)
        }
      })
    ).toThrow(/recovery-spend members under self-enrollment/)
    expect(() =>
      encodeClientKeyRecord({
        ...fullRecord,
        pending: {
          ceremony: 'self-enrollment',
          builtOnHead,
          replacementCode: code(8)
        }
      })
    ).toThrow(/recovery-spend members under self-enrollment/)
  })

  it('refuses to encode an unwrap key or replacement code of the wrong length', () => {
    expect(() =>
      encodeClientKeyRecord({
        ...fullRecord,
        pending: {
          ceremony: 'recovery-spend',
          builtOnHead,
          unwrapKey: new Uint8Array(8)
        }
      })
    ).toThrow(/pending unwrap key is not 32 bytes/)
    expect(() =>
      encodeClientKeyRecord({
        ...fullRecord,
        pending: {
          ceremony: 'recovery-spend',
          builtOnHead,
          replacementCode: secret(9)
        }
      })
    ).toThrow(/pending replacement code is not 16 bytes/)
  })
})

describe('isEnrolledClientKeyRecord', () => {
  it('is true on a complete record, with and without pending', () => {
    expect(
      isEnrolledClientKeyRecord(
        decodeClientKeyRecord({
          contents: encodeClientKeyRecord(fullRecord)
        })
      )
    ).toBe(true)
    expect(
      isEnrolledClientKeyRecord(
        decodeClientKeyRecord({
          contents: encodeClientKeyRecord({
            ...fullRecord,
            pending: { ceremony: 'self-enrollment', builtOnHead }
          })
        })
      )
    ).toBe(true)
  })

  it('is false when each required member is individually absent, and agrees with the assert', () => {
    const cases: ClientKeyRecord[] = [
      { clientSeed: fullRecord.clientSeed },
      { clientSeed: fullRecord.clientSeed, userKey: fullRecord.userKey },
      {
        clientSeed: fullRecord.clientSeed,
        userKey: fullRecord.userKey,
        webvhUpdateKeys: fullRecord.webvhUpdateKeys
      },
      {
        clientSeed: fullRecord.clientSeed,
        userKey: fullRecord.userKey,
        webvhUpdateKeys: fullRecord.webvhUpdateKeys,
        controller: fullRecord.controller
      }
    ]
    for (const record of cases) {
      const isEnrolled = isEnrolledClientKeyRecord(record)
      expect(isEnrolled).toBe(false)
      expect(() => assertEnrolledClientKeyRecord({ record })).toThrow()
    }
    expect(
      isEnrolledClientKeyRecord(
        decodeClientKeyRecord({
          contents: encodeClientKeyRecord(fullRecord)
        })
      )
    ).toBe(true)
    expect(() =>
      assertEnrolledClientKeyRecord({
        record: decodeClientKeyRecord({
          contents: encodeClientKeyRecord(fullRecord)
        })
      })
    ).not.toThrow()
  })
})
