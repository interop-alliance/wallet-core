/**
 * Unit tests for the contacts last-write-wins conflict rule
 * (`src/sync/contactsConflict.ts`): the newest stamp wins, a tombstone on
 * either side resolves to the remote master, and every unreachable-payload
 * case falls back the way the module documents.
 */
import { describe, expect, it } from 'vitest'
import type { DocCipher, Json } from '@interop/was-client/sync'
import {
  contactHeadPayloadOf,
  resolveContactHeadConflict
} from '../../src/sync/contactsConflict.js'

/**
 * A minimal valid contact head payload.
 *
 * @param options {object}
 * @param options.updatedAt {string}
 * @param [options.writerId] {string}
 * @returns {object}
 */
function head({
  updatedAt,
  writerId = 'writer-a'
}: {
  updatedAt: string
  writerId?: string
}) {
  return {
    contactId: 'urn:uuid:contact-1',
    updatedAt,
    writerId,
    contact: { displayName: 'Ada Lovelace' }
  }
}

const older = head({ updatedAt: '2026-08-01T00:00:00.000Z' })
const newer = head({ updatedAt: '2026-08-02T00:00:00.000Z' })

/**
 * A cipher over envelopes that carry their plaintext under `jwe`.
 *
 * @param [options] {object}
 * @param [options.failing] {boolean}   decryption always throws
 * @returns {DocCipher}
 */
function fakeCipher({ failing = false }: { failing?: boolean } = {}) {
  return {
    async decrypt({ envelope }: { envelope: unknown }) {
      if (failing) {
        throw new Error('cannot decrypt')
      }
      return (envelope as { jwe: { body: unknown } }).jwe.body
    }
  } as unknown as DocCipher
}

/**
 * Wraps a payload in something `isEncryptedEnvelope` recognizes.
 *
 * @param body {Json}
 * @returns {Json}
 */
function envelope(body: Json): Json {
  return { jwe: { protected: 'e30', recipients: [], body } }
}

describe('contactHeadPayloadOf', () => {
  it('passes a plaintext head through', async () => {
    expect(await contactHeadPayloadOf({ data: newer })).toEqual(newer)
  })

  it('decrypts an envelope with the collection cipher', async () => {
    expect(
      await contactHeadPayloadOf({
        data: envelope(newer),
        cipher: fakeCipher()
      })
    ).toEqual(newer)
  })

  it('is undefined without a cipher, on a failed decrypt, or on garbage', async () => {
    expect(
      await contactHeadPayloadOf({ data: envelope(newer) })
    ).toBeUndefined()
    expect(
      await contactHeadPayloadOf({
        data: envelope(newer),
        cipher: fakeCipher({ failing: true })
      })
    ).toBeUndefined()
    expect(await contactHeadPayloadOf({ data: { nope: true } })).toBeUndefined()
    expect(await contactHeadPayloadOf({ data: null })).toBeUndefined()
  })
})

describe('resolveContactHeadConflict', () => {
  it('gives the newer stamp the win, in both directions', async () => {
    expect(
      await resolveContactHeadConflict({ remote: newer, local: older })
    ).toBe('remote')
    expect(
      await resolveContactHeadConflict({ remote: older, local: newer })
    ).toBe('local')
  })

  it('resolves a tombstone on either side to the remote master', async () => {
    expect(
      await resolveContactHeadConflict({
        remote: older,
        local: newer,
        remoteDeleted: true
      })
    ).toBe('remote')
    expect(
      await resolveContactHeadConflict({
        remote: older,
        local: newer,
        localDeleted: true
      })
    ).toBe('remote')
  })

  it('lets a valid local side repair a malformed remote one', async () => {
    expect(
      await resolveContactHeadConflict({ remote: { junk: 1 }, local: newer })
    ).toBe('local')
  })

  it('falls back to the remote master when neither side is usable', async () => {
    expect(
      await resolveContactHeadConflict({ remote: { junk: 1 }, local: null })
    ).toBe('remote')
    expect(
      await resolveContactHeadConflict({
        remote: envelope(newer),
        local: envelope(older)
      })
    ).toBe('remote')
  })

  it('decides through the cipher when both sides are envelopes', async () => {
    const cipher = fakeCipher()
    expect(
      await resolveContactHeadConflict({
        remote: envelope(older),
        local: envelope(newer),
        cipher
      })
    ).toBe('local')
  })
})
