/**
 * Unit tests for the contacts last-write-wins conflict rule
 * (`src/sync/contactsConflict.ts`): the newest stamp wins, a tombstone on
 * either side resolves to the remote master, every unreachable-payload case
 * falls back the way the module documents, and the cipher's integrity refusal
 * leaves the resolver instead of settling the conflict, naming the side it
 * refused.
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

/**
 * The resource id every row in these tests is addressed under -- the id the
 * cipher verifies a stored envelope was sealed for.
 */
const ROW_ID = 'urn:uuid:contact-1'

/**
 * Some other row's resource id: what a misfiled envelope was sealed for, and
 * what a decoy `id` inside a decrypted payload names.
 */
const OTHER_ROW_ID = 'urn:uuid:contact-2'

const older = head({ updatedAt: '2026-08-01T00:00:00.000Z' })
const newer = head({ updatedAt: '2026-08-02T00:00:00.000Z' })

/**
 * A cipher over envelopes that carry their plaintext under `jwe`, recording
 * on `ids` the resource id every decrypt was addressed with.
 *
 * Refuses an envelope read under any id but the one it was sealed for
 * ({@link ROW_ID} unless the envelope says otherwise), the way was-client's own
 * cipher refuses a re-addressed body: with an `IntegrityError`.
 *
 * An envelope can carry its own `failWith` name too, so one side of a conflict
 * reads as held under no key while the other still decrypts.
 *
 * @param [options] {object}
 * @param [options.failWith] {string}   every decrypt throws an error carrying
 *   this `name` instead of resolving, ahead of the binding check
 * @returns {DocCipher & { ids: string[] }}
 */
function fakeCipher({ failWith }: { failWith?: string } = {}) {
  const ids: string[] = []
  return {
    ids,
    async decrypt({ id, envelope }: { id: string; envelope: unknown }) {
      ids.push(id)
      const {
        body,
        sealedFor = ROW_ID,
        failWith: envelopeFailWith
      } = (
        envelope as {
          jwe: { body: unknown; sealedFor?: string; failWith?: string }
        }
      ).jwe
      const name = failWith ?? envelopeFailWith
      if (name !== undefined) {
        throw Object.assign(new Error('cannot decrypt'), { name })
      }
      if (id !== sealedFor) {
        throw Object.assign(new Error('re-addressed envelope'), {
          name: 'IntegrityError'
        })
      }
      return body
    }
  } as unknown as DocCipher & { ids: string[] }
}

/**
 * Wraps a payload in something `isEncryptedEnvelope` recognizes.
 *
 * @param body {Json}
 * @param [options] {object}
 * @param [options.sealedFor] {string}   the resource id the envelope was
 *   sealed for, when it is not {@link ROW_ID}
 * @param [options.failWith] {string}   the error name the fake cipher throws
 *   for this envelope alone, as for a key this replica does not hold
 * @returns {Json}
 */
function envelope(
  body: Json,
  { sealedFor, failWith }: { sealedFor?: string; failWith?: string } = {}
): Json {
  return {
    jwe: {
      protected: 'e30',
      recipients: [],
      body,
      ...(sealedFor && { sealedFor }),
      ...(failWith && { failWith })
    }
  }
}

describe('contactHeadPayloadOf', () => {
  it('passes a plaintext head through when no cipher is passed', async () => {
    expect(await contactHeadPayloadOf({ id: ROW_ID, data: newer })).toEqual(
      newer
    )
  })

  it('reads a plaintext head as unreachable under a cipher, without decrypting it', async () => {
    const cipher = fakeCipher()
    expect(
      await contactHeadPayloadOf({ id: ROW_ID, data: newer, cipher })
    ).toBeUndefined()
    expect(cipher.ids).toEqual([])
  })

  it('decrypts an envelope with the collection cipher', async () => {
    expect(
      await contactHeadPayloadOf({
        id: ROW_ID,
        data: envelope(newer),
        cipher: fakeCipher()
      })
    ).toEqual(newer)
  })

  it('is undefined without a cipher, on a no-key decrypt, or on garbage', async () => {
    expect(
      await contactHeadPayloadOf({ id: ROW_ID, data: envelope(newer) })
    ).toBeUndefined()
    for (const failWith of ['UnknownEpochError', 'KeyUnwrapError', 'Error']) {
      expect(
        await contactHeadPayloadOf({
          id: ROW_ID,
          data: envelope(newer),
          cipher: fakeCipher({ failWith })
        })
      ).toBeUndefined()
    }
    expect(
      await contactHeadPayloadOf({ id: ROW_ID, data: { nope: true } })
    ).toBeUndefined()
    expect(
      await contactHeadPayloadOf({ id: ROW_ID, data: null })
    ).toBeUndefined()
  })

  it('rethrows the cipher integrity refusal instead of reading it as unusable', async () => {
    await expect(
      contactHeadPayloadOf({
        id: ROW_ID,
        data: envelope(newer, { sealedFor: OTHER_ROW_ID }),
        cipher: fakeCipher()
      })
    ).rejects.toMatchObject({ name: 'IntegrityError' })
  })

  it('addresses the decrypt with the row id, not an id inside the payload', async () => {
    const cipher = fakeCipher()
    expect(
      await contactHeadPayloadOf({
        id: ROW_ID,
        data: envelope({ ...newer, id: OTHER_ROW_ID }),
        cipher
      })
    ).toEqual({ ...newer, id: OTHER_ROW_ID })
    expect(cipher.ids).toEqual([ROW_ID])
  })
})

describe('resolveContactHeadConflict', () => {
  it('gives the newer stamp the win, in both directions', async () => {
    expect(
      await resolveContactHeadConflict({
        id: ROW_ID,
        remote: newer,
        local: older
      })
    ).toBe('remote')
    expect(
      await resolveContactHeadConflict({
        id: ROW_ID,
        remote: older,
        local: newer
      })
    ).toBe('local')
  })

  it('resolves a tombstone on either side to the remote master', async () => {
    expect(
      await resolveContactHeadConflict({
        id: ROW_ID,
        remote: older,
        local: newer,
        remoteDeleted: true
      })
    ).toBe('remote')
    expect(
      await resolveContactHeadConflict({
        id: ROW_ID,
        remote: older,
        local: newer,
        localDeleted: true
      })
    ).toBe('remote')
  })

  it('lets a valid local side repair a malformed remote one', async () => {
    expect(
      await resolveContactHeadConflict({
        id: ROW_ID,
        remote: { junk: 1 },
        local: newer
      })
    ).toBe('local')
  })

  it('falls back to the remote master when neither side is usable', async () => {
    expect(
      await resolveContactHeadConflict({
        id: ROW_ID,
        remote: { junk: 1 },
        local: null
      })
    ).toBe('remote')
    expect(
      await resolveContactHeadConflict({
        id: ROW_ID,
        remote: envelope(newer),
        local: envelope(older)
      })
    ).toBe('remote')
  })

  it('decides through the cipher when both sides are envelopes', async () => {
    const cipher = fakeCipher()
    expect(
      await resolveContactHeadConflict({
        id: ROW_ID,
        remote: envelope(older),
        local: envelope(newer),
        cipher
      })
    ).toBe('local')
  })

  it('reports which side the binding check refused', async () => {
    const refusals: Array<{ side: string; name: string }> = []
    const onIntegrityRefusal = ({
      side,
      err
    }: {
      side: string
      err: unknown
    }) => void refusals.push({ side, name: (err as Error).name })

    await expect(
      resolveContactHeadConflict({
        id: ROW_ID,
        remote: envelope(newer, { sealedFor: OTHER_ROW_ID }),
        local: envelope(older),
        cipher: fakeCipher(),
        onIntegrityRefusal
      })
    ).rejects.toMatchObject({ name: 'IntegrityError' })
    expect(refusals).toEqual([{ side: 'remote', name: 'IntegrityError' }])

    refusals.length = 0
    await expect(
      resolveContactHeadConflict({
        id: ROW_ID,
        remote: envelope(older),
        local: envelope(newer, { sealedFor: OTHER_ROW_ID }),
        cipher: fakeCipher(),
        onIntegrityRefusal
      })
    ).rejects.toMatchObject({ name: 'IntegrityError' })
    expect(refusals).toEqual([{ side: 'local', name: 'IntegrityError' }])
  })

  it('reports both sides when both are sealed for another resource', async () => {
    const refusals: string[] = []

    await expect(
      resolveContactHeadConflict({
        id: ROW_ID,
        remote: envelope(newer, { sealedFor: OTHER_ROW_ID }),
        local: envelope(older, { sealedFor: OTHER_ROW_ID }),
        cipher: fakeCipher(),
        onIntegrityRefusal: ({ side }) => void refusals.push(side)
      })
    ).rejects.toMatchObject({ name: 'IntegrityError' })
    expect(refusals).toEqual(['remote', 'local'])
  })

  it('reports no refusal for a side this replica holds no key for', async () => {
    const refusals: string[] = []

    expect(
      await resolveContactHeadConflict({
        id: ROW_ID,
        remote: envelope(newer, { failWith: 'UnknownEpochError' }),
        local: envelope(older),
        cipher: fakeCipher(),
        onIntegrityRefusal: ({ side }) => void refusals.push(side)
      })
    ).toBe('local')
    expect(refusals).toEqual([])
  })

  it('throws when either side is sealed for another resource', async () => {
    await expect(
      resolveContactHeadConflict({
        id: ROW_ID,
        remote: envelope(newer, { sealedFor: OTHER_ROW_ID }),
        local: envelope(older),
        cipher: fakeCipher()
      })
    ).rejects.toMatchObject({ name: 'IntegrityError' })
    await expect(
      resolveContactHeadConflict({
        id: ROW_ID,
        remote: envelope(older),
        local: envelope(newer, { sealedFor: OTHER_ROW_ID }),
        cipher: fakeCipher()
      })
    ).rejects.toMatchObject({ name: 'IntegrityError' })
  })

  it('leaves the no-key rules alone: one usable side wins, neither falls back', async () => {
    // The unreadable remote side carries the fresher stamp, so a comparison
    // that reached it would answer 'remote'.
    expect(
      await resolveContactHeadConflict({
        id: ROW_ID,
        remote: envelope(newer, { failWith: 'UnknownEpochError' }),
        local: envelope(older),
        cipher: fakeCipher()
      })
    ).toBe('local')
    expect(
      await resolveContactHeadConflict({
        id: ROW_ID,
        remote: envelope(older),
        local: envelope(newer),
        cipher: fakeCipher({ failWith: 'UnknownEpochError' })
      })
    ).toBe('remote')
  })

  it('lets a local envelope beat a newer plaintext remote head under a cipher', async () => {
    // The plaintext remote carries the fresher stamp, so a comparison that
    // read it would answer 'remote' and discard the local envelope.
    const cipher = fakeCipher()
    expect(
      await resolveContactHeadConflict({
        id: ROW_ID,
        remote: newer,
        local: envelope(older),
        cipher
      })
    ).toBe('local')
    expect(cipher.ids).toEqual([ROW_ID])
  })

  it('lets a remote envelope beat a newer plaintext local head under a cipher', async () => {
    const cipher = fakeCipher()
    expect(
      await resolveContactHeadConflict({
        id: ROW_ID,
        remote: envelope(older),
        local: newer,
        cipher
      })
    ).toBe('remote')
    expect(cipher.ids).toEqual([ROW_ID])
  })

  it('addresses both sides decrypt with the row id, not a decoy in the payload', async () => {
    const cipher = fakeCipher()
    expect(
      await resolveContactHeadConflict({
        id: ROW_ID,
        remote: envelope({ ...older, id: OTHER_ROW_ID }),
        local: envelope({ ...newer, id: OTHER_ROW_ID }),
        cipher
      })
    ).toBe('local')
    expect(cipher.ids).toEqual([ROW_ID, ROW_ID])
  })
})
