/**
 * Unit tests for the inbox message envelope (`src/space/inboxMessage.ts`):
 * the builder's output parses, a hand-built message parses, unknown members
 * are ignored, and malformed bodies are refused.
 */
import { describe, expect, it } from 'vitest'
import {
  inboxGrantMessage,
  parseInboxGrantMessage
} from '../../src/space/index.js'

const ACTOR = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function zcap(): Record<string, unknown> {
  return {
    '@context': ['https://w3id.org/zcap/v1'],
    id: 'urn:uuid:1d2b6e1c-6f4c-4f0e-9d2a-3c1a8a0e7b11',
    controller: ACTOR,
    parentCapability:
      'urn:zcap:root:https%3A%2F%2Fexample.com%2Fspace%2Fabc%2F',
    invocationTarget: 'https://example.com/space/abc/inbox/',
    allowedAction: ['POST'],
    expires: '2027-01-01T00:00:00Z',
    proof: { type: 'DataIntegrityProof', proofValue: 'z123' }
  }
}

function handBuilt(): Record<string, unknown> {
  return { type: 'Grant', actor: ACTOR, object: { zcaps: [zcap()] } }
}

describe('inbox message envelope', () => {
  it('parses the builder output', () => {
    const message = inboxGrantMessage({
      actor: ACTOR,
      zcaps: [zcap() as never]
    })
    expect(message.type).toBe('Grant')
    expect(parseInboxGrantMessage(message)).toEqual(message)
  })

  it('parses a message hand-built from the wire shape', () => {
    const body = handBuilt()
    expect(parseInboxGrantMessage(body)).toBe(body)
  })

  it('ignores unknown members and keeps them verbatim', () => {
    const body = handBuilt()
    body['@context'] = 'https://www.w3.org/ns/activitystreams'
    const zcaps = (body.object as { zcaps: Record<string, unknown>[] }).zcaps
    zcaps[0]!.extra = { nested: true }
    const parsed = parseInboxGrantMessage(body)
    expect(parsed).toBeDefined()
    expect((parsed as unknown as Record<string, unknown>)['@context']).toBe(
      'https://www.w3.org/ns/activitystreams'
    )
    expect(parsed?.object.zcaps[0]?.extra).toEqual({ nested: true })
  })

  it('accepts a proof array', () => {
    const body = handBuilt()
    const zcaps = (body.object as { zcaps: Record<string, unknown>[] }).zcaps
    zcaps[0]!.proof = [{ type: 'DataIntegrityProof' }]
    expect(parseInboxGrantMessage(body)).toBe(body)
  })

  it('refuses an array type', () => {
    expect(
      parseInboxGrantMessage({ ...handBuilt(), type: ['Grant'] })
    ).toBeUndefined()
  })

  it('refuses a non-did:key actor', () => {
    expect(
      parseInboxGrantMessage({ ...handBuilt(), actor: 'did:web:example.com' })
    ).toBeUndefined()
  })

  it('refuses an empty zcaps', () => {
    expect(
      parseInboxGrantMessage({ ...handBuilt(), object: { zcaps: [] } })
    ).toBeUndefined()
  })

  it('refuses a zcap missing proof', () => {
    const { proof: _proof, ...withoutProof } = zcap()
    expect(
      parseInboxGrantMessage({
        ...handBuilt(),
        object: { zcaps: [withoutProof] }
      })
    ).toBeUndefined()
  })

  it('refuses a non-object body', () => {
    expect(parseInboxGrantMessage('Grant')).toBeUndefined()
    expect(parseInboxGrantMessage(null)).toBeUndefined()
    expect(parseInboxGrantMessage([handBuilt()])).toBeUndefined()
  })

  it('refuses a string zcaps', () => {
    expect(
      parseInboxGrantMessage({ ...handBuilt(), object: { zcaps: 'zcap' } })
    ).toBeUndefined()
  })

  it('builder refuses an empty zcaps or a non-did:key actor', () => {
    expect(() => inboxGrantMessage({ actor: ACTOR, zcaps: [] })).toThrow(
      TypeError
    )
    expect(() =>
      inboxGrantMessage({
        actor: 'did:web:example.com',
        zcaps: [zcap() as never]
      })
    ).toThrow(TypeError)
  })
})
