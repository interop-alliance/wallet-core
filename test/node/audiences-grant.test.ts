/**
 * Unit tests for the audience member grant (`src/audiences/audienceGrant.ts`):
 * the exact delegation options, the trailing-slash refusal, and the
 * plaintext provisioning attribute.
 */
import { describe, expect, it } from 'vitest'
import type { ZcapClient } from '@interop/ezcap'
import {
  AUDIENCE_PROVISION_ATTRIBUTES,
  delegateAudienceGrant
} from '../../src/audiences/index.js'

function fakeZcapClient(): {
  zcapClient: ZcapClient
  calls: Record<string, unknown>[]
} {
  const calls: Record<string, unknown>[] = []
  const zcapClient = {
    async delegate(options: Record<string, unknown>) {
      calls.push(options)
      return { id: 'urn:zcap:stub' }
    }
  } as unknown as ZcapClient
  return { zcapClient, calls }
}

const COLLECTION_URL = 'https://example.com/space/abc/friends/'
const MEMBER = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

describe('audience grant', () => {
  it('delegates GET and HEAD on the container URL verbatim', async () => {
    const { zcapClient, calls } = fakeZcapClient()
    const parentCapability = { id: 'urn:zcap:parent' } as never
    const expires = new Date('2027-01-01T00:00:00Z')
    const zcap = await delegateAudienceGrant({
      zcapClient,
      parentCapability,
      collectionUrl: COLLECTION_URL,
      controller: MEMBER,
      expires
    })
    expect(zcap).toEqual({ id: 'urn:zcap:stub' })
    expect(calls).toHaveLength(1)
    expect(calls[0]).toEqual({
      capability: parentCapability,
      invocationTarget: COLLECTION_URL,
      controller: MEMBER,
      allowedActions: ['GET', 'HEAD'],
      expires
    })
    expect(calls[0]?.capability).toBe(parentCapability)
  })

  it('passes a root zcap id string through', async () => {
    const { zcapClient, calls } = fakeZcapClient()
    await delegateAudienceGrant({
      zcapClient,
      parentCapability: 'urn:zcap:root:x',
      collectionUrl: COLLECTION_URL,
      controller: MEMBER,
      expires: new Date()
    })
    expect(calls[0]?.capability).toBe('urn:zcap:root:x')
  })

  it('refuses a target without a trailing slash', async () => {
    const { zcapClient, calls } = fakeZcapClient()
    await expect(
      delegateAudienceGrant({
        zcapClient,
        parentCapability: 'urn:zcap:root:x',
        collectionUrl: 'https://example.com/space/abc/friends',
        controller: MEMBER,
        expires: new Date()
      })
    ).rejects.toThrow(TypeError)
    expect(calls).toHaveLength(0)
  })

  it('provisions an audience as plaintext', () => {
    expect(AUDIENCE_PROVISION_ATTRIBUTES.encryption).toBe('plaintext')
  })
})
