/**
 * Unit tests for the `connections` grant index
 * (`src/connections/grants.ts`, `src/connections/didKey.ts`): the reader
 * checks that drop a grant delegated to another party or targeting another
 * Space, the targets, the live and expired split, the recipient kid, and the
 * signing-key join.
 */
import { describe, expect, it } from 'vitest'
import { x25519RecipientFromDidKey } from '@interop/was-client/edv/cipher'
import {
  collectionIdInSpace,
  connectionGrants,
  connectionRecipientKid,
  grantRecipientKid,
  grantTargets,
  isTargetInSpace,
  parseConnectionEntry,
  signingKeyMultibaseOfDid,
  splitGrantsByExpiry
} from '../../src/connections/index.js'
import type { ConnectionEntry } from '../../src/connections/index.js'
import { SPACE_URL, zcap } from './fixtures/memoryConnections.js'

const AGENT = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const OTHER = 'did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf'
const STAMP = '2026-10-01T00:00:00.000Z'
const NOW = new Date('2026-10-15T00:00:00.000Z')

function wrapper(
  value: ReturnType<typeof zcap>,
  grantKind = 'grant'
): Record<string, unknown> {
  return { zcap: value, grantKind, grantedAt: STAMP }
}

function agentEntry(grants: Array<Record<string, unknown>>): ConnectionEntry {
  const parsed = parseConnectionEntry({
    version: 1,
    kind: 'agent',
    id: AGENT,
    firstSeen: STAMP,
    lastSeen: STAMP,
    grants,
    writers: []
  })
  if (parsed === undefined) {
    throw new Error('fixture did not parse')
  }
  return parsed
}

describe('connectionGrants', () => {
  it('drops a grant delegated to another party or targeting another Space', () => {
    const entry = agentEntry([
      wrapper(zcap({ id: 'urn:zcap:mine', controller: AGENT })),
      wrapper(zcap({ id: 'urn:zcap:foreign', controller: OTHER })),
      wrapper(
        zcap({
          id: 'urn:zcap:elsewhere',
          controller: AGENT,
          target: 'https://was.example/space/OTHER/private-credentials/'
        })
      ),
      wrapper(
        zcap({
          id: 'urn:zcap:climbing',
          controller: AGENT,
          target: `${SPACE_URL}../OTHER/private-credentials/`
        })
      ),
      wrapper(
        zcap({
          id: 'urn:zcap:host',
          controller: AGENT,
          target: 'https://evil.example/space/SPACE/private-credentials/'
        })
      ),
      wrapper(
        zcap({
          id: 'urn:zcap:share',
          controller: AGENT,
          collection: 'contacts'
        }),
        'share'
      )
    ])
    const grants = connectionGrants({ entry, spaceUrl: SPACE_URL })
    expect(grants.map(grant => grant.zcapId)).toEqual([
      'urn:zcap:mine',
      'urn:zcap:share'
    ])
    expect(grants[1]).toMatchObject({
      controller: AGENT,
      target: `${SPACE_URL}contacts/`,
      allowedAction: ['GET'],
      grantKind: 'share',
      grantedAt: STAMP
    })
    // The stored capability rides along verbatim, ready to POST.
    expect(grants[0]?.zcap).toEqual(
      zcap({ id: 'urn:zcap:mine', controller: AGENT })
    )
  })

  it('refuses a Space URL without its trailing slash', () => {
    expect(() =>
      isTargetInSpace({
        target: `${SPACE_URL}contacts/`,
        spaceUrl: SPACE_URL.slice(0, -1)
      })
    ).toThrow(TypeError)
    expect(isTargetInSpace({ target: 'not a url', spaceUrl: SPACE_URL })).toBe(
      false
    )
  })
})

describe('collectionIdInSpace', () => {
  it('names the Collection a container URL of the Space addresses', () => {
    expect(
      collectionIdInSpace({
        target: `${SPACE_URL}private-credentials/`,
        spaceUrl: SPACE_URL
      })
    ).toBe('private-credentials')
    expect(
      collectionIdInSpace({
        target: `${SPACE_URL}app%20docs/`,
        spaceUrl: SPACE_URL
      })
    ).toBe('app docs')
  })

  it('names nothing for a Resource, a sub-resource, the Space, or another Space', () => {
    for (const target of [
      `${SPACE_URL}contacts/some-resource`,
      `${SPACE_URL}contacts/meta/log`,
      `${SPACE_URL}contacts`,
      SPACE_URL,
      'https://was.example/space/OTHER/contacts/',
      'not a url'
    ]) {
      expect(
        collectionIdInSpace({ target, spaceUrl: SPACE_URL })
      ).toBeUndefined()
    }
  })
})

describe('grant readers', () => {
  const entry = agentEntry([
    wrapper(zcap({ id: 'urn:zcap:live', controller: AGENT })),
    wrapper(
      zcap({
        id: 'urn:zcap:expired',
        controller: AGENT,
        collection: 'contacts',
        expires: '2026-10-02T00:00:00.000Z'
      })
    ),
    wrapper(zcap({ id: 'urn:zcap:again', controller: AGENT }))
  ])
  const grants = connectionGrants({ entry, spaceUrl: SPACE_URL })

  it('splits live from expired', () => {
    const { live, expired } = splitGrantsByExpiry({ grants, now: NOW })
    expect(live.map(grant => grant.zcapId)).toEqual([
      'urn:zcap:live',
      'urn:zcap:again'
    ])
    expect(expired.map(grant => grant.zcapId)).toEqual(['urn:zcap:expired'])
  })

  it('lists distinct targets', () => {
    expect(grantTargets({ grants })).toEqual([
      `${SPACE_URL}private-credentials/`,
      `${SPACE_URL}contacts/`
    ])
  })

  it('derives the recipient kid a grant controller names', () => {
    const expected = x25519RecipientFromDidKey({ did: AGENT }).id
    expect(grantRecipientKid({ grant: grants[0]! })).toBe(expected)
    expect(connectionRecipientKid({ did: AGENT })).toBe(expected)
    expect(expected.startsWith(`${AGENT}#z6LS`)).toBe(true)
    expect(connectionRecipientKid({ did: 'did:web:example.com' })).toBe(
      undefined
    )
  })

  it('takes the signing-key multibase off an Ed25519 did:key only', () => {
    expect(signingKeyMultibaseOfDid({ did: AGENT })).toBe(
      AGENT.slice('did:key:'.length)
    )
    expect(signingKeyMultibaseOfDid({ did: `${AGENT}#frag` })).toBeUndefined()
    expect(
      signingKeyMultibaseOfDid({ did: 'did:webvh:SCID:example.com' })
    ).toBeUndefined()
  })
})
