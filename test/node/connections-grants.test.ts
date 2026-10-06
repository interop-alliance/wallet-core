/**
 * Unit tests for the `connections` grant index
 * (`src/connections/grants.ts`, `src/connections/didKey.ts`): the reader
 * checks that drop a grant delegated to another party or targeting another
 * Space, the targets, the live and expired split, the recipient kid, the
 * signing-key join, and the agent-connection readers.
 */
import { describe, expect, it } from 'vitest'
import { x25519RecipientFromDidKey } from '@interop/was-client/edv/cipher'
import {
  AGENT_GRANT_RENEWAL_WINDOW_MS,
  agentConnectionsSignedBy,
  agentGrantDue,
  collectionIdInSpace,
  connectionGrants,
  connectionRecipientKid,
  grantRecipientKid,
  grantTargets,
  isTargetInSpace,
  latestGrantsPerScope,
  liveInboxChannel,
  parseConnectionEntry,
  receivedGrantLapsed,
  receivedGrants,
  renewalScopeGrants,
  signingKeyMultibaseOfDid,
  splitGrantsByExpiry
} from '../../src/connections/index.js'
import type {
  ConnectionEntry,
  ConnectionGrant,
  ConnectionZcap
} from '../../src/connections/index.js'
import {
  AGENT_INBOX,
  PAIRWISE,
  SPACE_URL,
  zcap
} from './fixtures/memoryConnections.js'

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

const DAY_MS = 24 * 60 * 60 * 1000

function receivedRecord({
  id,
  controller = PAIRWISE,
  target = AGENT_INBOX,
  allowedAction = ['POST'],
  expires = '2027-01-01T00:00:00.000Z',
  receivedAt = STAMP,
  grantKind = 'inbox'
}: {
  id: string
  controller?: string
  target?: string
  allowedAction?: string | string[]
  expires?: string
  receivedAt?: string
  grantKind?: string
}): Record<string, unknown> {
  return {
    zcap: {
      ...zcap({ id, controller, target, expires }),
      allowedAction
    },
    grantKind,
    receivedAt
  }
}

function entryWith(members: Record<string, unknown>): ConnectionEntry {
  const parsed = parseConnectionEntry({
    version: 1,
    kind: 'agent',
    id: AGENT,
    firstSeen: STAMP,
    lastSeen: STAMP,
    grants: [],
    writers: [],
    ...members
  })
  if (parsed === undefined) {
    throw new Error('fixture did not parse')
  }
  return parsed
}

describe('receivedGrants', () => {
  const grantsReceived = [
    receivedRecord({ id: 'urn:zcap:inbox' }),
    receivedRecord({ id: 'urn:zcap:foreign', controller: OTHER }),
    receivedRecord({
      id: 'urn:zcap:here',
      target: `${SPACE_URL}inbox/`
    }),
    receivedRecord({ id: 'urn:zcap:no-post', allowedAction: ['GET'] }),
    receivedRecord({ id: 'urn:zcap:string-post', allowedAction: 'POST' })
  ]

  it('keeps a pairwise-controlled grant outside this Space, an inbox grant allowing POST', () => {
    const entry = entryWith({ grantsReceived })
    const grants = receivedGrants({
      entry,
      pairwiseDid: PAIRWISE,
      spaceUrl: SPACE_URL
    })
    expect(grants.map(grant => grant.zcapId)).toEqual([
      'urn:zcap:inbox',
      'urn:zcap:string-post'
    ])
    expect(grants[0]).toMatchObject({
      controller: PAIRWISE,
      target: AGENT_INBOX,
      grantKind: 'inbox',
      receivedAt: STAMP
    })
  })

  it('returns none on a retired entry', () => {
    const entry = entryWith({ grantsReceived, retired: STAMP })
    expect(
      receivedGrants({ entry, pairwiseDid: PAIRWISE, spaceUrl: SPACE_URL })
    ).toEqual([])
  })
})

describe('receivedGrantLapsed and liveInboxChannel', () => {
  const LIFETIME = 30 * DAY_MS
  const read = (records: Array<Record<string, unknown>>) =>
    receivedGrants({
      entry: entryWith({ grantsReceived: records }),
      pairwiseDid: PAIRWISE,
      spaceUrl: SPACE_URL
    })

  it('lapses at the earlier of expires and receivedAt plus the lifetime', () => {
    const [byExpiry, byLifetime, live] = read([
      receivedRecord({
        id: 'urn:zcap:by-expiry',
        expires: '2026-10-10T00:00:00.000Z'
      }),
      receivedRecord({
        id: 'urn:zcap:by-lifetime',
        receivedAt: '2026-09-01T00:00:00.000Z'
      }),
      receivedRecord({ id: 'urn:zcap:live' })
    ])
    const lapsed = (grant: typeof live) =>
      receivedGrantLapsed({ grant: grant!, now: NOW, maxLifetimeMs: LIFETIME })
    expect(lapsed(byExpiry)).toBe(true)
    expect(lapsed(byLifetime)).toBe(true)
    expect(lapsed(live)).toBe(false)
  })

  it('chooses the live inbox grant with the later expires', () => {
    const grants = read([
      receivedRecord({
        id: 'urn:zcap:later',
        expires: '2027-03-01T00:00:00.000Z'
      }),
      receivedRecord({
        id: 'urn:zcap:earlier',
        expires: '2027-02-01T00:00:00.000Z'
      }),
      receivedRecord({
        id: 'urn:zcap:lapsed',
        expires: '2026-10-10T00:00:00.000Z'
      })
    ])
    expect(
      liveInboxChannel({ grants, now: NOW, maxLifetimeMs: 365 * DAY_MS })
        ?.zcapId
    ).toBe('urn:zcap:later')
    expect(
      liveInboxChannel({
        grants,
        now: new Date('2028-01-01T00:00:00.000Z'),
        maxLifetimeMs: 365 * DAY_MS
      })
    ).toBeUndefined()
  })
})

function grantOf({
  id,
  controller = AGENT,
  target = `${SPACE_URL}private-credentials/`,
  allowedAction = ['GET'],
  expires = '2027-01-01T00:00:00.000Z',
  grantedAt = STAMP
}: {
  id: string
  controller?: string
  target?: string
  allowedAction?: string | string[]
  expires?: string
  grantedAt?: string
}): ConnectionGrant {
  const value: ConnectionZcap = {
    id,
    controller,
    invocationTarget: target,
    allowedAction,
    expires
  }
  return {
    zcapId: id,
    controller,
    target,
    allowedAction,
    expires,
    grantKind: 'grant',
    grantedAt,
    zcap: value
  }
}

describe('latestGrantsPerScope', () => {
  it('keeps the greatest expires per scope', () => {
    const grants = [
      grantOf({ id: 'a', expires: '2027-02-01T00:00:00.000Z' }),
      grantOf({ id: 'b', expires: '2027-03-01T00:00:00.000Z' }),
      grantOf({ id: 'c', expires: '2027-01-01T00:00:00.000Z' })
    ]
    expect(latestGrantsPerScope({ grants }).map(grant => grant.zcapId)).toEqual(
      ['b']
    )
  })

  it('keeps the later record on an expires tie', () => {
    expect(
      latestGrantsPerScope({
        grants: [
          grantOf({ id: 'first', expires: '2027-01-01T00:00:00.000Z' }),
          grantOf({ id: 'second', expires: '2027-01-01T00:00:00.000Z' })
        ]
      }).map(grant => grant.zcapId)
    ).toEqual(['second'])
  })

  it('separates scopes by controller, target (with a * marker), and action set', () => {
    const grants = [
      grantOf({ id: 'base', expires: '2027-01-01T00:00:00.000Z' }),
      grantOf({ id: 'other-controller', controller: OTHER }),
      grantOf({
        id: 'starred',
        target: `${SPACE_URL}private-credentials/*`
      }),
      grantOf({ id: 'write', allowedAction: ['GET', 'PUT'] }),
      grantOf({ id: 'write-reordered', allowedAction: ['PUT', 'GET'] }),
      grantOf({
        id: 'string-action',
        allowedAction: 'GET',
        expires: '2027-06-01T00:00:00.000Z'
      })
    ]
    expect(latestGrantsPerScope({ grants }).map(grant => grant.zcapId)).toEqual(
      ['string-action', 'other-controller', 'starred', 'write-reordered']
    )
  })
})

describe('renewalScopeGrants', () => {
  it('keeps the read and inbox grants one consent produced', () => {
    const OTHER_STAMP = '2026-09-01T00:00:00.000Z'
    const grants = [
      grantOf({
        id: 'read',
        allowedAction: ['HEAD', 'GET']
      }),
      grantOf({
        id: 'inbox',
        target: `${SPACE_URL}inbox/`,
        allowedAction: ['POST']
      }),
      grantOf({ id: 'write', allowedAction: ['PUT'] }),
      grantOf({
        id: 'read-elsewhen',
        allowedAction: ['GET', 'HEAD'],
        grantedAt: OTHER_STAMP
      }),
      grantOf({
        id: 'read-resource',
        target: `${SPACE_URL}private-credentials/one`,
        allowedAction: ['GET', 'HEAD']
      })
    ]
    expect(
      renewalScopeGrants({ grants, spaceUrl: SPACE_URL }).map(
        grant => grant.zcapId
      )
    ).toEqual(['read', 'inbox'])
  })

  it('finds no scope without an inbox grant', () => {
    expect(
      renewalScopeGrants({
        grants: [grantOf({ id: 'read', allowedAction: ['GET', 'HEAD'] })],
        spaceUrl: SPACE_URL
      })
    ).toEqual([])
  })
})

const ACCOUNT = 'did:webvh:SCID:example.com'
const CLIENT_KEY = 'z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2'
const STRUCK_KEY = 'z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'
const ANNEX_VM =
  'did:webvh:ANNEX:example.com#z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw'
const POINTED = 'urn:zcap:generation:current'
const DOC = {
  verificationMethod: [
    { id: `${ACCOUNT}#${CLIENT_KEY}`, publicKeyMultibase: CLIENT_KEY }
  ],
  capabilityDelegation: [`${ACCOUNT}#${CLIENT_KEY}`]
}

function signed({
  id,
  signer,
  expires = '2027-10-01T00:00:00.000Z',
  parent
}: {
  id: string
  signer: string
  expires?: string
  parent?: Record<string, unknown>
}): ConnectionZcap {
  return {
    '@context': ['https://w3id.org/zcap/v1'],
    id,
    controller: AGENT,
    parentCapability:
      (parent?.id as string | undefined) ??
      'urn:zcap:root:https%3A%2F%2Fwas.example%2Fspace%2FSPACE%2F',
    invocationTarget: `${SPACE_URL}private-credentials/`,
    allowedAction: ['GET'],
    expires,
    proof: {
      type: 'DataIntegrityProof',
      verificationMethod: signer,
      capabilityChain: [
        'urn:zcap:root:https%3A%2F%2Fwas.example%2Fspace%2FSPACE%2F',
        ...(parent !== undefined ? [parent] : [])
      ]
    }
  }
}

function generationDelegation({
  id,
  signer
}: {
  id: string
  signer: string
}): Record<string, unknown> {
  return {
    id,
    controller: 'did:webvh:ANNEX:example.com',
    proof: { type: 'DataIntegrityProof', verificationMethod: signer }
  }
}

describe('agentGrantDue', () => {
  const now = Date.parse('2026-10-01T00:00:00.000Z')
  const expiringIn = (days: number) =>
    new Date(now + days * DAY_MS).toISOString()

  it('is due inside the 90-day window and not outside it', () => {
    expect(AGENT_GRANT_RENEWAL_WINDOW_MS).toBe(90 * DAY_MS)
    const root = (expires: string) =>
      signed({
        id: 'urn:zcap:leaf',
        signer: `${ACCOUNT}#${CLIENT_KEY}`,
        expires
      })
    expect(agentGrantDue({ zcap: root(expiringIn(60)), doc: DOC, now })).toBe(
      true
    )
    expect(agentGrantDue({ zcap: root(expiringIn(100)), doc: DOC, now })).toBe(
      false
    )
  })

  it('is not due once past its expires', () => {
    const zcap = signed({
      id: 'urn:zcap:leaf',
      signer: `${ACCOUNT}#${CLIENT_KEY}`,
      expires: expiringIn(-1)
    })
    expect(agentGrantDue({ zcap, doc: DOC, now })).toBe(false)
  })

  it('is due under a replaced parent whose signer still stands, and not once it is struck', () => {
    const replaced = signed({
      id: 'urn:zcap:leaf',
      signer: ANNEX_VM,
      expires: expiringIn(200),
      parent: generationDelegation({
        id: 'urn:zcap:generation:old',
        signer: `${ACCOUNT}#${CLIENT_KEY}`
      })
    })
    expect(
      agentGrantDue({
        zcap: replaced,
        pointedDelegationId: POINTED,
        doc: DOC,
        now
      })
    ).toBe(true)
    const struck = signed({
      id: 'urn:zcap:leaf',
      signer: ANNEX_VM,
      expires: expiringIn(200),
      parent: generationDelegation({
        id: 'urn:zcap:generation:old',
        signer: `${ACCOUNT}#${STRUCK_KEY}`
      })
    })
    expect(
      agentGrantDue({
        zcap: struck,
        pointedDelegationId: POINTED,
        doc: DOC,
        now
      })
    ).toBe(false)
  })

  it('is not due on a root-anchored grant whose signer left the document', () => {
    const zcap = signed({
      id: 'urn:zcap:leaf',
      signer: `${ACCOUNT}#${STRUCK_KEY}`,
      expires: expiringIn(200)
    })
    expect(
      agentGrantDue({ zcap, pointedDelegationId: POINTED, doc: DOC, now })
    ).toBe(false)
  })

  it('is not due on an annex-signed grant under the pointed delegation', () => {
    const zcap = signed({
      id: 'urn:zcap:leaf',
      signer: ANNEX_VM,
      expires: expiringIn(200),
      parent: generationDelegation({
        id: POINTED,
        signer: `${ACCOUNT}#${CLIENT_KEY}`
      })
    })
    expect(
      agentGrantDue({ zcap, pointedDelegationId: POINTED, doc: DOC, now })
    ).toBe(false)
  })
})

describe('agentConnectionsSignedBy', () => {
  const rootGrant = (signer: string, id: string) => ({
    zcap: signed({ id, signer }),
    grantKind: 'grant',
    grantedAt: STAMP
  })
  const annexGrant = (parentSigner: string, id: string) => ({
    zcap: signed({
      id,
      signer: ANNEX_VM,
      parent: generationDelegation({ id: POINTED, signer: parentSigner })
    }),
    grantKind: 'grant',
    grantedAt: STAMP
  })
  const rootSigned = entryWith({
    grants: [rootGrant(`did:key:${CLIENT_KEY}#${CLIENT_KEY}`, 'urn:zcap:r')]
  })
  const annexSigned = entryWith({
    grants: [annexGrant(`${ACCOUNT}#${CLIENT_KEY}`, 'urn:zcap:a')]
  })
  const otherSigner = entryWith({
    grants: [
      rootGrant(`${ACCOUNT}#${STRUCK_KEY}`, 'urn:zcap:o1'),
      annexGrant(`${ACCOUNT}#${STRUCK_KEY}`, 'urn:zcap:o2')
    ]
  })
  const retired = entryWith({
    grants: [rootGrant(`${ACCOUNT}#${CLIENT_KEY}`, 'urn:zcap:x')],
    retired: STAMP
  })
  const app = entryWith({
    kind: 'app',
    grants: [rootGrant(`${ACCOUNT}#${CLIENT_KEY}`, 'urn:zcap:y')]
  })
  const entries = [rootSigned, annexSigned, otherSigner, retired, app]

  it('names the agents a key signed grants for, by the root and annex arms', () => {
    for (const keyId of [
      CLIENT_KEY,
      `${ACCOUNT}#${CLIENT_KEY}`,
      `did:key:${CLIENT_KEY}#${CLIENT_KEY}`
    ]) {
      expect(
        agentConnectionsSignedBy({ entries, keyId, spaceUrl: SPACE_URL })
      ).toEqual([rootSigned, annexSigned])
    }
  })
})
