/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Classification of incoming VC API messages: wrapping CHAPI get / store events
 * as typed requests / offers, normalizing a VPR's queries, projecting a VPR
 * body onto the `{ didAuth, vcQueries, zcapRequests }` profile, and validating
 * the App Connect `AppConnectQuery` `app` block (the `appUrl` rules). Ported
 * from Freewallet `classify.test.ts`.
 */
import { describe, it, expect } from 'vitest'
import {
  appConnectRequestOf,
  serializedAppUrl,
  classifyCHAPIGetEvent,
  classifyCHAPIStoreEvent,
  classifyRequest,
  credentialQueriesOf,
  normalizeAgentName,
  requestingAgentOf,
  AGENT_NAME_MAX_LENGTH,
  credentialsOf,
  didAuthMethodSupported,
  isDidAuthOnly,
  queriesOf,
  zcapQueriesOf
} from '../../src/request/index.js'
import type {
  CHAPIGetEvent,
  CHAPIStoreEvent,
  IQueryByExample,
  IVPRQuery
} from '../../src/request/index.js'

const BARE_VC = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: 'https://issuer.example.com/issuers/14',
  validFrom: '2018-02-24T05:28:04Z',
  credentialSubject: { id: 'did:example:abcdef1234567', name: 'Jane Doe' }
}

function storeEvent(
  credential: CHAPIStoreEvent['credential']
): CHAPIStoreEvent {
  return { credential, respondWith: () => {} }
}

describe('classifyCHAPIGetEvent', () => {
  it('wraps a get event as an IVPRequest', () => {
    const event: CHAPIGetEvent = {
      credentialRequestOrigin: 'https://verifier.example',
      credentialRequestOptions: {
        web: {
          VerifiablePresentation: { query: { type: 'DIDAuthentication' } }
        }
      },
      respondWith: () => {}
    }
    const request = classifyCHAPIGetEvent(event)
    expect(request.credentialRequestOrigin).toBe('https://verifier.example')
    expect(request.verifiablePresentationRequest.query).toEqual({
      type: 'DIDAuthentication'
    })
  })

  it('throws when the get event carries no VerifiablePresentation request', () => {
    const event = {
      credentialRequestOrigin: 'https://verifier.example',
      respondWith: () => {}
    } as CHAPIGetEvent
    expect(() => classifyCHAPIGetEvent(event)).toThrow(
      /missing a VerifiablePresentation request/
    )
  })
})

describe('classifyCHAPIStoreEvent', () => {
  it('wraps a bare offered credential in a presentation', () => {
    const offer = classifyCHAPIStoreEvent(
      storeEvent({ dataType: 'VerifiableCredential', data: BARE_VC as never })
    )
    const presentation = offer.verifiablePresentation
    expect(presentation.type).toEqual(['VerifiablePresentation'])
    expect(presentation['@context']).toEqual([
      'https://www.w3.org/ns/credentials/v2'
    ])
    expect(credentialsOf(presentation)).toEqual([BARE_VC])
  })

  it('wraps a bare credential even when dataType is absent', () => {
    const offer = classifyCHAPIStoreEvent(
      storeEvent({ data: BARE_VC as never })
    )
    expect(credentialsOf(offer.verifiablePresentation)).toEqual([BARE_VC])
  })

  it('uses the VC 1.0 context when wrapping a VC 1.0 credential', () => {
    const v1 = {
      ...BARE_VC,
      '@context': ['https://www.w3.org/2018/credentials/v1']
    }
    const offer = classifyCHAPIStoreEvent(
      storeEvent({ dataType: 'VerifiableCredential', data: v1 as never })
    )
    expect(offer.verifiablePresentation['@context']).toEqual([
      'https://www.w3.org/2018/credentials/v1'
    ])
  })

  it('passes an offered presentation through unchanged', () => {
    const presentation = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      verifiableCredential: [BARE_VC]
    }
    const offer = classifyCHAPIStoreEvent(
      storeEvent({
        dataType: 'VerifiablePresentation',
        data: presentation as never
      })
    )
    expect(offer.verifiablePresentation).toBe(presentation)
    expect(credentialsOf(offer.verifiablePresentation)).toEqual([BARE_VC])
  })

  it('normalizes a single (non-array) verifiableCredential', () => {
    const presentation = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      verifiableCredential: BARE_VC
    }
    expect(credentialsOf(presentation as never)).toEqual([BARE_VC])
  })

  it('throws on an unrecognized payload', () => {
    expect(() =>
      classifyCHAPIStoreEvent(
        storeEvent({
          dataType: 'Whatever',
          data: { type: ['Whatever'] } as never
        })
      )
    ).toThrow(/unrecognized payload/)
  })

  it('throws the descriptive error on a primitive data payload', () => {
    for (const data of ['a string', 42, true, null]) {
      expect(() =>
        classifyCHAPIStoreEvent(
          storeEvent({
            dataType: 'VerifiablePresentation',
            data: data as never
          })
        )
      ).toThrow(/unrecognized payload/)
    }
  })

  it('throws the descriptive error on a primitive credential payload', () => {
    expect(() =>
      classifyCHAPIStoreEvent(
        storeEvent({ dataType: 'VerifiableCredential', data: 'nope' as never })
      )
    ).toThrow(/unrecognized payload/)
  })
})

describe('queriesOf', () => {
  it('normalizes a single query to an array', () => {
    const query = { type: 'DIDAuthentication' } as const
    expect(queriesOf({ query })).toEqual([query])
  })

  it('returns an empty array for an empty VPR body', () => {
    expect(queriesOf({})).toEqual([])
  })

  it('drops entries that are not typed query objects', () => {
    const query = { type: 'QueryByExample' } as never
    expect(
      queriesOf({ query: [undefined, null, 'nope', query] as never })
    ).toEqual([query])
  })
})

describe('classifyRequest', () => {
  const app = { name: 'x', appUrl: 'https://app.example/x' }

  it('classifies an empty VPR body without throwing', () => {
    expect(classifyRequest({})).toEqual({
      didAuth: false,
      vcQueries: [],
      zcapRequests: []
    })
  })

  it('separates DID Auth, credential, and capability axes', () => {
    const capabilityQuery = {
      controller: 'did:key:zController',
      invocationTarget: 'https://example.com/target',
      allowedAction: ['GET']
    }
    const profile = classifyRequest({
      query: [
        { type: 'DIDAuthentication', acceptedMethods: [{ method: 'key' }] },
        {
          type: 'QueryByExample',
          credentialQuery: { example: { type: 'Foo' } }
        },
        { type: 'AuthorizationCapabilityQuery', capabilityQuery }
      ]
    })
    expect(profile.didAuth).toBe(true)
    expect(profile.vcQueries).toHaveLength(1)
    expect(profile.zcapRequests).toEqual([capabilityQuery])
  })

  it('throws on more than one DIDAuthentication query', () => {
    expect(() =>
      classifyRequest({
        query: [{ type: 'DIDAuthentication' }, { type: 'DIDAuthentication' }]
      })
    ).toThrow(/More than one DIDAuthentication/)
  })

  it('recognizes the legacy ZcapQuery type string', () => {
    const capabilityQuery = {
      controller: 'did:key:zController',
      invocationTarget: 'https://example.com/target'
    }
    const profile = classifyRequest({
      query: [{ type: 'ZcapQuery', capabilityQuery }]
    })
    expect(profile.zcapRequests).toEqual([capabilityQuery])
    // The App Connect app fixture is unused by the shared classifier.
    expect(app.name).toBe('x')
  })

  it('carries the self-declared agent name, trimmed', () => {
    const capabilityQuery = {
      controller: 'did:key:zController',
      invocationTarget: 'https://example.com/target'
    }
    const profile = classifyRequest({
      agent: { name: '  research-bot ' },
      query: [{ type: 'AuthorizationCapabilityQuery', capabilityQuery }]
    })
    expect(profile.agent).toEqual({ name: 'research-bot' })
    expect(classifyRequest({ query: [] })).not.toHaveProperty('agent')
  })

  it('refuses a malformed agent member at classification', () => {
    expect(() => classifyRequest({ agent: 'research-bot' } as never)).toThrow(
      /"agent" member must be an object/
    )
    expect(() => classifyRequest({ agent: { name: '' } })).toThrow(
      /must not be empty/
    )
  })
})

describe('requestingAgentOf / normalizeAgentName', () => {
  it('reads nothing off a request without an agent member', () => {
    expect(requestingAgentOf({})).toBeUndefined()
  })

  it('trims and keeps Unicode letters', () => {
    expect(normalizeAgentName({ name: ' Ayudante de búsqueda ' })).toBe(
      'Ayudante de búsqueda'
    )
    expect(requestingAgentOf({ agent: { name: '研究助手' } })).toEqual({
      name: '研究助手'
    })
  })

  it('refuses a non-string, empty, overlong, or control-bearing name', () => {
    expect(() => normalizeAgentName({ name: 42 })).toThrow(/must be a string/)
    expect(() => normalizeAgentName({ name: '   ' })).toThrow(
      /must not be empty/
    )
    expect(() =>
      normalizeAgentName({ name: 'a'.repeat(AGENT_NAME_MAX_LENGTH + 1) })
    ).toThrow(/at most 64 characters/)
    expect(
      normalizeAgentName({ name: 'a'.repeat(AGENT_NAME_MAX_LENGTH) })
    ).toHaveLength(AGENT_NAME_MAX_LENGTH)
    expect(() => normalizeAgentName({ name: 'line\nbreak' })).toThrow(
      /control characters/
    )
    expect(() => normalizeAgentName({ name: 'tab\there' })).toThrow(
      /control characters/
    )
    expect(() => normalizeAgentName({ name: 'c1\u0085here' })).toThrow(
      /control characters/
    )
  })

  it('refuses an agent member that is not an object', () => {
    expect(() => requestingAgentOf({ agent: null as never })).toThrow(
      /must be an object/
    )
    expect(() => requestingAgentOf({ agent: ['x'] as never })).toThrow(
      /must be an object/
    )
  })
})

describe('zcapQueriesOf', () => {
  it('normalizes a single capabilityQuery and flattens arrays', () => {
    const a = { controller: 'did:key:a', invocationTarget: 't1' }
    const b = { controller: 'did:key:b', invocationTarget: 't2' }
    const queries: IVPRQuery[] = [
      { type: 'ZcapQuery', capabilityQuery: a },
      { type: 'AuthorizationCapabilityQuery', capabilityQuery: [b] }
    ]
    expect(zcapQueriesOf(queries)).toEqual([a, b])
  })

  it('throws on a zcap query missing its capabilityQuery detail', () => {
    const queries = [{ type: 'ZcapQuery' }] as never as IVPRQuery[]
    expect(() => zcapQueriesOf(queries)).toThrow(/missing its capabilityQuery/)
  })
})

describe('credentialQueriesOf', () => {
  const detail = { reason: 'Please present any VC.', example: {} }

  it('normalizes a single credentialQuery to an array', () => {
    const query: IQueryByExample = {
      type: 'QueryByExample',
      credentialQuery: detail
    }
    expect(credentialQueriesOf(query)).toEqual([detail])
  })

  it('passes an array of credentialQuery details through', () => {
    const query: IQueryByExample = {
      type: 'QueryByExample',
      credentialQuery: [detail, detail]
    }
    expect(credentialQueriesOf(query)).toEqual([detail, detail])
  })

  it('returns an empty array when credentialQuery is absent', () => {
    expect(credentialQueriesOf({ type: 'QueryByExample' } as never)).toEqual([])
  })
})

describe('isDidAuthOnly / didAuthMethodSupported', () => {
  it('isDidAuthOnly is true only for a pure DID Auth request', () => {
    expect(
      isDidAuthOnly({ didAuth: true, vcQueries: [], zcapRequests: [] })
    ).toBe(true)
    expect(
      isDidAuthOnly({
        didAuth: true,
        vcQueries: [
          { type: 'QueryByExample', credentialQuery: { example: {} } }
        ],
        zcapRequests: []
      })
    ).toBe(false)
  })

  it('didAuthMethodSupported honors an acceptedMethods constraint', () => {
    expect(
      didAuthMethodSupported([
        { type: 'DIDAuthentication', acceptedMethods: [{ method: 'key' }] }
      ])
    ).toBe(true)
    expect(
      didAuthMethodSupported([
        { type: 'DIDAuthentication', acceptedMethods: [{ method: 'web' }] }
      ])
    ).toBe(false)
    expect(didAuthMethodSupported([{ type: 'DIDAuthentication' }])).toBe(true)
  })

  it('didAuthMethodSupported dispatches on the presentable methods', () => {
    const accepting = (method: string): IVPRQuery[] => [
      { type: 'DIDAuthentication', acceptedMethods: [{ method }] }
    ]
    const web = accepting('web')
    const webvh = accepting('webvh')
    // A session that can present the account's did:web or did:webvh form
    // answers a request naming either; one that can present neither refuses.
    expect(didAuthMethodSupported(web, ['key', 'web', 'webvh'])).toBe(true)
    expect(didAuthMethodSupported(webvh, ['key', 'web', 'webvh'])).toBe(true)
    expect(didAuthMethodSupported(web, ['key'])).toBe(false)
    expect(didAuthMethodSupported(webvh, ['key'])).toBe(false)
    // A method no session presents is refused whatever the session holds.
    expect(
      didAuthMethodSupported(accepting('ion'), ['key', 'web', 'webvh'])
    ).toBe(false)
    // An unconstrained request stays satisfiable on every set.
    expect(
      didAuthMethodSupported([{ type: 'DIDAuthentication' }], ['key'])
    ).toBe(true)
  })

  it('didAuthMethodSupported tolerates a malformed acceptedMethods', () => {
    expect(
      didAuthMethodSupported([
        { type: 'DIDAuthentication', acceptedMethods: [null] } as never
      ])
    ).toBe(false)
    expect(
      didAuthMethodSupported([
        {
          type: 'DIDAuthentication',
          acceptedMethods: [null, { method: 'key' }]
        } as never
      ])
    ).toBe(true)
    expect(
      didAuthMethodSupported([
        { type: 'DIDAuthentication', acceptedMethods: 'key' } as never
      ])
    ).toBe(true)
  })
})

describe('serializedAppUrl', () => {
  const origin = 'https://app.example'

  it('returns the parsed URL serialization for a valid appUrl', () => {
    expect(
      serializedAppUrl({ appUrl: 'https://app.example/notes/', origin })
    ).toBe('https://app.example/notes/')
  })

  it('normalizes spellings that name the same application', () => {
    // Default port, dot-segments, and percent-encoding case all serialize to
    // one canonical form.
    expect(
      serializedAppUrl({ appUrl: 'https://app.example:443/notes/', origin })
    ).toBe('https://app.example/notes/')
    expect(
      serializedAppUrl({ appUrl: 'https://app.example/a/../notes/', origin })
    ).toBe('https://app.example/notes/')
  })

  it('rejects a relative or unparseable appUrl', () => {
    expect(() => serializedAppUrl({ appUrl: '/notes/', origin })).toThrow(
      /absolute URL/
    )
    expect(() => serializedAppUrl({ appUrl: 'not a url', origin })).toThrow(
      /absolute URL/
    )
  })

  it('rejects an appUrl carrying a fragment, including a bare "#"', () => {
    expect(() =>
      serializedAppUrl({ appUrl: 'https://app.example/notes/#top', origin })
    ).toThrow(/fragment/)
    // A bare trailing "#" sets an empty (non-null) fragment that url.hash
    // reports as '' -- it must still be refused.
    expect(() =>
      serializedAppUrl({ appUrl: 'https://app.example/notes/#', origin })
    ).toThrow(/fragment/)
  })

  it('accepts a percent-encoded %23 (not a fragment)', () => {
    expect(
      serializedAppUrl({ appUrl: 'https://app.example/no%23tes', origin })
    ).toBe('https://app.example/no%23tes')
  })

  it('rejects a cross-origin appUrl', () => {
    expect(() =>
      serializedAppUrl({ appUrl: 'https://evil.example/notes/', origin })
    ).toThrow(/same-origin/)
    expect(() =>
      serializedAppUrl({ appUrl: 'http://app.example/notes/', origin })
    ).toThrow(/same-origin/)
    expect(() =>
      serializedAppUrl({ appUrl: 'https://app.example:8443/notes/', origin })
    ).toThrow(/same-origin/)
  })
})

describe('appConnectRequestOf', () => {
  const origin = 'https://app.example'
  const appConnectQuery = (app: unknown, capabilityQuery?: unknown) =>
    ({ type: 'AppConnectQuery', app, capabilityQuery }) as never as IVPRQuery

  it('returns null when no AppConnectQuery is present', () => {
    expect(
      appConnectRequestOf({
        queries: [{ type: 'DIDAuthentication' }],
        origin
      })
    ).toBeNull()
  })

  it('classifies a valid query, serializing the appUrl', () => {
    const result = appConnectRequestOf({
      queries: [
        appConnectQuery({
          name: 'Notes',
          appUrl: 'https://app.example:443/notes/'
        })
      ],
      origin
    })
    expect(result).toEqual({
      app: { name: 'Notes', appUrl: 'https://app.example/notes/' },
      capabilityQueries: []
    })
  })

  it('normalizes capabilityQuery to an array and rebuilds each entry from the allowlist', () => {
    const result = appConnectRequestOf({
      queries: [
        appConnectQuery(
          { name: 'Notes', appUrl: 'https://app.example/n' },
          {
            referenceId: 'space',
            allowedAction: ['read', 'write'],
            invocationTarget: { type: 'urn:x:collection' },
            reason: 'smuggled display text',
            controller: 'did:key:attacker'
          }
        )
      ],
      origin
    })
    expect(result?.capabilityQueries).toEqual([
      {
        referenceId: 'space',
        allowedAction: ['read', 'write'],
        invocationTarget: { type: 'urn:x:collection' }
      }
    ])
  })

  it('throws on a missing or non-string app member', () => {
    for (const app of [
      undefined,
      { name: 'Notes' },
      { appUrl: 'https://app.example/n' },
      { name: 'Notes', appUrl: 42 },
      { name: 'Notes', credentialType: 'NotesAppKey', vocabBase: 'https://x#' }
    ]) {
      expect(() =>
        appConnectRequestOf({ queries: [appConnectQuery(app)], origin })
      ).toThrow(/app name \/ appUrl/)
    }
  })

  it('throws on an appUrl violating the URL rules', () => {
    for (const appUrl of [
      '/notes/',
      'https://app.example/notes/#frag',
      'https://evil.example/notes/'
    ]) {
      expect(() =>
        appConnectRequestOf({
          queries: [appConnectQuery({ name: 'Notes', appUrl })],
          origin
        })
      ).toThrow()
    }
  })

  it('throws on more than one AppConnectQuery', () => {
    const query = appConnectQuery({
      name: 'Notes',
      appUrl: 'https://app.example/n'
    })
    expect(() =>
      appConnectRequestOf({ queries: [query, query], origin })
    ).toThrow(/More than one AppConnectQuery/)
  })

  it('throws when combined with QueryByExample or standalone zcap queries', () => {
    const query = appConnectQuery({
      name: 'Notes',
      appUrl: 'https://app.example/n'
    })
    for (const other of [
      { type: 'QueryByExample', credentialQuery: { example: {} } },
      { type: 'AuthorizationCapabilityQuery', capabilityQuery: {} },
      { type: 'ZcapQuery', capabilityQuery: {} }
    ] as IVPRQuery[]) {
      expect(() =>
        appConnectRequestOf({ queries: [query, other], origin })
      ).toThrow(/cannot be combined/)
    }
  })

  it('throws on a malformed capabilityQuery entry', () => {
    expect(() =>
      appConnectRequestOf({
        queries: [
          appConnectQuery({ name: 'Notes', appUrl: 'https://app.example/n' }, [
            null
          ])
        ],
        origin
      })
    ).toThrow(/malformed capabilityQuery/)
  })
})
