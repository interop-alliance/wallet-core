/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Classification of incoming VC API messages: wrapping CHAPI get / store events
 * as typed requests / offers, normalizing a VPR's queries, and projecting a VPR
 * body onto the `{ didAuth, vcQueries, zcapRequests }` profile. Ported from
 * Freewallet `classify.test.ts` (App Connect cases stay Freewallet-side).
 */
import { describe, it, expect } from 'vitest'
import {
  classifyCHAPIGetEvent,
  classifyCHAPIStoreEvent,
  classifyRequest,
  credentialQueriesOf,
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
  const app = { name: 'x', credentialType: 'y', vocabBase: 'z' }

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
})
