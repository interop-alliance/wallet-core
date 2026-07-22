/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Parsing of incoming wallet API messages: extracting the JSON `request`
 * parameter from a `dccrequest://` deep link (`parseWalletApiUrl`) and
 * classifying a parsed object by its discriminating property
 * (`parseWalletApiMessage`), plus the `isWalletApiMessage` / `zcapsRequested` /
 * `isDIDAuthOnlyRequest` helpers. Ported from DCW `vcApi.test.ts` (parse half);
 * the `query-string` dependency is replaced by the native `URL`, so the
 * `dccrequest://` fixtures are built compactly here rather than copied verbatim.
 */
import { describe, it, expect } from 'vitest'
import {
  isDIDAuthOnlyRequest,
  isWalletApiMessage,
  parseWalletApiMessage,
  parseWalletApiUrl,
  zcapsRequested
} from '../../src/request/index.js'
import type {
  IExchangeInvitation,
  IIssueRequest,
  IVPOffer,
  IVPRequest,
  IVPRQuery,
  WalletApiMessage
} from '../../src/request/index.js'

/** Encodes a message object into a `dccrequest://` deep link. */
function dccrequest(message: object): string {
  return `dccrequest://?request=${encodeURIComponent(JSON.stringify(message))}`
}

describe('parseWalletApiUrl + parseWalletApiMessage', () => {
  it('parses an IExchangeInvitation url', () => {
    const url = dccrequest({
      credentialRequestOrigin:
        'https://interop-alliance.github.io/wallet-to-webapp-demo',
      protocols: {
        vcapi:
          'https://verifierplus.org/api/exchanges/909b5871-a72c-497a-a752-e2c3f12db30b'
      }
    })
    const messageObject = parseWalletApiUrl({ url })!
    expect(messageObject.protocols).toBeTruthy()
    const message = parseWalletApiMessage({
      messageObject
    }) as IExchangeInvitation
    expect(message.protocols.vcapi).toBeTruthy()
  })

  it('parses an IVPRequest url', () => {
    const url = dccrequest({
      credentialRequestOrigin: 'https://example.com/endpoint',
      verifiablePresentationRequest: {
        query: [
          { type: 'DIDAuthentication', acceptedMethods: [{ method: 'key' }] }
        ],
        challenge: '99612b24-63d9-11ea-b99f-4f66f3e4f81a',
        domain: 'https://example.com/endpoint'
      }
    })
    const messageObject = parseWalletApiUrl({ url })!
    expect(messageObject.credentialRequestOrigin).toBeTruthy()
    const message = parseWalletApiMessage({ messageObject }) as IVPRequest
    expect(message.verifiablePresentationRequest).toBeTruthy()
  })

  it('parses an IVPOffer url', () => {
    const url = dccrequest({
      credentialRequestOrigin: 'https://example.com/endpoint',
      verifiablePresentation: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: []
      }
    })
    const messageObject = parseWalletApiUrl({ url })!
    expect(messageObject.credentialRequestOrigin).toBeTruthy()
    const message = parseWalletApiMessage({ messageObject }) as IVPOffer
    expect(message.verifiablePresentation).toBeTruthy()
  })

  it('parses an IIssueRequest url', () => {
    const url = dccrequest({
      credentialRequestOrigin: 'https://example.com/endpoint',
      issueRequest: {
        credential: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential'],
          credentialSubject: { id: 'did:example:1' }
        }
      },
      redirectUrl: 'https://example.com/done'
    })
    const messageObject = parseWalletApiUrl({ url })!
    expect(messageObject.credentialRequestOrigin).toBeTruthy()
    const message = parseWalletApiMessage({ messageObject }) as IIssueRequest
    expect(message.issueRequest.credential).toBeTruthy()
  })

  it('returns undefined when the url carries no request parameter', () => {
    expect(
      parseWalletApiUrl({ url: 'https://example.com/nothing' })
    ).toBeUndefined()
  })

  it('returns undefined when the request parameter is not valid JSON', () => {
    expect(
      parseWalletApiUrl({ url: 'dccrequest://?request=not-json' })
    ).toBeUndefined()
  })

  it('returns undefined for an unrecognized message shape', () => {
    expect(
      parseWalletApiMessage({ messageObject: { foo: 'bar' } })
    ).toBeUndefined()
  })
})

describe('isWalletApiMessage', () => {
  it('recognizes each message shape', () => {
    expect(isWalletApiMessage('{"protocols":{}}')).toBe(true)
    expect(isWalletApiMessage('{"verifiablePresentationRequest":{}}')).toBe(
      true
    )
    expect(isWalletApiMessage('{"verifiablePresentation":{}}')).toBe(true)
    expect(isWalletApiMessage('{"issueRequest":{}}')).toBe(true)
  })

  it('rejects malformed JSON and unrelated objects', () => {
    expect(isWalletApiMessage('not json')).toBe(false)
    expect(isWalletApiMessage('{"foo":"bar"}')).toBe(false)
  })
})

describe('zcapsRequested', () => {
  it('returns the zcap queries (both type strings)', () => {
    const zcapQuery = {
      type: 'ZcapQuery',
      capabilityQuery: { controller: 'did:key:a', invocationTarget: 't' }
    }
    const authQuery = {
      type: 'AuthorizationCapabilityQuery',
      capabilityQuery: { controller: 'did:key:b', invocationTarget: 't2' }
    }
    const queries = [
      { type: 'DIDAuthentication' },
      zcapQuery,
      authQuery
    ] as IVPRQuery[]
    expect(zcapsRequested({ queries })).toEqual({
      zcapRequests: [zcapQuery, authQuery]
    })
  })

  it('returns an empty object when no zcap is requested', () => {
    const queries = [{ type: 'DIDAuthentication' }] as IVPRQuery[]
    expect(zcapsRequested({ queries })).toEqual({})
  })
})

describe('isDIDAuthOnlyRequest', () => {
  it('is true for a VPR whose only query is DIDAuthentication', () => {
    const message: WalletApiMessage = {
      verifiablePresentationRequest: { query: [{ type: 'DIDAuthentication' }] }
    }
    expect(isDIDAuthOnlyRequest(message)).toBe(true)
  })

  it('is false when a credential query is also present', () => {
    const message: WalletApiMessage = {
      verifiablePresentationRequest: {
        query: [
          { type: 'DIDAuthentication' },
          { type: 'QueryByExample', credentialQuery: { example: {} } }
        ]
      }
    }
    expect(isDIDAuthOnlyRequest(message)).toBe(false)
  })

  it('is false for a non-request message', () => {
    const message: WalletApiMessage = { protocols: {} }
    expect(isDIDAuthOnlyRequest(message)).toBe(false)
  })
})
