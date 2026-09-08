/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the pure request-to-response pipeline
 * (`src/request/processRequest.ts`): the domain-binding check, the App Connect
 * gate and its preconditions (processor present, origin present, query
 * well-formed), the zcap delegation path, the nothing-to-send case, and the
 * signed DID-Auth response. Real Ed25519 keys sign the presentations.
 */
import { describe, expect, it, vi } from 'vitest'
import {
  domainMatchesOrigin,
  hasAppConnectQuery,
  processRequest
} from '../../src/request/index.js'
import type {
  IVPRDetails,
  IVPRQuery,
  IZcap,
  RequestProcessors
} from '../../src/request/index.js'
import { makePresentationSigner } from './fixtures/request/signer.js'

const ORIGIN = 'https://app.example'

function queryOfType(type: string, rest: object = {}): IVPRQuery {
  return { type, ...rest } as never as IVPRQuery
}

function appConnectQuery(app: object = { name: 'Demo', appUrl: ORIGIN + '/' }) {
  return queryOfType('AppConnectQuery', {
    app,
    capabilityQuery: {
      referenceId: 'space',
      allowedAction: ['GET'],
      invocationTarget: 'https://was.example/space/abc/'
    }
  })
}

describe('domainMatchesOrigin', () => {
  it('matches a bare host against a full origin URL', () => {
    expect(
      domainMatchesOrigin({ domain: 'verifier.example', origin: ORIGIN })
    ).toBe(false)
    expect(domainMatchesOrigin({ domain: 'app.example', origin: ORIGIN })).toBe(
      true
    )
    expect(
      domainMatchesOrigin({ domain: 'https://app.example/x', origin: ORIGIN })
    ).toBe(true)
  })

  it('fails closed with no origin or an unparseable domain', () => {
    expect(domainMatchesOrigin({ domain: 'app.example' })).toBe(false)
    expect(domainMatchesOrigin({ domain: 'not a host', origin: ORIGIN })).toBe(
      false
    )
  })
})

describe('hasAppConnectQuery', () => {
  it('is true exactly when an AppConnectQuery is in the set', () => {
    expect(hasAppConnectQuery([])).toBe(false)
    expect(hasAppConnectQuery([queryOfType('DIDAuthentication')])).toBe(false)
    expect(
      hasAppConnectQuery([queryOfType('DIDAuthentication'), appConnectQuery()])
    ).toBe(true)
  })
})

describe('processRequest', () => {
  it('refuses a DID Auth domain the request did not arrive from', async () => {
    const presentationSigner = await makePresentationSigner()
    const request: IVPRDetails = {
      query: queryOfType('DIDAuthentication'),
      challenge: 'c1',
      domain: 'verifier.example'
    }
    await expect(
      processRequest({
        request,
        presentationSigner,
        credentialRequestOrigin: 'https://other.example'
      })
    ).rejects.toThrow(/does not match request origin/)
  })

  it('returns {} when there is nothing to send', async () => {
    const presentationSigner = await makePresentationSigner()
    const request: IVPRDetails = { query: queryOfType('QueryByExample') }
    await expect(
      processRequest({ request, presentationSigner })
    ).resolves.toEqual({})
  })

  it('signs a DID-Auth VP with the holder set when the domain matches', async () => {
    const presentationSigner = await makePresentationSigner()
    const request: IVPRDetails = {
      query: queryOfType('DIDAuthentication'),
      challenge: 'c1',
      domain: 'app.example'
    }
    const response = await processRequest({
      request,
      presentationSigner,
      credentialRequestOrigin: ORIGIN
    })
    expect(response.verifiablePresentation?.holder).toBe(
      presentationSigner.holder
    )
    expect(response.verifiablePresentation?.proof).toBeDefined()
    expect(response.zcaps).toEqual([])
  })

  it('delegates the approved capabilities and returns them beside the VP', async () => {
    const presentationSigner = await makePresentationSigner()
    const zcap = { id: 'urn:zcap:1' } as never as IZcap
    const processZcaps: NonNullable<RequestProcessors['processZcaps']> = vi.fn(
      async () => [zcap]
    )
    const request: IVPRDetails = {
      query: [
        queryOfType('AuthorizationCapabilityQuery', {
          capabilityQuery: {
            referenceId: 'space',
            allowedAction: ['GET'],
            invocationTarget: 'https://was.example/space/abc/'
          }
        })
      ]
    }
    const response = await processRequest({
      request,
      presentationSigner,
      processors: { processZcaps }
    })
    expect(processZcaps).toHaveBeenCalledOnce()
    expect(
      vi
        .mocked(processZcaps)
        .mock.calls[0]![0].zcapRequests.map(detail => detail.referenceId)
    ).toEqual(['space'])
    expect(response.zcaps).toEqual([zcap])
    expect(response.verifiablePresentation?.proof).toBeUndefined()
  })

  describe('the App Connect gate', () => {
    it('refuses an App Connect request with no processAppConnect processor', async () => {
      const presentationSigner = await makePresentationSigner()
      await expect(
        processRequest({
          request: { query: appConnectQuery() },
          presentationSigner,
          credentialRequestOrigin: ORIGIN
        })
      ).rejects.toThrow(/no processAppConnect/)
    })

    it('refuses an App Connect request with no requesting origin', async () => {
      const presentationSigner = await makePresentationSigner()
      const processAppConnect = vi.fn()
      await expect(
        processRequest({
          request: { query: appConnectQuery() },
          presentationSigner,
          processors: { processAppConnect }
        })
      ).rejects.toThrow(/requires a requesting origin/)
      expect(processAppConnect).not.toHaveBeenCalled()
    })

    it('surfaces a malformed app block before the processor runs', async () => {
      const presentationSigner = await makePresentationSigner()
      const processAppConnect = vi.fn()
      await expect(
        processRequest({
          request: { query: appConnectQuery({ name: 'Demo' }) },
          presentationSigner,
          credentialRequestOrigin: ORIGIN,
          processors: { processAppConnect }
        })
      ).rejects.toThrow(/missing its app name \/ appUrl/)
      expect(processAppConnect).not.toHaveBeenCalled()
    })

    it('hands the validated request to the processor and returns its response', async () => {
      const presentationSigner = await makePresentationSigner()
      const walletResponse = { verifiablePresentation: undefined, zcaps: [] }
      const processAppConnect: NonNullable<
        RequestProcessors['processAppConnect']
      > = vi.fn(async () => walletResponse)
      const request: IVPRDetails = {
        query: [queryOfType('DIDAuthentication'), appConnectQuery()],
        challenge: 'c1',
        domain: 'app.example'
      }
      const response = await processRequest({
        request,
        presentationSigner,
        credentialRequestOrigin: ORIGIN,
        processors: { processAppConnect },
        cryptosuite: 'eddsa-rdfc-2022'
      })
      expect(response).toBe(walletResponse)
      expect(processAppConnect).toHaveBeenCalledOnce()
      const args = vi.mocked(processAppConnect).mock.calls[0]![0]
      expect(args.request).toBe(request)
      expect(args.origin).toBe(ORIGIN)
      expect(args.challenge).toBe('c1')
      expect(args.domain).toBe('app.example')
      expect(args.didAuthRequested).toBe(true)
      expect(args.cryptosuite).toBe('eddsa-rdfc-2022')
      expect(args.appConnect.app).toEqual({
        name: 'Demo',
        appUrl: ORIGIN + '/'
      })
      expect(args.appConnect.capabilityQueries).toEqual([
        {
          referenceId: 'space',
          allowedAction: ['GET'],
          invocationTarget: 'https://was.example/space/abc/'
        }
      ])
    })
  })
})
