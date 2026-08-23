/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * `openInteractionRequest`: the answering wallet's one-call entry point over a
 * VCALM interaction URL -- resolve the protocols map, begin the named
 * exchange, hand back the VPR. The network transport is injected as a
 * `FetchLike` (a `vi.fn()` mock).
 */
import { describe, it, expect, vi } from 'vitest'
import { openInteractionRequest } from '../../src/request/index.js'
import type { FetchLike, IVPRDetails } from '../../src/request/index.js'

const INTERACTION_URL = 'https://coordinator.example/interactions/abc?iuv=1'
const EXCHANGE_URL = 'https://coordinator.example/workflows/z1/exchanges/z2'

const VPR: IVPRDetails = {
  query: [{ type: 'DIDAuthentication', acceptedMethods: [{ method: 'key' }] }],
  domain: 'verifier.example',
  challenge: 'z1A7B6'
}

function fetchMock({
  protocols,
  protocolsStatus,
  beginStatus,
  beginBody
}: {
  protocols?: Record<string, string>
  protocolsStatus?: number
  beginStatus?: number
  beginBody?: unknown
}): FetchLike {
  return vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
    if (!init || init.method === undefined) {
      // The protocols GET.
      const status = protocolsStatus ?? 200
      return {
        ok: status < 400,
        status,
        statusText: status === 404 ? 'Not Found' : 'OK',
        json: async () => ({ protocols })
      }
    }
    // The exchange begin POST.
    const status = beginStatus ?? 200
    return {
      ok: status < 400,
      status,
      statusText: status === 404 ? 'Not Found' : 'OK',
      text: async () => JSON.stringify(beginBody ?? {})
    }
  }) as unknown as FetchLike
}

describe('openInteractionRequest', () => {
  it('opens an interaction: URL end to end (vcapi)', async () => {
    const fetch = fetchMock({
      protocols: { vcapi: EXCHANGE_URL },
      beginBody: { verifiablePresentationRequest: VPR }
    })
    const result = await openInteractionRequest({
      url: `interaction:${INTERACTION_URL}`,
      fetch
    })
    expect(result).toEqual({
      interactionUrl: INTERACTION_URL,
      exchangeUrl: EXCHANGE_URL,
      request: VPR
    })
    const calls = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls
    const [protocolsUrl, protocolsInit] = calls[0]!
    expect(protocolsUrl).toBe(INTERACTION_URL)
    expect(protocolsInit.headers.Accept).toBe('application/json')
    const [beginUrl, beginInit] = calls[1]!
    expect(beginUrl).toBe(EXCHANGE_URL)
    expect(beginInit.method).toBe('POST')
    expect(beginInit.body).toBe('{}')
  })

  it('opens a bare https URL carrying iuv', async () => {
    const fetch = fetchMock({
      protocols: { vcapi: EXCHANGE_URL },
      beginBody: { verifiablePresentationRequest: VPR }
    })
    const result = await openInteractionRequest({ url: INTERACTION_URL, fetch })
    expect(result.request).toEqual(VPR)
    expect(result.interactionUrl).toBe(INTERACTION_URL)
  })

  it('prefers the interact protocol over vcapi', async () => {
    const interactUrl = 'https://coordinator.example/interactions/z1A2b3'
    const fetch = fetchMock({
      protocols: { interact: interactUrl, vcapi: EXCHANGE_URL },
      beginBody: { verifiablePresentationRequest: VPR }
    })
    const result = await openInteractionRequest({
      url: INTERACTION_URL,
      fetch
    })
    expect(result.exchangeUrl).toBe(interactUrl)
    const calls = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls
    expect(calls[1]![0]).toBe(interactUrl)
  })

  it('refuses text that is not an interaction URL, with no fetch made', async () => {
    const fetch = vi.fn() as unknown as FetchLike
    await expect(
      openInteractionRequest({ url: 'https://example.com/plain', fetch })
    ).rejects.toThrow(/not an interaction url/i)
    expect(fetch).not.toHaveBeenCalled()
  })

  it('reports a 404 on the protocols fetch as EphemeralExchangeGoneError', async () => {
    const fetch = fetchMock({ protocolsStatus: 404 })
    await expect(
      openInteractionRequest({ url: INTERACTION_URL, fetch })
    ).rejects.toMatchObject({ name: 'EphemeralExchangeGoneError' })
  })

  it('reports a 404 on the begin POST as EphemeralExchangeGoneError', async () => {
    const fetch = fetchMock({
      protocols: { vcapi: EXCHANGE_URL },
      beginStatus: 404
    })
    await expect(
      openInteractionRequest({ url: INTERACTION_URL, fetch })
    ).rejects.toMatchObject({ name: 'EphemeralExchangeGoneError' })
  })

  it('refuses a protocols map naming no usable exchange, with no begin POST', async () => {
    const fetch = fetchMock({ protocols: { OID4VP: 'openid4vp://' } })
    await expect(
      openInteractionRequest({ url: INTERACTION_URL, fetch })
    ).rejects.toThrow(/names no usable exchange/)
    expect(
      (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls
    ).toHaveLength(1)
  })

  it('surfaces a begin reply with no VPR', async () => {
    const fetch = fetchMock({
      protocols: { vcapi: EXCHANGE_URL },
      beginBody: { redirectUrl: 'https://x' }
    })
    await expect(
      openInteractionRequest({ url: INTERACTION_URL, fetch })
    ).rejects.toThrow(/did not return a verifiablePresentationRequest/)
  })
})
