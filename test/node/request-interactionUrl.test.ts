/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * VCALM `interaction:` URL handling: detection, normalization to the inner HTTPS
 * URL, and fetching the advertised protocols map (with the transport injected as
 * a `FetchLike`). Ported from DCW `interactionUrl.test.ts`.
 */
import { describe, it, expect, vi } from 'vitest'
import {
  fetchInteractionProtocols,
  isInteractionUrl,
  parseInteractionUrl
} from '../../src/request/index.js'
import type { FetchLike } from '../../src/request/index.js'

describe('isInteractionUrl', () => {
  it('detects interaction: scheme with plaintext URL', () => {
    expect(isInteractionUrl('interaction:https://example.com/path?iuv=1')).toBe(
      true
    )
  })

  it('detects interaction: scheme with URL-encoded URL', () => {
    expect(
      isInteractionUrl('interaction:https%3A%2F%2Fexample.com%2Fpath%3Fiuv%3D1')
    ).toBe(true)
  })

  it('detects HTTPS URL with iuv=1', () => {
    expect(isInteractionUrl('https://example.com/path?iuv=1')).toBe(true)
  })

  it('detects HTTPS URL with iuv=2 (any iuv value)', () => {
    expect(isInteractionUrl('https://example.com/path?iuv=2')).toBe(true)
  })

  it('returns false for HTTPS URL without iuv', () => {
    expect(isInteractionUrl('https://example.com/path')).toBe(false)
  })

  it('returns false for a wallet API request URL', () => {
    expect(
      isInteractionUrl(
        'https://lcw.app/request?request=%7B%22protocols%22%3A%7B%7D%7D'
      )
    ).toBe(false)
  })

  it('returns false for a dccrequest:// URL', () => {
    expect(
      isInteractionUrl(
        'dccrequest://request?request=%7B%22protocols%22%3A%7B%7D%7D'
      )
    ).toBe(false)
  })

  it('returns false for non-URL text', () => {
    expect(isInteractionUrl('not a url')).toBe(false)
  })
})

describe('parseInteractionUrl', () => {
  it('strips interaction: prefix from plaintext URL', () => {
    expect(
      parseInteractionUrl('interaction:https://example.com/path?iuv=1')
    ).toBe('https://example.com/path?iuv=1')
  })

  it('strips interaction: prefix and decodes URL-encoded URL', () => {
    expect(
      parseInteractionUrl(
        'interaction:https%3A%2F%2Fexample.com%2Fpath%3Fiuv%3D1'
      )
    ).toBe('https://example.com/path?iuv=1')
  })

  it('returns HTTPS interaction URL as-is', () => {
    expect(parseInteractionUrl('https://example.com/path?iuv=1')).toBe(
      'https://example.com/path?iuv=1'
    )
  })

  it('handles interaction: with an http (non-https) URL', () => {
    expect(
      parseInteractionUrl('interaction:http://localhost:3000/path?iuv=1')
    ).toBe('http://localhost:3000/path?iuv=1')
  })

  it('handles interaction: with a URL-encoded http URL', () => {
    expect(
      parseInteractionUrl(
        'interaction:http%3A%2F%2Flocalhost%3A3000%2Fpath%3Fiuv%3D1'
      )
    ).toBe('http://localhost:3000/path?iuv=1')
  })
})

describe('fetchInteractionProtocols', () => {
  const URL_1 = 'https://example.com/interactions/abc?iuv=1'

  function jsonFetch(
    body: unknown,
    init: { ok?: boolean; status?: number; statusText?: string } = {}
  ): FetchLike {
    return vi.fn().mockResolvedValue({
      ok: init.ok ?? true,
      status: init.status ?? 200,
      statusText: init.statusText ?? 'OK',
      json: async () => body
    }) as unknown as FetchLike
  }

  it('fetches with GET and Accept: application/json', async () => {
    const protocols = {
      vcapi: 'https://saas.example/workflows/123/exchanges/987'
    }
    const fetch = jsonFetch({ protocols })
    const result = await fetchInteractionProtocols(URL_1, { fetch })
    expect(result).toEqual(protocols)
    const [url, init] = (fetch as unknown as ReturnType<typeof vi.fn>).mock
      .calls[0]!
    expect(url).toBe(URL_1)
    expect(init.headers.Accept).toBe('application/json')
  })

  it('returns a protocols map with multiple protocols', async () => {
    const protocols = {
      vcapi: 'https://saas.example/workflows/123/exchanges/987',
      OID4VP: 'openid4vp://?client_id=...'
    }
    const result = await fetchInteractionProtocols(URL_1, {
      fetch: jsonFetch({ protocols })
    })
    expect(result).toEqual(protocols)
  })

  it('returns protocols even when no vcapi is present (caller decides)', async () => {
    const protocols = { OID4VP: 'openid4vp://?client_id=...' }
    const result = await fetchInteractionProtocols(URL_1, {
      fetch: jsonFetch({ protocols })
    })
    expect(result).toEqual(protocols)
  })

  it('throws when the response has no protocols key', async () => {
    await expect(
      fetchInteractionProtocols(URL_1, { fetch: jsonFetch({}) })
    ).rejects.toThrow('Interaction URL response missing "protocols" map.')
  })

  it('throws when the response is not ok', async () => {
    await expect(
      fetchInteractionProtocols(URL_1, {
        fetch: jsonFetch(
          {},
          { ok: false, status: 404, statusText: 'Not Found' }
        )
      })
    ).rejects.toThrow('Interaction URL fetch failed: 404 Not Found')
  })
})
