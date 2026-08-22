/**
 * Unit tests for the requester's ephemeral-exchange transport
 * (`src/request/ephemeralExchange.ts`): the exact shape of the create call
 * (both wallet apps must POST byte-identical bodies to the same route, with
 * the stored request wrapped as a VC-API `verifiablePresentationRequest`
 * response body), the
 * `Location`-header / body-`location` fallback, and the polling loop's three
 * outcomes -- complete, gone (a `404`), and transient-and-retried -- plus the
 * abort path, which must both reject with the caller's reason and stop
 * fetching, and the deadline, which rejects with its own error class. The
 * transport is injected, so no network is touched. The zcap-only VPR builder
 * (`src/request/capabilityRequest.ts`) is covered at the end.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ONBOARDING_INVITE_TTL_MS } from '../../src/enrollment/onboardingInvite.js'
import { composeCapabilityRequest } from '../../src/request/capabilityRequest.js'
import {
  createEphemeralExchange,
  EPHEMERAL_EXCHANGE_INTERACTION_PATH,
  EPHEMERAL_EXCHANGE_POLL_INTERVAL_MS,
  EPHEMERAL_EXCHANGE_TTL_MS,
  EphemeralExchangeGoneError,
  EphemeralExchangeTimeoutError,
  pollEphemeralExchange
} from '../../src/request/ephemeralExchange.js'

const SERVER_URL = 'https://was.example'
const EXCHANGE_URL = 'https://was.example/workflows/ephemeral/exchanges/abc123'
const REQUEST = { query: [{ type: 'WalletOnboardingQuery' }] }

/**
 * A minimal `Response` stand-in: only the members the module reads.
 *
 * @param [options] {object}
 * @param [options.status] {number}
 * @param [options.headers] {Record<string, string>}
 * @param [options.body] {unknown}
 * @returns {Response}
 */
function fakeResponse({
  status = 200,
  headers = {},
  body
}: {
  status?: number
  headers?: Record<string, string>
  body?: unknown
} = {}): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get: (name: string) => headers[name.toLowerCase()] ?? null
    },
    json: async () => {
      if (body === undefined) {
        throw new Error('No JSON body.')
      }
      return body
    }
  } as unknown as Response
}

describe('createEphemeralExchange', () => {
  it('posts the request and reads the Location header', async () => {
    const fetchMock = vi.fn(async () =>
      fakeResponse({ status: 201, headers: { location: EXCHANGE_URL } })
    )

    const created = await createEphemeralExchange({
      serverUrl: SERVER_URL,
      request: REQUEST,
      fetch: fetchMock
    })

    expect(fetchMock).toHaveBeenCalledWith(
      'https://was.example/workflows/ephemeral/exchanges',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          request: { verifiablePresentationRequest: REQUEST }
        })
      }
    )
    expect(created.exchangeUrl).toBe(EXCHANGE_URL)
    expect(created.interactionUrl).toBe(
      `${EXCHANGE_URL}${EPHEMERAL_EXCHANGE_INTERACTION_PATH}`
    )
    expect(EPHEMERAL_EXCHANGE_INTERACTION_PATH).toBe('/protocols?iuv=1')
  })

  it('falls back to the body location when no header is set', async () => {
    const fetchMock = vi.fn(async () =>
      fakeResponse({ status: 201, body: { location: EXCHANGE_URL } })
    )

    const created = await createEphemeralExchange({
      serverUrl: SERVER_URL,
      request: REQUEST,
      fetch: fetchMock
    })

    expect(created.exchangeUrl).toBe(EXCHANGE_URL)
  })

  it('tolerates a trailing slash on the server URL', async () => {
    const fetchMock = vi.fn(async () =>
      fakeResponse({ status: 201, headers: { location: EXCHANGE_URL } })
    )

    await createEphemeralExchange({
      serverUrl: 'https://was.example/',
      request: REQUEST,
      fetch: fetchMock
    })

    expect(fetchMock).toHaveBeenCalledWith(
      'https://was.example/workflows/ephemeral/exchanges',
      expect.anything()
    )
  })

  it('throws when the server refuses the create', async () => {
    const fetchMock = vi.fn(async () => fakeResponse({ status: 429 }))

    await expect(
      createEphemeralExchange({
        serverUrl: SERVER_URL,
        request: REQUEST,
        fetch: fetchMock
      })
    ).rejects.toThrow(/429/)
  })

  it('throws when the created exchange has no location', async () => {
    const fetchMock = vi.fn(async () => fakeResponse({ status: 201, body: {} }))

    await expect(
      createEphemeralExchange({
        serverUrl: SERVER_URL,
        request: REQUEST,
        fetch: fetchMock
      })
    ).rejects.toThrow(/no location/)
  })
})

describe('pollEphemeralExchange', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('resolves with the response once the exchange completes', async () => {
    const fetchMock = vi
      .fn<() => Promise<Response>>()
      .mockResolvedValueOnce(
        fakeResponse({ body: { id: 'abc123', sequence: 0, state: 'pending' } })
      )
      .mockResolvedValueOnce(
        fakeResponse({
          body: {
            id: 'abc123',
            sequence: 1,
            state: 'complete',
            response: { verifiablePresentation: { hello: 'world' } }
          }
        })
      )

    const polling = pollEphemeralExchange({
      exchangeUrl: EXCHANGE_URL,
      fetch: fetchMock
    })

    await vi.advanceTimersByTimeAsync(EPHEMERAL_EXCHANGE_POLL_INTERVAL_MS * 2)

    await expect(polling).resolves.toEqual({
      verifiablePresentation: { hello: 'world' }
    })
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('rejects with the gone error on a 404', async () => {
    const fetchMock = vi.fn(async () => fakeResponse({ status: 404 }))

    const polling = pollEphemeralExchange({
      exchangeUrl: EXCHANGE_URL,
      fetch: fetchMock
    })
    const settled = await polling.catch((err: unknown) => err)

    expect(settled).toBeInstanceOf(EphemeralExchangeGoneError)
    expect((settled as Error).name).toBe('EphemeralExchangeGoneError')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('retries a transient network failure', async () => {
    const fetchMock = vi
      .fn<() => Promise<Response>>()
      .mockRejectedValueOnce(new Error('network down'))
      .mockResolvedValueOnce(
        fakeResponse({ body: { state: 'complete', response: { ok: true } } })
      )

    const polling = pollEphemeralExchange({
      exchangeUrl: EXCHANGE_URL,
      fetch: fetchMock
    })

    await vi.advanceTimersByTimeAsync(EPHEMERAL_EXCHANGE_POLL_INTERVAL_MS * 2)

    await expect(polling).resolves.toEqual({ ok: true })
  })

  it('stops polling and rejects when the signal aborts', async () => {
    const fetchMock = vi.fn(async () =>
      fakeResponse({ body: { state: 'pending' } })
    )
    const controller = new AbortController()

    const polling = pollEphemeralExchange({
      exchangeUrl: EXCHANGE_URL,
      signal: controller.signal,
      fetch: fetchMock
    })
    const settled = polling.catch((err: unknown) => err)

    await vi.advanceTimersByTimeAsync(EPHEMERAL_EXCHANGE_POLL_INTERVAL_MS)
    const callsBeforeAbort = fetchMock.mock.calls.length
    controller.abort(new Error('cancelled'))

    await expect(settled).resolves.toEqual(new Error('cancelled'))

    await vi.advanceTimersByTimeAsync(EPHEMERAL_EXCHANGE_POLL_INTERVAL_MS * 3)
    expect(fetchMock).toHaveBeenCalledTimes(callsBeforeAbort)
  })

  it('rejects immediately when the signal is already aborted', async () => {
    const fetchMock = vi.fn(async () =>
      fakeResponse({ body: { state: 'pending' } })
    )
    const controller = new AbortController()
    controller.abort(new Error('cancelled before start'))

    const settled = await pollEphemeralExchange({
      exchangeUrl: EXCHANGE_URL,
      signal: controller.signal,
      fetch: fetchMock
    }).catch((err: unknown) => err)

    expect(settled).toEqual(new Error('cancelled before start'))
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('passes the signal to fetch so an in-flight request is cancelled', async () => {
    const fetchMock = vi.fn(async () =>
      fakeResponse({ body: { state: 'complete', response: null } })
    )
    const controller = new AbortController()

    await pollEphemeralExchange({
      exchangeUrl: EXCHANGE_URL,
      signal: controller.signal,
      fetch: fetchMock
    })

    expect(fetchMock).toHaveBeenCalledWith(EXCHANGE_URL, {
      signal: expect.any(AbortSignal)
    })
  })

  it('aborts the in-flight request when the caller aborts', async () => {
    let seenSignal: AbortSignal | undefined
    const fetchMock = vi.fn(
      (_url: string, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          seenSignal = init?.signal ?? undefined
          seenSignal?.addEventListener('abort', () =>
            reject(seenSignal?.reason)
          )
        })
    )
    const controller = new AbortController()

    const settled = pollEphemeralExchange({
      exchangeUrl: EXCHANGE_URL,
      signal: controller.signal,
      fetch: fetchMock
    }).catch((err: unknown) => err)
    await vi.advanceTimersByTimeAsync(0)
    controller.abort(new Error('cancelled mid-flight'))

    await expect(settled).resolves.toEqual(new Error('cancelled mid-flight'))
    expect(seenSignal?.aborted).toBe(true)
  })

  it('rejects with the timeout error once timeoutMs elapses', async () => {
    const fetchMock = vi.fn(async () =>
      fakeResponse({ body: { state: 'pending' } })
    )

    const settled = pollEphemeralExchange({
      exchangeUrl: EXCHANGE_URL,
      timeoutMs: EPHEMERAL_EXCHANGE_POLL_INTERVAL_MS * 2 + 1,
      fetch: fetchMock
    }).catch((err: unknown) => err)

    await vi.advanceTimersByTimeAsync(EPHEMERAL_EXCHANGE_POLL_INTERVAL_MS * 2)
    expect(fetchMock).toHaveBeenCalledTimes(3)
    await vi.advanceTimersByTimeAsync(1)

    const err = await settled
    expect(err).toBeInstanceOf(EphemeralExchangeTimeoutError)
    expect((err as Error).name).toBe('EphemeralExchangeTimeoutError')

    await vi.advanceTimersByTimeAsync(EPHEMERAL_EXCHANGE_POLL_INTERVAL_MS * 3)
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })

  it('aborts the in-flight request at the deadline', async () => {
    const fetchMock = vi.fn(
      (_url: string, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () =>
            reject(init.signal?.reason)
          )
        })
    )

    const settled = pollEphemeralExchange({
      exchangeUrl: EXCHANGE_URL,
      timeoutMs: 500,
      fetch: fetchMock
    }).catch((err: unknown) => err)
    await vi.advanceTimersByTimeAsync(500)

    expect(await settled).toBeInstanceOf(EphemeralExchangeTimeoutError)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('resolves before the deadline and clears its timer', async () => {
    const fetchMock = vi.fn(async () =>
      fakeResponse({ body: { state: 'complete', response: { ok: true } } })
    )

    await expect(
      pollEphemeralExchange({
        exchangeUrl: EXCHANGE_URL,
        timeoutMs: 60_000,
        fetch: fetchMock
      })
    ).resolves.toEqual({ ok: true })
    expect(vi.getTimerCount()).toBe(0)
  })
})

describe('composeCapabilityRequest', () => {
  const detail = {
    controller: 'did:key:z6MkrequesterExample',
    invocationTarget: { type: 'https://w3id.org/byoe#public-collection' },
    allowedAction: ['GET', 'PUT']
  }

  it('wraps the details in one AuthorizationCapabilityQuery', () => {
    expect(composeCapabilityRequest({ capabilityQueries: [detail] })).toEqual({
      query: [
        { type: 'AuthorizationCapabilityQuery', capabilityQuery: [detail] }
      ]
    })
  })

  it('carries a challenge when given one', () => {
    const request = composeCapabilityRequest({
      capabilityQueries: [detail],
      challenge: 'nonce-1'
    })
    expect(request.query).toEqual([
      expect.objectContaining({ challenge: 'nonce-1' })
    ])
  })

  it('refuses an empty request', () => {
    expect(() => composeCapabilityRequest({ capabilityQueries: [] })).toThrow(
      /at least one/
    )
  })

  it('refuses a detail missing its controller or target', () => {
    expect(() =>
      composeCapabilityRequest({
        capabilityQueries: [{ ...detail, controller: '' }]
      })
    ).toThrow(/controller/)
    expect(() =>
      composeCapabilityRequest({
        capabilityQueries: [{ ...detail, invocationTarget: '' }]
      })
    ).toThrow(/invocationTarget/)
  })
})

describe('exchange constants', () => {
  it('expires the onboarding invite inside the server exchange TTL', () => {
    expect(EPHEMERAL_EXCHANGE_TTL_MS).toBe(10 * 60 * 1000)
    expect(ONBOARDING_INVITE_TTL_MS).toBeLessThan(EPHEMERAL_EXCHANGE_TTL_MS)
    expect(EPHEMERAL_EXCHANGE_POLL_INTERVAL_MS).toBeGreaterThan(0)
  })
})
