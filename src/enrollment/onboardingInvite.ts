/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The inviter's half of the wallet-onboarding invite: creating an ephemeral
 * exchange on the WAS server that carries a `WalletOnboardingQuery`
 * (`@interop/wallet-core/request`) as its stored request, and polling that
 * exchange until the other wallet posts its response envelope
 * (`onboardingResponse.ts`). Pure logic -- no UI framework, no DOM, and no
 * module-level mutable state: every run is per-instance, cancelled through the
 * caller's `AbortSignal`, with the network transport injected.
 *
 * These routes are deliberately unauthenticated (a capability-URL posture: the
 * exchange URL is the secret, and it travels point-to-point through the QR
 * code), so nothing here signs a request.
 */

/**
 * How often the inviter polls the exchange for the enrollee's response.
 */
export const ONBOARDING_POLL_INTERVAL_MS = 3000

/**
 * How long an invite is offered for, comfortably inside the server's
 * ten-minute exchange TTL so the countdown expires before the server does.
 */
export const ONBOARDING_INVITE_TTL_MS = 5 * 60 * 1000

/**
 * The exchange path the interaction URL adds, with the interaction-URL
 * version query the other wallet's scanner expects.
 */
export const ONBOARDING_INTERACTION_PATH = '/protocols?iuv=1'

/**
 * The subset of `fetch` this module uses, so a caller (or a test) injects its
 * own transport instead of relying on the global.
 */
type FetchLike = (input: string, init?: RequestInit) => Promise<Response>

/**
 * Raised when the exchange is no longer on the server (a `404`): it either
 * expired or was never created. The remedy is a fresh invite, so a caller
 * renders its "code expired" state. Dispatch on `err.name` rather than
 * `instanceof`: the transport is injected and may resolve to a different copy
 * of this package, which makes the name the stable contract.
 */
export class OnboardingExchangeGoneError extends Error {
  constructor(message = 'The onboarding exchange is no longer available.') {
    super(message)
    this.name = 'OnboardingExchangeGoneError'
  }
}

/**
 * Strips a trailing slash from a configured base URL, so joining a path onto
 * it cannot produce a doubled separator.
 *
 * @param options {object}
 * @param options.serverUrl {string}
 * @returns {string}
 */
function normalizedServerUrl({ serverUrl }: { serverUrl: string }): string {
  return serverUrl.replace(/\/+$/, '')
}

/**
 * INVITER: creates an ephemeral exchange holding the onboarding request as its
 * stored request, and returns both the exchange URL (the inviter polls it) and
 * the interaction URL (the QR code carries it).
 *
 * The server relays the stored request verbatim as its reply to the begin
 * POST, so the VPR details are stored wrapped as a VC-API exchange response
 * (`{ verifiablePresentationRequest: request }`) -- the shape the joining
 * wallet's classifier reads.
 *
 * The exchange URL is read from the `Location` response header, falling back
 * to the body's `location` member -- deployments differ on which they set,
 * and either alone is enough.
 *
 * @param options {object}
 * @param options.serverUrl {string}   the configured WAS server base URL
 * @param options.request {unknown}   the VPR details to store
 * @param [options.fetch] {FetchLike}
 * @returns {Promise<{ exchangeUrl: string, interactionUrl: string }>}
 */
export async function createOnboardingExchange({
  serverUrl,
  request,
  fetch: fetchImpl = globalThis.fetch
}: {
  serverUrl: string
  request: unknown
  fetch?: FetchLike
}): Promise<{ exchangeUrl: string; interactionUrl: string }> {
  const url = `${normalizedServerUrl({ serverUrl })}/workflows/ephemeral/exchanges`
  const response = await fetchImpl(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      request: { verifiablePresentationRequest: request }
    })
  })
  if (!response.ok) {
    throw new Error(
      `Could not create the onboarding exchange (HTTP ${response.status}).`
    )
  }
  let exchangeUrl = response.headers?.get('location') ?? ''
  if (!exchangeUrl) {
    try {
      const body = (await response.json()) as { location?: string }
      exchangeUrl = body?.location ?? ''
    } catch (err) {
      console.warn('Could not parse the created exchange body:', err)
    }
  }
  if (!exchangeUrl) {
    throw new Error('The created onboarding exchange has no location.')
  }
  return {
    exchangeUrl,
    interactionUrl: `${exchangeUrl}${ONBOARDING_INTERACTION_PATH}`
  }
}

/**
 * Sleeps for `delayMs`, rejecting promptly with the signal's reason if the
 * caller aborts first. The timer is always cleared.
 *
 * @param options {object}
 * @param options.delayMs {number}
 * @param [options.signal] {AbortSignal}
 * @returns {Promise<void>}
 */
function abortableDelay({
  delayMs,
  signal
}: {
  delayMs: number
  signal?: AbortSignal
}): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason)
      return
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolve()
    }, delayMs)
    function onAbort() {
      clearTimeout(timer)
      reject(signal?.reason)
    }
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

/**
 * INVITER: polls the exchange until the other wallet posts its response, and
 * resolves with that response body verbatim (the caller's consent panel
 * interprets it, typically through `parseOnboardingResponse`).
 *
 * A `404` means the exchange expired or was never there, and rejects with
 * {@link OnboardingExchangeGoneError}. Every other failure -- a network
 * error, another non-ok status, an unparseable body -- is transient and
 * simply retried on the next tick. An aborted signal rejects promptly with
 * the signal's reason, cancelling any in-flight request.
 *
 * @param options {object}
 * @param options.exchangeUrl {string}
 * @param [options.signal] {AbortSignal}
 * @param [options.intervalMs] {number}
 * @param [options.fetch] {FetchLike}
 * @returns {Promise<unknown>}   the completed exchange's `response` member
 */
export async function pollOnboardingExchange({
  exchangeUrl,
  signal,
  intervalMs = ONBOARDING_POLL_INTERVAL_MS,
  fetch: fetchImpl = globalThis.fetch
}: {
  exchangeUrl: string
  signal?: AbortSignal
  intervalMs?: number
  fetch?: FetchLike
}): Promise<unknown> {
  for (;;) {
    if (signal?.aborted) {
      throw signal.reason
    }
    try {
      const response = await fetchImpl(exchangeUrl, { signal })
      if (response.status === 404) {
        throw new OnboardingExchangeGoneError()
      }
      if (response.ok) {
        const body = (await response.json()) as {
          state?: string
          response?: unknown
        }
        if (body?.state === 'complete') {
          return body.response
        }
      }
    } catch (err) {
      if (signal?.aborted) {
        throw signal.reason
      }
      if ((err as Error)?.name === 'OnboardingExchangeGoneError') {
        throw err
      }
      // Anything else is transient -- keep polling.
      console.warn('Polling the onboarding exchange failed; retrying:', err)
    }
    await abortableDelay({ delayMs: intervalMs, signal })
  }
}
