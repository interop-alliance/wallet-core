/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The requester's half of an ephemeral exchange on a WAS server: creating an
 * exchange that carries a Verifiable Presentation Request as its stored
 * request, and polling that exchange until the answering wallet posts its
 * response. Generic over what the request asks for -- a wallet's onboarding
 * invite stores a `WalletOnboardingQuery` (`onboarding.ts`), a CLI asking for
 * capabilities stores a zcap-only request (`capabilityRequest.ts`). Pure
 * logic: no UI framework, no DOM, and no module-level mutable state; every
 * run is per-instance, cancelled through the caller's `AbortSignal` or the
 * poll's own deadline, with the network transport injected.
 *
 * These routes are deliberately unauthenticated (a capability-URL access model:
 * the exchange URL is the secret, and it travels point-to-point, as a QR code
 * or a printed link), so nothing here signs a request.
 */
import { log } from '../log.js'
import type { FetchLike } from './types.js'

/**
 * How often the requester polls the exchange for the wallet's response.
 */
export const EPHEMERAL_EXCHANGE_POLL_INTERVAL_MS = 3000

/**
 * How long the server keeps an ephemeral exchange. A poll past it can only
 * ever find the exchange gone, so a caller with no other bound (a CLI) passes
 * this as its `timeoutMs`; a UI offering the exchange for a shorter window
 * (an invite countdown) picks its own.
 */
export const EPHEMERAL_EXCHANGE_TTL_MS = 10 * 60 * 1000

/**
 * The exchange path the interaction URL adds, with the interaction-URL
 * version query the answering wallet's scanner expects.
 */
export const EPHEMERAL_EXCHANGE_INTERACTION_PATH = '/protocols?iuv=1'

/**
 * Raised when the exchange is no longer on the server (a `404`): it either
 * expired or was never created. The remedy is a fresh exchange, so a caller
 * renders its "expired" state. Dispatch on `err.name` rather than
 * `instanceof`: the transport is injected and may resolve to a different copy
 * of this package, which makes the name the stable contract.
 *
 * Also what the answering side raises on a 404: `fetchInteractionProtocols`
 * (`interactionUrl.ts`), the exchange client's `postToExchange`-based helpers
 * (`exchangeClient.ts`), and `openInteractionRequest`
 * (`interactionRequest.ts`), which composes both.
 */
export class EphemeralExchangeGoneError extends Error {
  constructor(message = 'The ephemeral exchange is no longer available.') {
    super(message)
    this.name = 'EphemeralExchangeGoneError'
  }
}

/**
 * Raised when the poll's own `timeoutMs` elapses before the exchange
 * completes. Distinct from {@link EphemeralExchangeGoneError}: the exchange
 * may still be on the server and approvable, the requester just stopped
 * waiting. Dispatch on `err.name`, for the same reason as the gone error.
 */
export class EphemeralExchangeTimeoutError extends Error {
  constructor(
    message = 'Timed out waiting for the ephemeral exchange to complete.'
  ) {
    super(message)
    this.name = 'EphemeralExchangeTimeoutError'
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
 * REQUESTER: creates an ephemeral exchange holding the request as its stored
 * request, and returns both the exchange URL (the requester polls it) and the
 * interaction URL (what the QR code or printed link carries).
 *
 * The server relays the stored request verbatim as its reply to the begin
 * POST, so the VPR details are stored wrapped as a VC-API exchange response
 * (`{ verifiablePresentationRequest: request }`) -- the shape the answering
 * wallet's classifier reads.
 *
 * The exchange URL is read from the `Location` response header, falling back
 * to the body's `location` member -- deployments differ on which they set,
 * and either alone is enough.
 *
 * @param options {object}
 * @param options.serverUrl {string}   the WAS server base URL
 * @param options.request {unknown}   the VPR details to store
 * @param [options.fetch] {FetchLike}
 * @returns {Promise<{ exchangeUrl: string, interactionUrl: string }>}
 */
export async function createEphemeralExchange({
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
      `Could not create the ephemeral exchange (HTTP ${response.status}).`
    )
  }
  let exchangeUrl = response.headers?.get('location') ?? ''
  if (!exchangeUrl) {
    try {
      const body = (await response.json()) as { location?: string }
      exchangeUrl = body?.location ?? ''
    } catch (err) {
      log.warn('Could not parse the created exchange body', { err })
    }
  }
  if (!exchangeUrl) {
    throw new Error('The created ephemeral exchange has no location.')
  }
  return {
    exchangeUrl,
    interactionUrl: `${exchangeUrl}${EPHEMERAL_EXCHANGE_INTERACTION_PATH}`
  }
}

/**
 * Sleeps for `delayMs`, rejecting promptly with the signal's reason if the
 * signal aborts first. The timer is always cleared.
 *
 * @param options {object}
 * @param options.delayMs {number}
 * @param options.signal {AbortSignal}
 * @returns {Promise<void>}
 */
function abortableDelay({
  delayMs,
  signal
}: {
  delayMs: number
  signal: AbortSignal
}): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(signal.reason)
      return
    }
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort)
      resolve()
    }, delayMs)
    function onAbort() {
      clearTimeout(timer)
      reject(signal.reason)
    }
    signal.addEventListener('abort', onAbort, { once: true })
  })
}

/**
 * REQUESTER: polls the exchange until the wallet posts its response, and
 * resolves with that response body verbatim (the caller interprets it: an
 * onboarding invite through `parseOnboardingResponse`, a capability request
 * by reading the presentation's `zcap` member).
 *
 * A `404` means the exchange expired or was never there, and rejects with
 * {@link EphemeralExchangeGoneError}. Every other failure -- a network error,
 * another non-ok status, an unparseable body -- is transient and simply
 * retried on the next tick. Two bounds end the wait early: the caller's
 * `signal` rejects promptly with its own reason, and `timeoutMs` (measured
 * from the call) rejects with {@link EphemeralExchangeTimeoutError}; either
 * cancels an in-flight request. Without both, the poll runs until the
 * exchange completes or disappears.
 *
 * @param options {object}
 * @param options.exchangeUrl {string}
 * @param [options.signal] {AbortSignal}
 * @param [options.timeoutMs] {number}   the poll's own deadline
 * @param [options.intervalMs] {number}
 * @param [options.fetch] {FetchLike}
 * @returns {Promise<unknown>}   the completed exchange's `response` member
 */
export async function pollEphemeralExchange({
  exchangeUrl,
  signal,
  timeoutMs,
  intervalMs = EPHEMERAL_EXCHANGE_POLL_INTERVAL_MS,
  fetch: fetchImpl = globalThis.fetch
}: {
  exchangeUrl: string
  signal?: AbortSignal
  timeoutMs?: number
  intervalMs?: number
  fetch?: FetchLike
}): Promise<unknown> {
  // One internal signal folds the caller's abort and the deadline together,
  // so a single `signal` reaches fetch and the delay. The caller's reason is
  // forwarded verbatim; the deadline aborts with the timeout error.
  const controller = new AbortController()
  const onCallerAbort = () => controller.abort(signal?.reason)
  if (signal?.aborted) {
    onCallerAbort()
  } else {
    signal?.addEventListener('abort', onCallerAbort, { once: true })
  }
  const deadline =
    timeoutMs === undefined
      ? undefined
      : setTimeout(
          () => controller.abort(new EphemeralExchangeTimeoutError()),
          timeoutMs
        )
  try {
    for (;;) {
      if (controller.signal.aborted) {
        throw controller.signal.reason
      }
      try {
        const response = await fetchImpl(exchangeUrl, {
          signal: controller.signal
        })
        if (response.status === 404) {
          throw new EphemeralExchangeGoneError()
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
        if (controller.signal.aborted) {
          throw controller.signal.reason
        }
        if ((err as Error)?.name === 'EphemeralExchangeGoneError') {
          throw err
        }
        // Anything else is transient -- keep polling.
        log.warn('Polling the ephemeral exchange failed; retrying', { err })
      }
      await abortableDelay({ delayMs: intervalMs, signal: controller.signal })
    }
  } finally {
    signal?.removeEventListener('abort', onCallerAbort)
    if (deadline !== undefined) {
      clearTimeout(deadline)
    }
  }
}
