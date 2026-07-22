/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * VCALM `interaction:` URL handling: detecting an interaction URL, normalizing
 * it to its inner HTTPS URL, and fetching the protocols map it advertises. An
 * interaction URL is a level of indirection a verifier / issuer hands the wallet
 * (over a deep link or QR code) that resolves to a `protocols` map naming the
 * real exchange endpoints.
 *
 * Ported verbatim from DCW's `app/lib/interactionUrl.ts`, with the network
 * transport injected ({@link FetchLike}, default `globalThis.fetch`).
 */
import type { FetchLike } from './types.js'

const INTERACTION_SCHEME_PREFIX = 'interaction:'

/**
 * Detects whether a URL is a VCALM interaction URL.
 *
 * Two formats:
 * - `interaction:` scheme: `interaction:https://example.com/path?iuv=1`
 * - HTTPS URL with an `iuv` query param: `https://example.com/path?iuv=1`
 *
 * @param url {string}
 * @returns {boolean}
 */
export function isInteractionUrl(url: string): boolean {
  if (url.startsWith(INTERACTION_SCHEME_PREFIX)) {
    return true
  }
  try {
    const parsed = new URL(url)
    return parsed.searchParams.has('iuv')
  } catch {
    return false
  }
}

/**
 * Normalizes any interaction URL to the inner HTTPS interaction URL. Accepts any
 * URL that passed {@link isInteractionUrl}.
 *
 * - `interaction:https://...?iuv=1` strips the prefix
 * - `interaction:https%3A%2F%2F...` strips the prefix and decodes (URL-encoded
 *   after `interaction:` is non-standard, but handled for robustness)
 * - `https://...?iuv=1` is returned as-is
 *
 * @param url {string}
 * @returns {string}
 */
export function parseInteractionUrl(url: string): string {
  if (!url.startsWith(INTERACTION_SCHEME_PREFIX)) {
    return url
  }
  const inner = url.slice(INTERACTION_SCHEME_PREFIX.length)
  // Non-standard: the inner URL may be URL-encoded after the `interaction:`
  // prefix.
  if (inner.startsWith('http%3A') || inner.startsWith('https%3A')) {
    return decodeURIComponent(inner)
  }
  return inner
}

/**
 * Fetches the interaction protocols response from a VCALM interaction URL. Sends
 * GET with `Accept: application/json` per the VCALM spec, and returns the
 * protocols map. Logs a warning if the `iuv` param value is not `1`; throws if
 * the response is not ok or the `protocols` key is missing.
 *
 * @param interactionUrl {string}
 * @param [options] {object}
 * @param [options.fetch] {FetchLike}
 * @returns {Promise<Record<string, string>>}
 */
export async function fetchInteractionProtocols(
  interactionUrl: string,
  { fetch = globalThis.fetch }: { fetch?: FetchLike } = {}
): Promise<Record<string, string>> {
  try {
    const parsed = new URL(interactionUrl)
    const iuv = parsed.searchParams.get('iuv')
    if (iuv && iuv !== '1') {
      console.warn(
        `[fetchInteractionProtocols] Unexpected iuv value "${iuv}" ` +
          '(expected "1"). Proceeding anyway.'
      )
    }
  } catch {
    throw new Error(`Invalid interaction URL: ${interactionUrl}`)
  }

  const response = await fetch(interactionUrl, {
    headers: { Accept: 'application/json' }
  })

  if (!response.ok) {
    throw new Error(
      `Interaction URL fetch failed: ${response.status} ${response.statusText}`
    )
  }

  const body = await response.json()

  if (!body.protocols || typeof body.protocols !== 'object') {
    throw new Error('Interaction URL response missing "protocols" map.')
  }

  return body.protocols
}
