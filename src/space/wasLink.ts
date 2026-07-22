/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `was-link` QR hand-off payload -- the "Connect mobile wallet" flow where
 * the web wallet displays a QR that carries an account's controller secret and
 * the mobile wallet scans it.
 *
 * The payload is a NON-URL JSON blob (deliberately not a link, so the OS camera
 * app / deep-link handling never routes it and it cannot leak into browser
 * history or link-preview fetchers). It is accepted only by the in-app scanner.
 * Shape: `{ v: 1, t: 'was-link', serverUrl, secret: base64url(utf8(passphrase)) }`.
 */
import { base64urlnopad } from '@scure/base'
import { HumanReadableError } from './errors.js'

/** The decoded link: the WAS server plus the controller secret AS A STRING. */
export interface WasLinkPayload {
  serverUrl: string
  /** The controller secret (already decoded back to the passphrase string). */
  secret: string
}

const NOT_A_LINK = 'This QR code is not a wallet connection code.'
const BAD_SERVER =
  'Connection code points at an insecure or invalid server and was rejected.'

/** Strips optional base64 padding so the no-pad decoder accepts either form. */
function stripPadding(value: string): string {
  return value.replace(/=+$/, '')
}

/**
 * Validates the scanned `serverUrl` before the wallet ever signs a request to
 * it. The code carries the controller secret in the clear, so a bad `serverUrl`
 * would let a crafted QR aim capability-signed requests (and the secret) at an
 * attacker-controlled or cleartext host. Requires a parseable `https:` URL;
 * plain `http:` is allowed ONLY for loopback dev hosts.
 *
 * This is a scheme/host rule, not an allowlist: the payload carries its own
 * `serverUrl`, and there is no app-configured set of permitted servers to inject
 * -- a connection code names the storage server the user is joining. If a
 * consuming app later needs to constrain the host further, that check belongs at
 * the call site, on the returned {@link WasLinkPayload.serverUrl}.
 */
function assertValidServerUrl(serverUrl: string): void {
  let url: URL
  try {
    url = new URL(serverUrl)
  } catch {
    throw new HumanReadableError(BAD_SERVER)
  }
  const isLoopback =
    url.hostname === 'localhost' ||
    url.hostname === '127.0.0.1' ||
    url.hostname === '::1'
  if (url.protocol === 'https:' || (url.protocol === 'http:' && isLoopback)) {
    return
  }
  throw new HumanReadableError(BAD_SERVER)
}

/**
 * Encodes a passphrase into the payload's `secret` field: `base64url(utf8(...))`,
 * no padding.
 *
 * @param passphrase {string}
 * @returns {string}
 */
export function encodeWasLinkSecret(passphrase: string): string {
  return base64urlnopad.encode(new TextEncoder().encode(passphrase))
}

/**
 * Builds the full `was-link` payload string a QR encodes.
 *
 * @param options {object}
 * @param options.serverUrl {string}
 * @param options.passphrase {string}
 * @returns {string}
 */
export function buildWasLinkPayload({
  serverUrl,
  passphrase
}: {
  serverUrl: string
  passphrase: string
}): string {
  return JSON.stringify({
    v: 1,
    t: 'was-link',
    serverUrl,
    secret: encodeWasLinkSecret(passphrase)
  })
}

/**
 * Parses and validates a scanned payload, returning the server URL and the
 * decoded string secret. Throws {@link HumanReadableError} for anything that is
 * not a valid current-version `was-link` payload (so the scanner shows a clean
 * message rather than mis-handling an unrelated QR).
 *
 * @param raw {string}   the raw scanned code value
 * @returns {WasLinkPayload}
 */
export function parseWasLinkPayload(raw: string): WasLinkPayload {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new HumanReadableError(NOT_A_LINK)
  }
  if (typeof parsed !== 'object' || parsed === null) {
    throw new HumanReadableError(NOT_A_LINK)
  }

  const { v, t, serverUrl, secret } = parsed as Record<string, unknown>
  if (t !== 'was-link') {
    throw new HumanReadableError(NOT_A_LINK)
  }
  if (v !== 1) {
    throw new HumanReadableError(
      'This connection code is from a newer app version. Please update.'
    )
  }
  if (typeof serverUrl !== 'string' || serverUrl.length === 0) {
    throw new HumanReadableError('Connection code is missing its server.')
  }
  assertValidServerUrl(serverUrl)
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new HumanReadableError('Connection code is missing its secret.')
  }

  let secretText: string
  try {
    secretText = new TextDecoder().decode(
      base64urlnopad.decode(stripPadding(secret))
    )
  } catch {
    throw new HumanReadableError('Connection code has a malformed secret.')
  }
  if (secretText.length === 0) {
    throw new HumanReadableError('Connection code has an empty secret.')
  }

  return { serverUrl, secret: secretText }
}
