/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The universal wallet-input classifier: one ordered discrimination for every
 * place a wallet accepts arbitrary text -- a QR scan, a paste box, a file
 * drop, an opened deep link. Each wallet had grown its own ladder, so a
 * grammar one wallet routed the other silently mis-handled (a connect code
 * read as a credential URL, a connection payload read as nothing at all).
 *
 * Classification only: nothing here fetches, navigates, or stores. The caller
 * supplies the handlers ({@link handleWalletInput}) or switches on the
 * discriminated result itself.
 *
 * The order is the whole design, because several grammars are subsets of
 * others. Most specific first:
 *
 * 1. **`was-link`** -- the wallet-connection QR payload, a non-URL JSON blob
 *    (deliberately not a link, so no OS handler ever routes it). Checked first
 *    because it is JSON that would otherwise fall through to the credential
 *    branch.
 * 2. **`connect-code`** -- a `freewallet-connect:` client-enrollment code,
 *    recognized by prefix.
 * 3. **`legacy-request`** -- the legacy credential-request link: a registered
 *    deep link carrying both `vc_request_url` and `issuer`. Necessarily ahead
 *    of the generic deep-link branch, which it would otherwise be swallowed by.
 * 4. **`interaction-url`** -- a VCALM interaction URL (`interaction:` scheme,
 *    or `iuv=1`), the indirection that resolves to a protocols map.
 * 5. **`deep-link`** -- any other link on one of the app's registered schemes,
 *    routed by the app's own link handling.
 * 6. **`wallet-api-message`** -- a wallet API message, either as raw JSON or
 *    carried in a `request` query parameter of a link that is NOT on a
 *    registered scheme (a plain `https:` QR from a site that has one). The
 *    parameter form is checked before the raw-JSON form so the message is
 *    handed back parsed either way.
 * 7. **`credentials`** -- the fallback: raw VC/VP JSON, or a URL to fetch one
 *    from. Deliberately last, since it is the only branch that cannot be
 *    recognized positively.
 *
 * Nothing is classified as "unrecognized": the credential branch is where
 * unrecognized text lands, and the resolver a caller runs there is what
 * produces the honest error message.
 */
import { isConnectCode } from '../enrollment/connectCode.js'
import { WAS_LINK_TYPE } from '../space/wasLink.js'
import { isInteractionUrl } from './interactionUrl.js'
import {
  isWalletApiMessage,
  parseWalletApiMessage,
  parseWalletApiUrl
} from './parse.js'
import type { WalletApiMessage } from './types.js'

/**
 * What a piece of wallet input turned out to be. Every variant carries the
 * trimmed `text` it was classified from, plus whatever the classification
 * already parsed (a classifier that recognized a grammar has usually parsed
 * enough of it that re-parsing in the handler would be waste and drift).
 */
export type WalletInput =
  | { kind: 'was-link'; text: string }
  | { kind: 'connect-code'; text: string }
  | { kind: 'legacy-request'; text: string; params: Record<string, string> }
  | { kind: 'interaction-url'; text: string }
  | { kind: 'deep-link'; text: string }
  | { kind: 'wallet-api-message'; text: string; message: WalletApiMessage }
  | { kind: 'credentials'; text: string }

/**
 * The query parameters of a link, whatever its scheme. Uses the substring
 * after the first `?` rather than `new URL`, so a custom-protocol link parses
 * the same way an `https:` one does.
 *
 * @param text {string}
 * @returns {URLSearchParams}
 */
function queryParamsOf(text: string): URLSearchParams {
  const start = text.indexOf('?')
  return new URLSearchParams(start === -1 ? '' : text.slice(start + 1))
}

/**
 * Whether the text parses as a `was-link` connection payload's JSON shape.
 * Matched structurally on the `t` member rather than by calling the parser, so
 * an unrelated JSON blob is not refused with a connection-code error message.
 *
 * @param text {string}
 * @returns {boolean}
 */
function isWasLinkPayload(text: string): boolean {
  if (!text.startsWith('{')) {
    return false
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    return false
  }
  return (
    parsed !== null &&
    typeof parsed === 'object' &&
    (parsed as { t?: unknown }).t === WAS_LINK_TYPE
  )
}

/**
 * Classifies one piece of wallet input. See the module doc for the order and
 * why each branch sits where it does.
 *
 * @param text {string}   the scanned, pasted, or opened text
 * @param [options] {object}
 * @param [options.deepLinkSchemes] {string[]}   the link prefixes this app has
 *   registered (custom protocols and universal app links). Empty, the
 *   deep-link and legacy-request branches never match -- a wallet with no
 *   registered links has nothing to route them to
 * @returns {WalletInput}
 */
export function classifyWalletInput(
  text: string,
  { deepLinkSchemes = [] }: { deepLinkSchemes?: string[] } = {}
): WalletInput {
  const trimmed = text.trim()

  if (isWasLinkPayload(trimmed)) {
    return { kind: 'was-link', text: trimmed }
  }
  if (isConnectCode(trimmed)) {
    return { kind: 'connect-code', text: trimmed }
  }

  const isDeepLink = deepLinkSchemes.some(scheme => trimmed.startsWith(scheme))
  if (isDeepLink) {
    const params = queryParamsOf(trimmed)
    if (params.has('vc_request_url') && params.has('issuer')) {
      return {
        kind: 'legacy-request',
        text: trimmed,
        params: Object.fromEntries(params.entries())
      }
    }
  }
  if (isInteractionUrl(trimmed)) {
    return { kind: 'interaction-url', text: trimmed }
  }
  if (isDeepLink) {
    return { kind: 'deep-link', text: trimmed }
  }

  // A link on an unregistered scheme can still carry a wallet API message in
  // its `request` parameter (a site's own QR code).
  const carried = parseWalletApiUrl({ url: trimmed })
  const message = carried
    ? parseWalletApiMessage({ messageObject: carried })
    : isWalletApiMessage(trimmed)
      ? parseWalletApiMessage({
          messageObject: JSON.parse(trimmed) as object
        })
      : undefined
  if (message) {
    return { kind: 'wallet-api-message', text: trimmed, message }
  }

  return { kind: 'credentials', text: trimmed }
}

/**
 * The handlers a caller injects, one per classified kind. Every handler is
 * optional: an input whose kind has no handler throws, which is what keeps a
 * wallet that does not implement a grammar from silently doing the wrong thing
 * with it.
 */
export interface WalletInputHandlers<T> {
  wasLink?: (input: { text: string }) => T | Promise<T>
  connectCode?: (input: { text: string }) => T | Promise<T>
  legacyRequest?: (input: {
    text: string
    params: Record<string, string>
  }) => T | Promise<T>
  interactionUrl?: (input: { text: string }) => T | Promise<T>
  deepLink?: (input: { text: string }) => T | Promise<T>
  walletApiMessage?: (input: {
    text: string
    message: WalletApiMessage
  }) => T | Promise<T>
  credentials?: (input: { text: string }) => T | Promise<T>
}

/**
 * Classifies input and dispatches it to the matching handler.
 *
 * @param options {object}
 * @param options.text {string}   the scanned, pasted, or opened text
 * @param [options.deepLinkSchemes] {string[]}   this app's registered link
 *   prefixes
 * @param options.handlers {WalletInputHandlers}   the injected handlers
 * @returns {Promise<*>}   whatever the matching handler resolves to
 */
export async function handleWalletInput<T>({
  text,
  deepLinkSchemes,
  handlers
}: {
  text: string
  deepLinkSchemes?: string[]
  handlers: WalletInputHandlers<T>
}): Promise<T> {
  const input = classifyWalletInput(text, { deepLinkSchemes })
  switch (input.kind) {
    case 'was-link':
      return dispatch({ handler: handlers.wasLink, input })
    case 'connect-code':
      return dispatch({ handler: handlers.connectCode, input })
    case 'legacy-request':
      return dispatch({ handler: handlers.legacyRequest, input })
    case 'interaction-url':
      return dispatch({ handler: handlers.interactionUrl, input })
    case 'deep-link':
      return dispatch({ handler: handlers.deepLink, input })
    case 'wallet-api-message':
      return dispatch({ handler: handlers.walletApiMessage, input })
    default:
      return dispatch({ handler: handlers.credentials, input })
  }
}

/**
 * Runs one handler, or refuses because this wallet does not implement the
 * grammar the input turned out to be.
 *
 * @param options {object}
 * @param [options.handler] {Function}
 * @param options.input {WalletInput}
 * @returns {Promise<*>}
 */
async function dispatch<T, Input extends WalletInput>({
  handler,
  input
}: {
  handler?: (input: Input) => T | Promise<T>
  input: Input
}): Promise<T> {
  if (!handler) {
    throw new Error(`Unhandled wallet input of kind "${input.kind}".`)
  }
  return handler(input)
}
