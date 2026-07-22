/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Parsing of incoming wallet/VC API messages that arrive as JSON text or a
 * deep-link URL (`dccrequest://...?request=<json>`), plus the small
 * query-inspection helpers a caller runs over a parsed VPR body. Ported from
 * DCW's `app/lib/walletRequestApi.ts`; the `query-string` dependency is dropped
 * in favor of the native `URL` / `URLSearchParams`.
 */
import type {
  IExchangeInvitation,
  IIssueRequest,
  IVPOffer,
  IVPRequest,
  IVPRQuery,
  IZcapQuery,
  WalletApiMessage
} from './types.js'

// The DID-Auth query helper is spelled `isDIDAuthRequested` in `classify.ts`;
// DCW imported it as `isDidAuthRequested`. Both names resolve to one function.
export { isDIDAuthRequested as isDidAuthRequested } from './classify.js'

/**
 * Whether a JSON string is a recognized wallet API message: an exchange
 * invitation, a presentation request, a presentation offer, or an issuance
 * request. Malformed JSON is not a message.
 *
 * @param text {string}
 * @returns {boolean}
 */
export function isWalletApiMessage(text: string): boolean {
  let messageObject
  try {
    messageObject = JSON.parse(text)
  } catch (_) {
    return false
  }
  return (
    !!messageObject &&
    typeof messageObject === 'object' &&
    ('protocols' in messageObject ||
      'verifiablePresentationRequest' in messageObject ||
      'verifiablePresentation' in messageObject ||
      'issueRequest' in messageObject)
  )
}

/**
 * Classifies a parsed message object into one of the wallet API message types
 * by its discriminating property. Returns `undefined` for an unrecognized
 * shape.
 *
 * @param options {object}
 * @param options.messageObject {object}
 * @returns {WalletApiMessage | undefined}
 */
export function parseWalletApiMessage({
  messageObject
}: {
  messageObject: object
}): WalletApiMessage | undefined {
  if ('protocols' in messageObject) {
    return messageObject as IExchangeInvitation
  }
  if ('verifiablePresentationRequest' in messageObject) {
    return messageObject as IVPRequest
  }
  if ('verifiablePresentation' in messageObject) {
    return messageObject as IVPOffer
  }
  if ('issueRequest' in messageObject) {
    return messageObject as IIssueRequest
  }
  // Message not recognized / not supported, return undefined.
  return undefined
}

/**
 * Extracts and parses the wallet API message carried in a deep-link URL's
 * `request` query parameter (`dccrequest://...?request=<json>`). Returns
 * `undefined` when the parameter is absent or its value is not valid JSON.
 *
 * @param options {object}
 * @param options.url {string}
 * @returns {Record<string, unknown> | undefined}
 */
export function parseWalletApiUrl({
  url
}: {
  url: string
}): Record<string, unknown> | undefined {
  let messageText: string | null
  try {
    messageText = new URL(url).searchParams.get('request')
  } catch {
    return undefined
  }
  if (messageText === null) {
    // URL does not contain a "request" parameter.
    return undefined
  }
  try {
    // `URLSearchParams.get` has already percent-decoded the value.
    return JSON.parse(messageText) as Record<string, unknown>
  } catch (err) {
    console.error(
      `Error parsing incoming wallet API message: "${messageText}"`,
      err
    )
    return undefined
  }
}

/**
 * Filters an incoming VCALM query set for capability (zcap) requests, returning
 * only those. Recognizes both the canonical `AuthorizationCapabilityQuery` and
 * the legacy `ZcapQuery` type strings.
 *
 * @param options {object}
 * @param options.queries {IVPRQuery[]}
 * @returns {{ zcapRequests?: IZcapQuery[] }}
 */
export function zcapsRequested({ queries }: { queries: IVPRQuery[] }): {
  zcapRequests?: IZcapQuery[]
} {
  const zcapRequests = queries.filter(
    (q): q is IZcapQuery =>
      q.type === 'ZcapQuery' || q.type === 'AuthorizationCapabilityQuery'
  )
  if (zcapRequests.length > 0) {
    return { zcapRequests }
  }
  return {}
}

/**
 * Returns true if the message is a VPR whose only query type is
 * `DIDAuthentication` (i.e. no credential sharing is involved).
 *
 * @param message {WalletApiMessage}
 * @returns {boolean}
 */
export function isDIDAuthOnlyRequest(message: WalletApiMessage): boolean {
  if (!('verifiablePresentationRequest' in message)) {
    return false
  }
  const { query } = message.verifiablePresentationRequest
  const queries = Array.isArray(query) ? query : [query]
  return (
    queries.length > 0 &&
    queries.every(q => !!q && q.type === 'DIDAuthentication')
  )
}
