/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Opens a VCALM interaction URL end to end: resolves its protocols map, begins
 * the exchange it names, and hands back the Verifiable Presentation Request the
 * exchange is actually asking for. This is the answering wallet's counterpart
 * of `createEphemeralExchange` (`ephemeralExchange.ts`): a requester stores a
 * VPR on an ephemeral exchange and prints the interaction URL; this opens it.
 *
 * Classification is deliberately not done here. The caller runs its own
 * `classifyRequest` over the returned `request` -- freewallet's App
 * Connect-aware classifier must refuse an `AppConnectQuery` that arrives with
 * no attested origin, and the shared classifier here would silently filter it
 * out instead.
 */
import {
  fetchInteractionProtocols,
  isInteractionUrl,
  parseInteractionUrl
} from './interactionUrl.js'
import { startExchange, vcApiExchangeUrl } from './exchangeClient.js'
import type { FetchLike, IVPRDetails } from './types.js'

/**
 * Resolves an interaction URL to the Verifiable Presentation Request it names.
 * Throws a plain `Error` when the text is not an interaction URL, or when the
 * resolved protocols map names no usable exchange (`interact` or `vcapi`); a
 * `404` on either the protocols fetch or the exchange's begin POST surfaces as
 * {@link EphemeralExchangeGoneError} (dispatch on `err.name`), since either
 * one means the exchange expired or the link is wrong.
 *
 * @param options {object}
 * @param options.url {string}
 * @param [options.fetch] {FetchLike}
 * @returns {Promise<{ interactionUrl: string, exchangeUrl: string, request: IVPRDetails }>}
 */
export async function openInteractionRequest({
  url,
  fetch = globalThis.fetch
}: {
  url: string
  fetch?: FetchLike
}): Promise<{
  interactionUrl: string
  exchangeUrl: string
  request: IVPRDetails
}> {
  if (!isInteractionUrl(url)) {
    throw new Error(`Not an interaction URL: ${url}`)
  }
  const interactionUrl = parseInteractionUrl(url)
  const protocols = await fetchInteractionProtocols(interactionUrl, { fetch })
  const exchangeUrl = vcApiExchangeUrl({ protocols })
  if (!exchangeUrl) {
    throw new Error(
      `The interaction URL's protocols map names no usable exchange ` +
        `("interact" or "vcapi"): ${interactionUrl}`
    )
  }
  const request = await startExchange({ exchangeUrl, fetch })
  return { interactionUrl, exchangeUrl, request }
}
