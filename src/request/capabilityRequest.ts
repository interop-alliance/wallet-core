/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The zcap-only Verifiable Presentation Request: the request a relying party
 * stores on an ephemeral exchange (`ephemeralExchange.ts`) when all it wants
 * from the wallet is delegated capabilities on the user's Space. One
 * `AuthorizationCapabilityQuery` (the canonical VCALM type string; the wallet
 * side's `zcapQueriesOf` reads it back) carrying the requested capability
 * details verbatim. Deliberately no `DIDAuthentication` query and no
 * `domain`: the requester is asking for authority, not proving who it is to a
 * verifier, and a requester without an attested origin (a CLI) has no domain
 * a wallet could check.
 */
import type {
  ICapabilityQueryDetail,
  IVPRDetails,
  IVPRQuery,
  IZcapQuery
} from './types.js'

/**
 * REQUESTER: builds the zcap-only VPR details for a set of capability
 * requests. Each detail must name its `controller` (the grantee DID) and its
 * `invocationTarget` (a URL under the user's Space, or a wallet-defined
 * descriptor object); an empty set, or a detail missing either, throws --
 * there would be nothing for the wallet to ask consent for.
 *
 * @param options {object}
 * @param options.capabilityQueries {ICapabilityQueryDetail[]}
 * @param [options.challenge] {string}   a requester-chosen nonce the wallet
 *   echoes in its response presentation
 * @returns {IVPRDetails}
 */
export function composeCapabilityRequest({
  capabilityQueries,
  challenge
}: {
  capabilityQueries: ICapabilityQueryDetail[]
  challenge?: string
}): IVPRDetails {
  if (capabilityQueries.length === 0) {
    throw new Error('A capability request must ask for at least one zcap.')
  }
  for (const detail of capabilityQueries) {
    if (typeof detail.controller !== 'string' || detail.controller === '') {
      throw new Error('A capability query must name its "controller".')
    }
    const target = detail.invocationTarget
    if (
      (typeof target !== 'string' || target === '') &&
      (typeof target !== 'object' || target === null)
    ) {
      throw new Error('A capability query must name its "invocationTarget".')
    }
  }
  const query: IZcapQuery = {
    type: 'AuthorizationCapabilityQuery',
    capabilityQuery: capabilityQueries,
    ...(challenge !== undefined && { challenge })
  }
  return { query: [query as IVPRQuery] }
}
