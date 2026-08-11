/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The did:webvh id shape check, on its own leaf file so a module that only
 * needs to recognize an account DID (the `request` subpath's
 * `WalletOnboardingQuery` validation, for instance) can import it without
 * pulling in the zcap signing graph. Its public home stays `webvh/zcap.ts`,
 * which re-exports it.
 */

/**
 * Whether a DID (an account pointer's `did` member, typically) is a
 * did:webvh id -- the marker that the account's Space controller has been
 * promoted, so sessions must sign with the did:webvh keyId.
 *
 * @param did {string | undefined}
 * @returns {boolean}
 */
export function isWebvhDid(did: string | undefined): did is string {
  return typeof did === 'string' && did.startsWith('did:webvh:')
}
