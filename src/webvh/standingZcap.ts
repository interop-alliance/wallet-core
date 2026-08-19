/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The house policy for standing recorded zcaps -- the long-lived delegations a
 * wallet mints once and records beside a registry entry or inside a document
 * (the recovery `did.jsonl` bridge, an unlock Space's management zcap, the
 * companion generation delegation): one shared lifetime, one renewal window,
 * and the one staleness predicate every re-mint pass and login-time health
 * check asks. A leaf file (no internal imports), so both the `webvh` and
 * `recovery` layers can share it without a layering inversion; `recovery`
 * re-exports the members that were born there, so its public surface is
 * unchanged.
 */

/**
 * The standing zcap lifetime: one year, following NIST SP 800-57's
 * one-to-two-year cryptoperiod guidance for private signature keys. A
 * standing bearer artifact should not outlive its signing key's recommended
 * cryptoperiod; expiry is watched rather than terminal ({@link zcapExpiring}
 * flags the renewal window, and each artifact's own re-mint or renewal path
 * refreshes it).
 */
export const STANDING_ZCAP_TTL_MS = 365 * 24 * 60 * 60 * 1000

/**
 * How long before its `expires` a standing recorded zcap counts as stale:
 * thirty days, so a refresh (a re-mint, a login-time re-delegation, the
 * generation delegation's renew-precedes-mint stage) or a regenerate nudge
 * lands well before the zcap actually lapses.
 */
export const ZCAP_RENEWAL_WINDOW_MS = 30 * 24 * 60 * 60 * 1000

/**
 * Whether a recorded zcap expiry is past or inside the renewal window -- the
 * expiry half of the staleness predicate for every long-lived zcap a wallet
 * records beside its registry entries. The re-mint passes and the wallets'
 * login-time checks all ask this one predicate. A record carrying no expiry
 * (or an unparseable one) is uncheckable and therefore not assumed healthy,
 * matching the rot check's treatment of a missing `delegationKeyId`.
 *
 * @param options {object}
 * @param [options.expires] {string}   the recorded ISO 8601 expiry
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {boolean}
 */
export function zcapExpiring({
  expires,
  now = Date.now()
}: {
  expires?: string
  now?: number
}): boolean {
  if (!expires) {
    return true
  }
  const expiresAt = Date.parse(expires)
  if (Number.isNaN(expiresAt)) {
    return true
  }
  return expiresAt - now <= ZCAP_RENEWAL_WINDOW_MS
}
