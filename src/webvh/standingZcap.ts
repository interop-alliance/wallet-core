/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The house policy for standing recorded zcaps -- the long-lived delegations a
 * wallet mints once and records beside a registry entry or inside a document
 * (the recovery `did.jsonl` bridge, an unlock Space's management zcap, the
 * client annex generation delegation): one shared lifetime, one renewal window,
 * and the one staleness predicate every re-mint pass and login-time health
 * check asks. `recovery` re-exports the members that were born there, so its
 * public surface is unchanged.
 */
import { vmFragmentOf } from '@interop/vh-resource-log'
import type { IZcap } from '@interop/data-integrity-core'
import { delegationKeyInDocument } from './listClients.js'
import type { PublishedKeyDocument } from './listClients.js'

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

/**
 * The verification method that signed a delegation's proof -- recorded in the
 * registry entry so the health check and the re-mint's rot check can test it
 * against the current document without holding the code.
 *
 * @param delegation {IZcap}
 * @returns {string | undefined}
 */
export function delegationProofKeyId(delegation: IZcap): string | undefined {
  const { proof } = delegation as unknown as {
    proof?:
      | { verificationMethod?: string }
      | Array<{
          verificationMethod?: string
        }>
  }
  const single = Array.isArray(proof) ? proof[0] : proof
  return single?.verificationMethod
}

/**
 * The composed staleness rule for a standing recorded zcap, over the scalars
 * a registry entry records: the delegation's proof key id and its expiry.
 * Three axes, any one of which makes the grant stale:
 *
 * - EXPIRY -- past, inside the renewal window, or unrecorded
 *   ({@link zcapExpiring}).
 * - SIGNER DEATH -- the proof's verification method is no longer under
 *   `capabilityDelegation` in the verified account document, the
 *   current-key-set rule (`delegationKeyInDocument`). Checked only when a
 *   `doc` is supplied; a caller holding no verified document is opting out
 *   of this axis rather than asserting the grant healthy.
 * - RETIREMENT -- the caller names the key as retiring, so the grant is read
 *   against a PROJECTED post-edit document rather than the served one. The
 *   axis every ceremony needs that acts before the entry removing a key
 *   lands (the last-client transition's stages, whose document still lists
 *   the forgotten client), and the one that covers authority a client-side
 *   predicate cannot read at all -- a delegation about to be revoked
 *   server-side.
 *
 * @param options {object}
 * @param [options.doc] {PublishedKeyDocument}   the locally VERIFIED account
 *   document; omitted, the signer-death axis is skipped
 * @param [options.delegationKeyId] {string}   the recorded proof key id, in
 *   either DID form
 * @param [options.expires] {string}   the recorded ISO 8601 expiry
 * @param [options.retiringKeyMultibases] {string[]}   keys whose authority is
 *   about to end, as bare multibases or verification-method ids
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {boolean}
 */
export function recordedZcapStale({
  doc,
  delegationKeyId,
  expires,
  retiringKeyMultibases = [],
  now = Date.now()
}: {
  doc?: PublishedKeyDocument
  delegationKeyId?: string
  expires?: string
  retiringKeyMultibases?: string[]
  now?: number
}): boolean {
  if (zcapExpiring({ ...(expires !== undefined ? { expires } : {}), now })) {
    return true
  }
  const multibase =
    delegationKeyId === undefined
      ? undefined
      : (vmFragmentOf(delegationKeyId) ?? delegationKeyId)
  // Retiring keys arrive as bare multibases or as verification-method ids;
  // either way the comparison is on the multibase.
  const retiring = retiringKeyMultibases.some(
    key => multibase !== undefined && (vmFragmentOf(key) ?? key) === multibase
  )
  if (retiring) {
    return true
  }
  return (
    doc !== undefined &&
    !delegationKeyInDocument({
      doc,
      ...(delegationKeyId !== undefined ? { delegationKeyId } : {})
    })
  )
}

/**
 * {@link recordedZcapStale} over a delegation in hand: the same three axes,
 * reading the expiry and the proof key off the zcap itself. The shape every
 * caller holding the delegation uses (the record's bridge and its
 * `delegatedClients` sibling, the annex's embedded generation delegation), so
 * the two shapes can never drift onto different rules.
 *
 * @param options {object}
 * @param options.zcap {IZcap}   the recorded delegation
 * @param [options.doc] {PublishedKeyDocument}   the locally VERIFIED account
 *   document; omitted, the signer-death axis is skipped
 * @param [options.retiringKeyMultibases] {string[]}   keys whose authority is
 *   about to end
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {boolean}
 */
export function standingZcapStale({
  zcap,
  doc,
  retiringKeyMultibases,
  now
}: {
  zcap: IZcap
  doc?: PublishedKeyDocument
  retiringKeyMultibases?: string[]
  now?: number
}): boolean {
  const { expires } = zcap as { expires?: string }
  const delegationKeyId = delegationProofKeyId(zcap)
  return recordedZcapStale({
    ...(doc !== undefined ? { doc } : {}),
    ...(delegationKeyId !== undefined ? { delegationKeyId } : {}),
    ...(expires !== undefined ? { expires } : {}),
    ...(retiringKeyMultibases !== undefined ? { retiringKeyMultibases } : {}),
    ...(now !== undefined ? { now } : {})
  })
}
