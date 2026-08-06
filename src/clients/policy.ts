/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The disconnect-eligibility policy both "connected wallets" surfaces encode
 * as UI state, as data and pure functions -- so the rule that decides whether
 * a row can be disconnected is one rule, and each app supplies only its own
 * wording.
 *
 * Three refusals, each for a different reason:
 *
 * - **`self`** -- a client cannot disconnect itself. The document edit would
 *   also refuse (on the update key), but the surface should name the real rule
 *   and point at another connected wallet, or a recovery code.
 * - **`last-client`** -- the account's only enrolled client cannot be
 *   disconnected: that would abandon the account's update authority, leaving a
 *   log nobody can ever extend. Recovery-code issuance is the answer, not this
 *   button.
 * - **`unattributed-update-key`** -- the log attribution could not isolate the
 *   row's ACTIVE update key. Disconnecting with a guessed key could revoke a
 *   different client's authority, so the row is disabled rather than guessed
 *   at.
 *
 * And one non-failure: a cascade whose collection fan-out left failures
 * behind is a **resumable success**. The wallet IS disconnected -- the
 * document edit landed first and is the pull axis everywhere -- and the
 * remaining re-keying is detected from durable state alone, so the next run
 * (or the login-time completion sweep) finishes it. A surface that reported
 * that as an error would contradict its own refreshed listing.
 */
import type { RevokedClientKeys } from '../webvh/index.js'
import type { UserKeyCascadeResult } from '../keys/index.js'
import type { AccountClientView } from './listing.js'

/**
 * Why a listed row cannot be disconnected. See the module doc.
 */
export type DisconnectRefusal =
  'self' | 'last-client' | 'unattributed-update-key'

/**
 * Whether one listed row can be disconnected, and -- when it cannot -- which
 * rule refuses it.
 *
 * @param options {object}
 * @param options.client {AccountClientView}   the row in question
 * @param options.clients {AccountClientView[]}   the whole listing (the
 *   last-client rule is a property of the account, not of the row)
 * @returns {{ allowed: boolean, refusal?: DisconnectRefusal }}
 */
export function disconnectEligibility({
  client,
  clients
}: {
  client: AccountClientView
  clients: AccountClientView[]
}): { allowed: boolean; refusal?: DisconnectRefusal } {
  if (client.isCurrent) {
    return { allowed: false, refusal: 'self' }
  }
  if (clients.length <= 1) {
    return { allowed: false, refusal: 'last-client' }
  }
  if (!client.updateKeyMultibase) {
    return { allowed: false, refusal: 'unattributed-update-key' }
  }
  return { allowed: true }
}

/**
 * Narrows a listed row to the key set a revocation needs, throwing when the
 * row's active update key could not be attributed. A row with all three key
 * members present is exactly a `RevokedClientKeys`.
 *
 * @param options {object}
 * @param options.client {AccountClientView}
 * @returns {RevokedClientKeys}
 */
export function revokedClientKeysFor({
  client
}: {
  client: AccountClientView
}): RevokedClientKeys {
  if (!client.updateKeyMultibase) {
    throw new Error(
      "This wallet's update key could not be attributed from the account " +
        'log, so it cannot be disconnected from here.'
    )
  }
  return {
    signingKeyMultibase: client.signingKeyMultibase,
    keyAgreementKeyMultibase: client.keyAgreementKeyMultibase,
    updateKeyMultibase: client.updateKeyMultibase
  }
}

/**
 * How a completed cascade should be reported: `complete` when every encrypted
 * collection took the fresh key, `partial` when some did not -- a resumable
 * success, never an error (see the module doc).
 *
 * @param options {object}
 * @param options.collections {UserKeyCascadeResult}   the collection fan-out result
 * @returns {'complete' | 'partial'}
 */
export function cascadeCompletion({
  collections
}: {
  collections: UserKeyCascadeResult
}): 'complete' | 'partial' {
  return collections.failed.length > 0 ? 'partial' : 'complete'
}
