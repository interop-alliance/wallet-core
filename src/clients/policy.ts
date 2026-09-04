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
 * Two of the three are properties of the acting signer rather than of the
 * account, so they lift on the ladder branch (`decisions/0017`). A standing
 * credential's rung signs the removal entry, so it has no self to refuse, and
 * removing the last client abandons no update authority: the account lands
 * ladder-anchored, the shape a credential-anchored signup produces, and the
 * credential's own ladder extends the log from there. The row's confirm copy
 * states that transition. The unattributed-update-key refusal is a property
 * of the log and stands on both branches.
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
import type { RosterSealReport } from './revocation.js'

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
 * @param [options.signerKind] {string}   who would sign the removal entry:
 *   `'client'` (the default, an enrolled client's update keys) or `'ladder'`
 *   (a standing credential's rung), which lifts the self and last-client
 *   refusals -- see the module doc
 * @returns {{ allowed: boolean, refusal?: DisconnectRefusal }}
 */
export function disconnectEligibility({
  client,
  clients,
  signerKind = 'client'
}: {
  client: AccountClientView
  clients: AccountClientView[]
  signerKind?: 'client' | 'ladder'
}): { allowed: boolean; refusal?: DisconnectRefusal } {
  if (signerKind === 'client') {
    if (client.isCurrent) {
      return { allowed: false, refusal: 'self' }
    }
    if (clients.length <= 1) {
      return { allowed: false, refusal: 'last-client' }
    }
  }
  if (!client.updateKeyMultibase) {
    return { allowed: false, refusal: 'unattributed-update-key' }
  }
  return { allowed: true }
}

/**
 * Narrows a listed row to the key set a revocation needs, throwing when the
 * row's active update key could not be attributed. Carries no key-agreement
 * member: the revocation removes every key-agreement method the client's
 * controller marker claims, read off the document itself.
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
    updateKeyMultibase: client.updateKeyMultibase
  }
}

/**
 * How a completed cascade should be reported: `complete` when every encrypted
 * collection took the fresh key AND the roster's seal backstop did not fail,
 * `partial` otherwise -- a resumable success, never an error (see the module
 * doc). An unfinished seal is the same durable-staleness class as a stranded
 * collection: "a governed log's head anchor predates the membership change"
 * is detected from durable state alone, so a re-run (or the login sweep)
 * finishes it.
 *
 * @param options {object}
 * @param options.collections {UserKeyCascadeResult}   the collection fan-out result
 * @param [options.rosterSeal] {RosterSealReport}   the roster's seal-backstop
 *   report, where the cascade ran one
 * @returns {'complete' | 'partial'}
 */
export function cascadeCompletion({
  collections,
  rosterSeal
}: {
  collections: UserKeyCascadeResult
  rosterSeal?: RosterSealReport
}): 'complete' | 'partial' {
  return collections.failed.length > 0 || rosterSeal?.outcome === 'failed'
    ? 'partial'
    : 'complete'
}
