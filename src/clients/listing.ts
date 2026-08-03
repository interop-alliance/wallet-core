/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The enrolled-client listing behind a "wallets connected to this account"
 * surface: fetch and locally verify the account's world-readable did:webvh log
 * (the same verification step every ceremony runs), enumerate the clients it
 * enrolls, merge their display labels, and mark the row belonging to the
 * caller's own client.
 *
 * The listing IS the revocation surface, so the enumeration rule matters as
 * much as the display: `listEnrolledWebvhClients` keys on
 * `capabilityInvocation`, which is what structurally excludes a recovery
 * code's key (published under `keyAgreement` only, deliberately unmarked) and
 * the server-side conveniences (published under `authentication` /
 * `assertionMethod`) -- neither can appear, by construction rather than by a
 * filter someone must remember.
 *
 * Labels are display metadata with no authority, so a label-read failure
 * degrades to unlabeled rows; the listing itself fails only when the log
 * cannot be fetched or verified.
 */
import {
  listEnrolledWebvhClients,
  verifyAccountLog,
  type EnrolledWebvhClient
} from '../webvh/index.js'
import { readClientLabels, type ClientLabelsStore } from '../keys/index.js'

/**
 * Where an account's did:webvh log is published: the account DID plus the
 * Space and host its `id` collection is served from.
 */
export interface AccountLogPointer {
  did: string
  spaceId: string
  host: string
}

/**
 * One row of the listing: the log-stated client plus its display state.
 * `updateKeyMultibase` is absent when the log attribution could not isolate
 * the client's active update key, which is exactly when it cannot be
 * disconnected.
 */
export interface AccountClientView extends EnrolledWebvhClient {
  label?: string
  isCurrent: boolean
}

/**
 * Lists the wallet clients enrolled on an account, from the locally verified
 * did:webvh log, with labels merged and the caller's own client marked.
 *
 * @param options {object}
 * @param options.pointer {AccountLogPointer}   where the account log lives
 * @param [options.labelsStore] {ClientLabelsStore}   the
 *   `key-map/client-labels.json` store; omitted, every row is unlabeled
 * @param [options.ownSigningKeyMultibase] {string}   this client's own signing
 *   key, which marks its row `isCurrent`
 * @returns {Promise<AccountClientView[]>}
 */
export async function listAccountClients({
  pointer,
  labelsStore,
  ownSigningKeyMultibase
}: {
  pointer: AccountLogPointer
  labelsStore?: ClientLabelsStore
  ownSigningKeyMultibase?: string
}): Promise<AccountClientView[]> {
  const { log } = await verifyAccountLog(pointer)
  const clients = listEnrolledWebvhClients({ log })
  const labels = labelsStore
    ? (await readClientLabels({ store: labelsStore })).labels
    : {}
  return clients.map(client => ({
    ...client,
    ...(labels[client.signingKeyMultibase] !== undefined
      ? { label: labels[client.signingKeyMultibase] }
      : {}),
    isCurrent: client.signingKeyMultibase === ownSigningKeyMultibase
  }))
}

/**
 * The signing-key multibases of the account's currently enrolled wallet
 * clients, from the locally verified did:webvh log -- the key set a recorded
 * app grant's delegation proof must name to still verify under the
 * current-key-set rule (a grant signed by a since-disconnected client no
 * longer verifies).
 *
 * This is the connected-applications surface's half of the same read: the
 * gating on whether a session HAS a promoted account to check against stays
 * app-side, since only the app knows what a guest or a storage-less session
 * looks like. Throws when the log cannot be fetched or verified; a caller
 * treating the check as best-effort catches and degrades to "unknown" rather
 * than failing its page.
 *
 * @param options {object}
 * @param options.pointer {AccountLogPointer}
 * @returns {Promise<Set<string>>}
 */
export async function currentAccountSigningKeys({
  pointer
}: {
  pointer: AccountLogPointer
}): Promise<Set<string>> {
  const { log } = await verifyAccountLog(pointer)
  return new Set(
    listEnrolledWebvhClients({ log }).map(client => client.signingKeyMultibase)
  )
}
