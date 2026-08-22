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
 * the server-side convenience (the KMS authentication key, published under
 * `authentication` only) -- neither can appear, by construction rather than
 * by a filter someone must remember.
 *
 * Labels are display metadata with no authority, so a label-read failure
 * degrades to unlabeled rows; the listing itself fails only when the log
 * cannot be fetched or verified.
 *
 * The two reads are independent, so they run together, and either entry point
 * takes an already-verified log (`verifiedLog`) in place of fetching one --
 * the seam a caller needs to keep one verified log for a session instead of
 * re-verifying `did.jsonl` per surface. Whether such a cache is safe to hold,
 * and what invalidates it, is the caller's call.
 */
import {
  ladderVmIds,
  listEnrolledWebvhClients,
  verifyAccountLog,
  type EnrolledWebvhClient
} from '../webvh/index.js'
import { vmFragmentOf } from '@interop/vh-resource-log'
import { readClientLabels, type ClientLabelsStore } from '../keys/index.js'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'

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
 * A log that has already been fetched and locally verified -- exactly what
 * `verifyAccountLog` resolves to. Both entry points below accept one so a
 * caller holding a still-valid result (a session-lifetime cache, or two
 * surfaces mounting together) reads the account's clients without re-fetching
 * and re-verifying `did.jsonl`. The cache itself is the caller's: only the
 * caller knows which ceremonies invalidate it.
 */
export type VerifiedAccountLog = Awaited<ReturnType<typeof verifyAccountLog>>

/**
 * One row of the listing: the log-stated client plus its display state.
 * `keyAgreementKeyMultibases` is an empty array when the document carries no
 * marked key-agreement method for the client. `updateKeyMultibase` is absent
 * when the log attribution could not isolate the client's active update key,
 * which is exactly when it cannot be disconnected.
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
 * @param [options.verifiedLog] {VerifiedAccountLog}   an already-verified log
 *   to read instead of fetching and verifying one
 * @param [options.accountLogPinStore] {ResourceLogPinStore}   this client's
 *   chain-head pin for the account log, checked when the log is fetched here
 * @returns {Promise<AccountClientView[]>}
 */
export async function listAccountClients({
  pointer,
  labelsStore,
  ownSigningKeyMultibase,
  verifiedLog,
  accountLogPinStore
}: {
  pointer: AccountLogPointer
  labelsStore?: ClientLabelsStore
  ownSigningKeyMultibase?: string
  verifiedLog?: VerifiedAccountLog
  accountLogPinStore?: ResourceLogPinStore
}): Promise<AccountClientView[]> {
  // The log read and the label read are independent, so they run together.
  const [{ log }, labels] = await Promise.all([
    verifiedLog ??
      verifyAccountLog({
        ...pointer,
        ...(accountLogPinStore ? { pinStore: accountLogPinStore } : {})
      }),
    labelsStore
      ? readClientLabels({ store: labelsStore }).then(read => read.labels)
      : Promise.resolve<Record<string, string>>({})
  ])
  const clients = listEnrolledWebvhClients({ log })
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
 * @param [options.verifiedLog] {VerifiedAccountLog}   an already-verified log
 *   to read instead of fetching and verifying one
 * @param [options.accountLogPinStore] {ResourceLogPinStore}   this client's
 *   chain-head pin for the account log, checked when the log is fetched here
 * @returns {Promise<Set<string>>}
 */
export async function currentAccountSigningKeys({
  pointer,
  verifiedLog,
  accountLogPinStore
}: {
  pointer: AccountLogPointer
  verifiedLog?: VerifiedAccountLog
  accountLogPinStore?: ResourceLogPinStore
}): Promise<Set<string>> {
  const { log } =
    verifiedLog ??
    (await verifyAccountLog({
      ...pointer,
      ...(accountLogPinStore ? { pinStore: accountLogPinStore } : {})
    }))
  return new Set(
    listEnrolledWebvhClients({ log }).map(client => client.signingKeyMultibase)
  )
}

/**
 * The keys the locally verified document backs as the signer of a RE-MINTED
 * unlock or recovery record -- the allowlist a reader settles a record's
 * mixed-signer proof against once the record is decrypted and its pointer
 * names this account. It is {@link currentAccountSigningKeys} (every
 * enrolled client's signing key: the revocation cascade's and the login-time
 * refresh's re-mint signer) plus the ladder VMs the document lists (the
 * last-client forget's re-mint signer -- on a client-less account the ladder
 * VM is the only key left that can re-sign a record, and a reader that
 * refused it would refuse every other unlock method's record after the
 * transition). The ladder VM is recognized by the relation asymmetry
 * (`ladderVmIds`), never by a marker. Same fetch-or-verified-log contract as
 * its sibling.
 *
 * Deliberately NOT the app-grant check's key set: an app grant's delegation
 * signer must be an enrolled client (or, from a transient session, the annex
 * key under the generation delegation), and widening that listing to the
 * ladder VM would misread the transition state.
 *
 * @param options {object}
 * @param options.pointer {AccountLogPointer}
 * @param [options.verifiedLog] {VerifiedAccountLog}   an already-verified log
 *   to read instead of fetching and verifying one
 * @param [options.accountLogPinStore] {ResourceLogPinStore}   this client's
 *   chain-head pin for the account log, checked when the log is fetched here
 * @returns {Promise<Set<string>>}   public key multibases
 */
export async function currentAccountRecordSigners({
  pointer,
  verifiedLog,
  accountLogPinStore
}: {
  pointer: AccountLogPointer
  verifiedLog?: VerifiedAccountLog
  accountLogPinStore?: ResourceLogPinStore
}): Promise<Set<string>> {
  const verified =
    verifiedLog ??
    (await verifyAccountLog({
      ...pointer,
      ...(accountLogPinStore ? { pinStore: accountLogPinStore } : {})
    }))
  const keys = await currentAccountSigningKeys({
    pointer,
    verifiedLog: verified
  })
  for (const id of ladderVmIds({ doc: verified.doc })) {
    const multibase = vmFragmentOf(id)
    if (multibase !== undefined) {
      keys.add(multibase)
    }
  }
  return keys
}
