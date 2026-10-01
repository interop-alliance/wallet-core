/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The enrolled-client listing behind a "wallets connected to this account"
 * surface: fetch and locally verify the account's world-readable did:webvh log
 * (the same verification step every ceremony runs), enumerate the clients it
 * enrolls, join their names from the `connections` directory's wallet-client
 * entries, and mark the row belonging to the caller's own client.
 *
 * The listing IS the revocation surface, so the enumeration rule matters as
 * much as the display: `listEnrolledWebvhClients` keys on
 * `capabilityInvocation`, which is what structurally excludes a recovery
 * code's key (published under `keyAgreement` only, deliberately unmarked) and
 * the server-side convenience (the KMS authentication key, published under
 * `authentication` only) -- neither can appear, by construction rather than
 * by a filter someone must remember.
 *
 * Membership comes from the verified document alone: a directory entry with
 * no document client is not listed, and a document client with no entry is
 * listed unlabeled. Names are display metadata with no authority, so a
 * directory-read failure degrades to unlabeled rows; the listing itself fails
 * only when the log cannot be fetched or verified.
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
import { signingKeyMultibaseOfDid } from '../connections/didKey.js'
import type { ConnectionEntry } from '../connections/entry.js'
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
 * which is exactly when it cannot be disconnected. `label` (the user's own
 * name for the client) and `name` (its self-declared name) come from its
 * directory entry, kept apart so a surface picks the order.
 */
export interface AccountClientView extends EnrolledWebvhClient {
  label?: string
  name?: string
  isCurrent: boolean
}

/**
 * The directory's wallet-client entries keyed by the signing-key multibase
 * their did:key `id` carries. An entry of another kind, or one whose `id` is
 * not an Ed25519 did:key, names no client. The first entry per key wins.
 *
 * @param options {object}
 * @param options.entries {ReadonlyArray<ConnectionEntry>}
 * @returns {Map<string, ConnectionEntry>}
 */
function walletClientEntriesByKey({
  entries
}: {
  entries: ReadonlyArray<ConnectionEntry>
}): Map<string, ConnectionEntry> {
  const byKey = new Map<string, ConnectionEntry>()
  for (const entry of entries) {
    if (entry.kind !== 'wallet-client' || entry.id === undefined) {
      continue
    }
    const multibase = signingKeyMultibaseOfDid({ did: entry.id })
    if (multibase !== undefined && !byKey.has(multibase)) {
      byKey.set(multibase, entry)
    }
  }
  return byKey
}

/**
 * The verified account log every reader here stands on: the caller's own
 * already-verified log when it supplied one, else a fetch-and-verify under
 * its chain-head pin. Stated once so the three listings share one contract --
 * a supplied log is trusted verbatim, and a fetched one is pinned whenever
 * the caller keeps pins.
 *
 * @param options {object}
 * @param options.pointer {AccountLogPointer}   where the account log lives
 * @param [options.verifiedLog] {VerifiedAccountLog}   an already-verified log
 *   to read instead of fetching and verifying one
 * @param [options.accountLogPinStore] {ResourceLogPinStore}   this client's
 *   chain-head pin for the account log, checked when the log is fetched here
 * @returns {Promise<VerifiedAccountLog>}
 */
async function resolveVerifiedAccountLog({
  pointer,
  verifiedLog,
  accountLogPinStore
}: {
  pointer: AccountLogPointer
  verifiedLog?: VerifiedAccountLog
  accountLogPinStore?: ResourceLogPinStore
}): Promise<VerifiedAccountLog> {
  return (
    verifiedLog ??
    (await verifyAccountLog({
      ...pointer,
      ...(accountLogPinStore ? { pinStore: accountLogPinStore } : {})
    }))
  )
}

/**
 * The directory's names for the account's clients, or none when the caller
 * gave no directory read or the read failed: names are display metadata, and
 * a broken directory must not block the disconnect surface.
 *
 * @param options {object}
 * @param [options.readDirectoryEntries] {Function}
 * @returns {Promise<Map<string, ConnectionEntry>>}
 */
async function directoryNames({
  readDirectoryEntries
}: {
  readDirectoryEntries?: () => Promise<ReadonlyArray<ConnectionEntry>>
}): Promise<Map<string, ConnectionEntry>> {
  if (readDirectoryEntries === undefined) {
    return new Map()
  }
  try {
    return walletClientEntriesByKey({ entries: await readDirectoryEntries() })
  } catch {
    return new Map()
  }
}

/**
 * Lists the wallet clients enrolled on an account, from the locally verified
 * did:webvh log, with names joined from the directory and the caller's own
 * client marked.
 *
 * @param options {object}
 * @param options.pointer {AccountLogPointer}   where the account log lives
 * @param [options.readDirectoryEntries] {Function}   reads the `connections`
 *   directory's entries; its `wallet-client` entries name the rows. Omitted,
 *   or throwing, every row is unlabeled
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
  readDirectoryEntries,
  ownSigningKeyMultibase,
  verifiedLog,
  accountLogPinStore
}: {
  pointer: AccountLogPointer
  readDirectoryEntries?: () => Promise<ReadonlyArray<ConnectionEntry>>
  ownSigningKeyMultibase?: string
  verifiedLog?: VerifiedAccountLog
  accountLogPinStore?: ResourceLogPinStore
}): Promise<AccountClientView[]> {
  // The log read and the directory read are independent, so they run
  // together. A failed directory read leaves every row unlabeled.
  const [{ log }, named] = await Promise.all([
    resolveVerifiedAccountLog({ pointer, verifiedLog, accountLogPinStore }),
    directoryNames({ readDirectoryEntries })
  ])
  const clients = listEnrolledWebvhClients({ log })
  return clients.map(client => {
    const entry = named.get(client.signingKeyMultibase)
    return {
      ...client,
      ...(entry?.label !== undefined && { label: entry.label }),
      ...(entry?.name !== undefined && { name: entry.name }),
      isCurrent: client.signingKeyMultibase === ownSigningKeyMultibase
    }
  })
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
  const { log } = await resolveVerifiedAccountLog({
    pointer,
    verifiedLog,
    accountLogPinStore
  })
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
 * last-client forget's re-mint signer -- on an account with no enrolled client
 * the ladder VM is the only key left that can re-sign a record, and a reader
 * that refused it would refuse every other unlock method's record after the
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
  const verified = await resolveVerifiedAccountLog({
    pointer,
    verifiedLog,
    accountLogPinStore
  })
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
