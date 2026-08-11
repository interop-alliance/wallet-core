/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The login-time wrap-set roster policy: what a wallet does with
 * `key-map/user-key.jsonl` when a session starts, and how it decides between
 * refusing the session and carrying on offline.
 *
 * Two steps, in this order:
 *
 * - {@link checkUserKeyRosterAtLogin} -- one direct read of the roster, before
 *   any
 *   storage client or cipher is built (a stale key would silently fail to
 *   decrypt everything written since another client rotated it). The served
 *   roster is authenticated and checked against the locally pinned latest-seen
 *   epoch either way.
 *
 *   **Failure semantics.** The three roster refusals -- a rolled-back or
 *   replayed roster, an epoch configuration that fails authentication, and a
 *   current epoch this client cannot unwrap -- rethrow and refuse the session:
 *   they are the same continuity class as a substituted account pointer, and
 *   proceeding would mean acting under a key nobody vouched for. Anything else
 *   (an unreachable server, a transport hiccup) is warned about and resolves
 *   `null`, so an offline start keeps working from the cached key.
 *
 * - {@link convergeUserKeyRosterToAccount} -- the roster stage of the
 *   cascade-completion sweep, which the collection fan-out then runs behind. A
 *   revocation torn between its document edit and its roster rotation leaves
 *   the roster wrapping the CURRENT key to a client the document no longer
 *   keys -- durable and silent, since the revoked client's document edit will
 *   never be re-run -- so it is finished here. Strictly best-effort: a log
 *   that cannot be fetched or verified (offline, an unpromoted account) leaves
 *   the start's own roster read in place, and the next start tries again.
 *
 *   **Once per session.** A converged roster stays converged, and the engine
 *   restart (or storage-cipher rebuild) that adopts a rotation must not
 *   converge again. The guard is the caller's, because only the app knows what
 *   a session is.
 *
 * Adoption is a callback in both: persisting a key, pinning an epoch, swapping
 * a live session's vault keys, and rebuilding ciphers are app-side side
 * effects. What is NOT app-side is the ordering -- the key and the epoch pin
 * persist atomically (the pin must never advance without the key that
 * authenticated the roster it advanced to), and the adoption lands BEFORE the
 * collection fan-out runs against it.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import {
  convergeUserKeyRosterToDocument,
  UserKeyRosterContinuityError,
  UserKeyRosterIntegrityError,
  UserKeyRosterUnwrapError,
  readUserKeyRoster,
  type UserKey,
  type UserKeyRosterReadResult
} from '../keys/index.js'
import {
  ResourceLogContinuityError,
  ResourceLogIntegrityError
} from '../resourceLog/index.js'
import { verifyAccountLog } from '../webvh/index.js'
import type { AccountLogPointer } from './listing.js'

/**
 * What an adopted user key carries: the key itself, the roster epoch to
 * pin as latest-seen, and the descriptor it was read from.
 */
export interface AdoptedUserKey {
  userKey: UserKey
  latestEpochId: string
  descriptor: CollectionEncryption
}

/**
 * Whether a thrown error is one of the roster refusals -- a fabricated or
 * discontinuous roster log, a rolled-back or replayed roster, an epoch
 * configuration that fails authentication, and a current epoch this client
 * cannot unwrap. They are the continuity class that refuses a session rather
 * than degrading it, so both entry points rethrow them instead of warning and
 * carrying on.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
function isRosterRefusal(err: unknown): boolean {
  return (
    err instanceof ResourceLogContinuityError ||
    err instanceof ResourceLogIntegrityError ||
    err instanceof UserKeyRosterContinuityError ||
    err instanceof UserKeyRosterIntegrityError ||
    err instanceof UserKeyRosterUnwrapError
  )
}

/**
 * The login-time roster read. See the module doc for the failure semantics.
 *
 * Every read traces to the account document through the log-governed store
 * itself: the roster resolves only from the roster log's verified head, whose
 * entry proofs are checked against the locally verified account log. A log
 * that cannot be fetched lands in the transport-failure class -- the session
 * carries on under the cached key, WITHOUT adopting an unverifiable rotation
 * -- while a roster no enrolled client signed onto the log, and a log that
 * conflicts with the chain-head pin, are refusals like the other three.
 *
 * @param options {object}
 * @param options.store {EncryptionDescriptorStore}   the roster's descriptor
 *   store
 * @param [options.userKey] {UserKey}   this client's cached user key; omitted (a
 *   freshly enrolled client's first read) the key is always taken from the
 *   roster
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key -- its roster entry
 * @param [options.pinnedEpochId] {string}   the locally pinned latest-seen
 *   roster epoch
 * @param [options.onRosterRead] {Function}   called with the
 *   {@link AdoptedUserKey} of every successful read (whether or not it rotated),
 *   so the epoch pin advances to the epoch just authenticated; the key and the
 *   pin must persist atomically
 * @returns {Promise<UserKeyRosterReadResult | null>}   the read, or `null` when
 *   the account has no roster yet or the server could not be reached
 */
export async function checkUserKeyRosterAtLogin({
  store,
  userKey,
  clientKeyAgreementKey,
  pinnedEpochId,
  onRosterRead
}: {
  store: EncryptionDescriptorStore
  userKey?: UserKey
  clientKeyAgreementKey: IKeyAgreementKey
  pinnedEpochId?: string | null
  onRosterRead?: (adopted: AdoptedUserKey) => Promise<void>
}): Promise<UserKeyRosterReadResult | null> {
  try {
    const read = await readUserKeyRoster({
      store,
      ...(userKey ? { userKey } : {}),
      clientKeyAgreementKey,
      pinnedEpochId
    })
    if (!read) {
      return null
    }
    await onRosterRead?.({
      userKey: read.userKey,
      latestEpochId: read.latestEpochId,
      descriptor: read.descriptor
    })
    return read
  } catch (err) {
    if (isRosterRefusal(err)) {
      throw err
    }
    // An unreachable server (or any transport hiccup) must not lock the user
    // out of an offline start: the cached key stays authoritative.
    console.warn(
      'The wrap-set roster check failed; continuing with the cached ' +
        'user key:',
      err
    )
    return null
  }
}

/**
 * Converges the roster onto the account's locally verified did:webvh document,
 * adopting a rotation the ordinary way (a roster re-read) and handing back the
 * key and descriptor the collection fan-out should run against.
 *
 * Best-effort UP TO the rotation: a log that cannot be fetched or verified, or
 * a roster that turns out to need nothing, resolves to the unchanged input,
 * since the fan-out is still worth running on the key this start already has.
 * Past the rotation it is not best-effort at all -- once the roster has moved
 * to a fresh key, that key is readable only from the roster, so a failed
 * adoption throws rather than reporting `rotated: false` with the retired key
 * and descriptor (which would skip `onUserKeyAdopted` and fan the collections
 * out onto the pre-rotation epoch). The three roster refusals rethrow
 * throughout, exactly as {@link checkUserKeyRosterAtLogin} rethrows them.
 *
 * @param options {object}
 * @param options.pointer {AccountLogPointer}   where the account log lives
 * @param options.store {EncryptionDescriptorStore}   the roster's descriptor
 *   store
 * @param options.userKey {UserKey}   the start's current user key
 * @param options.descriptor {CollectionEncryption}   the start's roster read
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key
 * @param [options.pinnedEpochId] {string}   the locally pinned latest-seen
 *   roster epoch
 * @param [options.onUserKeyAdopted] {Function}   called with the
 *   {@link AdoptedUserKey} of a rotation, before the fan-out runs
 * @returns {Promise<object>}   whether the roster rotated on this call, the
 *   stale recipient kids found, and the key + descriptor to fan out with
 */
export async function convergeUserKeyRosterToAccount({
  pointer,
  store,
  userKey,
  descriptor,
  clientKeyAgreementKey,
  pinnedEpochId,
  onUserKeyAdopted
}: {
  pointer: AccountLogPointer
  store: EncryptionDescriptorStore
  userKey: UserKey
  descriptor: CollectionEncryption
  clientKeyAgreementKey: IKeyAgreementKey
  pinnedEpochId?: string | null
  onUserKeyAdopted?: (adopted: AdoptedUserKey) => Promise<void>
}): Promise<{
  rotated: boolean
  staleRecipientIds: string[]
  userKey: UserKey
  descriptor: CollectionEncryption
}> {
  const unchanged = {
    rotated: false,
    staleRecipientIds: [] as string[],
    userKey,
    descriptor
  }
  let rotated: boolean
  let staleRecipientIds: string[]
  try {
    const { doc } = await verifyAccountLog(pointer)
    const converged = await convergeUserKeyRosterToDocument({
      store,
      document: doc,
      descriptor
    })
    rotated = converged.rotated
    staleRecipientIds = converged.staleRecipientIds
  } catch (err) {
    if (isRosterRefusal(err)) {
      throw err
    }
    console.warn(
      'Could not converge the wrap-set roster onto the account document:',
      err
    )
    return unchanged
  }
  if (!rotated) {
    return unchanged
  }
  console.warn(
    'The wrap-set roster still wrapped the current key to ' +
      `${staleRecipientIds.length} recipient(s) the account document no ` +
      'longer keys; the rotation has been completed.'
  )

  // Rotated: the fresh key is only readable from the roster, so re-read it
  // and adopt it before the collection fan-out runs against it. A failure
  // here cannot resolve to the unchanged input -- the roster HAS moved.
  let read: UserKeyRosterReadResult | null
  try {
    read = await readUserKeyRoster({
      store,
      userKey,
      clientKeyAgreementKey,
      pinnedEpochId
    })
  } catch (err) {
    if (isRosterRefusal(err)) {
      throw err
    }
    throw new Error(
      'The wrap-set roster was rotated onto a fresh user key, but the ' +
        'read that adopts it failed; this session must not continue under ' +
        'the retired key.',
      { cause: err }
    )
  }
  if (!read) {
    throw new Error(
      'The wrap-set roster was rotated onto a fresh user key and then ' +
        'reported absent; this session must not continue under the retired ' +
        'key.'
    )
  }
  await onUserKeyAdopted?.({
    userKey: read.userKey,
    latestEpochId: read.latestEpochId,
    descriptor: read.descriptor
  })
  return {
    rotated: true,
    staleRecipientIds,
    userKey: read.userKey,
    descriptor: read.descriptor
  }
}
