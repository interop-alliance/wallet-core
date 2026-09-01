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
 *   **Failure semantics.** The roster refusals -- a fabricated or
 *   discontinuous roster log, a rolled-back or replayed epoch configuration,
 *   one that fails authentication, and a current epoch this client cannot
 *   unwrap -- rethrow and refuse the session: they are the same continuity
 *   class as a substituted account pointer, and proceeding would mean acting
 *   under a key nobody vouched for. The one carve-out is the chain-head pin's
 *   continuity reason `rollback` (see {@link isRosterRefusal}), which lands in
 *   the transport class instead. Anything in that class (an unreachable
 *   server, a transport hiccup, the rollback) is warned about and resolves
 *   `null`, so the start keeps working from the cached key. A throw from the
 *   app's adoption callback is a third class of its own: the read succeeded
 *   but the adopted key and epoch pin did not persist, so it propagates
 *   verbatim rather than degrading to the cached key.
 *
 * - {@link convergeUserKeyRosterToAccount} -- the roster stage of the
 *   cascade-completion sweep, which the collection fan-out then runs behind. A
 *   revocation torn between its document edit and its roster rotation leaves
 *   the roster wrapping the CURRENT key to a client the document no longer
 *   keys -- durable and silent, since the revoked client's document edit will
 *   never be re-run -- so it is finished here. On a sealable (log-governed)
 *   store the seal backstop follows: a revocation whose rotation no-op'd
 *   leaves nothing for the recipient convergence to find, but the roster
 *   log's head still anchors before the membership change, and that unsealed
 *   state is detected and closed here, idempotently. Strictly best-effort: a
 *   log that cannot be fetched or verified (offline, an unpromoted account)
 *   leaves the start's own roster read in place, and the next start tries
 *   again.
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
  isSealableDescriptorStore,
  readUserKeyRoster,
  type UserKey,
  type UserKeyRosterReadResult
} from '../keys/index.js'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import { log } from '../log.js'
import { isResourceLogRefusal } from '../resourceLog/errors.js'
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
 * discontinuous roster log, a rolled-back or replayed epoch configuration, an
 * epoch configuration that fails authentication, and a current epoch this
 * client cannot unwrap. They are the continuity class that refuses a session
 * rather than degrading it, so both entry points rethrow them instead of
 * warning and carrying on.
 *
 * The log half is {@link isResourceLogRefusal}, which carries the chain-head
 * pin's `rollback` carve-out for every reader of a governed log; what this
 * adds is the three names the generic taxonomy does not have. Among them the
 * epoch pin's own `UserKeyRosterContinuityError` stays a refusal with no
 * carve-out of its own: with no chain to compare it cannot tell a rollback
 * from a fork, and it is the guard that remains when the chain-head pin was
 * lost with a reinstall.
 *
 * Matched on `err.name` rather than `instanceof`, for the reason the shared
 * predicate is: the errors are raised inside the app-injected descriptor
 * store, which can resolve to a different copy of this package (linked, or
 * duplicated through a dependency tree), and a refusal from that copy must
 * not fall into the warn-and-proceed transport branch.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
function isRosterRefusal(err: unknown): boolean {
  if (isResourceLogRefusal(err)) {
    return true
  }
  const name = (err as { name?: unknown } | null)?.name
  return (
    name === 'UserKeyRosterContinuityError' ||
    name === 'UserKeyRosterIntegrityError' ||
    name === 'UserKeyRosterUnwrapError'
  )
}

/**
 * The login-time roster read. See the module doc for the failure semantics.
 *
 * Every read traces to the account document through the log-governed store
 * itself: the roster resolves only from the roster log's verified head, whose
 * entry proofs are checked against the locally verified account log. A log
 * that cannot be fetched, and a served log the chain-head pin reports as a
 * rollback, land in the transport-failure class -- the session carries on
 * under the cached key, WITHOUT adopting an unverifiable (or rolled-back)
 * rotation -- while a roster no enrolled client signed onto the log, and a
 * log the pin reports as a fork or an SCID/method switch, are refusals like
 * the other three.
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
 *   pin must persist atomically. A throw from this callback propagates to the
 *   caller verbatim -- it means the adopted key and pin did NOT persist, which
 *   is neither a transport hiccup nor a roster refusal
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
  let read: UserKeyRosterReadResult | null
  try {
    read = await readUserKeyRoster({
      store,
      ...(userKey ? { userKey } : {}),
      clientKeyAgreementKey,
      pinnedEpochId
    })
  } catch (err) {
    if (isRosterRefusal(err)) {
      throw err
    }
    // An unreachable server (or any transport hiccup) must not lock the user
    // out of an offline start: the cached key stays authoritative.
    log.warn(
      'The wrap-set roster check failed; continuing with the cached user key',
      {
        err
      }
    )
    return null
  }
  if (!read) {
    return null
  }
  // The adoption callback runs OUTSIDE the transport catch: the roster read
  // itself succeeded, so a throw here is the app failing to persist the
  // adopted key and epoch pin, and swallowing it into the warn-and-null path
  // would report a broken persist as an offline start (the session would
  // proceed on the retired cached key with the pin never advanced).
  await onRosterRead?.({
    userKey: read.userKey,
    latestEpochId: read.latestEpochId,
    descriptor: read.descriptor
  })
  return read
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
 * out onto the pre-rotation epoch). The roster refusals rethrow throughout,
 * exactly as {@link checkUserKeyRosterAtLogin} rethrows them, under the same
 * rollback carve-out.
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
 * @param [options.accountLogPinStore] {ResourceLogPinStore}   this client's
 *   chain-head pin for the account log; a served log the pin reports as a
 *   fork or an SCID/method switch is a refusal like the others, while a
 *   rollback resolves to the unchanged input under the carve-out
 * @param [options.onUserKeyAdopted] {Function}   called with the
 *   {@link AdoptedUserKey} of a rotation, before the fan-out runs
 * @returns {Promise<object>}   whether the roster rotated on this call,
 *   whether the seal backstop had to append (`sealed`), the stale recipient
 *   kids found, and the key + descriptor to fan out with
 */
export async function convergeUserKeyRosterToAccount({
  pointer,
  store,
  userKey,
  descriptor,
  clientKeyAgreementKey,
  pinnedEpochId,
  accountLogPinStore,
  onUserKeyAdopted
}: {
  pointer: AccountLogPointer
  store: EncryptionDescriptorStore
  userKey: UserKey
  descriptor: CollectionEncryption
  clientKeyAgreementKey: IKeyAgreementKey
  pinnedEpochId?: string | null
  accountLogPinStore?: ResourceLogPinStore
  onUserKeyAdopted?: (adopted: AdoptedUserKey) => Promise<void>
}): Promise<{
  rotated: boolean
  sealed: boolean
  staleRecipientIds: string[]
  userKey: UserKey
  descriptor: CollectionEncryption
}> {
  const unchanged = {
    rotated: false,
    sealed: false,
    staleRecipientIds: [] as string[],
    userKey,
    descriptor
  }
  let rotated: boolean
  let staleRecipientIds: string[]
  try {
    const { doc } = await verifyAccountLog({
      ...pointer,
      ...(accountLogPinStore ? { pinStore: accountLogPinStore } : {})
    })
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
    log.warn(
      'Could not converge the wrap-set roster onto the account document',
      {
        err
      }
    )
    return unchanged
  }

  // The seal backstop, on a sealable (log-governed) store: a converged
  // recipient set can still leave the roster log's head anchored before the
  // membership change -- the torn revocation whose rotation no-op'd (the
  // revoked client held no current-epoch wrap), which the recipient
  // convergence above finds nothing to rotate for. "A governed log's head
  // anchor predates the membership change" is the durable signal; sealing it
  // is idempotent, so every start may try. Refusal classes rethrow exactly
  // like the convergence's; anything else (transport) warns and leaves the
  // seal to the next start.
  let sealed = false
  if (isSealableDescriptorStore(store)) {
    try {
      sealed = (await store.seal()) === 'sealed'
    } catch (err) {
      if (isRosterRefusal(err)) {
        throw err
      }
      log.warn('Could not seal the wrap-set roster log', { err })
    }
  }

  if (!rotated) {
    return { ...unchanged, sealed }
  }
  log.warn(
    'The wrap-set roster still wrapped the current key to recipient(s) ' +
      'the account document no longer keys; the rotation has been completed',
    { staleRecipientCount: staleRecipientIds.length }
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
    sealed,
    staleRecipientIds,
    userKey: read.userKey,
    descriptor: read.descriptor
  }
}
