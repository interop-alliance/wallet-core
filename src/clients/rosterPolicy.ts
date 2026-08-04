/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The login-time wrap-set roster policy: what a wallet does with
 * `key-map/puk.json` when a session starts, and how it decides between
 * refusing the session and carrying on offline.
 *
 * Two steps, in this order:
 *
 * - {@link checkPukRosterAtLogin} -- one direct read of the roster, before any
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
 * - {@link convergePukRosterToAccount} -- the roster stage of the
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
  convergePukRosterToDocument,
  PukRosterContinuityError,
  PukRosterIntegrityError,
  PukRosterUnwrapError,
  readPukRoster,
  type Puk,
  type PukRosterReadResult
} from '../keys/index.js'
import { verifyAccountLog } from '../webvh/index.js'
import type { AccountLogPointer } from './listing.js'

/**
 * What an adopted per-user key carries: the key itself, the roster epoch to
 * pin as latest-seen, and the descriptor it was read from.
 */
export interface AdoptedPuk {
  puk: Puk
  latestEpochId: string
  descriptor: CollectionEncryption
}

/**
 * Whether a thrown error is one of the three roster refusals -- a rolled-back
 * or replayed roster, an epoch configuration that fails authentication, and a
 * current epoch this client cannot unwrap. They are the continuity class that
 * refuses a session rather than degrading it, so both entry points rethrow
 * them instead of warning and carrying on.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
function isRosterRefusal(err: unknown): boolean {
  return (
    err instanceof PukRosterContinuityError ||
    err instanceof PukRosterIntegrityError ||
    err instanceof PukRosterUnwrapError
  )
}

/**
 * The login-time roster read. See the module doc for the failure semantics.
 *
 * @param options {object}
 * @param options.store {EncryptionDescriptorStore}   the roster's descriptor
 *   store
 * @param [options.puk] {Puk}   this client's cached per-user key; omitted (a
 *   freshly enrolled client's first read) the key is always taken from the
 *   roster
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key -- its roster entry
 * @param [options.pinnedEpochId] {string}   the locally pinned latest-seen
 *   roster epoch
 * @param [options.onRosterRead] {Function}   called with the
 *   {@link AdoptedPuk} of every successful read (whether or not it rotated),
 *   so the epoch pin advances to the epoch just authenticated; the key and the
 *   pin must persist atomically
 * @returns {Promise<PukRosterReadResult | null>}   the read, or `null` when
 *   the account has no roster yet or the server could not be reached
 */
export async function checkPukRosterAtLogin({
  store,
  puk,
  clientKeyAgreementKey,
  pinnedEpochId,
  onRosterRead
}: {
  store: EncryptionDescriptorStore
  puk?: Puk
  clientKeyAgreementKey: IKeyAgreementKey
  pinnedEpochId?: string | null
  onRosterRead?: (adopted: AdoptedPuk) => Promise<void>
}): Promise<PukRosterReadResult | null> {
  try {
    const read = await readPukRoster({
      store,
      ...(puk ? { puk } : {}),
      clientKeyAgreementKey,
      pinnedEpochId
    })
    if (!read) {
      return null
    }
    await onRosterRead?.({
      puk: read.puk,
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
        'per-user key:',
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
 * and descriptor (which would skip `onPukAdopted` and fan the collections out
 * onto the pre-rotation epoch). The three roster refusals rethrow throughout,
 * exactly as {@link checkPukRosterAtLogin} rethrows them.
 *
 * @param options {object}
 * @param options.pointer {AccountLogPointer}   where the account log lives
 * @param options.store {EncryptionDescriptorStore}   the roster's descriptor
 *   store
 * @param options.puk {Puk}   the start's current per-user key
 * @param options.descriptor {CollectionEncryption}   the start's roster read
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key
 * @param [options.pinnedEpochId] {string}   the locally pinned latest-seen
 *   roster epoch
 * @param [options.onPukAdopted] {Function}   called with the
 *   {@link AdoptedPuk} of a rotation, before the fan-out runs
 * @returns {Promise<object>}   whether the roster rotated on this call, the
 *   stale recipient kids found, and the key + descriptor to fan out with
 */
export async function convergePukRosterToAccount({
  pointer,
  store,
  puk,
  descriptor,
  clientKeyAgreementKey,
  pinnedEpochId,
  onPukAdopted
}: {
  pointer: AccountLogPointer
  store: EncryptionDescriptorStore
  puk: Puk
  descriptor: CollectionEncryption
  clientKeyAgreementKey: IKeyAgreementKey
  pinnedEpochId?: string | null
  onPukAdopted?: (adopted: AdoptedPuk) => Promise<void>
}): Promise<{
  rotated: boolean
  staleRecipientIds: string[]
  puk: Puk
  descriptor: CollectionEncryption
}> {
  const unchanged = {
    rotated: false,
    staleRecipientIds: [] as string[],
    puk,
    descriptor
  }
  let rotated: boolean
  let staleRecipientIds: string[]
  try {
    const { doc } = await verifyAccountLog(pointer)
    const converged = await convergePukRosterToDocument({
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
  let read: PukRosterReadResult | null
  try {
    read = await readPukRoster({
      store,
      puk,
      clientKeyAgreementKey,
      pinnedEpochId
    })
  } catch (err) {
    if (isRosterRefusal(err)) {
      throw err
    }
    throw new Error(
      'The wrap-set roster was rotated onto a fresh per-user key, but the ' +
        'read that adopts it failed; this session must not continue under ' +
        'the retired key.',
      { cause: err }
    )
  }
  if (!read) {
    throw new Error(
      'The wrap-set roster was rotated onto a fresh per-user key and then ' +
        'reported absent; this session must not continue under the retired ' +
        'key.'
    )
  }
  await onPukAdopted?.({
    puk: read.puk,
    latestEpochId: read.latestEpochId,
    descriptor: read.descriptor
  })
  return {
    rotated: true,
    staleRecipientIds,
    puk: read.puk,
    descriptor: read.descriptor
  }
}
