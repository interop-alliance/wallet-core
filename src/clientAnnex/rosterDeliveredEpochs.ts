/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The mint policy's one home: **collection epochs install under the key the
 * roster delivers after the ensure, not the minted candidate**. The ensure
 * adopts a roster another run landed first, and epoch[0] is create-if-absent,
 * so installing under this run's candidate would key a collection to a key
 * nobody holds. One function, two callers: the credential-anchored
 * establishment's adopted-roster arm, and the mend entry point's roster arm.
 *
 * The stage order: ensure the roster (create-if-absent with the supplied
 * candidate; the entry proof rides the caller's store signer -- the ladder VM
 * on a ladder-anchored account, the ceremony-tail license's first-entry
 * shape), re-read the delivered key with the credential's own key-agreement
 * key, then complete the collection epochs under the DELIVERED key. Running
 * the fan-out is itself the completion test's re-entry: `ensureIndexedFirstEpoch`
 * is create-if-absent per collection, so an epoch-less encrypted collection
 * behind a present roster is finished here, durable state alone.
 *
 * Three refusal-shape rules:
 *
 * - A lost create race (two concurrent runners both saw an absent roster)
 *   re-reads and ADOPTS the winner's roster, reported as
 *   `'converged-elsewhere'` -- never an untyped escape on an account that is
 *   actually healthy.
 * - A roster adopted whose current epoch carries no wrap for this credential
 *   (`UserKeyRosterUnwrapError`) surfaces as its own `'no-wrap'` outcome, a
 *   distinct value rather than an escaping throw: it is a materially
 *   different, often attack-relevant state, and the caller maps it to its
 *   own copy.
 * - A failed roster or descriptor read is a transport error and rethrows
 *   unchanged -- absence is the only incompleteness signal, so a flap can
 *   neither fire a spurious mint nor read as a missing roster.
 *
 * Per-collection fan-out failures surface on the result's `epochs.failed`
 * list (the establishment's assert contract); nothing is discarded.
 */
import type { IZcap } from '@interop/data-integrity-core'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { CollectionEncryption, WasClient } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import {
  ensureUserKeyRoster,
  ensureWalletSpaceEpochs,
  readUserKeyRoster,
  type UserKey,
  type WalletSpaceEpochsResult
} from '../keys/index.js'

/**
 * The error names a lost roster-genesis race surfaces as: the guarded create
 * losing to a concurrent first init (`PreconditionFailedError` from the
 * descriptor store's `If-None-Match` create), or the log-governed store's
 * append CAS losing on the same race (`WebvhLogConflictError`). Matched by
 * `name` -- error classes do not survive crossing package copies.
 */
const CREATE_RACE_ERROR_NAMES = new Set([
  'PreconditionFailedError',
  'WebvhLogConflictError'
])

/**
 * What one run delivered. `'delivered'`: the roster (minted here or adopted
 * as found) delivered a key this credential unwraps, and the collection
 * epochs completed under it. `'converged-elsewhere'`: same, but this run's
 * genesis append lost the create race and adopted the winner's roster -- a
 * healthy account, never a failure. `'no-wrap'`: a roster was adopted whose
 * current epoch carries no wrap for this credential; nothing was installed.
 */
export type RosterDeliveredEpochsResult =
  | {
      outcome: 'delivered' | 'converged-elsewhere'
      /**
       * The key the roster DELIVERS -- the one the epochs installed under.
       */
      userKey: UserKey
      rosterDescriptor: CollectionEncryption
      /**
       * Whether this run's candidate became the roster's first epoch.
       */
      minted: boolean
      epochs: WalletSpaceEpochsResult
    }
  | {
      outcome: 'no-wrap'
      rosterDescriptor: CollectionEncryption
      /**
       * The `UserKeyRosterUnwrapError` the re-read surfaced.
       */
      error: unknown
    }

/**
 * Ensures the user-key roster exists and every encrypted collection carries
 * epoch[0] under the key the roster delivers (see the module doc for the
 * policy and the refusal shapes). The two authority pairs ride the caller's
 * handles: the SIGNER is the store's (`store`, ladder-signed appends on a
 * ladder-anchored account), the INVOCATION is `was`'s -- bootstrap root
 * pre-promotion, or a delegated capability post-promotion (`capability`).
 *
 * @param options {object}
 * @param options.store {EncryptionDescriptorStore}   the roster's descriptor
 *   store (the log-governed store, with the caller's signer)
 * @param options.candidateUserKey {UserKey}   the freshly minted candidate;
 *   installed as epoch[0] only when the roster is absent, and never the key
 *   the epochs install under unless the roster delivers it back
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   the credential's
 *   own key-agreement key -- the roster recipient the ensure wraps to, and
 *   the unwrap key of the re-read
 * @param options.was {WasClient}   the collection fan-out's storage client
 * @param options.spaceId {string}   the account Space's id
 * @param [options.capability] {IZcap}   the delegated invocation capability
 *   every fan-out request rides (a post-promotion caller: the generation
 *   delegation); absent, requests invoke the root capability
 * @param [options.collectionIds] {string[]}   the fan-out's collection set
 *   override, threaded through to `ensureWalletSpaceEpochs`
 * @param [options.beforeMint] {Function}   `() => Promise<void>` -- the mint
 *   guard, awaited exactly when THIS run's own decide-read observed the
 *   roster absent and is about to install the candidate as epoch[0]. A
 *   throw refuses the mint and propagates unchanged (never folded into the
 *   create-race adoption), so a caller's mint preconditions run against the
 *   same observation the mint acts on
 * @returns {Promise<RosterDeliveredEpochsResult>}
 */
export async function ensureRosterDeliveredEpochs({
  store,
  candidateUserKey,
  clientKeyAgreementKey,
  was,
  spaceId,
  capability,
  collectionIds,
  beforeMint
}: {
  store: EncryptionDescriptorStore
  candidateUserKey: UserKey
  clientKeyAgreementKey: IKeyAgreementKey
  was: WasClient
  spaceId: string
  capability?: IZcap
  collectionIds?: string[]
  beforeMint?: () => Promise<void>
}): Promise<RosterDeliveredEpochsResult> {
  // The ensure: create-if-absent with the candidate, the mint guard fired
  // on this run's own absent observation. A read failure is a transport
  // error and rethrows unchanged; only the guarded create's lost race is
  // caught, re-read, and adopted.
  let descriptor: CollectionEncryption
  let convergedElsewhere = false
  try {
    const current = await store.read()
    if (current !== null) {
      descriptor = current.descriptor
    } else {
      if (beforeMint !== undefined) {
        await beforeMint()
      }
      descriptor = await ensureUserKeyRoster({
        store,
        userKey: candidateUserKey,
        clientKeyAgreementKey
      })
    }
  } catch (err) {
    if (!CREATE_RACE_ERROR_NAMES.has((err as { name?: string }).name ?? '')) {
      throw err
    }
    const reread = await store.read()
    if (reread === null) {
      throw err
    }
    descriptor = reread.descriptor
    convergedElsewhere = true
  }
  const minted = descriptor.currentEpoch === candidateUserKey.id

  // The re-read: the key the roster DELIVERS, unwrapped with the
  // credential's own key-agreement key. The no-wrap adoption is its own
  // outcome, not an escaping throw.
  let userKey: UserKey
  try {
    const read = await readUserKeyRoster({
      store,
      descriptor,
      userKey: candidateUserKey,
      clientKeyAgreementKey
    })
    userKey = read.userKey
  } catch (err) {
    if ((err as { name?: string }).name === 'UserKeyRosterUnwrapError') {
      return { outcome: 'no-wrap', rosterDescriptor: descriptor, error: err }
    }
    throw err
  }

  // The fan-out, under the DELIVERED key -- create-if-absent per collection,
  // so this call is also the completion test's re-entry on an epoch-less
  // encrypted collection behind a present roster. Per-collection failures
  // ride the result's `failed` list to the caller.
  const epochs = await ensureWalletSpaceEpochs({
    was,
    spaceId,
    userKey,
    ...(capability !== undefined ? { capability } : {}),
    ...(collectionIds !== undefined ? { collectionIds } : {})
  })
  return {
    outcome: convergedElsewhere ? 'converged-elsewhere' : 'delivered',
    userKey,
    rosterDescriptor: descriptor,
    minted,
    epochs
  }
}
