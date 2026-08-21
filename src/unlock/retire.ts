/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Retiring a standing unlock credential: the ceremony behind "change my
 * passphrase" and "remove this passkey", run synchronously in an enrolled
 * client, in dependency order. A standing credential is not a stored string to
 * overwrite -- it holds a wrap in the user key roster and a `keyAgreement`
 * posture in the account's did:webvh document -- so retiring one is a real
 * rotation, on the same stages the client-revocation cascade runs.
 *
 * 1. **The document posture edit** (`removeUnlockKey`): the credential's
 *    `keyAgreement` entry (verbatim key or commitment) and its committed
 *    update-key hash leave the document in one log entry. That kills the
 *    credential's latent self-enrollment authority -- with its rung
 *    commitment gone, no reveal entry it could sign verifies -- and it is
 *    what makes stage 2 converge: the roster resolver, backed by this
 *    document, no longer keys the credential's entry.
 * 2. **The roster rotation and the collection fan-out**
 *    (`rotateRosterToDocumentAndCascade`): the user key rotates off the
 *    credential's wrap and every encrypted collection re-epochs onto the
 *    fresh key, so writes stop landing under epochs the retired credential
 *    could open.
 *
 * The order is load-bearing, and in that direction: the document removal
 * first means a run torn anywhere after it leaves the roster keying a
 * recipient the document no longer backs -- exactly the state the login-time
 * sweep detects and finishes. Torn the other way around, a rotation with the
 * posture still standing would simply re-escrow the credential and look
 * healthy.
 *
 * There is deliberately no recovery-delegation re-mint stage here (the
 * client-revocation cascade's fourth stage). A retired credential signs no
 * delegations: its own bridge delegation dies with its unlock Space, which
 * the app deletes as part of the change-method ceremony, and no other
 * credential's bridge chains through it.
 *
 * The COMPANION reach is its own stage (1b, the injected
 * `retireCompanionPosture` closure), between the document edit and the
 * roster tail: a standing credential's companion rung-0 key and hash live in
 * the pointed generation's log, kept nowhere the account document edit can
 * reach, so without it a retired credential keeps companion-write authority
 * for the life of the generation. The closure runs strike-or-swap: a
 * dedicated strike entry signed by a distinct committed rung
 * (`retireCompanionRung`) where the ceremony holds one, else a fresh
 * generation minted from a surviving credential's seed and re-pointed under
 * account-log update authority (`swapCompanionGeneration`), the retired rung
 * dying with the old generation. It also owns retiring the credential's
 * `delegatedClients` sibling: no server revocation is possible or needed --
 * the sibling delegation's record dies with the unlock Space the caller
 * deletes, and a swap (or the ordinary GC cadence) retires the generation it
 * targeted. Best-effort by contract: the closure catches its own failures
 * and reports them, so the roster rotation -- the ceremony's essential
 * remedy -- always runs.
 *
 * Convergence is the design: every stage detects its own completion from
 * durable state alone -- the posture edit no-ops when the document is already
 * settled, the rotation no-ops once every current-epoch recipient is
 * document-backed, and a collection is stale exactly when its current epoch
 * names a non-current user key generation -- so a naive full re-run finishes
 * a torn ceremony and a healthy account writes nothing.
 *
 * The honest limitation is the cascade's: ciphertext the credential's holder
 * already fetched and decrypted stays readable, and old epochs stay open to
 * the user key generations the credential already delivered. Retirement stops
 * future reads.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import {
  rotateRosterToDocumentAndCascade,
  type CascadeCollections,
  type RosterSealReport,
  type UserKey,
  type UserKeyCascadeResult
} from '../keys/index.js'
import type { ClientWebvhUpdateKeys, WebvhIdStore } from '../webvh/index.js'
import { removeUnlockKey, type StandingUnlockKeys } from './standingWebvh.js'

/**
 * What a completed retirement reports: whether the roster actually rotated on
 * this run (a re-run of an already-complete retirement reports `false`), the
 * roster's seal-backstop report (present when the roster store is sealable and
 * the roster stage ran), the per-collection fan-out result, the document as
 * the posture edit left it, and the rotated key with the roster descriptor it
 * was read from.
 */
export interface UnlockCredentialRetirementResult {
  rotated: boolean
  rosterSeal?: RosterSealReport
  collections: UserKeyCascadeResult
  document: object
  userKey?: UserKey
  rosterDescriptor?: CollectionEncryption
  companion?: CompanionPostureRetirement
}

/**
 * What the companion-posture stage reports: `struck` (a strike entry dropped
 * the retired rung's key and hash), `swapped` (a fresh generation replaced
 * the old one wholesale), `clean` (the pointed generation held no posture
 * for the retired credential), or `skipped` with the reason (`no-pointer`:
 * the account has no companion posture; `no-ladder-seed`: the ceremony holds
 * no seed that could strike or swap; `failed`: the closure's best-effort
 * catch).
 */
export interface CompanionPostureRetirement {
  action: 'struck' | 'swapped' | 'clean' | 'skipped'
  reason?: 'no-pointer' | 'no-ladder-seed' | 'failed'
}

/**
 * Retires one standing unlock credential from an account. See the module doc
 * for the order and the convergence story. Once the posture edit lands, a
 * thrown later stage leaves durable state a naive re-run -- or the login-time
 * sweep -- converges from.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}   the account's `id` collection store
 * @param options.updateKeys {ClientWebvhUpdateKeys}   the RETIRING (enrolled)
 *   client's own did:webvh update-key seeds, which sign the posture edit
 * @param options.unlockKeys {StandingUnlockKeys}   the retired credential's
 *   public posture (its key-agreement publication and its recorded update
 *   key, which the posture edit treats as a ladder anchor rather than truth
 *   -- see `removeUnlockKey`)
 * @param [options.ladderSeed] {Uint8Array}   the retired credential's ladder
 *   seed, when the ceremony holds the credential's secret; it strengthens the
 *   ladder attribution but is not required
 * @param [options.expectedDid] {string}   the account DID from the caller's
 *   stored account pointer; supplied, the posture edit refuses a `did.jsonl`
 *   resolving to any other account
 * @param [options.verb] {string}   what the caller is doing, for the
 *   pending-rotation refusal message (e.g. `'changing your passphrase'`)
 * @param options.rosterStore {EncryptionDescriptorStore}   the
 *   `key-map/user-key.jsonl` roster store
 * @param [options.userKey] {UserKey}   this client's cached user key
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key -- its roster entry
 * @param [options.pinnedEpochId] {string}   the locally pinned latest-seen
 *   roster epoch
 * @param [options.onUserKeyAdopted] {Function}   persists a rotated key:
 *   called with `{ userKey, latestEpochId, descriptor }` after the roster read
 *   and BEFORE the fan-out. The key and the epoch pin must persist atomically
 * @param options.collections {CascadeCollections}   the fan-out's work
 * @param [options.retireCompanionPosture] {Function}   `({ document }) =>
 *   Promise<CompanionPostureRetirement>` -- the companion reach (stage 1b in
 *   the module doc), run against the post-edit document; expected to catch
 *   its own failures and report them
 * @param [options.onRotationAdopted] {Function}   `({ userKey }) =>
 *   Promise<void>` -- the live-session adoption of a rotated key, run last so
 *   the session keeps operating without a re-login
 * @returns {Promise<UnlockCredentialRetirementResult>}
 */
export async function retireUnlockCredential({
  idStore,
  updateKeys,
  unlockKeys,
  ladderSeed,
  expectedDid,
  verb,
  rosterStore,
  userKey,
  clientKeyAgreementKey,
  pinnedEpochId,
  onUserKeyAdopted,
  collections,
  retireCompanionPosture,
  onRotationAdopted
}: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  unlockKeys: StandingUnlockKeys
  ladderSeed?: Uint8Array
  expectedDid?: string
  verb?: string
  rosterStore: EncryptionDescriptorStore
  userKey?: UserKey
  clientKeyAgreementKey: IKeyAgreementKey
  pinnedEpochId?: string | null
  onUserKeyAdopted?: (adopted: {
    userKey: UserKey
    latestEpochId: string
    descriptor: CollectionEncryption
  }) => Promise<void>
  collections: CascadeCollections
  retireCompanionPosture?: (options: {
    document: object
  }) => Promise<CompanionPostureRetirement>
  onRotationAdopted?: (rotation: { userKey: UserKey }) => Promise<void>
}): Promise<UnlockCredentialRetirementResult> {
  // 1. The document posture edit -- the credential's standing, first. It
  // resolves the document as it now stands, which is what stage 2 resolves
  // its remaining recipients from.
  const { did, doc, log } = await removeUnlockKey({
    idStore,
    updateKeys,
    unlockKeys,
    ...(ladderSeed ? { ladderSeed } : {}),
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(verb !== undefined ? { verb } : {})
  })

  // 1b. The companion reach, against the post-edit document: strike the
  // retired credential's rung posture out of the pointed generation, or swap
  // the generation out from under it. Best-effort by the closure's own
  // contract, so the roster rotation below always runs.
  const companion = await retireCompanionPosture?.({ document: doc })

  // 2. The shared roster-and-cascade tail: the roster rotation onto the
  // post-edit document (with its post-edit controller floor and its seal
  // backstop), then the collection fan-out onto the fresh key.
  const tail = await rotateRosterToDocumentAndCascade({
    rosterStore,
    did,
    doc,
    log,
    ...(userKey ? { userKey } : {}),
    clientKeyAgreementKey,
    pinnedEpochId,
    ...(onUserKeyAdopted ? { onUserKeyAdopted } : {}),
    collections
  })
  if (!tail.rosterDescriptor || !tail.userKey) {
    // No roster to rotate: the posture edit has landed, so the credential IS
    // retired -- a completed ceremony with nothing rotated.
    return {
      rotated: false,
      collections: tail.collections,
      document: doc,
      ...(companion ? { companion } : {})
    }
  }

  if (tail.rotated) {
    await onRotationAdopted?.({ userKey: tail.userKey })
  }

  return {
    rotated: tail.rotated,
    ...(tail.rosterSeal ? { rosterSeal: tail.rosterSeal } : {}),
    collections: tail.collections,
    document: doc,
    userKey: tail.userKey,
    rosterDescriptor: tail.rosterDescriptor,
    ...(companion ? { companion } : {})
  }
}
