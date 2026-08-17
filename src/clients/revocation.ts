/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The client-revocation cascade: disconnecting an enrolled wallet client from
 * an account, run synchronously in the revoking client, in dependency order.
 * One orchestrator for every wallet, with the two app-specific stages injected
 * rather than forked.
 *
 * 1. **The document edit** (`revokeWebvhClient`): the revoked client's two
 *    verification methods, its update key, and both its standing prerotation
 *    commitments leave the account's did:webvh document in one log entry.
 *    Under the current-key-set rule that single edit is the revoked client's
 *    pull axis EVERYWHERE -- its invocations, and every delegation and app
 *    grant it ever signed, stop verifying the moment its verification method
 *    leaves the document. There is no per-collection revoke anywhere in the
 *    cascade; apps a revoked client had connected reconnect through the
 *    ordinary connect flow.
 * 2. **The user key rotation** in the wrap-set roster, recipients resolved
 *    from the document the edit itself just resolved to (no re-fetch of the
 *    log this call just extended). On a log-governed roster store the
 *    orchestrator itself guarantees post-edit anchoring: the controller view
 *    built from the edit's own post-edit log is set as the store's freshness
 *    floor (`setControllerFloor`) before anything roster-side runs, so the
 *    rotation and the seal backstop anchor at or past the edit even where the
 *    app's injected controller resolution still serves a cached pre-edit
 *    view. The roster delivers, never sources, so the
 *    stage names no client at all: it converges the roster onto that document
 *    (the login sweep's own path), retiring every current-epoch recipient the
 *    document no longer keys in one rotation. Nothing here has to pair a
 *    client with its key-agreement key, so a client that published several
 *    of them, or none the caller knows, is retired just the same. An
 *    account with no roster yet stops here: the client IS disconnected, with
 *    nothing to rotate. On a sealable (log-governed) roster store, the seal
 *    backstop follows: a rotation that no-op'd appended nothing, so the
 *    roster log may still be anchored before the document edit -- `seal()`
 *    re-anchors it with an idempotent no-op entry, best-effort and reported
 *    rather than thrown.
 * 3. **The collection fan-out**: every encrypted collection is re-epoch'd onto
 *    the fresh key in parallel, so writes stop landing under epochs the
 *    revoked client can still decrypt. Failures are collected per collection
 *    and never abort the fan-out.
 * 4. **The recovery re-mints** (optional): delegations the revoked client had
 *    signed stopped chaining at stage 1, so a wallet that issues recovery
 *    codes re-mints them here -- while the registry is still readable under
 *    the session's pre-adoption vault keys.
 *
 * The revoking session then adopts the fresh key in place (`onRotationAdopted`
 * -- profile vault keys, storage ciphers, engine restarts: whatever "in place"
 * means for the app), so it keeps operating without a re-login.
 *
 * Convergence is the design: every stage detects its own completion from
 * durable state alone -- the log entry is idempotent, the roster no-ops once
 * the revoked entry is off the current epoch, and a collection is stale
 * exactly when its current epoch names a non-current key generation -- so a
 * mid-cascade crash strands nothing permanently and a naive full re-run
 * finishes it (the login-time completion sweep is the standing backstop). The
 * honest ceiling is unchanged: ciphertext the revoked client already fetched
 * stays readable to it, and old epochs open to keys it already held.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import {
  revokeWebvhClient,
  type ClientWebvhUpdateKeys,
  type PublishedKeyDocument,
  type RevokedClientKeys,
  type WebvhIdStore
} from '../webvh/index.js'
import {
  rotateRosterToDocumentAndCascade,
  type CascadeCollections,
  type RosterSealReport,
  type UserKey,
  type UserKeyCascadeResult
} from '../keys/index.js'

export type { CascadeCollections, RosterSealReport }

/**
 * What a completed cascade reports: whether the roster actually rotated on
 * this run (a re-run of an already-complete revocation reports `false`), the
 * roster's seal-backstop report (present when the roster store is sealable
 * and the roster stage ran), the per-collection fan-out result, the document
 * as the edit left it, and the recovery re-mint counts when that stage ran.
 */
export interface ClientRevocationResult {
  rotated: boolean
  rosterSeal?: RosterSealReport
  collections: UserKeyCascadeResult
  document: object
  userKey?: UserKey
  rosterDescriptor?: CollectionEncryption
  recovery?: { reminted: number; skipped: number }
}

/**
 * Runs the whole revocation cascade for one enrolled wallet client. See the
 * module doc for the order and the convergence story. Throws before touching
 * anything on a call that must not proceed (revoking this client itself, a
 * client whose active update key was not attributed); once the document edit
 * lands, a thrown later stage leaves durable state a naive re-run -- or the
 * login-time sweep -- converges from.
 *
 * The document edit's `StagedCommitmentAmbiguousError` passes through
 * unwrapped, so a surface can re-word it ("disconnect this wallet from the
 * other one instead"). Match it on `err.name ===
 * 'StagedCommitmentAmbiguousError'` -- a stable contract on that class --
 * rather than on `instanceof`, which does not survive a linked or duplicated
 * copy of this package.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}   the account's `id` collection store
 * @param options.updateKeys {ClientWebvhUpdateKeys}   THIS client's did:webvh
 *   update-key seeds, which sign the document edit
 * @param options.revokedClient {RevokedClientKeys}   the revoked client's
 *   public halves (its two verification-method multibases and its active
 *   update key)
 * @param [options.knownLatentHashes] {string[]}   the standing recovery codes'
 *   update-key hashes, so the document edit can tell the revoked client's
 *   staged commitment apart from a latent recovery commitment (the one
 *   ambiguous log shape). Best-effort on the caller's side: an unreadable
 *   registry simply omits them
 * @param [options.expectedDid] {string}   the account DID from the caller's
 *   stored account pointer; supplied, the document edit refuses a `did.jsonl`
 *   resolving to any other account
 * @param [options.ownSigningKeyMultibase] {string}   this client's own signing
 *   key; supplied, self-revocation is refused up front by the rule the surface
 *   should name, rather than by the update-key check inside the edit
 * @param options.rosterStore {EncryptionDescriptorStore}   the
 *   `key-map/user-key.jsonl` roster store
 * @param [options.userKey] {UserKey}   this client's cached user key
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key -- its roster entry
 * @param [options.pinnedEpochId] {string}   the locally pinned latest-seen
 *   roster epoch
 * @param [options.onUserKeyAdopted] {Function}   persists a rotated key: called
 *   with `{ userKey, latestEpochId, descriptor }` after the roster read and BEFORE
 *   the fan-out. The key and the epoch pin must persist atomically
 * @param options.collections {CascadeCollections}   the fan-out's work
 * @param [options.remintRecoveryDelegations] {Function}   `({ document }) =>
 *   Promise<{ reminted, skipped }>` -- the recovery-delegation re-mint stage,
 *   for a wallet that issues recovery codes
 * @param [options.onRotationAdopted] {Function}   `({ userKey }) => Promise<void>`
 *   -- the live-session adoption of a rotated key, run last so the session
 *   keeps operating without a re-login
 * @returns {Promise<ClientRevocationResult>}
 */
export async function revokeAccountClient({
  idStore,
  updateKeys,
  revokedClient,
  knownLatentHashes,
  expectedDid,
  ownSigningKeyMultibase,
  rosterStore,
  userKey,
  clientKeyAgreementKey,
  pinnedEpochId,
  onUserKeyAdopted,
  collections,
  remintRecoveryDelegations,
  onRotationAdopted
}: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  revokedClient: RevokedClientKeys
  knownLatentHashes?: string[]
  expectedDid?: string
  ownSigningKeyMultibase?: string
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
  remintRecoveryDelegations?: (options: {
    document: PublishedKeyDocument
  }) => Promise<{ reminted: number; skipped: number }>
  onRotationAdopted?: (rotation: { userKey: UserKey }) => Promise<void>
}): Promise<ClientRevocationResult> {
  if (
    ownSigningKeyMultibase &&
    ownSigningKeyMultibase === revokedClient.signingKeyMultibase
  ) {
    throw new Error(
      'This wallet cannot disconnect itself; use another enrolled wallet ' +
        'client (or a recovery code) instead.'
    )
  }
  if (!revokedClient.updateKeyMultibase) {
    throw new Error(
      "This wallet's update key could not be attributed from the account " +
        'log, so it cannot be disconnected from here.'
    )
  }

  // 1. The document edit -- the pull axis everywhere, first. It resolves the
  // document as it now stands, which is what stage 2 resolves its remaining
  // recipients from.
  const { did, doc, log } = await revokeWebvhClient({
    idStore,
    updateKeys,
    revokedClient,
    ...(knownLatentHashes ? { knownLatentHashes } : {}),
    ...(expectedDid !== undefined ? { expectedDid } : {})
  })

  // 2-3. The shared roster-and-cascade tail: the roster rotation onto the
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
    // No roster to rotate: the document edit has landed, so the client IS
    // disconnected -- a completed cascade with nothing rotated.
    return {
      rotated: false,
      collections: tail.collections,
      document: doc
    }
  }

  // 4. The recovery re-mints, while the registry is still readable under the
  // session's pre-adoption vault keys.
  const recovery = await remintRecoveryDelegations?.({ document: doc })

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
    ...(recovery ? { recovery } : {})
  }
}
