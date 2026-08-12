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
 *    log this call just extended). The roster delivers, never sources, so the
 *    revoked client's entry is dropped even before the retire filter. An
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
  type RevokedClientKeys,
  type WebvhIdStore
} from '../webvh/index.js'
import {
  cascadeCollectionsToUserKey,
  isSealableDescriptorStore,
  readUserKeyRoster,
  rosterRecipientKid,
  rotateUserKeyRoster,
  type UserKey,
  type UserKeyCascadeResult
} from '../keys/index.js'

/**
 * What the roster's seal backstop reported: `sealed` (the roster log's head
 * still anchored before the document edit, and the backstop append landed),
 * `noop` (already sealed -- the rotation itself was the sealing append, or a
 * re-run found nothing to do), or `failed` (the seal could not run; carried
 * in `error`, never thrown -- the cascade stays a resumable success and the
 * login sweep re-seals).
 */
export interface RosterSealReport {
  outcome: 'sealed' | 'noop' | 'failed'
  error?: unknown
}

/**
 * Where the cascade's collection fan-out gets its work: which encrypted
 * collections exist (only the app knows -- a mobile replica names the
 * collections it replicates, a web wallet also lists the app-provisioned ones
 * remotely) and how each one's descriptor store and encryption declaration are
 * reached.
 */
export interface CascadeCollections {
  collectionIds: string[] | (() => Promise<string[]>)
  storeFor: (collectionId: string) => EncryptionDescriptorStore
  isEncrypted?: (collectionId: string) => Promise<boolean>
}

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
 * Resolves the collection ids the fan-out covers, whether they are a fixed set
 * or a listing the app performs.
 *
 * @param options {object}
 * @param options.collections {CascadeCollections}
 * @returns {Promise<string[]>}
 */
async function collectionIdsOf({
  collections
}: {
  collections: CascadeCollections
}): Promise<string[]> {
  const { collectionIds } = collections
  return typeof collectionIds === 'function'
    ? await collectionIds()
    : collectionIds
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
    document: object
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
  const { doc } = await revokeWebvhClient({
    idStore,
    updateKeys,
    revokedClient,
    ...(knownLatentHashes ? { knownLatentHashes } : {}),
    ...(expectedDid !== undefined ? { expectedDid } : {})
  })

  // 2. The roster rotation, recipients resolved from that same document.
  // Whether there IS a roster is settled BEFORE the rotation: an account with
  // no `key-map/user-key.jsonl` (its collections are not encrypted yet) has nothing
  // to rotate, and the rotation itself refuses an absent descriptor rather
  // than no-op'ing. The document edit has already landed, so the client IS
  // disconnected -- a completed cascade with nothing rotated, not a failure.
  const roster = await rosterStore.read()
  if (roster === null) {
    return {
      rotated: false,
      collections: { outcomes: {}, failed: [] },
      document: doc
    }
  }
  await rotateUserKeyRoster({
    store: rosterStore,
    document: doc,
    retireRecipientId: rosterRecipientKid(revokedClient)
  })
  const read = await readUserKeyRoster({
    store: rosterStore,
    ...(userKey ? { userKey } : {}),
    clientKeyAgreementKey,
    pinnedEpochId
  })
  if (!read) {
    // The roster stood a moment ago and the rotation just wrote it, so its
    // disappearance is a real fault, not the no-roster case above: the fresh
    // key is only readable from the roster, and reporting success here would
    // fan out under the retired one.
    throw new Error(
      'The wrap-set roster vanished between its rotation and the read that ' +
        'adopts the fresh user key; the client is disconnected, but the ' +
        'rotation must be completed by re-running the revocation.'
    )
  }
  if (read.rotated) {
    await onUserKeyAdopted?.({
      userKey: read.userKey,
      latestEpochId: read.latestEpochId,
      descriptor: read.descriptor
    })
  }

  // 2b. The seal backstop: an ordinary rotation is the sealing append by
  // construction, but a rotation that no-op'd (the revoked client held no
  // current-epoch wrap -- an orphan client, or any re-run) appended nothing,
  // leaving the roster log's head anchored before the document edit. Sealing
  // is best-effort and reported, never thrown: the wallet IS disconnected
  // (stage 1 landed), and an unsealed log is durable state the login sweep
  // re-detects and finishes.
  let rosterSeal: RosterSealReport | undefined
  if (isSealableDescriptorStore(rosterStore)) {
    try {
      rosterSeal = { outcome: await rosterStore.seal() }
    } catch (err) {
      rosterSeal = { outcome: 'failed', error: err }
    }
  }

  // 3. The collection fan-out, in parallel -- run even when this call found
  // the roster already rotated (a re-run after a crash), because the staleness
  // rule finds exactly the stranded collections.
  const cascade = await cascadeCollectionsToUserKey({
    collectionIds: await collectionIdsOf({ collections }),
    storeFor: collections.storeFor,
    ...(collections.isEncrypted
      ? { isEncrypted: collections.isEncrypted }
      : {}),
    rosterDescriptor: read.descriptor,
    clientKeyAgreementKey,
    userKey: read.userKey
  })

  // 4. The recovery re-mints, while the registry is still readable under the
  // session's pre-adoption vault keys.
  const recovery = await remintRecoveryDelegations?.({ document: doc })

  if (read.rotated) {
    await onRotationAdopted?.({ userKey: read.userKey })
  }

  return {
    rotated: read.rotated,
    ...(rosterSeal ? { rosterSeal } : {}),
    collections: cascade,
    document: doc,
    userKey: read.userKey,
    rosterDescriptor: read.descriptor,
    ...(recovery ? { recovery } : {})
  }
}
