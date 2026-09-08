/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Provision-time key-epoch install for the wallet Space's encrypted
 * collections: every encrypted collection's descriptor carries an epoch roster
 * from birth (epoch[0] a fresh random epoch key, never a user-key generation),
 * and reads/writes are refused fail-closed until it does.
 * `provisionWalletSpace` (the crypto-free container ensure in `space`) creates
 * the collections bare; this EDV-bearing second step is where each one is both
 * DECLARED encrypted and given its epoch[0], wrapped to the user key
 * (recipient zero). On a governed collection the install is the genesis of the
 * collection's own history log -- one guarded create whose head state is the
 * descriptor -- so the declaration and the first epoch land as one write. It
 * lives in `keys` rather than `space` so the root barrel, which re-exports
 * `space`, stays free of the EDV crypto graph -- the same split was-client
 * makes between `ensureSpaceAndCollection` and `ensureFirstEpoch`.
 *
 * The install is store-shaped rather than handle-shaped: the caller supplies
 * a `storeFor` lookup, exactly as the cascade's `CascadeCollections.storeFor`
 * does, so the same fan-out drives a log-governed store and a
 * Description-backed one with no branch here.
 *
 * The install is re-provisioning, never a content migration: `ensureFirstEpoch`
 * installs a fresh epoch[0] onto ANY epoch-less descriptor, with no check for
 * content already in the collection. So any resource sealed before epochs
 * existed -- straight to the user key's key-agreement key, in the shape that
 * predates the epoch roster -- stops being routable once epoch[0] lands
 * (`UnknownEpochError`), and nothing here re-seals it. That is deliberate:
 * epoch-less encrypted content only ever existed in pre-release accounts, whose
 * affected population is effectively zero, and re-provisioning from scratch is
 * the supported answer for them, as it is for a pre-release keyring or recovery
 * record.
 */
import type { CollectionEncryption, WasClient } from '@interop/was-client'
import {
  ensureFirstEpoch,
  type EncryptionDescriptorStore,
  type RecipientPublicKey
} from '@interop/was-client/edv'

import { isResourceLogRefusal } from '../resourceLog/errors.js'
import { encryptedWalletCollectionIds } from '../space/collections.js'
import { provisionWalletSpace } from '../space/provisioning.js'
import { userKeyAsRecipient } from './userKeyCascade.js'
import type { UserKey } from './userKey.js'

/**
 * What the epoch[0] fan-out did, per collection id: the settled epoch-bearing
 * descriptor of every collection that came through (with whether this call is
 * the one that installed it), and the per-collection failures the caller
 * surfaces -- one stuck collection never discards the others' outcomes.
 */
export interface WalletSpaceEpochsResult {
  outcomes: Record<
    string,
    { installed: boolean; descriptor: CollectionEncryption }
  >
  failed: Array<{ collectionId: string; error: unknown }>
  /**
   * Set when the fan-out was refused whole by the mint gate: the settled
   * user-key roster's current epoch is not the `userKey` the caller handed
   * in, so installing collection epochs under that key would strand them on
   * a key the roster does not deliver. Nothing was installed and `outcomes`
   * is empty. `rosterEpochId` is the roster's current epoch; it is absent
   * only on a malformed roster naming no epoch at all, which is refused
   * alike. The caller that recovers the roster's real key is the one
   * installer.
   */
  skipped?: { rosterEpochId?: string }
}

/**
 * Installs key epoch[0] on a collection together with its blinded-index HMAC
 * key, so an encrypted collection is indexable at birth: the HMAC key is minted
 * alongside the epoch and wrapped to the same initial recipients.
 *
 * On a log-governed store this install IS the collection's governing-log
 * genesis: the guarded create (`If-None-Match: *`) that both declares the
 * Collection governed and lands the first epoch. A re-run over a log that
 * already exists adopts its head untouched (`installed: false`), and a lost
 * create race resolves the winner's descriptor the same way, so exactly one
 * epoch[0] ever exists per collection.
 *
 * The blinded-index key is installed at provisioning or never. A collection
 * provisioned before blind-index support carries an epoch roster with no `hmac`
 * member, and asking for one there is refused (`EncryptionError`); such a
 * descriptor is adopted as-is rather than the refusal propagating, so a
 * pre-blind-index collection keeps working unindexed. Every other failure is
 * rethrown unchanged.
 *
 * @param options {object}
 * @param options.store {EncryptionDescriptorStore}   the collection's
 *   descriptor store -- the log-governed one
 *   (`collectionDescriptorLogStore`) on a governed collection
 * @param options.recipients {RecipientPublicKey[]}   the initial readers'
 *   public key-agreement keys, recipients of epoch[0] and of the blinded-index
 *   key alike
 * @returns {Promise<{ descriptor: CollectionEncryption, installed: boolean }>}
 *   the collection's epoch-bearing descriptor, and whether this call installed
 *   its epoch[0]
 */
export async function ensureIndexedFirstEpoch({
  store,
  recipients
}: {
  store: EncryptionDescriptorStore
  recipients: RecipientPublicKey[]
}): Promise<{ descriptor: CollectionEncryption; installed: boolean }> {
  try {
    return await ensureFirstEpoch({
      store,
      recipients,
      blindedIndex: true
    })
  } catch (err) {
    // Errors cross package boundaries, so match the refusal on its stable
    // `name` rather than on `instanceof`.
    if ((err as Error | null)?.name !== 'EncryptionError') {
      throw err
    }
    return await ensureFirstEpoch({ store, recipients })
  }
}

/**
 * Installs key epoch[0] on every encrypted collection of the wallet Space
 * roster (or on the given `collectionIds`), concurrently, wrapped to the user
 * key, each with its blinded-index HMAC key. Each install is
 * `ensureIndexedFirstEpoch`: create-if-absent through the
 * descriptor-store seam, adopting (never overwriting) a roster another
 * provisioner already landed -- so re-running after a tear converges, and
 * exactly one epoch[0] ever exists per collection. On a governed collection
 * that install is also the DECLARATION: the genesis of the collection's own
 * history log, from which the server derives its Description's `encryption`
 * member. Run it after `provisionWalletSpace` has created the collections;
 * the wallet Space's provisioning is complete only once both steps have.
 *
 * Run both steps from the sync engine's `ensureProvisioned` seam
 * ({@link walletSpaceProvisioner} builds that closure) or, for a driver of its
 * own, equally before the collection's first content push: the
 * descriptor-before-first-content-push invariant rests on it.
 *
 * A collection that fails is reported in `failed` and the rest proceed, so a
 * transient failure on one collection never costs the caller the descriptors
 * the others just settled on. The caller decides what a failure means; a naive
 * full re-run converges, since the collections that did settle are adopted
 * untouched.
 *
 * **A verified-log refusal is a failure entry, carried verbatim.** A
 * collection whose governing log is fabricated or forked
 * (`isResourceLogRefusal`: a `ResourceLogIntegrityError`, or a
 * `ResourceLogContinuityError` whose reason is not `rollback`) lands in
 * `failed` like any other collection, but its `error` is the refusal itself
 * rather than the wrapped per-collection message, so a caller reading the
 * report tells it by `err.name`. The fan-out never throws for it: the
 * collections that did settle are still reported (and still reach
 * `walletSpaceProvisioner`'s `onSettled`), and the geneses' resumable-success
 * contract holds. A retry against the same served log cannot help that one
 * collection, and the report says so.
 *
 * **Re-minting after adoption.** `installed: false` is not on its own the eager
 * minter's re-mint trigger: it is equally the steady state of every re-run,
 * where nothing changed. The returned `descriptor` is what matters -- an eager
 * minter (one that seals envelopes at local write time against a cached
 * descriptor) builds its cipher from the descriptor returned here, and re-mints
 * every pending envelope that cipher cannot route before pushing.
 * `remintPendingEnvelopes` (`@interop/wallet-core/sync`) is that path; it
 * decides per row from the envelope itself, so running it with the returned
 * descriptor's cipher on every run is both correct and (in the settled case)
 * free.
 *
 * **The mint gate.** Collection epochs install only under the key the user-key
 * roster delivers. A caller holding the settled roster descriptor passes it as
 * `rosterDescriptor`, and the fan-out is refused whole (`skipped`, nothing
 * written) when the roster's current epoch is not `userKey`: epoch[0] is
 * create-if-absent and every later ensure adopts it, so a collection installed
 * under a key the roster does not deliver -- a genesis re-run's throwaway
 * candidate over an adopted roster, a cached key the roster has rotated away
 * from -- is keyed to nothing, permanently. The gate lives here so every
 * installer runs the same test rather than re-deriving it. A caller without
 * the roster in hand (the sync engine's provisioner, whose user key is the one
 * login just adopted from the roster) runs ungated.
 *
 * @param options {object}
 * @param options.storeFor {function}   `(collectionId) =>
 *   EncryptionDescriptorStore` -- each collection's descriptor store, the
 *   same lookup shape the cascade's `CascadeCollections.storeFor` takes. The
 *   caller's wiring decides the authority every request rides and, on a
 *   governed collection, the log signer its genesis append is proved by
 * @param options.userKey {UserKey}   the account's user key, epoch[0]'s one
 *   initial recipient
 * @param [options.rosterDescriptor] {CollectionEncryption}   the settled
 *   user-key roster descriptor, when the caller holds it: the mint gate
 *   refuses the fan-out unless its current epoch IS `userKey`
 * @param [options.collectionIds] {string[]}   the encrypted collections to
 *   cover; defaults to the wallet Space roster's encrypted collections. A
 *   caller naming its own ids (e.g. `contacts`) must name only collections
 *   the wallet stores EDV envelopes in
 * @param [options.spaceId] {string}   the account Space id, named in the
 *   per-collection failure messages
 * @returns {Promise<WalletSpaceEpochsResult>}   per collection id, the settled
 *   descriptor and whether this call installed its epoch[0] (`false` means an
 *   existing roster was adopted), plus the collections that failed
 * @throws {TypeError}   when `storeFor` is not a function, before any write
 */
export async function ensureWalletSpaceEpochs({
  storeFor,
  userKey,
  rosterDescriptor,
  collectionIds,
  spaceId
}: {
  storeFor: (collectionId: string) => EncryptionDescriptorStore
  userKey: UserKey
  rosterDescriptor?: CollectionEncryption
  collectionIds?: string[]
  spaceId?: string
}): Promise<WalletSpaceEpochsResult> {
  assertStoreFor(storeFor)
  if (rosterDescriptor && rosterDescriptor.currentEpoch !== userKey.id) {
    return {
      outcomes: {},
      failed: [],
      skipped:
        rosterDescriptor.currentEpoch !== undefined
          ? { rosterEpochId: rosterDescriptor.currentEpoch }
          : {}
    }
  }
  const ids = collectionIds ?? encryptedWalletCollectionIds()
  const outcomes: WalletSpaceEpochsResult['outcomes'] = {}
  const failed: Array<{ collectionId: string; error: unknown }> = []
  await Promise.all(
    ids.map(async collectionId => {
      try {
        const { installed, descriptor } = await ensureIndexedFirstEpoch({
          store: storeFor(collectionId),
          recipients: [userKeyAsRecipient({ userKey })]
        })
        outcomes[collectionId] = { installed, descriptor }
      } catch (err) {
        if (isResourceLogRefusal(err)) {
          // Verbatim, so the report carries the refusal's own `name`.
          failed.push({ collectionId, error: err })
          return
        }
        failed.push({
          collectionId,
          error: new Error(
            `Error installing the first key epoch for collection ` +
              `"${collectionId}"` +
              (spaceId === undefined ? '' : ` in space "${spaceId}"`) +
              '.',
            { cause: err }
          )
        })
      }
    })
  )
  return { outcomes, failed }
}

/**
 * Refuses a missing store lookup with a synchronous `TypeError`, the way the
 * geneses and the mend refuse a missing `collectionStoreFor`: a caller on the
 * former handle-shaped signature would otherwise see every collection land in
 * `failed` and a resolving call, which an app that stamps its profile
 * provisioned on return would never re-run.
 *
 * @param storeFor {unknown}
 * @returns {void}
 */
function assertStoreFor(
  storeFor: unknown
): asserts storeFor is (collectionId: string) => EncryptionDescriptorStore {
  if (typeof storeFor !== 'function') {
    throw new TypeError(
      'ensureWalletSpaceEpochs requires storeFor: ' +
        '(collectionId) => EncryptionDescriptorStore, each encrypted ' +
        "collection's descriptor store."
    )
  }
}

/**
 * Thrown by a {@link walletSpaceProvisioner} closure when the epoch[0] install
 * left any collection behind: the collections that did settle are adopted, and
 * the throw keeps the sync engine from memoizing a torn provisioning, so the
 * next cycle re-runs it and converges.
 */
export class WalletSpaceProvisioningError extends Error {
  failed: WalletSpaceEpochsResult['failed']
  constructor({ failed }: { failed: WalletSpaceEpochsResult['failed'] }) {
    super(
      `Wallet Space provisioning left ${failed.length} collection(s) ` +
        `without their first key epoch: ` +
        failed.map(entry => `"${entry.collectionId}"`).join(', ') +
        '.'
    )
    this.name = 'WalletSpaceProvisioningError'
    this.failed = failed
  }
}

/**
 * Builds the sync engine's `ensureProvisioned` closure for a wallet Space: the
 * provisioning two-step as one call -- `provisionWalletSpace` creates the
 * roster's collections, then {@link ensureWalletSpaceEpochs} declares each
 * encrypted one and installs its epoch[0] -- with the memoization the engine
 * adds on top.
 *
 * The closure is single-flight: one app runs one engine per synced
 * collection, and every engine's first cycle asks for the same provisioning,
 * so concurrent calls share one in-flight run instead of racing the same
 * create-if-absent writes. A run that leaves a collection without its epoch
 * throws {@link WalletSpaceProvisioningError} naming the collections, so the
 * engine does not memoize it and the next cycle re-runs it; the collections
 * that did settle are adopted untouched by that re-run.
 *
 * The optional `onSettled` hook receives every run's epoch report, a partial
 * one included, BEFORE the refusal above: a transient failure on one
 * collection never costs the caller the descriptors the others settled on,
 * the property the epoch install itself keeps. That report is what an eager
 * minter builds its cipher from: the returned descriptors are the settled
 * ones, adopted or installed, and the engine's `remintPending` seam then
 * re-mints whatever that cipher cannot route.
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.spaceId {string}
 * @param options.controllerDid {string}   the Space controller, used only when
 *   the Space does not exist yet
 * @param options.userKey {UserKey}   the account's user key, epoch[0]'s one
 *   initial recipient
 * @param options.storeFor {function}   `(collectionId) =>
 *   EncryptionDescriptorStore` -- each encrypted collection's descriptor
 *   store, threaded to {@link ensureWalletSpaceEpochs}
 * @param [options.collectionIds] {string[]}   the encrypted collections to
 *   cover; defaults to the wallet Space roster's encrypted collections
 * @param [options.onSettled] {function}
 *   `(result: WalletSpaceEpochsResult) => void | Promise<void>`, called after
 *   each run's epoch install with its report, before a partial run's refusal
 * @returns {() => Promise<void>}   the engine's `ensureProvisioned` seam
 */
export function walletSpaceProvisioner({
  was,
  spaceId,
  controllerDid,
  userKey,
  storeFor,
  collectionIds,
  onSettled
}: {
  was: WasClient
  spaceId: string
  controllerDid: string
  userKey: UserKey
  storeFor: (collectionId: string) => EncryptionDescriptorStore
  collectionIds?: string[]
  onSettled?: (result: WalletSpaceEpochsResult) => void | Promise<void>
}): () => Promise<void> {
  assertStoreFor(storeFor)
  let inFlight: Promise<void> | null = null
  const run = async (): Promise<void> => {
    await provisionWalletSpace({ was, spaceId, controllerDid })
    const result = await ensureWalletSpaceEpochs({
      storeFor,
      userKey,
      spaceId,
      collectionIds
    })
    await onSettled?.(result)
    if (result.failed.length > 0) {
      throw new WalletSpaceProvisioningError({ failed: result.failed })
    }
  }
  return async () => {
    if (inFlight === null) {
      inFlight = run().finally(() => {
        inFlight = null
      })
    }
    return inFlight
  }
}
