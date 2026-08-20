/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Provision-time key-epoch install for the wallet Space's encrypted
 * collections: every encrypted collection's descriptor carries an epoch roster
 * from birth (epoch[0] a fresh random epoch key, never a user-key generation),
 * and reads/writes are refused fail-closed until it does. `provisionWalletSpace`
 * (the crypto-free container ensure in `space`) declares the collections; this
 * EDV-bearing second step installs each one's epoch[0], wrapped to the user key
 * (recipient zero). It lives in `keys` rather than `space` so the root barrel,
 * which re-exports `space`, stays free of the EDV crypto graph -- the same
 * split was-client makes between `ensureSpaceAndCollection` and
 * `ensureFirstEpoch`.
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
import type {
  Collection,
  CollectionEncryption,
  IZcap,
  WasClient
} from '@interop/was-client'
import {
  ensureFirstEpoch,
  type RecipientPublicKey
} from '@interop/was-client/edv'

import { WALLET_SPACE_PROVISION_ROSTER } from '../space/collections.js'
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
}

/**
 * Installs key epoch[0] on a collection together with its blinded-index HMAC
 * key, so an encrypted collection is indexable at birth: the HMAC key is minted
 * alongside the epoch and wrapped to the same initial recipients.
 *
 * The blinded-index key is installed at provisioning or never. A collection
 * provisioned before blind-index support carries an epoch roster with no `hmac`
 * member, and asking for one there is refused (`EncryptionError`); such a
 * descriptor is adopted as-is rather than the refusal propagating, so a
 * pre-blind-index collection keeps working unindexed. Every other failure is
 * rethrown unchanged.
 *
 * @param options {object}
 * @param options.collection {Collection}   the (already declared encrypted)
 *   collection whose Description hosts the descriptor
 * @param options.recipients {RecipientPublicKey[]}   the initial readers'
 *   public key-agreement keys, recipients of epoch[0] and of the blinded-index
 *   key alike
 * @returns {Promise<{ descriptor: CollectionEncryption, installed: boolean }>}
 *   the collection's epoch-bearing descriptor, and whether this call installed
 *   its epoch[0]
 */
export async function ensureIndexedFirstEpoch({
  collection,
  recipients
}: {
  collection: Collection
  recipients: RecipientPublicKey[]
}): Promise<{ descriptor: CollectionEncryption; installed: boolean }> {
  try {
    return await ensureFirstEpoch({
      collection,
      recipients,
      blindedIndex: true
    })
  } catch (err) {
    // Errors cross package boundaries, so match the refusal on its stable
    // `name` rather than on `instanceof`.
    if ((err as Error).name !== 'EncryptionError') {
      throw err
    }
    return await ensureFirstEpoch({ collection, recipients })
  }
}

/**
 * Installs key epoch[0] on every encrypted collection of the wallet Space
 * roster (or on the given `collectionIds`), concurrently, wrapped to the user
 * key, each with its blinded-index HMAC key. Each install is
 * `ensureIndexedFirstEpoch`: create-if-absent through the
 * descriptor-store seam, adopting (never overwriting) a roster another
 * provisioner already landed -- so re-running after a tear converges, and
 * exactly one epoch[0] ever exists per collection. Run it after
 * `provisionWalletSpace` has declared the collections; the wallet Space's
 * provisioning is complete only once both steps have.
 *
 * Run both steps from the sync engine's `ensureProvisioned` seam (or, for a
 * driver of its own, equally before the collection's first content push): the
 * descriptor-before-first-content-push invariant rests on it.
 *
 * A collection that fails is reported in `failed` and the rest proceed, so a
 * transient failure on one collection never costs the caller the descriptors
 * the others just settled on. The caller decides what a failure means; a naive
 * full re-run converges, since the collections that did settle are adopted
 * untouched.
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
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.spaceId {string}
 * @param options.userKey {UserKey}   the account's user key, epoch[0]'s one
 *   initial recipient
 * @param [options.collectionIds] {string[]}   the encrypted collections to
 *   cover; defaults to the wallet Space roster's encrypted collections. A
 *   caller naming its own ids (e.g. `contacts`) must name only collections
 *   declared encrypted
 * @param [options.capability] {IZcap}   an invocation capability attached to
 *   every collection request (a delegated Space-subtree zcap -- the transient
 *   posture's generation delegation, for the tear heal on a promoted
 *   client-less account); absent, requests invoke the root capability
 * @returns {Promise<WalletSpaceEpochsResult>}   per collection id, the settled
 *   descriptor and whether this call installed its epoch[0] (`false` means an
 *   existing roster was adopted), plus the collections that failed
 */
export async function ensureWalletSpaceEpochs({
  was,
  spaceId,
  userKey,
  collectionIds,
  capability
}: {
  was: WasClient
  spaceId: string
  userKey: UserKey
  collectionIds?: string[]
  capability?: IZcap
}): Promise<WalletSpaceEpochsResult> {
  const ids =
    collectionIds ??
    WALLET_SPACE_PROVISION_ROSTER.filter(spec => spec.encryption === 'edv').map(
      spec => spec.collectionId
    )
  const outcomes: WalletSpaceEpochsResult['outcomes'] = {}
  const failed: Array<{ collectionId: string; error: unknown }> = []
  await Promise.all(
    ids.map(async collectionId => {
      try {
        const { installed, descriptor } = await ensureIndexedFirstEpoch({
          collection: was
            .space(spaceId, { capability })
            .collection(collectionId),
          recipients: [userKeyAsRecipient({ userKey })]
        })
        outcomes[collectionId] = { installed, descriptor }
      } catch (err) {
        failed.push({
          collectionId,
          error: new Error(
            `Error installing the first key epoch for collection ` +
              `"${collectionId}" in space "${spaceId}".`,
            { cause: err }
          )
        })
      }
    })
  )
  return { outcomes, failed }
}
