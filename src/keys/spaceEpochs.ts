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
 */
import type { WasClient } from '@interop/was-client'
import { ensureFirstEpoch } from '@interop/was-client/edv'

import { WALLET_SPACE_PROVISION_ROSTER } from '../space/collections.js'
import { userKeyAsRecipient } from './userKeyCascade.js'
import type { UserKey } from './userKey.js'

/**
 * Installs key epoch[0] on every encrypted collection of the wallet Space
 * roster (or on the given `collectionIds`), concurrently, wrapped to the user
 * key. Each install is `ensureFirstEpoch`: create-if-absent through the
 * descriptor-store seam, adopting (never overwriting) a roster another
 * provisioner already landed -- so re-running after a tear converges, and
 * exactly one epoch[0] ever exists per collection. Run it after
 * `provisionWalletSpace` has declared the collections; the wallet Space's
 * provisioning is complete only once both steps have.
 *
 * Run both steps from the sync engine's `ensureProvisioned` seam (or, for a
 * driver of its own, equally before the collection's first content push): the
 * descriptor-before-first-content-push invariant rests on it. A caller that
 * minted envelopes eagerly against a locally-minted roster and finds
 * `installed: false` here (another provisioner's create won) has adopted the
 * winner's descriptor and must re-mint its pending envelopes under that
 * descriptor's current epoch before pushing -- `remintPendingEnvelopes`
 * (`@interop/wallet-core/sync`) is that path.
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
 * @returns {Promise<Record<string, boolean>>}   per collection id, whether
 *   this call installed its epoch[0] (`false` means an existing roster was
 *   adopted)
 */
export async function ensureWalletSpaceEpochs({
  was,
  spaceId,
  userKey,
  collectionIds
}: {
  was: WasClient
  spaceId: string
  userKey: UserKey
  collectionIds?: string[]
}): Promise<Record<string, boolean>> {
  const ids =
    collectionIds ??
    WALLET_SPACE_PROVISION_ROSTER.filter(spec => spec.encryption === 'edv').map(
      spec => spec.collectionId
    )
  const installed: Record<string, boolean> = {}
  await Promise.all(
    ids.map(async collectionId => {
      try {
        const result = await ensureFirstEpoch({
          collection: was.space(spaceId).collection(collectionId),
          recipients: [userKeyAsRecipient({ userKey })]
        })
        installed[collectionId] = result.installed
      } catch (err) {
        throw new Error(
          `Error installing the first key epoch for collection ` +
            `"${collectionId}" in space "${spaceId}".`,
          { cause: err }
        )
      }
    })
  )
  return installed
}
