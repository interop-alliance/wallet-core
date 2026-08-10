/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The create-loss re-mint: the eager-minter half of the
 * descriptor-before-first-content-push ordering invariant.
 *
 * The invariant: a collection's encryption descriptor -- its key-epoch
 * roster -- is published before the collection's first content push, so no
 * envelope can reach the feed sealed under an epoch the published descriptor
 * does not carry. The engine enforces it structurally: `ensureProvisioned`
 * (which publishes the descriptor, create-if-absent) runs before every
 * cycle's migration sweep and push, so a lazy minter's envelopes are always
 * minted after the published descriptor has settled.
 *
 * An eager minter -- a replica that mints envelopes at local write time,
 * against a cached descriptor -- has one residual hole: envelopes minted
 * against a locally-minted epoch[0] while ANOTHER provisioner's descriptor
 * create won. At the next sync, provisioning adopts the winner's descriptor
 * (the create is compare-and-swap, never clobbering), leaving the pending
 * envelopes sealed under an epoch the published descriptor does not carry;
 * pushing them would land feed entries no other replica can route. The
 * remedy is {@link remintPendingEnvelopes}, run after adoption and before
 * the next push: each pending row the adopted cipher cannot route is
 * decrypted through the caller's stale-capable seam and re-encrypted under
 * the adopted descriptor's current epoch. This is legal exactly because a
 * pending row (dirty, never server-acked) has no feed existence -- envelope
 * immutability bites only once an envelope is ON the feed -- and the
 * re-encryption may therefore re-key the row (a content-derived id hashes
 * the ciphertext, so a re-mint mints a new id).
 */
import type { DocCipher, Json, SyncStore } from './types.js'
import { UnknownEpochError } from './types.js'

/**
 * Re-mints every pending (dirty, never-acked, live) row whose envelope the
 * given cipher cannot route to an epoch it knows -- the create-loss path for
 * an eager minter, run after adopting a published descriptor this client did
 * not install itself (`ensureWalletSpaceEpochs` reporting `installed: false`
 * on a collection it had already minted against) and before the next push.
 *
 * Each such row is decrypted through `decryptStale` (the pre-adoption cipher,
 * or a plaintext-projection read keyed by the row id), re-encrypted with
 * `cipher` (built from the adopted descriptor, so under its current epoch),
 * and handed to {@link SyncStore.replacePending} -- which may re-key the row,
 * since the re-mint is a fresh encryption. Rows already readable under the
 * adopted descriptor, acked rows (`version > 0` -- they HAVE feed existence
 * and are never re-minted), and tombstones are left untouched. A decrypt
 * failure other than an unknown epoch propagates: an envelope that is
 * corrupt, rather than merely minted under a losing epoch, is not this
 * helper's to settle.
 *
 * Idempotent: a re-run finds the re-minted rows readable and does nothing.
 *
 * @param options {object}
 * @param options.store {SyncStore}   must implement `replacePending`; its
 *   absence throws on the first row actually needing a re-mint (a lazy-minting
 *   consumer never does)
 * @param options.cipher {DocCipher}   built from the adopted (published)
 *   descriptor
 * @param options.decryptStale {function}   opens envelopes minted before the
 *   adoption; receives `{ id, envelope }` so a projection-backed caller can
 *   look the plaintext up by row id instead of decrypting
 * @param [options.signal] {AbortSignal}   checked between rows
 * @returns {Promise<{ pending: number; reminted: number }>}   pending live
 *   rows scanned, and how many were re-minted
 */
export async function remintPendingEnvelopes({
  store,
  cipher,
  decryptStale,
  signal
}: {
  store: SyncStore
  cipher: DocCipher
  decryptStale: (options: { id: string; envelope: Json }) => Promise<Json>
  signal?: AbortSignal
}): Promise<{ pending: number; reminted: number }> {
  const rows = await store.getDirtyRows()
  const pendingRows = rows.filter(
    row => !row.deleted && row.version === 0 && row.data !== null
  )
  let reminted = 0
  for (const row of pendingRows) {
    if (signal?.aborted) {
      break
    }
    const envelope = row.data as Json
    try {
      await cipher.decrypt({ envelope })
      continue
    } catch (err) {
      if (!(err instanceof UnknownEpochError)) {
        throw err
      }
    }
    if (!store.replacePending) {
      throw new Error(
        `Pending row "${row.id}" is sealed under an epoch the adopted ` +
          'descriptor does not carry, but this store implements no ' +
          '`replacePending`. An eager-minting replica must supply it so the ' +
          'create-loss re-mint can rewrite pre-feed envelopes.'
      )
    }
    const payload = await decryptStale({ id: row.id, envelope })
    const { id: newId, envelope: remintedEnvelope } = await cipher.encrypt({
      data: payload
    })
    await store.replacePending({
      id: row.id,
      newId,
      envelope: remintedEnvelope,
      ...(row.revision !== undefined && { revision: row.revision })
    })
    reminted += 1
  }
  return { pending: pendingRows.length, reminted }
}
