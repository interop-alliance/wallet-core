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
 * How many full re-mint passes are attempted before giving up. A pass that
 * ends with skipped rows (a local write bumped a row's revision between the
 * snapshot and the replace) re-snapshots and retries only what is still
 * unroutable; the bound keeps a hot-writing row from livelocking the pass.
 */
const MAX_REMINT_ATTEMPTS = 5

/**
 * Re-mints every pending (dirty, never-acked, live) row whose envelope the
 * given cipher cannot route to an epoch it knows -- the create-loss path for
 * an eager minter, run after adopting a published descriptor this client did
 * not install itself (`ensureWalletSpaceEpochs` returning an adopted
 * descriptor for a collection it had already minted against; the envelope, not
 * the `installed` flag, decides per row) and before the next push.
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
 * A replace the store SKIPS (`{ applied: false }` -- a local write bumped the
 * row's revision between the snapshot and the replace, so the row now holds a
 * body this pass never saw) is not counted as re-minted: the whole pass
 * re-snapshots and re-probes, settling the row under its fresh revision. Only
 * rows still unroutable are re-processed; the retry is bounded by
 * {@link MAX_REMINT_ATTEMPTS}, and a pass that exhausts the bound throws
 * rather than returning -- a row left sealed under the losing epoch MUST NOT
 * be pushed, since it would land on the feed as a permanently unroutable
 * entry.
 *
 * The store parameter is narrowed to one that implements `replacePending`
 * (optional on {@link SyncStore} itself, since a lazy-minting consumer never
 * re-mints): the requirement is a compile-time one, not a runtime throw.
 *
 * Idempotent: a re-run finds the re-minted rows readable and does nothing.
 *
 * @param options {object}
 * @param options.store {SyncStore}   must implement `replacePending`
 * @param options.cipher {DocCipher}   built from the adopted (published)
 *   descriptor
 * @param options.decryptStale {function}   opens envelopes minted before the
 *   adoption; receives `{ id, envelope }` so a projection-backed caller can
 *   look the plaintext up by row id instead of decrypting
 * @param [options.signal] {AbortSignal}   checked between rows
 * @returns {Promise<{ pending: number; reminted: number }>}   pending live
 *   rows the first pass scanned, and how many rows were re-minted (applied
 *   replaces only, across all passes)
 */
export async function remintPendingEnvelopes({
  store,
  cipher,
  decryptStale,
  signal
}: {
  store: SyncStore & {
    replacePending: NonNullable<SyncStore['replacePending']>
  }
  cipher: DocCipher
  decryptStale: (options: { id: string; envelope: Json }) => Promise<Json>
  signal?: AbortSignal
}): Promise<{ pending: number; reminted: number }> {
  let pending: number | undefined
  let reminted = 0
  let skipped: string[] = []

  for (let attempt = 0; attempt < MAX_REMINT_ATTEMPTS; attempt += 1) {
    if (signal?.aborted) {
      break
    }
    const rows = await store.getDirtyRows()
    const pendingRows = rows.filter(
      row => !row.deleted && row.version === 0 && row.data !== null
    )
    pending ??= pendingRows.length
    skipped = []

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
      const payload = await decryptStale({ id: row.id, envelope })
      const { id: newId, envelope: remintedEnvelope } = await cipher.encrypt({
        data: payload
      })
      const { applied } = await store.replacePending({
        id: row.id,
        newId,
        envelope: remintedEnvelope,
        ...(row.revision !== undefined && { revision: row.revision })
      })
      if (applied) {
        reminted += 1
      } else {
        skipped.push(row.id)
      }
    }

    if (skipped.length === 0 || signal?.aborted) {
      break
    }
  }

  if (skipped.length > 0 && !signal?.aborted) {
    throw new Error(
      `Re-mint gave up after ${MAX_REMINT_ATTEMPTS} attempts: pending ` +
        `row(s) ${skipped.join(', ')} kept being rewritten locally and are ` +
        'still sealed under an epoch the adopted descriptor does not carry. ' +
        'They must not be pushed; re-run the re-mint once local writes settle.'
    )
  }
  return { pending: pending ?? 0, reminted }
}
