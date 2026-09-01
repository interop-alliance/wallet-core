/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The read-side classification of what an injected `DocCipher` throws when it
 * cannot open an envelope.
 *
 * A decrypt has two distinguishable no-key outcomes, and a host that scans
 * rows must tell them apart: an epoch the descriptor this reader holds does
 * not list at all (`UnknownEpochError` -- possibly fresh data behind a stale
 * descriptor, so a re-read may fix it), and an epoch the descriptor does list
 * but this reader holds no key for (`KeyUnwrapError` -- real data, and
 * permanently unreadable here, since re-reading the same descriptor cannot
 * produce a key the reader was not given). Neither is corruption, so neither
 * row may be treated as garbage.
 *
 * Both are matched on `err.name`, never `instanceof`: the cipher is an
 * injected seam, and in a wallet whose `@interop/was-client` resolves to a
 * second copy (a `link:` dev setup, a dedupe miss through a dependency tree)
 * the class the cipher throws is not the class the caller imported. The cost
 * of the miss lands on real data -- a scan that misses `KeyUnwrapError` drops
 * the row into its undecryptable bucket, which a host is entitled to purge.
 * Both classes assign their `name` explicitly, which is what makes the string
 * a contract.
 *
 * The unknown-epoch half of the pair ships from `@interop/wallet-core/sync`
 * as `isUnknownEpochError`: the create-loss re-mint dispatches on it, and
 * `sync` deliberately imports nothing else in this library. This file is the
 * home of the other half, beside the cipher that raises it, and stays
 * import-free for the same reason `resourceLog/errors.ts` does.
 */

/**
 * Whether an error is the cipher's not-a-recipient signal (`KeyUnwrapError`):
 * the envelope's epoch IS on the descriptor this reader holds, but the reader
 * has no key for it -- never a recipient of that epoch, or removed and the
 * epoch rotated since. Real data, unreadable by this wallet, and never
 * garbage: a caller skips such a row and leaves it in place.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
export function isKeyUnwrapError(err: unknown): boolean {
  return (err as { name?: unknown } | null)?.name === 'KeyUnwrapError'
}
