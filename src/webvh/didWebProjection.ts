/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `did:web` projection of the account log: `id/did.json`, the document
 * `generateParallelDidWeb` derives from the resolved `did.jsonl`. The log is
 * the source of truth and the projection a derived cache, so this module owns
 * the two ways that cache is written -- the unconditional PUT every publish
 * tail makes ({@link putDidWebProjection}) and the read-then-write freshness
 * ensure a caller with no controller authority makes
 * ({@link ensureDidWebProjection}).
 *
 * The ensure exists because the projection is NOT republished by every entry.
 * A ladder-signed entry publishes through `publishEntryPinned`, which writes
 * `did.jsonl` alone: the bridge delegation a standing unlock credential
 * carries is a PUT on exactly that resource. So after a ladder-signed removal
 * or retirement (the last-client transition, a transient recovery) the served
 * projection can still publish a verification method the log has struck, and
 * a `did:web` resolver reading it accepts a key the account revoked. The
 * account's own WAS authorization is unaffected -- the server resolves the
 * controller out of `did.jsonl` and never reads `did.json` -- so this is a
 * `did:web` verifier concern rather than a storage one, but it is a
 * revocation bypass all the same.
 *
 * A transient visit closes it with no server change and no widened bridge:
 * its generation delegation targets the account Space's items subtree, which
 * covers `id/did.json`, so the visit invokes as its annex verification method
 * and republishes the projection itself. The ensure is deliberately a
 * compare-then-write rather than the publish tails' unconditional PUT,
 * because it runs on every visit rather than behind a won log
 * compare-and-swap: a healthy account must cost one GET and no write.
 *
 * The compare's input is a document the caller resolved earlier, so a
 * difference alone does not say which side is stale. Another client may have
 * published an inventory-removing entry and its correct projection in the
 * meantime, and writing the caller's older derivation over it would restore a
 * key the account just struck. Two guards keep that from happening. The
 * caller may hand in a `refresh` that re-resolves the log, and the write runs
 * only when the refreshed derivation still differs. And the PUT is a
 * compare-and-swap on the ETag of the read it was based on, so a projection
 * written between that read and the PUT stands and the ensure reports
 * `conflict` instead. The next visit is the mender in both cases.
 *
 * No wire artifact of its own: the resource id, the content type, and the
 * document shape are the ones `publishWebvhLog` already writes.
 */
import type { DIDDoc } from '@interop/did-method-webvh'
import { generateParallelDidWeb } from '@interop/did-method-webvh'
import { DID_DOCUMENT_RESOURCE } from '../space/collections.js'
import type { WebvhIdStore } from './didWebvh.js'

/**
 * Writes the `did:web` projection into the `id` collection: `did.json`, under
 * the `application/did+json` content type. The single PUT site, so the
 * resource id and content type cannot drift between the publish tails and the
 * freshness ensure.
 *
 * Unconditional by design at every publish-tail caller: the write is
 * serialized behind a won `did.jsonl` compare-and-swap, and the projection is
 * a derived cache of a log that is itself the source of truth.
 *
 * @param options {object}
 * @param options.store {object}   anything with the seam's `putIdResource`
 * @param options.webDoc {object}   the projection to publish, from
 *   `generateParallelDidWeb` (or `updateDID`'s `webDoc`, which is the same
 *   document)
 * @returns {Promise<void>}
 */
export async function putDidWebProjection({
  store,
  webDoc
}: {
  store: Pick<WebvhIdStore, 'putIdResource'>
  webDoc: object
}): Promise<void> {
  await store.putIdResource({
    resourceId: DID_DOCUMENT_RESOURCE,
    content: webDoc,
    contentType: 'application/did+json'
  })
}

/**
 * The error name a lost write precondition surfaces as -- was-client's
 * `PreconditionFailedError`, and whatever an alternative store implementation
 * throws under that name (the `WebvhIdStore` seam contract requires it).
 */
const PRECONDITION_FAILED_ERROR_NAME = 'PreconditionFailedError'

/**
 * THE PROJECTION FRESHNESS ENSURE: re-derives `did.json` from a resolved log's
 * DID and document, compares it against what the host serves, and republishes
 * only on a difference. The credential-only mender for a projection a
 * ladder-signed entry left behind (see the module doc): a transient visit runs
 * it through a store bound to its generation delegation, which covers the
 * account Space's items subtree and so may write `id/did.json` with no
 * widened bridge and no server change.
 *
 * The served document is compared as parsed JSON, key-order-insensitively, so
 * a host (or an earlier writer) that reserialized the same document does not
 * provoke a write. Absent, unparsable, and different all reach the write; only
 * an equal document is left alone.
 *
 * A difference is not by itself evidence that the served projection is the
 * stale side. The caller's `doc` was resolved at some earlier point, and a
 * concurrent writer may have published a newer log entry with its matching
 * projection since. Two guards keep this call from undoing that writer's work:
 *
 * 1. `refresh`, when supplied, re-resolves the log on the difference path.
 *    The write runs only when the derivation from the refreshed document
 *    still differs from what is served, so one extra read buys the ordering
 *    the plain compare cannot see.
 * 2. The PUT is conditional on the served read: `If-Match` on its ETag, or
 *    `If-None-Match: *` when the projection was absent. A projection written
 *    between the read and the PUT wins, and the outcome is `conflict`.
 *
 * Read and write errors PROPAGATE, a failed precondition excepted. The call is
 * one step of a login or a ceremony that has other work to do, and whether a
 * stale projection is worth failing that work over is the caller's decision,
 * not this function's -- every caller today treats it as best-effort.
 *
 * @param options {object}
 * @param options.store {object}   the narrow id-collection seam: the raw read
 *   plus the write (`Pick<WebvhIdStore, 'getIdResourceRaw' | 'putIdResource'>`,
 *   which `wasWebvhIdStore` and `delegatedWebvhLogStore` both satisfy). The
 *   read may be unauthenticated, the `id` collection being world-readable
 * @param options.did {string}   the account's did:webvh, from the resolved log
 * @param options.doc {DIDDoc}   the resolved did:webvh document
 * @param [options.refresh] {Function}   `() => Promise<{ did, doc }>`, a fresh
 *   resolution of the same log, called at most once and only on a detected
 *   difference. Its result replaces `did` / `doc` for the re-compare and for
 *   the write. Omitted, the caller's snapshot is written on any difference
 * @returns {Promise<{ outcome: 'current' | 'republished' | 'conflict' }>}
 *   `current` when the served projection already matched (before or after the
 *   refresh) and nothing was written; `republished` when the PUT landed;
 *   `conflict` when it lost its precondition to a concurrent writer, whose
 *   projection stands and whose successor visit is the mender
 */
export async function ensureDidWebProjection({
  store,
  did,
  doc,
  refresh
}: {
  store: Pick<WebvhIdStore, 'getIdResourceRaw' | 'putIdResource'>
  did: string
  doc: DIDDoc
  refresh?: () => Promise<{ did: string; doc: DIDDoc }>
}): Promise<{ outcome: 'current' | 'republished' | 'conflict' }> {
  const served = await store.getIdResourceRaw({
    resourceId: DID_DOCUMENT_RESOURCE
  })
  let expected = generateParallelDidWeb(did, doc)
  if (served !== undefined && servedMatches({ text: served.text, expected })) {
    return { outcome: 'current' }
  }
  if (refresh) {
    const fresh = await refresh()
    expected = generateParallelDidWeb(fresh.did, fresh.doc)
    if (
      served !== undefined &&
      servedMatches({ text: served.text, expected })
    ) {
      return { outcome: 'current' }
    }
  }
  try {
    await store.putIdResource({
      resourceId: DID_DOCUMENT_RESOURCE,
      content: expected,
      contentType: 'application/did+json',
      // Absent, the write is a create; present, an update-if-unchanged. A
      // backend serving no ETag versions nothing, so that write degrades to
      // an unconditional one, as every other publish here does.
      ...(served === undefined
        ? { ifNoneMatch: true }
        : served.etag !== undefined
          ? { ifMatch: served.etag }
          : {})
    })
  } catch (err) {
    // Matched by name: error classes do not survive crossing package copies,
    // and the seam contract names the `name` rather than the class.
    if ((err as Error)?.name !== PRECONDITION_FAILED_ERROR_NAME) {
      throw err
    }
    return { outcome: 'conflict' }
  }
  return { outcome: 'republished' }
}

/**
 * Whether the served projection text is the expected document. An unparsable
 * body reads as a mismatch rather than an error: whatever it is, it is not the
 * projection, and republishing is the answer either way.
 *
 * The expected document is round-tripped through JSON before the comparison,
 * so it is compared in the form the PUT would serialize it into -- a member
 * whose value is `undefined` disappears on both sides rather than reading as a
 * difference the write could never fix.
 *
 * @param options {object}
 * @param options.text {string}   the served body
 * @param options.expected {object}   the freshly derived projection
 * @returns {boolean}
 */
function servedMatches({
  text,
  expected
}: {
  text: string
  expected: object
}): boolean {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    return false
  }
  return sameJsonValue(JSON.parse(JSON.stringify(expected)), parsed)
}

/**
 * Structural JSON equality: object key order is immaterial, array order is
 * not. Used to decide whether the projection needs republishing, so a false
 * negative costs one idempotent PUT and a false positive would leave a stale
 * document standing -- which is why it compares recursively rather than by
 * serialized string.
 *
 * @param left {unknown}
 * @param right {unknown}
 * @returns {boolean}
 */
function sameJsonValue(left: unknown, right: unknown): boolean {
  if (left === right) {
    return true
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right)) {
      return false
    }
    return (
      left.length === right.length &&
      left.every((member, index) => sameJsonValue(member, right[index]))
    )
  }
  if (
    typeof left !== 'object' ||
    typeof right !== 'object' ||
    left === null ||
    right === null
  ) {
    return false
  }
  const leftEntries = Object.entries(left as Record<string, unknown>)
  const rightRecord = right as Record<string, unknown>
  return (
    leftEntries.length === Object.keys(rightRecord).length &&
    leftEntries.every(
      ([key, value]) =>
        Object.prototype.hasOwnProperty.call(rightRecord, key) &&
        sameJsonValue(value, rightRecord[key])
    )
  )
}
