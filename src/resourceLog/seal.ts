/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The sealing sweep (App Connect spec `#log-authorization`): after a
 * controller-document edit removes a member's append authority, every
 * co-managed resource log must gain an entry anchored at (or past) the
 * post-removal document version -- the "sealing append" that proves the
 * surviving writers extended the log under the new membership. An ordinary
 * post-edit write (a roster rotation) is that append by construction; the gap
 * this module closes is the run where no such write happens -- a rotation
 * that no-ops because the retiree held no current-epoch wrap (an orphan
 * client, or any re-run), leaving the log's head still anchored pre-removal.
 *
 * Both halves are computed from durable state alone, keeping every cascade's
 * no-checkpoint convergence rule: the membership change is read off the
 * controller view (the latest version whose `assertionMethod` set lost a
 * member against its predecessor -- only assertion removals affect append
 * authority, so a spent recovery code's `keyAgreement`-only method never
 * registers here), and the log's side is the verified head's effective anchor
 * ({@link VerifiedResourceLog}`.headAnchorIndex`). "Sealed" is simply "head
 * anchor at or past the removal", so the backstop append is idempotent and a
 * torn sweep is finished by a naive re-run.
 */
import type { ResourceLogStore } from '@interop/was-client/log'
import { appendResourceLog, readResourceLog } from './append.js'
import type { ResourceLogController } from './controller.js'
import type { ResourceLogSigner } from './entry.js'
import type { ResourceLogPinStore } from './pin.js'
import type { VerifiedResourceLog } from './verify.js'

/**
 * The controller's latest membership change: the largest index into
 * `controller.versionIds` whose `assertionMethod` key set LOST a member
 * against its predecessor's, or `0` when no version ever removed one (the
 * genesis version has no predecessor and can never register as a removal, so
 * `0` doubles as "nothing to seal against" -- every anchor satisfies it). An
 * unversioned controller resolves `0` for the same reason: with no version
 * history there is no removal to locate.
 *
 * @param options {object}
 * @param options.controller {ResourceLogController}   the verified controller
 *   view
 * @returns {Promise<number>}
 */
export async function latestAssertionRemovalIndex({
  controller
}: {
  controller: ResourceLogController
}): Promise<number> {
  let removalIndex = 0
  let previous: Set<string> | null = null
  for (const [index, versionId] of controller.versionIds.entries()) {
    const keys = await controller.assertionKeysAt(versionId)
    if (previous !== null) {
      for (const key of previous) {
        if (!keys.has(key)) {
          removalIndex = index
          break
        }
      }
    }
    previous = keys
  }
  return removalIndex
}

/**
 * Seals one resource log against the controller's latest membership change,
 * idempotently: when the verified head already anchors at or past the latest
 * `assertionMethod` removal (or the controller never removed one, or the log
 * does not exist yet, or the controller is unversioned) nothing is written;
 * otherwise the head state is re-appended VERBATIM as a no-op entry whose
 * only job is its post-removal anchor -- ordinary entries may repeat state
 * (only terminal entries are state-constrained), so the resource itself is
 * untouched. A closed log that needs sealing propagates the append path's
 * `ResourceLogClosedError`.
 *
 * `sealed` reports whether this call found the log unsealed (and it now is,
 * by this call's append or a concurrent writer's -- the rebase hook converges
 * rather than duplicating); `verified` is the log as last verified, `null`
 * when it was never read (absent, or nothing to seal against).
 *
 * @param options {object}
 * @param options.store {ResourceLogStore}   the log's transport seam
 * @param options.controller {ResourceLogController}   the verified controller
 *   view
 * @param options.expectedMethod {string}   the format identifier expected
 * @param options.pinStore {ResourceLogPinStore}   this client's chain-head
 *   pin for this log
 * @param options.logId {string}   the pin-slot key for this log, from
 *   `resourceLogPinId`
 * @param options.signer {ResourceLogSigner}   this client's enrolled signing
 *   key
 * @param [options.versionTime] {string}   RFC3339 UTC; defaults to now
 * @param [options.verified] {VerifiedResourceLog}   a log view the caller
 *   verified moments ago (the most recent read or confirmed append on the same
 *   store), letting the sweep skip its own read. Staleness is safe in both
 *   directions: entry anchors are verifier-enforced monotone, so a stale head
 *   anchoring at or past the removal means the true head does too, and an
 *   unsealed verdict is re-checked by the append path's own read before
 *   anything is written
 * @returns {Promise<{ sealed: boolean, verified: VerifiedResourceLog | null }>}
 */
export async function sealResourceLog({
  store,
  controller,
  expectedMethod,
  pinStore,
  logId,
  signer,
  versionTime,
  verified: knownVerified
}: {
  store: ResourceLogStore
  controller: ResourceLogController
  expectedMethod: string
  pinStore: ResourceLogPinStore
  logId: string
  signer: ResourceLogSigner
  versionTime?: string
  verified?: VerifiedResourceLog
}): Promise<{ sealed: boolean; verified: VerifiedResourceLog | null }> {
  if (controller.versionIds.length === 0) {
    return { sealed: false, verified: null }
  }
  const removalIndex = await latestAssertionRemovalIndex({ controller })
  if (removalIndex === 0) {
    return { sealed: false, verified: knownVerified ?? null }
  }
  let verified = knownVerified ?? null
  if (verified === null) {
    const current = await readResourceLog({
      store,
      controller,
      expectedMethod,
      pinStore,
      logId
    })
    if (current === null) {
      return { sealed: false, verified: null }
    }
    verified = current.verified
  }
  if (
    verified.headAnchorIndex !== null &&
    verified.headAnchorIndex >= removalIndex
  ) {
    return { sealed: false, verified }
  }
  const confirmed = await appendResourceLog({
    store,
    controller,
    expectedMethod,
    pinStore,
    logId,
    signer,
    // The rebase hook doubles as the convergence check: a concurrent writer
    // whose entry already anchors past the removal sealed the log for us.
    buildState: rebased =>
      rebased.headAnchorIndex !== null &&
      rebased.headAnchorIndex >= removalIndex
        ? null
        : rebased.head.state,
    ...(versionTime === undefined ? {} : { versionTime })
  })
  return { sealed: true, verified: confirmed }
}
