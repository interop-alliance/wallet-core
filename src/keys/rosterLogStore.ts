/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The log-governed descriptor store: was-client's generic
 * `logGovernedDescriptorStore` (reads resolve to the VERIFIED head entry's
 * state, writes become signed log appends, a lost race is the
 * `PreconditionFailedError` the recipient loops rebase on, and `seal()` is
 * the sealing sweep) wrapped with the two things the wallet adds, the
 * post-edit minimum controller version and the log's CLASS.
 *
 * The class is stated once, at construction, and the store applies it to
 * every controller view it resolves (`controllerForLogClass`), so both the
 * read-side verification and every append run under the rule the log's class
 * names -- the ceremony-tail license for the user key roster log,
 * `assertionMethod` membership alone for a per-collection encryption
 * descriptor log. Parameterizing the admission rule here is what keeps a
 * call site from exempting itself: a store cannot be built without saying
 * which class of log it governs.
 *
 * This is the enforcement point for "roster state is adopted only from a
 * verified log head": there is no read path around the verifier, and the
 * retired detached `epochsSig` has no successor to check -- the entry
 * proof's controller versionId in the did:webvh document took over its job
 * wholesale.
 *
 * The store is {@link SealableEncryptionDescriptorStore}: `seal()` exposes
 * the resource-log sealing sweep through the descriptor-store seam, so the
 * ceremonies and the login sweep can close the one durable gap the recipient
 * machinery leaves -- a rotation that no-ops (the retiree held no
 * current-epoch wrap) appends nothing, leaving the log's head carrying a
 * controller version before the membership change it should have sealed.
 */
import {
  logGovernedDescriptorStore as wasLogGovernedDescriptorStore,
  EPOCH_CONFIGURATION_STATE_TYPE,
  type EncryptionDescriptorStore
} from '@interop/was-client/edv'
import type {
  ResourceLogPinStore,
  ResourceLogSigner,
  ResourceLogStore
} from '@interop/vh-resource-log'
import {
  controllerForLogClass,
  type ResourceLogClass,
  type WebvhResourceLogController
} from '../resourceLog/index.js'

export { EPOCH_CONFIGURATION_STATE_TYPE }

/**
 * An `EncryptionDescriptorStore` whose resource is governed by a resource
 * log, and can therefore be SEALED: `seal()` runs the sealing sweep
 * (`sealResourceLog`) against the caller's currently verified controller
 * view, appending the idempotent no-op backstop entry when the log's head
 * still carries a controller version before the controller's latest
 * membership change -- `'sealed'` -- and writing nothing when the log is
 * already sealed, absent, or has no membership change to seal against --
 * `'noop'`.
 *
 * `setMinimumControllerVersion()` is the post-edit freshness contract: a
 * ceremony that just extended the account log (a revocation about to rotate
 * the roster, a ladder-signed enrollment approval about to escrow) hands the
 * store the controller view built from that post-edit log, and the store's
 * subsequent operations never resolve to anything staler. The injected
 * `resolveController` still wins whenever it is at or past the minimum (it
 * may be fresher -- a concurrent enrollment), so the minimum supersedes only
 * a stale cached view, which would otherwise anchor the append before the
 * edit: a rotation that leaves the log unsealed with the seal backstop blind
 * to the removal, or a ladder-signed escrow the license refuses.
 */
export interface SealableEncryptionDescriptorStore extends EncryptionDescriptorStore {
  seal(): Promise<'sealed' | 'noop'>
  setMinimumControllerVersion(options: {
    controller: WebvhResourceLogController
  }): void
}

/**
 * Whether a descriptor store is log-governed and sealable -- the guard the
 * ceremonies and sweeps use to run the seal backstop only where a governing
 * log exists (an ordinary Collection-Description-backed store has nothing to
 * seal). Both members of the interface are probed, since the cascade tail's
 * anchoring preamble relies on the second: a store decorated down to `seal`
 * alone would otherwise pass as anchorable and never be anchored.
 *
 * @param store {EncryptionDescriptorStore}
 * @returns {boolean}
 */
export function isSealableDescriptorStore(
  store: EncryptionDescriptorStore
): store is SealableEncryptionDescriptorStore {
  const candidate = store as Partial<SealableEncryptionDescriptorStore>
  return (
    typeof candidate.seal === 'function' &&
    typeof candidate.setMinimumControllerVersion === 'function'
  )
}

/**
 * Builds the log-governed `EncryptionDescriptorStore`.
 *
 * The controller view is resolved per operation (never held), so a caller
 * that just edited the account document -- a revocation about to rotate the
 * roster -- writes entries carrying the post-edit head it now verifies,
 * which is exactly what makes its rotation the sealing append. The revocation
 * orchestrator does not leave that freshness to the injected resolver's
 * wiring: it calls `setMinimumControllerVersion` with the view built from the edit's
 * own post-edit log, and a resolver still serving a stale cached view is
 * superseded by it (see the interface doc). Whichever view wins, the store
 * hands it out under its own log class's admission rule, so a minimum
 * version set by a ceremony cannot smuggle in another class's rule.
 *
 * @param options {object}
 * @param options.log {ResourceLogStore}   the log's transport seam
 * @param options.resolveController {function}
 *   `() => Promise<WebvhResourceLogController>` -- the caller's currently
 *   verified controller view (`webvhResourceLogController` over a
 *   `verifyAccountLog` result)
 * @param options.pinStore {ResourceLogPinStore}   this client's chain-head pin
 *   for this log
 * @param options.logId {string}   the pin-slot key for this log, from
 *   `resourceLogPinId`
 * @param options.signer {ResourceLogSigner}   this client's enrolled signing
 *   key, for the appends this store writes
 * @param options.logClass {ResourceLogClass}   which class of log this store
 *   governs, which is what decides the admission rule its ladder-signed
 *   appends run under
 * @returns {SealableEncryptionDescriptorStore}
 */
export function logGovernedDescriptorStore({
  log,
  resolveController,
  pinStore,
  logId,
  signer,
  logClass
}: {
  log: ResourceLogStore
  resolveController: () => Promise<WebvhResourceLogController>
  pinStore: ResourceLogPinStore
  logId: string
  signer: ResourceLogSigner
  logClass: ResourceLogClass
}): SealableEncryptionDescriptorStore {
  // The minimum controller version a post-edit ceremony set (see the
  // interface doc).
  let minimumControllerVersion: WebvhResourceLogController | null = null

  /**
   * The view every operation runs under: the freshest of the resolved and
   * minimum views, narrowed to this store's log class.
   *
   * @returns {Promise<WebvhResourceLogController>}
   */
  async function currentController(): Promise<WebvhResourceLogController> {
    return controllerForLogClass({
      controller: await resolvedController(),
      logClass
    })
  }

  /**
   * The freshness half: the injected resolver's view, superseded by the
   * minimum a post-edit ceremony set when the resolver is behind it.
   *
   * @returns {Promise<WebvhResourceLogController>}
   */
  async function resolvedController(): Promise<WebvhResourceLogController> {
    const resolved = await resolveController()
    if (minimumControllerVersion === null) {
      return resolved
    }
    const minimumHead =
      minimumControllerVersion.versionIds[
        minimumControllerVersion.versionIds.length - 1
      ]
    // A resolved view carrying the minimum's head version is at or past it
    // (the controller-log version list is append-only) and wins; one that
    // does not is a stale cache the minimum supersedes.
    if (
      minimumHead !== undefined &&
      !resolved.versionIds.includes(minimumHead)
    ) {
      return minimumControllerVersion
    }
    return resolved
  }

  const store = wasLogGovernedDescriptorStore({
    log,
    resolveController: currentController,
    pinStore,
    logId,
    signer
  })

  return {
    ...store,
    setMinimumControllerVersion({ controller }) {
      minimumControllerVersion = controller
    }
  }
}
