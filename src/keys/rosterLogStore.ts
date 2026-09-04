/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The log-governed descriptor store: an `EncryptionDescriptorStore` whose
 * resource is governed by a resource log (the Resource Log Profile). Reads
 * resolve to the VERIFIED head entry's state -- chain, proofs, external
 * authorization, and the chain-head pin all checked before any descriptor is
 * handed out -- and writes become signed log appends. Because the seam is
 * unchanged, all of
 * was-client's roster machinery (`initRecipients` / `addRecipient` /
 * `removeRecipient`, with their compare-and-swap retry loops) drives the log
 * without knowing it: a CAS conflict on the log (the library's
 * `ResourceLogConflictError`, minted by the store adapter) is translated
 * back to the `PreconditionFailedError` those loops already rebase on, at
 * this boundary -- the `EncryptionDescriptorStore` port documents that
 * class, and was-client's edv recipient loops match on it.
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
  PreconditionFailedError,
  type CollectionEncryption
} from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import { RESOURCE_LOG_METHOD } from '@interop/storage-core'
import {
  buildResourceLogEntry,
  buildResourceLogGenesis,
  confirmAppend,
  isResourceLogConflictError,
  ResourceLogClosedError,
  sealResourceLog,
  verifyResourceLog,
  verifyResourceLogAppend,
  type ResourceLogPinStore,
  type ResourceLogSigner,
  type ResourceLogStore,
  type VerifiedResourceLog
} from '@interop/vh-resource-log'
import type { WebvhResourceLogController } from '../resourceLog/index.js'
import {
  EPOCH_CONFIGURATION_STATE_TYPE,
  readGovernedEpochConfiguration
} from '../descriptors/logSource.js'

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
 * Translates the log-store port's CAS conflict (the library's
 * `ResourceLogConflictError`, matched by `name` -- it is minted in the store
 * adapter's package, which may resolve its own library copy) into the
 * `PreconditionFailedError` the `EncryptionDescriptorStore` port documents
 * and was-client's edv recipient loops rebase on. Any other error -- an
 * untranslated `PreconditionFailedError` included -- returns unchanged.
 *
 * @param err {unknown}
 * @returns {unknown}   the error to rethrow
 */
function asDescriptorStoreConflict(err: unknown): unknown {
  if (isResourceLogConflictError(err)) {
    return new PreconditionFailedError((err as Error).message, {
      status: 412,
      cause: err
    })
  }
  return err
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
 * superseded by it (see the interface doc).
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
 * @returns {SealableEncryptionDescriptorStore}
 */
export function logGovernedDescriptorStore({
  log,
  resolveController,
  pinStore,
  logId,
  signer
}: {
  log: ResourceLogStore
  resolveController: () => Promise<WebvhResourceLogController>
  pinStore: ResourceLogPinStore
  logId: string
  signer: ResourceLogSigner
}): SealableEncryptionDescriptorStore {
  // The verified log observed by the most recent read on this store instance;
  // a replace builds its entry on that head, pinned to the same read's etag,
  // so a stale head loses the CAS instead of forking.
  let lastVerified: VerifiedResourceLog | null = null
  // The controller view `lastVerified` was verified under: the library's
  // pre-write pass reads the head's controller version as an index into
  // THAT view's version list, so a replace may only run it against a view
  // this one is a prefix of.
  let lastVerifiedView: WebvhResourceLogController | null = null

  // The minimum controller version a post-edit ceremony set (see the
  // interface doc).
  let minimumControllerVersion: WebvhResourceLogController | null = null

  async function currentController(): Promise<WebvhResourceLogController> {
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

  function toState(
    descriptor: CollectionEncryption
  ): CollectionEncryption & { type: string } {
    const { history: _history, ...rest } = descriptor
    return { ...rest, type: EPOCH_CONFIGURATION_STATE_TYPE }
  }

  async function settle({
    entry,
    controller
  }: {
    entry: Parameters<typeof confirmAppend>[0]['entry']
    controller: WebvhResourceLogController
  }): Promise<void> {
    const readBack = await confirmAppend({ store: log, entry })
    const confirmed = await verifyResourceLog({
      entries: readBack.entries,
      controller,
      expectedMethod: RESOURCE_LOG_METHOD,
      pin: await pinStore.read({ logId })
    })
    await pinStore.write({ logId, pin: confirmed.pin })
    lastVerified = confirmed
    lastVerifiedView = controller
  }

  return {
    async read() {
      let view: WebvhResourceLogController | null = null
      const current = await readGovernedEpochConfiguration({
        store: log,
        resolveController: async () => {
          view = await currentController()
          return view
        },
        pinStore,
        logId
      })
      if (current === null) {
        lastVerified = null
        lastVerifiedView = null
        return null
      }
      lastVerified = current.verified
      lastVerifiedView = view
      return {
        descriptor: current.descriptor,
        etag: current.etag
      }
    },

    async replace(descriptor, { ifMatch }) {
      if (lastVerified === null) {
        throw new Error(
          'Cannot replace the governed descriptor: replace must follow a ' +
            'read on the same store instance.'
        )
      }
      if (ifMatch === undefined) {
        throw new Error(
          'Cannot replace the governed descriptor: the backend returned no ' +
            'validator, and the profile forbids an unconditional write.'
        )
      }
      if (lastVerified.terminal) {
        throw new ResourceLogClosedError({ nextLog: lastVerified.terminal })
      }
      const controller = await currentController()
      // The pre-write pass's precondition, enforced rather than assumed: the
      // view that verified `lastVerified` must be a prefix of this one (the
      // account log is append-only, so carrying its head version is enough).
      // A resolver that regressed is reported as the port's conflict class,
      // so the edv machinery re-reads under the current view and rebases
      // instead of the pass refusing on a bound that indexes another list.
      const verifiedHead =
        lastVerifiedView?.versionIds[lastVerifiedView.versionIds.length - 1]
      if (
        verifiedHead !== undefined &&
        !controller.versionIds.includes(verifiedHead)
      ) {
        throw new PreconditionFailedError(
          'Cannot replace the governed descriptor: the controller view ' +
            `resolved for this write does not carry version "${verifiedHead}", ` +
            'which the preceding read verified against; re-read and retry.',
          { status: 412 }
        )
      }
      const entry = await buildResourceLogEntry({
        head: lastVerified.head,
        state: toState(descriptor),
        controller,
        signer
      })
      // The library's pre-write pass, run BEFORE the append lands: the entry
      // is verified as a reader would verify it at its ordinal (shape, chain,
      // proof, membership at the head's controller version, and the
      // controller's `admitAppend` hook carrying the ceremony-tail license).
      // Read-back would refuse the same entry anyway, but only after it
      // poisoned the served log for every reader.
      await verifyResourceLogAppend({
        entry,
        controller,
        head: lastVerified
      })
      // A stale validator throws the library's conflict error here,
      // translated back to the PreconditionFailedError the edv machinery's
      // CAS loop re-reads and rebases on (the descriptor-store port's
      // documented class). An untranslated PreconditionFailedError from a
      // store passes through unchanged, already satisfying the port.
      try {
        await log.append(entry, { ifMatch })
      } catch (err) {
        throw asDescriptorStoreConflict(err)
      }
      await settle({ entry, controller })
    },

    async create(descriptor) {
      // A held pin means this client has already verified a roster log in
      // this slot, so there is nothing to create. The pinned read refuses an
      // absent log as a rollback (a host hiding the pinned log must not be
      // answered with a fresh genesis over it); a served one is the lost
      // create race, translated so the edv machinery re-reads and adopts it.
      if ((await pinStore.read({ logId })) !== null) {
        await readGovernedEpochConfiguration({
          store: log,
          resolveController: currentController,
          pinStore,
          logId
        })
        throw new PreconditionFailedError(
          'The resource log create lost its guarded-create race: a log is ' +
            'already pinned and served; re-read and adopt it.',
          { status: 412 }
        )
      }
      const controller = await currentController()
      const genesis = await buildResourceLogGenesis({
        state: toState(descriptor),
        method: RESOURCE_LOG_METHOD,
        controller,
        signer
      })
      // The pre-write pass for a genesis: verified as a one-entry log before
      // anything is created, so a non-member signer never leaves behind a
      // log no reader accepts. `pin: null` is deliberate: the candidate is
      // not served history, and continuity belongs to the read-back.
      try {
        await verifyResourceLog({
          entries: [genesis],
          controller,
          expectedMethod: RESOURCE_LOG_METHOD,
          pin: null
        })
      } catch (err) {
        // A refused genesis against a log that already exists is a lost
        // create race (matched by name: the class may come from another
        // library copy), translated to the port's conflict class so the edv
        // machinery re-reads and adopts the winner's descriptor. With no log
        // served, or on any other class (a port bug), the error propagates
        // with nothing adopted.
        if (!(
          err instanceof Error && err.name === 'ResourceLogIntegrityError'
        )) {
          throw err
        }
        if ((await log.read()) === null) {
          throw err
        }
        throw new PreconditionFailedError(
          'The resource log create lost its guarded-create race: the genesis ' +
            `was refused pre-write (${err.message}) and a log is already ` +
            'served; re-read and adopt it.',
          { status: 412, cause: err }
        )
      }
      // A lost guarded-create race throws the library's conflict error,
      // translated so the edv machinery re-reads and adopts the winner's
      // descriptor.
      try {
        await log.create(genesis)
      } catch (err) {
        throw asDescriptorStoreConflict(err)
      }
      await settle({ entry: genesis, controller })
    },

    async seal() {
      const controller = await currentController()
      // Reuse the log view the most recent read or confirmed append on this
      // store instance verified: a rotation that just appended carries a
      // version past the removal, so the sweep resolves noop with no
      // re-fetch, and a stale view is safe (sealResourceLog's append path
      // re-reads before writing).
      const { sealed, verified } = await sealResourceLog({
        store: log,
        controller,
        expectedMethod: RESOURCE_LOG_METHOD,
        pinStore,
        logId,
        signer,
        ...(lastVerified === null ? {} : { verified: lastVerified })
      })
      if (verified !== null) {
        lastVerified = verified
        lastVerifiedView = controller
      }
      return sealed ? 'sealed' : 'noop'
    },

    setMinimumControllerVersion({ controller }) {
      minimumControllerVersion = controller
    }
  }
}
