/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The chain-head pin: the client-local durable record of a resource log's
 * verified identity and latest verified head, kept per log beside the app's
 * other continuity pins (the account pointer, the roster epoch pin). The pin
 * is what turns one-shot verification into continuity: a served log whose
 * SCID or method differs from the pin outside a verified handover, or whose
 * history is not a descendant of the pinned head, is refused instead of
 * adopted. Storage is the app's concern (freewallet: beside its other pins in
 * localStorage; DCW: a table row), so only the seam lives here, plus an
 * in-memory implementation for tests and single-session use.
 *
 * The seam is keyed: every read and write names the log it concerns with a
 * `logId`, so one store instance serves every log a wallet holds. Wallet-core
 * supplies the key at every call, built by {@link resourceLogPinId} (or one of
 * the named builders over it), so an app implements one keyed store and never
 * chooses keys itself.
 */

/**
 * One log's pin: the format identifier from the genesis `parameters.method`,
 * the SCID, and the `versionId` of the latest verified head. Established at
 * first contact (trust-on-first-use of the log's identity), advanced only
 * after a full verification whose head is the pinned head or a descendant,
 * and replaced wholesale only across a verified handover.
 */
export interface ResourceLogHeadPin {
  method: string
  scid: string
  head: string
}

/**
 * Where a client keeps its chain-head pins, one record per log, keyed by
 * `logId`. `read` resolves `null` before first contact with that log. Writes
 * happen only on the two legal transitions (advance after full verification,
 * replace across a verified handover) -- the verifier never regresses a pin.
 *
 * The `logId` uniquely names one log among all the logs this store instance
 * serves: one store may serve every log a wallet holds, keyed per log, and two
 * different logs must never share a `logId`. Wallet-core supplies the key at
 * every read and write, built by {@link resourceLogPinId} (or one of the named
 * builders over it), so an implementation never chooses keys of its own.
 */
export interface ResourceLogPinStore {
  read(options: { logId: string }): Promise<ResourceLogHeadPin | null>
  write(options: { logId: string; pin: ResourceLogHeadPin }): Promise<void>
}

/**
 * The pin-slot key for one log: an opaque per-log identity key for pin
 * storage, not a fetchable path or URL.
 *
 * It is deliberately host-free. The `spaceId` is the account's stable random
 * id, so a log served from a claimed new host lands in the SAME pin slot and
 * is checked against the pin already held, rather than opening a fresh
 * trust-on-first-use slate (the mirror-fork concern).
 *
 * @param options {object}
 * @param options.spaceId {string}   the Space the log lives in
 * @param options.collectionId {string}   the collection holding the log
 * @param options.resourceId {string}   the log resource's id
 * @returns {string}
 */
export function resourceLogPinId({
  spaceId,
  collectionId,
  resourceId
}: {
  spaceId: string
  collectionId: string
  resourceId: string
}): string {
  return `space/${spaceId}/${collectionId}/${resourceId}`
}

/**
 * An in-memory pin store: continuity within one session only, keyed by
 * `logId` like any other implementation, so one instance serves several logs.
 * Tests use it as the seam's reference implementation; apps persist for real.
 *
 * @returns {ResourceLogPinStore}
 */
export function memoryResourceLogPinStore(): ResourceLogPinStore {
  const pins = new Map<string, ResourceLogHeadPin>()
  return {
    async read({ logId }) {
      return pins.get(logId) ?? null
    },
    async write({ logId, pin }) {
      pins.set(logId, pin)
    }
  }
}
