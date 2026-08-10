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
 * Where a client keeps its chain-head pins, one record per log. `read`
 * resolves `null` before first contact. Writes happen only on the two legal
 * transitions (advance after full verification, replace across a verified
 * handover) -- the verifier never regresses a pin.
 */
export interface ResourceLogPinStore {
  read(): Promise<ResourceLogHeadPin | null>
  write(pin: ResourceLogHeadPin): Promise<void>
}

/**
 * An in-memory pin store: continuity within one session only. Tests use it
 * as the seam's reference implementation; apps persist for real.
 *
 * @returns {ResourceLogPinStore}
 */
export function memoryResourceLogPinStore(): ResourceLogPinStore {
  let pin: ResourceLogHeadPin | null = null
  return {
    async read() {
      return pin
    },
    async write(next: ResourceLogHeadPin) {
      pin = next
    }
  }
}
