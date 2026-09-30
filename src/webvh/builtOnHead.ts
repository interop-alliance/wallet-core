/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The resume marker a torn ceremony's pending record carries: the head
 * (`{ scid, versionId }`) the ceremony's pivot entry was about to be built
 * on, handed to the caller by the persist-before-publish seam and handed back
 * on a resume. The shape check, the reached check, and the refusal live here
 * so the self-enrollment and the transient-recovery continuation apply the
 * same guard: `signAccountEntry` runs both in its read preamble, so any
 * ceremony that threads the marker through is guarded by construction.
 */
import type { DIDLog } from '@interop/did-method-webvh'

/**
 * The marker itself: the genesis SCID and the head entry's `versionId`.
 */
export type BuiltOnHead = { scid: string; versionId: string }

/**
 * Refuses a malformed resume marker before any read. A marker whose members
 * are missing or empty could not be compared against anything, so accepting
 * one would hand a resume the mint-skip WITHOUT the fork guard the marker
 * exists to apply -- fail-open exactly where the guard matters.
 *
 * @param options {object}
 * @param options.builtOnHead {unknown}   the supplied marker
 * @returns {void}
 */
export function assertBuiltOnHeadShape({
  builtOnHead
}: {
  builtOnHead: unknown
}): void {
  const { scid, versionId } = (builtOnHead ?? {}) as {
    scid?: unknown
    versionId?: unknown
  }
  if (
    builtOnHead === null ||
    typeof builtOnHead !== 'object' ||
    typeof scid !== 'string' ||
    scid === '' ||
    typeof versionId !== 'string' ||
    versionId === ''
  ) {
    throw new TypeError(
      'The resume marker (builtOnHead) must carry a non-empty scid and ' +
        'versionId; a marker that cannot be compared would resume with no ' +
        'fork guard at all.'
    )
  }
}

/**
 * Refuses a served log that has not reached the recorded head: a different
 * SCID, or no entry carrying the recorded `versionId`. Checked before a
 * resumed ceremony's completion check, so a truncated served log is refused
 * rather than read as "not complete yet" and rebuilt over.
 *
 * @param options {object}
 * @param options.log {DIDLog}   the served log
 * @param options.builtOnHead {object}   the recorded `{ scid, versionId }`
 * @returns {void}
 */
export function assertBuiltOnHeadReached({
  log,
  builtOnHead
}: {
  log: DIDLog
  builtOnHead: BuiltOnHead
}): void {
  const genesisScid = log[0]?.parameters.scid ?? ''
  const reached = log.some(entry => entry.versionId === builtOnHead.versionId)
  if (genesisScid !== builtOnHead.scid || !reached) {
    throw new BuiltOnHeadNotReachedError({ builtOnHead })
  }
}

/**
 * Thrown when a resumed ceremony is served an account log that has not
 * reached the head its pending record was written against -- a different SCID,
 * or no entry carrying the recorded `versionId`. Rebuilding the pivot entry
 * over such a log would fork the account off a head the ceremony already
 * committed to, which the chain-head pin alone does not catch: the pin is
 * written non-atomically after the pivot entry publishes, so a run torn
 * between the two leaves a pin one entry behind, and the continuity check
 * accepts a served log at exactly the pinned length.
 *
 * **`name` is a stable contract.** It is always the string
 * `'BuiltOnHeadNotReachedError'`, and a consumer should match on that rather
 * than on `instanceof`: a wallet app that links this package (or holds two
 * copies of it through a dependency tree) gets a different class object for
 * the same error, so `instanceof` silently fails there while the name does
 * not.
 */
export class BuiltOnHeadNotReachedError extends Error {
  /**
   * The head the pending record recorded, which the served log did not reach.
   */
  builtOnHead: BuiltOnHead

  /**
   * @param options {object}
   * @param options.builtOnHead {object}   the recorded `{ scid, versionId }`
   */
  constructor({ builtOnHead }: { builtOnHead: BuiltOnHead }) {
    super(
      'did:webvh: the served account log has not reached the head this ' +
        `resumed ceremony was built on (scid ${builtOnHead.scid}, version ` +
        `${builtOnHead.versionId}); the resume is refused rather than ` +
        'rebuilt over it.'
    )
    this.name = 'BuiltOnHeadNotReachedError'
    this.builtOnHead = builtOnHead
  }
}
