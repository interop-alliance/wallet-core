/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The ceremony-tail license on ladder-signed resource-log appends (clause B
 * of the ladder VM's authority clauses). A ladder-signed append is accepted
 * in exactly two shapes: the log's first entry (creation, never extension --
 * callers admit that shape by not calling this check on a genesis entry),
 * or a rotation anchored at a posture-changing controller-document version,
 * one-shot -- refused when the verified log head already carries an entry
 * anchored at that version or later. Everything else, above all a rotation
 * against an unchanged document (the silent-rekey shape), is refused with
 * {@link ResourceLogLicenseError}. Anchors compare by position in the
 * controller's verified version history, the structural twin of the sealing
 * sweep's `headAnchorIndex >= removalIndex` check.
 */
import type { ResourceLogController } from './controller.js'
import { ResourceLogLicenseError } from './errors.js'

/**
 * Set equality over posture members.
 *
 * @param left {Set<string>}
 * @param right {Set<string>}
 * @returns {boolean}
 */
function setsEqual(left: Set<string>, right: Set<string>): boolean {
  if (left.size !== right.size) {
    return false
  }
  for (const member of left) {
    if (!right.has(member)) {
      return false
    }
  }
  return true
}

/**
 * Evaluates the ceremony-tail license's second shape for one ladder-signed
 * append: the append must anchor at a posture-changing document version V --
 * S(V) differs from S(V-1) in either direction, with S(-1) empty for a
 * genesis-version anchor -- and no verified entry may already anchor at V or
 * later (`headAnchorIndex >= anchorIndex` refuses; the license is one-shot,
 * so a torn ceremony's late-arriving tail still passes while a second
 * rotation against the same anchor does not). A `null` anchor index (an
 * unversioned controller, where no anchor exists to license against) is
 * refused fail-closed.
 *
 * @param options {object}
 * @param options.controller {ResourceLogController}   the verified controller
 *   view
 * @param options.anchorIndex {number | null}   the append's anchor as an
 *   index into `controller.versionIds` (`null`: unanchored)
 * @param options.headAnchorIndex {number | null}   the verified log head's
 *   effective anchor before this append (`null`: the log has no anchored
 *   entries yet)
 * @returns {Promise<void>}
 */
export async function assertLadderAppendLicensed({
  controller,
  anchorIndex,
  headAnchorIndex
}: {
  controller: ResourceLogController
  anchorIndex: number | null
  headAnchorIndex: number | null
}): Promise<void> {
  if (
    anchorIndex === null ||
    anchorIndex < 0 ||
    anchorIndex >= controller.versionIds.length
  ) {
    throw new ResourceLogLicenseError(
      'A ladder-signed append past the genesis entry cannot be licensed ' +
        'without an anchor into the controller document version history.'
    )
  }
  const current = (
    await controller.postureAt(controller.versionIds[anchorIndex]!)
  ).postureKeys
  const previous =
    anchorIndex === 0
      ? new Set<string>()
      : (await controller.postureAt(controller.versionIds[anchorIndex - 1]!))
          .postureKeys
  if (setsEqual(current, previous)) {
    throw new ResourceLogLicenseError(
      'The ladder-signed append anchors at a controller document version ' +
        'that did not change the credential posture (a rotation against an ' +
        'unchanged document is never licensed).'
    )
  }
  if (headAnchorIndex !== null && headAnchorIndex >= anchorIndex) {
    throw new ResourceLogLicenseError(
      'The verified log head already carries an entry anchored at or past ' +
        'this posture-changing document version (the license is one-shot).'
    )
  }
}
