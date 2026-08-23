/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The ceremony-tail license on ladder-signed resource-log appends (clause B
 * of the ladder VM's authority clauses). A ladder-signed append is accepted
 * in exactly two shapes: the log's first entry (creation, not extension --
 * callers admit that shape by not calling this check on a genesis entry),
 * or a rotation that carries an inventory-changing controller document
 * version, one-shot -- refused when the verified log head already carries
 * an entry at that version or later. Both shapes carry a per-entry rule: at
 * most one of an entry's proofs may be by a ladder key, so a second ladder
 * key cannot co-sign its way around the one-shot. A rotation co-signed by an
 * ordinary member stays licensed. Everything else, above all a rotation
 * against an unchanged document (the silent-rekey shape), is refused with
 * {@link ResourceLogLicenseError}. Controller versions compare by position
 * in the controller's verified version history, the structural twin of the
 * sealing sweep's `headControllerVersionIndex >= removalIndex` check.
 */
import type { WebvhResourceLogController } from './controller.js'
import { ResourceLogLicenseError } from './errors.js'

/**
 * Set equality over inventory members.
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
 * append: the append must carry an inventory-changing document version V --
 * S(V) differs from S(V-1) in either direction, with S(-1) empty for the
 * genesis version -- and no verified entry may already carry V or later
 * (`headControllerVersionIndex >= controllerVersionIndex` refuses; the
 * license is one-shot, so a torn ceremony's late-arriving tail still passes
 * while a second rotation against the same version does not). A `null`
 * controller version index (an unversioned controller, where no version
 * exists to license against) is refused fail-closed.
 *
 * The one-shot is spent per entry, so the entry itself may carry at most one
 * ladder-key proof: a second ladder key among `proofKeys` refuses, because
 * every proof of an entry shares one controller version and two ladder
 * signatures would otherwise spend the same version twice. Proof order does
 * not matter -- `proofKeys` is read as a set, and the caller's hook runs on
 * each proof, so the refusal lands on whichever ladder-key proof is admitted
 * first. A ladder proof co-signed by an ordinary member is untouched.
 *
 * @param options {object}
 * @param options.controller {object}   the verified controller view's
 *   version list and inventory accessor
 * @param options.controllerVersionIndex {number | null}   the append's
 *   controller version as an index into `controller.versionIds` (`null`:
 *   no controller version)
 * @param options.headControllerVersionIndex {number | null}   the verified
 *   log head's effective controller version index before this append
 *   (`null`: the log has no versioned entries yet)
 * @param options.proofKeys {string[]}   every signing-key multibase on the
 *   entry, distinct, read as a set
 * @returns {Promise<void>}
 */
export async function assertLadderAppendLicensed({
  controller,
  controllerVersionIndex,
  headControllerVersionIndex,
  proofKeys
}: {
  controller: Pick<WebvhResourceLogController, 'versionIds' | 'inventoryAt'>
  controllerVersionIndex: number | null
  headControllerVersionIndex: number | null
  proofKeys: string[]
}): Promise<void> {
  if (
    controllerVersionIndex === null ||
    controllerVersionIndex < 0 ||
    controllerVersionIndex >= controller.versionIds.length
  ) {
    throw new ResourceLogLicenseError(
      'A ladder-signed append past the genesis entry cannot be licensed ' +
        'without a controller document version to license against.'
    )
  }
  const inventory = await controller.inventoryAt(
    controller.versionIds[controllerVersionIndex]!
  )
  let ladderProofs = 0
  for (const key of proofKeys) {
    if (inventory.ladderKeys.has(key)) {
      ladderProofs += 1
    }
  }
  if (ladderProofs > 1) {
    throw new ResourceLogLicenseError(
      'The append carries more than one ladder-signed proof (at most one ' +
        'ladder key may sign an entry, so a co-signing ladder key cannot ' +
        'spend the one-shot twice).'
    )
  }
  const current = inventory.inventoryKeys
  const previous =
    controllerVersionIndex === 0
      ? new Set<string>()
      : (
          await controller.inventoryAt(
            controller.versionIds[controllerVersionIndex - 1]!
          )
        ).inventoryKeys
  if (setsEqual(current, previous)) {
    throw new ResourceLogLicenseError(
      'The ladder-signed append carries a controller document version ' +
        'that did not change the credential inventory (a rotation against an ' +
        'unchanged document is never licensed).'
    )
  }
  if (
    headControllerVersionIndex !== null &&
    headControllerVersionIndex >= controllerVersionIndex
  ) {
    throw new ResourceLogLicenseError(
      'The verified log head already carries an entry at or past this ' +
        'inventory-changing document version (the license is one-shot).'
    )
  }
}
