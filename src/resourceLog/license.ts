/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The ceremony-tail license on ladder-signed resource-log appends (clause B
 * of the ladder VM's authority clauses). A ladder-signed append is accepted
 * in exactly three shapes: the log's first entry (creation, not extension --
 * callers admit that shape by not calling this check on a genesis entry);
 * a rotation that carries an inventory-changing controller document version
 * (shape 2); or a rotation carrying a version whose ENROLLED-CLIENT set
 * changed and whose entry a rung of the appending ladder signed (shape 3).
 * Shapes 2 and 3 are one-shot -- refused when the verified log head already
 * carries an entry at that version or later -- and both carry a per-entry
 * rule: at most one of an entry's proofs may be by a ladder key, so a second
 * ladder key cannot co-sign its way around the one-shot. A rotation co-signed
 * by an ordinary member stays licensed. Everything else, above all a rotation
 * against an unchanged document (the silent-rekey shape), is refused with
 * {@link ResourceLogLicenseError}. Controller versions compare by position
 * in the controller's verified version history, the structural twin of the
 * sealing sweep's `headControllerVersionIndex >= removalIndex` check.
 *
 * Shape 3's signer conjunct is the whole of what keeps it out of the
 * any-`keyAgreement`-change predicate the clause rejects. A client's own
 * enrollment or revocation entry is signed by a client, so it mints no shot
 * for any ladder; only a ladder-signed enrollment or removal does, and only
 * for the ladder that signed it. Whose rung signed a version is read from the
 * log alone (`ladderRungKeys` on the controller inventory), so a verifier
 * needs no ladder seed, and a ladder the log does not attribute is refused.
 *
 * Shape 3 is a verifier-side rule on an append-only log: a reader that has
 * not shipped it refuses the whole roster log, because this refusal is thrown
 * from the admission hook and the verifier propagates it. Rollout is
 * therefore verifier-first -- every reader of a roster log ships shape 3
 * before any writer emits an append that needs it.
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
 * Evaluates the ceremony-tail license's second and third shapes for one
 * ladder-signed append. Shape 2: the append carries an inventory-changing
 * document version V -- S(V) differs from S(V-1) in either direction, with
 * S(-1) empty for the genesis version. Shape 3: the version's enrolled-client
 * set differs from V-1's, in either direction, AND one of the update keys
 * that signed the version's own entry is a rung the log attributes to the
 * ladder signing this append. Either shape then meets the same one-shot
 * check: no verified entry may already carry V or later
 * (`headControllerVersionIndex >= controllerVersionIndex` refuses, so a torn
 * ceremony's late-arriving tail still passes while a second rotation against
 * the same version does not). A `null` controller version index (an
 * unversioned controller, where no version exists to license against) is
 * refused fail-closed.
 *
 * The appending ladder is read off `proofKeys` rather than passed: the entry
 * carries at most one ladder proof (the refusal below), and the port promises
 * the calling proof's own key is among them, so the intersection with the
 * version's ladder keys names exactly the ladder whose shot is being spent.
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
  const ladderProofKeys = proofKeys.filter(key => inventory.ladderKeys.has(key))
  if (ladderProofKeys.length > 1) {
    throw new ResourceLogLicenseError(
      'The append carries more than one ladder-signed proof (at most one ' +
        'ladder key may sign an entry, so a co-signing ladder key cannot ' +
        'spend the one-shot twice).'
    )
  }
  const previous =
    controllerVersionIndex === 0
      ? undefined
      : await controller.inventoryAt(
          controller.versionIds[controllerVersionIndex - 1]!
        )
  const inventoryChanged = !setsEqual(
    inventory.inventoryKeys,
    previous?.inventoryKeys ?? new Set<string>()
  )
  const clientSetChanged = !setsEqual(
    inventory.enrolledClientKeys,
    previous?.enrolledClientKeys ?? new Set<string>()
  )
  // Shape 3's signer conjunct: a rung the log attributes to THIS ladder signed
  // the version's entry. An unattributed ladder holds no rungs here, so it
  // never satisfies the conjunct.
  const appendingLadderKey = ladderProofKeys[0]
  const ownRungs =
    appendingLadderKey === undefined
      ? undefined
      : inventory.ladderRungKeys.get(appendingLadderKey)
  const signedByOwnLadder = [...(ownRungs ?? [])].some(rung =>
    inventory.entrySignerKeys.has(rung)
  )
  if (!inventoryChanged && !(clientSetChanged && signedByOwnLadder)) {
    throw new ResourceLogLicenseError(
      'The ladder-signed append carries a controller document version that ' +
        'neither changed the credential inventory nor changed the ' +
        'enrolled-client set under a rung of this ladder (a rotation ' +
        'against an unchanged document is never licensed).'
    )
  }
  if (
    headControllerVersionIndex !== null &&
    headControllerVersionIndex >= controllerVersionIndex
  ) {
    throw new ResourceLogLicenseError(
      'The verified log head already carries an entry at or past this ' +
        'licensed document version (the license is one-shot).'
    )
  }
}
