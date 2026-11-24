/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The ceremony-tail license on ladder-signed resource-log appends (clause B
 * of the ladder VM's authority clauses). A ladder-signed append is accepted
 * in exactly three shapes: the log's first entry (creation, not extension --
 * callers admit that shape by not calling this check on a genesis entry), or
 * a rotation carrying a controller document version V at or before which a
 * licensed version W stands after the verified log head's version. A version
 * W is licensed for a ladder when it changed the credential inventory (shape
 * 2), or when it changed the ENROLLED-CLIENT set and a rung of that ladder
 * signed W's own entry (shape 3). A version licensed by shape 3 for another
 * ladder alone does not serve. W may equal V, and may also come before it,
 * so a torn ceremony's completing append can carry the head its writer last
 * verified.
 *
 * Both shapes are one-shot. An accepted entry carries V, so it spends every
 * licensed version at or before V for every ladder, and the next ladder
 * rotation needs a licensed version after V. A head at or past V refuses.
 * Each entry also carries a per-entry rule: at most one of its proofs may be
 * by a ladder key, so a second ladder key cannot co-sign its way around the
 * one-shot. A rotation co-signed by an ordinary member stays licensed.
 * Everything else, above all a rotation with no unspent licensed version
 * (the silent-rekey shape), is refused with {@link ResourceLogLicenseError}.
 * Controller versions compare by position in the controller's verified
 * version history, the structural twin of the sealing sweep's
 * `headControllerVersionIndex >= removalIndex` check.
 *
 * Shape 3's signer conjunct is the whole of what keeps it out of the
 * any-`keyAgreement`-change predicate the clause rejects. A client's own
 * enrollment or revocation entry is signed by a client, so it mints no shot
 * for any ladder; only a ladder-signed enrollment or removal does, and only
 * for the ladder that signed it. Whose rung signed a version is read from the
 * log alone (`ladderRungKeys` on the controller inventory), so a verifier
 * needs no ladder seed, and a ladder the log does not attribute is refused.
 *
 * Shape 3 and the later carried version are verifier-side rules on an
 * append-only log: a reader that has not shipped them refuses the whole
 * roster log, because this refusal is thrown from the admission hook and the
 * verifier propagates it. Rollout is therefore verifier-first -- every reader
 * of a roster log ships a rule before any writer emits an append that needs
 * it.
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
 * ladder-signed append carrying document version V. The append is accepted
 * when some version W after the head's version and at or before V is
 * licensed for the appending ladder. The scan runs downward from V and stops
 * at the first licensed version. It does not test the head's version or an
 * earlier one as W. The head's inventory is read only as the baseline its
 * successor is compared against. Under a `null` head the scan has no lower
 * bound, so V itself must be the licensed version.
 *
 * W is licensed by shape 2 when S(W) differs from S(W-1) in either direction,
 * with S(-1) empty for the genesis version. W is licensed by shape 3 when its
 * enrolled-client set differs from W-1's, in either direction, AND one of the
 * update keys that signed W's own entry is a rung the log attributes to the
 * appending ladder. Shape 3 is read entirely at W: both client sets, the rung
 * attribution, and the entry signers.
 *
 * A head at or past V refuses before any scan, since every licensed version
 * at or before V is then spent (the one-shot). A `null` controller version
 * index (an unversioned controller, where no version exists to license
 * against) is refused fail-closed.
 *
 * The appending ladder is read off `proofKeys` rather than passed: the
 * ladder VM, as listed at V, whose key signs the entry. The entry carries at
 * most one ladder proof (the refusal below), and the port promises the
 * calling proof's own key is among them, so the intersection with V's ladder
 * keys names exactly the ladder whose shot is being spent.
 *
 * The one-shot is spent per entry, so the entry itself may carry at most one
 * ladder-key proof, counted at V: a second ladder key among `proofKeys`
 * refuses, because every proof of an entry shares one controller version and
 * two ladder signatures would otherwise spend the same versions twice. Proof
 * order does not matter -- `proofKeys` is read as a set, and the caller's
 * hook runs on each proof, so the refusal lands on whichever ladder-key proof
 * is admitted first. A ladder proof co-signed by an ordinary member is
 * untouched.
 *
 * This check does not decide whether a key may sign at V. A ladder VM struck
 * before V is not among V's `assertionMethod` keys, and the resource-log
 * verifier refuses its proof before the admission hook runs.
 *
 * @param options {object}
 * @param options.controller {object}   the verified controller view's
 *   version list and inventory accessor
 * @param options.controllerVersionIndex {number | null}   the append's
 *   controller version as an index into `controller.versionIds` (`null`:
 *   no controller version)
 * @param options.headControllerVersionIndex {number | null}   the verified
 *   log head's effective controller version index before this append
 *   (`null`: the log has no versioned entries yet, and the carried version
 *   must then be licensed itself)
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
  const inventoryAtIndex = (index: number) =>
    controller.inventoryAt(controller.versionIds[index]!)
  const carried = await inventoryAtIndex(controllerVersionIndex)
  const ladderProofKeys = proofKeys.filter(key => carried.ladderKeys.has(key))
  if (ladderProofKeys.length > 1) {
    throw new ResourceLogLicenseError(
      'The append carries more than one ladder-signed proof (at most one ' +
        'ladder key may sign an entry, so a co-signing ladder key cannot ' +
        'spend the one-shot twice).'
    )
  }
  if (
    headControllerVersionIndex !== null &&
    headControllerVersionIndex >= controllerVersionIndex
  ) {
    throw new ResourceLogLicenseError(
      'The verified log head already carries an entry at or past this ' +
        'document version, so every licensed version at or before it is ' +
        'spent (the license is one-shot).'
    )
  }
  const appendingLadderKey = ladderProofKeys[0]
  // A log with no versioned head gives the scan no lower bound to stop at,
  // so the carried version must be the licensed one itself there.
  const lowestIndex =
    headControllerVersionIndex === null
      ? controllerVersionIndex
      : headControllerVersionIndex + 1
  let current = carried
  for (let index = controllerVersionIndex; index >= lowestIndex; index--) {
    const previous = index === 0 ? undefined : await inventoryAtIndex(index - 1)
    const inventoryChanged = !setsEqual(
      current.inventoryKeys,
      previous?.inventoryKeys ?? new Set<string>()
    )
    if (inventoryChanged) {
      return
    }
    const clientSetChanged = !setsEqual(
      current.enrolledClientKeys,
      previous?.enrolledClientKeys ?? new Set<string>()
    )
    // Shape 3's signer conjunct, read at this version: a rung the log
    // attributes to THIS ladder signed the version's entry. An unattributed
    // ladder holds no rungs here, so it does not satisfy the conjunct.
    const ownRungs =
      appendingLadderKey === undefined
        ? undefined
        : current.ladderRungKeys.get(appendingLadderKey)
    const signedByOwnLadder = [...(ownRungs ?? [])].some(rung =>
      current.entrySignerKeys.has(rung)
    )
    if (clientSetChanged && signedByOwnLadder) {
      return
    }
    if (previous === undefined) {
      break
    }
    current = previous
  }
  throw new ResourceLogLicenseError(
    'The ladder-signed append carries a controller document version that, ' +
      "like every version after the verified log head's, neither changed " +
      'the credential inventory nor changed the enrolled-client set under a ' +
      'rung of this ladder (a rotation against an unchanged document is ' +
      'never licensed).'
  )
}
