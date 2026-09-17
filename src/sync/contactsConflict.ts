/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The last-write-wins conflict rule for the mutable `contacts` head
 * collection. Every other synced collection is immutable and content-addressed,
 * so a write-write conflict is impossible there. A contact head document is
 * genuinely overwritten in place under a stable row id, so two replicas CAN
 * race on the same row -- and a remote-master-always default would silently
 * drop one side's edit.
 *
 * The rule lives here rather than in `@interop/social-core` because deciding
 * it means DECRYPTING both sides: a head payload rides inside an encrypted
 * envelope, and the `updatedAt` / `writerId` pair the rule compares is sealed
 * inside it. The comparison itself is still social-core's
 * (`remotePayloadWins`), and both replicas run the same one, so they converge
 * with no duplicates and no round trips.
 *
 * **Fail-safe to remote.** Whenever the fields the rule needs are unreachable
 * -- a tombstone on either side, a missing cipher, an envelope this replica
 * holds no key for, a body that is not a valid head payload -- the remote
 * master wins. That is the always-converging default, so a malformed side
 * simply loses: a valid local over a malformed remote re-pushes and repairs the
 * server copy, a valid remote over a malformed local is adopted, and two
 * malformed sides adopt the server version rather than re-fighting the conflict
 * forever. A delete is in the same class deliberately: a tombstone carries no
 * fresher stamp (a delete does not rewrite the head payload), so deletion wins.
 *
 * **An integrity refusal is not an unreachable side.** A decrypt refused by the
 * cipher's envelope-to-resource binding check (was-client's `IntegrityError`)
 * says the stored body was written for a different resource than the one it was
 * read under: the host altered the data or served it under another id. Scoring
 * that as one more unreachable side would let the fail-safe default settle the
 * conflict silently and discard the refusal, which is the binding check's whole
 * point. It is rethrown instead, so it leaves the resolver and fails the
 * replication cycle -- the rule `@interop/was-sync`'s own last-write-wins
 * resolver follows on the same seam. A side this replica simply holds no key
 * for (`UnknownEpochError`, `KeyUnwrapError`) is not that: it stays unreachable
 * and stays on the fail-safe path above.
 *
 * Both directions fail the cycle, and no winner is returned: a misbound remote
 * side and a misbound local side are refused alike. The caller learns WHICH
 * side was refused through the optional `onIntegrityRefusal` callback, which
 * fires once per refused side (both sides can be refused in one conflict)
 * before the refusal is rethrown. The callback is a reporting seam alone, so it
 * decides nothing.
 *
 * Everything imported here is crypto-free: the envelope predicate and the
 * `DocCipher` seam come from was-client's plain `sync` module (the same one the
 * replication engine uses), never from its `edv` module, and the comparison
 * comes from zero-dependency social-core. That keeps the `sync` subpath loadable
 * in a plain test runner -- the EDV graph is the app's to pull in, at the point
 * where it builds the cipher it passes down.
 */
import {
  isEncryptedEnvelope,
  isIntegrityError,
  type DocCipher,
  type Json
} from '@interop/was-client/sync'
import {
  isContactHeadPayload,
  remotePayloadWins,
  type ContactHeadPayload
} from '@interop/social-core'

/**
 * Which side of a contact-head conflict wins.
 */
export type ContactConflictWinner = 'remote' | 'local'

/**
 * Recovers a validated head payload from a stored row body: decrypts an
 * envelope, passes plaintext through, and resolves `undefined` when the
 * payload (and so the fields the rule compares) cannot be reached.
 *
 * A side this replica holds no key for is unreachable. What the fail-safe rule
 * below then does with it depends on which side it was: an unreachable local
 * side hands the conflict to the remote master, while an unreachable remote
 * side leaves the reachable local body to win. Neither side is ever compared on
 * a body it could not open.
 *
 * The decrypt is addressed with the row's own id, and an envelope sealed for
 * another resource is refused with an `IntegrityError` rather than read as one
 * more unreachable side. That refusal is rethrown, out of the resolver and into
 * the replication cycle. See the module doc.
 *
 * @param options {object}
 * @param options.id {string}   the contact head row's resource id, the id the
 *   stored envelope must be sealed for
 * @param options.data {Json}   the stored body: an encrypted envelope or a
 *   plaintext payload
 * @param [options.cipher] {DocCipher}   the collection's document cipher;
 *   absent for a plaintext store, in which case an envelope is unreachable
 * @returns {Promise<ContactHeadPayload | undefined>}
 * @throws {Error}   the cipher's `IntegrityError`: the stored envelope was
 *   sealed for a different resource than `id`
 */
export async function contactHeadPayloadOf({
  id,
  data,
  cipher
}: {
  id: string
  data: Json | undefined
  cipher?: DocCipher
}): Promise<ContactHeadPayload | undefined> {
  if (data === null || data === undefined) {
    return undefined
  }
  let body: unknown = data
  if (isEncryptedEnvelope(data)) {
    if (!cipher) {
      return undefined
    }
    try {
      body = await cipher.decrypt({ id, envelope: data })
    } catch (err) {
      if (isIntegrityError(err)) {
        throw err
      }
      return undefined
    }
  }
  return isContactHeadPayload(body) ? body : undefined
}

/**
 * Decides a contact-head conflict. See the module doc for the fail-safe rule.
 *
 * @param options {object}
 * @param options.id {string}   the contested row's resource id, which both
 *   sides' envelopes must be sealed for
 * @param options.remote {Json}   the remote (master) row body
 * @param options.local {Json}   the local row body
 * @param [options.cipher] {DocCipher}   the collection's document cipher
 * @param [options.remoteDeleted] {boolean}   the remote side is a tombstone
 * @param [options.localDeleted] {boolean}   the local side is a tombstone
 * @param [options.onIntegrityRefusal] {Function}   reports each side the
 *   binding check refused, as `{ side, err }`, before the refusal is rethrown
 * @returns {Promise<ContactConflictWinner>}
 * @throws {Error}   the cipher's `IntegrityError` from either side: the
 *   conflict is left undecided and the replication cycle fails
 */
export async function resolveContactHeadConflict({
  id,
  remote,
  local,
  cipher,
  remoteDeleted = false,
  localDeleted = false,
  onIntegrityRefusal
}: {
  id: string
  remote: Json | undefined
  local: Json | undefined
  cipher?: DocCipher
  remoteDeleted?: boolean
  localDeleted?: boolean
  onIntegrityRefusal?: (refusal: {
    side: 'remote' | 'local'
    err: unknown
  }) => void
}): Promise<ContactConflictWinner> {
  if (remoteDeleted || localDeleted) {
    return 'remote'
  }
  // Both sides decrypt independently, so they decrypt concurrently. Each
  // side's own unreachability (no key for the envelope, a malformed payload) is
  // already resolved as `undefined` inside the helper, so the join changes
  // nothing about the fail-safe rule below. An integrity refusal on either side
  // rejects instead, and no winner is returned.
  const [remoteResult, localResult] = await Promise.allSettled([
    contactHeadPayloadOf({ id, data: remote, cipher }),
    contactHeadPayloadOf({ id, data: local, cipher })
  ])
  // `allSettled` rather than `all`, so a conflict whose two sides are both
  // misbound reports both before the first refusal leaves. The refusal itself
  // is rethrown unchanged, so the caller still matches it on `name`.
  const sides = [
    { side: 'remote', result: remoteResult },
    { side: 'local', result: localResult }
  ] as const
  for (const { side, result } of sides) {
    if (result.status === 'rejected' && isIntegrityError(result.reason)) {
      onIntegrityRefusal?.({ side, err: result.reason })
    }
  }
  if (remoteResult.status === 'rejected') {
    throw remoteResult.reason
  }
  if (localResult.status === 'rejected') {
    throw localResult.reason
  }
  const remoteHead = remoteResult.value
  const localHead = localResult.value
  if (remoteHead && localHead) {
    return remotePayloadWins(remoteHead, localHead) ? 'remote' : 'local'
  }
  // Exactly one usable side wins on its own; neither usable falls back to the
  // always-converging default.
  if (localHead && !remoteHead) {
    return 'local'
  }
  return 'remote'
}
