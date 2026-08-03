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
 * envelope, and the `updatedAt` / writer pair the rule compares is sealed
 * inside it. The comparison itself is still social-core's
 * (`remotePayloadWins`), and both replicas run the same one, so they converge
 * with no duplicates and no round trips.
 *
 * **Fail-safe to remote.** Whenever the fields the rule needs are unreachable
 * -- a tombstone on either side, a missing cipher, an envelope that will not
 * decrypt, a body that is not a valid head payload -- the remote master wins.
 * That is the always-converging default, so a malformed side simply loses: a
 * valid local over a malformed remote re-pushes and repairs the server copy, a
 * valid remote over a malformed local is adopted, and two malformed sides adopt
 * the server version rather than re-fighting the conflict forever. A delete is
 * in the same class deliberately: a tombstone carries no fresher stamp (a
 * delete does not rewrite the head payload), so deletion wins.
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
 * @param options {object}
 * @param options.data {Json}   the stored body: an encrypted envelope or a
 *   plaintext payload
 * @param [options.cipher] {DocCipher}   the collection's document cipher;
 *   absent for a plaintext store, in which case an envelope is unreachable
 * @returns {Promise<ContactHeadPayload | undefined>}
 */
export async function contactHeadPayloadOf({
  data,
  cipher
}: {
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
      body = await cipher.decrypt({ envelope: data })
    } catch {
      return undefined
    }
  }
  return isContactHeadPayload(body) ? body : undefined
}

/**
 * Decides a contact-head conflict. See the module doc for the fail-safe rule.
 *
 * @param options {object}
 * @param options.remote {Json}   the remote (master) row body
 * @param options.local {Json}   the local row body
 * @param [options.cipher] {DocCipher}   the collection's document cipher
 * @param [options.remoteDeleted] {boolean}   the remote side is a tombstone
 * @param [options.localDeleted] {boolean}   the local side is a tombstone
 * @returns {Promise<ContactConflictWinner>}
 */
export async function resolveContactHeadConflict({
  remote,
  local,
  cipher,
  remoteDeleted = false,
  localDeleted = false
}: {
  remote: Json | undefined
  local: Json | undefined
  cipher?: DocCipher
  remoteDeleted?: boolean
  localDeleted?: boolean
}): Promise<ContactConflictWinner> {
  if (remoteDeleted || localDeleted) {
    return 'remote'
  }
  const remoteHead = await contactHeadPayloadOf({ data: remote, cipher })
  const localHead = await contactHeadPayloadOf({ data: local, cipher })
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
