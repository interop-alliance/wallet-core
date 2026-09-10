/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Revoking a recorded app or agent grant, and reading the server's answer
 * against the verified account document: the connected-apps counterpart of
 * {@link revokeTreatingAlreadyRevokedAsSuccess}, with the same policy. The
 * one local skip is a grant expired beyond the revocation clock-skew margin.
 * Everything else is POSTed, since a revocation the server accepts is the
 * only proof the grant is off the account, and a plain refusal is then
 * classified on what the client can check.
 *
 * What the client can check differs by how the grant was delegated. A grant
 * delegated straight under the Space root is signed by an enrolled client's
 * key, and dies with that client's document entry (the current-key-set
 * rule): the same reading `deriveGrantSignerState` (`/clients`) marks a
 * listing row with, over this one grant. A grant a transient session minted
 * is signed by a client-annex per-visit key the account document never
 * lists, and chains under the generation delegation embedded as the last
 * link of its `proof.capabilityChain`; it dies when that delegation's signer
 * leaves the document, or when the account document's delegated-clients
 * pointer moves to another generation.
 */
import type { IDelegatedZcap, IZcap } from '@interop/data-integrity-core'
import { deriveGrantSignerState } from '../clients/grantState.js'
import {
  delegationAtExpiry,
  delegationExpired,
  delegationProofKeyId,
  delegationSignerGone,
  type PublishedKeyDocument
} from '../webvh/index.js'
import { clientAnnexDidParts } from './log.js'

/**
 * What a recorded grant is read against, off the session's verified account
 * document: the account DID an enrolled client's promoted verification-method
 * id is under, the enrolled clients' signing-key multibases (the two as
 * `deriveGrantSignerState` takes them), the verified document itself (what an
 * embedded generation delegation's proof key is checked against), and the
 * annex DID the document's delegated-clients pointer currently names, absent
 * when it names none. The first two settle the orphaned reading; the last two
 * settle whether an annex-signed grant's generation delegation still stands.
 */
export interface AccountSignerCheck {
  accountDid: string
  currentSigningKeys: Set<string>
  doc: PublishedKeyDocument
  clientAnnexDid?: string
}

/**
 * How a server refusal of a grant's revocation is read, when the client can
 * read it: `expired` (`now` is inside the skew band around the grant's own
 * `expires`, or past it, {@link delegationAtExpiry}), `orphaned` (a grant
 * delegated straight under the Space root whose signer has left the verified
 * document), `signer-gone` (a grant chained under an embedded parent
 * delegation whose own proof key has checkably left the verified document
 * under `capabilityDelegation`, {@link delegationSignerGone}, which catches
 * a generation delegation replaced within its generation as well as one
 * struck with its signer), or `generation-swapped` (a parent that is provably
 * a generation delegation, its `controller` parsing as an annex DID, naming
 * a generation other than the one the account document currently points
 * at).
 */
export type GrantRevocationRefusal =
  'expired' | 'orphaned' | 'signer-gone' | 'generation-swapped'

/**
 * What {@link revokeRecordedGrant} did: `revoked` (the POST landed),
 * `already-revoked` (the server's genuine `AlreadyRevokedError`), `expired`
 * with no POST sent (the grant is past its `expires` by more than the skew
 * margin), or one of the {@link GrantRevocationRefusal} readings of a plain
 * refusal.
 */
export type GrantRevocationOutcome =
  'revoked' | 'already-revoked' | GrantRevocationRefusal

/**
 * Reads a plain server refusal of a recorded grant's revocation against the
 * verified account document, and says why the chain no longer verifies when
 * the client can tell. Without a `signerCheck` only the expiry reading
 * applies. Every uncheckable case reads as undefined, so the refusal is
 * rethrown rather than counted: a parent whose proof key is absent or
 * fragment-less, a parent of some other shape, a document that currently
 * points at no generation, and a legacy grant that recorded no signer.
 *
 * The chain reading walks `proof.capabilityChain`, where the delegation
 * suite writes it: a grant a transient session minted embeds its parent, the
 * generation delegation, as the chain's last link; a grant delegated under
 * the Space root carries only the root's id string there.
 *
 * @param options {object}
 * @param options.zcap {IZcap}   the recorded full capability
 * @param [options.signerCheck] {AccountSignerCheck}
 * @param options.now {number}   epoch milliseconds
 * @returns {GrantRevocationRefusal | undefined}   undefined when the client
 *   cannot say why the server refused
 */
export function classifyGrantRevocationRefusal({
  zcap,
  signerCheck,
  now
}: {
  zcap: IZcap
  signerCheck?: AccountSignerCheck
  now: number
}): GrantRevocationRefusal | undefined {
  if (delegationAtExpiry({ zcap, now })) {
    return 'expired'
  }
  if (!signerCheck) {
    return undefined
  }
  const parent = embeddedParentCapability(zcap)
  if (parent === undefined) {
    const state = deriveGrantSignerState({
      signerKeyIds: [delegationProofKeyId(zcap)],
      accountDid: signerCheck.accountDid,
      currentSigningKeys: signerCheck.currentSigningKeys
    })
    return state === 'orphaned' ? 'orphaned' : undefined
  }
  if (delegationSignerGone({ zcap: parent, doc: signerCheck.doc })) {
    return 'signer-gone'
  }
  const { controller } = parent as { controller?: unknown }
  if (
    signerCheck.clientAnnexDid !== undefined &&
    typeof controller === 'string' &&
    isClientAnnexDid(controller) &&
    controller !== signerCheck.clientAnnexDid
  ) {
    return 'generation-swapped'
  }
  return undefined
}

/**
 * Submits the revocation of one recorded grant and classifies the server's
 * answer, the policy {@link revokeTreatingAlreadyRevokedAsSuccess} states
 * for a generation delegation. The one local skip is a grant whose own
 * `expires` is past by more than the revocation clock-skew margin
 * ({@link delegationExpired}). Everything else is POSTed, whatever the
 * caller's document says about the signer: the document a login read is a
 * snapshot. was-client's `AlreadyRevokedError` is success. A plain
 * `ValidationError` is read through {@link classifyGrantRevocationRefusal},
 * and rethrown when the client cannot say why. Every other failure is
 * rethrown. Errors are matched on `err.name`, since error classes do not
 * survive crossing package copies.
 *
 * @param options {object}
 * @param options.revoke {Function}   `(zcap) => Promise<void>` -- POSTs the
 *   revocation (`was.revoke`)
 * @param options.zcap {IZcap}   the recorded full capability
 * @param [options.signerCheck] {AccountSignerCheck}   read against the grant
 *   when the server refuses the POST
 * @param options.now {number}   epoch milliseconds
 * @returns {Promise<GrantRevocationOutcome>}
 */
export async function revokeRecordedGrant({
  revoke,
  zcap,
  signerCheck,
  now
}: {
  revoke: (zcap: IDelegatedZcap) => Promise<void>
  zcap: IZcap
  signerCheck?: AccountSignerCheck
  now: number
}): Promise<GrantRevocationOutcome> {
  if (delegationExpired({ zcap, now })) {
    return 'expired'
  }
  try {
    await revoke(zcap as unknown as IDelegatedZcap)
  } catch (err) {
    const name = (err as { name?: string } | null)?.name
    if (name === 'AlreadyRevokedError') {
      return 'already-revoked'
    }
    if (name === 'ValidationError') {
      const refusal = classifyGrantRevocationRefusal({ zcap, signerCheck, now })
      if (refusal !== undefined) {
        return refusal
      }
    }
    throw err
  }
  return 'revoked'
}

/**
 * The parent capability a delegation embeds as the last link of its
 * `proof.capabilityChain`, when the chain embeds one (an object rather than
 * an id string). A delegated zcap carries exactly one `capabilityDelegation`
 * proof, but the wire shape allows an array; the first proof is read.
 *
 * @param zcap {IZcap}
 * @returns {IZcap | undefined}
 */
export function embeddedParentCapability(zcap: IZcap): IZcap | undefined {
  const { proof } = zcap as { proof?: unknown }
  const single = Array.isArray(proof) ? proof[0] : proof
  if (!single || typeof single !== 'object') {
    return undefined
  }
  const chain = (single as { capabilityChain?: unknown }).capabilityChain
  if (!Array.isArray(chain) || chain.length === 0) {
    return undefined
  }
  const last: unknown = chain[chain.length - 1]
  return last !== null && typeof last === 'object' ? (last as IZcap) : undefined
}

/**
 * Whether a DID string is a client annex did:webvh, by the same parse
 * {@link clientAnnexDidParts} applies.
 *
 * @param did {string}
 * @returns {boolean}
 */
export function isClientAnnexDid(did: string): boolean {
  try {
    clientAnnexDidParts({ did })
    return true
  } catch {
    return false
  }
}
