/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The grant-state check a connected-apps surface runs over a recorded
 * delegation's signer: whether the grants an app or agent holds still verify
 * under the current-key-set rule (a delegation verifies iff its verification
 * method is in the account document as resolved now).
 *
 * The check reads the account document alone, so it can only answer for a
 * signer that document ever listed: an enrolled client's key, under its
 * did:key form (`did:key:<mb>#<mb>`) or its promoted form
 * (`<accountDid>#<mb>`). A grant minted from a transient session is signed
 * by a client-annex per-visit key (`<clientAnnexDid>#<vm>`), which the account
 * document never lists by design: its chain runs one delegation deeper, under
 * the generation delegation, and stays alive until that delegation expires
 * or the generation is collected. Neither event is visible in the account
 * document, so such a signer derives as `unknown` rather than as `orphaned` --
 * "absent from the account document" is the annex's normal state, not
 * evidence that a wallet client was disconnected. Whether such a chain is
 * still alive is settled by the revocation POST itself; a refusal is then
 * read by `classifyGrantRevocationRefusal` in
 * `clientAnnex/grantRevocation.ts`, which checks the annex-signed grant's
 * embedded generation delegation instead: its signer, and the generation it
 * names.
 */

/**
 * Whether a set of recorded grants still verifies under the current-key-set
 * rule:
 *
 * - `active` -- at least one recorded grant was signed by a verification
 *   method the account document currently publishes.
 * - `orphaned` -- every recorded signer was an enrolled client's key, and
 *   none is in the current document: the wallet client that minted the
 *   grants has since been disconnected, so every grant stopped verifying
 *   with that document edit. The grantee must reconnect to be usable again.
 * - `unknown` -- the document cannot decide: no signers were recorded, no
 *   verified document is available, or every non-current signer is a
 *   client-annex per-visit key the document never lists.
 */
export type GrantSignerState = 'active' | 'orphaned' | 'unknown'

/**
 * Derives the {@link GrantSignerState} of a set of recorded delegation signers
 * against the enrolled clients' signing keys the account's locally verified
 * did:webvh document currently publishes. Matching is on the key-multibase
 * fragment, so a grant signed under the did:key form of a still-enrolled
 * client's key stays active.
 *
 * A signer is judged against the document only when the document could have
 * listed it: its DID is the account DID or a did:key. Any other signer (a
 * client annex's did:webvh) was never in the document, so its absence says
 * nothing, and a row whose every non-current signer is of that kind derives
 * as `unknown`.
 *
 * @param options {object}
 * @param options.signerKeyIds {Array<string | undefined>}   each recorded
 *   grant's `proof.verificationMethod`; undefined for a summary-only record
 * @param options.accountDid {string}   the account's did:webvh, the DID an
 *   enrolled client's promoted verification-method id is under
 * @param [options.currentSigningKeys] {Set<string>}   the enrolled clients'
 *   signing-key multibases, or undefined when no verified document is
 *   available
 * @returns {GrantSignerState}
 */
export function deriveGrantSignerState({
  signerKeyIds,
  accountDid,
  currentSigningKeys
}: {
  signerKeyIds: Array<string | undefined>
  accountDid: string
  currentSigningKeys?: Set<string>
}): GrantSignerState {
  if (!currentSigningKeys) {
    return 'unknown'
  }
  const signers = signerKeyIds.filter(
    (keyId): keyId is string => keyId !== undefined
  )
  if (signers.length === 0) {
    return 'unknown'
  }
  let accountSigners = 0
  for (const keyId of signers) {
    const hash = keyId.indexOf('#')
    if (hash < 0) {
      continue
    }
    const did = keyId.slice(0, hash)
    if (did !== accountDid && !did.startsWith('did:key:')) {
      continue
    }
    accountSigners += 1
    if (currentSigningKeys.has(keyId.slice(hash + 1))) {
      return 'active'
    }
  }
  return accountSigners > 0 ? 'orphaned' : 'unknown'
}
