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

import { parseVersionedVm } from '@interop/vh-resource-log'
import { delegationSignerKeyReader } from '../webvh/index.js'
import type { PublishedKeyDocument } from '../webvh/index.js'

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
 * against the keys the account's locally verified did:webvh document
 * currently publishes under `capabilityDelegation`. Each signer is read
 * through `delegationSignerKey` (`webvh`), the one reader every
 * delegation-signer check shares, so the document itself is taken rather
 * than a key set a caller built by some other rule, and a grant signed under
 * the did:key form of a still-listed key stays active.
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
 * @param [options.doc] {PublishedKeyDocument}   the locally verified account
 *   document, or undefined when none is available
 * @returns {GrantSignerState}
 */
export function deriveGrantSignerState({
  signerKeyIds,
  accountDid,
  doc
}: {
  signerKeyIds: Array<string | undefined>
  accountDid: string
  doc?: PublishedKeyDocument
}): GrantSignerState {
  if (!doc) {
    return 'unknown'
  }
  const signers = signerKeyIds.filter(
    (keyId): keyId is string => keyId !== undefined
  )
  if (signers.length === 0) {
    return 'unknown'
  }
  const signerKey = delegationSignerKeyReader({ doc })
  let accountSigners = 0
  for (const keyId of signers) {
    // Split the way the reader splits it, so the two cannot disagree on
    // which DID an id is under.
    const did = parseVersionedVm(keyId)?.did
    if (
      did === undefined ||
      (did !== accountDid && !did.startsWith('did:key:'))
    ) {
      continue
    }
    accountSigners += 1
    if (signerKey(keyId) !== undefined) {
      return 'active'
    }
  }
  return accountSigners > 0 ? 'orphaned' : 'unknown'
}
