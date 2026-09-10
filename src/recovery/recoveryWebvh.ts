/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The did:webvh half of recovery-code lifecycle: the split configuration a
 * code holds as a standing unlock credential that retires on spend. At
 * issuance the document gains the code's `keyAgreement` verification method
 * (an ordinary Multikey entry -- deliberately unmarked; a recovery key is
 * distinguishable structurally, since it appears under `keyAgreement` and
 * `assertionMethod`/`capabilityDelegation` while every enrolled client also
 * publishes an invocation relationship, so client listings key on
 * `capabilityInvocation` and never see it), the code's ladder VM, and its
 * rung-0 hash in `nextKeyHashes` -- decryption and delegation standing,
 * update authority latent: rung 0 joins `updateKeys` nowhere, and every key
 * of the set exists nowhere until the code is typed.
 *
 * At recovery time the pre-committed rung 0 reveals itself to sign the
 * self-enrolling continuation, two entries:
 *
 * 1. **Reveal + commit**: rung 0 joins `updateKeys` (its hash stands
 *    committed since issuance, which is what makes the entry verify -- the
 *    ordinary ladder reveal) and `nextKeyHashes` extends with the NEW
 *    ordinary client's update- and staged-key hashes plus the replacement
 *    code's rung-0 hash.
 * 2. **Add + retire**: signed by the new client's update key (revealed from
 *    the commit), this entry publishes the new client's verification methods
 *    and update key, removes the spent code's `keyAgreement` VM and its
 *    ladder VM (with every other standing credential's, by the relation
 *    asymmetry), publishes the replacement code's inventory, and drops the
 *    spent code's revealed rung and its hash -- so no recovery authority
 *    stands afterwards.
 *
 * Both entries are written through the caller's store seam; the recovery
 * continuation publishes ONLY `did.jsonl` (the delegation the record carries
 * covers nothing else -- narrow scope preserves loudness), and hands back the
 * final `webDoc` so the recovered session can republish `did.json` once it is
 * the authorized controller. Every step is idempotent/resumable: re-running
 * with the same key material converges without forking the log.
 */
import type { DIDDoc, DIDLog } from '@interop/did-method-webvh'
import {
  assertCanonicalClientKeys,
  clientAdditionFields,
  withLogConflictRetry
} from '../webvh/didWebvh.js'
import type {
  ClientWebvhUpdateKeys,
  WebvhEnrollmentKeys,
  WebvhIdStore
} from '../webvh/didWebvh.js'
import { publishUnlockKey, removeUnlockKey } from '../unlock/standingWebvh.js'
import type { UnlockInventoryPart } from '../unlock/standingWebvh.js'
import type { AccountLogSigner } from '../webvh/accountEntry.js'
import { recoveryContinuationOnce } from './continuation.js'
import type {
  RecoveryLogStore,
  RecoveryPublicKeys,
  ReplacementRecoveryPublicKeys
} from './continuation.js'

// The continuation's shared core and the names both variants read live in
// `continuation.ts`; this module stays their public home.
export {
  RecoveryCredentialStandingError,
  RecoveryKeyNotCommittedError,
  recoveryVmId,
  retiredCredentialVmIdsFromLog
} from './continuation.js'
export type {
  RecoveryLogStore,
  RecoveryPublicKeys,
  ReplacementRecoveryPublicKeys
} from './continuation.js'

/**
 * ISSUANCE: publishes a recovery code's split configuration into the
 * document -- the code's `keyAgreement` verification method (an ordinary,
 * unmarked Multikey entry, the key published verbatim: a code is
 * high-entropy, so no commitment is needed), its rung-0 hash committed in
 * `nextKeyHashes`, and its ladder VM. The code's update key joins
 * `updateKeys` nowhere. A thin wrapper over the
 * standing unlock-key inventory core ({@link publishUnlockKey}), which owns
 * idempotence and the conditional publish.
 *
 * `part` is how the ladder branch splits the entry so the code's decryption
 * material precedes its authority: a key entry (`'key'`), then the escrow,
 * then an authority entry (`'authority'`) carrying the ladder VM and the
 * rung-0 commitment. An enrolled client's issuance escrows before the entry
 * and writes the merged `'all'` entry.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.signer {AccountLogSigner}   who signs the entry: the ISSUING
 *   client's own did:webvh update-key seeds, or the acting credential's
 *   ladder seed
 * @param options.recovery {RecoveryPublicKeys}   the code's public halves
 * @param options.ladderSeed {Uint8Array}   the code's OWN ladder seed,
 *   derived from the code bytes (`recoveryClientFromCode`). The entry
 *   installs that ladder's VM, and `recovery.updateKeyMultibase` is its
 *   rung 0
 * @param [options.part] {string}   `'all'` (the default), `'key'`, or
 *   `'authority'` -- see above
 * @param [options.expectedDid] {string}   the account DID the log must
 *   resolve to, from the caller's stored account pointer. The read runs under
 *   the store's own chain-head pin: a served log that is a rollback, a fork,
 *   or an identity switch against the pinned head is refused
 *   (`ResourceLogContinuityError`)
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}   the account
 *   DID and the document and log as this call leaves them
 */
export async function publishRecoveryKey({
  idStore,
  signer,
  recovery,
  ladderSeed,
  part,
  expectedDid
}: {
  idStore: WebvhIdStore
  signer: AccountLogSigner
  recovery: RecoveryPublicKeys
  ladderSeed: Uint8Array
  part?: UnlockInventoryPart
  expectedDid?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  return publishUnlockKey({
    idStore,
    signer,
    unlockKeys: {
      keyAgreement: {
        publicKeyMultibase: recovery.keyAgreementKeyMultibase
      },
      updateKeyMultibase: recovery.updateKeyMultibase
    },
    // Every code carries a ladder, so the authority half of its inventory is
    // that ladder's VM beside the rung-0 commitment.
    ladderSeed,
    ...(part !== undefined ? { part } : {}),
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    verb: 'issuing a recovery code'
  })
}

/**
 * REVOCATION: removes a recovery code's whole inventory from the document --
 * its `keyAgreement` verification method, its committed rung-0 hash, and its
 * ladder VM -- in one entry, through the same shared inventory core
 * ({@link removeUnlockKey}). The roster-side half (rotating the user key
 * epoch off the code's wrap) is the caller's, and runs after this so the
 * resolver's document no longer backs the removed entry.
 *
 * The revoker holds neither the code bytes nor its ladder seed, so the VM
 * claim is seedless: the removal attributes it from the log, anchored on the
 * rung-0 update-key multibase the registry recorded at issuance
 * (`recovery.updateKeyMultibase`). The claim is required rather than
 * best-effort. A VM no attribution arm claims refuses the whole revocation
 * with `UnclaimedLadderVmRetirementError` before anything is written, since a
 * standing ladder VM whose credential is otherwise retired keeps its
 * delegation authority -- including the DELETE-only capability on the account
 * Space that the account-deletion ceremony mints.
 *
 * @param options {object}   see {@link publishRecoveryKey}, except that
 *   `ladderSeed` is optional here: a revoking client does not hold it, and
 *   the code's own holder is the only party who can supply it
 * @param [options.projectionStore] {object}   an `id`-collection store the
 *   caller may write through, passed straight to the inventory edit: the
 *   post-strike `did:web` projection is PUT through it immediately before
 *   that entry publishes, so a ladder-signed revocation does not leave
 *   `did.json` naming the revoked code. Best-effort, and omitted the
 *   behavior is unchanged (see `removeUnlockKey`)
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}   see
 *   {@link publishRecoveryKey}
 */
export async function removeRecoveryKey({
  idStore,
  signer,
  recovery,
  ladderSeed,
  projectionStore,
  expectedDid
}: {
  idStore: WebvhIdStore
  signer: AccountLogSigner
  recovery: RecoveryPublicKeys
  ladderSeed?: Uint8Array
  projectionStore?: Pick<WebvhIdStore, 'getIdResourceRaw' | 'putIdResource'>
  expectedDid?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  return removeUnlockKey({
    idStore,
    signer,
    unlockKeys: {
      keyAgreement: {
        publicKeyMultibase: recovery.keyAgreementKeyMultibase
      },
      updateKeyMultibase: recovery.updateKeyMultibase
    },
    ...(ladderSeed ? { ladderSeed } : {}),
    ...(projectionStore ? { projectionStore } : {}),
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    verb: 'revoking a recovery code'
  })
}

/**
 * RECOVERY (run by the code-derived client through the delegated `did.jsonl`
 * PUT): writes the self-enrolling continuation described in the module doc --
 * the reveal-and-commit entry signed by the code's pre-committed update key,
 * then the add-and-retire entry signed by the new ordinary client's update
 * key. Resumable from durable state alone: a completed continuation is
 * detected by the new client's update key already being authorized (no-op),
 * a torn one by the standing commitments (the commit step re-runs
 * convergently -- the spent code's hash is deliberately carried through the
 * commit entry, so a resumed commit can re-state the revealed key). Both
 * entries publish conditionally on the read they were built on, and a race
 * lost to a concurrent ceremony re-runs the continuation from the top -- the
 * same resumable path a tear takes.
 *
 * @param options {object}
 * @param options.store {RecoveryLogStore}   public log read + delegated PUT
 * @param options.recovery {object}   the spent code's update seed and public
 *   halves
 * @param options.recovery.updateSeed {Uint8Array}
 * @param options.recovery.keyAgreementKeyMultibase {string}
 * @param options.recovery.updateKeyMultibase {string}
 * @param options.newClientKeys {WebvhEnrollmentKeys}   the new ordinary
 *   client's public halves
 * @param options.newClientUpdateSeeds {ClientWebvhUpdateKeys}   the new
 *   client's update-key seeds (minted by the recovery flow, which therefore
 *   holds them and can sign the add entry)
 * @param options.replacement {ReplacementRecoveryPublicKeys}   the
 *   replacement code's public halves -- its key-agreement key, its rung-0
 *   update key, and its ladder VM key -- committed and published in the same
 *   continuation
 * @param options.onCommitted {function}
 *   `(committed: { builtOnHead: { scid, versionId } }) => Promise<void>` --
 *   the REQUIRED persist-before-publish seam. It runs once per attempt, after
 *   the reveal-and-commit entry stands (published here, or standing from a
 *   torn earlier run) and BEFORE the add-and-retire entry -- the ceremony's
 *   pivot -- is built. The caller persists the successor material there
 *   (the `pending` codec group of `keys/clientKeyRecord.ts`: ceremony
 *   `'recovery-spend'`, the handed-back `builtOnHead`, the spent code's
 *   unwrap key, the replacement code's bytes), so the pivot can never retire
 *   the spent code while its successors exist only in tab memory, per the
 *   post-pivot derivability rule (`decisions/0010`). Unlike the transient
 *   continuation's seam it returns nothing into the entry: the remembered spend
 *   has no annex pointer to move. A throw propagates and the add-and-retire
 *   entry is withheld -- the code stays unspent, and a re-run with the same
 *   code converges. The seam must be idempotent: the conflict retry invokes
 *   it again. The caveat to hold on to: the idempotent COMPLETED branch (the
 *   new client's update key already authorized) returns without ever
 *   entering the seam. A re-run after a tear here MUST pass the SAME
 *   `replacement` halves back in, re-derived from the persisted replacement
 *   code's bytes -- the reveal entry already committed that code's update-key
 *   hash, and a re-run minting a fresh replacement would leave the first
 *   one's commitment standing forever with no `keyAgreement` method behind
 *   it: a code the commitment check accepts but that decrypts nothing. With
 *   the halves reused, the only residue of a torn or abandoned run is the
 *   never-published CLIENT's committed hashes, inert orphans in
 *   `nextKeyHashes` exactly as on the self-enrollment seam (keys of a lost
 *   random seed; nothing can reveal them)
 * @param [options.expectedDid] {string}   the account DID the log must resolve
 *   to, where the recovering flow already knows it. Every read both entries
 *   are built on is checked against the store's own chain-head pin (a served
 *   prefix is refused before the reveal entry lands, not only by a verify
 *   that follows both entries), and the pin advances to each entry as it
 *   publishes
 * @returns {Promise<object>}
 *   the account DID, the final `did.json` projection when the add-and-retire
 *   entry ran here, and `committed` -- whether THIS call published the pivot
 *   entry (`false` exactly on the idempotent completed branch, where a torn
 *   earlier run had already published it). It is an observability signal, not
 *   a success flag: a returning call means the continuation stands either
 *   way, so a caller clears its pending state on the RETURN, whatever
 *   `committed` says. Its absence from a return value is a build skew, which
 *   is why it is stated rather than inferred.
 *   `retiredCredentialVmIds` lists the `keyAgreement` verification-method ids
 *   this entry struck for pre-recovery credentials OTHER than the spent code
 *   -- what the caller drops registry entries and deletes unlock Spaces for.
 *   On the completed branch, whose entry already landed, it is derived from
 *   the log, so a resume reports the same list the first run did
 */
export async function recoverWebvhClient(options: {
  store: RecoveryLogStore
  recovery: RecoveryPublicKeys & { updateSeed: Uint8Array }
  newClientKeys: WebvhEnrollmentKeys
  newClientUpdateSeeds: ClientWebvhUpdateKeys
  replacement: ReplacementRecoveryPublicKeys
  onCommitted: (committed: {
    builtOnHead: { scid: string; versionId: string }
  }) => Promise<void>
  expectedDid?: string
}): Promise<{
  did: string
  webDoc?: object
  committed: boolean
  retiredCredentialVmIds: string[]
  struckRungHashes: string[]
  unclaimedCredentialVmIds: string[]
}> {
  // The seam is what gets the successor material persisted before the pivot
  // entry retires the spent code; a call omitting it would silently keep the
  // window in which the document names successors nothing can re-derive.
  // Refused before any read, so nothing is published.
  if (typeof options.onCommitted !== 'function') {
    throw new TypeError(
      'recoverWebvhClient requires onCommitted: the successor material must ' +
        'be persisted before the add-and-retire entry retires the spent code.'
    )
  }
  // A non-canonical pair could only ever throw at the add-and-retire build,
  // AFTER the reveal entry published and the seam persisted; refused here,
  // nothing is published or persisted.
  assertCanonicalClientKeys({
    signingKeyMultibase: options.newClientKeys.signingKeyMultibase,
    keyAgreementKeyMultibase: options.newClientKeys.keyAgreementKeyMultibase
  })
  const {
    newClientKeys,
    newClientUpdateSeeds,
    onCommitted,
    expectedDid,
    ...shared
  } = options
  const outcome = await withLogConflictRetry(() =>
    recoveryContinuationOnce({
      ...shared,
      successor: {
        updateKeyMultibase: newClientKeys.updateKeyMultibase,
        updateSeed: newClientUpdateSeeds.updateSeed,
        stagedKeyMultibase: newClientKeys.stagedUpdateKeyMultibase
      },
      onCommitted,
      // The new client's verification methods and update key in. A three-way
      // controller split: the new client's signing method and the replacement
      // code's key-agreement method are controlled by the account; the new
      // client's key-agreement method alone carries the controller marker
      // (see clientKeyAgreementController) -- which is exactly what tells the
      // two simultaneously published keyAgreement methods apart. The marked
      // pair and its relation membership come from the shared add-side
      // builder, which refuses a new client whose key-agreement key is not
      // its signing key's canonical twin; the core appends the replacement
      // code's unmarked method after it.
      added: ({ did }) => {
        const { methods, relations } = clientAdditionFields({
          controller: did,
          signingKeyMultibase: newClientKeys.signingKeyMultibase,
          keyAgreementKeyMultibase: newClientKeys.keyAgreementKeyMultibase
        })
        return { methods, ...relations }
      },
      ...(expectedDid !== undefined ? { expectedDid } : {})
    })
  )
  // The document and log stay inside: the remembered session re-verifies
  // the log for itself once it is the controller.
  const { doc: _doc, log: _log, ...rest } = outcome
  return rest
}
