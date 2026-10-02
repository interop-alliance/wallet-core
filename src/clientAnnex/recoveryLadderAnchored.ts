/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The transient-recovery continuation -- the ladder-anchored variant of the
 * recovery subpath's `recoverWebvhClient`, split out beside the rest of the
 * annex-anchored ceremonies: a code spent on a non-remembered browser mints
 * no enrolled client, and the ladder VM the fresh credential's own bind
 * publishes is what anchors the account, so it lands ladder-anchored, with
 * no enrolled client. The enrolled-client
 * continuation and the recovery-key inventory edits stay in
 * `recovery/recoveryWebvh.ts`.
 */
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import type { DIDDoc, DIDLog } from '@interop/did-method-webvh'
import {
  ladderVerificationMethod,
  withLogConflictRetry
} from '../webvh/didWebvh.js'
import {
  unlockKeyVerificationMethod,
  unlockKeyVmId,
  type UnlockKeyAgreementPublication
} from '../unlock/standingWebvh.js'
import {
  RECOVERY_CODE_SPEND_REFUSALS,
  recoveryContinuationOnce,
  spendOutcome
} from '../recovery/continuation.js'
import type {
  RecoveryCodeSpendStage,
  RecoveryLogStore,
  RecoveryPublicKeys,
  ReplacementRecoveryPublicKeys
} from '../recovery/continuation.js'
import type { BuiltOnHead } from '../webvh/builtOnHead.js'
import { ceremonyEvents } from '../ceremonyEvents.js'
import { log } from '../log.js'
import { ladderRung, ladderVmKeyMultibase } from '../webvh/ladderDerivation.js'
import { clientAnnexDidParts, servicesPointedAtClientAnnex } from './log.js'

/**
 * THE TRANSIENT-RECOVERY CONTINUATION (run by the code-derived client through
 * the delegated `did.jsonl` PUT, on a non-remembered browser): the
 * ladder-anchored variant of {@link recoverWebvhClient}. No enrolled client is
 * minted anywhere; the fresh credential's LADDER stands in for one, so the
 * account lands ladder-anchored, with no enrolled client. Two entries:
 *
 * 1. **Reveal + commit**: the code's update key joins `updateKeys` (its hash
 *    stands committed since issuance) and `nextKeyHashes` extends with the
 *    fresh ladder's rung-0 and rung-1 hashes (rung 0's own carry-over hash
 *    plus the staged rung, the ladder-anchored genesis configuration) and the
 *    replacement code's update-key hash.
 * 2. **Add + retire**, signed by the fresh ladder's rung 0: the ladder VM
 *    (the stable sibling, under `assertionMethod` and `capabilityDelegation`
 *    only) and the fresh credential's `keyAgreement` entry
 *    (commitment or verbatim -- the entry the mandatory rotation's recipient
 *    resolver will back the credential's standing wrap with) in; the
 *    replacement code's inventory in; the spent code's VM, update key, and hash
 *    out; and EVERY pre-recovery standing credential fully retired -- its
 *    ladder VM and its `keyAgreement` member both struck. The recognition is
 *    structural on both axes: `ladderVmIds` by the relation asymmetry, and
 *    `credentialKeyAgreementMethods` by the account-DID controller (an
 *    enrolled client's key-agreement method carries the client marker
 *    instead, so enrolled clients keep their pairs). Other unspent recovery
 *    codes fall under the same rule and are retired too: a code's
 *    `keyAgreement` member is unmarked and verbatim, indistinguishable from a
 *    passkey's, and a cold-browser recovery has no way to put the choice to
 *    the user. Each retired credential's whole update-key inventory goes in
 *    the same entry: the rung hashes it has standing in `nextKeyHashes`, and
 *    any rung of its own left revealed in `updateKeys`. The VM strike alone
 *    would rot only a ladder-signed bridge. A bridge minted by an enrolled
 *    client -- a passkey added, or a code issued, from a remembered session
 *    -- signs with that client's account key, and the client survives this
 *    entry, so the committed rung would stay revealable through it
 *    (`decisions/0014`). Each credential is anchored from the log alone, its
 *    `keyAgreement` member naming rung 0's hash (`ladderCommitment`), and one
 *    whose member names none is reported on `unclaimedCredentialVmIds`
 *    rather than struck. Its bridge stays live but
 *    inert: nothing revokes it, and it can extend nothing. Rung 0
 *    replaces the spent code's key in `updateKeys`. This same entry
 *    also points `#DelegatedClients` at the annex generation `onCommitted`
 *    minted. That is what the atomicity buys: the entry retires the
 *    pre-recovery credential's ladder VM, so a pointer written after it would
 *    leave a window in which the document names a generation no surviving
 *    record's sibling delegation targets, and neither credential could enroll
 *    a transient client.
 *
 * The entry is the ceremony-tail license's inventory-changing controller
 * version: the `keyAgreement` inventory set and the ladder-VM set both change
 * here, which is what licenses the caller's ONE ladder-signed roster append
 * (the mandatory rotation) carrying that controller version.
 *
 * `onCommitted` is the persist-before-publish seam: it runs after the
 * reveal-and-commit entry stands (so a revoked code has already been refused)
 * and BEFORE the add entry publishes the ladder VM -- the caller durably
 * writes the replacement code's record and the fresh credential's unlock
 * record there, so a tab death can never publish an anchor nobody can
 * derive. The ladder seed that record carries is not new at the seam: the
 * caller persisted it before the reveal entry (see the resume contract
 * below), and the seam is where the unlock record built around it becomes
 * durable. It must be idempotent: the conflict retry and a resumed run
 * invoke it again. It returns the fresh annex generation's DID,
 * which the add entry then points the `#DelegatedClients` service entry at.
 *
 * Resumable from durable state alone, like the enrolled-client continuation: a
 * completed run is detected by rung 0 already authorized; a torn one by the
 * standing commitments. Both detections are scoped to the ladder seed handed
 * in: the rung pair and the ladder VM derive from it, so a re-run with the
 * SAME seed finds its own reveal entry standing (the rung revealed and every
 * hash committed) and skips it, while a re-run with a freshly minted seed
 * derives a different rung 0 and publishes a second reveal entry that dedups
 * the replacement's hash away (the two-addition shape the readers in
 * `ladder.ts` keep recognizing for logs written that way). A caller
 * therefore persists the fresh ladder seed BEFORE the reveal entry and hands
 * the same seed back on a resume, with the head its persisted state recorded
 * as `resume.builtOnHead`. A resume that meets an already-complete
 * continuation takes the completed branch WITHOUT re-entering `onCommitted`,
 * so the caller must be able to treat it as success on its own.
 *
 * A fresh credential whose `keyAgreement` id already stands in the document
 * (the same passphrase re-typed) is refused before the reveal entry with
 * `RecoveryCredentialStandingError`: this entry retires every pre-recovery
 * credential, and one it re-bound instead would keep its old rung
 * commitments under a struck ladder VM.
 *
 * @param options {object}
 * @param options.store {RecoveryLogStore}   public log read + delegated PUT.
 *   Every read both entries are built on is checked against the store's
 *   chain-head pin (a served prefix is refused before the reveal entry lands,
 *   not only by a verify that follows both entries), and the pin advances to
 *   each entry as it publishes
 * @param options.recovery {object}   the spent code's update seed and public
 *   halves
 * @param options.recovery.updateSeed {Uint8Array}
 * @param options.recovery.keyAgreementKeyMultibase {string}
 * @param options.recovery.updateKeyMultibase {string}
 * @param options.ladderSeed {Uint8Array}   the FRESH credential's ladder seed
 *   (recovery binds a fresh passphrase, so the ladder exists at exactly this
 *   moment); rung 0, rung 1, and the ladder VM all derive from it. On a
 *   resume it is the seed the torn run persisted, verbatim, so the resumed
 *   run re-derives the torn run's rung pair and detects its reveal entry as
 *   already published rather than minting a second one
 * @param options.credentialKeyAgreement {UnlockKeyAgreementPublication}   the
 *   fresh credential's key-agreement publication (a commitment for a
 *   passphrase-derived key)
 * @param options.replacement {ReplacementRecoveryPublicKeys}   the
 *   replacement code's public halves -- its key-agreement key, its rung-0
 *   update key, and its ladder VM key -- committed and published in the same
 *   continuation
 * @param [options.expectedDid] {string}   the account DID the log must resolve
 *   to, where the recovering flow already knows it
 * @param options.onCommitted {function}
 *   `(committed: { builtOnHead: { scid, versionId } }) =>
 *   Promise<{ clientAnnexDid: string }>` -- the persist-before-publish seam
 *   described above. Both the seam and the annex DID it returns are
 *   REQUIRED: the add entry points the `#DelegatedClients` service entry at
 *   it, and a caller that named no generation would republish the stranding
 *   this ordering exists to prevent. `builtOnHead` is the head of the log
 *   snapshot the add entry is about to be built on (the SCID and the latest
 *   entry's `versionId`), which a resume hands back as `resume.builtOnHead`
 * @param [options.resume] {object}   `{ builtOnHead: { scid, versionId } }`
 *   -- the resume marker the torn run's persisted state recorded, beside the
 *   ladder seed handed in as `ladderSeed`. Supplied, each attempt's first read
 *   is refused with `BuiltOnHeadNotReachedError` unless the served log carries
 *   that SCID and an entry with that `versionId`, as the self-enrollment
 *   resume is. The marker guards the head alone: a resume must also pass the
 *   SAME `replacement` halves back, since a fresh replacement would publish a
 *   reveal entry of its own for the new hash (the abandoned one is struck at
 *   the add entry). The chain-head pin cannot stand in for it: a transient visit's
 *   pin is in-memory and gone with the tab, so the marker is the only fork
 *   guard a resumed spend holds. Both members must be non-empty strings; a
 *   malformed marker is refused with a `TypeError` before any read
 * @returns {Promise<object>}   the account DID, the post-continuation
 *   document and log (the rotation's recipient source and anchor), the
 *   `keyAgreement` verification-method ids this entry struck for
 *   pre-recovery credentials OTHER than the spent code
 *   (`retiredCredentialVmIds` -- what the caller drops registry entries and
 *   deletes unlock Spaces for; on a resumed run whose add entry already
 *   landed it is derived from the log, so the resume reports the same list
 *   the first run did), `committed` -- whether THIS call published the add
 *   entry (`false` exactly on the completed branch, where a torn earlier run
 *   had already published it and `onCommitted` was not entered; a returning
 *   call means the continuation stands either way), and, when the add entry
 *   ran here, the final `did.json` projection
 */
export async function recoverWebvhLadderAnchored(options: {
  store: RecoveryLogStore
  recovery: RecoveryPublicKeys & { updateSeed: Uint8Array }
  ladderSeed: Uint8Array
  credentialKeyAgreement: UnlockKeyAgreementPublication
  replacement: ReplacementRecoveryPublicKeys
  expectedDid?: string
  onCommitted: (committed: {
    builtOnHead: BuiltOnHead
  }) => Promise<{ clientAnnexDid: string }>
  resume?: { builtOnHead: BuiltOnHead }
}): Promise<{
  did: string
  doc: DIDDoc
  log: DIDLog
  retiredCredentialVmIds: string[]
  struckRungHashes: string[]
  unclaimedCredentialVmIds: string[]
  webDoc?: object
  committed: boolean
}> {
  // The seam is what makes the fresh credential's and replacement code's
  // material durable before the add entry publishes the ladder VM; a call
  // omitting it would republish the stranding this ordering exists to
  // prevent. Refused before any read, so nothing is published.
  if (typeof options.onCommitted !== 'function') {
    throw new TypeError(
      'recoverWebvhLadderAnchored requires onCommitted: the replacement ' +
        'code and the fresh credential record must be persisted before the ' +
        'add entry publishes the ladder VM.'
    )
  }
  const {
    ladderSeed,
    credentialKeyAgreement,
    onCommitted,
    resume,
    expectedDid,
    ...shared
  } = options
  // The fresh ladder: rung 0 is the successor key the add entry authorizes
  // and signs with, rung 1 its staged partner (the ladder-anchored genesis
  // configuration), and the VM the stable sibling the entry installs.
  const [rung0, rung1, ladderVmKey] = await Promise.all([
    ladderRung({ ladderSeed, index: 0 }),
    ladderRung({ ladderSeed, index: 1 }),
    ladderVmKeyMultibase({ ladderSeed })
  ])
  // The fresh credential's member names its own rung 0, which the reveal
  // entry commits first among its additions and the add entry reveals.
  const ladderCommitment = await deriveNextKeyHash(rung0.keyMultibase)
  // One run outside the conflict retry, on the recovery subpath's stage
  // vocabulary. This path is transient, so no event carries an account
  // identifier, and nothing derived from the code or the fresh credential.
  const events = ceremonyEvents<RecoveryCodeSpendStage>({
    ceremony: 'recovery-code-spend',
    log,
    refusals: RECOVERY_CODE_SPEND_REFUSALS
  })
  const outcome = await events.run(
    () =>
      withLogConflictRetry(() =>
        recoveryContinuationOnce({
          ...shared,
          successor: {
            updateKeyMultibase: rung0.keyMultibase,
            updateSeed: rung0.seed,
            stagedKeyMultibase: rung1.keyMultibase
          },
          // The persist-before-publish seam: the replacement code's record and
          // the fresh credential's unlock record become durable HERE, before
          // the add entry publishes the ladder VM. The ladder seed itself was
          // persisted before the reveal entry; the seam hands back the head a
          // resume presents as `resume.builtOnHead`.
          onCommitted,
          // A passphrase the account already stands on is refused before the
          // reveal entry: this continuation retires that credential, and
          // re-binding it would leave its old rungs standing under a new VM.
          credentialVmIds: did => [
            unlockKeyVmId({ did, keyAgreement: credentialKeyAgreement })
          ],
          // The ladder VM (under the relation asymmetry: `assertionMethod` and
          // `capabilityDelegation` only -- no `authentication`, no
          // `capabilityInvocation` -- which is also what keeps it out of every
          // client listing) and the fresh credential's keyAgreement inventory in;
          // the core appends the replacement code's after them. Atomic with the
          // retirement: the `#DelegatedClients` pointer and the ladder-VM set
          // change in one entry, so no window exists in which the document
          // points at a generation the surviving record cannot reach.
          added: ({ did, doc, persisted }) => {
            // Refuses a malformed pointer target before the entry is built.
            clientAnnexDidParts({ did: persisted.clientAnnexDid })
            const ladderVmId = `${did}#${ladderVmKey}`
            const credentialVmId = unlockKeyVmId({
              did,
              keyAgreement: credentialKeyAgreement
            })
            return {
              methods: [
                ladderVerificationMethod({
                  controller: did,
                  publicKeyMultibase: ladderVmKey
                }),
                unlockKeyVerificationMethod({
                  did,
                  keyAgreement: credentialKeyAgreement,
                  ladderCommitment
                })
              ],
              assertionMethod: [ladderVmId],
              keyAgreement: [credentialVmId],
              capabilityDelegation: [ladderVmId],
              services: servicesPointedAtClientAnnex({
                doc,
                accountDid: did,
                clientAnnexDid: persisted.clientAnnexDid
              })
            }
          },
          ...(resume !== undefined ? { builtOnHead: resume.builtOnHead } : {}),
          ...(expectedDid !== undefined ? { expectedDid } : {}),
          events
        })
      ),
    spendOutcome
  )
  return outcome
}
