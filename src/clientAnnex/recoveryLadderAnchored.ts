/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The transient-recovery continuation -- the ladder-anchored variant of the
 * recovery subpath's `recoverWebvhClient`, split out beside the rest of the
 * annex-anchored ceremonies: a code spent on a non-remembered browser mints
 * no enrolled client, and the ladder VM the fresh credential's own bind
 * publishes is what anchors the account, so it lands client-less and
 * ladder-anchored. The enrolled-client
 * continuation and the recovery-key inventory edits stay in
 * `recovery/recoveryWebvh.ts`.
 */
import { deriveNextKeyHash, updateDID } from '@interop/did-method-webvh'
import type {
  DIDDoc,
  DIDLog,
  VerificationMethod
} from '@interop/did-method-webvh'
import {
  assertCarryOverCommitments,
  ladderVerificationMethod,
  MULTIKEY_VM_TYPE,
  pinOfLog,
  relationIds,
  updateKeySigner,
  withLogConflictRetry
} from '../webvh/didWebvh.js'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import { ladderVmIds } from '../webvh/listClients.js'
import { credentialKeyAgreementMethods } from '../webvh/keyAgreement.js'
import {
  unlockKeyVerificationMethod,
  unlockKeyVmId,
  type UnlockKeyAgreementPublication
} from '../unlock/standingWebvh.js'
import {
  publishLogOnly,
  readLogOrThrow,
  RecoveryKeyNotCommittedError,
  recoveryVmId,
  retiredCredentialVmIdsFromLog,
  type RecoveryLogStore,
  type RecoveryPublicKeys
} from '../recovery/recoveryWebvh.js'
import {
  assertNextKeyHashesRemain,
  attributeRetiredCredentialRungs,
  ladderRung,
  ladderVmKeyMultibase,
  retiredCredentialRungsBeforeKey
} from './ladder.js'
import { clientAnnexDidParts, servicesPointedAtClientAnnex } from './log.js'

/**
 * THE TRANSIENT-RECOVERY CONTINUATION (run by the code-derived client through
 * the delegated `did.jsonl` PUT, on a non-remembered browser): the
 * ladder-anchored variant of {@link recoverWebvhClient}. No enrolled client is
 * minted anywhere; the fresh credential's LADDER stands in for one, so the
 * account lands client-less and ladder-anchored. Two entries:
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
 *    bind entry naming rung 0, and an ambiguous one is reported on
 *    `unclaimedCredentialVmIds` rather than struck. Its bridge stays live but
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
 * record (the ladder seed inside) there, so a tab death can never publish an
 * anchor nobody can derive. It must be idempotent: the conflict retry and a
 * resumed run invoke it again. It returns the fresh annex generation's DID,
 * which the add entry then points the `#DelegatedClients` service entry at.
 *
 * Resumable from durable state alone, like the enrolled-client continuation: a
 * completed run is detected by rung 0 already authorized; a torn one by the
 * standing commitments. Note what the completion detection is scoped to: a
 * caller that mints its ladder seed per call (freewallet's does) can only hit
 * the completed branch inside this call's own conflict retry, since a later
 * process derives a different rung 0 and re-runs the whole continuation. A
 * caller that persists its ladder seed and resumes across processes takes the
 * completed branch WITHOUT re-entering `onCommitted`, so it must be able to
 * treat an already-complete continuation as success on its own.
 *
 * @param options {object}
 * @param options.store {RecoveryLogStore}   public log read + delegated PUT
 * @param options.recovery {object}   the spent code's update seed and public
 *   halves
 * @param options.recovery.updateSeed {Uint8Array}
 * @param options.recovery.keyAgreementKeyMultibase {string}
 * @param options.recovery.updateKeyMultibase {string}
 * @param options.ladderSeed {Uint8Array}   the FRESH credential's ladder seed
 *   (recovery binds a fresh passphrase, so the ladder exists at exactly this
 *   moment); rung 0, rung 1, and the ladder VM all derive from it
 * @param options.credentialKeyAgreement {UnlockKeyAgreementPublication}   the
 *   fresh credential's key-agreement publication (a commitment for a
 *   passphrase-derived key)
 * @param options.replacement {RecoveryPublicKeys}   the replacement code's
 *   public halves, committed and published in the same continuation
 * @param [options.expectedDid] {string}   the account DID the log must resolve
 *   to, where the recovering flow already knows it
 * @param options.onCommitted {function}
 *   `() => Promise<{ clientAnnexDid: string }>` -- the persist-before-publish
 *   seam described above. Both the seam and the annex DID it returns are
 *   REQUIRED: the add entry points the `#DelegatedClients` service entry at
 *   it, and a caller that named no generation would republish the stranding
 *   this ordering exists to prevent
 * @param [options.pinStore] {ResourceLogPinStore}   this caller's chain-head
 *   pins; every read both entries are built on is checked against the pinned
 *   head (a served prefix is refused before the reveal entry lands, not only
 *   by a verify that follows both entries), and the pin advances to each
 *   entry as it publishes
 * @param [options.logId] {string}   the account log's pin slot
 *   (`accountLogPinId({ spaceId })`); required whenever a `pinStore` is
 *   supplied
 * @returns {Promise<object>}   the account DID, the post-continuation
 *   document and log (the rotation's recipient source and anchor), the
 *   `keyAgreement` verification-method ids this entry struck for
 *   pre-recovery credentials OTHER than the spent code
 *   (`retiredCredentialVmIds` -- what the caller drops registry entries and
 *   deletes unlock Spaces for; on a resumed run whose add entry already
 *   landed it is derived from the log, so the resume reports the same list
 *   the first run did), and, when the add entry ran here, the final
 *   `did.json` projection
 */
export async function recoverWebvhLadderAnchored(options: {
  store: RecoveryLogStore
  recovery: RecoveryPublicKeys & { updateSeed: Uint8Array }
  ladderSeed: Uint8Array
  credentialKeyAgreement: UnlockKeyAgreementPublication
  replacement: RecoveryPublicKeys
  expectedDid?: string
  onCommitted: () => Promise<{ clientAnnexDid: string }>
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{
  did: string
  doc: DIDDoc
  log: DIDLog
  retiredCredentialVmIds: string[]
  struckRungHashes: string[]
  unclaimedCredentialVmIds: string[]
  webDoc?: object
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
  return withLogConflictRetry(() => recoverWebvhLadderAnchoredOnce(options))
}

/**
 * One attempt of {@link recoverWebvhLadderAnchored}, re-invoked by the
 * conflict retry.
 *
 * @param options {object}   see {@link recoverWebvhLadderAnchored}
 * @returns {Promise<object>}   see {@link recoverWebvhLadderAnchored}
 */
async function recoverWebvhLadderAnchoredOnce({
  store,
  recovery,
  ladderSeed,
  credentialKeyAgreement,
  replacement,
  expectedDid,
  onCommitted,
  pinStore,
  logId
}: {
  store: RecoveryLogStore
  recovery: RecoveryPublicKeys & { updateSeed: Uint8Array }
  ladderSeed: Uint8Array
  credentialKeyAgreement: UnlockKeyAgreementPublication
  replacement: RecoveryPublicKeys
  expectedDid?: string
  onCommitted: () => Promise<{ clientAnnexDid: string }>
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{
  did: string
  doc: DIDDoc
  log: DIDLog
  retiredCredentialVmIds: string[]
  struckRungHashes: string[]
  unclaimedCredentialVmIds: string[]
  webDoc?: object
}> {
  // Each attempt's own read is what the CAS publish is built on, so the
  // continuity check runs here -- and again on a conflict-retry re-run -- not
  // only on the verify that follows both entries.
  const pinned = {
    ...(pinStore ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {})
  }
  let published = await readLogOrThrow({
    store,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...pinned
  })

  const rung0 = await ladderRung({ ladderSeed, index: 0 })
  const rung1 = await ladderRung({ ladderSeed, index: 1 })
  const ladderVmKey = await ladderVmKeyMultibase({ ladderSeed })
  // Derived before the completion check, because a resume recomputes the
  // strike with the same protected sets the first run used.
  const recoveryHash = await deriveNextKeyHash(recovery.updateKeyMultibase)
  const rung0Hash = await deriveNextKeyHash(rung0.keyMultibase)
  const rung1Hash = await deriveNextKeyHash(rung1.keyMultibase)
  const replacementHash = await deriveNextKeyHash(
    replacement.updateKeyMultibase
  )

  // Already complete (a torn earlier run finished the add entry): the fresh
  // ladder's rung 0 is authorized, which only the add entry writes.
  if (published.updateKeys.includes(rung0.keyMultibase)) {
    // The add entry already struck the pre-recovery credentials, so the
    // document names none of them any more. The report is derived from the
    // log instead (`retiredCredentialVmIdsFromLog`), so a resume tells the
    // caller exactly what the first run told it.
    const retired = retiredCredentialVmIdsFromLog({
      log: published.log,
      did: published.did,
      successorKeyMultibase: rung0.keyMultibase,
      spentVmId: recoveryVmId({
        did: published.did,
        keyAgreementKeyMultibase: recovery.keyAgreementKeyMultibase
      })
    })
    // The strike is recomputed by re-running it over the log as it stood just
    // before the add entry, with the same protected sets, so a resume reports
    // exactly what the first run reported rather than a second definition of
    // the same question.
    const strike = await retiredCredentialRungsBeforeKey({
      log: published.log,
      authorizedKeyMultibase: rung0.keyMultibase,
      credentialVmIds: retired,
      protectedHashes: [rung0Hash, rung1Hash, replacementHash],
      protectedKeys: [rung0.keyMultibase]
    })
    return {
      did: published.did,
      doc: published.doc,
      log: published.log,
      retiredCredentialVmIds: retired,
      struckRungHashes: strike.struckHashes,
      unclaimedCredentialVmIds: strike.unclaimedCredentialVmIds
    }
  }

  // The reveal-and-commit entry, skipped when a torn earlier run already
  // published it (the revealed key authorized AND every needed hash
  // committed).
  const revealed = published.updateKeys.includes(recovery.updateKeyMultibase)
  const committed = [rung0Hash, rung1Hash, replacementHash].every(hash =>
    published.nextKeyHashes.includes(hash)
  )
  if (!revealed || !committed) {
    if (!revealed && !published.nextKeyHashes.includes(recoveryHash)) {
      throw new RecoveryKeyNotCommittedError()
    }
    await assertCarryOverCommitments({ published })
    const signer = await updateKeySigner({ seed: recovery.updateSeed })
    const updated = await updateDID({
      log: published.log,
      signer,
      alsoKnownAsWeb: true,
      updateKeys: [
        ...new Set([...published.updateKeys, recovery.updateKeyMultibase])
      ],
      // The spent code's own hash is kept through this entry (so a resumed
      // commit can re-state the revealed key); the add entry drops it.
      nextKeyHashes: [
        ...new Set([
          ...published.nextKeyHashes,
          recoveryHash,
          rung0Hash,
          rung1Hash,
          replacementHash
        ])
      ]
    })
    await publishLogOnly({
      store,
      log: updated.log,
      ifMatch: published.etag
    })
    // Advance the pin to what the reveal entry just published, so the re-read
    // below (and any read after a tear here) refuses a host that rolls the
    // log back behind it.
    if (pinStore && logId !== undefined) {
      await pinStore.write({ logId, pin: pinOfLog(updated.log) })
    }
    // The same account the reveal entry just extended, under the same pin.
    published = await readLogOrThrow({
      store,
      expectedDid: published.did,
      ...pinned
    })
  }

  // The persist-before-publish seam: the replacement code's record and the
  // fresh credential's unlock record (the ladder seed inside) become durable
  // HERE, before the add entry publishes the ladder VM that seed backs.
  const persisted = await onCommitted()
  // Refuses a malformed pointer target before the entry is built.
  clientAnnexDidParts({ did: persisted.clientAnnexDid })

  // The add-and-retire entry: the ladder VM, the fresh credential's
  // keyAgreement inventory, and the replacement code's inventory in; the spent
  // code's VM, update key, and hash out; every pre-recovery standing
  // credential fully retired -- its ladder VM and its keyAgreement member
  // both. Signed by rung 0, whose hash the commit entry just committed.
  const { did, doc } = published
  const spentVmId = recoveryVmId({
    did,
    keyAgreementKeyMultibase: recovery.keyAgreementKeyMultibase
  })
  const replacementVmId = recoveryVmId({
    did,
    keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase
  })
  const ladderVms = ladderVmIds({ doc })
  const ladderVm = ladderVerificationMethod({
    controller: did,
    publicKeyMultibase: ladderVmKey
  })
  const ladderVmId = `${did}#${ladderVmKey}`
  const credentialVm = unlockKeyVerificationMethod({
    did,
    keyAgreement: credentialKeyAgreement
  })
  const credentialVmId = unlockKeyVmId({
    did,
    keyAgreement: credentialKeyAgreement
  })
  // Every pre-recovery credential's keyAgreement member, by the account-DID
  // controller (an enrolled client's carries the client marker instead), less
  // the ids this entry itself adds. The spent code's own id is reported
  // separately: the caller already retires that one by name.
  const addedVmIds = [ladderVmId, credentialVmId, replacementVmId]
  const struckCredentialVmIds = credentialKeyAgreementMethods({ doc, did })
    .map(method => method.id)
    .filter((id): id is string => typeof id === 'string')
    .filter(id => !addedVmIds.includes(id))
  const retiredCredentialVmIds = struckCredentialVmIds.filter(
    id => id !== spentVmId
  )
  // Each retired credential's committed rungs and any revealed rung of its
  // own go in the SAME entry. Striking the VM alone rots a ladder-signed
  // bridge, but a bridge an enrolled client minted outlives the strike, and
  // that client survives this entry -- so a committed rung left standing is a
  // reveal the retired credential could still perform. The anchoring is
  // log-only (this browser holds no registry), and an unanchorable credential
  // is reported rather than struck.
  const strike = await attributeRetiredCredentialRungs({
    log: published.log,
    credentialVmIds: retiredCredentialVmIds,
    protectedHashes: [rung0Hash, rung1Hash, replacementHash],
    protectedKeys: [rung0.keyMultibase]
  })
  const addedMethods: VerificationMethod[] = [
    ladderVm,
    credentialVm,
    {
      id: replacementVmId,
      type: MULTIKEY_VM_TYPE,
      controller: did,
      publicKeyMultibase: replacement.keyAgreementKeyMultibase
    }
  ]
  const existingMethods = (doc.verificationMethod ?? []) as VerificationMethod[]
  const verificationMethods = [
    ...existingMethods.filter(
      method =>
        method.id !== spentVmId &&
        !addedMethods.some(added => added.id === method.id) &&
        (method.id === undefined ||
          (!ladderVms.includes(method.id) &&
            !struckCredentialVmIds.includes(method.id)))
    ),
    ...addedMethods
  ]
  // The retirement filter runs over the EXISTING relation ids only, and the
  // added ids join afterwards: a resumed run's fresh ladder VM already stands
  // in `doc.capabilityDelegation`, so filtering the union would strike the
  // very method this entry is publishing.
  const withoutRemoved = (
    relation: Array<string | { id?: string }> | undefined,
    added?: string[]
  ) => [
    ...new Set([
      ...relationIds(relation).filter(
        referencedId =>
          referencedId !== spentVmId &&
          !ladderVms.includes(referencedId) &&
          !struckCredentialVmIds.includes(referencedId)
      ),
      ...(added ?? [])
    ])
  ]

  const signer = await updateKeySigner({ seed: rung0.seed })
  const updated = await updateDID({
    log: published.log,
    signer,
    alsoKnownAsWeb: true,
    updateKeys: [
      ...new Set([
        ...published.updateKeys.filter(
          key =>
            key !== recovery.updateKeyMultibase &&
            !strike.struckKeys.includes(key)
        ),
        rung0.keyMultibase
      ])
    ],
    nextKeyHashes: assertNextKeyHashesRemain({
      nextKeyHashes: published.nextKeyHashes.filter(
        hash => hash !== recoveryHash && !strike.struckHashes.includes(hash)
      ),
      ceremony: 'the transient-recovery add-and-retire entry'
    }),
    verificationMethods,
    // The ladder VM's relation asymmetry: `assertionMethod` and
    // `capabilityDelegation` only -- no `authentication`, no
    // `capabilityInvocation` -- which is also what keeps it out of every
    // client listing.
    authentication: withoutRemoved(doc.authentication),
    assertionMethod: withoutRemoved(doc.assertionMethod, [ladderVmId]),
    keyAgreement: withoutRemoved(doc.keyAgreement, [
      credentialVmId,
      replacementVmId
    ]),
    capabilityInvocation: withoutRemoved(doc.capabilityInvocation),
    capabilityDelegation: withoutRemoved(doc.capabilityDelegation, [
      ladderVmId
    ]),
    // Atomic with the retirement above: the pointer and the ladder-VM set
    // change in one entry, so no window exists in which the document points
    // at a generation the surviving record cannot reach.
    services: servicesPointedAtClientAnnex({
      doc,
      accountDid: did,
      clientAnnexDid: persisted.clientAnnexDid
    })
  })
  // Conditional on the read this entry was built on: the re-read above when
  // the commit entry ran here, the first read when it was skipped.
  await publishLogOnly({ store, log: updated.log, ifMatch: published.etag })
  // Advance the pin to what this entry just published, so a host rolling the
  // log back straight afterwards is refused on the next read.
  if (pinStore && logId !== undefined) {
    await pinStore.write({ logId, pin: pinOfLog(updated.log) })
  }
  return {
    did: updated.did,
    doc: updated.doc,
    log: updated.log,
    retiredCredentialVmIds,
    struckRungHashes: strike.struckHashes,
    unclaimedCredentialVmIds: strike.unclaimedCredentialVmIds,
    webDoc: updated.webDoc
  }
}
