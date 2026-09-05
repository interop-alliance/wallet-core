/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The shared core of the two recovery continuations: the control flow a
 * spent code's two entries share whether the successor is an enrolled client
 * (`recoverWebvhClient`, the remembered variant in `recoveryWebvh.ts`) or a
 * fresh credential's ladder (`recoverWebvhLadderAnchored`, the transient
 * variant in `clientAnnex/`). The two differ in exactly three things: the
 * successor key the add-and-retire entry authorizes and signs with, the
 * verification methods and relation memberships that entry adds, and what the
 * `onCommitted` seam hands back into it. Everything else -- the resume
 * detection, the reveal-and-commit entry, the seam's placement, the
 * structural retirement of every pre-recovery credential, the rung strike,
 * and the entry assembly -- is here once, so a change to the mechanics is
 * made once and the two variants publish byte-identical entries for the
 * parts they share.
 *
 * Lives in `recovery/` rather than beside the transient variant because the
 * layer rule lets the annex import from the base and not the reverse.
 */
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import type {
  DIDDoc,
  DIDLog,
  ServiceEndpoint,
  VerificationMethod
} from '@interop/did-method-webvh'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import {
  effectiveParameters,
  ladderVerificationMethod,
  MULTIKEY_VM_TYPE,
  readPublishedLogOrThrow,
  servedHead
} from '../webvh/didWebvh.js'
import type { PublishedWebvhLog, WebvhIdStore } from '../webvh/didWebvh.js'
import { accountEntryHead, signAccountEntry } from '../webvh/accountEntry.js'
import { mergeVerificationMethods } from '../webvh/mergeMethods.js'
import type { RelationMembership } from '../webvh/mergeMethods.js'
import {
  credentialKeyAgreementMethods,
  ladderVmIds,
  retiredCredentialKeys
} from '../resourceLog/document.js'
// The base-side dependency the lint config pins: the ladder ATTRIBUTION
// helpers only, never the annex log machinery. The add-and-retire entry
// resolves each retired credential's standing rungs from the log with them.
import {
  assertNextKeyHashesRemain,
  attributeRetiredCredentialRungs,
  retiredCredentialRungsBeforeKey
} from '../clientAnnex/ladder.js'

/**
 * What the add-and-retire entry retired, read back OFF THE LOG -- the resumed
 * spend's answer to the same question the live run answers from the document
 * it is editing. A run torn after that entry but before the caller's registry
 * and unlock-Space teardown resumes into the already-complete branch, and
 * without this it would be told nothing was retired and leave every other
 * credential's registry entry standing.
 *
 * The entry is located by its own signature on the log: it is the first entry
 * whose effective `updateKeys` authorize the successor key (the fresh
 * ladder's rung 0 on the transient continuation, the new client's update key
 * on the remembered one), which only that entry writes. What it retired is
 * then the credential-class `keyAgreement` ids its predecessor published and
 * it does not, less the spent code's own id -- the same exclusion the live
 * branch makes, since the caller retires that one by name.
 *
 * @param options {object}
 * @param options.log {DIDLog}   the verified account log
 * @param options.did {string}   the account DID the log resolves to
 * @param options.successorKeyMultibase {string}   the update key only the
 *   add-and-retire entry authorizes
 * @param options.spentVmId {string}   the spent code's key-agreement
 *   verification-method id, excluded from the result
 * @returns {string[]}   the retired credentials' key-agreement ids, empty
 *   when no entry authorizes the successor key or it is the genesis entry
 */
export function retiredCredentialVmIdsFromLog({
  log,
  did,
  successorKeyMultibase,
  spentVmId
}: {
  log: DIDLog
  did: string
  successorKeyMultibase: string
  spentVmId: string
}): string[] {
  const params = effectiveParameters(log)
  const index = params.findIndex(entry =>
    (entry.updateKeys ?? []).includes(successorKeyMultibase)
  )
  const previous = index > 0 ? log[index - 1]?.state : undefined
  const entryDoc = index > 0 ? log[index]?.state : undefined
  if (previous === undefined || entryDoc === undefined) {
    return []
  }
  return retiredCredentialKeys({
    doc: entryDoc,
    prevDoc: previous,
    did
  }).filter(id => id !== spentVmId)
}

/**
 * What a recovery spend retired, the three members both continuations
 * report: the credential-class `keyAgreement` ids the add-and-retire entry
 * struck for pre-recovery credentials OTHER than the spent code (what a
 * caller drops registry entries and deletes unlock Spaces for), the rung
 * hashes the entry struck, and the retired credentials whose rungs the log
 * could not attribute -- each of which keeps a committed rung it could still
 * reveal, and is left for the caller to report rather than struck.
 */
export interface RecoverySpendRetirement {
  retiredCredentialVmIds: string[]
  struckRungHashes: string[]
  unclaimedCredentialVmIds: string[]
}

/**
 * The retirement report of a spend whose add-and-retire entry already
 * stands, read back off the log: the same three members the continuation
 * returns, derived the way its completed branch derives them, so a resume
 * that holds only the successor's public halves (a remembered spend's pending
 * client-key record, say) reports exactly what the first run reported rather
 * than a second definition of the same question.
 *
 * The entry is located by the successor key it authorized
 * ({@link retiredCredentialVmIdsFromLog}), and the strike is recomputed over
 * the log as it stood just before that entry with the same protected sets the
 * first run used: the successor key and its staged partner, and the
 * replacement code's rung 0. A log that does not authorize the successor key
 * (the entry never landed) reports nothing retired, since there is no entry to
 * read back.
 *
 * @param options {object}
 * @param options.log {DIDLog}   the verified account log
 * @param options.did {string}   the account DID the log resolves to
 * @param options.successor {object}   the public halves of the key the entry
 *   authorized (`updateKeyMultibase`) and the staged partner whose hash the
 *   reveal entry committed after it (`stagedKeyMultibase`)
 * @param options.replacementUpdateKeyMultibase {string}   the replacement
 *   code's rung-0 update key
 * @param options.spentKeyAgreementKeyMultibase {string}   the spent code's
 *   key-agreement key, excluded from the retired set
 * @returns {Promise<RecoverySpendRetirement>}
 */
export async function recoverySpendRetirementFromLog({
  log,
  did,
  successor,
  replacementUpdateKeyMultibase,
  spentKeyAgreementKeyMultibase
}: {
  log: DIDLog
  did: string
  successor: { updateKeyMultibase: string; stagedKeyMultibase: string }
  replacementUpdateKeyMultibase: string
  spentKeyAgreementKeyMultibase: string
}): Promise<RecoverySpendRetirement> {
  const authorized = effectiveParameters(log).some(entry =>
    (entry.updateKeys ?? []).includes(successor.updateKeyMultibase)
  )
  if (!authorized) {
    return {
      retiredCredentialVmIds: [],
      struckRungHashes: [],
      unclaimedCredentialVmIds: []
    }
  }
  const retiredCredentialVmIds = retiredCredentialVmIdsFromLog({
    log,
    did,
    successorKeyMultibase: successor.updateKeyMultibase,
    spentVmId: recoveryVmId({
      did,
      keyAgreementKeyMultibase: spentKeyAgreementKeyMultibase
    })
  })
  const protectedHashes = await Promise.all([
    deriveNextKeyHash(successor.updateKeyMultibase),
    deriveNextKeyHash(successor.stagedKeyMultibase),
    deriveNextKeyHash(replacementUpdateKeyMultibase)
  ])
  const strike = await retiredCredentialRungsBeforeKey({
    log,
    authorizedKeyMultibase: successor.updateKeyMultibase,
    credentialVmIds: retiredCredentialVmIds,
    protectedHashes,
    protectedKeys: [successor.updateKeyMultibase]
  })
  return {
    retiredCredentialVmIds,
    struckRungHashes: strike.struckHashes,
    unclaimedCredentialVmIds: strike.unclaimedCredentialVmIds
  }
}

/**
 * The verification-method id a code's key-agreement key publishes under --
 * the ordinary `<did>#<multibase>` form, indistinguishable by id from any
 * other keyAgreement entry. Consumers that must exclude recovery entries do
 * it structurally (an enrolled client is a `capabilityInvocation` entry; a
 * recovery key never has one) or by the registry's recorded multibase.
 *
 * @param options {object}
 * @param options.did {string}   the account's did:webvh
 * @param options.keyAgreementKeyMultibase {string}
 * @returns {string}
 */
export function recoveryVmId({
  did,
  keyAgreementKeyMultibase
}: {
  did: string
  keyAgreementKeyMultibase: string
}): string {
  return `${did}#${keyAgreementKeyMultibase}`
}

/**
 * The public halves of a recovery code as the document and log carry them:
 * the X25519 key-agreement key published as the recovery VM, and the update
 * key whose hash stands in `nextKeyHashes`.
 */
export interface RecoveryPublicKeys {
  keyAgreementKeyMultibase: string
  updateKeyMultibase: string
}

/**
 * The public halves a SPEND needs of the replacement code it publishes: the
 * two above plus the code's ladder VM key, which the add-and-retire entry
 * installs under `assertionMethod` and `capabilityDelegation`. A code is a
 * standing unlock credential with a ladder (`decisions/0020`) and its bridge
 * delegation is signed by that ladder's VM (`decisions/0019`), so a
 * replacement published without the VM could neither sign its own bridge nor
 * spend. `recoveryClientFromCode` produces all three.
 */
export interface ReplacementRecoveryPublicKeys extends RecoveryPublicKeys {
  ladderVmKeyMultibase: string
}

/**
 * Thrown by the recovery continuation when the log carries neither the code's
 * update key nor its committed hash -- the code was revoked (or never
 * issued), so no continuation can verify.
 */
export class RecoveryKeyNotCommittedError extends Error {
  constructor(
    message = 'The account log no longer commits this recovery code; the ' +
      'code has been revoked or was never issued.'
  ) {
    super(message)
    this.name = 'RecoveryKeyNotCommittedError'
  }
}

/**
 * Thrown by the recovery continuation, before its reveal entry, when a
 * credential-class `keyAgreement` id the add-and-retire entry would introduce
 * already stands in the document -- the user re-typed a passphrase the
 * account already stands on. The recovery exists to retire that credential,
 * and an entry that re-binds it would strike its old ladder VM while leaving
 * its old rung commitments standing, one member backed by two ladders. The
 * app maps the refusal to "choose a passphrase you have not used". Nothing
 * is published.
 */
export class RecoveryCredentialStandingError extends Error {
  readonly credentialVmIds: string[]

  constructor({ credentialVmIds }: { credentialVmIds: string[] }) {
    super(
      'The recovery would re-bind a credential the account already stands ' +
        `on (${credentialVmIds.join(', ')}); choose a credential the account ` +
        'has not used.'
    )
    this.name = 'RecoveryCredentialStandingError'
    this.credentialVmIds = credentialVmIds
  }
}

/**
 * The narrow store seam the recovery continuation writes through: a public
 * read of the log and the delegated `did.jsonl` PUT. A subset of
 * {@link WebvhIdStore}, so an app's remote-store class satisfies it too.
 */
export type RecoveryLogStore = Pick<
  WebvhIdStore,
  'getIdResourceRaw' | 'putIdResource'
>

/**
 * What a variant adds to the add-and-retire entry beyond the replacement
 * code's own inventory, which the core appends after it: the verification
 * methods, and the ids each relation gains. Order is load-bearing on the wire
 * -- the methods land in `verificationMethod` and each relation in the order
 * given, with the replacement code's after them.
 */
export interface RecoveryAddedInventory extends RelationMembership {
  methods: VerificationMethod[]
  services?: ServiceEndpoint[]
}

/**
 * What one attempt of a recovery continuation returns: the superset both
 * variants pick their public outcome from.
 */
export interface RecoveryContinuationOutcome extends RecoverySpendRetirement {
  did: string
  doc: DIDDoc
  log: DIDLog
  webDoc?: object
  committed: boolean
}

/**
 * One attempt of a recovery continuation, the shared control flow of
 * `recoverWebvhClient` and `recoverWebvhLadderAnchored`; each wraps it in the
 * conflict retry under its own preconditions. Both entries go through the
 * account-entry seam ({@link signAccountEntry}) on its committed-key arm: the
 * spent code's rung 0 signs the reveal-and-commit entry, and the successor
 * key that entry committed signs the add-and-retire entry, so the pinned
 * read, the carry-over precondition, the self-reveal union, the conditional
 * publish, and the pin advance are the seam's. The body detects a completed
 * run by the successor key standing authorized (reporting what the entry
 * retired off the log), publishes the reveal-and-commit entry unless a torn
 * earlier run left it standing, enters the `onCommitted` seam, and builds the
 * add-and-retire entry from what the variant's `added` callback hands in.
 *
 * The reveal-and-commit entry commits, in this order, the successor key's
 * hash, its staged partner's hash, and the replacement code's rung-0 hash --
 * the ratified append order of `decisions/0007` (the replacement's comes
 * LAST) and the anchor rule of `decisions/0014` both read that order. The
 * add-and-retire entry is built on the head the reveal entry's own publish
 * leaves standing, with no read in between; against a store whose PUT serves
 * no ETag it is re-read under the same pin instead, so its compare-and-swap
 * never degrades to an unconditional write.
 *
 * @param options {object}
 * @param options.store {RecoveryLogStore}
 * @param options.recovery {object}   the spent code's update seed and public
 *   halves
 * @param options.successor {object}   the key the add-and-retire entry
 *   authorizes and signs with (`updateKeyMultibase`, from `updateSeed`) and
 *   the staged partner whose hash the reveal entry commits right after it
 *   (`stagedKeyMultibase`: the new client's staged key, or the fresh ladder's
 *   rung 1)
 * @param options.replacement {ReplacementRecoveryPublicKeys}
 * @param options.onCommitted {function}   the persist-before-publish seam,
 *   entered once per attempt after the reveal entry stands and before the
 *   pivot is built; what it resolves to is handed to `added`
 * @param options.added {function}   builds the variant's additions to the
 *   add-and-retire entry from the account DID, the document the entry edits,
 *   and what the seam persisted
 * @param [options.credentialVmIds] {function}   `(did) => string[]` -- the
 *   credential-class `keyAgreement` ids `added` will introduce, checked
 *   against the read document before the reveal entry: one already standing
 *   is refused with {@link RecoveryCredentialStandingError}. The transient
 *   variant supplies its fresh credential's; the remembered variant's new
 *   client publishes a marked pair, which is never credential-class
 * @param [options.expectedDid] {string}
 * @param [options.pinStore] {ResourceLogPinStore}
 * @param [options.logId] {string}
 * @returns {Promise<RecoveryContinuationOutcome>}
 */
export async function recoveryContinuationOnce<Persisted>({
  store,
  recovery,
  successor,
  replacement,
  onCommitted,
  added,
  credentialVmIds,
  expectedDid,
  pinStore,
  logId
}: {
  store: RecoveryLogStore
  recovery: RecoveryPublicKeys & { updateSeed: Uint8Array }
  successor: {
    updateKeyMultibase: string
    updateSeed: Uint8Array
    stagedKeyMultibase: string
  }
  replacement: ReplacementRecoveryPublicKeys
  onCommitted: (committed: {
    builtOnHead: { scid: string; versionId: string }
  }) => Promise<Persisted>
  added: (context: {
    did: string
    doc: DIDDoc
    persisted: Persisted
  }) => RecoveryAddedInventory
  credentialVmIds?: (did: string) => string[]
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<RecoveryContinuationOutcome> {
  const pinned = {
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {})
  }
  const missingMessage = 'did:webvh: did.jsonl is missing; nothing to recover.'

  // The successor's own hashes, which the reveal entry commits and the strike
  // never touches; {@link recoverySpendRetirementFromLog} re-derives the same
  // sets for a resumed run.
  const [recoveryHash, successorHash, stagedHash, replacementHash] =
    await Promise.all([
      deriveNextKeyHash(recovery.updateKeyMultibase),
      deriveNextKeyHash(successor.updateKeyMultibase),
      deriveNextKeyHash(successor.stagedKeyMultibase),
      deriveNextKeyHash(replacement.updateKeyMultibase)
    ])
  const protectedHashes = [successorHash, stagedHash, replacementHash]
  const protectedKeys = [successor.updateKeyMultibase]
  const spentVmIdOf = (did: string) =>
    recoveryVmId({
      did,
      keyAgreementKeyMultibase: recovery.keyAgreementKeyMultibase
    })
  const complete = (read: PublishedWebvhLog) =>
    read.updateKeys.includes(successor.updateKeyMultibase)

  // The reveal-and-commit entry, signed by the spent code's rung 0. Each
  // attempt's own read is what the CAS publish is built on, so the continuity
  // check runs here -- and again on a conflict-retry re-run -- not only on
  // the verify that follows both entries.
  const reveal = await signAccountEntry({
    idStore: store,
    signer: { kind: 'committed', updateSeed: recovery.updateSeed },
    ...pinned,
    missingMessage,
    verb: 'spending a recovery code',
    logOnly: true,
    skip: read => {
      // Already complete (a torn earlier run finished the add entry): the
      // successor key is authorized, which only the add entry writes.
      if (complete(read)) {
        return true
      }
      // A member this continuation would re-bind: refused before anything
      // publishes, on the first attempt and on a resume alike.
      const standing = (credentialVmIds?.(read.did) ?? []).filter(id =>
        credentialKeyAgreementMethods({ doc: read.doc, did: read.did }).some(
          method => method.id === id
        )
      )
      if (standing.length > 0) {
        throw new RecoveryCredentialStandingError({ credentialVmIds: standing })
      }
      // Skipped when a torn earlier run already published it (the revealed
      // key authorized AND every needed hash committed).
      const revealed = read.updateKeys.includes(recovery.updateKeyMultibase)
      if (!revealed && !read.nextKeyHashes.includes(recoveryHash)) {
        throw new RecoveryKeyNotCommittedError()
      }
      return (
        revealed &&
        protectedHashes.every(hash => read.nextKeyHashes.includes(hash))
      )
    },
    // The spent code's own hash is kept through this entry by the arm's
    // carry-over union (so a resumed commit can re-state the revealed key);
    // the add entry drops it. The three new hashes follow in the ratified
    // order, the replacement code's last.
    build: () => ({ commitHashes: protectedHashes })
  })
  let published = accountEntryHead({ outcome: reveal })

  // The seam is deliberately NOT entered on the completed branch -- nothing
  // is about to be published, so there is no pivot to persist ahead of.
  if (complete(published)) {
    // The add entry already struck the pre-recovery credentials, so the
    // document names none of them any more. The report is read back off the
    // log instead ({@link recoverySpendRetirementFromLog}, the same entry
    // point an app's own resume calls), so a resume tells the caller exactly
    // what the first run told it.
    const retirement = await recoverySpendRetirementFromLog({
      log: published.log,
      did: published.did,
      successor: {
        updateKeyMultibase: successor.updateKeyMultibase,
        stagedKeyMultibase: successor.stagedKeyMultibase
      },
      replacementUpdateKeyMultibase: replacement.updateKeyMultibase,
      spentKeyAgreementKeyMultibase: recovery.keyAgreementKeyMultibase
    })
    return {
      did: published.did,
      doc: published.doc,
      log: published.log,
      committed: false,
      ...retirement
    }
  }
  if (reveal.updated && published.etag === undefined) {
    // The same account the reveal entry just extended, under the same pin.
    published = await readPublishedLogOrThrow({
      idStore: store,
      ...pinned,
      expectedDid: published.did,
      missingMessage
    })
  }

  // The persist-before-publish seam: the successor material is persisted
  // HERE, on the head the add-and-retire entry is about to be built on,
  // before that entry -- the ceremony's pivot -- retires the spent code.
  // Reached on both paths into the add entry: the reveal entry just published
  // above, or a torn earlier run's reveal entry standing already.
  const persisted = await onCommitted({
    builtOnHead: servedHead(published.log)
  })

  // The add-and-retire entry: the variant's successor inventory in, the
  // replacement code's inventory in after it, every pre-recovery standing
  // credential fully retired -- the spent code by name, and every other one
  // structurally (its ladder VM by the relation asymmetry, its keyAgreement
  // member by the account-DID controller). Signed by the successor key, whose
  // hash the commit entry just committed.
  let retiredCredentialVmIds: string[] = []
  let strike: Awaited<ReturnType<typeof attributeRetiredCredentialRungs>> = {
    struckHashes: [],
    struckKeys: [],
    unclaimedCredentialVmIds: []
  }
  const add = await signAccountEntry({
    idStore: store,
    signer: { kind: 'committed', updateSeed: successor.updateSeed },
    published,
    ...pinned,
    expectedDid: published.did,
    verb: 'spending a recovery code',
    logOnly: true,
    build: async ({ published: read }) => {
      const { did, doc } = read
      const spentVmId = spentVmIdOf(did)
      const replacementVmId = recoveryVmId({
        did,
        keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase
      })
      // The replacement code's ladder VM, published in the same entry as its
      // key-agreement member: a code is a standing credential with a ladder,
      // and its own bridge delegation is signed by this VM, so a replacement
      // without it could never spend (`decisions/0019`, `decisions/0020`).
      // Its rung-0 hash needs nothing here -- the reveal-and-commit entry
      // committed it, and this entry carries it through.
      const replacementLadderVmId = `${did}#${replacement.ladderVmKeyMultibase}`
      const variant = added({ did, doc, persisted })
      const addedMethods: VerificationMethod[] = [
        ...variant.methods,
        {
          id: replacementVmId,
          type: MULTIKEY_VM_TYPE,
          controller: did,
          publicKeyMultibase: replacement.keyAgreementKeyMultibase
        },
        ladderVerificationMethod({
          controller: did,
          publicKeyMultibase: replacement.ladderVmKeyMultibase
        })
      ]
      // The full retirement, recognized structurally rather than from a list
      // the caller supplies: every standing ladder VM, and every keyAgreement
      // member the account DID controls, less the ids this entry itself adds.
      // Other unspent recovery codes retire with the rest -- a code's member
      // is unmarked and verbatim, indistinguishable from a passkey's. The
      // enrolled clients' marked pairs and the KMS convenience key are
      // untouched -- neither is account-DID-controlled keyAgreement.
      const ladderVms = ladderVmIds({ doc })
      const addedVmIds = addedMethods
        .map(method => method.id)
        .filter((id): id is string => typeof id === 'string')
      const struckCredentialVmIds = credentialKeyAgreementMethods({ doc, did })
        .map(method => method.id)
        .filter((id): id is string => typeof id === 'string')
        .filter(id => !addedVmIds.includes(id))
      retiredCredentialVmIds = struckCredentialVmIds.filter(
        id => id !== spentVmId
      )
      // Each retired credential's committed rungs and any revealed rung of its
      // own go in the SAME entry. Striking the ladder VM rots only a
      // ladder-signed bridge; a bridge an enrolled client minted outlives the
      // strike, and that client survives this entry, so a committed rung left
      // standing is a reveal the retired credential could still perform
      // (`decisions/0014`). Anchored from the log alone, and an unanchorable
      // credential is reported rather than struck.
      strike = await attributeRetiredCredentialRungs({
        log: read.log,
        credentialVmIds: retiredCredentialVmIds,
        protectedHashes,
        protectedKeys
      })
      const struck = (id: string): boolean =>
        id === spentVmId ||
        ladderVms.includes(id) ||
        struckCredentialVmIds.includes(id)
      return {
        // The spent code's revealed rung and every struck rung leave; the
        // arm unions the successor key in after this.
        updateKeys: read.updateKeys.filter(
          key =>
            key !== recovery.updateKeyMultibase &&
            !strike.struckKeys.includes(key)
        ),
        nextKeyHashes: assertNextKeyHashesRemain({
          nextKeyHashes: read.nextKeyHashes.filter(
            hash => hash !== recoveryHash && !strike.struckHashes.includes(hash)
          ),
          ceremony: 'the recovery add-and-retire entry'
        }),
        // The retirement runs over the EXISTING document only, and the added
        // ids join afterwards: a ladder VM this entry publishes may already
        // stand in `doc.capabilityDelegation`, and filtering the union would
        // strike the very method this entry is publishing.
        ...mergeVerificationMethods({
          doc,
          methods: addedMethods,
          retire: struck,
          relations: {
            authentication: variant.authentication,
            // The ladder VMs' relation asymmetry: `assertionMethod` and
            // `capabilityDelegation` only, so neither reads as an enrolled
            // client.
            assertionMethod: [
              ...(variant.assertionMethod ?? []),
              replacementLadderVmId
            ],
            // The variant's own key-agreement member precedes the replacement
            // code's: the position `decisions/0014`'s anchor rule reads the
            // pair by.
            keyAgreement: [...(variant.keyAgreement ?? []), replacementVmId],
            capabilityInvocation: variant.capabilityInvocation,
            capabilityDelegation: [
              ...(variant.capabilityDelegation ?? []),
              replacementLadderVmId
            ]
          }
        }),
        ...(variant.services ? { services: variant.services } : {})
      }
    }
  })
  // The build never declines, so the seam published.
  const updated = add.updated!
  return {
    did: updated.did,
    doc: updated.doc,
    log: updated.log,
    webDoc: updated.webDoc,
    committed: true,
    retiredCredentialVmIds,
    struckRungHashes: strike.struckHashes,
    unclaimedCredentialVmIds: strike.unclaimedCredentialVmIds
  }
}
