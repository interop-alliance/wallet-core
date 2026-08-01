/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The did:webvh half of recovery-code lifecycle: the split posture the
 * roster identity model gives a code. At issuance the document gains the
 * code's `keyAgreement` verification method (an ordinary Multikey entry --
 * deliberately unmarked; a recovery key is distinguishable structurally,
 * since it appears ONLY under `keyAgreement` while every enrolled client
 * also publishes signing relationships, so client listings key on
 * `capabilityInvocation` and never see it) and `nextKeyHashes` gains the
 * code's update-key hash -- decryption standing, authority latent: the
 * code's update key joins `updateKeys` nowhere, and its material exists
 * nowhere until the code is typed.
 *
 * At recovery time the pre-committed update key reveals itself to sign the
 * self-enrolling continuation, two entries:
 *
 * 1. **Reveal + commit**: the code's update key joins `updateKeys` (its hash
 *    stands committed since issuance, which is what makes the entry verify)
 *    and `nextKeyHashes` extends with the NEW ordinary client's update- and
 *    staged-key hashes plus the replacement code's update-key hash.
 * 2. **Add + retire**: signed by the new client's update key (revealed from
 *    the commit), this entry publishes the new client's verification methods
 *    and update key, removes the spent code's `keyAgreement` VM, publishes
 *    the replacement code's, and drops the spent code's update key and hash
 *    -- so no recovery authority stands afterwards.
 *
 * Both entries are written through the caller's store seam; the recovery
 * continuation publishes ONLY `did.jsonl` (the delegation the record carries
 * covers nothing else -- narrow scope preserves loudness), and hands back the
 * final `webDoc` so the recovered session can republish `did.json` once it is
 * the authorized controller. Every step is idempotent/resumable: re-running
 * with the same key material converges without forking the log.
 */
import {
  deriveNextKeyHash,
  logToJsonlString,
  updateDID
} from '@interop/did-method-webvh'
import type { VerificationMethod } from '@interop/did-method-webvh'
import { DID_LOG_RESOURCE } from '../space/collections.js'
import {
  MULTIKEY_VM_TYPE,
  publishWebvhLog,
  readPublishedLog,
  relationIds,
  updateKeyMultibase,
  updateKeySigner
} from '../webvh/didWebvh.js'
import type {
  ClientWebvhUpdateKeys,
  PublishedWebvhLog,
  WebvhEnrollmentKeys,
  WebvhIdStore
} from '../webvh/didWebvh.js'

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
 * The narrow store seam the recovery continuation writes through: a public
 * read of the log and the delegated `did.jsonl` PUT. A subset of
 * {@link WebvhIdStore}, so an app's remote-store class satisfies it too.
 */
export type RecoveryLogStore = Pick<
  WebvhIdStore,
  'getIdResourceRaw' | 'putIdResource'
>

/**
 * Reads and resolves the published log through the narrow recovery seam.
 *
 * @param options {object}
 * @param options.store {RecoveryLogStore}
 * @returns {Promise<PublishedWebvhLog>}
 */
async function readLogOrThrow({
  store
}: {
  store: RecoveryLogStore
}): Promise<PublishedWebvhLog> {
  // readPublishedLog only calls getIdResourceRaw, so the narrow seam is safe.
  const published = await readPublishedLog({
    idStore: store as WebvhIdStore
  })
  if (!published) {
    throw new Error('did:webvh: did.jsonl is missing; nothing to recover.')
  }
  return published
}

/**
 * Publishes `did.jsonl` through the narrow recovery seam -- the log only,
 * never `did.json` (the delegation covers nothing else; the recovered
 * session republishes the projection once it is the controller).
 *
 * @param options {object}
 * @param options.store {RecoveryLogStore}
 * @param options.log {object}
 * @returns {Promise<void>}
 */
async function publishLogOnly({
  store,
  log
}: {
  store: RecoveryLogStore
  log: Parameters<typeof logToJsonlString>[0]
}): Promise<void> {
  await store.putIdResource({
    resourceId: DID_LOG_RESOURCE,
    content: logToJsonlString(log),
    contentType: 'text/jsonl'
  })
}

/**
 * Asserts the carry-over commitment convention holds for every currently
 * authorized update key -- the precondition for any entry that re-states
 * `updateKeys` (the resolver checks the re-stated set against the previous
 * entry's `nextKeyHashes`).
 *
 * @param options {object}
 * @param options.published {PublishedWebvhLog}
 * @returns {Promise<void>}
 */
async function assertCarryOverCommitments({
  published
}: {
  published: PublishedWebvhLog
}): Promise<void> {
  for (const key of published.updateKeys) {
    if (!published.nextKeyHashes.includes(await deriveNextKeyHash(key))) {
      throw new Error(
        'did:webvh: the published log does not carry the active update ' +
          "keys' own hashes in nextKeyHashes (it predates the carry-over " +
          'commitment convention); re-provision the account first.'
      )
    }
  }
}

/**
 * ISSUANCE (run by an enrolled client, root authority): publishes a recovery
 * code's split posture into the document -- one entry adding the code's
 * `keyAgreement` verification method (an ordinary, unmarked Multikey entry)
 * and committing its update-key hash in `nextKeyHashes`. The code's update
 * key joins `updateKeys` nowhere. Idempotent: a posture already published is
 * a no-op, so re-running a torn issuance converges.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.updateKeys {ClientWebvhUpdateKeys}   the ISSUING client's
 *   own did:webvh update-key seeds
 * @param options.recovery {RecoveryPublicKeys}   the code's public halves
 * @returns {Promise<{ did: string }>}
 */
export async function publishRecoveryKey({
  idStore,
  updateKeys,
  recovery
}: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  recovery: RecoveryPublicKeys
}): Promise<{ did: string }> {
  const published = await readLogOrThrow({ store: idStore })
  const { did, doc } = published
  const recoveryHash = await deriveNextKeyHash(recovery.updateKeyMultibase)
  const vmId = recoveryVmId({
    did,
    keyAgreementKeyMultibase: recovery.keyAgreementKeyMultibase
  })

  const vmPresent = (doc.verificationMethod ?? []).some(
    method => method.id === vmId
  )
  const hashCommitted = published.nextKeyHashes.includes(recoveryHash)
  if (vmPresent && hashCommitted) {
    return { did }
  }

  const activeKey = await updateKeyMultibase({ seed: updateKeys.updateSeed })
  if (!published.updateKeys.includes(activeKey)) {
    throw new Error(
      "did:webvh: the published log does not authorize this client's active " +
        'update key; finalize the pending rotation before issuing a ' +
        'recovery code.'
    )
  }
  await assertCarryOverCommitments({ published })

  const existingMethods = (doc.verificationMethod ?? []) as VerificationMethod[]
  const recoveryMethod: VerificationMethod = {
    id: vmId,
    type: MULTIKEY_VM_TYPE,
    controller: did,
    publicKeyMultibase: recovery.keyAgreementKeyMultibase
  }
  const signer = await updateKeySigner({ seed: updateKeys.updateSeed })
  const updated = await updateDID({
    log: published.log,
    signer,
    updateKeys: published.updateKeys,
    nextKeyHashes: [...new Set([...published.nextKeyHashes, recoveryHash])],
    verificationMethods: [
      ...existingMethods.filter(method => method.id !== vmId),
      recoveryMethod
    ],
    authentication: relationIds(doc.authentication),
    assertionMethod: relationIds(doc.assertionMethod),
    keyAgreement: [...new Set([...relationIds(doc.keyAgreement), vmId])],
    capabilityInvocation: relationIds(doc.capabilityInvocation),
    capabilityDelegation: relationIds(doc.capabilityDelegation)
  })
  if (!updated.webDoc) {
    throw new Error(
      'did:webvh: updateDID returned no webDoc despite the did:web alsoKnownAs.'
    )
  }
  await publishWebvhLog({ idStore, log: updated.log, webDoc: updated.webDoc })
  return { did: updated.did }
}

/**
 * REVOCATION (run by an enrolled client, root authority): removes a recovery
 * code's posture from the document -- its `keyAgreement` verification method
 * and its committed update-key hash -- in one entry. Idempotent. The
 * roster-side half (rotating the PUK epoch off the code's wrap) is the
 * caller's, and runs after this so the resolver's document no longer backs
 * the removed entry.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.updateKeys {ClientWebvhUpdateKeys}   the REVOKING client's
 *   own did:webvh update-key seeds
 * @param options.recovery {RecoveryPublicKeys}   the code's public halves
 * @returns {Promise<{ did: string }>}
 */
export async function removeRecoveryKey({
  idStore,
  updateKeys,
  recovery
}: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  recovery: RecoveryPublicKeys
}): Promise<{ did: string }> {
  const published = await readLogOrThrow({ store: idStore })
  const { did, doc } = published
  const recoveryHash = await deriveNextKeyHash(recovery.updateKeyMultibase)
  const vmId = recoveryVmId({
    did,
    keyAgreementKeyMultibase: recovery.keyAgreementKeyMultibase
  })

  const vmPresent = (doc.verificationMethod ?? []).some(
    method => method.id === vmId
  )
  const hashCommitted = published.nextKeyHashes.includes(recoveryHash)
  if (!vmPresent && !hashCommitted) {
    return { did }
  }

  const activeKey = await updateKeyMultibase({ seed: updateKeys.updateSeed })
  if (!published.updateKeys.includes(activeKey)) {
    throw new Error(
      "did:webvh: the published log does not authorize this client's active " +
        'update key; finalize the pending rotation before revoking a ' +
        'recovery code.'
    )
  }
  await assertCarryOverCommitments({ published })

  const existingMethods = (doc.verificationMethod ?? []) as VerificationMethod[]
  const signer = await updateKeySigner({ seed: updateKeys.updateSeed })
  const updated = await updateDID({
    log: published.log,
    signer,
    updateKeys: published.updateKeys,
    nextKeyHashes: published.nextKeyHashes.filter(
      hash => hash !== recoveryHash
    ),
    verificationMethods: existingMethods.filter(method => method.id !== vmId),
    authentication: relationIds(doc.authentication),
    assertionMethod: relationIds(doc.assertionMethod),
    keyAgreement: relationIds(doc.keyAgreement).filter(id => id !== vmId),
    capabilityInvocation: relationIds(doc.capabilityInvocation),
    capabilityDelegation: relationIds(doc.capabilityDelegation)
  })
  if (!updated.webDoc) {
    throw new Error(
      'did:webvh: updateDID returned no webDoc despite the did:web alsoKnownAs.'
    )
  }
  await publishWebvhLog({ idStore, log: updated.log, webDoc: updated.webDoc })
  return { did: updated.did }
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
 * commit entry, so a resumed commit can re-state the revealed key).
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
 * @param options.replacement {RecoveryPublicKeys}   the replacement code's
 *   public halves, committed and published in the same continuation
 * @returns {Promise<{ did: string, webDoc?: object }>}   the account DID and,
 *   when the add entry ran here, the final `did.json` projection for the
 *   recovered session to republish
 */
export async function recoverWebvhClient({
  store,
  recovery,
  newClientKeys,
  newClientUpdateSeeds,
  replacement
}: {
  store: RecoveryLogStore
  recovery: RecoveryPublicKeys & { updateSeed: Uint8Array }
  newClientKeys: WebvhEnrollmentKeys
  newClientUpdateSeeds: ClientWebvhUpdateKeys
  replacement: RecoveryPublicKeys
}): Promise<{ did: string; webDoc?: object }> {
  let published = await readLogOrThrow({ store })

  // Already complete (a torn earlier run finished the add entry): the new
  // client's update key is authorized, which only the add entry writes.
  if (published.updateKeys.includes(newClientKeys.updateKeyMultibase)) {
    return { did: published.did }
  }

  const recoveryHash = await deriveNextKeyHash(recovery.updateKeyMultibase)
  const newUpdateHash = await deriveNextKeyHash(
    newClientKeys.updateKeyMultibase
  )
  const newStagedHash = await deriveNextKeyHash(
    newClientKeys.stagedUpdateKeyMultibase
  )
  const replacementHash = await deriveNextKeyHash(
    replacement.updateKeyMultibase
  )

  // The reveal-and-commit entry, skipped when a torn earlier run already
  // published it (the revealed key authorized AND every needed hash
  // committed).
  const revealed = published.updateKeys.includes(recovery.updateKeyMultibase)
  const committed = [newUpdateHash, newStagedHash, replacementHash].every(
    hash => published.nextKeyHashes.includes(hash)
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
      updateKeys: [
        ...new Set([...published.updateKeys, recovery.updateKeyMultibase])
      ],
      // The spent code's own hash is kept through this entry (so a resumed
      // commit can re-state the revealed key); the add entry drops it.
      nextKeyHashes: [
        ...new Set([
          ...published.nextKeyHashes,
          recoveryHash,
          newUpdateHash,
          newStagedHash,
          replacementHash
        ])
      ]
    })
    await publishLogOnly({ store, log: updated.log })
    published = await readLogOrThrow({ store })
  }

  // The add-and-retire entry: the new client's verification methods and
  // update key in; the spent code's VM, update key, and hash out; the
  // replacement code's VM in. Signed by the new client's update key, whose
  // hash the commit entry just committed.
  const { did, doc } = published
  const vmId = (publicKeyMultibase: string) => `${did}#${publicKeyMultibase}`
  const spentVmId = recoveryVmId({
    did,
    keyAgreementKeyMultibase: recovery.keyAgreementKeyMultibase
  })
  const replacementVmId = recoveryVmId({
    did,
    keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase
  })
  const addedMethods: VerificationMethod[] = [
    {
      id: vmId(newClientKeys.signingKeyMultibase),
      publicKeyMultibase: newClientKeys.signingKeyMultibase
    },
    {
      id: vmId(newClientKeys.keyAgreementKeyMultibase),
      publicKeyMultibase: newClientKeys.keyAgreementKeyMultibase
    },
    {
      id: replacementVmId,
      publicKeyMultibase: replacement.keyAgreementKeyMultibase
    }
  ].map(method => ({
    ...method,
    type: MULTIKEY_VM_TYPE,
    controller: did
  }))
  const existingMethods = (doc.verificationMethod ?? []) as VerificationMethod[]
  const verificationMethods = [
    ...existingMethods.filter(
      method =>
        method.id !== spentVmId &&
        !addedMethods.some(added => added.id === method.id)
    ),
    ...addedMethods
  ]
  const withReference = (
    relation: Array<string | { id?: string }> | undefined,
    id: string
  ) => [...new Set([...relationIds(relation), id])]
  const signingVmId = vmId(newClientKeys.signingKeyMultibase)

  const signer = await updateKeySigner({
    seed: newClientUpdateSeeds.updateSeed
  })
  const updated = await updateDID({
    log: published.log,
    signer,
    updateKeys: [
      ...new Set([
        ...published.updateKeys.filter(
          key => key !== recovery.updateKeyMultibase
        ),
        newClientKeys.updateKeyMultibase
      ])
    ],
    nextKeyHashes: published.nextKeyHashes.filter(
      hash => hash !== recoveryHash
    ),
    verificationMethods,
    authentication: withReference(doc.authentication, signingVmId),
    assertionMethod: withReference(doc.assertionMethod, signingVmId),
    keyAgreement: [
      ...new Set([
        ...relationIds(doc.keyAgreement).filter(id => id !== spentVmId),
        vmId(newClientKeys.keyAgreementKeyMultibase),
        replacementVmId
      ])
    ],
    capabilityInvocation: withReference(doc.capabilityInvocation, signingVmId),
    capabilityDelegation: withReference(doc.capabilityDelegation, signingVmId)
  })
  await publishLogOnly({ store, log: updated.log })
  return { did: updated.did, webDoc: updated.webDoc }
}
