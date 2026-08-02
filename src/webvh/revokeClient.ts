/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Client revocation, the did:webvh half: removing an enrolled wallet client
 * from the document roster. Per the identity model this is a pure roster edit
 * -- nothing shared rotates, because nothing was shared -- and, because a
 * removal reveals no new key, it is a SINGLE log entry (unlike enrollment's
 * two): the client's Ed25519 verification method leaves all four signing
 * relationships, its X25519 twin leaves `keyAgreement`, its update key leaves
 * `updateKeys`, and both of its standing commitments leave `nextKeyHashes` --
 * the carry-over hash of its active update key, and the hash of its staged
 * key.
 *
 * The staged-key hash is the subtle half, and removing it is load-bearing: a
 * hash left committed in `nextKeyHashes` is a standing credential -- an entry
 * verifies against its own re-stated `updateKeys`, each hashing into the
 * previous entry's commitments, so a revoked client whose staged hash
 * survived could author an entry revealing that key and re-seize update
 * authority (the same reveal mechanism recovery uses legitimately). The hash
 * itself is opaque (only the revoked client ever held the staged key), so it
 * is recovered by **log attribution**: every staged commitment was added in
 * the entry that revealed or committed its client's active key -- genesis,
 * an enrollment commit, a rotation, a recovery reveal-and-commit -- and
 * diffing that entry's `nextKeyHashes` against its predecessor isolates it.
 * The one ambiguous shape is a recovery continuation, whose commit entry also
 * carries the replacement code's latent hash; the caller disambiguates by
 * supplying the standing recovery-code hashes it knows
 * (`knownLatentHashes`, from its recovery registry), and a residue of more
 * than one candidate refuses loudly rather than guessing
 * ({@link StagedCommitmentAmbiguousError}) -- removing a wrong hash would
 * either leave the revoked client re-enrollable or brick another party's
 * standing commitment.
 */
import { deriveNextKeyHash, updateDID } from '@interop/did-method-webvh'
import type { DIDLog, VerificationMethod } from '@interop/did-method-webvh'
import {
  assertCarryOverCommitments,
  effectiveParameters,
  publishWebvhLog,
  readPublishedLog,
  relationIds,
  updateKeyMultibase,
  updateKeySigner
} from './didWebvh.js'
import type {
  ClientWebvhUpdateKeys,
  WebvhClientKeys,
  WebvhIdStore
} from './didWebvh.js'

/**
 * The public halves of the client being revoked, as the document and log
 * carry them: its two verification-method multibases and its active update
 * key. The staged-key hash is deliberately absent -- it is recovered from the
 * log (see the module doc), since no other party ever held the staged key.
 */
export interface RevokedClientKeys extends WebvhClientKeys {
  updateKeyMultibase: string
}

/**
 * Thrown when the log attribution cannot isolate the revoked client's staged
 * commitment to a single hash -- more than one candidate survives after the
 * known latent (recovery-code) hashes are excluded. Refusing beats guessing:
 * see the module doc. The fix is to pass the standing recovery codes' update-
 * key hashes as `knownLatentHashes`.
 */
export class StagedCommitmentAmbiguousError extends Error {
  candidates: string[]
  constructor({ candidates }: { candidates: string[] }) {
    super(
      "did:webvh: the revoked client's staged-key commitment cannot be " +
        'isolated in nextKeyHashes (more than one candidate hash); pass the ' +
        "standing recovery codes' update-key hashes as knownLatentHashes."
    )
    this.name = 'StagedCommitmentAmbiguousError'
    this.candidates = candidates
  }
}

/**
 * Recovers the revoked client's staged-key hash from the log (see the module
 * doc for why attribution works and where it can be ambiguous). Resolves
 * `undefined` when there is nothing to attribute -- the client's key never
 * entered `updateKeys`, or its commitment event added no other hash (already
 * cleaned up).
 *
 * @param options {object}
 * @param options.log {DIDLog}
 * @param options.revokedUpdateKey {string}   the revoked client's active
 *   update-key multibase
 * @param options.knownLatentHashes {string[]}   standing latent commitments
 *   the caller can vouch for (recovery-code update-key hashes)
 * @returns {Promise<string | undefined>}
 */
async function attributeStagedHash({
  log,
  revokedUpdateKey,
  knownLatentHashes
}: {
  log: DIDLog
  revokedUpdateKey: string
  knownLatentHashes: string[]
}): Promise<string | undefined> {
  const revokedHash = await deriveNextKeyHash(revokedUpdateKey)
  const params = effectiveParameters(log)
  const added = (index: number): Set<string> => {
    const previous = new Set(index > 0 ? params[index - 1]!.nextKeyHashes : [])
    return new Set(
      params[index]!.nextKeyHashes.filter(hash => !previous.has(hash))
    )
  }
  const prune = (candidates: Set<string>): Set<string> => {
    candidates.delete(revokedHash)
    for (const hash of knownLatentHashes) {
      candidates.delete(hash)
    }
    return candidates
  }

  // The entry where the revoked client's active key ENTERED updateKeys (the
  // latest such, in case of anything odd).
  let revealIndex = -1
  for (let index = params.length - 1; index >= 0; index--) {
    const present = params[index]!.updateKeys.includes(revokedUpdateKey)
    const before =
      index > 0 && params[index - 1]!.updateKeys.includes(revokedUpdateKey)
    if (present && !before) {
      revealIndex = index
      break
    }
  }
  if (revealIndex === -1) {
    return undefined
  }

  // A rotation entry commits the fresh staged hash in the same entry that
  // reveals the new active key (genesis likewise commits both of its hashes
  // in entry one), so the reveal entry's own additions are tried first. An
  // enrollment add or a recovery add-and-retire adds no hash at the reveal.
  const atReveal = prune(added(revealIndex))
  if (atReveal.size === 1) {
    return [...atReveal][0]
  }
  if (atReveal.size > 1) {
    throw new StagedCommitmentAmbiguousError({ candidates: [...atReveal] })
  }

  // Fall back to the entry that COMMITTED the revoked key's own hash (an
  // enrollment commit entry, or a recovery reveal-and-commit): the staged
  // hash was added beside it.
  let commitIndex = -1
  for (let index = revealIndex; index >= 0; index--) {
    const present = params[index]!.nextKeyHashes.includes(revokedHash)
    const before =
      index > 0 && params[index - 1]!.nextKeyHashes.includes(revokedHash)
    if (present && !before) {
      commitIndex = index
      break
    }
  }
  if (commitIndex === -1) {
    return undefined
  }
  const atCommit = prune(added(commitIndex))
  if (atCommit.size > 1) {
    throw new StagedCommitmentAmbiguousError({ candidates: [...atCommit] })
  }
  return atCommit.size === 1 ? [...atCommit][0] : undefined
}

/**
 * REVOCATION (run by another enrolled client, root authority): removes an
 * enrolled wallet client from the published document -- its two verification
 * methods out of the document and all five relationship arrays, its update
 * key out of `updateKeys`, and its carry-over and staged hashes out of
 * `nextKeyHashes` -- in one log entry (a removal reveals no key, so
 * prerotation forces no commit entry). Under the current-key-set rule this
 * single edit is also the revoked client's pull axis everywhere: its
 * invocations and every delegation it signed stop verifying the moment its
 * verification method leaves the document.
 *
 * Idempotent: a client with no remaining presence (verification methods,
 * update key, commitments all gone) is a no-op, so a naive re-run after a
 * mid-cascade crash converges without forking the log.
 *
 * Self-revocation is refused: the entry is signed by THIS client's active
 * update key, and a client that removed its own key could not have signed
 * the removal the resolver will verify (and would strand the cascade that
 * follows the document edit). Revoking the last remaining client is refused
 * by the same guard.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.updateKeys {ClientWebvhUpdateKeys}   the REVOKING client's
 *   own did:webvh update-key seeds
 * @param options.revokedClient {RevokedClientKeys}   the revoked client's
 *   public halves
 * @param [options.knownLatentHashes] {string[]}   standing latent commitments
 *   the caller vouches for (the recovery registry's update-key hashes),
 *   excluded from the staged-hash attribution
 * @returns {Promise<{ did: string }>}
 */
export async function revokeWebvhClient({
  idStore,
  updateKeys,
  revokedClient,
  knownLatentHashes = []
}: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  revokedClient: RevokedClientKeys
  knownLatentHashes?: string[]
}): Promise<{ did: string }> {
  const published = await readPublishedLog({ idStore })
  if (!published) {
    throw new Error('did:webvh: did.jsonl is missing; nothing to revoke from.')
  }
  const { did, doc } = published

  const activeKey = await updateKeyMultibase({ seed: updateKeys.updateSeed })
  if (revokedClient.updateKeyMultibase === activeKey) {
    throw new Error(
      'did:webvh: a client cannot revoke itself; disconnect this client ' +
        'from another enrolled client instead.'
    )
  }

  const signingVmId = `${did}#${revokedClient.signingKeyMultibase}`
  const keyAgreementVmId = `${did}#${revokedClient.keyAgreementKeyMultibase}`
  const revokedHash = await deriveNextKeyHash(revokedClient.updateKeyMultibase)
  const existingMethods = (doc.verificationMethod ?? []) as VerificationMethod[]
  const vmPresent = existingMethods.some(
    method => method.id === signingVmId || method.id === keyAgreementVmId
  )
  const keyPresent = published.updateKeys.includes(
    revokedClient.updateKeyMultibase
  )
  const hashPresent = published.nextKeyHashes.includes(revokedHash)
  if (!vmPresent && !keyPresent && !hashPresent) {
    return { did }
  }

  if (!published.updateKeys.includes(activeKey)) {
    throw new Error(
      "did:webvh: the published log does not authorize this client's active " +
        'update key; finalize the pending rotation before revoking a client.'
    )
  }
  await assertCarryOverCommitments({ published })

  // The revoked client's staged commitment, recovered from the log while the
  // log still shows the enrollment (attribution needs the standing entries,
  // so this runs before the removal entry is built).
  const stagedHash = keyPresent
    ? await attributeStagedHash({
        log: published.log,
        revokedUpdateKey: revokedClient.updateKeyMultibase,
        knownLatentHashes
      })
    : undefined

  const removedHashes = new Set(
    [revokedHash, stagedHash].filter(
      (hash): hash is string => hash !== undefined
    )
  )
  const removedVmIds = new Set([signingVmId, keyAgreementVmId])
  const signer = await updateKeySigner({ seed: updateKeys.updateSeed })
  const updated = await updateDID({
    log: published.log,
    signer,
    updateKeys: published.updateKeys.filter(
      key => key !== revokedClient.updateKeyMultibase
    ),
    nextKeyHashes: published.nextKeyHashes.filter(
      hash => !removedHashes.has(hash)
    ),
    verificationMethods: existingMethods.filter(
      method => !method.id || !removedVmIds.has(method.id)
    ),
    authentication: relationIds(doc.authentication).filter(
      id => id !== signingVmId
    ),
    assertionMethod: relationIds(doc.assertionMethod).filter(
      id => id !== signingVmId
    ),
    keyAgreement: relationIds(doc.keyAgreement).filter(
      id => id !== keyAgreementVmId
    ),
    capabilityInvocation: relationIds(doc.capabilityInvocation).filter(
      id => id !== signingVmId
    ),
    capabilityDelegation: relationIds(doc.capabilityDelegation).filter(
      id => id !== signingVmId
    )
  })
  if (!updated.webDoc) {
    throw new Error(
      'did:webvh: updateDID returned no webDoc despite the did:web alsoKnownAs.'
    )
  }
  await publishWebvhLog({ idStore, log: updated.log, webDoc: updated.webDoc })
  return { did: updated.did }
}
