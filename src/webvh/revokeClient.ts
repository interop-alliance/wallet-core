/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Client revocation, the did:webvh half: removing an enrolled wallet client
 * from the document roster. Per the identity model this is a pure roster edit
 * -- nothing shared rotates, because nothing was shared -- and, because a
 * removal reveals no new key, it is a SINGLE log entry (unlike enrollment's
 * two): the client's Ed25519 verification method leaves all four signing
 * relationships, EVERY key-agreement method its controller marker claims
 * (`controller: did:key:<signing multibase>`, read off the document rather
 * than derived, so a client with several published keys is fully revoked and
 * a deliberately unmarked recovery-code method is never touched) leaves
 * `keyAgreement`, its update key leaves
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
 * Two shapes commit more than the staged hash in one entry: a recovery
 * continuation (the replacement code's latent hash rides beside it) and a
 * standing credential's reveal-and-commit self-enrollment (the ladder's
 * next-rung hash does). The caller first disambiguates by supplying the
 * standing recovery-code hashes it knows (`knownLatentHashes`, from its
 * recovery registry); when more than one candidate still survives, the
 * append-order convention of decision 0007 resolves it positionally -- the
 * staged hash is the addition immediately AFTER the revoked client's
 * update-key hash in the entry's `nextKeyHashes` append order (the next-rung
 * hash is last) -- and only a residue position cannot resolve either refuses
 * loudly rather than guessing ({@link StagedCommitmentAmbiguousError}):
 * removing a wrong hash would either leave the revoked client re-enrollable
 * or brick another party's standing commitment.
 */
import { deriveNextKeyHash, updateDID } from '@interop/did-method-webvh'
import type {
  DIDDoc,
  DIDLog,
  VerificationMethod
} from '@interop/did-method-webvh'
import { relationIds } from '../resourceLog/document.js'
import {
  assertCarryOverCommitments,
  concludeWithPublishedLog,
  effectiveParameters,
  publishUpdatedLog,
  readPublishedLog,
  updateKeyMultibase,
  updateKeySigner,
  withLogConflictRetry
} from './didWebvh.js'
import {
  attributeClientUpdateKey,
  listEnrolledWebvhClients,
  markedKeyAgreementMultibases
} from './listClients.js'
import type {
  ClientWebvhUpdateKeys,
  PublishedWebvhLog,
  WebvhIdStore
} from './didWebvh.js'

/**
 * The public halves of the client being revoked, as the document and log
 * carry them: its signing-key multibase and its active update key. The
 * staged-key hash is deliberately absent -- it is recovered from the log (see
 * the module doc), since no other party ever held the staged key.
 *
 * The key-agreement half is deliberately absent too: the removal reads every
 * key-agreement method the client's controller marker claims off the document
 * itself, so no caller-supplied key-agreement key is ever needed to revoke the
 * client completely.
 */
export interface RevokedClientKeys {
  signingKeyMultibase: string
  updateKeyMultibase: string
}

/**
 * Thrown when the log attribution cannot isolate the revoked client's staged
 * commitment to a single hash -- more than one candidate survives after the
 * known latent (recovery-code) hashes are excluded, and the decision-0007
 * append-order rule cannot resolve the residue positionally either (the
 * client's update-key hash is not among the entry's additions, or the
 * addition after it is not a surviving candidate). Refusing beats guessing:
 * see the module doc.
 *
 * **`name` is a stable contract.** It is always the string
 * `'StagedCommitmentAmbiguousError'`, and a consumer should match on that
 * rather than on `instanceof`: a wallet app that links this package (or holds
 * two copies of it through a dependency tree) gets a different class object for
 * the same error, so `instanceof` silently fails there while the name does not.
 */
export class StagedCommitmentAmbiguousError extends Error {
  candidates: string[]
  constructor({ candidates }: { candidates: string[] }) {
    super(
      "did:webvh: the revoked client's staged-key commitment cannot be " +
        'isolated in nextKeyHashes -- more than one candidate hash survives ' +
        'the known-latent-hash exclusion, and the append-order rule cannot ' +
        "place one immediately after the client's update-key hash."
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
  // Filtering the entry's own nextKeyHashes preserves its append order, which
  // the positional fallback below relies on (decision 0007).
  const orderedAdded = (index: number): string[] => {
    const previous = new Set(index > 0 ? params[index - 1]!.nextKeyHashes : [])
    return params[index]!.nextKeyHashes.filter(hash => !previous.has(hash))
  }
  const added = (index: number): Set<string> => new Set(orderedAdded(index))
  const prune = (candidates: Set<string>): Set<string> => {
    candidates.delete(revokedHash)
    for (const hash of knownLatentHashes) {
      candidates.delete(hash)
    }
    return candidates
  }
  // The decision-0007 positional rule, applied only when the prune leaves more
  // than one candidate: the staged hash is the addition immediately AFTER the
  // revoked client's update-key hash in the entry's append order (the ladder's
  // next-rung hash is last). Resolves undefined -- the ambiguity refusal
  // stands -- when the update-key hash is not among the entry's additions, or
  // its successor is not a surviving candidate.
  const stagedByPosition = (
    index: number,
    candidates: Set<string>
  ): string | undefined => {
    const additions = orderedAdded(index)
    const anchor = additions.indexOf(revokedHash)
    if (anchor === -1) {
      return undefined
    }
    const successor = additions[anchor + 1]
    return successor !== undefined && candidates.has(successor)
      ? successor
      : undefined
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
    const positional = stagedByPosition(revealIndex, atReveal)
    if (positional !== undefined) {
      return positional
    }
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
    const positional = stagedByPosition(commitIndex, atCommit)
    if (positional !== undefined) {
      return positional
    }
    throw new StagedCommitmentAmbiguousError({ candidates: [...atCommit] })
  }
  return atCommit.size === 1 ? [...atCommit][0] : undefined
}

/**
 * The revoked client's update key as the log states it NOW, which is not
 * necessarily the one the caller supplied: a listing is a snapshot, and the
 * client being revoked can self-rotate between the listing and the revocation
 * (its old key retired, a fresh one revealed). Acting on the stale key is the
 * dangerous shape -- the removal entry would strike nothing out of
 * `updateKeys` while the document edit still went through, returning success
 * over a client that kept full log-update authority.
 *
 * So while the client's verification methods still stand, membership in
 * `updateKeys` is the ONLY thing that accepts the supplied key. A key that is
 * merely committed in `nextKeyHashes` is not the client's active key at all --
 * it is the client's STAGED key (its hash committed, the key itself never
 * revealed), which a caller can easily have to hand beside the active one.
 * Acting on it would strike nothing out of `updateKeys` while the document
 * edit still landed: exactly the silent-authority-retention shape this
 * function exists to prevent. Both that shape and a plainly stale key resolve
 * the same way -- the client's current key is re-derived from the log by
 * attribution on its signing key (the same attribution the listing performs).
 * Re-deriving beats refusing here because the identity being revoked is the
 * verification method, not the key snapshot: telling the caller to re-list
 * would send it back into the same race, and the log states the answer
 * already. An attribution that cannot isolate a single key throws rather than
 * guessing -- removing a wrong key would revoke another client's authority.
 *
 * With NO verification methods published (`vmPresent` false) the supplied key
 * is returned verbatim, since there is no client in the document to attribute
 * against: either nothing of this client stands anywhere (the idempotent no-op
 * the caller falls through to), or a torn enrollment left only its committed
 * hash in `nextKeyHashes` with no methods yet published, and the removal entry
 * strikes that standing commitment.
 *
 * @param options {object}
 * @param options.published {PublishedWebvhLog}
 * @param options.revokedClient {RevokedClientKeys}
 * @param options.vmPresent {boolean}   whether the document still publishes
 *   the revoked client's verification methods
 * @returns {Promise<string>}
 */
async function currentRevokedUpdateKey({
  published,
  revokedClient,
  vmPresent
}: {
  published: PublishedWebvhLog
  revokedClient: RevokedClientKeys
  vmPresent: boolean
}): Promise<string> {
  const supplied = revokedClient.updateKeyMultibase
  if (published.updateKeys.includes(supplied)) {
    return supplied
  }
  if (!vmPresent) {
    // No client in the document to attribute against: the idempotent no-op
    // below, or a torn enrollment whose committed hash is all there is to
    // strike.
    return supplied
  }
  const attributed = attributeClientUpdateKey({
    log: published.log,
    signingKeyMultibase: revokedClient.signingKeyMultibase
  })
  if (!attributed) {
    throw new Error(
      'did:webvh: the update key supplied for the revoked client is not ' +
        'authorized by the log -- it either rotated away since the listing, ' +
        "or it is the client's staged key, committed but never revealed -- " +
        "and the log attribution cannot isolate the client's current update " +
        'key; re-list the enrolled clients and revoke with the active key the ' +
        'listing states.'
    )
  }
  return attributed
}

/**
 * What a removal edit strikes, computed from the published log before any
 * entry is built: the removed client's verification-method ids, whether any
 * of them still stand (`vmPresent`), the update key the LOG states for the
 * client now ({@link clientRemovalTarget} re-derives a stale or staged key by
 * attribution), that key's carry-over hash, and whether anything at all is
 * left to remove (`present`). Shared by the revocation entry
 * ({@link revokeWebvhClient}) and the ladder-signed forget entry
 * (`forgetWebvhClient` in the unlock module), so the two removal shapes can
 * never drift.
 */
export interface ClientRemovalTarget {
  signingVmId: string
  keyAgreementVmIds: Set<string>
  vmPresent: boolean
  removedUpdateKey: string
  removedHash: string
  keyPresent: boolean
  hashPresent: boolean
  present: boolean
}

/**
 * Computes what removing one enrolled client strikes from the published
 * document and log (see {@link ClientRemovalTarget}). Pure read: nothing is
 * published, and an absent client resolves with `present: false` rather than
 * throwing (the idempotent no-op the callers fall through to).
 *
 * @param options {object}
 * @param options.published {PublishedWebvhLog}
 * @param options.client {RevokedClientKeys}   the removed client's public
 *   halves; an `updateKeyMultibase` the log does not authorize (stale, or the
 *   client's staged key) is re-derived from the log
 * @returns {Promise<ClientRemovalTarget>}
 */
export async function clientRemovalTarget({
  published,
  client
}: {
  published: PublishedWebvhLog
  client: RevokedClientKeys
}): Promise<ClientRemovalTarget> {
  const { did, doc } = published
  const signingVmId = `${did}#${client.signingKeyMultibase}`
  // Every key-agreement method the removed client's controller marker claims,
  // read off the document rather than paired from the caller's snapshot: a
  // client that published more than one is fully removed, and a caller whose
  // snapshot named a key the document never carried cannot leave a live
  // method behind.
  const keyAgreementVmIds = new Set(
    markedKeyAgreementMultibases({
      doc,
      signingKeyMultibase: client.signingKeyMultibase
    }).map(multibase => `${did}#${multibase}`)
  )
  const existingMethods = (doc.verificationMethod ?? []) as VerificationMethod[]
  const vmPresent = existingMethods.some(
    method =>
      method.id === signingVmId ||
      (method.id !== undefined && keyAgreementVmIds.has(method.id))
  )

  // The key the log states for this client now, which a self-rotation since
  // the caller's listing may have moved on.
  const removedUpdateKey = await currentRevokedUpdateKey({
    published,
    revokedClient: client,
    vmPresent
  })
  const removedHash = await deriveNextKeyHash(removedUpdateKey)
  const keyPresent = published.updateKeys.includes(removedUpdateKey)
  const hashPresent = published.nextKeyHashes.includes(removedHash)
  return {
    signingVmId,
    keyAgreementVmIds,
    vmPresent,
    removedUpdateKey,
    removedHash,
    keyPresent,
    hashPresent,
    present: vmPresent || keyPresent || hashPresent
  }
}

/**
 * Builds the removal entry's document and parameter fields from a computed
 * target: the client's verification methods out of the document and all five
 * relationship arrays, its update key out of `updateKeys`, and its carry-over
 * and staged hashes out of `nextKeyHashes` (the staged hash recovered by log
 * attribution -- see the module doc for why leaving it would be a re-seizure
 * credential, and where the attribution is ambiguous). The caller supplies
 * these to `updateDID` beside its own signer -- an enrolled client's update
 * key for a revocation, a revealed ladder rung for a forget.
 *
 * @param options {object}
 * @param options.published {PublishedWebvhLog}
 * @param options.target {ClientRemovalTarget}
 * @param [options.knownLatentHashes] {string[]}   standing latent commitments
 *   the caller vouches for (the recovery registry's update-key hashes),
 *   excluded from the staged-hash attribution
 * @returns {Promise<object>}   the `updateDID` field bundle
 */
export async function clientRemovalFields({
  published,
  target,
  knownLatentHashes = []
}: {
  published: PublishedWebvhLog
  target: ClientRemovalTarget
  knownLatentHashes?: string[]
}): Promise<{
  updateKeys: string[]
  nextKeyHashes: string[]
  verificationMethods: VerificationMethod[]
  authentication: string[]
  assertionMethod: string[]
  keyAgreement: string[]
  capabilityInvocation: string[]
  capabilityDelegation: string[]
}> {
  const { doc } = published
  const { signingVmId, keyAgreementVmIds, removedUpdateKey } = target

  // The removed client's staged commitment, recovered from the log while the
  // log still shows the enrollment (attribution needs the standing entries,
  // so this runs before the removal entry is built).
  const stagedHash = target.keyPresent
    ? await attributeStagedHash({
        log: published.log,
        revokedUpdateKey: removedUpdateKey,
        knownLatentHashes
      })
    : undefined

  const removedHashes = new Set(
    [target.removedHash, stagedHash].filter(
      (hash): hash is string => hash !== undefined
    )
  )
  const removedVmIds = new Set([signingVmId, ...keyAgreementVmIds])
  const existingMethods = (doc.verificationMethod ?? []) as VerificationMethod[]
  return {
    updateKeys: published.updateKeys.filter(key => key !== removedUpdateKey),
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
      id => !keyAgreementVmIds.has(id)
    ),
    capabilityInvocation: relationIds(doc.capabilityInvocation).filter(
      id => id !== signingVmId
    ),
    capabilityDelegation: relationIds(doc.capabilityDelegation).filter(
      id => id !== signingVmId
    )
  }
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
 * update key, commitments all gone) is a no-op on the log (it still republishes
 * `did.json` from the resolved log, healing a torn earlier publish of this
 * cascade -- the revoking client invokes as the controller, so it may write
 * the projection), so a naive re-run after a mid-cascade crash converges
 * without forking the log.
 *
 * The supplied `updateKeyMultibase` is treated as a snapshot, not as truth: a
 * client that self-rotated between the caller's listing and this call -- or a
 * caller that supplied the client's staged key rather than its active one --
 * is revoked at the key the LOG states, re-derived by attribution (see
 * {@link currentRevokedUpdateKey}). Without that, a key that is not in
 * `updateKeys` would strike nothing out of it and the call would report
 * success over a client that kept full log-update authority.
 *
 * Self-revocation is refused: the entry is signed by THIS client's active
 * update key, and a client that removed its own key could not have signed
 * the removal the resolver will verify (and would strand the cascade that
 * follows the document edit). Revoking the last remaining client is refused
 * by the same guard.
 *
 * The removal entry publishes conditionally on the log this call read, so a
 * concurrent enrollment landing in between is never erased by the revocation
 * (nor the revocation by it): the loser re-runs and rebases its entry on the
 * winner's head (see `withLogConflictRetry`).
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.updateKeys {ClientWebvhUpdateKeys}   the REVOKING client's
 *   own did:webvh update-key seeds
 * @param options.revokedClient {RevokedClientKeys}   the revoked client's
 *   public halves; an `updateKeyMultibase` the log does not authorize (stale,
 *   or the client's staged key) is re-derived from the log
 * @param [options.knownLatentHashes] {string[]}   standing latent commitments
 *   the caller vouches for (the recovery registry's update-key hashes),
 *   excluded from the staged-hash attribution
 * @param [options.expectedDid] {string}   the account DID the log must resolve
 *   to, from the caller's stored account pointer
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}   the
 *   account's DID, its resolved document AFTER the edit -- what the roster
 *   rotation that follows resolves its remaining recipients from, so the
 *   caller needs no re-fetch of the log it just extended -- and the post-edit
 *   log itself, from which that rotation's controller view is built (the
 *   revocation cascade's post-edit anchoring). On the idempotent no-op path
 *   these are the already-published document and log, which state the same
 *   thing.
 */
export async function revokeWebvhClient(options: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  revokedClient: RevokedClientKeys
  knownLatentHashes?: string[]
  expectedDid?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  return withLogConflictRetry(() => revokeWebvhClientOnce(options))
}

/**
 * One attempt of {@link revokeWebvhClient}, re-invoked by the conflict retry.
 *
 * @param options {object}   see {@link revokeWebvhClient}
 * @returns {Promise<{ did: string, doc: DIDDoc, log: DIDLog }>}
 */
async function revokeWebvhClientOnce({
  idStore,
  updateKeys,
  revokedClient,
  knownLatentHashes = [],
  expectedDid
}: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  revokedClient: RevokedClientKeys
  knownLatentHashes?: string[]
  expectedDid?: string
}): Promise<{ did: string; doc: DIDDoc; log: DIDLog }> {
  const published = await readPublishedLog({
    idStore,
    ...(expectedDid !== undefined ? { expectedDid } : {})
  })
  if (!published) {
    throw new Error('did:webvh: did.jsonl is missing; nothing to revoke from.')
  }

  const target = await clientRemovalTarget({ published, client: revokedClient })

  const activeKey = await updateKeyMultibase({ seed: updateKeys.updateSeed })
  if (
    target.removedUpdateKey === activeKey ||
    revokedClient.updateKeyMultibase === activeKey
  ) {
    throw new Error(
      'did:webvh: a client cannot revoke itself; disconnect this client ' +
        'from another enrolled client instead.'
    )
  }

  if (!target.present) {
    // Nothing left to remove, but a torn earlier publish can still have left
    // did.json lagging the log. Reachable here because this path invokes as
    // the controller; a lag left by a ladder-signed entry is mended by
    // `ensureDidWebProjection` instead.
    const concluded = await concludeWithPublishedLog({ idStore, published })
    return { ...concluded, log: published.log }
  }

  if (!published.updateKeys.includes(activeKey)) {
    throw new Error(
      "did:webvh: the published log does not authorize this client's active " +
        'update key; finalize the pending rotation before revoking a client.'
    )
  }
  await assertCarryOverCommitments({ published })

  const fields = await clientRemovalFields({
    published,
    target,
    knownLatentHashes
  })
  const signer = await updateKeySigner({ seed: updateKeys.updateSeed })
  const updated = await updateDID({
    log: published.log,
    signer,
    alsoKnownAsWeb: true,
    ...fields
  })
  await publishUpdatedLog({ idStore, updated, ifMatch: published.etag })
  return { did: updated.did, doc: updated.doc, log: updated.log }
}

/**
 * The update keys and committed hashes that belong to the account's SURVIVING
 * enrolled clients -- what no credential retirement may ever strike, however
 * an attribution walk came by them.
 *
 * A ceremony that retires several credentials in one entry resolves each one's
 * rungs from the log, and a mis-anchored walk can land on an enrolled client's
 * key instead. Striking that key is silent and unhealable: the client keeps
 * its verification methods and its roster wrap, and simply can never extend
 * the account log again. So the protection is structural rather than a
 * property of the walk. Every client the document lists under
 * `capabilityInvocation` contributes its active update key (recovered by the
 * same attribution the listing performs), that key's carry-over hash, and its
 * staged hash where the log attributes one. An ambiguous staged attribution
 * protects every candidate, since over-protecting only leaves a rung standing
 * while under-protecting destroys a client.
 *
 * A client whose ACTIVE update key the listing cannot attribute at all is a
 * hole in that reasoning: it contributes nothing, so nothing of its would be
 * protected. Rather than protect a guess, the helper names it on `ambiguous`
 * and the caller withholds the whole strike. The same shape already disables
 * a row's disconnect in the clients surface.
 *
 * @param options {object}
 * @param options.log {DIDLog}   a resolved, caller-verified log, read BEFORE
 *   the entry is built
 * @param [options.retiredVmIds] {string[]}   verification-method ids the entry
 *   is retiring. A client whose marked `keyAgreement` method is among them is
 *   not surviving and contributes nothing. Credential-class members are never
 *   client-marked, so on today's ceremonies this list never matches; the
 *   parameter is what keeps that an assertion rather than an assumption
 * @param [options.knownLatentHashes] {string[]}   standing latent commitments
 *   the caller vouches for -- for a credential retirement, the rung hashes its
 *   own walks claimed. Excluded from the staged-hash attribution, so a
 *   retiring credential's rung committed beside a client's staged hash cannot
 *   make that attribution ambiguous and get itself protected
 * @returns {Promise<{ keys: Set<string>, hashes: Set<string>,
 *   ambiguous: string[] }>}
 */
export async function survivingClientKeyProtection({
  log,
  retiredVmIds = [],
  knownLatentHashes = []
}: {
  log: DIDLog
  retiredVmIds?: string[]
  knownLatentHashes?: string[]
}): Promise<{ keys: Set<string>; hashes: Set<string>; ambiguous: string[] }> {
  const keys = new Set<string>()
  const hashes = new Set<string>()
  const ambiguous: string[] = []
  if (log.length === 0) {
    return { keys, hashes, ambiguous }
  }
  const did = log[log.length - 1]!.state.id
  const retired = new Set(retiredVmIds)
  for (const client of listEnrolledWebvhClients({ log })) {
    const retiredHere = client.keyAgreementKeyMultibases.some(multibase =>
      retired.has(`${did}#${multibase}`)
    )
    if (retiredHere) {
      continue
    }
    const updateKey = client.updateKeyMultibase
    if (updateKey === undefined) {
      // Nothing of this client can be protected, so nothing may be struck.
      ambiguous.push(client.signingKeyMultibase)
      continue
    }
    keys.add(updateKey)
    hashes.add(await deriveNextKeyHash(updateKey))
    try {
      const staged = await attributeStagedHash({
        log,
        revokedUpdateKey: updateKey,
        knownLatentHashes
      })
      if (staged !== undefined) {
        hashes.add(staged)
      }
    } catch (err) {
      // Ambiguous: protect every candidate rather than none.
      if ((err as Error).name !== 'StagedCommitmentAmbiguousError') {
        throw err
      }
      for (const candidate of (err as StagedCommitmentAmbiguousError)
        .candidates) {
        hashes.add(candidate)
      }
    }
  }
  return { keys, hashes, ambiguous }
}
