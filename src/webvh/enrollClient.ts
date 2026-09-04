/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The log half of the client enrollment ceremony: the two account-log entries
 * that publish a second wallet client into the account's did:webvh document.
 * The roster wrap that pairs with them is the enrollment module's, placed by
 * signer kind (`decisions/0018`).
 */
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import type { DIDLog, VerificationMethod } from '@interop/did-method-webvh'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import { relationIds } from '../resourceLog/document.js'
import { signAccountEntry } from './accountEntry.js'
import type { AccountLogSigner } from './accountEntry.js'
import {
  concludeWithPublishedLog,
  markedVerificationMethodPair,
  withLogConflictRetry
} from './didWebvh.js'
import type {
  PublishedWebvhLog,
  WebvhEnrollmentKeys,
  WebvhIdStore
} from './didWebvh.js'

/**
 * Enrolls a second wallet client into the published did:webvh document -- the
 * log half of the enrollment ceremony. Two entries, forced by prerotation (a
 * new update key must hash into the PREVIOUS entry's `nextKeyHashes`):
 *
 * 1. **Commit**: a sparse entry extending `nextKeyHashes` with the new
 *    client's update-key and staged-key hashes (document and `updateKeys`
 *    untouched).
 * 2. **Add**: an entry adding the new client's verification methods (its
 *    Ed25519 key under the four signing relationships, its X25519 twin under
 *    `keyAgreement`) and its update key to `updateKeys`.
 *
 * On the CLIENT arm both entries are signed by the enrolling client's active
 * update key (quorum-of-one: any single enrolled client can enroll). On the
 * LADDER arm they are signed by the acting credential's rung, through the
 * credential's bridge delegation: the commit entry carries the new client's
 * two hashes beside the rung's own carry-over hash, and the add entry is
 * signed by the same rung, revealed by the commit (`decisions/0018`).
 *
 * The ceremony is resumable from stored state alone: a tear after the commit
 * is detected by its hashes already standing in `nextKeyHashes` (skip to the
 * add entry), and a completed enrollment is detected by the update key
 * already being authorized (no-op). Re-running with the same key set
 * converges without forking the log.
 *
 * Each entry publishes conditionally on the read it was built on (the add
 * entry on the mid-ceremony re-read), so a concurrent ceremony -- a
 * revocation, another enrollment -- can never be erased by this one; a lost
 * race re-runs from the top (see {@link withLogConflictRetry}) and rebases on
 * the new head.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.signer {AccountLogSigner}   who signs both entries: the
 *   enrolling client's own update-key seeds, or the acting credential's
 *   ladder seed
 * @param options.newClient {WebvhEnrollmentKeys}   the enrollee's public
 *   halves
 * @param [options.expectedDid] {string}   the account DID the log must
 *   resolve to
 * @param [options.pinStore] {ResourceLogPinStore}   the caller's chain-head
 *   pins
 * @param [options.logId] {string}   the account log's pin slot; required
 *   whenever a `pinStore` is supplied
 * @returns {Promise<{ did: string, log: DIDLog }>}   the account DID and the
 *   post-add log -- the head this call published, or the already-enrolled
 *   head it found -- so an orchestrator can anchor what follows (the ladder
 *   branch's escrow append) at the add entry's version
 */
export async function enrollWebvhClient(options: {
  idStore: WebvhIdStore
  signer: AccountLogSigner
  newClient: WebvhEnrollmentKeys
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; log: DIDLog }> {
  return withLogConflictRetry(() => enrollWebvhClientOnce(options))
}

/**
 * One attempt of {@link enrollWebvhClient}, re-invoked by the conflict retry.
 *
 * @param options {object}   see {@link enrollWebvhClient}
 * @returns {Promise<{ did: string, log: DIDLog }>}
 */
async function enrollWebvhClientOnce({
  idStore,
  signer,
  newClient,
  expectedDid,
  pinStore,
  logId
}: {
  idStore: WebvhIdStore
  signer: AccountLogSigner
  newClient: WebvhEnrollmentKeys
  expectedDid?: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<{ did: string; log: DIDLog }> {
  const pinned = {
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(pinStore ? { pinStore } : {}),
    ...(logId !== undefined ? { logId } : {}),
    missingMessage: 'did:webvh: did.jsonl is missing; nothing to enroll into.'
  }
  const newUpdateKeyHash = await deriveNextKeyHash(newClient.updateKeyMultibase)
  const newStagedKeyHash = await deriveNextKeyHash(
    newClient.stagedUpdateKeyMultibase
  )
  let alreadyEnrolled: { did: string; log: DIDLog } | undefined

  // The commit entry (skipped when a torn earlier run already published it,
  // and when the enrollment is already complete).
  const commit = await signAccountEntry({
    idStore,
    signer,
    ...pinned,
    verb: 'enrolling',
    build: async ({ published }) => {
      // Already enrolled (a completed earlier run): the new client's update
      // key is authorized, which only the add entry writes. Idempotent no-op
      // on the log. On the client arm it still heals a did.json THIS
      // ceremony's earlier run left lagging (the enrolling client invokes as
      // the controller, so it may write it); a lag a ladder-signed entry left
      // is mended by `ensureDidWebProjection` instead.
      if (published.updateKeys.includes(newClient.updateKeyMultibase)) {
        alreadyEnrolled =
          signer.kind === 'client'
            ? {
                ...(await concludeWithPublishedLog({ idStore, published })),
                log: published.log
              }
            : { did: published.did, log: published.log }
        return undefined
      }
      if (
        published.nextKeyHashes.includes(newUpdateKeyHash) &&
        published.nextKeyHashes.includes(newStagedKeyHash)
      ) {
        return undefined
      }
      // A sparse entry re-states the authorized updateKeys, and the resolver
      // checks each against the PREVIOUS entry's commitments -- so every
      // currently authorized key's hash must already stand in nextKeyHashes
      // (the carry-over convention, asserted by the seam). A log minted
      // before the convention cannot take a non-rotating entry.
      return { commitHashes: [newUpdateKeyHash, newStagedKeyHash] }
    }
  })
  if (alreadyEnrolled) {
    return alreadyEnrolled
  }

  // The add entry: the new client's two verification methods and its update
  // key, on top of the full existing document (updateDID replaces the
  // verification-method set and relationship arrays wholesale). It reads for
  // itself through the same verifying path when the commit entry published,
  // so it always builds on the published, resolved state; when the commit was
  // skipped it builds on the read that skipped it.
  const carriedHead: { published?: PublishedWebvhLog } = commit.updated
    ? {}
    : { published: commit.published }
  const added = await signAccountEntry({
    idStore,
    signer,
    ...pinned,
    ...carriedHead,
    verb: 'enrolling',
    build: ({ published }) => {
      const { did, doc, updateKeys: authorizedKeys } = published
      const vmId = (publicKeyMultibase: string) =>
        `${did}#${publicKeyMultibase}`
      // The signing method is controlled by the account; the key-agreement
      // method alone carries the controller marker, and the pair builder
      // refuses a key-agreement key that is not the signing key's canonical
      // twin.
      const addedMethods: VerificationMethod[] = markedVerificationMethodPair({
        controller: did,
        signingKeyMultibase: newClient.signingKeyMultibase,
        keyAgreementKeyMultibase: newClient.keyAgreementKeyMultibase
      })
      const existingMethods = (doc.verificationMethod ??
        []) as VerificationMethod[]
      const verificationMethods = [
        ...existingMethods.filter(
          method => !addedMethods.some(add => add.id === method.id)
        ),
        ...addedMethods
      ]
      const withReference = (
        relation: Array<string | { id?: string }> | undefined,
        id: string
      ) => [...new Set([...relationIds(relation), id])]
      const signingVmId = vmId(newClient.signingKeyMultibase)
      return {
        updateKeys: [
          ...new Set([...authorizedKeys, newClient.updateKeyMultibase])
        ],
        verificationMethods,
        authentication: withReference(doc.authentication, signingVmId),
        assertionMethod: withReference(doc.assertionMethod, signingVmId),
        keyAgreement: withReference(
          doc.keyAgreement,
          vmId(newClient.keyAgreementKeyMultibase)
        ),
        capabilityInvocation: withReference(
          doc.capabilityInvocation,
          signingVmId
        ),
        capabilityDelegation: withReference(
          doc.capabilityDelegation,
          signingVmId
        )
      }
    }
  })
  const head = added.updated ?? added.published
  return { did: head.did, log: head.log }
}
