/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The per-collection half of the user key rotation cascade: once the roster's
 * current epoch has moved to a fresh user key (a client revoked, a recovery
 * code spent or revoked), every encrypted collection must take a new epoch
 * naming the fresh user key and retire the old one -- otherwise writes keep
 * landing under an epoch key the revoked party still holds.
 *
 * The staleness rule is the one the revocation spike verified: **a collection
 * is stale exactly when its current epoch names a user key KAK other than the
 * roster's current** -- detectable from durable data alone, no checkpoint
 * resource anywhere, which is what makes a crashed cascade resumable by a naive
 * full re-run (and what the login-time completion sweep re-checks). Which KAKs
 * are "user key generations" is read from the roster itself: its epochs ARE the
 * user key generations, each escrow-wrapped to every enrolled client, so any
 * enrolled client can recover any generation's key ({@link
 * unwrapUserKeyGenerations}) -- needed both to recognize a stale epoch and to
 * escrow the fresh user key into a stranded collection's history.
 *
 * The cascade is rotation-only: every encrypted collection's descriptor
 * carries an epoch roster from provisioning (`ensureWalletSpaceEpochs`), so a
 * descriptor met without epochs can only mean a tampering or pre-provisioning
 * host and is refused fail-closed. A descriptor whose `currentEpoch` names no
 * epoch in its own list is refused the same way (the shape
 * `readUserKeyRoster` refuses on the roster itself): collection descriptors
 * arrive host-served with no server-side epoch invariants, so a mismatched
 * pair is a configuration no enrolled client authenticated, never something
 * to evaluate against the last epoch. No construction anywhere installs a
 * user-key secret as a collection epoch secret, which is what keeps a
 * collection-epoch escrow (an App Connect grant, a share) from ever handing a
 * grantee the user key itself.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import {
  addRecipient,
  epochKeyIdFor,
  hasKeyEpochs,
  replaceRecipient,
  unwrapEpochSecret,
  type EncryptionDescriptorStore,
  type RecipientPublicKey
} from '@interop/was-client/edv'
import { isSealableDescriptorStore } from './rosterLogStore.js'
import { userKeyVaultKeys, type UserKey } from './userKey.js'

/**
 * A user key presented as an epoch-roster recipient: the kid is the
 * self-describing `<did:key>#<fingerprint>` form every collection epoch names
 * the user under, and the public key is the did:key's own multibase.
 *
 * @param options {object}
 * @param options.userKey {UserKey}
 * @returns {RecipientPublicKey}
 */
export function userKeyAsRecipient({
  userKey
}: {
  userKey: UserKey
}): RecipientPublicKey {
  return {
    id: epochKeyIdFor(userKey.id),
    publicKeyMultibase: userKey.id.split(':')[2]!
  }
}

/**
 * Recovers every user key generation from the roster descriptor: each roster
 * epoch is one generation (its id the generation's did:key, its wrapped secret
 * the generation's raw key), escrow-wrapped to every enrolled client -- so this
 * client's key-agreement key unwraps them all, in roster (chronological) order.
 * A generation whose wrap is missing or fails to unwrap is skipped rather than
 * fatal (the cascade then simply cannot recognize or escrow that generation;
 * the current epoch always unwraps or the roster read itself would have
 * refused).
 *
 * @param options {object}
 * @param options.descriptor {CollectionEncryption}   the roster descriptor
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key
 * @returns {Promise<UserKey[]>}   the generations, oldest first
 */
export async function unwrapUserKeyGenerations({
  descriptor,
  clientKeyAgreementKey
}: {
  descriptor: CollectionEncryption
  clientKeyAgreementKey: IKeyAgreementKey
}): Promise<UserKey[]> {
  const generations: UserKey[] = []
  for (const epoch of descriptor.epochs ?? []) {
    const entry = epoch.recipients.find(
      recipient => recipient.header.kid === clientKeyAgreementKey.id
    )
    if (!entry) {
      continue
    }
    const secret = await unwrapEpochSecret({
      entry,
      keyAgreementKey: clientKeyAgreementKey
    })
    if (secret) {
      generations.push({ id: epoch.id, secret })
    }
  }
  return generations
}

/**
 * What one collection's cascade step did: `noop` (already on the current user
 * key), `sealed` (already on the current user key, but the collection's
 * governing log still anchored before the membership change -- the backstop
 * append landed), `escrowed` (the current user key's wrap was completed into
 * history with no stale epoch to rotate), or `rotated` (a fresh epoch sealed
 * to the current user key, the stale generations retired).
 */
export type CollectionUserKeyRotationOutcome =
  'noop' | 'sealed' | 'escrowed' | 'rotated'

/**
 * Brings ONE encrypted collection's epoch roster onto the current user key --
 * the per-collection op of the revocation cascade and of the completion sweep:
 *
 * - **Stale current epoch** (names a non-current generation): one
 *   `replaceRecipient` write -- the current user key escrowed into every epoch,
 *   a fresh epoch minted without the stale generations. Two requests per
 *   collection; app recipients and other readers ride through untouched (the
 *   default did:key resolver re-wraps them).
 * - **Current already** and fully escrowed: no epoch write at all, so a naive
 *   re-run after a mid-cascade crash converges with zero redundant epochs. On
 *   a log-governed (sealable) store this is exactly where an unsealed log can
 *   hide -- the rotation that should have re-anchored the log never wrote --
 *   so the store's seal backstop runs here (`sealed` when it appended);
 *   rotated and escrowed writes seal by construction, anchored at the
 *   caller's current controller head.
 * - **No epochs**, or a `currentEpoch` naming no epoch in the descriptor's
 *   own list: refused fail-closed (see the module doc) -- provisioning
 *   installs every encrypted collection's epoch[0], so the cascade never
 *   mints a first epoch, and never guesses which epoch an inconsistent
 *   descriptor meant.
 *
 * The pull axis is deliberately a no-op here: a user key rotation follows a
 * document edit (client revocation, code retirement) that already killed the
 * revoked party's server-side access everywhere under the current-key-set
 * rule -- there is no per-collection revoke.
 *
 * @param options {object}
 * @param options.store {EncryptionDescriptorStore}   the collection's
 *   descriptor store
 * @param options.userKey {UserKey}   the roster's CURRENT user key
 * @param options.generations {UserKey[]}   every roster generation this client
 *   could unwrap ({@link unwrapUserKeyGenerations}), oldest first
 * @returns {Promise<CollectionUserKeyRotationOutcome>}
 */
export async function rotateCollectionEpochsToUserKey({
  store,
  userKey,
  generations
}: {
  store: EncryptionDescriptorStore
  userKey: UserKey
  generations: UserKey[]
}): Promise<CollectionUserKeyRotationOutcome> {
  const current = await store.read()
  if (current === null) {
    return 'noop'
  }
  const descriptor = current.descriptor
  const staleGenerations = generations.filter(
    generation => generation.id !== userKey.id
  )

  if (!hasKeyEpochs(descriptor)) {
    throw new Error(
      'The collection descriptor carries no key epochs. Every encrypted ' +
        'collection installs its epoch[0] at provision time, so an ' +
        'epoch-less descriptor can only come from a tampering or ' +
        'pre-provisioning host; refusing to rotate it.'
    )
  }

  const currentEpoch = descriptor.epochs.find(
    epoch => epoch.id === descriptor.currentEpoch
  )
  if (!currentEpoch) {
    throw new Error(
      "The collection descriptor's currentEpoch names no epoch in its own " +
        'epochs list. No enrolled client authenticated such a configuration; ' +
        'refusing to evaluate it against any other epoch.'
    )
  }
  const currentKids = new Set(
    currentEpoch.recipients.map(entry => entry.header.kid)
  )
  const staleKids = staleGenerations
    .map(generation => epochKeyIdFor(generation.id))
    .filter(kid => currentKids.has(kid))
  const userKeyKid = epochKeyIdFor(userKey.id)

  if (staleKids.length === 0) {
    const escrowComplete = (descriptor.epochs ?? []).every(epoch =>
      epoch.recipients.some(entry => entry.header.kid === userKeyKid)
    )
    if (currentKids.has(userKeyKid) && escrowComplete) {
      if (isSealableDescriptorStore(store)) {
        return (await store.seal()) === 'sealed' ? 'sealed' : 'noop'
      }
      return 'noop'
    }
  }
  if (staleKids.length > 0) {
    // The escrow owner: the newest stale generation still named by the
    // current epoch, which the cascade invariant escrowed into every prior
    // epoch -- so it unwraps the whole history for the fresh user key's escrow.
    const ownerGeneration = [...staleGenerations]
      .reverse()
      .find(generation => currentKids.has(epochKeyIdFor(generation.id)))!
    const owner = userKeyVaultKeys({ userKey: ownerGeneration })
    await replaceRecipient({
      store,
      retire: staleKids,
      recipient: userKeyAsRecipient({ userKey }),
      owner: { keyAgreementKey: owner.keyAgreementKey },
      pull: async () => {}
    })
    return 'rotated'
  }

  if (!currentKids.has(userKeyKid)) {
    // No stale generation to retire, but the current user key is not a recipient
    // at all: this collection's roster is not user-key-owned in a shape this
    // cascade can heal -- surface it rather than silently minting an epoch
    // whose history the account cannot read.
    throw new Error(
      'The collection current epoch names no user key generation this client ' +
        'can recognize; its roster cannot be rotated to the current user key.'
    )
  }

  // Escrow completion only: the current epoch is already on the current user key,
  // but some historical epoch is missing its wrap. The owner must unwrap
  // exactly those epochs -- the newest generation named by every incomplete
  // epoch.
  const incomplete = (descriptor.epochs ?? []).filter(
    epoch => !epoch.recipients.some(entry => entry.header.kid === userKeyKid)
  )
  const escrowOwner = [...generations]
    .reverse()
    .find(generation =>
      incomplete.every(epoch =>
        epoch.recipients.some(
          entry => entry.header.kid === epochKeyIdFor(generation.id)
        )
      )
    )
  if (!escrowOwner) {
    throw new Error(
      "The current user key cannot be escrowed into this collection's history: " +
        'no held user key generation is a recipient of every incomplete epoch.'
    )
  }
  const owner = userKeyVaultKeys({ userKey: escrowOwner })
  await addRecipient({
    store,
    recipient: userKeyAsRecipient({ userKey }),
    owner: { keyAgreementKey: owner.keyAgreementKey }
  })
  return 'escrowed'
}

/**
 * What the collection fan-out did, per collection id: the outcomes for every
 * collection that needed (or took) work, and the per-collection failures the
 * caller surfaces -- the cascade never aborts on one stuck collection.
 */
export interface UserKeyCascadeResult {
  outcomes: Record<string, CollectionUserKeyRotationOutcome>
  failed: Array<{ collectionId: string; error: unknown }>
}

/**
 * The collection fan-out of the user key rotation cascade: re-epochs every
 * named collection onto the roster's current user key, in parallel, unwrapping
 * the user key generations from the roster once. The wallet supplies what only
 * it knows -- which collections exist (`collectionIds`) and how to reach each
 * one's descriptor (`storeFor`); the per-collection staleness rule and re-epoch
 * live in {@link rotateCollectionEpochsToUserKey}.
 *
 * A collection that fails is reported in `failed` and the rest proceed; the
 * caller decides what a failure means (the login-time completion sweep is the
 * standing backstop, and the staleness rule makes a naive full re-run
 * converge with zero redundant epochs).
 *
 * @param options {object}
 * @param options.collectionIds {string[]}   the encrypted collections to
 *   cover, deduplicated by the caller
 * @param options.storeFor {Function}   `(collectionId) =>
 *   EncryptionDescriptorStore` -- the collection's descriptor store
 * @param [options.isEncrypted] {Function}   `(collectionId) =>
 *   Promise<boolean>` -- optional pre-filter, checked inside each collection's
 *   own task so a throwing check lands in that collection's `failed` entry
 *   (e.g. a standard collection an account never provisioned server-side)
 * @param options.rosterDescriptor {CollectionEncryption}   the freshly read
 *   `key-map/user-key.jsonl` roster (the source of the user key generations)
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key, unwrapping the generations
 * @param options.userKey {UserKey}   the roster's current user key
 * @returns {Promise<UserKeyCascadeResult>}
 */
export async function cascadeCollectionsToUserKey({
  collectionIds,
  storeFor,
  isEncrypted,
  rosterDescriptor,
  clientKeyAgreementKey,
  userKey
}: {
  collectionIds: string[]
  storeFor: (collectionId: string) => EncryptionDescriptorStore
  isEncrypted?: (collectionId: string) => Promise<boolean>
  rosterDescriptor: CollectionEncryption
  clientKeyAgreementKey: IKeyAgreementKey
  userKey: UserKey
}): Promise<UserKeyCascadeResult> {
  const generations = await unwrapUserKeyGenerations({
    descriptor: rosterDescriptor,
    clientKeyAgreementKey
  })
  const outcomes: Record<string, CollectionUserKeyRotationOutcome> = {}
  const failed: Array<{ collectionId: string; error: unknown }> = []
  await Promise.all(
    collectionIds.map(async collectionId => {
      try {
        if (isEncrypted && !(await isEncrypted(collectionId))) {
          return
        }
        outcomes[collectionId] = await rotateCollectionEpochsToUserKey({
          store: storeFor(collectionId),
          userKey,
          generations
        })
      } catch (err) {
        failed.push({ collectionId, error: err })
      }
    })
  )
  return { outcomes, failed }
}
