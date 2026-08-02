/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The per-collection half of the PUK rotation cascade: once the roster's
 * current epoch has moved to a fresh PUK (a client revoked, a recovery code
 * spent or revoked), every encrypted collection must take a new epoch naming
 * the fresh PUK and retire the old one -- otherwise writes keep landing under
 * an epoch key the revoked party still holds.
 *
 * The staleness rule is the one the revocation spike verified: **a collection
 * is stale exactly when its current epoch names a PUK KAK other than the
 * roster's current** -- detectable from durable data alone, no checkpoint
 * resource anywhere, which is what makes a crashed cascade resumable by a
 * naive full re-run (and what the login-time completion sweep re-checks).
 * Which KAKs are "PUK generations" is read from the roster itself: its epochs
 * ARE the PUK generations, each escrow-wrapped to every enrolled client, so
 * any enrolled client can recover any generation's key
 * ({@link unwrapPukGenerations}) -- needed both to recognize a stale epoch
 * and to escrow the fresh PUK into a stranded collection's history.
 *
 * One residue, accepted: a collection with NO epochs gets the newest prior
 * generation installed as its first epoch (pre-epoch envelopes are sealed to
 * the era's PUK KAK, and the PUK IS the epoch construction, so they ARE
 * epoch-of-that-generation envelopes) -- envelopes older than that
 * generation, on a collection every prior cascade missed, stay readable only
 * to sessions that held the older key.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import {
  addRecipient,
  epochKeyIdFor,
  initRecipients,
  replaceRecipient,
  unwrapEpochSecret,
  type EncryptionDescriptorStore,
  type RecipientPublicKey
} from '@interop/was-client/edv'
import { ValidationError } from '@interop/was-client'
import { pukVaultKeys, type Puk } from './puk.js'

/**
 * A PUK presented as an epoch-roster recipient: the kid is the
 * self-describing `<did:key>#<fingerprint>` form every collection epoch names
 * the user under, and the public key is the did:key's own multibase.
 *
 * @param options {object}
 * @param options.puk {Puk}
 * @returns {RecipientPublicKey}
 */
export function pukAsRecipient({ puk }: { puk: Puk }): RecipientPublicKey {
  return {
    id: epochKeyIdFor(puk.id),
    publicKeyMultibase: puk.id.split(':')[2]!
  }
}

/**
 * Recovers every PUK generation from the roster descriptor: each roster epoch
 * is one generation (its id the generation's did:key, its wrapped secret the
 * generation's raw key), escrow-wrapped to every enrolled client -- so this
 * client's key-agreement key unwraps them all, in roster (chronological)
 * order. A generation whose wrap is missing or fails to unwrap is skipped
 * rather than fatal (the cascade then simply cannot recognize or escrow that
 * generation; the current epoch always unwraps or the roster read itself
 * would have refused).
 *
 * @param options {object}
 * @param options.descriptor {CollectionEncryption}   the roster descriptor
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key
 * @returns {Promise<Puk[]>}   the generations, oldest first
 */
export async function unwrapPukGenerations({
  descriptor,
  clientKeyAgreementKey
}: {
  descriptor: CollectionEncryption
  clientKeyAgreementKey: IKeyAgreementKey
}): Promise<Puk[]> {
  const generations: Puk[] = []
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
 * What one collection's cascade step did: `noop` (already on the current
 * PUK), `installed` (a pre-epoch collection on a first-generation account
 * gained its first epoch; nothing to retire), `escrowed` (the current PUK's
 * wrap was completed into history with no stale epoch to rotate), or
 * `rotated` (a fresh epoch sealed to the current PUK, the stale generations
 * retired -- the pre-epoch install falls through to this).
 */
export type CollectionPukRotationOutcome =
  'noop' | 'installed' | 'escrowed' | 'rotated'

/**
 * Brings ONE encrypted collection's epoch roster onto the current PUK -- the
 * per-collection op of the revocation cascade and of the completion sweep:
 *
 * - **No epochs yet**: install the newest PRIOR generation as the first epoch
 *   (see the module doc), wrapped to that generation and the current PUK,
 *   then fall through to the rotation. A first-generation account (nothing
 *   prior) installs the current PUK alone and is done.
 * - **Stale current epoch** (names a non-current generation): one
 *   `replaceRecipient` write -- the current PUK escrowed into every epoch,
 *   a fresh epoch minted without the stale generations. Two requests per
 *   collection; app recipients and other readers ride through untouched (the
 *   default did:key resolver re-wraps them).
 * - **Current already** and fully escrowed: no write at all, so a naive
 *   re-run after a mid-cascade crash converges with zero redundant epochs.
 *
 * The pull axis is deliberately a no-op here: a PUK rotation follows a
 * document edit (client revocation, code retirement) that already killed the
 * revoked party's server-side access everywhere under the current-key-set
 * rule -- there is no per-collection revoke.
 *
 * @param options {object}
 * @param options.store {EncryptionDescriptorStore}   the collection's
 *   descriptor store
 * @param options.puk {Puk}   the roster's CURRENT PUK
 * @param options.generations {Puk[]}   every roster generation this client
 *   could unwrap ({@link unwrapPukGenerations}), oldest first
 * @returns {Promise<CollectionPukRotationOutcome>}
 */
export async function rotateCollectionEpochsToPuk({
  store,
  puk,
  generations
}: {
  store: EncryptionDescriptorStore
  puk: Puk
  generations: Puk[]
}): Promise<CollectionPukRotationOutcome> {
  const current = await store.read()
  if (current === null) {
    return 'noop'
  }
  let descriptor = current.descriptor
  const staleGenerations = generations.filter(
    generation => generation.id !== puk.id
  )

  if (!descriptor.epochs?.length || !descriptor.currentEpoch) {
    // Pre-epoch: the collection's envelopes are sealed to the era's PUK KAK,
    // which -- the PUK being the epoch construction -- makes them epoch-of-
    // that-generation envelopes. Install that generation as the first epoch.
    const previous = staleGenerations[staleGenerations.length - 1]
    if (!previous) {
      await initRecipients({
        store,
        recipients: [pukAsRecipient({ puk })],
        epoch: { epochId: puk.id, secret: puk.secret }
      })
      return 'installed'
    }
    try {
      descriptor = await initRecipients({
        store,
        recipients: [
          pukAsRecipient({ puk: previous }),
          pukAsRecipient({ puk })
        ],
        epoch: { epochId: previous.id, secret: previous.secret }
      })
    } catch (err) {
      // A concurrent cascade won the first-epoch race; re-read and continue
      // into the rotation below against whatever it installed.
      if (!(err instanceof ValidationError)) {
        throw err
      }
      const reread = await store.read()
      if (reread === null) {
        throw err
      }
      descriptor = reread.descriptor
    }
  }

  const currentEpoch =
    descriptor.epochs!.find(epoch => epoch.id === descriptor.currentEpoch) ??
    descriptor.epochs![descriptor.epochs!.length - 1]!
  const currentKids = new Set(
    currentEpoch.recipients.map(entry => entry.header.kid)
  )
  const staleKids = staleGenerations
    .map(generation => epochKeyIdFor(generation.id))
    .filter(kid => currentKids.has(kid))
  const pukKid = epochKeyIdFor(puk.id)

  if (staleKids.length === 0) {
    const escrowComplete = (descriptor.epochs ?? []).every(epoch =>
      epoch.recipients.some(entry => entry.header.kid === pukKid)
    )
    if (currentKids.has(pukKid) && escrowComplete) {
      return 'noop'
    }
  }
  if (staleKids.length > 0) {
    // The escrow owner: the newest stale generation still named by the
    // current epoch, which the cascade invariant escrowed into every prior
    // epoch -- so it unwraps the whole history for the fresh PUK's escrow.
    const ownerGeneration = [...staleGenerations]
      .reverse()
      .find(generation => currentKids.has(epochKeyIdFor(generation.id)))!
    const owner = pukVaultKeys({ puk: ownerGeneration })
    await replaceRecipient({
      store,
      retire: staleKids,
      recipient: pukAsRecipient({ puk }),
      owner: { keyAgreementKey: owner.keyAgreementKey },
      pull: async () => {}
    })
    return 'rotated'
  }

  if (!currentKids.has(pukKid)) {
    // No stale generation to retire, but the current PUK is not a recipient
    // at all: this collection's roster is not PUK-owned in a shape this
    // cascade can heal -- surface it rather than silently minting an epoch
    // whose history the account cannot read.
    throw new Error(
      'The collection current epoch names no PUK generation this client ' +
        'can recognize; its roster cannot be rotated to the current PUK.'
    )
  }

  // Escrow completion only: the current epoch is already on the current PUK,
  // but some historical epoch is missing its wrap. The owner must unwrap
  // exactly those epochs -- the newest generation named by every incomplete
  // epoch.
  const incomplete = (descriptor.epochs ?? []).filter(
    epoch => !epoch.recipients.some(entry => entry.header.kid === pukKid)
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
      "The current PUK cannot be escrowed into this collection's history: " +
        'no held PUK generation is a recipient of every incomplete epoch.'
    )
  }
  const owner = pukVaultKeys({ puk: escrowOwner })
  await addRecipient({
    store,
    recipient: pukAsRecipient({ puk }),
    owner: { keyAgreementKey: owner.keyAgreementKey }
  })
  return 'escrowed'
}

/**
 * What the collection fan-out did, per collection id: the outcomes for every
 * collection that needed (or took) work, and the per-collection failures the
 * caller surfaces -- the cascade never aborts on one stuck collection.
 */
export interface PukCascadeResult {
  outcomes: Record<string, CollectionPukRotationOutcome>
  failed: Array<{ collectionId: string; error: unknown }>
}

/**
 * The collection fan-out of the PUK rotation cascade: re-epochs every named
 * collection onto the roster's current PUK, in parallel, unwrapping the PUK
 * generations from the roster once. The wallet supplies what only it knows --
 * which collections exist (`collectionIds`) and how to reach each one's
 * descriptor (`storeFor`); the per-collection staleness rule and re-epoch live
 * in {@link rotateCollectionEpochsToPuk}.
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
 *   `key-map/puk.json` roster (the source of the PUK generations)
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key, unwrapping the generations
 * @param options.puk {Puk}   the roster's current PUK
 * @returns {Promise<PukCascadeResult>}
 */
export async function cascadeCollectionsToPuk({
  collectionIds,
  storeFor,
  isEncrypted,
  rosterDescriptor,
  clientKeyAgreementKey,
  puk
}: {
  collectionIds: string[]
  storeFor: (collectionId: string) => EncryptionDescriptorStore
  isEncrypted?: (collectionId: string) => Promise<boolean>
  rosterDescriptor: CollectionEncryption
  clientKeyAgreementKey: IKeyAgreementKey
  puk: Puk
}): Promise<PukCascadeResult> {
  const generations = await unwrapPukGenerations({
    descriptor: rosterDescriptor,
    clientKeyAgreementKey
  })
  const outcomes: Record<string, CollectionPukRotationOutcome> = {}
  const failed: Array<{ collectionId: string; error: unknown }> = []
  await Promise.all(
    collectionIds.map(async collectionId => {
      try {
        if (isEncrypted && !(await isEncrypted(collectionId))) {
          return
        }
        outcomes[collectionId] = await rotateCollectionEpochsToPuk({
          store: storeFor(collectionId),
          puk,
          generations
        })
      } catch (err) {
        failed.push({ collectionId, error: err })
      }
    })
  )
  return { outcomes, failed }
}
