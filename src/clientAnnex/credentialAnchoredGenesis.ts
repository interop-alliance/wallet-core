/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The account-genesis ceremony's CREDENTIAL-ANCHORED variant: such a
 * signup mints no enrolled client, so the ceremony is anchored on the unlock
 * credential's ladder alone. The stage order mirrors `ensureAccountGenesis`
 * with the enrolled-client members swapped for their ladder analogs:
 *
 * 1. Space provisioning under the ladder VM's bare did:key -- the bootstrap
 *    controller (wallet-core decision 0004, freewallet decision 0002's
 *    resolution of the orphan-Space tear): re-derivable from the unlock
 *    record's ladder seed, so a tab death here strands nothing a later
 *    login cannot finish or unwind.
 * 2. The optional KMS key map (`provideDidWebKeys`), acquired only once the
 *    Space exists -- the enrolled-client ceremony's stage, verbatim: a
 *    KMS-keeping wallet creates the keystore under the ladder VM's bare
 *    did:key and writes keys.json and did.json into the Space here.
 *    Best-effort: a throw is collected and the genesis proceeds
 *    keystore-less; a later login's heal supplies the missing convenience
 *    key.
 * 3. The ladder-anchored did:webvh genesis
 *    (`ensureLadderAnchoredDidWebvh`): the entry signed by ladder rung 0,
 *    `updateKeys` = [rung 0], `nextKeyHashes` = [hash(rung 0), hash(rung 1)],
 *    the ladder VM and the credential's `keyAgreement` inventory folded in --
 *    plus, when stage 2 delivered a key map, the KMS-held authentication VM
 *    under `authentication` only -- `portable` unchanged.
 * 4. The user-key roster genesis, wrapped to the CREDENTIAL's standing
 *    key-agreement key -- the only recipient a ladder-anchored account has
 *    -- with the entry proof signed by the ladder VM (the ceremony-tail
 *    license's first-entry shape). The account is credential-recoverable
 *    from the moment this lands.
 * 5. Epoch[0] on every encrypted roster collection -- gated twice, unlike the
 *    enrolled-client flow. The roster stage must have landed, AND the roster's
 *    current epoch must BE the `userKey` this run was handed: the user key
 *    here exists only in this tab's memory, so installing collection epochs
 *    under a key the roster does not deliver would strand the collections on a
 *    key that dies with the tab. The second gate is what a re-run over an
 *    earlier run's roster hits: `read()` adopts a roster keyed to that run's
 *    user key, and this run's candidate key is a throwaway nobody holds --
 *    installing epoch[0] under it on a collection the earlier run never
 *    reached would key that collection to nothing, permanently, since the
 *    install is create-if-absent and every later ensure adopts it. So the
 *    stage is skipped whole and reported on `epochsSkipped`; the caller
 *    that recovers the roster's real key is the one installer. With both
 *    gates the tear heal is always clean: no roster means no epochs, and a
 *    fresh user key re-runs both.
 * 6. Space-controller promotion, last -- every earlier stage ran under the
 *    bootstrap did:key the Space's stored controller authorizes.
 *
 * Idempotent end to end on the enrolled-client flow's convention; the did:webvh
 * stage adopts a published log iff the ladder attributes it (a naive re-run
 * would mint a different SCID, so adoption IS the torn-signup convergence).
 */
import {
  initRecipients,
  type RecipientPublicKey
} from '@interop/was-client/edv'
import type { CollectionEncryption, WasClient } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'

import { provisionWalletSpace } from '../space/index.js'
import { ladderVmAgent } from './zcap.js'
import type { DIDLog } from '@interop/did-method-webvh'
import type {
  DidWebKeyMapV2,
  PublishedWebvhLog,
  WebvhIdStore
} from '../webvh/didWebvh.js'
import { ensureLadderAnchoredDidWebvh } from './ladderAnchored.js'
import type { UnlockKeyAgreementPublication } from '../unlock/standingWebvh.js'
import {
  ensureWalletSpaceEpochs,
  mintUserKey,
  type UserKey,
  type WalletSpaceEpochsResult
} from '../keys/index.js'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import {
  AccountGenesisSpaceError,
  ensurePromotedSpaceController,
  mintSpaceId,
  type AccountGenesisResult
} from '../genesis/accountGenesis.js'
import { stageNotifier, type StageNotifier } from '../log.js'

/**
 * The key set a credential-anchored signup mints locally before anything
 * touches the network: the data Space id and the account's user key -- nothing else.
 * No client seed and no client update-key seeds exist (that is the point);
 * the ladder seed is minted by the unlock layer beside the record that
 * carries it, and every other key derives from it.
 *
 * @returns {Promise<{ spaceId: string, userKey: Required<UserKey> }>}
 */
export async function mintCredentialAnchoredAccountKeySet(): Promise<{
  spaceId: string
  userKey: Required<UserKey>
}> {
  return { spaceId: mintSpaceId(), userKey: await mintUserKey() }
}

/**
 * Runs the credential-anchored account-genesis ceremony (see the module doc
 * for the stage order and its whys). The caller has already durably written the
 * unlock record carrying the ladder seed -- the transposed
 * persist-before-publish rule: rung 0 must never publish before the seed
 * that derives it is recoverable.
 *
 * @param options {object}
 * @param options.was {WasClient}   signing as the ladder VM's bare did:key
 *   (the bootstrap controller; build it over `ladderVmAgent`)
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed,
 *   already sealed into the durably written unlock record
 * @param options.keyAgreement {UnlockKeyAgreementPublication}   the
 *   credential's key-agreement publication (commitment or verbatim), folded
 *   into the genesis document
 * @param options.standingRecipient {RecipientPublicKey}   the credential's
 *   standing key-agreement key as a roster recipient (`id` its roster kid)
 * @param options.userKey {UserKey}   the account's user key, epoch[0] of the
 *   roster and recipient zero of every encrypted collection
 * @param options.idStore {WebvhIdStore}   the account's `id` collection
 *   store, signing as the same bootstrap did:key
 * @param options.rosterStoreFor {Function}   `({ did, log }) =>
 *   EncryptionDescriptorStore` -- the user-key roster's store once the DID is
 *   known, with a LADDER-signed `ResourceLogSigner` (the first-entry shape).
 *   `log` is the account log the did:webvh stage just adopted or published,
 *   so a store resolving its controller view can read it out of this run's
 *   own head instead of fetching `did.jsonl` again
 * @param [options.provideDidWebKeys] {Function}   `() =>
 *   Promise<DidWebKeyMapV2 | undefined>` -- the KMS key-map acquisition (a
 *   wallet that keeps a KMS runs its did:web provisioning here, after the
 *   Space exists, under the ladder VM's bare did:key); absent or resolving
 *   `undefined`, the genesis is ladder-and-credential-only and no `keys.json`
 *   is ever written. A throw is collected, not fatal: the genesis proceeds
 *   keystore-less and a later login heals the document with the convenience
 *   key
 * @param [options.expectedDid] {string}   the account DID, when the caller
 *   holds a pointer that already names one (a heal re-run); a fresh signup
 *   and a fresh-terminal heal legitimately hold none
 * @param [options.accountLogPinStore] {ResourceLogPinStore}   the chain-head
 *   pins the genesis read and create ride (a transient signup passes the
 *   visit's in-memory store)
 * @param [options.onDidPublished] {Function}   `({ did }) => Promise<void>`
 * @param [options.promoteController] {boolean}   default `true`; an app whose
 *   account pointer must durably name the DID first (freewallet's record
 *   re-bind) passes `false` and promotes after that write
 * @param [options.onStage] {StageNotifier}   observational: called as each
 *   stage finishes, with `space-provisioning`, `webvh-genesis`,
 *   `roster-genesis`, `collection-epochs`, and (only when this ceremony
 *   promotes) `controller-promotion`. Stage 2's own boundary is the
 *   caller's `provideDidWebKeys` thunk, which is where a caller marks it
 * @returns {Promise<AccountGenesisResult>}   with `published` and
 *   `logMinted` always set: the account log's verified head the did:webvh
 *   stage adopted or minted, and which of the two it was -- the head is only
 *   safely reusable downstream when this run minted it
 */
export async function ensureCredentialAnchoredAccountGenesis({
  was,
  wasServerUrl,
  spaceId,
  ladderSeed,
  keyAgreement,
  standingRecipient,
  userKey,
  idStore,
  rosterStoreFor,
  provideDidWebKeys,
  expectedDid,
  accountLogPinStore,
  onDidPublished,
  promoteController = true,
  onStage
}: {
  was: WasClient
  wasServerUrl: string
  spaceId: string
  ladderSeed: Uint8Array
  keyAgreement: UnlockKeyAgreementPublication
  standingRecipient: RecipientPublicKey
  userKey: UserKey
  idStore: WebvhIdStore
  rosterStoreFor: (options: {
    did: string
    log: DIDLog
  }) => EncryptionDescriptorStore
  provideDidWebKeys?: () => Promise<DidWebKeyMapV2 | undefined>
  expectedDid?: string
  accountLogPinStore?: ResourceLogPinStore
  onDidPublished?: (published: { did: string }) => Promise<void>
  promoteController?: boolean
  onStage?: StageNotifier
}): Promise<
  AccountGenesisResult & { published: PublishedWebvhLog; logMinted: boolean }
> {
  const failed: AccountGenesisResult['failed'] = []
  const stage = stageNotifier(onStage)
  const bootstrap = await ladderVmAgent({ ladderSeed })

  // 1. The Space and its collection roster, create-if-absent under the
  // ladder VM's bare did:key. The typed refusal, exactly as on the
  // enrolled-client flow: nothing downstream can proceed without a Space.
  try {
    await provisionWalletSpace({ was, spaceId, controllerDid: bootstrap.id })
  } catch (err) {
    throw new AccountGenesisSpaceError({ spaceId, cause: err })
  }
  stage('space-provisioning')

  // 2. The optional KMS key map, acquired only once the Space exists (a
  // KMS-keeping wallet creates the keystore under the ladder VM's bare
  // did:key and writes keys.json and did.json into the Space here). A throw
  // degrades to the ladder-and-credential-only genesis rather than aborting:
  // every later ceremony anchors in the ladder, and a later login heals the
  // document with the convenience key.
  let didWebKeys: DidWebKeyMapV2 | undefined
  if (provideDidWebKeys) {
    try {
      didWebKeys = await provideDidWebKeys()
    } catch (err) {
      failed.push({ stage: 'didWebKeys', error: err })
    }
  }

  // 3. The ladder-anchored did:webvh genesis -- probe, adopt
  // (ladder-attributed), or create-and-publish. Fatal on failure, like the
  // enrolled-client stage.
  const { did, published, logMinted } = await ensureLadderAnchoredDidWebvh({
    idStore,
    wasServerUrl,
    spaceId,
    ...(didWebKeys ? { didWebKeys } : {}),
    ladderSeed,
    keyAgreement,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(accountLogPinStore ? { pinStore: accountLogPinStore } : {})
  })
  await onDidPublished?.({ did })
  stage('webvh-genesis')

  // 4. The roster genesis: epoch[0] IS the user key, wrapped once, to the
  // credential's standing key-agreement key. The store's ladder-signed
  // genesis append is the ceremony-tail license's first-entry shape.
  let rosterDescriptor: CollectionEncryption | undefined
  try {
    const store = rosterStoreFor({ did, log: published.log })
    const current = await store.read()
    rosterDescriptor =
      current !== null
        ? current.descriptor
        : await initRecipients({
            store,
            recipients: [standingRecipient],
            epoch: { epochId: userKey.id, secret: userKey.secret }
          })
  } catch (err) {
    failed.push({ stage: 'roster', error: err })
  }
  stage('roster-genesis')

  // 5. Epoch[0] on every encrypted roster collection, only behind a landed
  // roster whose current epoch IS this run's user key (see the module doc:
  // the user key is memory-only here, and an adopted roster keyed to another
  // run's key would have the collections installed under a throwaway).
  let epochs: WalletSpaceEpochsResult | undefined
  let epochsSkipped: AccountGenesisResult['epochsSkipped']
  if (rosterDescriptor) {
    if (rosterDescriptor.currentEpoch === userKey.id) {
      try {
        epochs = await ensureWalletSpaceEpochs({ was, spaceId, userKey })
      } catch (err) {
        failed.push({ stage: 'epochs', error: err })
      }
    } else {
      epochsSkipped =
        rosterDescriptor.currentEpoch !== undefined
          ? { rosterEpochId: rosterDescriptor.currentEpoch }
          : {}
    }
  }
  stage('collection-epochs')

  // 6. The controller promotion, last. The bootstrap client IS the bare
  // did:key client, so it serves the heal branch too.
  let promotion: AccountGenesisResult['promotion']
  if (promoteController) {
    try {
      promotion = await ensurePromotedSpaceController({
        was,
        wasAsClient: was,
        spaceId,
        did
      })
    } catch (err) {
      failed.push({ stage: 'promotion', error: err })
    }
    stage('controller-promotion')
  }

  return {
    did,
    published,
    logMinted,
    ...(rosterDescriptor ? { rosterDescriptor } : {}),
    ...(epochs ? { epochs } : {}),
    ...(epochsSkipped ? { epochsSkipped } : {}),
    ...(promotion ? { promotion } : {}),
    failed
  }
}
