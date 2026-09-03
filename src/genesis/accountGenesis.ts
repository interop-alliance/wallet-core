/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The account-genesis ceremony: minting a brand-new wallet account's key set
 * and provisioning its data Space, in the one stage order every wallet app
 * must encode identically -- Space provisioning, did:webvh genesis, user-key
 * roster genesis (after DID publication, so the roster log's entry proofs
 * anchor in the published document), epoch[0] on every encrypted roster
 * collection, and Space-controller promotion.
 *
 * Two callers, one ceremony. A wallet that keeps a KMS (freewallet) supplies
 * `provideDidWebKeys` and gets the KMS-backed did:webvh genesis; a wallet
 * with no KMS anywhere in the path (dcw) supplies nothing and gets the
 * client-keys-only genesis. The keyring bind is deliberately NOT a stage:
 * where an app binds an unlock method (and whether it binds one at all)
 * stays app-side, as does the `userExists` probe -- that probe exists only
 * because a passphrase signup can collide with an existing account, which is
 * an unlock-layer concern, not an account-genesis one.
 *
 * Every stage detects its own completion from durable state alone (the
 * cascade/sweep pattern): the Space provisioning and the epoch install are
 * create-if-absent and adopt what an earlier provisioner landed, the
 * did:webvh genesis probes `did.jsonl` and adopts a log its seeds still
 * authorize, the roster genesis returns an existing roster untouched, and
 * the promotion is a state machine over the Space Description. So a torn run
 * heals by naively re-running the whole ceremony, backstopped by the
 * login-time sweeps.
 *
 * The essential identity chain -- Space provisioning and the did:webvh
 * genesis -- throws on failure (nothing downstream can proceed without it);
 * the stages after it are collected in `failed` instead, so a transient
 * failure on one never costs the caller the others' outcomes -- a completed
 * call with `failed` entries is a resumable success, finished by a re-run.
 */
import { base64urlnopad } from '@scure/base'
import type { CollectionEncryption, WasClient } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'

import { provisionWalletSpace, WALLET_SPACE_NAME } from '../space/index.js'
import {
  clientSigningKeyMultibase,
  ensureDidWebvh,
  mintClientWebvhUpdateKeys,
  type ClientWebvhUpdateKeys,
  type DidWebKeyMapV2,
  type ICapabilityAgent,
  type PublishedWebvhLog,
  type WebvhIdStore
} from '../webvh/index.js'
import {
  ensureUserKeyRoster,
  ensureWalletSpaceEpochs,
  mintUserKey,
  type UserKey,
  type WalletSpaceEpochsResult
} from '../keys/index.js'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'

/**
 * The byte length of a freshly minted data-Space id.
 */
const SPACE_ID_BYTES = 32

/**
 * The complete key set a brand-new account mints locally before anything
 * touches the network: the data Space id, this founding client's identity
 * seed, the account's user key, and the client-held did:webvh update-key
 * seeds. Persisting the set client-local (under the app's unlock layer) is
 * the caller's job, and for the update keys it must happen BEFORE
 * {@link ensureAccountGenesis} publishes anything -- the seeds are the only
 * update authority the log will ever accept.
 */
export interface AccountKeySet {
  spaceId: string
  clientSeed: Uint8Array
  userKey: Required<UserKey>
  updateKeys: ClientWebvhUpdateKeys
}

/**
 * Mints a fresh data-Space id: 32 random bytes, base64url without padding.
 * Random rather than controller-derived on purpose: the Space's controller is
 * promoted to a did:webvh whose id embeds this Space id, so a
 * controller-derived id would be circular.
 *
 * @returns {string}
 */
export function mintSpaceId(): string {
  return base64urlnopad.encode(
    crypto.getRandomValues(new Uint8Array(SPACE_ID_BYTES))
  )
}

/**
 * Mints the complete key set of a brand-new account: a fresh Space id, a
 * 32-byte client identity seed (expanded to the founding client's agents via
 * `agentsFromSeed`), the account's user key, and the did:webvh update-key
 * pair. Pure minting -- nothing here touches the network or any store.
 *
 * @returns {Promise<AccountKeySet>}
 */
export async function mintAccountKeySet(): Promise<AccountKeySet> {
  const clientSeed = crypto.getRandomValues(new Uint8Array(32))
  return {
    spaceId: mintSpaceId(),
    clientSeed,
    userKey: await mintUserKey(),
    updateKeys: await mintClientWebvhUpdateKeys()
  }
}

/**
 * What the promotion stage found and did: `promoted` (the Space Description
 * named another controller -- on a fresh signup, this founding client's
 * did:key -- and the ceremony moved it to the account DID), `confirmed` (the
 * Space already names the account DID; nothing written), or `healed` (the
 * Description was unreadable under the session's signing identity -- the torn
 * state where the controller PUT never landed -- and the re-PUT signed as the
 * stored did:key controller landed it).
 */
export type SpaceControllerPromotion = 'promoted' | 'confirmed' | 'healed'

/**
 * Promotes the data Space's controller to the account's did:webvh, as a state
 * machine over the Space Description so every state a torn earlier run can
 * leave behind converges:
 *
 * - The Description reads and already names `did`: nothing to do.
 * - The Description reads and names another controller (a fresh signup: this
 *   founding client's did:key, which `was` is then signing as): one configure
 *   PUT moves it to `did`.
 * - The Description is unreadable (`null` covers both absent and
 *   unauthorized): the torn case, where the session already signs under the
 *   did:webvh but the controller PUT never landed, so the server still
 *   authorizes only the stored did:key controller. The re-PUT goes through
 *   `wasAsClient`, the handle signing under this client's plain did:key.
 *
 * The PUT always carries the full `{ name, controller }` description, so the
 * unreadable-Description merge guard in was-client's `configure` never
 * defaults anything from a state this ceremony cannot see.
 *
 * @param options {object}
 * @param options.was {WasClient}   signing as the session currently signs
 *   (this client's did:key on a fresh signup; the promoted did:webvh keyId on
 *   a heal re-run)
 * @param [options.wasAsClient] {WasClient}   signing under this client's
 *   plain did:key, for the torn-promotion heal; omitted, that branch refuses
 *   instead of healing
 * @param options.spaceId {string}
 * @param options.did {string}   the account's did:webvh DID
 * @returns {Promise<SpaceControllerPromotion>}
 */
export async function ensurePromotedSpaceController({
  was,
  wasAsClient,
  spaceId,
  did
}: {
  was: WasClient
  wasAsClient?: WasClient
  spaceId: string
  did: string
}): Promise<SpaceControllerPromotion> {
  const space = was.space(spaceId)
  const description = await space.describe()
  if (description !== null) {
    if (description.controller === did) {
      return 'confirmed'
    }
    // The read a statement above is the current Description, so it rides as
    // `current` and was-client skips its own pre-merge describe.
    await space.configure({
      current: description,
      name: WALLET_SPACE_NAME,
      controller: did
    })
    return 'promoted'
  }
  if (!wasAsClient) {
    throw new Error(
      'The Space Description is unreadable under the current signing ' +
        'identity and no did:key-signed client was supplied to heal a torn ' +
        'controller promotion.'
    )
  }
  // No `current` here: the null above came from a read under `was`, a
  // different signing identity than this heal PUT rides, so it is no answer
  // for what `wasAsClient` can see. was-client reads for itself.
  await wasAsClient
    .space(spaceId)
    .configure({ name: WALLET_SPACE_NAME, controller: did })
  return 'healed'
}

/**
 * The Space-provisioning stage of {@link ensureAccountGenesis} failed: the
 * Space (or part of its collection roster) could not be ensured, so nothing
 * downstream ran. Raised as its own class with a stable `name`, so a caller
 * that treats the later stages as non-fatal can still let a missing Space
 * propagate -- match it on `err.name === 'AccountGenesisSpaceError'`, never
 * `instanceof` (the error can be raised by a linked or duplicated copy of
 * this package).
 */
export class AccountGenesisSpaceError extends Error {
  constructor(options: { spaceId: string; cause: unknown }) {
    super(
      `Provisioning the wallet Space "${options.spaceId}" failed; ` +
        'the account-genesis ceremony did not proceed.',
      { cause: options.cause }
    )
    this.name = 'AccountGenesisSpaceError'
  }
}

/**
 * The stages whose failures the ceremony collects instead of throwing (see
 * the module doc for the split).
 */
export type AccountGenesisStage =
  'didWebKeys' | 'roster' | 'epochs' | 'promotion'

/**
 * What a completed ceremony reports: the account DID, each collected stage's
 * outcome where it ran (the roster descriptor, the per-collection epoch
 * install -- whose own `failed` list stays inside it -- and what the
 * promotion found), and the stages that failed on this run. A result with
 * `failed` entries is a resumable success: the account exists and is
 * identified, and a naive re-run of the whole ceremony finishes the rest.
 */
export interface AccountGenesisResult {
  did: string
  /**
   * The account log's verified head as the did:webvh stage left it -- the
   * served head it adopted, or the one it minted paired with its create PUT's
   * ETag -- for the stage after the ceremony to build on rather than re-read.
   * Set by the credential-anchored ceremony alone; the plain genesis's
   * did:webvh stage hands no head back.
   */
  published?: PublishedWebvhLog
  /**
   * Whether the did:webvh stage MINTED that head (a fresh signup) rather than
   * adopting a served one (a heal re-run). A later stage may reuse a minted
   * head freely -- the account did not exist a moment ago, so no other writer
   * holds it -- but an adopted head is only a snapshot: its document's
   * completion tests are unprotected by any ETag and another client may have
   * moved past them by the time a later stage reads them.
   */
  logMinted?: boolean
  rosterDescriptor?: CollectionEncryption
  epochs?: WalletSpaceEpochsResult
  /**
   * Set when the epochs stage was skipped: the adopted user-key roster's
   * current epoch is not the `userKey` the ceremony was handed, so installing
   * collection epochs under that key would strand them on a key the roster
   * does not deliver. The caller that recovers the roster's real key is the
   * one installer (freewallet's establishment heal branch does this).
   * `rosterEpochId` is the adopted roster's current epoch; it is absent only
   * on a malformed roster naming no epoch at all, which is skipped alike.
   */
  epochsSkipped?: { rosterEpochId?: string }
  promotion?: SpaceControllerPromotion
  failed: Array<{ stage: AccountGenesisStage; error: unknown }>
}

/**
 * Runs the account-genesis ceremony against an already-minted
 * {@link AccountKeySet} (whose update-key seeds the caller has already
 * persisted client-local). Idempotent end to end: every stage adopts what an
 * earlier run landed, so a torn run -- and a lost create race against a
 * concurrent provisioner -- heals by re-running.
 *
 * Stage order (the module doc has the why): Space provisioning, the optional
 * KMS key-map acquisition, did:webvh genesis, user-key roster genesis, the
 * encrypted collections' epoch[0] install, Space-controller promotion.
 *
 * @param options {object}
 * @param options.was {WasClient}   signing as the session currently signs:
 *   this client's did:key on a fresh signup, the promoted did:webvh keyId on
 *   a heal re-run over an already-promoted account
 * @param [options.wasAsClient] {WasClient}   signing under this client's
 *   plain did:key, for the torn-promotion heal (see
 *   {@link ensurePromotedSpaceController})
 * @param options.wasServerUrl {string}   the storage server the account
 *   lives on; the did:webvh id embeds its host
 * @param options.spaceId {string}
 * @param options.keyAgent {ICapabilityAgent}   this founding client's signing
 *   key agent (`agentsFromSeed` over the key set's `clientSeed`); its did:key
 *   id is the Space's controller at creation
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key -- its published `keyAgreement` verification
 *   method, and the roster's first recipient
 * @param options.userKey {UserKey}   the account's user key, recipient zero
 *   of every encrypted collection and the roster's first epoch
 * @param options.updateKeys {ClientWebvhUpdateKeys}   the client-held
 *   did:webvh update-key seeds, already persisted client-local
 * @param options.idStore {WebvhIdStore}   the account's `id` collection
 *   store the did:webvh ceremony reads and publishes through
 * @param options.rosterStoreFor {Function}   `({ did }) =>
 *   EncryptionDescriptorStore` -- builds the user-key roster's descriptor
 *   store once the account DID is known (the log-governed store's controller
 *   view and chain-head pin are the app's wiring)
 * @param [options.provideDidWebKeys] {Function}   `() =>
 *   Promise<DidWebKeyMapV2 | undefined>` -- the KMS key-map acquisition (a
 *   wallet that keeps a KMS runs its did:web provisioning here, after the
 *   Space exists); absent or resolving `undefined`, the genesis is
 *   client-keys-only and no `keys.json` is ever written. A throw is
 *   collected, not fatal: the genesis proceeds client-keys-only and a later
 *   run heals the document with the convenience key
 * @param [options.expectedDid] {string}   the account's did:webvh from the
 *   caller's stored account pointer, when it already names one; the genesis
 *   read then refuses a published log resolving to any other account
 * @param [options.accountLogPinStore] {ResourceLogPinStore}   this client's
 *   chain-head pin for the account log
 * @param [options.onDidPublished] {Function}   `({ did }) => Promise<void>`
 *   -- runs between the DID publication and the roster genesis, so the app
 *   can adopt the DID (and drop any verified-log memo) before the roster
 *   store's controller view resolves against the published document
 * @param [options.promoteController] {boolean}   whether to run the
 *   promotion stage (default `true`). An app whose account pointer must
 *   durably name the DID BEFORE the controller PUT lands -- and whose
 *   pointer write lives outside this call (freewallet's keyring re-bind) --
 *   passes `false` and runs {@link ensurePromotedSpaceController} itself
 *   after that write
 * @returns {Promise<AccountGenesisResult>}
 */
export async function ensureAccountGenesis({
  was,
  wasAsClient,
  wasServerUrl,
  spaceId,
  keyAgent,
  clientKeyAgreementKey,
  userKey,
  updateKeys,
  idStore,
  rosterStoreFor,
  provideDidWebKeys,
  expectedDid,
  accountLogPinStore,
  onDidPublished,
  promoteController = true
}: {
  was: WasClient
  wasAsClient?: WasClient
  wasServerUrl: string
  spaceId: string
  keyAgent: ICapabilityAgent
  clientKeyAgreementKey: IKeyAgreementKey
  userKey: UserKey
  updateKeys: ClientWebvhUpdateKeys
  idStore: WebvhIdStore
  rosterStoreFor: (options: { did: string }) => EncryptionDescriptorStore
  provideDidWebKeys?: () => Promise<DidWebKeyMapV2 | undefined>
  expectedDid?: string
  accountLogPinStore?: ResourceLogPinStore
  onDidPublished?: (published: { did: string }) => Promise<void>
  promoteController?: boolean
}): Promise<AccountGenesisResult> {
  const failed: AccountGenesisResult['failed'] = []

  // 1. The Space and its collection roster, create-if-absent under this
  // founding client's did:key controller (adopted untouched when it exists).
  // Raised as the typed refusal so a caller that treats the later stages as
  // non-fatal can still propagate a Space that never came up.
  try {
    await provisionWalletSpace({ was, spaceId, controllerDid: keyAgent.id })
  } catch (err) {
    throw new AccountGenesisSpaceError({ spaceId, cause: err })
  }

  // 2. The optional KMS key map, acquired only once the Space exists (a
  // KMS-keeping wallet writes keys.json and did.json into it here). A throw
  // degrades to the client-keys-only genesis rather than aborting: every
  // later ceremony anchors in client keys, and the first KMS-capable re-run
  // heals the document with the convenience key.
  let didWebKeys: DidWebKeyMapV2 | undefined
  if (provideDidWebKeys) {
    try {
      didWebKeys = await provideDidWebKeys()
    } catch (err) {
      failed.push({ stage: 'didWebKeys', error: err })
    }
  }

  // 3. The did:webvh genesis -- probe, adopt, or create-and-publish. Fatal on
  // failure: the account DID is what every remaining stage anchors in.
  const { publicKeyMultibase: keyAgreementKeyMultibase } =
    clientKeyAgreementKey as unknown as { publicKeyMultibase?: string }
  if (!keyAgreementKeyMultibase) {
    throw new Error('The client key-agreement key has no public multibase.')
  }
  const { did } = await ensureDidWebvh({
    idStore,
    wasServerUrl,
    spaceId,
    ...(didWebKeys ? { didWebKeys } : {}),
    clientKeys: {
      signingKeyMultibase: clientSigningKeyMultibase({ keyAgent }),
      keyAgreementKeyMultibase
    },
    updateKeys,
    ...(expectedDid !== undefined ? { expectedDid } : {}),
    ...(accountLogPinStore ? { pinStore: accountLogPinStore } : {})
  })
  await onDidPublished?.({ did })

  // 4. The user-key roster genesis, strictly after the DID publication: the
  // roster log's entry proofs anchor in the published document, so a roster
  // created first could never verify.
  let rosterDescriptor: CollectionEncryption | undefined
  try {
    rosterDescriptor = await ensureUserKeyRoster({
      store: rosterStoreFor({ did }),
      userKey,
      clientKeyAgreementKey
    })
  } catch (err) {
    failed.push({ stage: 'roster', error: err })
  }

  // 5. Epoch[0] on every encrypted roster collection, wrapped to the user
  // key. Its own per-collection failures stay inside the result (`epochs
  // .failed`); only a fan-out that could not run at all lands here.
  let epochs: WalletSpaceEpochsResult | undefined
  try {
    epochs = await ensureWalletSpaceEpochs({ was, spaceId, userKey })
  } catch (err) {
    failed.push({ stage: 'epochs', error: err })
  }

  // 6. The controller promotion, last: every earlier stage ran under the
  // signing identity the Space's stored controller authorizes. Skipped when
  // the caller's account-pointer write must land first (see the JSDoc).
  let promotion: SpaceControllerPromotion | undefined
  if (promoteController) {
    try {
      promotion = await ensurePromotedSpaceController({
        was,
        ...(wasAsClient ? { wasAsClient } : {}),
        spaceId,
        did
      })
    } catch (err) {
      failed.push({ stage: 'promotion', error: err })
    }
  }

  return {
    did,
    ...(rosterDescriptor ? { rosterDescriptor } : {}),
    ...(epochs ? { epochs } : {}),
    ...(promotion ? { promotion } : {}),
    failed
  }
}
