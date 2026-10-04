/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The convergence property every mender registration claims, against the
 * real server. Each block's first run mends a torn account and reports at
 * least one `clean` entry. The same block run again against the same account
 * then reports `noop` for every entry and issues no request other than a GET
 * or a HEAD.
 *
 * Wallet-core carries no registration table of its own, so this suite builds
 * one over the menders wallet-core ships, with each invariant's authority
 * taken from the wallets' declarations. Two blocks run, since the
 * held-authority filter splits the table, each over its own account so the
 * two tears stay apart:
 *
 * - The remembered block, held `enrolled`, acting as the enrolled client of
 *   an enrolled-client account: the Space-controller promotion and the
 *   login-time roster sweep with its collection fan-out. The tear is a
 *   recovery code issued and then revoked with no roster tail, so the roster
 *   still wraps the user key to a key the document no longer lists. The
 *   first run rotates the roster off it and re-epochs every collection.
 * - The transient block, held `ladder`, acting as transient visits on the
 *   credential of a passphrase account: the transient readiness ensure, the
 *   credential-anchored mend, and the collection fan-out under the
 *   generation delegation. A wallet runs the first two at a routing call
 *   site rather than on a chain. This table lists them under the transient
 *   chain so one block runs them. The tear is the pointed annex Space,
 *   deleted through a DELETE-only capability. The first run's ensure mints a
 *   fresh Space and generation, the in-memory record takes the re-sealed
 *   delegations, and the visit the later registrations act through is
 *   enrolled into the fresh generation. The promotion runs only in the
 *   remembered block, since it reads the Space Description with a root
 *   invocation, which a transient visit's annex VM cannot make.
 *
 * The directory writer sweep is left out: it is an encounter site over
 * `connections` entries, and no account shape writes one.
 */
import { WasClient } from '@interop/was-client'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import {
  clientAnnexDidParts,
  deleteSpaceWithCapability,
  ensureCredentialClientAnnexGeneration,
  ladderVmAgent,
  ladderVmZcapClient,
  mendCredentialAnchoredAccount,
  mintSpaceRootVerbCapability
} from '../../src/clientAnnex/index.js'
import {
  checkUserKeyRosterAtLogin,
  convergeUserKeyRosterToAccount
} from '../../src/clients/index.js'
import { ensurePromotedSpaceController } from '../../src/genesis/index.js'
import {
  accountCollectionStores,
  cascadeCollectionsToUserKey,
  readUserKeyRoster,
  userKeyRosterDescriptorStore,
  userKeyRosterLogSigner
} from '../../src/keys/index.js'
import type { UserKey, UserKeyCascadeResult } from '../../src/keys/index.js'
import type { Logger } from '../../src/log.js'
import { setLogger } from '../../src/log.js'
import {
  errorNameOf,
  heldAuthorities,
  menderRegistry,
  runMenderBlock
} from '../../src/menders/index.js'
import type {
  ChainTrigger,
  InvariantDeclaration,
  InvariantId,
  MendOutcomeKind,
  MendReport,
  MendReportEntry,
  Registration,
  ResolvedAuthority
} from '../../src/menders/index.js'
import { removeRecoveryKey } from '../../src/recovery/index.js'
import { webvhResourceLogController } from '../../src/resourceLog/index.js'
import { encryptedWalletCollectionIds } from '../../src/space/collections.js'
import type { CeremonyId } from '../../src/space/index.js'
import { ID_COLLECTION } from '../../src/space/index.js'
import {
  buildEnrolledClientAccount,
  buildPassphraseAccount,
  issueRecoveryCode
} from '../../src/testing/index.js'
import type { EstablishedAccount } from '../../src/testing/index.js'
import {
  delegatedWebvhLogStore,
  didKeyZcapClient,
  verifyAccountLog,
  wasWebvhIdStore
} from '../../src/webvh/index.js'
import type { WebvhIdStore } from '../../src/webvh/index.js'
import {
  bootServer,
  bridgeLogStore,
  transientVisit
} from './fixtures/credentialAnchoredAccount.js'

type Account = Awaited<ReturnType<typeof buildEnrolledClientAccount>>
type Visit = Awaited<ReturnType<typeof transientVisit>>

/**
 * A transient session on the credential. `account` carries what the unlock
 * record holds (the bridge and sibling delegations) and the annex Space the
 * document points at, so a re-seal or a fresh annex replaces it. `visit` is
 * the transient visit the session acts through, enrolled into the pointed
 * generation on first use.
 */
interface TransientSession {
  account: EstablishedAccount
  pinStore: ReturnType<typeof memoryResourceLogPinStore>
  visit?: Visit
}

/**
 * Both sessions a block's registrations act through. One object serves both
 * blocks, and each registration reads the half its authority names. The
 * mutable members are what a wallet persists between logins: the adopted
 * user key and roster epoch pin, and the unlock record's delegations.
 */
interface Deps {
  remembered: {
    account: Account
    pinStore: ReturnType<typeof memoryResourceLogPinStore>
    userKey: UserKey
    pinnedEpochId?: string
  }
  transient: TransientSession
}

/**
 * The session's transient visit, enrolled into the pointed generation the
 * first time a registration needs it and reused after that.
 *
 * @param session {TransientSession}
 * @returns {Promise<Visit>}
 */
async function currentVisit(session: TransientSession): Promise<Visit> {
  session.visit ??= await transientVisit({ account: session.account })
  return session.visit
}

/**
 * The outcome of a stage that reports whether it wrote.
 *
 * @param wrote {boolean}
 * @returns {MendOutcomeKind}
 */
function wroteOutcome(wrote: boolean): MendOutcomeKind {
  return wrote ? 'clean' : 'noop'
}

/**
 * The entries for the two invariants a collection fan-out reports: 2 from a
 * governing log the fan-out had to seal, 3 from an epoch it had to rotate
 * or escrow. A failed collection fails both.
 *
 * @param fanOut {UserKeyCascadeResult}
 * @returns {Array<MendReportEntry<CeremonyId>>}
 */
function fanOutEntries(
  fanOut: UserKeyCascadeResult
): Array<MendReportEntry<CeremonyId>> {
  const outcomes = Object.values(fanOut.outcomes)
  if (fanOut.failed.length > 0) {
    const errorName = errorNameOf(fanOut.failed[0]!.error)
    return [
      {
        invariant: 'governed-log-heads-anchor-past-the-membership-change',
        outcome: 'failed',
        errorName
      },
      {
        invariant: 'collection-epochs-name-the-current-user-key',
        outcome: 'failed',
        errorName
      }
    ]
  }
  return [
    {
      invariant: 'governed-log-heads-anchor-past-the-membership-change',
      outcome: wroteOutcome(outcomes.includes('sealed'))
    },
    {
      invariant: 'collection-epochs-name-the-current-user-key',
      outcome: wroteOutcome(
        outcomes.includes('rotated') || outcomes.includes('escrowed')
      )
    }
  ]
}

/**
 * One mend report member's entry: absent means its arm did not fire, a
 * converged member means it wrote, and an unconverged one failed.
 *
 * @param options {object}
 * @param options.invariant {InvariantId}
 * @param [options.member] {object}   the arm's report member
 * @returns {MendReportEntry<CeremonyId>}
 */
function mendArmEntry({
  invariant,
  member
}: {
  invariant: InvariantId
  member?: { converged: boolean; error?: unknown }
}): MendReportEntry<CeremonyId> {
  if (member === undefined) {
    return { invariant, outcome: 'noop' }
  }
  if (member.converged) {
    return { invariant, outcome: 'clean' }
  }
  return {
    invariant,
    outcome: 'failed',
    ...(member.error !== undefined
      ? { errorName: errorNameOf(member.error) }
      : {})
  }
}

/**
 * The enrolled client's user key roster store: root invocations as the
 * client, appends signed by its own key, the controller view resolved per
 * operation.
 *
 * @param options {object}
 * @param options.account {Account}
 * @param options.pinStore {ResourceLogPinStore}
 * @returns {EncryptionDescriptorStore}
 */
function enrolledRosterStore({
  account,
  pinStore
}: {
  account: Account
  pinStore: ReturnType<typeof memoryResourceLogPinStore>
}) {
  const { serverUrl, spaceId, accountDid, client } = account
  return userKeyRosterDescriptorStore({
    storageServerUrl: serverUrl,
    zcapClient: client.zcapClient,
    spaceId,
    resolveController: async () =>
      webvhResourceLogController({
        did: accountDid,
        log: (
          await verifyAccountLog({
            did: accountDid,
            spaceId,
            host: serverUrl,
            pinStore
          })
        ).log
      }),
    pinStore,
    signer: userKeyRosterLogSigner({ keyAgent: client.agents.keyAgent })
  })
}

/**
 * The transient visit's user key roster store: invoked by the visit's annex
 * VM under the generation delegation, appends signed by the ladder VM.
 *
 * @param options {object}
 * @param options.account {EstablishedAccount}
 * @param options.visit {Visit}
 * @returns {Promise<EncryptionDescriptorStore>}
 */
async function transientRosterStore({
  account,
  visit
}: {
  account: EstablishedAccount
  visit: Visit
}) {
  const { serverUrl, spaceId, accountDid, ladderSeed } = account
  return userKeyRosterDescriptorStore({
    storageServerUrl: serverUrl,
    zcapClient: visit.zcapClient,
    spaceId,
    resolveController: async () =>
      webvhResourceLogController({
        did: accountDid,
        log: (
          await verifyAccountLog({
            did: accountDid,
            spaceId,
            host: serverUrl,
            pinStore: visit.pinStore
          })
        ).log
      }),
    pinStore: visit.pinStore,
    signer: userKeyRosterLogSigner({
      keyAgent: await ladderVmAgent({ ladderSeed })
    }),
    capability: visit.generationDelegation
  })
}

const COLLECTION_IDS = encryptedWalletCollectionIds()

/**
 * The declarations, authorities as the wallets declare them. Triggers name
 * the chains this suite runs each invariant on.
 */
const DECLARATIONS: ReadonlyArray<InvariantDeclaration<Deps, CeremonyId>> = [
  {
    id: 'roster-wraps-exactly-the-document-key-set',
    statement:
      "The user key roster's current epoch wraps the user key to exactly the key-agreement keys the account document lists.",
    standsOn: ['ladder-anchored', 'enrolled'],
    authority: 'enrolled',
    triggers: ['remembered-login-chain'],
    ceremonies: ['client-revocation', 'self-enrollment'],
    evidence: ['verified-log'],
    warn: 'Could not converge the roster onto the account document'
  },
  {
    id: 'governed-log-heads-anchor-past-the-membership-change',
    statement:
      "Each encrypted collection's governing log has a verified head anchored past the controller's latest assertion-key removal.",
    standsOn: ['ladder-anchored', 'enrolled'],
    authority: 'account',
    triggers: ['remembered-login-chain', 'transient-login-chain'],
    ceremonies: ['client-revocation', 'forget-client'],
    evidence: ['verified-log'],
    warn: 'Could not seal the collection governing logs'
  },
  {
    id: 'collection-epochs-name-the-current-user-key',
    statement:
      "Every encrypted collection's current key epoch names the current user key generation.",
    standsOn: ['ladder-anchored', 'enrolled'],
    authority: 'account',
    triggers: ['remembered-login-chain', 'transient-login-chain'],
    ceremonies: ['client-revocation', 'unlock-credential-rotation'],
    evidence: ['verified-log', 'host-listing'],
    warn: 'Could not cascade the collections onto the current user key'
  },
  {
    id: 'unlock-record-points-at-the-account-did',
    statement:
      "The acting credential's unlock record points at the account's did:webvh.",
    standsOn: ['ladder-anchored', 'enrolled'],
    authority: 'ladder',
    triggers: ['transient-login-chain'],
    ceremonies: ['credential-anchored-genesis'],
    evidence: ['served-unlock-record'],
    warn: 'Could not mend the credential-anchored establishment'
  },
  {
    id: 'space-controller-is-the-account-did',
    statement: "The data Space's controller is the account's did:webvh.",
    standsOn: ['ladder-anchored', 'enrolled'],
    authority: 'account',
    triggers: ['remembered-login-chain', 'transient-login-chain'],
    ceremonies: ['account-genesis', 'credential-anchored-genesis'],
    evidence: ['host-listing'],
    warn: 'Could not promote the Space controller'
  },
  {
    id: 'roster-and-collection-epochs-exist',
    statement:
      'The account has a user key roster the acting credential can open, and every encrypted collection carries an epoch under it.',
    standsOn: ['ladder-anchored'],
    authority: 'ladder',
    triggers: ['transient-login-chain'],
    ceremonies: ['credential-anchored-genesis'],
    evidence: ['verified-log'],
    warn: 'Could not mend the roster and collection epochs'
  },
  {
    id: 'registry-records-the-establishing-credential',
    statement:
      'A credential whose establishment landed has its registry entry, with its delegations recorded.',
    standsOn: ['ladder-anchored'],
    authority: 'ladder',
    triggers: ['transient-login-chain'],
    ceremonies: ['credential-anchored-genesis'],
    evidence: ['verified-registry'],
    warn: 'Could not mend the registry entry'
  },
  {
    id: 'annex-generation-is-reachable',
    statement:
      'The account document points at a published annex generation in a live auxiliary Space, and the sibling delegation aims at that Space.',
    standsOn: ['ladder-anchored', 'enrolled'],
    authority: 'ladder',
    triggers: ['transient-login-chain'],
    ceremonies: ['credential-anchored-genesis'],
    evidence: ['verified-log', 'host-listing'],
    warn: 'Could not ensure the annex generation'
  },
  {
    id: 'generation-delegation-is-current',
    statement:
      "The pointed generation's embedded delegation is unexpired and signed by a key the verified account document still lists.",
    standsOn: ['ladder-anchored', 'enrolled'],
    authority: 'account',
    triggers: ['transient-login-chain'],
    ceremonies: ['client-revocation', 'unlock-credential-rotation'],
    evidence: ['verified-log', 'local-clock'],
    warn: 'Could not renew the generation delegation'
  },
  {
    id: 'roster-log-head-anchors-past-the-membership-change',
    statement:
      "The user key roster log's verified head is anchored past the controller's latest assertion-key removal.",
    standsOn: ['ladder-anchored', 'enrolled'],
    authority: 'enrolled',
    triggers: ['remembered-login-chain'],
    ceremonies: ['client-revocation', 'forget-client'],
    evidence: ['verified-log'],
    warn: 'Could not seal the roster log'
  }
]

/**
 * The Space-controller promotion, as the enrolled client.
 */
const PROMOTION: Registration<Deps, CeremonyId> = {
  trigger: 'remembered-login-chain',
  reports: ['space-controller-is-the-account-did'],
  async converge({ remembered: { account } }) {
    const promotion = await ensurePromotedSpaceController({
      was: new WasClient({
        serverUrl: account.serverUrl,
        zcapClient: account.client.zcapClient
      }),
      spaceId: account.spaceId,
      did: account.accountDid
    })
    return [
      {
        invariant: 'space-controller-is-the-account-did',
        outcome: wroteOutcome(promotion !== 'confirmed')
      }
    ]
  }
}

/**
 * The login-time roster sweep, as the enrolled client: the roster read, the
 * convergence onto the document with its seal backstop, then the collection
 * fan-out.
 */
const ROSTER_SWEEP: Registration<Deps, CeremonyId> = {
  trigger: 'remembered-login-chain',
  reports: [
    'roster-wraps-exactly-the-document-key-set',
    'roster-log-head-anchors-past-the-membership-change',
    'governed-log-heads-anchor-past-the-membership-change',
    'collection-epochs-name-the-current-user-key'
  ],
  async converge({ remembered }) {
    const { account, pinStore: rememberedPins } = remembered
    const { serverUrl, spaceId, accountDid, client } = account
    const store = enrolledRosterStore({ account, pinStore: rememberedPins })
    const clientKeyAgreementKey = client.agents
      .keyAgreementKey as IKeyAgreementKey
    const adopt = async (adopted: {
      userKey: UserKey
      latestEpochId: string
    }) => {
      remembered.userKey = adopted.userKey
      remembered.pinnedEpochId = adopted.latestEpochId
    }
    const read = await checkUserKeyRosterAtLogin({
      store,
      userKey: remembered.userKey,
      clientKeyAgreementKey,
      pinnedEpochId: remembered.pinnedEpochId ?? null,
      onRosterRead: adopt
    })
    if (read === null) {
      throw new Error('test: the roster read resolved nothing')
    }
    const converged = await convergeUserKeyRosterToAccount({
      pointer: { did: accountDid, spaceId, host: serverUrl },
      store,
      userKey: read.userKey,
      descriptor: read.descriptor,
      ...(read.etag !== undefined ? { etag: read.etag } : {}),
      clientKeyAgreementKey,
      pinnedEpochId: remembered.pinnedEpochId ?? null,
      accountLogPinStore: rememberedPins,
      onUserKeyAdopted: adopt
    })
    const fanOut = await cascadeCollectionsToUserKey({
      collectionIds: COLLECTION_IDS,
      storeFor: accountCollectionStores({
        storageServerUrl: serverUrl,
        zcapClient: client.zcapClient,
        spaceId,
        did: accountDid,
        pinStore: rememberedPins,
        signer: userKeyRosterLogSigner({ keyAgent: client.agents.keyAgent })
      }),
      rosterDescriptor: converged.descriptor,
      clientKeyAgreementKey,
      userKey: converged.userKey
    })
    return [
      {
        invariant: 'roster-wraps-exactly-the-document-key-set',
        outcome: wroteOutcome(
          converged.rotated || converged.escrowedRecipientIds.length > 0
        )
      },
      {
        invariant: 'roster-log-head-anchors-past-the-membership-change',
        outcome: wroteOutcome(converged.sealed)
      },
      ...fanOutEntries(fanOut)
    ]
  }
}

/**
 * The transient readiness ensure, as the credential: the bridge and sibling
 * delegations re-seal into the in-memory record when either is re-minted,
 * and a generation the visit was not enrolled into retires the visit, so
 * the next registration enrolls a fresh one there.
 */
const READINESS: Registration<Deps, CeremonyId> = {
  trigger: 'transient-login-chain',
  reports: [
    'annex-generation-is-reachable',
    'generation-delegation-is-current'
  ],
  async converge({ transient }) {
    const { serverUrl, spaceId, accountDid, ladderSeed, standing } =
      transient.account
    const verified = await verifyAccountLog({
      did: accountDid,
      spaceId,
      host: serverUrl,
      pinStore: transient.pinStore
    })
    const ensured = await ensureCredentialClientAnnexGeneration({
      wasServerUrl: serverUrl,
      spaceId,
      account: { did: accountDid, doc: verified.doc, log: verified.log },
      ladderSeed,
      standingClient: {
        did: standing.clientDid,
        zcapClient: standing.agents.zcapClient
      },
      bootstrapWasFor: ({ keyAgent }) =>
        new WasClient({
          serverUrl,
          zcapClient: didKeyZcapClient({ keyAgent })
        }),
      delegation: transient.account.bridge,
      idStoreFor: ({ delegation }) =>
        delegatedWebvhLogStore({
          host: serverUrl,
          spaceId,
          collectionId: ID_COLLECTION.id,
          delegation,
          zcapClient: standing.agents.zcapClient,
          pinStore: transient.pinStore
        }) as WebvhIdStore,
      onRebindRecord: async ({ delegation, delegatedClients }) => {
        transient.account = {
          ...transient.account,
          bridge: delegation,
          sibling: delegatedClients
        }
      },
      delegatedClients: transient.account.sibling
    })
    transient.account = {
      ...transient.account,
      annexSpaceId: clientAnnexDidParts({ did: ensured.clientAnnexDid }).spaceId
    }
    if (transient.visit?.clientAnnexDid !== ensured.clientAnnexDid) {
      transient.visit = undefined
    }
    return [
      {
        invariant: 'annex-generation-is-reachable',
        outcome: wroteOutcome(
          ensured.generationMinted ||
            ensured.spaceMinted ||
            ensured.pointedSpaceMissing ||
            ensured.siblingReminted ||
            ensured.bridgeReminted
        )
      },
      {
        invariant: 'generation-delegation-is-current',
        outcome: wroteOutcome(ensured.delegationRenewed)
      }
    ]
  }
}

/**
 * The credential-anchored mend, as the transient visit. The establishment
 * hooks are the builder's bootstrap wiring; a healthy promoted account never
 * reaches them. No registry hook is given, since no shape writes a registry
 * record, so the registry arm cannot fire.
 */
const MEND: Registration<Deps, CeremonyId> = {
  trigger: 'transient-login-chain',
  reports: [
    'unlock-record-points-at-the-account-did',
    'space-controller-is-the-account-did',
    'roster-and-collection-epochs-exist',
    'registry-records-the-establishing-credential'
  ],
  async converge({ transient }) {
    const { account } = transient
    const { serverUrl, spaceId, accountDid, ladderSeed, standing } = account
    const visit = await currentVisit(transient)
    const bootstrapAgent = await ladderVmAgent({ ladderSeed })
    const bootstrapZcap = didKeyZcapClient({ keyAgent: bootstrapAgent })
    const bootstrapWas = new WasClient({ serverUrl, zcapClient: bootstrapZcap })
    // The ladder VM's key signs both the bootstrap and the visit's appends.
    const ladderSigner = userKeyRosterLogSigner({ keyAgent: bootstrapAgent })
    const report = await mendCredentialAnchoredAccount({
      account: {
        controller: accountDid,
        pointer: { did: accountDid, spaceId, host: serverUrl },
        ladderSeed
      },
      standing: {
        clientDid: standing.clientDid,
        keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase,
        recipientKid: standing.recipientKid,
        keyAgreementKey: standing.agents.keyAgreementKey as IKeyAgreementKey
      },
      bindRecord: async () => {
        throw new Error('test: the mend tried to re-bind the record')
      },
      rosterStoreFor: ({ did, log }) =>
        userKeyRosterDescriptorStore({
          storageServerUrl: serverUrl,
          zcapClient: bootstrapZcap,
          spaceId,
          resolveController: async () =>
            webvhResourceLogController({ did, log }),
          pinStore: visit.pinStore,
          signer: ladderSigner
        }),
      collectionStoreFor: ({ did, log }) =>
        accountCollectionStores({
          storageServerUrl: serverUrl,
          zcapClient: bootstrapZcap,
          spaceId,
          did,
          pinStore: visit.pinStore,
          signer: ladderSigner,
          log
        }),
      bootstrapWasFor: () => bootstrapWas,
      idStore: wasWebvhIdStore({
        was: bootstrapWas,
        spaceId,
        pinStore: visit.pinStore
      }),
      lowEntropy: true,
      delegatedClients: account.sibling,
      invocation: {
        was: new WasClient({ serverUrl, zcapClient: visit.zcapClient }),
        zcapClient: visit.zcapClient,
        capability: visit.generationDelegation
      },
      rosterStore: await transientRosterStore({ account, visit }),
      collectionStore: accountCollectionStores({
        storageServerUrl: serverUrl,
        zcapClient: visit.zcapClient,
        spaceId,
        did: accountDid,
        pinStore: visit.pinStore,
        signer: ladderSigner,
        capability: visit.generationDelegation
      }),
      hasRosterEpochPin: async () => false
    })
    return [
      mendArmEntry({
        invariant: 'unlock-record-points-at-the-account-did',
        member: report.establishment
      }),
      mendArmEntry({
        invariant: 'space-controller-is-the-account-did',
        member: report.promotion
      }),
      mendArmEntry({
        invariant: 'roster-and-collection-epochs-exist',
        member: report.rosterEpochs
      }),
      mendArmEntry({
        invariant: 'registry-records-the-establishing-credential',
        member: report.registry
      })
    ]
  }
}

/**
 * The collection fan-out, as the transient visit: the roster read with the
 * credential's own key-agreement key, then every encrypted collection
 * brought onto that key under the generation delegation.
 */
const TRANSIENT_FAN_OUT: Registration<Deps, CeremonyId> = {
  trigger: 'transient-login-chain',
  reports: [
    'governed-log-heads-anchor-past-the-membership-change',
    'collection-epochs-name-the-current-user-key'
  ],
  async converge({ transient }) {
    const { account } = transient
    const { serverUrl, spaceId, accountDid, ladderSeed, standing } = account
    const visit = await currentVisit(transient)
    const clientKeyAgreementKey = standing.agents
      .keyAgreementKey as IKeyAgreementKey
    const read = await readUserKeyRoster({
      store: await transientRosterStore({ account, visit }),
      clientKeyAgreementKey
    })
    if (read === null) {
      throw new Error('test: the roster read resolved nothing')
    }
    const fanOut = await cascadeCollectionsToUserKey({
      collectionIds: COLLECTION_IDS,
      storeFor: accountCollectionStores({
        storageServerUrl: serverUrl,
        zcapClient: visit.zcapClient,
        spaceId,
        did: accountDid,
        pinStore: visit.pinStore,
        signer: userKeyRosterLogSigner({
          keyAgent: await ladderVmAgent({ ladderSeed })
        }),
        capability: visit.generationDelegation
      }),
      rosterDescriptor: read.descriptor,
      clientKeyAgreementKey,
      userKey: read.userKey
    })
    return fanOutEntries(fanOut)
  }
}

const REGISTRY = menderRegistry<
  Registration<Deps, CeremonyId>,
  Deps,
  CeremonyId
>({
  declarations: DECLARATIONS,
  sites: [PROMOTION, ROSTER_SWEEP, READINESS, MEND, TRANSIENT_FAN_OUT]
})

/**
 * A logger that drops everything and keeps the warn and error calls, so a
 * test can assert none fired.
 *
 * @returns {{ logger: Logger, loud: Array<{ level: string, msg: string }> }}
 */
function quietLogger() {
  const loud: Array<{ level: string; msg: string }> = []
  const ignore = () => undefined
  const logger: Logger = {
    debug: ignore,
    info: ignore,
    warn: msg => {
      loud.push({ level: 'warn', msg })
    },
    error: msg => {
      loud.push({ level: 'error', msg })
    }
  }
  return { logger, loud }
}

describe('a mender block run over a torn account, then re-run', () => {
  let server: Awaited<ReturnType<typeof bootServer>>
  let deps: Deps
  const quiet = quietLogger()
  let restoreLogger: (() => void) | undefined

  beforeAll(async () => {
    server = await bootServer()
    // The package-wide logger too: the roster sweep warns through it rather
    // than through the block's logger.
    const previous = setLogger(quiet.logger)
    restoreLogger = () => setLogger(previous)
    const rememberedAccount = await buildEnrolledClientAccount({
      serverUrl: server.serverUrl
    })
    const transientAccount = await buildPassphraseAccount({
      serverUrl: server.serverUrl
    })
    deps = {
      remembered: {
        account: rememberedAccount,
        pinStore: memoryResourceLogPinStore(),
        userKey: rememberedAccount.client.userKey
      },
      transient: {
        account: transientAccount,
        pinStore: memoryResourceLogPinStore()
      }
    }
  })

  beforeEach(() => {
    server.faults.reset()
    quiet.loud.length = 0
  })

  afterAll(async () => {
    restoreLogger?.()
    await server.close()
  })

  /**
   * Runs one block over the shared table.
   *
   * @param options {object}
   * @param options.trigger {ChainTrigger}
   * @param options.kind {ResolvedAuthority}
   * @returns {Promise<MendReport<CeremonyId>>}
   */
  async function runBlock({
    trigger,
    kind
  }: {
    trigger: ChainTrigger
    kind: ResolvedAuthority
  }): Promise<MendReport<CeremonyId>> {
    return runMenderBlock<Deps, CeremonyId>({
      registry: REGISTRY,
      trigger,
      held: heldAuthorities({ kind }),
      route: { popup: false },
      deps,
      logger: quiet.logger
    })
  }

  /**
   * Runs a block twice. The first run must mend: it reports every declared
   * invariant, nothing failed, and `clean` for each of `mends`. The second
   * run must be a pure read: every entry `noop`, every declared invariant
   * reported, no warn or error, and nothing but GET and HEAD requests on the
   * server.
   *
   * @param options {object}
   * @param options.trigger {ChainTrigger}
   * @param options.kind {ResolvedAuthority}
   * @param options.mends {InvariantId[]}   the invariants the first run
   *   must report `clean`
   * @returns {Promise<void>}
   */
  async function expectMendThenQuiet({
    trigger,
    kind,
    mends
  }: {
    trigger: ChainTrigger
    kind: ResolvedAuthority
    mends: InvariantId[]
  }): Promise<void> {
    const declared = new Set(
      REGISTRY.dueAt({
        held: heldAuthorities({ kind }),
        trigger,
        route: { popup: false }
      }).flatMap(site => site.reports)
    )

    const first = await runBlock({ trigger, kind })
    expect(new Set(first.map(entry => entry.invariant))).toEqual(declared)
    const failed = first.filter(
      entry => entry.outcome !== 'noop' && entry.outcome !== 'clean'
    )
    expect(failed, JSON.stringify(failed)).toEqual([])
    const cleaned = first
      .filter(entry => entry.outcome === 'clean')
      .map(entry => entry.invariant)
    expect(cleaned, JSON.stringify(first)).toEqual(
      expect.arrayContaining(mends)
    )

    server.faults.reset()
    quiet.loud.length = 0
    const second = await runBlock({ trigger, kind })

    expect(new Set(second.map(entry => entry.invariant))).toEqual(declared)
    const unconverged = second.filter(entry => entry.outcome !== 'noop')
    expect(unconverged, JSON.stringify(unconverged)).toEqual([])
    expect(quiet.loud, JSON.stringify(quiet.loud)).toEqual([])
    const writes = server.faults.requests
      .filter(record => record.method !== 'GET' && record.method !== 'HEAD')
      .map(({ method, path, status }) => ({ method, path, status }))
    expect(writes, JSON.stringify(writes)).toEqual([])
  }

  it('the remembered block rotates the roster off a revoked code, then writes nothing', async () => {
    const { account } = deps.remembered
    // The tear: a recovery code issued, then its inventory struck by the
    // credential with no roster tail, so the roster still wraps the user key
    // to the code's key.
    const issued = await issueRecoveryCode({ account })
    await removeRecoveryKey({
      idStore: bridgeLogStore({
        account,
        pinStore: memoryResourceLogPinStore()
      }) as WebvhIdStore,
      signer: { kind: 'ladder', ladderSeed: account.ladderSeed },
      recovery: {
        keyAgreementKeyMultibase: issued.client.keyAgreementKeyMultibase,
        updateKeyMultibase: issued.client.updateKeyMultibase
      },
      expectedDid: account.accountDid
    })

    await expectMendThenQuiet({
      trigger: 'remembered-login-chain',
      kind: 'enrolled',
      mends: [
        'roster-wraps-exactly-the-document-key-set',
        'collection-epochs-name-the-current-user-key'
      ]
    })
  })

  it('the transient block re-mints a deleted annex Space, then writes nothing', async () => {
    const { serverUrl, accountDid, annexSpaceId, ladderSeed, standing } =
      deps.transient.account
    // The tear: the pointed annex Space, deleted by the standing client
    // through a DELETE-only child of its root the ladder VM delegates.
    const capability = await mintSpaceRootVerbCapability({
      zcapClient: await ladderVmZcapClient({ accountDid, ladderSeed }),
      storageServerUrl: serverUrl,
      spaceId: annexSpaceId,
      verb: 'DELETE',
      controller: standing.clientDid
    })
    expect(
      await deleteSpaceWithCapability({
        storageServerUrl: serverUrl,
        zcapClient: standing.agents.zcapClient,
        spaceId: annexSpaceId,
        capability
      })
    ).toEqual({ outcome: 'deleted' })

    await expectMendThenQuiet({
      trigger: 'transient-login-chain',
      kind: 'ladder',
      mends: ['annex-generation-is-reachable']
    })
    expect(deps.transient.account.annexSpaceId).not.toBe(annexSpaceId)
  })
})
