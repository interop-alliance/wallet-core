/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * TEST FIXTURES ONLY. The shared account builder: the named account shapes a
 * test starts from, each made through this package's own ceremonies against
 * a real WAS server, with no fake store anywhere. Both wallets use it from
 * their test globs only, and this package's integration tier uses it too.
 *
 * Never import this subpath from production code. Each consumer keeps a lint
 * restriction excluding `@interop/wallet-core/testing` from its non-test
 * globs.
 *
 * The builder imports no server package. The caller boots the server (the
 * integration tier boots `was-teaching-server` in process) and hands over
 * its URL; every client built here targets that URL.
 *
 * Every shape starts as a credential-anchored signup
 * (`establishCredentialAnchoredAccount`) and adds one thing in the order a
 * wallet's ladder-kind session runs it, acting as the signup credential:
 *
 * - `buildPassphraseAccount`: nothing more.
 * - `buildSecondCredentialAccount`: a second standing credential
 *   (`addStandingCredential`), the standing establishment's ladder branch.
 * - `buildRecoveryCodeAccount`: one issued, unspent recovery code
 *   (`issueRecoveryCode`), the issuance's ladder branch.
 * - `buildEnrolledClientAccount`: one enrolled client (`enrollClient`), the
 *   credential's self-enrollment.
 *
 * A passphrase derives through `FAST_KDF`, an HKDF stand-in for the shipped
 * Argon2id set, so a passphrase shape derives in microseconds. A passphrase
 * credential is low-entropy, so its `keyAgreement` key publishes as a hash
 * commitment.
 *
 * The unlock records every shape binds are held in memory and never written:
 * their codec and their storage are the wallet's. What a shape returns in
 * their place is what the bind carried, the bridge and sibling delegations
 * and the ladder seed, so a test can act as the credential afterwards.
 *
 * No shape performs the other app-side writes either. No shape writes an
 * unlock-methods registry record. No shape writes a `connections` directory
 * entry for the enrolled client. Each ladder-context add
 * (`addStandingCredential`, `issueRecoveryCode`) enrolls one transient VM
 * into the pointed generation, and `buildPassphraseAccount` enrolls none. So
 * a shape's annex VM count differs from a real signup's.
 *
 * Each builder run keeps its own in-memory chain-head pins, as a fresh tab
 * would.
 */
import { WasClient } from '@interop/was-client'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { agentsFromSeed } from '@interop/was-client/identity'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'

import {
  clientAnnexDidParts,
  clientAnnexLogStore,
  commitClientAnnexRung,
  delegatedClientsPointer,
  embeddedGenerationDelegation,
  enrollTransientClient,
  establishCredentialAnchoredAccount,
  ladderVmAgent,
  ladderVmZcapClient,
  mintDelegatedClientsDelegation,
  selfEnrollClientCore
} from '../clientAnnex/index.js'
import { mintSpaceId } from '../genesis/index.js'
import { deriveUnlockSeed, unlockIdentityFromSeed } from '../keyring/index.js'
import {
  accountCollectionStores,
  addUserKeyRosterRecipient,
  userKeyRosterDescriptorStore,
  userKeyRosterLogSigner
} from '../keys/index.js'
import {
  delegateLogWrite,
  generateRecoveryCode,
  publishRecoveryKey,
  recoveryClientFromCode
} from '../recovery/index.js'
import { webvhResourceLogController } from '../resourceLog/index.js'
import { ID_COLLECTION } from '../space/index.js'
import {
  generateLadderSeed,
  publishUnlockKey,
  standingClientFromUnlockSeed
} from '../unlock/index.js'
import {
  clientSigningKeyMultibase,
  delegatedWebvhLogStore,
  didKeyZcapClient,
  keyAgreementCommitment,
  ladderRung,
  verifyAccountLog,
  wasWebvhIdStore,
  webvhZcapClient
} from '../webvh/index.js'
import type { WebvhIdStore } from '../webvh/index.js'
import { FAST_KDF } from './fastKdf.js'

/**
 * A passphrase no other account in the process uses.
 *
 * @returns {string}
 */
function uniquePassphrase(): string {
  return `builder-account-${crypto.randomUUID()}-Zz9!`
}

/**
 * A fresh credential and the account Space id it will be carried under: a
 * random ladder seed, and the standing client derived from the credential's
 * unlock seed. Given a passphrase, the unlock seed derives under `FAST_KDF`
 * and the credential is low-entropy; the unlock identity rides along so a
 * test can name its unlock Space. Without one, the unlock seed is 32 random
 * bytes and the credential is high-entropy.
 *
 * @param [options] {object}
 * @param [options.passphrase] {string}
 * @returns {Promise<object>}   `{ spaceId, ladderSeed, standing, lowEntropy,
 *   unlock? }`
 */
export async function mintCredential({
  passphrase
}: { passphrase?: string } = {}) {
  const unlockSeed =
    passphrase === undefined
      ? crypto.getRandomValues(new Uint8Array(32))
      : await deriveUnlockSeed({ secret: passphrase, kdf: FAST_KDF })
  return {
    spaceId: mintSpaceId(),
    ladderSeed: generateLadderSeed(),
    standing: await standingClientFromUnlockSeed({ unlockSeed }),
    lowEntropy: passphrase !== undefined,
    ...(passphrase === undefined
      ? {}
      : { unlock: await unlockIdentityFromSeed({ seed: unlockSeed }) })
  }
}

/**
 * A credential as {@link mintCredential} returns it.
 */
export type BuilderCredential = Awaited<ReturnType<typeof mintCredential>>

/**
 * Establishes a credential-anchored account on the server, through one run of
 * the signup ceremony. Each call is one run with its own in-memory pins, as a
 * fresh tab's would be, so a test re-running a torn establishment passes the
 * same `credential` again.
 *
 * @param options {object}
 * @param options.serverUrl {string}   the booted server's URL
 * @param [options.credential] {BuilderCredential}   from `mintCredential`; a
 *   fresh high-entropy one when omitted
 * @returns {Promise<object>}   the account's ids, the credential's ladder seed
 *   and standing client, and the bridge and sibling delegations the re-bind
 *   carried
 */
export async function establishAccount({
  serverUrl,
  credential
}: {
  serverUrl: string
  credential?: BuilderCredential
}) {
  const { spaceId, ladderSeed, standing, lowEntropy, unlock } =
    credential ?? (await mintCredential())
  const pinStore = memoryResourceLogPinStore()
  const bootstrapAgent = await ladderVmAgent({ ladderSeed })
  const bootstrapZcap = didKeyZcapClient({ keyAgent: bootstrapAgent })
  const bootstrapWas = new WasClient({ serverUrl, zcapClient: bootstrapZcap })
  const signer = userKeyRosterLogSigner({ keyAgent: bootstrapAgent })

  // The unlock record, held in memory. The re-bind is the last call, and the
  // one carrying the sibling delegation.
  const binds: Array<{ delegation: IZcap; delegatedClients?: IZcap }> = []
  const establishment = await establishCredentialAnchoredAccount({
    wasServerUrl: serverUrl,
    spaceId,
    ladderSeed,
    standing: {
      clientDid: standing.clientDid,
      keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase,
      recipientKid: standing.recipientKid,
      keyAgreementKey: standing.agents.keyAgreementKey
    },
    lowEntropy,
    bindRecord: async ({ delegation, delegatedClients }) => {
      binds.push({
        delegation,
        ...(delegatedClients ? { delegatedClients } : {})
      })
      return {
        createdAt: new Date(Date.now() + binds.length).toISOString(),
        unlockSpaceId: unlock?.spaceId ?? 'unlock-space-held-in-memory'
      }
    },
    rosterStoreFor: ({ did, log }) =>
      userKeyRosterDescriptorStore({
        storageServerUrl: serverUrl,
        zcapClient: bootstrapZcap,
        spaceId,
        resolveController: async () => webvhResourceLogController({ did, log }),
        pinStore,
        signer
      }),
    collectionStoreFor: ({ did, log }) =>
      accountCollectionStores({
        storageServerUrl: serverUrl,
        zcapClient: bootstrapZcap,
        spaceId,
        did,
        pinStore,
        signer,
        log
      }),
    bootstrapWasFor: () => bootstrapWas,
    idStore: wasWebvhIdStore({ was: bootstrapWas, spaceId, pinStore })
  })

  const record = binds.at(-1)
  if (!record?.delegatedClients) {
    throw new Error('fixture: the re-bind carried no sibling delegation')
  }
  const pointed = delegatedClientsPointer({ doc: establishment.accountLog.doc })
  if (pointed === undefined) {
    throw new Error('fixture: the establishment left no pointer')
  }
  return {
    serverUrl,
    spaceId,
    accountDid: establishment.did,
    annexSpaceId: clientAnnexDidParts({ did: pointed }).spaceId,
    ladderSeed,
    standing,
    bridge: record.delegation,
    sibling: record.delegatedClients
  }
}

export type EstablishedAccount = Awaited<ReturnType<typeof establishAccount>>

/**
 * A credential-anchored account with one passphrase.
 *
 * @param options {object}
 * @param options.serverUrl {string}
 * @param [options.passphrase] {string}   a unique one by default
 * @returns {Promise<object>}   the established account plus `passphrase`
 */
export async function buildPassphraseAccount({
  serverUrl,
  passphrase = uniquePassphrase()
}: {
  serverUrl: string
  passphrase?: string
}): Promise<EstablishedAccount & { passphrase: string }> {
  const account = await establishAccount({
    serverUrl,
    credential: await mintCredential({ passphrase })
  })
  return { ...account, passphrase }
}

/**
 * The account-ceremony context a transient session on the account's
 * credential acts under (the ladder kind): the account log written through
 * the record's bridge and signed by a ladder rung, and roster appends signed
 * by the ladder VM and invoked by a per-visit annex VM under the generation
 * delegation, the only authority such a session holds over the account
 * Space once its controller is the did:webvh.
 *
 * @param options {object}
 * @param options.account {EstablishedAccount}
 * @param options.pinStore {ResourceLogPinStore}   the run's chain-head pins
 * @returns {Promise<object>}   `{ idStore, rosterStore, signer }`
 */
async function ladderContext({
  account,
  pinStore
}: {
  account: EstablishedAccount
  pinStore: ResourceLogPinStore
}) {
  const { serverUrl, spaceId, accountDid, annexSpaceId, ladderSeed } = account
  const readAccountLog = async () =>
    verifyAccountLog({ did: accountDid, spaceId, host: serverUrl, pinStore })

  // The transient visit: a per-visit key enrolled into the pointed
  // generation through the record's sibling delegation.
  const { keyAgent } = await agentsFromSeed({
    seed: crypto.getRandomValues(new Uint8Array(32))
  })
  const enrolled = await enrollTransientClient({
    readAccountDocument: async () => (await readAccountLog()).doc,
    storeForGenerationId: generationId =>
      delegatedWebvhLogStore({
        host: serverUrl,
        spaceId: annexSpaceId,
        collectionId: generationId,
        delegation: account.sibling,
        zcapClient: account.standing.agents.zcapClient,
        pinStore
      }),
    ladderSeed,
    transientKeyMultibase: clientSigningKeyMultibase({ keyAgent })
  })
  const capability = embeddedGenerationDelegation({ doc: enrolled.doc })
  if (capability === undefined) {
    throw new Error('fixture: the generation carries no delegation')
  }

  return {
    // Public reads of the world-readable `did.jsonl`, and the bridge's
    // delegated PUT, invoked by the credential's standing client. The two
    // publishers declare the wide `WebvhIdStore` but only forward the store
    // to `signAccountEntry`, which needs the three-member shape.
    idStore: delegatedWebvhLogStore({
      host: serverUrl,
      spaceId,
      collectionId: ID_COLLECTION.id,
      delegation: account.bridge,
      zcapClient: account.standing.agents.zcapClient,
      pinStore
    }) as WebvhIdStore,
    // The controller view resolves per operation, so an append after an
    // entry anchors at the post-entry head.
    rosterStore: userKeyRosterDescriptorStore({
      storageServerUrl: serverUrl,
      zcapClient: webvhZcapClient({ keyAgent, did: enrolled.clientAnnexDid }),
      spaceId,
      resolveController: async () =>
        webvhResourceLogController({
          did: accountDid,
          log: (await readAccountLog()).log
        }),
      pinStore,
      signer: userKeyRosterLogSigner({
        keyAgent: await ladderVmAgent({ ladderSeed })
      }),
      capability
    }),
    signer: { kind: 'ladder' as const, ladderSeed },
    standingKeyAgreementKey: account.standing.agents
      .keyAgreementKey as IKeyAgreementKey
  }
}

/**
 * Adds a second standing credential to the account, acting as the account's
 * existing credential in a transient session: the standing establishment's
 * ladder branch. The new credential's bridge and sibling delegations are
 * signed by its OWN ladder VM; its record binds in memory; its ladder's rung
 * 0 is committed into the pointed generation (blocking on this branch); the
 * bind entry publishes, signed by the acting credential's ladder; and only
 * then is the new credential escrowed into the roster, since a ladder-signed
 * roster append is licensed at the inventory-changing version its own entry
 * mints.
 *
 * A second call with the same passphrase is not a converging re-run: each
 * call mints a fresh ladder seed, so the re-bind is refused at
 * `publishUnlockKey`.
 *
 * @param options {object}
 * @param options.account {EstablishedAccount}   the acting credential's
 *   account
 * @param [options.passphrase] {string}   the new credential's passphrase, a
 *   unique one by default
 * @returns {Promise<object>}   the new credential's passphrase, standing
 *   client, ladder seed, bridge, and sibling
 */
export async function addStandingCredential({
  account,
  passphrase = uniquePassphrase()
}: {
  account: EstablishedAccount
  passphrase?: string
}) {
  const { serverUrl, spaceId, accountDid, annexSpaceId } = account
  const pinStore = memoryResourceLogPinStore()
  const ctx = await ladderContext({ account, pinStore })
  const pointer = { did: accountDid, spaceId, host: serverUrl }
  const { standing, ladderSeed } = await mintCredential({ passphrase })
  const rung0 = await ladderRung({ ladderSeed, index: 0 })
  const boundZcapClient = await ladderVmZcapClient({ accountDid, ladderSeed })

  // The bridge and sibling, held in memory as the bound record's members.
  const bridge = await delegateLogWrite({
    zcapClient: boundZcapClient,
    pointer,
    recoveryClientDid: standing.clientDid
  })
  const sibling = await mintDelegatedClientsDelegation({
    zcapClient: boundZcapClient,
    wasServerUrl: serverUrl,
    clientAnnexSpaceId: annexSpaceId,
    controller: standing.clientDid
  })

  // The bound credential's annex rung 0, committed under the acting
  // credential's rung through the acting record's sibling.
  const { doc } = await verifyAccountLog({
    did: accountDid,
    spaceId,
    host: serverUrl,
    pinStore
  })
  const clientAnnexDid = delegatedClientsPointer({ doc })
  if (clientAnnexDid === undefined) {
    throw new Error('fixture: the account points at no annex generation')
  }
  const { generationId } = clientAnnexDidParts({ did: clientAnnexDid })
  await commitClientAnnexRung({
    store: clientAnnexLogStore({
      was: new WasClient({
        serverUrl,
        zcapClient: account.standing.agents.zcapClient
      }),
      spaceId: annexSpaceId,
      generationId,
      pinStore,
      capability: account.sibling
    }),
    boundLadderSeed: ladderSeed,
    actingLadderSeed: account.ladderSeed,
    generationId,
    expectedDid: clientAnnexDid
  })

  await publishUnlockKey({
    idStore: ctx.idStore,
    signer: ctx.signer,
    unlockKeys: {
      keyAgreement: {
        commitment: await keyAgreementCommitment({
          keyAgreementKeyMultibase: standing.keyAgreementKeyMultibase
        })
      },
      updateKeyMultibase: rung0.keyMultibase
    },
    ladderSeed,
    expectedDid: accountDid
  })
  await addUserKeyRosterRecipient({
    store: ctx.rosterStore,
    recipient: {
      id: standing.recipientKid,
      publicKeyMultibase: standing.keyAgreementKeyMultibase
    },
    ownerKeyAgreementKey: ctx.standingKeyAgreementKey
  })
  return { passphrase, standing, ladderSeed, bridge, sibling }
}

/**
 * Issues one recovery code, acting as the account's credential in a
 * transient session: the issuance's ladder branch. The code's bridge is
 * signed by the code's own ladder VM and binds in memory; then the code's
 * `keyAgreement` key publishes, its wrap is escrowed into the roster, and the
 * authority half (its ladder VM and rung-0 commitment) publishes last. The
 * code is not spent.
 *
 * @param options {object}
 * @param options.account {EstablishedAccount}
 * @returns {Promise<object>}   `{ code, client, recoveryKid, bridge }`
 */
export async function issueRecoveryCode({
  account
}: {
  account: EstablishedAccount
}) {
  const { serverUrl, spaceId, accountDid } = account
  const pinStore = memoryResourceLogPinStore()
  const ctx = await ladderContext({ account, pinStore })
  const pointer = { did: accountDid, spaceId, host: serverUrl }
  const code = generateRecoveryCode()
  const client = await recoveryClientFromCode({ code })
  const recovery = {
    keyAgreementKeyMultibase: client.keyAgreementKeyMultibase,
    updateKeyMultibase: client.updateKeyMultibase
  }

  const bridge = await delegateLogWrite({
    zcapClient: await ladderVmZcapClient({
      accountDid,
      ladderSeed: client.ladderSeed
    }),
    pointer,
    recoveryClientDid: client.clientDid
  })

  const publishPart = async (part: 'key' | 'authority') =>
    publishRecoveryKey({
      idStore: ctx.idStore,
      signer: ctx.signer,
      recovery,
      ladderSeed: client.ladderSeed,
      part,
      expectedDid: accountDid
    })
  await publishPart('key')
  await addUserKeyRosterRecipient({
    store: ctx.rosterStore,
    recipient: {
      id: client.recipientKid,
      publicKeyMultibase: client.keyAgreementKeyMultibase
    },
    ownerKeyAgreementKey: ctx.standingKeyAgreementKey
  })
  await publishPart('authority')
  return { code, client, recoveryKid: client.recipientKid, bridge }
}

/**
 * Self-enrolls one enrolled client with the account's credential
 * (`selfEnrollClientCore`), writing the account log through the record's
 * bridge. The `onCommitted` seam is an in-memory no-op: a wallet persists
 * the pending client-key record there, and here the seeds the core hands
 * back are returned to the caller, which is this fixture's persist. A torn
 * run is not this fixture's subject.
 *
 * @param options {object}
 * @param options.account {EstablishedAccount}
 * @returns {Promise<object>}   the new client's seed, agents, signing key
 *   multibase, did:webvh update keys, did:key, the user key it read, and a
 *   zcap client signing as `<accountDid>#<signing key>`
 */
export async function enrollClient({
  account
}: {
  account: EstablishedAccount
}) {
  const { serverUrl, spaceId, accountDid, ladderSeed, standing } = account
  const pinStore = memoryResourceLogPinStore()
  const enrolled = await selfEnrollClientCore({
    pointer: { did: accountDid, spaceId, host: serverUrl },
    ladderSeed,
    credentialKeyAgreementKey: standing.agents
      .keyAgreementKey as IKeyAgreementKey,
    logStore: delegatedWebvhLogStore({
      host: serverUrl,
      spaceId,
      collectionId: ID_COLLECTION.id,
      delegation: account.bridge,
      zcapClient: standing.agents.zcapClient,
      pinStore
    }),
    onCommitted: async () => {}
  })
  const agents = await agentsFromSeed({ seed: enrolled.clientSeed })
  const zcapClient: ZcapClient = webvhZcapClient({
    keyAgent: agents.keyAgent,
    did: accountDid
  })
  return {
    clientSeed: enrolled.clientSeed,
    agents,
    signingKeyMultibase: clientSigningKeyMultibase({
      keyAgent: agents.keyAgent
    }),
    webvhUpdateKeys: enrolled.webvhUpdateKeys,
    clientDid: enrolled.clientDid,
    userKey: enrolled.userKey,
    zcapClient
  }
}

/**
 * The passphrase shape plus a second standing credential.
 *
 * @param options {object}
 * @param options.serverUrl {string}
 * @param [options.passphrase] {string}   a unique one by default
 * @returns {Promise<object>}   the passphrase account plus `second`
 */
export async function buildSecondCredentialAccount({
  serverUrl,
  passphrase
}: {
  serverUrl: string
  passphrase?: string
}) {
  const account = await buildPassphraseAccount({
    serverUrl,
    ...(passphrase === undefined ? {} : { passphrase })
  })
  return { ...account, second: await addStandingCredential({ account }) }
}

/**
 * The passphrase shape plus one issued, unspent recovery code.
 *
 * @param options {object}
 * @param options.serverUrl {string}
 * @param [options.passphrase] {string}   a unique one by default
 * @returns {Promise<object>}   the passphrase account plus `recovery`
 */
export async function buildRecoveryCodeAccount({
  serverUrl,
  passphrase
}: {
  serverUrl: string
  passphrase?: string
}) {
  const account = await buildPassphraseAccount({
    serverUrl,
    ...(passphrase === undefined ? {} : { passphrase })
  })
  return { ...account, recovery: await issueRecoveryCode({ account }) }
}

/**
 * The passphrase shape plus one enrolled client.
 *
 * @param options {object}
 * @param options.serverUrl {string}
 * @param [options.passphrase] {string}   a unique one by default
 * @returns {Promise<object>}   the passphrase account plus `client`
 */
export async function buildEnrolledClientAccount({
  serverUrl,
  passphrase
}: {
  serverUrl: string
  passphrase?: string
}) {
  const account = await buildPassphraseAccount({
    serverUrl,
    ...(passphrase === undefined ? {} : { passphrase })
  })
  return { ...account, client: await enrollClient({ account }) }
}
