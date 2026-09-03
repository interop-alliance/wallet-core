/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The account-genesis ceremony's credential-anchored variant
 * (`src/genesis/credentialAnchoredGenesis.ts`): the credential-anchored signup's
 * ceremony, anchored on the unlock credential's ladder alone. Driven with
 * real key material (a random ladder seed, a standing client derived from a
 * random unlock seed, `mintUserKey`) against the shared in-memory fakes, so
 * the genesis publishes a real, verifiable ladder-anchored did:webvh log.
 *
 * What the suite pins beyond the enrolled-client ceremony's contract: the Space is
 * bootstrapped under the LADDER VM's did:key; the roster's one recipient is
 * the credential's standing key-agreement key; the collection-epoch stage is
 * gated on the roster landing (the user key is memory-only here); a re-run
 * adopts the published log by ladder attribution (a naive re-create would
 * mint a different SCID); and a log another credential's ladder published is
 * refused fail-closed, never built on.
 */
import { describe, expect, it } from 'vitest'

import { readLogFromString } from '@interop/did-method-webvh'
import type { CollectionEncryption, WasClient } from '@interop/was-client'
import { PreconditionFailedError } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'

import {
  ensureCredentialAnchoredAccountGenesis,
  mintCredentialAnchoredAccountKeySet
} from '../../src/clientAnnex/credentialAnchoredGenesis.js'
import type {
  DidWebKeyMapV2,
  KmsAuthenticationBinding
} from '../../src/webvh/didWebvh.js'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import { accountLogPinId } from '../../src/webvh/verifyLog.js'
import { ladderVmAgent } from '../../src/clientAnnex/zcap.js'
import { ladderVmIds } from '../../src/resourceLog/document.js'
import {
  generateLadderSeed,
  ladderRung,
  ladderVmKeyMultibase
} from '../../src/clientAnnex/ladder.js'
import { standingClientFromUnlockSeed } from '../../src/unlock/index.js'
import { WALLET_SPACE_PROVISION_ROSTER } from '../../src/space/index.js'
import {
  ensureWalletSpaceEpochs,
  userKeyAsRecipient
} from '../../src/keys/index.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-genesis'

/**
 * The encrypted roster collections -- the ones epoch[0] lands on.
 */
const EDV_ROSTER_IDS = WALLET_SPACE_PROVISION_ROSTER.filter(
  spec => spec.encryption === 'edv'
).map(spec => spec.collectionId)

/**
 * The Collection Description fields the fake stores.
 */
interface StoredDescription {
  name?: string
  encryption?: CollectionEncryption
}

/**
 * The stateful was-client fake from the enrolled-client genesis suite, trimmed to the
 * surfaces this ceremony drives (the KMS key-map stage is a caller-supplied
 * closure, so no KMS surface exists on the fake).
 *
 * @returns {object}   the `was` handle, a controller reader, and a
 *   per-collection descriptor reader
 */
function fakeWas() {
  let spaceDescription: { name?: string; controller?: string } | null = null
  const collections = new Map<
    string,
    { description: StoredDescription; version: number; isPublic: boolean }
  >()
  const was = {
    space: (spaceId: string) => {
      expect(spaceId).toBe(SPACE_ID)
      return {
        describe: async () =>
          spaceDescription ? { id: SPACE_ID, ...spaceDescription } : null,
        configure: async (options: { name?: string; controller?: string }) => {
          spaceDescription = { ...options }
          return { id: SPACE_ID, type: ['Space'], ...options }
        },
        collection: (collectionId: string) => ({
          describe: async () => {
            const entry = collections.get(collectionId)
            return entry ? structuredClone(entry.description) : null
          },
          configure: async (options: {
            name?: string
            encryption?: CollectionEncryption
          }) => {
            const entry = collections.get(collectionId)
            const description: StoredDescription = {
              name: options.name,
              ...(options.encryption ? { encryption: options.encryption } : {})
            }
            if (entry) {
              entry.description = description
              entry.version++
            } else {
              collections.set(collectionId, {
                description,
                version: 0,
                isPublic: false
              })
            }
          },
          isPublic: async () =>
            collections.get(collectionId)?.isPublic ?? false,
          setPublic: async () => {
            const entry = collections.get(collectionId)
            if (entry) {
              entry.isPublic = true
            }
          },
          describeWithEtag: async () => {
            const entry = collections.get(collectionId)
            return entry
              ? {
                  description: structuredClone(entry.description),
                  etag: `v${entry.version}`
                }
              : null
          },
          replaceDescription: async (
            description: StoredDescription,
            { ifMatch }: { ifMatch?: string }
          ) => {
            const entry = collections.get(collectionId)!
            if (ifMatch !== `v${entry.version}`) {
              throw new PreconditionFailedError('stale description etag')
            }
            entry.description = structuredClone(description)
            entry.version++
          }
        })
      }
    }
  } as unknown as WasClient
  return {
    was,
    controller: () => spaceDescription?.controller,
    /**
     * How many collections the Space provisioning has configured so far --
     * the observable the KMS stage's concurrency is asserted against.
     */
    collectionsConfigured: () => collections.size,
    descriptorOf: (collectionId: string) =>
      collections.get(collectionId)!.description.encryption!,
    /**
     * Drops a collection's epoch roster, keeping the scheme marker the
     * provisioning step left -- the state a collection is in when an earlier
     * run's epoch fan-out never reached it.
     */
    stripEpochs: (collectionId: string) => {
      const entry = collections.get(collectionId)!
      const {
        epochs: _epochs,
        currentEpoch: _currentEpoch,
        ...rest
      } = entry.description.encryption as CollectionEncryption
      entry.description = {
        ...entry.description,
        encryption: rest as CollectionEncryption
      }
      entry.version++
    }
  }
}

/**
 * An in-memory `EncryptionDescriptorStore` for the user-key roster, with an
 * optional one-shot write failure.
 *
 * @param [options] {object}
 * @param [options.failFirstWrite] {boolean}
 * @returns {EncryptionDescriptorStore}   plus a `_getDescriptor` reader
 */
function memoryDescriptorStore({
  failFirstWrite = false
}: { failFirstWrite?: boolean } = {}): EncryptionDescriptorStore & {
  _getDescriptor(): CollectionEncryption | null
} {
  let descriptor: CollectionEncryption | null = null
  let version = 0
  let pendingFailure = failFirstWrite
  const failOnce = () => {
    if (pendingFailure) {
      pendingFailure = false
      throw new Error('injected: the roster store is unavailable')
    }
  }
  return {
    async read() {
      return descriptor
        ? { descriptor: structuredClone(descriptor), etag: `v${version}` }
        : null
    },
    async replace(next, { ifMatch }: { ifMatch?: string }) {
      failOnce()
      if (ifMatch !== `v${version}`) {
        throw new PreconditionFailedError('stale descriptor etag')
      }
      descriptor = next
      version++
    },
    async create(next) {
      failOnce()
      if (descriptor) {
        throw new PreconditionFailedError('descriptor already exists')
      }
      descriptor = next
      version++
    },
    _getDescriptor() {
      return descriptor ? structuredClone(descriptor) : null
    }
  }
}

/**
 * The minting credential: a random ladder seed plus the standing client
 * derived from a random unlock seed -- the roster recipient and the
 * key-agreement publication both come from it.
 */
async function mintingCredential() {
  const ladderSeed = generateLadderSeed()
  const standing = await standingClientFromUnlockSeed({
    unlockSeed: crypto.getRandomValues(new Uint8Array(32))
  })
  return {
    ladderSeed,
    keyAgreement: {
      publicKeyMultibase: standing.keyAgreementKeyMultibase
    },
    standingRecipient: {
      id: standing.recipientKid,
      publicKeyMultibase: standing.keyAgreementKeyMultibase
    }
  }
}

/**
 * The number of entries in the published did:webvh log.
 */
function logLength(log: string | undefined): number {
  return readLogFromString(log!).length
}

/**
 * The KMS key map a KMS-keeping wallet's `provideDidWebKeys` resolves --
 * bare multibase fragments, the same shape the enrolled-client genesis suite uses.
 */
const KMS_AUTH_MULTIBASE = 'z6MkAuthConvenience'
function didWebKeyMap(): DidWebKeyMapV2 {
  return {
    authentication: {
      vmId: `did:web:example#${KMS_AUTH_MULTIBASE}`,
      kmsKeyId: 'kms/keys/auth'
    }
  }
}

/**
 * The relation arrays of the published genesis document, as vm-id strings.
 */
function publishedDoc(logText: string) {
  const log = readLogFromString(logText)
  return log[log.length - 1]!.state as {
    verificationMethod?: Array<{ id?: string; publicKeyMultibase?: string }>
    authentication?: string[]
    assertionMethod?: string[]
    keyAgreement?: string[]
    capabilityInvocation?: string[]
    capabilityDelegation?: string[]
  }
}

describe('mintCredentialAnchoredAccountKeySet', () => {
  it('mints only the Space id and the user key -- no client members exist', async () => {
    const keySet = await mintCredentialAnchoredAccountKeySet()

    expect(Object.keys(keySet).sort()).toEqual(['spaceId', 'userKey'])
    expect(keySet.spaceId).toHaveLength(43)
    expect(keySet.userKey.id.startsWith('did:key:')).toBe(true)
    expect(keySet.userKey.secret).toHaveLength(32)
  })
})

describe('ensureCredentialAnchoredAccountGenesis (fresh)', () => {
  it('bootstraps under the ladder did:key, publishes the ladder-anchored genesis, seeds the roster to the credential, and promotes', async () => {
    const credential = await mintingCredential()
    const { spaceId: _ignored, userKey } =
      await mintCredentialAnchoredAccountKeySet()
    const fakes = memoryIdStore()
    const store = memoryDescriptorStore()
    const pinStore = memoryResourceLogPinStore()
    const { was, controller, descriptorOf } = fakeWas()
    const published: string[] = []
    let controllerAtDidPublish: string | undefined

    const result = await ensureCredentialAnchoredAccountGenesis({
      was,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      ladderSeed: credential.ladderSeed,
      keyAgreement: credential.keyAgreement,
      standingRecipient: credential.standingRecipient,
      userKey,
      idStore: fakes.idStore,
      rosterStoreFor: () => store,
      accountLogPinStore: pinStore,
      onDidPublished: async ({ did }) => {
        published.push(did)
        controllerAtDidPublish = controller()
      }
    })

    expect(result.failed).toEqual([])
    expect(result.did.startsWith('did:webvh:')).toBe(true)
    expect(published).toEqual([result.did])

    // The Space was bootstrapped under the LADDER VM's did:key: that is what
    // makes a tear before promotion recoverable by re-derivation.
    const bootstrap = await ladderVmAgent({
      ladderSeed: credential.ladderSeed
    })
    expect(controllerAtDidPublish).toBe(bootstrap.id)

    // One entry, signed by rung 0, committing rung 0's carry-over hash and
    // rung 1; the ladder VM and the credential's keyAgreement inventory are
    // folded in (the full parameter shape is pinned by the unlock-ladder-anchored
    // suite -- here the ceremony-level essentials).
    const log = readLogFromString(fakes.log()!)
    expect(log).toHaveLength(1)
    const rung0 = await ladderRung({
      ladderSeed: credential.ladderSeed,
      index: 0
    })
    expect(log[0]!.parameters.updateKeys).toEqual([rung0.keyMultibase])
    expect(log[0]!.parameters.nextKeyHashes).toHaveLength(2)
    expect(log[0]!.parameters.portable).toBe(true)
    const doc = log[0]!.state as {
      verificationMethod?: Array<{ publicKeyMultibase?: string }>
    }
    expect(ladderVmIds({ doc: doc as never })).toHaveLength(1)
    const ladderMultibase = await ladderVmKeyMultibase({
      ladderSeed: credential.ladderSeed
    })
    expect(
      doc.verificationMethod!.some(
        method => method.publicKeyMultibase === ladderMultibase
      )
    ).toBe(true)

    // The trust-on-first-use pin was written by the creator itself.
    expect(
      await pinStore.read({ logId: accountLogPinId({ spaceId: SPACE_ID }) })
    ).not.toBeNull()

    // The roster's one recipient is the credential's standing key-agreement
    // key -- the account is credential-recoverable from this moment.
    expect(result.rosterDescriptor!.currentEpoch).toBe(userKey.id)
    expect(
      result.rosterDescriptor!.epochs![0]!.recipients.map(
        entry => entry.header.kid
      )
    ).toEqual([credential.standingRecipient.id])

    // epoch[0] landed on every encrypted roster collection.
    expect(result.epochs!.failed).toEqual([])
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(result.epochs!.outcomes[collectionId]!.installed).toBe(true)
      expect(descriptorOf(collectionId).epochs).toHaveLength(1)
    }

    // The Space ends up controlled by the account DID.
    expect(result.promotion).toBe('promoted')
    expect(controller()).toBe(result.did)
  })

  it('leaves the ladder did:key as controller when the caller promotes itself', async () => {
    const credential = await mintingCredential()
    const { userKey } = await mintCredentialAnchoredAccountKeySet()
    const fakes = memoryIdStore()
    const { was, controller } = fakeWas()

    const result = await ensureCredentialAnchoredAccountGenesis({
      was,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      ladderSeed: credential.ladderSeed,
      keyAgreement: credential.keyAgreement,
      standingRecipient: credential.standingRecipient,
      userKey,
      idStore: fakes.idStore,
      rosterStoreFor: () => memoryDescriptorStore(),
      promoteController: false
    })

    expect(result.failed).toEqual([])
    expect('promotion' in result).toBe(false)
    const bootstrap = await ladderVmAgent({
      ladderSeed: credential.ladderSeed
    })
    expect(controller()).toBe(bootstrap.id)
  })
})

describe('ensureCredentialAnchoredAccountGenesis (convergence)', () => {
  it('adopts everything on a full re-run by ladder attribution', async () => {
    const credential = await mintingCredential()
    const { userKey } = await mintCredentialAnchoredAccountKeySet()
    const fakes = memoryIdStore()
    const store = memoryDescriptorStore()
    const { was, controller, descriptorOf } = fakeWas()
    const run = () =>
      ensureCredentialAnchoredAccountGenesis({
        was,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        ladderSeed: credential.ladderSeed,
        keyAgreement: credential.keyAgreement,
        standingRecipient: credential.standingRecipient,
        userKey,
        idStore: fakes.idStore,
        rosterStoreFor: () => store
      })

    const first = await run()
    const entriesAfterFirst = logLength(fakes.log())
    const settledEpochs = EDV_ROSTER_IDS.map(collectionId =>
      structuredClone(descriptorOf(collectionId))
    )

    const second = await run()

    // A naive re-create would mint a DIFFERENT SCID (createDID timestamps
    // the entry); the same DID coming back is the adoption at work.
    expect(second.did).toBe(first.did)
    expect(second.failed).toEqual([])
    expect(logLength(fakes.log())).toBe(entriesAfterFirst)
    expect(second.rosterDescriptor).toEqual(first.rosterDescriptor)
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(second.epochs!.outcomes[collectionId]!.installed).toBe(false)
    }
    expect(
      EDV_ROSTER_IDS.map(collectionId => descriptorOf(collectionId))
    ).toEqual(settledEpochs)
    expect(second.promotion).toBe('confirmed')
    expect(controller()).toBe(first.did)
  })

  it("refuses a published log another credential's ladder anchors", async () => {
    const winner = await mintingCredential()
    const loser = await mintingCredential()
    const { userKey } = await mintCredentialAnchoredAccountKeySet()
    const fakes = memoryIdStore()
    const { was } = fakeWas()
    const run = (credential: Awaited<ReturnType<typeof mintingCredential>>) =>
      ensureCredentialAnchoredAccountGenesis({
        was,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        ladderSeed: credential.ladderSeed,
        keyAgreement: credential.keyAgreement,
        standingRecipient: credential.standingRecipient,
        userKey,
        idStore: fakes.idStore,
        rosterStoreFor: () => memoryDescriptorStore()
      })

    const first = await run(winner)
    const entriesAfterFirst = logLength(fakes.log())

    // The loser's ceremony finds a published log its own ladder cannot
    // attribute: fail closed, never adopt or extend.
    await expect(run(loser)).rejects.toMatchObject({
      name: 'LadderAttributionError'
    })
    expect(logLength(fakes.log())).toBe(entriesAfterFirst)
    expect(first.did.startsWith('did:webvh:')).toBe(true)
  })

  it('skips the epoch stage when the adopted roster is keyed to another user key', async () => {
    const credential = await mintingCredential()
    const { userKey: first } = await mintCredentialAnchoredAccountKeySet()
    const { userKey: candidate } = await mintCredentialAnchoredAccountKeySet()
    const fakes = memoryIdStore()
    const store = memoryDescriptorStore()
    const { was, descriptorOf, stripEpochs } = fakeWas()
    const run = (userKey: typeof first) =>
      ensureCredentialAnchoredAccountGenesis({
        was,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        ladderSeed: credential.ladderSeed,
        keyAgreement: credential.keyAgreement,
        standingRecipient: credential.standingRecipient,
        userKey,
        idStore: fakes.idStore,
        rosterStoreFor: () => store
      })

    const settled = await run(first)
    expect(settled.failed).toEqual([])

    // The tear this pins: an earlier run's epoch fan-out never reached this
    // collection, so it carries the scheme marker and no epoch roster.
    const stranded = EDV_ROSTER_IDS[0]!
    const untouched = EDV_ROSTER_IDS.slice(1)
    stripEpochs(stranded)
    expect(descriptorOf(stranded).epochs).toBeUndefined()
    const settledEpochs = untouched.map(collectionId =>
      structuredClone(descriptorOf(collectionId))
    )

    // The re-run adopts the earlier roster -- keyed to `first` -- while
    // holding a throwaway candidate key nobody will ever hold again.
    const rerun = await run(candidate)

    expect(rerun.failed).toEqual([])
    expect(rerun.rosterDescriptor!.currentEpoch).toBe(first.id)
    expect(rerun.epochsSkipped).toEqual({ rosterEpochId: first.id })
    expect('epochs' in rerun).toBe(false)

    // Nothing was installed under the candidate key: the stranded collection
    // is still epoch-less, and the settled ones still name `first`.
    expect(descriptorOf(stranded).epochs).toBeUndefined()
    expect(untouched.map(collectionId => descriptorOf(collectionId))).toEqual(
      settledEpochs
    )
    for (const collectionId of untouched) {
      expect(
        descriptorOf(collectionId).epochs![0]!.recipients.map(
          entry => entry.header.kid
        )
      ).toEqual([userKeyAsRecipient({ userKey: first }).id])
    }

    // The completer: the caller that recovers the roster's real key is the
    // one installer, and it finishes the fan-out.
    const completed = await ensureWalletSpaceEpochs({
      was,
      spaceId: SPACE_ID,
      userKey: first
    })

    expect(completed.failed).toEqual([])
    expect(completed.outcomes[stranded]!.installed).toBe(true)
    const descriptor = descriptorOf(stranded)
    expect(descriptor.epochs).toHaveLength(1)
    expect(descriptor.currentEpoch).toBe(descriptor.epochs![0]!.id)
    expect(
      descriptor.epochs![0]!.recipients.map(entry => entry.header.kid)
    ).toEqual([userKeyAsRecipient({ userKey: first }).id])
  })

  it('gates the epoch stage on the roster landing, and heals both on re-run', async () => {
    const credential = await mintingCredential()
    const { userKey } = await mintCredentialAnchoredAccountKeySet()
    const fakes = memoryIdStore()
    const { was, controller, descriptorOf } = fakeWas()
    const store = memoryDescriptorStore({ failFirstWrite: true })
    const run = () =>
      ensureCredentialAnchoredAccountGenesis({
        was,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        ladderSeed: credential.ladderSeed,
        keyAgreement: credential.keyAgreement,
        standingRecipient: credential.standingRecipient,
        userKey,
        idStore: fakes.idStore,
        rosterStoreFor: () => store
      })

    const torn = await run()

    // The roster failure is collected -- and, unlike the enrolled-client flow, the
    // epoch stage is SKIPPED: the user key exists only in this tab's memory,
    // so collection epochs must never outlive the roster wrap that delivers
    // it. The promoted-account-with-no-roster state this leaves is exactly
    // the tear the transient login's heal detects and finishes.
    expect(torn.failed).toHaveLength(1)
    expect(torn.failed[0]!.stage).toBe('roster')
    expect(torn.rosterDescriptor).toBeUndefined()
    expect('epochs' in torn).toBe(false)
    for (const collectionId of EDV_ROSTER_IDS) {
      // The provisioning stub's scheme marker stands, but no epoch roster
      // landed on any collection.
      expect(descriptorOf(collectionId).epochs).toBeUndefined()
    }
    expect(torn.promotion).toBe('promoted')

    const healed = await run()

    expect(healed.failed).toEqual([])
    expect(healed.did).toBe(torn.did)
    expect(healed.rosterDescriptor!.currentEpoch).toBe(userKey.id)
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(healed.epochs!.outcomes[collectionId]!.installed).toBe(true)
    }
    expect(healed.promotion).toBe('confirmed')
    expect(controller()).toBe(torn.did)
  })
})

describe('ensureCredentialAnchoredAccountGenesis (KMS-backed)', () => {
  it('folds the KMS authentication VM into the published genesis, under authentication only', async () => {
    const credential = await mintingCredential()
    const { userKey } = await mintCredentialAnchoredAccountKeySet()
    const fakes = memoryIdStore()
    const { was, collectionsConfigured } = fakeWas()
    let collectionsAtStart = -1
    let collectionsAtWrite = -1

    const result = await ensureCredentialAnchoredAccountGenesis({
      was,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      ladderSeed: credential.ladderSeed,
      keyAgreement: credential.keyAgreement,
      standingRecipient: credential.standingRecipient,
      userKey,
      idStore: fakes.idStore,
      rosterStoreFor: () => memoryDescriptorStore(),
      provideKmsAuthentication: async ({ spaceReady }) => {
        // The stage starts before the Space is provisioned; only the write
        // it orders behind `spaceReady` waits for the collection roster.
        collectionsAtStart = collectionsConfigured()
        await spaceReady
        collectionsAtWrite = collectionsConfigured()
        const written = await fakes.idStore.putKeyMap({
          content: didWebKeyMap(),
          ifNoneMatch: true
        })
        return {
          keys: didWebKeyMap(),
          ...(written?.etag !== undefined ? { etag: written.etag } : {})
        }
      }
    })

    expect(result.failed).toEqual([])
    expect(collectionsAtStart).toBeLessThan(collectionsAtWrite)
    expect(collectionsAtWrite).toBe(WALLET_SPACE_PROVISION_ROSTER.length)
    const doc = publishedDoc(fakes.log()!)
    const kmsVmId = `${result.did}#${KMS_AUTH_MULTIBASE}`
    const ladderVmId = `${result.did}#${await ladderVmKeyMultibase({
      ladderSeed: credential.ladderSeed
    })}`

    // The convenience key joins authentication ONLY: the ladder VM's two
    // relations and the credential's keyAgreement entry stand unchanged, and
    // nothing invocable enters the document.
    expect(doc.authentication).toEqual([kmsVmId])
    expect(doc.assertionMethod).toEqual([ladderVmId])
    expect(doc.capabilityDelegation).toEqual([ladderVmId])
    expect(doc.capabilityInvocation ?? []).toEqual([])
    expect(doc.keyAgreement).toHaveLength(1)
    expect(doc.keyAgreement).not.toContain(kmsVmId)
    expect(doc.verificationMethod).toHaveLength(3)
    expect(doc.verificationMethod).toContainEqual({
      id: kmsVmId,
      type: 'Multikey',
      controller: result.did,
      publicKeyMultibase: KMS_AUTH_MULTIBASE
    })

    // The create path records the DID into keys.json's webvh block beside
    // the KMS bindings, exactly as the enrolled-client ensure does.
    const keys = fakes.keys() as DidWebKeyMapV2
    expect(keys.webvh).toEqual({ did: result.did })
    expect(keys.authentication).toEqual(didWebKeyMap().authentication)
  })

  it('converges the genesis rewrite when another writer moved keys.json on', async () => {
    const credential = await mintingCredential()
    const { userKey } = await mintCredentialAnchoredAccountKeySet()
    const fakes = memoryIdStore()
    const { was } = fakeWas()

    // The rewrite runs after the genesis entry has published, so a lost
    // precondition on this bookkeeping resource must not fail the signup:
    // the rewrite re-reads and lands on the served ETag.
    const result = await ensureCredentialAnchoredAccountGenesis({
      was,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      ladderSeed: credential.ladderSeed,
      keyAgreement: credential.keyAgreement,
      standingRecipient: credential.standingRecipient,
      userKey,
      idStore: fakes.idStore,
      rosterStoreFor: () => memoryDescriptorStore(),
      provideKmsAuthentication: async ({ spaceReady }) => {
        await spaceReady
        const written = await fakes.idStore.putKeyMap({
          content: didWebKeyMap(),
          ifNoneMatch: true
        })
        // A concurrent establishment writes the same resource between the
        // two stages, so the ETag this stage reports is already stale.
        await fakes.idStore.putKeyMap({ content: didWebKeyMap() })
        return {
          keys: didWebKeyMap(),
          ...(written?.etag !== undefined ? { etag: written.etag } : {})
        }
      }
    })

    expect(result.failed).toEqual([])
    expect(result.promotion).toBe('promoted')
    const keys = fakes.keys() as DidWebKeyMapV2
    expect(keys.webvh).toEqual({ did: result.did })
    expect(keys.authentication).toEqual(didWebKeyMap().authentication)
  })

  it('backfills the webvh block on a re-run that adopts the published log', async () => {
    const credential = await mintingCredential()
    const { userKey } = await mintCredentialAnchoredAccountKeySet()
    const fakes = memoryIdStore()
    const store = memoryDescriptorStore()
    const { was } = fakeWas()
    // The tear: the genesis entry publishes, then the rewrite that would add
    // the `webvh` block is lost. A transport failure there is fatal, as it is
    // on every other stage-3 write.
    let keyMapWrites = 0
    const tearing = {
      ...fakes.idStore,
      putKeyMap: async (
        options: Parameters<typeof fakes.idStore.putKeyMap>[0]
      ) => {
        keyMapWrites += 1
        if (keyMapWrites === 2) {
          throw new Error('injected: the keys.json rewrite was lost')
        }
        return fakes.idStore.putKeyMap(options)
      }
    }
    const kmsStage = async ({
      spaceReady
    }: {
      spaceReady: Promise<unknown>
    }) => {
      await spaceReady
      const written = await tearing.putKeyMap({
        content: didWebKeyMap(),
        ifNoneMatch: true
      })
      return {
        keys: didWebKeyMap(),
        ...(written?.etag !== undefined ? { etag: written.etag } : {})
      }
    }

    await expect(
      ensureCredentialAnchoredAccountGenesis({
        was,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        ladderSeed: credential.ladderSeed,
        keyAgreement: credential.keyAgreement,
        standingRecipient: credential.standingRecipient,
        userKey,
        idStore: tearing,
        rosterStoreFor: () => store,
        provideKmsAuthentication: kmsStage
      })
    ).rejects.toThrow('injected')
    expect((fakes.keys() as DidWebKeyMapV2).webvh).toBeUndefined()

    // The next establishment adopts the published log and records the DID
    // into the map the torn run left, under the served ETag.
    const rerun = await ensureCredentialAnchoredAccountGenesis({
      was,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      ladderSeed: credential.ladderSeed,
      keyAgreement: credential.keyAgreement,
      standingRecipient: credential.standingRecipient,
      userKey,
      idStore: fakes.idStore,
      rosterStoreFor: () => store,
      provideKmsAuthentication: async ({ spaceReady }) => {
        await spaceReady
        return { keys: didWebKeyMap() }
      }
    })

    const keys = fakes.keys() as DidWebKeyMapV2
    expect(keys.webvh).toEqual({ did: rerun.did })
    expect(keys.authentication).toEqual(didWebKeyMap().authentication)
  })

  it('collects a thrown KMS stage and publishes the ladder-and-credential-only genesis', async () => {
    const credential = await mintingCredential()
    const { userKey } = await mintCredentialAnchoredAccountKeySet()
    const fakes = memoryIdStore()
    const { was, controller } = fakeWas()

    const result = await ensureCredentialAnchoredAccountGenesis({
      was,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      ladderSeed: credential.ladderSeed,
      keyAgreement: credential.keyAgreement,
      standingRecipient: credential.standingRecipient,
      userKey,
      idStore: fakes.idStore,
      rosterStoreFor: () => memoryDescriptorStore(),
      provideKmsAuthentication: async () => {
        throw new Error('injected: the KMS is unreachable')
      }
    })

    // The one collected stage; the run completed and everything else landed.
    expect(result.failed).toHaveLength(1)
    expect(result.failed[0]!.stage).toBe('kmsAuthentication')
    expect((result.failed[0]!.error as Error).message).toContain('injected')
    expect(result.did.startsWith('did:webvh:')).toBe(true)
    expect(result.rosterDescriptor!.currentEpoch).toBe(userKey.id)
    expect(result.promotion).toBe('promoted')
    expect(controller()).toBe(result.did)

    // The genesis is client/ladder-keys-only: no KMS VM anywhere.
    const doc = publishedDoc(fakes.log()!)
    expect(doc.authentication ?? []).toEqual([])
    expect(doc.verificationMethod).toHaveLength(2)
  })

  it('adopts a published log without the KMS VM unchanged, even when the key map resolves', async () => {
    const credential = await mintingCredential()
    const { userKey } = await mintCredentialAnchoredAccountKeySet()
    const fakes = memoryIdStore()
    const store = memoryDescriptorStore()
    const { was } = fakeWas()
    const run = (
      provideKmsAuthentication?: () => Promise<KmsAuthenticationBinding>
    ) =>
      ensureCredentialAnchoredAccountGenesis({
        was,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        ladderSeed: credential.ladderSeed,
        keyAgreement: credential.keyAgreement,
        standingRecipient: credential.standingRecipient,
        userKey,
        idStore: fakes.idStore,
        rosterStoreFor: () => store,
        ...(provideKmsAuthentication ? { provideKmsAuthentication } : {})
      })

    const first = await run()
    const entriesAfterFirst = logLength(fakes.log())

    // Adopting a published log never edits it: no second entry, no error --
    // and no later entry ever adds the missing KMS key.
    const rerun = await run(async () => ({ keys: didWebKeyMap() }))

    expect(rerun.failed).toEqual([])
    expect(rerun.did).toBe(first.did)
    expect(logLength(fakes.log())).toBe(entriesAfterFirst)
    const doc = publishedDoc(fakes.log()!)
    expect(doc.authentication ?? []).toEqual([])
    expect(doc.verificationMethod).toHaveLength(2)
    // No keys.json record either: the adoption path never writes.
    expect(fakes.keys()).toEqual({})
  })
})
