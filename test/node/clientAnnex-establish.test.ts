/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The credential-anchored establishment orchestrator
 * (`src/clientAnnex/establish.ts`): the stage order over real key material
 * against in-memory fakes, the conditional first bind, the `lowEntropy`
 * fail-safe, the required-hook TypeErrors, and -- the family the extraction
 * exists to centralize -- tear convergence at each stage boundary: kill the
 * run there, re-run, assert convergence (same SCID by ladder attribution, no
 * duplicate log entries, the `beforePromotion` hook re-fired, promotion
 * landed). Plus the shared mint-policy stage
 * (`ensureRosterDeliveredEpochs`): epochs install under the key the roster
 * DELIVERS, the lost create race adopts and reports converged-elsewhere, the
 * no-wrap adoption is its own outcome, and the completion test re-enters on
 * an epoch-less encrypted collection behind a present roster. Plus the
 * one-read composition: a whole fresh signup spends one `did.jsonl` read
 * (three before the genesis's head was threaded forward), while a heal
 * re-run keeps its two, since a head this run did not mint says nothing
 * about a pointer a concurrent login may have written meanwhile.
 */
import { describe, expect, it } from 'vitest'

import { readLogFromString } from '@interop/did-method-webvh'
import type { CollectionEncryption, WasClient } from '@interop/was-client'
import { PreconditionFailedError } from '@interop/was-client'
import { initRecipients } from '@interop/was-client/edv'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import {
  pinOfLog,
  readPublishedLog,
  WebvhLogConflictError
} from '../../src/webvh/didWebvh.js'
import { ladderSignedGenerationDelegationMinter } from '../../src/clientAnnex/heal.js'
import type { IZcap } from '@interop/data-integrity-core'

import {
  ensurePointedClientAnnexGeneration,
  establishCredentialAnchoredAccount
} from '../../src/clientAnnex/establish.js'
import { CREDENTIAL_ANCHORED_ESTABLISHMENT_STAGES } from '../../src/clientAnnex/stages.js'
import { mendCredentialAnchoredAccount } from '../../src/clientAnnex/mend.js'
import type { CredentialAnchoredMendReport } from '../../src/clientAnnex/mend.js'
import type { CredentialAnchoredEstablishment } from '../../src/clientAnnex/establish.js'
import { ensureRosterDeliveredEpochs } from '../../src/clientAnnex/rosterDeliveredEpochs.js'
import {
  clientAnnexDidParts,
  clientAnnexLogPinId,
  delegatedClientsPointer,
  mintDelegatedClientsDelegation
} from '../../src/clientAnnex/log.js'
import { generateLadderSeed, ladderRung } from '../../src/clientAnnex/ladder.js'
import {
  ladderVmAgent,
  ladderVmZcapClient
} from '../../src/clientAnnex/zcap.js'
import { standingClientFromUnlockSeed } from '../../src/unlock/index.js'
import { WALLET_SPACE_PROVISION_ROSTER } from '../../src/space/index.js'
import { provisionWalletSpace } from '../../src/space/provisioning.js'
import { mintUserKey, userKeyAsRecipient } from '../../src/keys/index.js'
import type { UserKey } from '../../src/keys/index.js'
import { DID_LOG_RESOURCE } from '../../src/space/collections.js'
import type { WebvhIdStore } from '../../src/webvh/didWebvh.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'account-space-establish'

/**
 * The encrypted roster collections -- the ones epoch[0] lands on.
 */
const EDV_ROSTER_IDS = WALLET_SPACE_PROVISION_ROSTER.filter(
  spec => spec.encryption === 'edv'
).map(spec => spec.collectionId)

/**
 * The Space Description / Collection Description fields the fake stores.
 */
interface StoredDescription {
  name?: string
  encryption?: CollectionEncryption
}

/**
 * A multi-Space stateful was-client fake: the credential-anchored genesis
 * suite's collection surfaces (describe / configure / describeWithEtag /
 * replaceDescription) per Space, plus the resource surface the annex log
 * store drives (get / getWithEtag / put with etag preconditions), plus two
 * kill switches for the tear-convergence family. Space `configure` MERGES
 * into the standing description (the server's Space type is immutable, so a
 * controller flip must not erase it).
 *
 * @returns {object}
 */
function multiFakeWas() {
  interface SpaceState {
    description: Record<string, unknown> | null
    collections: Map<
      string,
      { description: StoredDescription; version: number; isPublic: boolean }
    >
    resources: Map<string, { text: string; version: number }>
  }
  const spaces = new Map<string, SpaceState>()
  // Every Space `configure` and the options it carried, so a test can assert
  // which writes handed was-client a `current` instead of asking for a read.
  const spaceConfigures: Array<{
    spaceId: string
    options: Record<string, unknown>
  }> = []
  const kill = {
    /**
     * Fail the next Space `configure` naming a did:webvh controller for
     * this Space id -- the promotion write, uniquely.
     */
    nextPromotionOf: undefined as string | undefined,
    /**
     * Fail the next ANNEX-Space controller flip (a did:webvh-controller
     * `configure` on a Space other than the account's) with this error --
     * a transport error, or a 403-shaped refusal.
     */
    nextAnnexFlip: undefined as Error | undefined,
    /**
     * Hand back no validator from every annex generation-log PUT -- the
     * seam a backend that serves no ETags presents, where a minted head
     * cannot be carried forward into a compare-and-swap.
     */
    dropAnnexLogPutEtag: false,
    /**
     * Refuse the next annex generation-log PUT that carries an `If-Match`
     * -- the lost compare-and-swap on a threaded head.
     */
    nextAnnexLogIfMatch: false
  }
  /**
   * Reads of an annex generation's `did.jsonl` (a `gen-` collection's log),
   * so a test can assert the establishment stands on the head its mint
   * published instead of re-reading it.
   */
  const counts = { annexLogReads: 0 }
  const isAnnexLog = (collectionId: string, resourceId: string) =>
    collectionId.startsWith('gen-') && resourceId === DID_LOG_RESOURCE
  /**
   * Space ids the DEFAULT `was` handle is not authorized on -- the fake's
   * authority model for a Space the bootstrap did:key can no longer write.
   * Reads are MASKED as absence (`null`), the way WAS privacy-merges an
   * unauthorized read into a 404; only writes surface the 403-shaped
   * refusal. `privilegedWas` bypasses it (the standing client whose
   * capability the server accepts).
   */
  const authRefuse = new Set<string>()
  const forbidden = () =>
    Object.assign(new Error('injected: forbidden under this authority'), {
      status: 403
    })
  const spaceOf = (spaceId: string): SpaceState => {
    const existing = spaces.get(spaceId)
    if (existing) {
      return existing
    }
    const fresh: SpaceState = {
      description: null,
      collections: new Map(),
      resources: new Map()
    }
    spaces.set(spaceId, fresh)
    return fresh
  }
  const spaceHandle = (spaceId: string, privileged: boolean) => {
    const state = spaceOf(spaceId)
    const masked = () => !privileged && authRefuse.has(spaceId)
    const refuseWrite = () => {
      if (masked()) {
        throw forbidden()
      }
    }
    return {
      describe: async () => {
        if (masked()) {
          return null
        }
        return state.description ? { ...state.description } : null
      },
      configure: async (options: Record<string, unknown>) => {
        refuseWrite()
        spaceConfigures.push({ spaceId, options })
        if (
          kill.nextPromotionOf === spaceId &&
          typeof options.controller === 'string' &&
          options.controller.startsWith('did:webvh:')
        ) {
          kill.nextPromotionOf = undefined
          throw new Error('injected: the promotion write failed')
        }
        if (
          kill.nextAnnexFlip !== undefined &&
          spaceId !== SPACE_ID &&
          typeof options.controller === 'string' &&
          options.controller.startsWith('did:webvh:')
        ) {
          const error = kill.nextAnnexFlip
          kill.nextAnnexFlip = undefined
          throw error
        }
        // `current` is was-client's pre-merge input, never a stored field,
        // and the real client returns the merged Description it wrote.
        const { current: _current, ...fields } = options
        state.description = {
          id: spaceId,
          ...(state.description ?? {}),
          ...fields
        }
        return { ...state.description }
      },
      collection: (collectionId: string) => {
        const rowOf = () => state.collections.get(collectionId)
        return {
          describe: async () => {
            const entry = rowOf()
            return entry ? structuredClone(entry.description) : null
          },
          configure: async (options: {
            name?: string
            encryption?: CollectionEncryption
          }) => {
            const entry = rowOf()
            const description: StoredDescription = {
              name: options.name,
              ...(options.encryption ? { encryption: options.encryption } : {})
            }
            if (entry) {
              entry.description = description
              entry.version++
            } else {
              state.collections.set(collectionId, {
                description,
                version: 0,
                isPublic: false
              })
            }
          },
          isPublic: async () => rowOf()?.isPublic ?? false,
          setPublic: async () => {
            const entry = rowOf()
            if (entry) {
              entry.isPublic = true
            }
          },
          describeWithEtag: async () => {
            const entry = rowOf()
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
            const entry = rowOf()!
            if (ifMatch !== `v${entry.version}`) {
              throw new PreconditionFailedError('stale description etag')
            }
            entry.description = structuredClone(description)
            entry.version++
          },
          resource: (resourceId: string) => {
            const key = `${collectionId}/${resourceId}`
            return {
              get: async () => {
                if (isAnnexLog(collectionId, resourceId)) {
                  counts.annexLogReads += 1
                }
                const row = masked() ? undefined : state.resources.get(key)
                if (row === undefined) {
                  return null
                }
                try {
                  return JSON.parse(row.text)
                } catch {
                  return row.text
                }
              },
              getWithEtag: async () => {
                if (isAnnexLog(collectionId, resourceId)) {
                  counts.annexLogReads += 1
                }
                const row = masked() ? undefined : state.resources.get(key)
                return row === undefined
                  ? null
                  : { data: row.text, etag: `"${row.version}"` }
              },
              put: async (
                bytes: Uint8Array,
                {
                  ifMatch,
                  ifNoneMatch
                }: { ifMatch?: string; ifNoneMatch?: string } = {}
              ) => {
                refuseWrite()
                const row = state.resources.get(key)
                if (ifNoneMatch === '*' && row !== undefined) {
                  throw new PreconditionFailedError(
                    `${key} already exists (If-None-Match: *).`
                  )
                }
                if (
                  kill.nextAnnexLogIfMatch &&
                  ifMatch !== undefined &&
                  isAnnexLog(collectionId, resourceId)
                ) {
                  kill.nextAnnexLogIfMatch = false
                  throw new PreconditionFailedError(
                    `${key} has moved on (injected stale If-Match).`
                  )
                }
                if (
                  ifMatch !== undefined &&
                  ifMatch !== `"${row?.version ?? 'absent'}"`
                ) {
                  throw new PreconditionFailedError(
                    `${key} has moved on (stale If-Match).`
                  )
                }
                if (!state.collections.has(collectionId)) {
                  state.collections.set(collectionId, {
                    description: { name: collectionId },
                    version: 0,
                    isPublic: false
                  })
                }
                const version = (row?.version ?? 0) + 1
                state.resources.set(key, {
                  text: new TextDecoder().decode(bytes),
                  version
                })
                // The real client hands back the stored resource's new
                // validator, which is what lets a ceremony build its next
                // entry on the head it just wrote.
                if (
                  kill.dropAnnexLogPutEtag &&
                  isAnnexLog(collectionId, resourceId)
                ) {
                  return undefined
                }
                return { etag: `"${version}"` }
              }
            }
          }
        }
      }
    }
  }
  const was = {
    space: (spaceId: string) => spaceHandle(spaceId, false)
  } as unknown as WasClient
  const privilegedWas = {
    space: (spaceId: string) => spaceHandle(spaceId, true)
  } as unknown as WasClient
  return {
    was,
    privilegedWas,
    authRefuse,
    kill,
    counts,
    spaces,
    spaceConfigures,
    controllerOf: (spaceId: string) =>
      spaces.get(spaceId)?.description?.controller as string | undefined,
    descriptorOf: (spaceId: string, collectionId: string) =>
      spaces.get(spaceId)!.collections.get(collectionId)!.description
        .encryption!,
    /**
     * Drops a collection's epoch roster, keeping the scheme marker -- the
     * state an earlier run's epoch fan-out never reached.
     */
    stripEpochs: (spaceId: string, collectionId: string) => {
      const entry = spaces.get(spaceId)!.collections.get(collectionId)!
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
    },
    /**
     * The Space ids beyond the account's -- the annex Spaces the runs
     * minted, orphans included.
     */
    annexSpaceIds: () =>
      [...spaces.keys()].filter(spaceId => spaceId !== SPACE_ID)
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
 * A derived standing credential: a random ladder seed plus the standing
 * client identity from a random unlock seed, in the orchestrator's
 * `standing` shape.
 */
async function establishCredential() {
  const ladderSeed = generateLadderSeed()
  const client = await standingClientFromUnlockSeed({
    unlockSeed: crypto.getRandomValues(new Uint8Array(32))
  })
  return {
    ladderSeed,
    client,
    standing: {
      clientDid: client.clientDid,
      keyAgreementKeyMultibase: client.keyAgreementKeyMultibase,
      recipientKid: client.recipientKid,
      keyAgreementKey: client.agents.keyAgreementKey
    }
  }
}

/**
 * A recording `bindRecord` hook: monotone stamps, a fixed unlock Space id,
 * and an optional one-shot failure on the re-bind call.
 */
function recordingBindRecord({
  failRebindOnce = false
}: { failRebindOnce?: boolean } = {}) {
  const calls: Array<{
    controller: string
    pointer: { spaceId: string; host: string; did?: string }
    delegation: IZcap
    delegatedClients?: IZcap
    delegateManagementTo?: string
    priorCreatedAt?: string
  }> = []
  let stamps = 0
  let pendingFailure = failRebindOnce
  const hook = async (options: (typeof calls)[number]) => {
    if (options.delegateManagementTo !== undefined && pendingFailure) {
      pendingFailure = false
      throw new Error('injected: the re-bind write failed')
    }
    calls.push(options)
    stamps++
    return {
      createdAt: `2026-08-26T00:00:00.00${stamps}Z`,
      unlockSpaceId: 'unlock-space-establish'
    }
  }
  return { hook, calls }
}

/**
 * The establishment world: the multi-Space fake, an in-memory account log,
 * a roster store, a pin store, a derived credential, and a `run` closure
 * over the shared members.
 */
async function establishWorld({
  rosterStore = memoryDescriptorStore(),
  bind = recordingBindRecord()
}: {
  rosterStore?: ReturnType<typeof memoryDescriptorStore>
  bind?: ReturnType<typeof recordingBindRecord>
} = {}) {
  const server = multiFakeWas()
  const account = memoryIdStore()
  const pinStore = memoryResourceLogPinStore()
  const credential = await establishCredential()
  const hookRuns: string[] = []
  const run = (
    overrides: Partial<
      Parameters<typeof establishCredentialAnchoredAccount>[0]
    > = {}
  ) =>
    establishCredentialAnchoredAccount({
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      ladderSeed: credential.ladderSeed,
      standing: credential.standing,
      lowEntropy: true,
      bindRecord: bind.hook,
      rosterStoreFor: () => rosterStore,
      bootstrapWasFor: () => server.was,
      idStore: account.idStore,
      pinStore,
      ...overrides
    })
  return {
    server,
    account,
    pinStore,
    credential,
    rosterStore,
    bind,
    hookRuns,
    run
  }
}

/**
 * The number of entries in the published did:webvh log.
 */
function logLength(log: string | undefined): number {
  return readLogFromString(log!).length
}

/**
 * The published account document (the last entry's state).
 */
function publishedDoc(logText: string) {
  const log = readLogFromString(logText)
  return log[log.length - 1]!.state as {
    verificationMethod?: Array<{
      id?: string
      type?: string
      publicKeyMultibase?: string
    }>
    service?: Array<{ id?: string; type?: string; serviceEndpoint?: string }>
  }
}

describe('establishCredentialAnchoredAccount (fresh)', () => {
  it('runs the six stages in order and lands a promoted, pointed, standing account', async () => {
    const world = await establishWorld()
    const controllersAtHook: Array<string | undefined> = []
    let hookContext:
      | {
          did: string
          userKey: UserKey
          establishment: CredentialAnchoredEstablishment
        }
      | undefined

    const result = await world.run({
      beforePromotion: async ({ did, userKey, establishment }) => {
        controllersAtHook.push(world.server.controllerOf(SPACE_ID))
        hookContext = { did, userKey, establishment }
      }
    })

    // The published account: two entries (genesis + the pointer entry), the
    // document pointing at the annex generation.
    expect(result.did.startsWith('did:webvh:')).toBe(true)
    expect(logLength(world.account.log())).toBe(2)
    const doc = publishedDoc(world.account.log()!)
    const pointed = delegatedClientsPointer({ doc: doc as never })
    expect(pointed).toBeDefined()

    // The annex Space exists, controller-flipped to the account DID.
    const annexSpaceId = clientAnnexDidParts({ did: pointed! }).spaceId
    expect(world.server.annexSpaceIds()).toEqual([annexSpaceId])
    expect(world.server.controllerOf(annexSpaceId)).toBe(result.did)

    // The bind hook ran twice: the DID-less first bind, then the re-bind
    // with the full pointer, both delegations, and the management target,
    // its stamp advancing past the first bind's.
    expect(world.bind.calls).toHaveLength(2)
    const [first, rebind] = world.bind.calls
    expect(first!.pointer).toEqual({ spaceId: SPACE_ID, host: WAS_URL })
    expect(first!.delegatedClients).toBeUndefined()
    expect(first!.delegateManagementTo).toBeUndefined()
    expect(rebind!.pointer).toEqual({
      spaceId: SPACE_ID,
      host: WAS_URL,
      did: result.did
    })
    expect(rebind!.delegatedClients).toBeDefined()
    expect(rebind!.delegateManagementTo).toBe(result.did)
    expect(rebind!.priorCreatedAt).toBe('2026-08-26T00:00:00.001Z')
    expect(result.unlockSpaceId).toBe('unlock-space-establish')

    // The pre-promotion hook saw the bootstrap controller (the last root
    // window) and the established members; the promotion then landed.
    const bootstrap = await ladderVmAgent({
      ladderSeed: world.credential.ladderSeed
    })
    expect(controllersAtHook).toEqual([bootstrap.id])
    expect(hookContext!.did).toBe(result.did)
    expect(hookContext!.establishment).toBe(result)
    expect(world.server.controllerOf(SPACE_ID)).toBe(result.did)

    // The roster's one epoch is the delivered user key, and every encrypted
    // collection carries epoch[0] under it.
    const roster = world.rosterStore._getDescriptor()!
    expect(roster.currentEpoch).toBe(hookContext!.userKey.id)
    for (const collectionId of EDV_ROSTER_IDS) {
      const descriptor = world.server.descriptorOf(SPACE_ID, collectionId)
      expect(descriptor.epochs).toHaveLength(1)
      expect(
        descriptor.epochs![0]!.recipients.map(entry => entry.header.kid)
      ).toEqual([userKeyAsRecipient({ userKey: hookContext!.userKey }).id])
    }

    // The standing fields the registry entry records: bind-time rung 0 and
    // the two delegations' members.
    const rung0 = await ladderRung({
      ladderSeed: world.credential.ladderSeed,
      index: 0
    })
    expect(result.standingFields.updateKeyMultibase).toBe(rung0.keyMultibase)
    expect(result.standingFields.rosterKid).toBe(
      world.credential.standing.recipientKid
    )
    expect(result.standingFields.unlockClientDid).toBe(
      world.credential.standing.clientDid
    )
    expect(result.standingFields.delegationKeyId).toBeDefined()
    expect(result.standingFields.delegationExpires).toBeDefined()
    expect(result.standingFields.delegatedClientsKeyId).toBeDefined()
    expect(result.standingFields.delegatedClientsExpires).toBeDefined()
    expect(result.failed).toEqual([])
  })

  it('reports each stage boundary to onStage, in order, as it finishes', async () => {
    const world = await establishWorld()
    const stages: string[] = []

    await world.run({ onStage: stage => stages.push(stage) })

    // The stages a fresh establishment runs, in order -- asserted against
    // the exported tuple itself, since that tuple is what a consumer's
    // progress display derives its step list from: a rename that reaches
    // one and not the other fails here. `kms-authentication` fires whether
    // or not a thunk was supplied, since it marks the ceremony's own join;
    // `beforePromotion` is unsupplied and does not appear, that boundary
    // being the caller's own closure to mark.
    expect(stages).toEqual([...CREDENTIAL_ANCHORED_ESTABLISHMENT_STAGES])
    expect(CREDENTIAL_ANCHORED_ESTABLISHMENT_STAGES).toEqual([
      'interim-bind',
      'space-provisioning',
      'kms-authentication',
      'webvh-genesis',
      'roster-genesis',
      'collection-epochs',
      'account-log-read',
      'annex-generation',
      'record-rebind',
      'controller-promotion'
    ])
  })

  it('runs to completion when the caller notifier throws (telemetry is never fatal)', async () => {
    const world = await establishWorld()

    const result = await world.run({
      onStage: () => {
        throw new Error('the caller notifier blew up')
      }
    })

    expect(result.did.startsWith('did:webvh:')).toBe(true)
    expect(world.server.controllerOf(SPACE_ID)).toBe(result.did)
  })

  it('publishes the keyAgreement commitment unless lowEntropy is explicitly false (the fail-safe)', async () => {
    // `lowEntropy` is required at the type level; the fail-safe is the
    // RUNTIME rule -- any value that is not exactly `false` (a JS caller's
    // dropped or junk value included) publishes the commitment.
    const ambiguous = [
      true,
      undefined as unknown as boolean,
      'yes' as unknown as boolean
    ]
    for (const lowEntropy of ambiguous) {
      const world = await establishWorld()
      await world.run({ lowEntropy })
      const doc = publishedDoc(world.account.log()!)
      // The commitment publishes; the verbatim KDF-derived key never does.
      expect(
        doc.verificationMethod!.some(
          method => method.type === 'MultikeyCommitment'
        )
      ).toBe(true)
      expect(
        doc.verificationMethod!.some(
          method =>
            method.publicKeyMultibase ===
            world.credential.standing.keyAgreementKeyMultibase
        )
      ).toBe(false)
    }

    const world = await establishWorld()
    await world.run({ lowEntropy: false })
    const doc = publishedDoc(world.account.log()!)
    expect(
      doc.verificationMethod!.some(
        method =>
          method.publicKeyMultibase ===
          world.credential.standing.keyAgreementKeyMultibase
      )
    ).toBe(true)
  })

  it('refuses a missing required hook synchronously, before any write', async () => {
    const world = await establishWorld()
    for (const missing of [
      'bindRecord',
      'rosterStoreFor',
      'bootstrapWasFor'
    ] as const) {
      expect(() => world.run({ [missing]: undefined } as never)).toThrowError(
        TypeError
      )
    }
    expect(world.bind.calls).toHaveLength(0)
    expect(world.account.log()).toBeUndefined()
    expect(world.server.spaces.size).toBe(0)
  })

  it('skips the first bind when the caller passed priorCreatedAt from a standing hit', async () => {
    const world = await establishWorld()

    const result = await world.run({ priorCreatedAt: '2026-08-25T12:00:00Z' })

    // One bind only -- the re-bind -- threading the standing stamp; a
    // DID-less re-write of a record that already carries the ladder seed
    // could downgrade a sibling browser's completed re-bind.
    expect(world.bind.calls).toHaveLength(1)
    expect(world.bind.calls[0]!.delegateManagementTo).toBe(result.did)
    expect(world.bind.calls[0]!.priorCreatedAt).toBe('2026-08-25T12:00:00Z')
  })

  it('runs the best-effort keystore promotion after the Space promotion and collects its failure', async () => {
    const world = await establishWorld()
    const promoted: Array<{ did: string; controller?: string }> = []

    const result = await world.run({
      promoteKeystore: async ({ did }) => {
        promoted.push({ did, controller: world.server.controllerOf(SPACE_ID) })
      }
    })
    expect(promoted).toEqual([{ did: result.did, controller: result.did }])

    const failing = await establishWorld()
    const failingResult = await failing.run({
      promoteKeystore: async () => {
        throw new Error('injected: the KMS is unreachable')
      }
    })
    expect(failingResult.failed).toHaveLength(1)
    expect(failingResult.failed[0]!.stage).toBe('keystorePromotion')
    expect(failing.server.controllerOf(SPACE_ID)).toBe(failingResult.did)
  })
})

describe('establishCredentialAnchoredAccount (tear convergence)', () => {
  it('stage 1: a run torn right after the first bind converges from the record alone', async () => {
    // The stage-1 tear state: the standing record exists (the caller holds
    // its stamp), nothing else does. The re-run is the whole establishment.
    const world = await establishWorld()
    let hookRuns = 0

    const healed = await world.run({
      priorCreatedAt: '2026-08-25T12:00:00Z',
      beforePromotion: async () => {
        hookRuns++
      }
    })

    expect(logLength(world.account.log())).toBe(2)
    expect(hookRuns).toBe(1)
    expect(world.server.controllerOf(SPACE_ID)).toBe(healed.did)
    expect(world.server.annexSpaceIds()).toHaveLength(1)
    expect(world.bind.calls).toHaveLength(1)

    // The annex Space's two Description writes each state their own
    // `current`, so was-client re-describes for neither: the ensure's create
    // knows the Space is absent, and the flip that follows carries what the
    // create wrote.
    const [annexSpaceId] = world.server.annexSpaceIds()
    const annexConfigures = world.server.spaceConfigures.filter(
      call => call.spaceId === annexSpaceId
    )
    expect(annexConfigures).toHaveLength(2)
    expect(annexConfigures[0]!.options.current).toBeNull()
    expect(annexConfigures[1]!.options).toMatchObject({
      current: { id: annexSpaceId },
      controller: healed.did
    })
  })

  it('stage 2: a failed roster stage is fatal pre-re-bind, and the re-run converges on the same SCID', async () => {
    const rosterStore = memoryDescriptorStore({ failFirstWrite: true })
    const world = await establishWorld({ rosterStore })
    let hookRuns = 0

    await expect(
      world.run({
        beforePromotion: async () => {
          hookRuns++
        }
      })
    ).rejects.toThrow(/roster stage failed/)

    // The tear is the heal-able kind: one genesis entry, the record still
    // DID-less (one bind, no re-bind), no promotion, no registry hook.
    expect(logLength(world.account.log())).toBe(1)
    expect(world.bind.calls).toHaveLength(1)
    expect(hookRuns).toBe(0)
    const bootstrap = await ladderVmAgent({
      ladderSeed: world.credential.ladderSeed
    })
    expect(world.server.controllerOf(SPACE_ID)).toBe(bootstrap.id)
    const genesisEntry = world.account.log()!

    const healed = await world.run({
      beforePromotion: async () => {
        hookRuns++
      }
    })

    // Convergence: the published SCID is adopted (the genesis entry is
    // byte-identical), the pointer entry lands once, the hook fires, the
    // promotion lands.
    expect(world.account.log()!.startsWith(genesisEntry)).toBe(true)
    expect(logLength(world.account.log())).toBe(2)
    expect(hookRuns).toBe(1)
    expect(world.server.controllerOf(SPACE_ID)).toBe(healed.did)
    expect(world.rosterStore._getDescriptor()).not.toBeNull()
  })

  it("stage 2c: a re-run over an earlier run's roster installs epochs under the DELIVERED key, never the candidate", async () => {
    const world = await establishWorld()
    const earlier = await mintUserKey()
    // The earlier run's roster: keyed to its user key, wrapped to this same
    // credential's standing key-agreement key.
    await initRecipients({
      store: world.rosterStore,
      recipients: [
        {
          id: world.credential.standing.recipientKid,
          publicKeyMultibase: world.credential.standing.keyAgreementKeyMultibase
        }
      ],
      epoch: { epochId: earlier.id, secret: earlier.secret }
    })
    let deliveredToHook: UserKey | undefined

    const result = await world.run({
      beforePromotion: async ({ userKey }) => {
        deliveredToHook = userKey
      }
    })

    expect(result.epochsSkipped).toEqual({ rosterEpochId: earlier.id })
    expect(deliveredToHook!.id).toBe(earlier.id)
    for (const collectionId of EDV_ROSTER_IDS) {
      const descriptor = world.server.descriptorOf(SPACE_ID, collectionId)
      expect(descriptor.currentEpoch).toBe(descriptor.epochs![0]!.id)
      expect(
        descriptor.epochs![0]!.recipients.map(entry => entry.header.kid)
      ).toEqual([userKeyAsRecipient({ userKey: earlier }).id])
    }
  })

  it('stage 3: a run torn at the pointer entry re-runs to a pointed account, minting another Space (the recorded residue)', async () => {
    const world = await establishWorld()
    // Fail the SECOND log put -- the pointer entry (the genesis is the
    // first).
    let logPuts = 0
    const baseIdStore = world.account.idStore
    const tearingIdStore = {
      ...baseIdStore,
      async putIdResource(
        options: Parameters<(typeof baseIdStore)['putIdResource']>[0]
      ) {
        if (options.resourceId === DID_LOG_RESOURCE && ++logPuts === 2) {
          throw new Error('injected: the pointer entry write failed')
        }
        return baseIdStore.putIdResource(options)
      }
    }

    await expect(world.run({ idStore: tearingIdStore })).rejects.toThrow(
      /pointer entry write failed/
    )

    // The stranded state: one genesis entry, one live annex Space nothing
    // durable names (the stated orphan residue), no re-bind, no promotion.
    expect(logLength(world.account.log())).toBe(1)
    const [strandedSpaceId] = world.server.annexSpaceIds()
    expect(strandedSpaceId).toBeDefined()
    expect(world.bind.calls).toHaveLength(1)

    // The record-only re-run mints ANOTHER Space -- within this ceremony no
    // record names the stranded one (the sibling is only written by stage 4,
    // after the pointer entry), so the orphan is the recorded residue.
    const blind = await world.run({
      priorCreatedAt: '2026-08-26T00:00:00.001Z'
    })
    expect(world.server.annexSpaceIds()).toHaveLength(2)
    const blindPointer = delegatedClientsPointer({
      doc: publishedDoc(world.account.log()!) as never
    })
    expect(clientAnnexDidParts({ did: blindPointer! }).spaceId).not.toBe(
      strandedSpaceId
    )
    expect(world.server.controllerOf(SPACE_ID)).toBe(blind.did)
  })

  it('stage 3: a sibling-named Space the bootstrap key can no longer write falls back to a fresh mint instead of failing', async () => {
    const world = await establishWorld()
    let logPuts = 0
    const baseIdStore = world.account.idStore
    const tearingIdStore = {
      ...baseIdStore,
      async putIdResource(
        options: Parameters<(typeof baseIdStore)['putIdResource']>[0]
      ) {
        if (options.resourceId === DID_LOG_RESOURCE && ++logPuts === 2) {
          throw new Error('injected: the pointer entry write failed')
        }
        return baseIdStore.putIdResource(options)
      }
    }
    await expect(world.run({ idStore: tearingIdStore })).rejects.toThrow(
      /pointer entry write failed/
    )
    const [strandedSpaceId] = world.server.annexSpaceIds()
    // The tear ran the controller flip, so the stranded Space no longer
    // answers to the bootstrap did:key -- model that refusal.
    world.server.authRefuse.add(strandedSpaceId!)
    const accountDid = (
      readLogFromString(world.account.log()!)[0]!.state as { id: string }
    ).id
    const ladderClient = await ladderVmZcapClient({
      accountDid,
      ladderSeed: world.credential.ladderSeed
    })
    const sibling = await mintDelegatedClientsDelegation({
      zcapClient: ladderClient,
      wasServerUrl: WAS_URL,
      clientAnnexSpaceId: strandedSpaceId!,
      controller: world.credential.standing.clientDid
    })

    const healed = await world.run({ delegatedClients: sibling })

    // The authorization refusal fell back to the fresh-mint arm: a second
    // Space, the pointer naming it, the run completed.
    expect(world.server.annexSpaceIds()).toHaveLength(2)
    const pointed = delegatedClientsPointer({
      doc: publishedDoc(world.account.log()!) as never
    })
    expect(clientAnnexDidParts({ did: pointed! }).spaceId).not.toBe(
      strandedSpaceId
    )
    expect(world.server.controllerOf(SPACE_ID)).toBe(healed.did)
  })

  it('stage 3: a transport-failed controller flip aborts BEFORE the pointer entry', async () => {
    const world = await establishWorld()
    world.server.kill.nextAnnexFlip = new Error(
      'injected: the flip transport failed'
    )

    await expect(world.run()).rejects.toThrow(/flip transport failed/)

    // No pointer entry published: a document pointing at a generation whose
    // Space still answers to the bare ladder did:key would be unreachable
    // forever, so the tear stays the convergeable kind.
    expect(logLength(world.account.log())).toBe(1)
    expect(
      delegatedClientsPointer({
        doc: publishedDoc(world.account.log()!) as never
      })
    ).toBeUndefined()

    const healed = await world.run({
      priorCreatedAt: '2026-08-26T00:00:00.001Z'
    })
    expect(world.server.controllerOf(SPACE_ID)).toBe(healed.did)
    expect(logLength(world.account.log())).toBe(2)
  })

  it('stage 3: an authorization-refused flip (a concurrent run flipped first) still converges', async () => {
    const world = await establishWorld()
    world.server.kill.nextAnnexFlip = Object.assign(
      new Error('injected: already flipped by a concurrent run'),
      { status: 403 }
    )

    const result = await world.run()

    expect(logLength(world.account.log())).toBe(2)
    expect(
      delegatedClientsPointer({
        doc: publishedDoc(world.account.log()!) as never
      })
    ).toBeDefined()
    expect(world.server.controllerOf(SPACE_ID)).toBe(result.did)
  })

  it("fails BEFORE the re-bind on an account this credential's ladder does not attribute", async () => {
    // The no-rung-of-this-ladder class (a struck ladder VM is its other
    // face): the establishment must refuse while the record is still in its
    // pre-re-bind shape, never after a re-bind that would leave a rebound
    // record with no registry entry and no mender.
    const world = await establishWorld()
    await world.run()

    const loser = await establishCredential()
    const loserBind = recordingBindRecord()
    await expect(
      establishCredentialAnchoredAccount({
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        ladderSeed: loser.ladderSeed,
        standing: loser.standing,
        lowEntropy: true,
        bindRecord: loserBind.hook,
        rosterStoreFor: () => memoryDescriptorStore(),
        bootstrapWasFor: () => world.server.was,
        idStore: world.account.idStore
      })
    ).rejects.toMatchObject({ name: 'LadderAttributionError' })

    // The first bind may have run; the RE-BIND never did.
    expect(
      loserBind.calls.filter(call => call.delegateManagementTo !== undefined)
    ).toHaveLength(0)
  })

  it('stage 4: a re-bind tear re-runs without a duplicate generation or log entry', async () => {
    const bind = recordingBindRecord({ failRebindOnce: true })
    const world = await establishWorld({ bind })

    await expect(world.run()).rejects.toThrow(/re-bind write failed/)
    expect(logLength(world.account.log())).toBe(2)
    expect(world.server.annexSpaceIds()).toHaveLength(1)

    const healed = await world.run({
      priorCreatedAt: '2026-08-26T00:00:00.001Z'
    })

    // The pointer gate held: no second generation, no third entry; the
    // re-bind and the promotion landed.
    expect(logLength(world.account.log())).toBe(2)
    expect(world.server.annexSpaceIds()).toHaveLength(1)
    expect(
      world.bind.calls.filter(call => call.delegateManagementTo !== undefined)
    ).toHaveLength(1)
    expect(world.server.controllerOf(SPACE_ID)).toBe(healed.did)
  })

  it('stage 5: a throwing beforePromotion fails the establishment pre-promotion, and the re-run re-fires it', async () => {
    const world = await establishWorld()
    let hookRuns = 0

    await expect(
      world.run({
        beforePromotion: async () => {
          hookRuns++
          throw new Error('injected: the registry write failed')
        }
      })
    ).rejects.toThrow(/registry write failed/)
    const bootstrap = await ladderVmAgent({
      ladderSeed: world.credential.ladderSeed
    })
    expect(world.server.controllerOf(SPACE_ID)).toBe(bootstrap.id)

    const healed = await world.run({
      priorCreatedAt: '2026-08-26T00:00:00.002Z',
      beforePromotion: async () => {
        hookRuns++
      }
    })
    expect(hookRuns).toBe(2)
    expect(world.server.controllerOf(SPACE_ID)).toBe(healed.did)
    expect(logLength(world.account.log())).toBe(2)
  })

  it('stage 6: a failed promotion re-runs to a promoted account with no duplicate entries', async () => {
    const world = await establishWorld()
    world.server.kill.nextPromotionOf = SPACE_ID
    let hookRuns = 0

    await expect(
      world.run({
        beforePromotion: async () => {
          hookRuns++
        }
      })
    ).rejects.toThrow(/promotion write failed/)
    expect(hookRuns).toBe(1)

    const healed = await world.run({
      priorCreatedAt: '2026-08-26T00:00:00.002Z',
      beforePromotion: async () => {
        hookRuns++
      }
    })
    expect(hookRuns).toBe(2)
    expect(world.server.controllerOf(SPACE_ID)).toBe(healed.did)
    expect(logLength(world.account.log())).toBe(2)
    expect(world.server.annexSpaceIds()).toHaveLength(1)
  })
})

describe("ensureRosterDeliveredEpochs (the mint policy's one home)", () => {
  /**
   * A provisioned account Space (collections with scheme markers, no
   * epochs) and the shared parameters.
   */
  async function rosterWorld() {
    const server = multiFakeWas()
    const credential = await establishCredential()
    await provisionWalletSpace({
      was: server.was,
      spaceId: SPACE_ID,
      controllerDid: credential.standing.clientDid
    })
    return { server, credential }
  }

  it('mints the candidate as epoch[0] when the roster is absent and installs the epochs under it', async () => {
    const { server, credential } = await rosterWorld()
    const store = memoryDescriptorStore()
    const candidate = await mintUserKey()

    const result = await ensureRosterDeliveredEpochs({
      store,
      candidateUserKey: candidate,
      clientKeyAgreementKey: credential.standing.keyAgreementKey,
      was: server.was,
      spaceId: SPACE_ID
    })

    expect(result.outcome).toBe('delivered')
    if (result.outcome !== 'delivered') {
      throw new Error('unreachable')
    }
    expect(result.minted).toBe(true)
    expect(result.userKey.id).toBe(candidate.id)
    expect(result.epochs.failed).toEqual([])
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(
        server
          .descriptorOf(SPACE_ID, collectionId)
          .epochs![0]!.recipients.map(entry => entry.header.kid)
      ).toEqual([userKeyAsRecipient({ userKey: candidate }).id])
    }
  })

  it('installs the epochs under the key the roster DELIVERS, not the minted candidate', async () => {
    const { server, credential } = await rosterWorld()
    const store = memoryDescriptorStore()
    const delivered = await mintUserKey()
    await initRecipients({
      store,
      recipients: [
        {
          id: credential.standing.recipientKid,
          publicKeyMultibase: credential.standing.keyAgreementKeyMultibase
        }
      ],
      epoch: { epochId: delivered.id, secret: delivered.secret }
    })
    const candidate = await mintUserKey()

    const result = await ensureRosterDeliveredEpochs({
      store,
      candidateUserKey: candidate,
      clientKeyAgreementKey: credential.standing.keyAgreementKey,
      was: server.was,
      spaceId: SPACE_ID
    })

    expect(result.outcome).toBe('delivered')
    if (result.outcome !== 'delivered') {
      throw new Error('unreachable')
    }
    expect(result.minted).toBe(false)
    expect(result.userKey.id).toBe(delivered.id)
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(
        server
          .descriptorOf(SPACE_ID, collectionId)
          .epochs![0]!.recipients.map(entry => entry.header.kid)
      ).toEqual([userKeyAsRecipient({ userKey: delivered }).id])
    }
  })

  it('adopts the winner of a lost create race and reports converged-elsewhere', async () => {
    const { server, credential } = await rosterWorld()
    const winnerKey = await mintUserKey()
    const winnerStore = memoryDescriptorStore()
    await initRecipients({
      store: winnerStore,
      recipients: [
        {
          id: credential.standing.recipientKid,
          publicKeyMultibase: credential.standing.keyAgreementKeyMultibase
        }
      ],
      epoch: { epochId: winnerKey.id, secret: winnerKey.secret }
    })
    // The racing store: absent until this run's guarded create loses, the
    // winner's roster visible from then on. The refusal is the log-governed
    // store's append CAS (`WebvhLogConflictError`), the one that escapes the
    // init machinery untyped.
    let winnerVisible = false
    const store: EncryptionDescriptorStore = {
      async read() {
        return winnerVisible ? winnerStore.read() : null
      },
      async replace() {
        throw new Error('unreachable: the loser never replaces')
      },
      async create() {
        winnerVisible = true
        throw new WebvhLogConflictError(
          'the roster genesis append lost the log CAS'
        )
      }
    }

    const result = await ensureRosterDeliveredEpochs({
      store,
      candidateUserKey: await mintUserKey(),
      clientKeyAgreementKey: credential.standing.keyAgreementKey,
      was: server.was,
      spaceId: SPACE_ID
    })

    expect(result.outcome).toBe('converged-elsewhere')
    if (result.outcome === 'no-wrap') {
      throw new Error('unreachable')
    }
    expect(result.minted).toBe(false)
    expect(result.userKey.id).toBe(winnerKey.id)
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(
        server
          .descriptorOf(SPACE_ID, collectionId)
          .epochs![0]!.recipients.map(entry => entry.header.kid)
      ).toEqual([userKeyAsRecipient({ userKey: winnerKey }).id])
    }
  })

  it('surfaces a roster with no wrap for this credential as its own outcome, installing nothing', async () => {
    const { server, credential } = await rosterWorld()
    const other = await establishCredential()
    const store = memoryDescriptorStore()
    const foreignKey = await mintUserKey()
    await initRecipients({
      store,
      recipients: [
        {
          id: other.standing.recipientKid,
          publicKeyMultibase: other.standing.keyAgreementKeyMultibase
        }
      ],
      epoch: { epochId: foreignKey.id, secret: foreignKey.secret }
    })

    const result = await ensureRosterDeliveredEpochs({
      store,
      candidateUserKey: await mintUserKey(),
      clientKeyAgreementKey: credential.standing.keyAgreementKey,
      was: server.was,
      spaceId: SPACE_ID
    })

    expect(result.outcome).toBe('no-wrap')
    if (result.outcome !== 'no-wrap') {
      throw new Error('unreachable')
    }
    expect((result.error as { name?: string }).name).toBe(
      'UserKeyRosterUnwrapError'
    )
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(server.descriptorOf(SPACE_ID, collectionId).epochs).toBeUndefined()
    }
  })

  it('re-enters on an epoch-less encrypted collection behind a present roster (the completion test)', async () => {
    const { server, credential } = await rosterWorld()
    const store = memoryDescriptorStore()
    const delivered = await mintUserKey()
    await initRecipients({
      store,
      recipients: [
        {
          id: credential.standing.recipientKid,
          publicKeyMultibase: credential.standing.keyAgreementKeyMultibase
        }
      ],
      epoch: { epochId: delivered.id, secret: delivered.secret }
    })
    const run = () =>
      ensureRosterDeliveredEpochs({
        store,
        candidateUserKey: delivered,
        clientKeyAgreementKey: credential.standing.keyAgreementKey,
        was: server.was,
        spaceId: SPACE_ID
      })
    await run()
    const stranded = EDV_ROSTER_IDS[0]!
    server.stripEpochs(SPACE_ID, stranded)
    expect(server.descriptorOf(SPACE_ID, stranded).epochs).toBeUndefined()

    const result = await run()

    expect(result.outcome).toBe('delivered')
    if (result.outcome !== 'delivered') {
      throw new Error('unreachable')
    }
    expect(result.epochs.outcomes[stranded]!.installed).toBe(true)
    expect(server.descriptorOf(SPACE_ID, stranded).epochs).toHaveLength(1)
  })
})

describe('ensurePointedClientAnnexGeneration (the stage-3 primitive)', () => {
  it('is gated on the pointer: a pointed document is returned as-is with nothing written', async () => {
    const world = await establishWorld()
    const result = await world.run()
    const view = readLogFromString(world.account.log()!)
    const doc = view[view.length - 1]!.state
    const spacesBefore = world.server.spaces.size
    const entriesBefore = logLength(world.account.log())

    const reused = await ensurePointedClientAnnexGeneration({
      account: {
        did: result.did,
        doc: doc as never,
        log: view as never
      },
      wasServerUrl: WAS_URL,
      accountSpaceId: SPACE_ID,
      ladderSeed: world.credential.ladderSeed,
      was: world.server.was,
      mintController: 'did:key:z6MkNeverUsed',
      mintGenerationDelegation: async () => {
        throw new Error('unreachable: the pointed arm mints nothing')
      },
      idStore: world.account.idStore
    })

    expect(reused.generationMinted).toBe(false)
    expect(reused.spaceMinted).toBe(false)
    expect(reused.clientAnnexDid.startsWith('did:webvh:')).toBe(true)
    expect(world.server.spaces.size).toBe(spacesBefore)
    expect(logLength(world.account.log())).toBe(entriesBefore)
  })

  it('converges onto the sibling-named Space under a standing invocation authority', async () => {
    // The stranded state a stage-3 tear leaves: the Space created and
    // flipped, the pointer entry never published -- and the bootstrap
    // did:key refused by the flipped Space. A caller holding a standing
    // invocation authority (the add/change-method fold's shape) converges
    // onto that Space instead of minting another.
    const world = await establishWorld()
    let logPuts = 0
    const baseIdStore = world.account.idStore
    const tearingIdStore = {
      ...baseIdStore,
      async putIdResource(
        options: Parameters<(typeof baseIdStore)['putIdResource']>[0]
      ) {
        if (options.resourceId === DID_LOG_RESOURCE && ++logPuts === 2) {
          throw new Error('injected: the pointer entry write failed')
        }
        return baseIdStore.putIdResource(options)
      }
    }
    await expect(world.run({ idStore: tearingIdStore })).rejects.toThrow(
      /pointer entry write failed/
    )
    const [strandedSpaceId] = world.server.annexSpaceIds()
    world.server.authRefuse.add(strandedSpaceId!)
    const published = await readPublishedLog({
      idStore: world.account.idStore
    })
    const accountDid = published!.did
    const ladderClient = await ladderVmZcapClient({
      accountDid,
      ladderSeed: world.credential.ladderSeed
    })
    const sibling = await mintDelegatedClientsDelegation({
      zcapClient: ladderClient,
      wasServerUrl: WAS_URL,
      clientAnnexSpaceId: strandedSpaceId!,
      controller: world.credential.standing.clientDid
    })

    const outcome = await ensurePointedClientAnnexGeneration({
      account: published!,
      wasServerUrl: WAS_URL,
      accountSpaceId: SPACE_ID,
      ladderSeed: world.credential.ladderSeed,
      was: world.server.was,
      mintController: 'did:key:z6MkNeverUsed',
      mintGenerationDelegation: ladderSignedGenerationDelegationMinter({
        accountDid,
        ladderSeed: world.credential.ladderSeed,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID
      }),
      idStore: world.account.idStore,
      delegatedClients: sibling,
      invocation: {
        was: world.server.privilegedWas,
        capability: sibling
      }
    })

    expect(outcome.spaceMinted).toBe(false)
    expect(outcome.generationMinted).toBe(true)
    expect(clientAnnexDidParts({ did: outcome.clientAnnexDid }).spaceId).toBe(
      strandedSpaceId
    )
    // No second Space, and the pointer entry landed.
    expect(world.server.annexSpaceIds()).toEqual([strandedSpaceId])
    expect(logLength(world.account.log())).toBe(2)
    expect(
      delegatedClientsPointer({
        doc: publishedDoc(world.account.log()!) as never
      })
    ).toBe(outcome.clientAnnexDid)
  })
})

describe('mendCredentialAnchoredAccount (the mend entry point)', () => {
  /**
   * The mend's option bundle over an establishment world: the establishment
   * hooks verbatim, a DID-less or promoted pointer per test, and the
   * post-promotion members where a test supplies them.
   */
  function mendWith(
    world: Awaited<ReturnType<typeof establishWorld>>,
    overrides: Partial<Parameters<typeof mendCredentialAnchoredAccount>[0]> = {}
  ): Promise<CredentialAnchoredMendReport> {
    return mendCredentialAnchoredAccount({
      account: {
        controller: world.credential.standing.clientDid,
        pointer: { spaceId: SPACE_ID, host: WAS_URL },
        ladderSeed: world.credential.ladderSeed
      },
      standing: world.credential.standing,
      lowEntropy: true,
      bindRecord: world.bind.hook,
      rosterStoreFor: () => world.rosterStore,
      bootstrapWasFor: () => world.server.was,
      idStore: world.account.idStore,
      pinStore: world.pinStore,
      hasRosterEpochPin: async () => false,
      ...overrides
    })
  }

  /**
   * The published account DID, read off the genesis entry.
   */
  function publishedDid(world: Awaited<ReturnType<typeof establishWorld>>) {
    return (readLogFromString(world.account.log()!)[0]!.state as { id: string })
      .id
  }

  /**
   * A fully established world plus the promoted-pointer mend members: the
   * account core naming the DID, and a post-promotion invocation triple over
   * the privileged handle.
   */
  async function promotedWorld() {
    const world = await establishWorld()
    const established = await world.run()
    const invocation = {
      was: world.server.privilegedWas,
      zcapClient: {} as never,
      capability: { id: 'urn:zcap:test-generation-delegation' } as IZcap
    }
    const promoted = (
      overrides: Partial<
        Parameters<typeof mendCredentialAnchoredAccount>[0]
      > = {}
    ) =>
      mendWith(world, {
        account: {
          controller: world.credential.standing.clientDid,
          pointer: { spaceId: SPACE_ID, host: WAS_URL, did: established.did },
          ladderSeed: world.credential.ladderSeed
        },
        ...overrides
      })
    return { world, established, invocation, promoted }
  }

  it('refuses a missing required hook synchronously', async () => {
    const world = await establishWorld()
    for (const missing of [
      'bindRecord',
      'rosterStoreFor',
      'bootstrapWasFor',
      'hasRosterEpochPin'
    ] as const) {
      expect(() => mendWith(world, { [missing]: undefined } as never)).toThrow(
        TypeError
      )
    }
  })

  it('establishment arm: a DID-less state with no published log runs the whole establishment and asks for re-entry', async () => {
    const world = await establishWorld()
    let hookRuns = 0

    const report = await mendWith(world, {
      beforePromotion: async () => {
        hookRuns++
      }
    })

    expect(report.establishment).toMatchObject({
      converged: true,
      outcome: 'established'
    })
    expect(report.reenter).toBe(true)
    expect(report.establishment!.did!.startsWith('did:webvh:')).toBe(true)
    expect(hookRuns).toBe(1)
    expect(world.server.controllerOf(SPACE_ID)).toBe(report.establishment!.did)
    expect(logLength(world.account.log())).toBe(2)
  })

  it('establishment arm: a raw establishment throw lands in the report, never propagated', async () => {
    const rosterStore = memoryDescriptorStore({ failFirstWrite: true })
    const world = await establishWorld({ rosterStore })

    const report = await mendWith(world)

    expect(report.establishment!.converged).toBe(false)
    expect(report.reenter).toBe(false)
    expect(String((report.establishment!.error as Error).message)).toMatch(
      /roster stage failed/
    )
  })

  it('establishment arm: a stale DID-less record over a resolvable, attributing log re-binds instead of re-running (the downgrade probe / non-termination pin)', async () => {
    const world = await establishWorld()

    // The first mend converges the whole establishment...
    const first = await mendWith(world)
    expect(first.establishment!.outcome).toBe('established')
    // ...which fired its own registry hook in the root window, so the
    // re-entry is NOT repair-shaped.
    expect(first.reenterRepairShaped).toBeUndefined()
    const entriesAfter = logLength(world.account.log())
    const spacesAfter = world.server.annexSpaceIds().length
    const bindsAfter = world.bind.calls.length

    // ...and a caller whose store keeps serving the stale DID-less record
    // re-enters. The probe finds the published, ladder-attributing log and
    // re-binds the record -- exactly one establishment run ever happens, no
    // duplicate entries, no second annex Space.
    const second = await mendWith(world, {
      priorCreatedAt:
        world.bind.calls[world.bind.calls.length - 1]!.priorCreatedAt
    })

    expect(second.establishment).toMatchObject({
      converged: true,
      outcome: 'rebound'
    })
    expect(second.reenter).toBe(true)
    // The re-bind ran no registry hook, so the caller's re-entry must carry
    // repairShaped for the registry arm to fire.
    expect(second.reenterRepairShaped).toBe(true)
    expect(logLength(world.account.log())).toBe(entriesAfter)
    expect(world.server.annexSpaceIds()).toHaveLength(spacesAfter)
    // One more bind ran -- the re-bind, with the full pointer and the
    // management target -- and no first bind (no genesis re-run).
    expect(world.bind.calls).toHaveLength(bindsAfter + 1)
    const rebind = world.bind.calls[world.bind.calls.length - 1]!
    expect(rebind.pointer.did).toBe(first.establishment!.did)
    expect(rebind.delegateManagementTo).toBe(first.establishment!.did)
    expect(rebind.delegatedClients).toBeDefined()
  })

  it('establishment arm: a resolvable log another ladder owns falls through to the establishment run, whose refusal is reported', async () => {
    const world = await establishWorld()
    await world.run()

    // A different credential's mend over the same account log: the probe
    // resolves the log but the ladder does not attribute, so the arm runs
    // the establishment, which refuses -- reported, not thrown.
    const loser = await establishCredential()
    const loserBind = recordingBindRecord()
    const report = await mendCredentialAnchoredAccount({
      account: {
        controller: loser.standing.clientDid,
        pointer: { spaceId: SPACE_ID, host: WAS_URL },
        ladderSeed: loser.ladderSeed
      },
      standing: loser.standing,
      lowEntropy: true,
      bindRecord: loserBind.hook,
      rosterStoreFor: () => memoryDescriptorStore(),
      bootstrapWasFor: () => world.server.was,
      idStore: world.account.idStore,
      hasRosterEpochPin: async () => false
    })

    expect(report.establishment!.converged).toBe(false)
    expect(report.reenter).toBe(false)
    expect((report.establishment!.error as Error).name).toBe(
      'LadderAttributionError'
    )
  })

  it('promotion arm, delegated-read trigger: completes the promotion, retries the read once, and converges', async () => {
    const world = await establishWorld()
    world.server.kill.nextPromotionOf = SPACE_ID
    await expect(world.run()).rejects.toThrow(/promotion write failed/)
    const did = publishedDid(world)
    const original = new Error('injected: the delegated roster read failed')
    let retries = 0

    const report = await mendWith(world, {
      account: {
        controller: world.credential.standing.clientDid,
        pointer: { spaceId: SPACE_ID, host: WAS_URL, did },
        ladderSeed: world.credential.ladderSeed
      },
      delegatedRead: {
        error: original,
        retry: async () => {
          retries++
        }
      }
    })

    expect(report.promotion).toMatchObject({
      converged: true,
      outcome: 'retried'
    })
    expect(retries).toBe(1)
    expect(world.server.controllerOf(SPACE_ID)).toBe(did)
  })

  it('promotion arm, delegated-read trigger: a failing promotion attempt rethrows the ORIGINAL error unchanged', async () => {
    const { world, established, promoted } = await promotedWorld()
    // The healthy promoted account refuses the bootstrap did:key outright;
    // the arm's doomed promotion attempt must surface as the caller's own
    // original error, never the promotion's.
    world.server.authRefuse.add(SPACE_ID)
    const original = new Error('injected: the original delegated read error')

    await expect(
      promoted({
        delegatedRead: {
          error: original,
          retry: async () => {}
        }
      })
    ).rejects.toBe(original)
    expect(world.server.controllerOf(SPACE_ID)).toBe(established.did)
  })

  it('promotion arm, delegated-read trigger: a still-failing retry rethrows the ORIGINAL error unchanged', async () => {
    const world = await establishWorld()
    world.server.kill.nextPromotionOf = SPACE_ID
    await expect(world.run()).rejects.toThrow(/promotion write failed/)
    const did = publishedDid(world)
    const original = new Error('injected: the original delegated read error')

    await expect(
      mendWith(world, {
        account: {
          controller: world.credential.standing.clientDid,
          pointer: { spaceId: SPACE_ID, host: WAS_URL, did },
          ladderSeed: world.credential.ladderSeed
        },
        delegatedRead: {
          error: original,
          retry: async () => {
            throw new Error('injected: the retry failed too')
          }
        }
      })
    ).rejects.toBe(original)
    // The promotion itself still landed (the ensure ran before the retry).
    expect(world.server.controllerOf(SPACE_ID)).toBe(did)
  })

  it('promotion arm, probe trigger: an authorized read showing a bootstrap controller classifies the tear and mends it', async () => {
    const world = await establishWorld()
    world.server.kill.nextPromotionOf = SPACE_ID
    await expect(world.run()).rejects.toThrow(/promotion write failed/)
    const did = publishedDid(world)

    const report = await mendWith(world, {
      account: {
        controller: world.credential.standing.clientDid,
        pointer: { spaceId: SPACE_ID, host: WAS_URL, did },
        ladderSeed: world.credential.ladderSeed
      }
    })

    expect(report.promotion).toMatchObject({
      converged: true,
      outcome: 'promoted'
    })
    expect(world.server.controllerOf(SPACE_ID)).toBe(did)
  })

  it('healthy fast path: no arm fires, no registry work, an empty report', async () => {
    const { promoted } = await promotedWorld()
    let hookRuns = 0

    const report = await promoted({
      beforePromotion: async () => {
        hookRuns++
      }
    })

    expect(report).toEqual({ reenter: false })
    expect(hookRuns).toBe(0)
  })

  it('roster arm: a promoted account with no roster mints under the delegated invocation and lands the epochs (the legacy empty-roster form)', async () => {
    const { world, invocation, promoted } = await promotedWorld()
    // The defensive/legacy T3 shape: roster gone, collections epoch-less --
    // constructed, since the orchestrator itself cannot leave it.
    const emptyRoster = memoryDescriptorStore()
    for (const collectionId of EDV_ROSTER_IDS) {
      world.server.stripEpochs(SPACE_ID, collectionId)
    }
    // The promoted Space no longer answers to the bootstrap did:key, so the
    // arm converges only if its precondition reads and its fan-out actually
    // ride the DELEGATED invocation authority, never the bootstrap handle.
    world.server.authRefuse.add(SPACE_ID)

    const report = await promoted({
      rosterStore: emptyRoster,
      invocation
    })

    expect(report.rosterEpochs).toMatchObject({
      converged: true,
      outcome: 'delivered'
    })
    const delivered = report.rosterEpochs!.userKey!
    expect(emptyRoster._getDescriptor()!.currentEpoch).toBe(delivered.id)
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(
        world.server
          .descriptorOf(SPACE_ID, collectionId)
          .epochs![0]!.recipients.map(entry => entry.header.kid)
      ).toEqual([userKeyAsRecipient({ userKey: delivered }).id])
    }
  })

  it('roster arm: an epoch-less encrypted collection behind a PRESENT roster re-enters on a repair-shaped entry (the reachable form)', async () => {
    const { world, invocation, promoted } = await promotedWorld()
    const stranded = EDV_ROSTER_IDS[0]!
    world.server.stripEpochs(SPACE_ID, stranded)

    const report = await promoted({
      rosterStore: world.rosterStore,
      invocation,
      repairShaped: true
    })

    expect(report.rosterEpochs).toMatchObject({
      converged: true,
      outcome: 'delivered'
    })
    expect(world.server.descriptorOf(SPACE_ID, stranded).epochs).toHaveLength(1)
  })

  it('roster arm: a lost roster-genesis race adopts the winner and reports converged-elsewhere', async () => {
    const { world, invocation, promoted } = await promotedWorld()
    for (const collectionId of EDV_ROSTER_IDS) {
      world.server.stripEpochs(SPACE_ID, collectionId)
    }
    const winnerKey = await mintUserKey()
    const winnerStore = memoryDescriptorStore()
    await initRecipients({
      store: winnerStore,
      recipients: [
        {
          id: world.credential.standing.recipientKid,
          publicKeyMultibase: world.credential.standing.keyAgreementKeyMultibase
        }
      ],
      epoch: { epochId: winnerKey.id, secret: winnerKey.secret }
    })
    let winnerVisible = false
    const racing: EncryptionDescriptorStore = {
      async read() {
        return winnerVisible ? winnerStore.read() : null
      },
      async replace() {
        throw new Error('unreachable: the loser never replaces')
      },
      async create() {
        winnerVisible = true
        throw new WebvhLogConflictError(
          'the roster genesis append lost the log CAS'
        )
      }
    }

    const report = await promoted({ rosterStore: racing, invocation })

    expect(report.rosterEpochs).toMatchObject({
      converged: true,
      outcome: 'converged-elsewhere'
    })
    expect(report.rosterEpochs!.userKey!.id).toBe(winnerKey.id)
  })

  it('roster arm: a roster with no wrap for this credential is its own outcome, never folded into no-roster', async () => {
    const { promoted, invocation } = await promotedWorld()
    const other = await establishCredential()
    const foreignKey = await mintUserKey()
    const foreignStore = memoryDescriptorStore()
    await initRecipients({
      store: foreignStore,
      recipients: [
        {
          id: other.standing.recipientKid,
          publicKeyMultibase: other.standing.keyAgreementKeyMultibase
        }
      ],
      epoch: { epochId: foreignKey.id, secret: foreignKey.secret }
    })

    const report = await promoted({
      rosterStore: foreignStore,
      invocation,
      repairShaped: true
    })

    expect(report.rosterEpochs).toMatchObject({
      converged: false,
      outcome: 'no-wrap'
    })
    expect((report.rosterEpochs!.error as { name?: string }).name).toBe(
      'UserKeyRosterUnwrapError'
    )
  })

  it('roster arm: the mint preconditions refuse a fabricated-absent roster', async () => {
    // Precondition 3: an encrypted collection already epoch'd beside a
    // served-absent roster is fabricated absence.
    const { world, invocation, promoted } = await promotedWorld()
    const epochd = await promoted({
      rosterStore: memoryDescriptorStore(),
      invocation
    })
    expect(epochd.rosterEpochs).toMatchObject({
      converged: false,
      outcome: 'mint-refused'
    })
    expect(String((epochd.rosterEpochs!.error as Error).message)).toMatch(
      /already carries a key epoch/
    )
    for (const collectionId of EDV_ROSTER_IDS) {
      world.server.stripEpochs(SPACE_ID, collectionId)
    }

    // Precondition 1: a held client-local roster-epoch pin refuses the mint.
    const pinned = await promoted({
      rosterStore: memoryDescriptorStore(),
      invocation,
      hasRosterEpochPin: async () => true
    })
    expect(pinned.rosterEpochs).toMatchObject({
      converged: false,
      outcome: 'mint-refused'
    })
    expect(String((pinned.rosterEpochs!.error as Error).message)).toMatch(
      /roster-epoch pin/
    )

    // Precondition 2: the verified document publishing a standing credential
    // other than the minting one refuses the mint.
    const other = await establishCredential()
    const foreign = await promoted({
      rosterStore: memoryDescriptorStore(),
      invocation,
      standing: other.standing
    })
    expect(foreign.rosterEpochs).toMatchObject({
      converged: false,
      outcome: 'mint-refused'
    })
    expect(String((foreign.rosterEpochs!.error as Error).message)).toMatch(
      /another standing credential/
    )
  })

  it('roster arm: a failed roster read is transport, never incompleteness -- no mint, no spurious refusal shape', async () => {
    const { promoted, invocation } = await promotedWorld()
    const failing: EncryptionDescriptorStore = {
      async read() {
        throw new Error('injected: the roster read transport failed')
      },
      async replace() {
        throw new Error('unreachable')
      },
      async create() {
        throw new Error('unreachable: transport must not mint')
      }
    }

    const report = await promoted({ rosterStore: failing, invocation })

    expect(report.rosterEpochs!.converged).toBe(false)
    expect(report.rosterEpochs!.outcome).toBeUndefined()
    expect(String((report.rosterEpochs!.error as Error).message)).toMatch(
      /transport failed/
    )
  })

  it('registry arm: a repair-shaped entry re-fires the read-first hook under the post-promotion authority', async () => {
    const { world, established, invocation, promoted } = await promotedWorld()
    const userKey = await mintUserKey()
    const fired: Array<{
      did: string
      userKeyId: string
      updateKeyMultibase: string
      unlockSpaceId: string
    }> = []
    const authoritiesSeen: unknown[] = []

    const report = await promoted({
      invocation,
      repairShaped: true,
      userKey,
      registry: { unlockSpaceId: 'unlock-space-establish' },
      beforePromotion: async ({
        was,
        did,
        userKey: contextKey,
        establishment
      }) => {
        authoritiesSeen.push(was)
        fired.push({
          did,
          userKeyId: contextKey.id,
          updateKeyMultibase: establishment.standingFields.updateKeyMultibase,
          unlockSpaceId: establishment.unlockSpaceId
        })
      }
    })

    expect(report.registry).toEqual({ converged: true })
    // The hook fired under the caller's POST-PROMOTION authority, never the
    // bootstrap handle.
    expect(authoritiesSeen).toEqual([invocation.was])
    const rung0 = await ladderRung({
      ladderSeed: world.credential.ladderSeed,
      index: 0
    })
    expect(fired).toEqual([
      {
        did: established.did,
        userKeyId: userKey.id,
        updateKeyMultibase: rung0.keyMultibase,
        unlockSpaceId: 'unlock-space-establish'
      }
    ])
  })

  it('registry arm: a throwing hook reports, and a missing context skips-and-reports', async () => {
    const { invocation, promoted } = await promotedWorld()
    const userKey = await mintUserKey()

    const throwing = await promoted({
      invocation,
      repairShaped: true,
      userKey,
      registry: { unlockSpaceId: 'unlock-space-establish' },
      beforePromotion: async () => {
        throw new Error('injected: the registry write refused')
      }
    })
    expect(throwing.registry!.converged).toBe(false)
    expect(String((throwing.registry!.error as Error).message)).toMatch(
      /registry write refused/
    )

    const contextless = await promoted({
      invocation,
      repairShaped: true,
      userKey,
      beforePromotion: async () => {}
    })
    expect(contextless.registry).toEqual({
      converged: false,
      skipped: 'no-registry-context'
    })
  })

  it('establishment arm: a stage-3 tear (revealed rung, NO pointer) runs the establishment, never the re-bind', async () => {
    // The genesis published and rung 0 revealed, but the pointer entry never
    // landed: classifying this as a record downgrade would send it into a
    // re-bind with no sibling target, permanently. The mender is the
    // establishment run itself -- its pointer stage is the ensure.
    const world = await establishWorld()
    let logPuts = 0
    const baseIdStore = world.account.idStore
    const tearingIdStore = {
      ...baseIdStore,
      async putIdResource(
        options: Parameters<(typeof baseIdStore)['putIdResource']>[0]
      ) {
        if (options.resourceId === DID_LOG_RESOURCE && ++logPuts === 2) {
          throw new Error('injected: the pointer entry write failed')
        }
        return baseIdStore.putIdResource(options)
      }
    }
    await expect(world.run({ idStore: tearingIdStore })).rejects.toThrow(
      /pointer entry write failed/
    )
    expect(logLength(world.account.log())).toBe(1)

    const report = await mendWith(world, {
      priorCreatedAt: '2026-08-26T00:00:00.001Z'
    })

    expect(report.establishment).toMatchObject({
      converged: true,
      outcome: 'established'
    })
    expect(report.reenter).toBe(true)
    // The establishment converged on the published SCID: two entries, the
    // pointer present, the promotion landed.
    expect(logLength(world.account.log())).toBe(2)
    expect(
      delegatedClientsPointer({
        doc: publishedDoc(world.account.log()!) as never
      })
    ).toBeDefined()
    expect(world.server.controllerOf(SPACE_ID)).toBe(report.establishment!.did)
  })

  it("establishment arm: the probe's continuity refusal rethrows by name, never swallowed into a re-run", async () => {
    const world = await establishWorld()
    await world.run()
    expect(logLength(world.account.log())).toBe(2)
    // A host serving a valid PREFIX of the real log: the chain-head pin the
    // establishment advanced refuses it as a rollback.
    const baseIdStore = world.account.idStore
    const truncatingIdStore = {
      ...baseIdStore,
      async getIdResourceRaw(
        options: Parameters<(typeof baseIdStore)['getIdResourceRaw']>[0]
      ) {
        const read = await baseIdStore.getIdResourceRaw(options)
        if (read === undefined) {
          return read
        }
        return { ...read, text: read.text.split('\n')[0]! }
      }
    }

    await expect(
      mendWith(world, { idStore: truncatingIdStore })
    ).rejects.toMatchObject({ name: 'ResourceLogContinuityError' })
  })

  it('a throwing bootstrap factory rides the report of the arm the pointer shape selects', async () => {
    const world = await establishWorld()
    const throwingFactory = () => {
      throw new Error('injected: no bootstrap client')
    }

    const didless = await mendWith(world, {
      bootstrapWasFor: throwingFactory
    })
    expect(didless.establishment).toMatchObject({ converged: false })
    expect(String((didless.establishment!.error as Error).message)).toMatch(
      /no bootstrap client/
    )

    const { promoted } = await promotedWorld()
    const report = await promoted({ bootstrapWasFor: throwingFactory })
    expect(report.promotion).toMatchObject({ converged: false })
    expect(String((report.promotion!.error as Error).message)).toMatch(
      /no bootstrap client/
    )
  })

  it('roster arm: an epoch-less encrypted collection behind a PRESENT roster fires the arm with NO flag (the completion test)', async () => {
    const { world, invocation, promoted } = await promotedWorld()
    const stranded = EDV_ROSTER_IDS[0]!
    world.server.stripEpochs(SPACE_ID, stranded)

    const report = await promoted({
      rosterStore: world.rosterStore,
      invocation
    })

    expect(report.rosterEpochs).toMatchObject({
      converged: true,
      outcome: 'delivered'
    })
    expect(world.server.descriptorOf(SPACE_ID, stranded).epochs).toHaveLength(1)
  })

  it("promotion arm, delegated-read trigger: a 'confirmed' promotion on a healthy account fires neither the roster completion nor the registry hook", async () => {
    // A mere transport flap on the caller's read: the mend confirms the
    // promotion already stands, retries, and must NOT treat the entry as
    // repair-shaped.
    const { world, invocation, promoted } = await promotedWorld()
    const userKey = await mintUserKey()
    let hookRuns = 0
    let retries = 0

    const report = await promoted({
      delegatedRead: {
        error: new Error('injected: a transport flap'),
        retry: async () => {
          retries++
        }
      },
      rosterStore: world.rosterStore,
      invocation,
      userKey,
      registry: { unlockSpaceId: 'unlock-space-establish' },
      beforePromotion: async () => {
        hookRuns++
      }
    })

    expect(report.promotion).toMatchObject({
      converged: true,
      outcome: 'retried'
    })
    expect(retries).toBe(1)
    expect(report.rosterEpochs).toBeUndefined()
    expect(report.registry).toBeUndefined()
    expect(hookRuns).toBe(0)
  })

  it('promotion arm, probe trigger: a mended promotion marks the entry repair-shaped and fires the registry hook', async () => {
    const world = await establishWorld()
    world.server.kill.nextPromotionOf = SPACE_ID
    await expect(world.run()).rejects.toThrow(/promotion write failed/)
    const did = publishedDid(world)
    const invocation = {
      was: world.server.privilegedWas,
      zcapClient: {} as never,
      capability: { id: 'urn:zcap:test-generation-delegation' } as IZcap
    }
    const userKey = await mintUserKey()
    let hookRuns = 0

    const report = await mendWith(world, {
      account: {
        controller: world.credential.standing.clientDid,
        pointer: { spaceId: SPACE_ID, host: WAS_URL, did },
        ladderSeed: world.credential.ladderSeed
      },
      invocation,
      userKey,
      registry: { unlockSpaceId: 'unlock-space-establish' },
      beforePromotion: async () => {
        hookRuns++
      }
    })

    expect(report.promotion).toMatchObject({
      converged: true,
      outcome: 'promoted'
    })
    expect(report.registry).toEqual({ converged: true })
    expect(hookRuns).toBe(1)
    expect(world.server.controllerOf(SPACE_ID)).toBe(did)
  })
})

describe('the establishment reads the account log once', () => {
  /**
   * A counting wrapper over the account's `id` store: every `did.jsonl`
   * read, and -- when `dropPutEtag` is set -- a publish seam that hands back
   * no validator, which is what the seam did before it forwarded the PUT's
   * own ETag. That variant is the honest "before" measurement, since the
   * ceremony then has no compare-and-swap-capable head to carry forward.
   */
  function countingAccountStore(
    idStore: WebvhIdStore,
    { dropPutEtag = false }: { dropPutEtag?: boolean } = {}
  ) {
    const counter = { logReads: 0 }
    const store: WebvhIdStore = {
      ...idStore,
      async getIdResourceRaw(options: { resourceId: string }) {
        if (options.resourceId === DID_LOG_RESOURCE) {
          counter.logReads += 1
        }
        return idStore.getIdResourceRaw(options)
      },
      async putIdResource(
        options: Parameters<WebvhIdStore['putIdResource']>[0]
      ) {
        const written = await idStore.putIdResource(options)
        return dropPutEtag ? undefined : written
      }
    }
    return { store, counter }
  }

  it('spends one did.jsonl read on a whole fresh signup (was three)', async () => {
    const world = await establishWorld()
    const { store, counter } = countingAccountStore(world.account.idStore)

    const result = await world.run({ idStore: store })

    // One read: the genesis stage's create-or-adopt probe. The genesis
    // MINTED this account's log, so the stage-3 preamble and the pointer
    // entry both ride the head that stage handed forward. Before the head
    // was threaded the same run spent three: the probe, the preamble's
    // re-read, and the pointer entry's own.
    expect(counter.logReads).toBe(1)
    expect(logLength(world.account.log())).toBe(2)
    // The head the run ends standing on is the pointer entry's own.
    expect(result.accountLog.did).toBe(result.did)
    expect(result.accountLog.log).toHaveLength(2)
    const served = await world.account.idStore.getIdResourceRaw({
      resourceId: DID_LOG_RESOURCE
    })
    expect(result.accountLog.etag).toBe(served!.etag)
  })

  it('spends two on a heal re-run, whose genesis adopts rather than mints', async () => {
    const world = await establishWorld()
    await world.run()
    const { store, counter } = countingAccountStore(world.account.idStore)

    const result = await world.run({ idStore: store })

    // The probe adopts a log this run did not mint, so the stage-3 preamble
    // reads for itself: the account is live, and the pointer completion test
    // it reads off the document is protected by no ETag, so a concurrent
    // login's generation must not be missed. Two reads, the width this stage
    // always had.
    expect(counter.logReads).toBe(2)
    // Convergence: the re-run appended nothing and pointed at the standing
    // generation rather than minting a second one.
    expect(logLength(world.account.log())).toBe(2)
    expect(world.server.annexSpaceIds()).toHaveLength(1)
    expect(result.accountLog.log).toHaveLength(2)
  })

  it('reads once more when the publish seam hands back no validator', async () => {
    const world = await establishWorld()
    const { store, counter } = countingAccountStore(world.account.idStore, {
      dropPutEtag: true
    })

    const result = await world.run({ idStore: store })

    // The minted head carries no ETag, so the stage-3 preamble reads for
    // itself rather than letting the pointer entry's compare-and-swap
    // degrade to an unconditional write: the probe plus that one read.
    expect(counter.logReads).toBe(2)
    expect(logLength(world.account.log())).toBe(2)
    expect(result.accountLog.log).toHaveLength(2)
  })
})

describe('the establishment reads the annex generation log never', () => {
  /**
   * The one annex generation log the run published: its Space, its
   * generation collection, and the serialized log.
   */
  function annexGeneration(server: ReturnType<typeof multiFakeWas>) {
    const [annexSpaceId] = server.annexSpaceIds()
    const resources = server.spaces.get(annexSpaceId!)!.resources
    const [key, row] = [...resources.entries()].find(
      ([resourceKey]) =>
        resourceKey.startsWith('gen-') &&
        resourceKey.endsWith(`/${DID_LOG_RESOURCE}`)
    )!
    return {
      spaceId: annexSpaceId!,
      generationId: key.slice(0, key.lastIndexOf('/')),
      log: row.text
    }
  }

  it('spends no generation-log read on a whole fresh signup', async () => {
    const world = await establishWorld()

    await world.run()

    // Zero reads: the mint WROTE the genesis, so the delegation install
    // stands on the head it handed forward, and the pointer entry that
    // follows touches the account log alone. Before the head was threaded
    // the install re-read the log this run had just written.
    expect(world.server.counts.annexLogReads).toBe(0)
    const generation = annexGeneration(world.server)
    // Genesis plus the delegation embed.
    expect(logLength(generation.log)).toBe(2)
    // The install's own publish established the generation's pin slot, so
    // threading the head cost the run no continuity.
    const pinned = await world.pinStore.read({
      logId: clientAnnexLogPinId({
        spaceId: generation.spaceId,
        generationId: generation.generationId
      })
    })
    expect(pinned).toEqual(pinOfLog(readLogFromString(generation.log)))
  })

  it('reads once when the publish seam hands back no validator', async () => {
    const world = await establishWorld()
    world.server.kill.dropAnnexLogPutEtag = true

    await world.run()

    // The minted head carries no ETag, so the install reads for itself
    // rather than letting its entry's compare-and-swap degrade to an
    // unconditional write.
    expect(world.server.counts.annexLogReads).toBe(1)
    expect(logLength(annexGeneration(world.server).log)).toBe(2)
  })

  it('falls back to the pinned re-read on a lost compare-and-swap', async () => {
    const world = await establishWorld()
    world.server.kill.nextAnnexLogIfMatch = true

    await world.run()

    // The threaded head lost its compare-and-swap, so the conflict retry
    // re-read under the pin and published on the fresh head: one read, one
    // generation, and the same two entries.
    expect(world.server.counts.annexLogReads).toBe(1)
    expect(world.server.annexSpaceIds()).toHaveLength(1)
    expect(logLength(annexGeneration(world.server).log)).toBe(2)
  })
})
