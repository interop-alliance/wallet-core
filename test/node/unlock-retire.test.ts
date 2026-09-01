/**
 * Unit tests for the unlock-credential retirement ceremony
 * (`src/unlock/retire.ts`): the ordinary rotate-and-adopt run, the graceful
 * "no roster to rotate" completion on an account whose collections are not
 * encrypted yet, the fail-closed dependent-record re-mint that precedes the
 * document edit, the convergence of a naive re-run, and the post-edit
 * controller floor a sealable roster store is given. The document inventory
 * edit itself is stubbed -- it has its own tests against a real log -- so what
 * is exercised here is the ceremony's own ordering and outcome reporting.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { DIDLog } from '@interop/did-method-webvh'
import type { CollectionEncryption } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { retireUnlockCredential } from '../../src/unlock/retire.js'
import {
  attributeUnlockLadderInventory,
  removeUnlockKey,
  type StandingUnlockKeys
} from '../../src/unlock/standingWebvh.js'
import { readPublishedLogOrThrow } from '../../src/webvh/didWebvh.js'
import {
  addUserKeyRosterRecipient,
  ensureUserKeyRoster,
  rosterRecipientKid
} from '../../src/keys/userKeyRoster.js'
import { logGovernedDescriptorStore } from '../../src/keys/rosterLogStore.js'
import { userKeyRosterPinId } from '../../src/keys/rosterStore.js'
import { mintUserKey } from '../../src/keys/userKey.js'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import type { WebvhResourceLogController } from '../../src/resourceLog/index.js'
import type {
  ClientWebvhUpdateKeys,
  WebvhIdStore
} from '../../src/webvh/index.js'
import {
  makeRosterClient,
  rosterDocumentFor,
  type RosterTestClient
} from './fixtures/rosterClient.js'
import {
  CONTROLLER_DID,
  fakeController,
  memoryLogStore
} from './fixtures/resourceLog.js'

const ROSTER_LOG_ID = userKeyRosterPinId({ spaceId: 'urn:uuid:space' })

vi.mock('../../src/unlock/standingWebvh.js', async importOriginal => {
  const actual =
    await importOriginal<typeof import('../../src/unlock/standingWebvh.js')>()
  return {
    ...actual,
    removeUnlockKey: vi.fn(),
    attributeUnlockLadderInventory: vi.fn()
  }
})

// Stage 0's pre-edit read moved to the shared webvh helper; every other
// export of that module stays real.
vi.mock('../../src/webvh/didWebvh.js', async importOriginal => {
  const actual =
    await importOriginal<typeof import('../../src/webvh/didWebvh.js')>()
  return {
    ...actual,
    readPublishedLogOrThrow: vi.fn()
  }
})

/**
 * An in-memory descriptor store.
 *
 * @returns {object}
 */
function memoryStore(): EncryptionDescriptorStore & {
  state: { descriptor?: CollectionEncryption }
  writes: number
} {
  const holder = {
    state: {} as { descriptor?: CollectionEncryption },
    writes: 0,
    async read() {
      return holder.state.descriptor
        ? { descriptor: holder.state.descriptor, etag: '"v"' }
        : null
    },
    async replace(descriptor: CollectionEncryption) {
      holder.state.descriptor = descriptor
      holder.writes += 1
    },
    async create(descriptor: CollectionEncryption) {
      holder.state.descriptor = descriptor
      holder.writes += 1
    }
  }
  return holder
}

/**
 * The retired credential's key-agreement key, as its roster entry carries it.
 *
 * @returns {Promise<IKeyAgreementKey & { publicKeyMultibase: string }>}
 */
async function makeCredentialKak(): Promise<
  IKeyAgreementKey & { publicKeyMultibase: string }
> {
  const kak = await X25519KeyAgreementKey2020.generate()
  const did = `did:key:${kak.publicKeyMultibase}`
  kak.controller = did
  kak.id = `${did}#${kak.publicKeyMultibase}`
  return kak as IKeyAgreementKey & { publicKeyMultibase: string }
}

const idStore = {} as WebvhIdStore
const updateKeys = {} as ClientWebvhUpdateKeys
const collections = { collectionIds: [], storeFor: () => memoryStore() }

/**
 * A fake post-edit account log, one version per client set -- the shape
 * `webvhResourceLogController` reads off a verified did:webvh log.
 *
 * @param versions {RosterTestClient[][]}
 * @returns {DIDLog}
 */
function accountLogFor(versions: RosterTestClient[][]): DIDLog {
  return versions.map((versionClients, index) => ({
    versionId: `${index + 1}-v${index + 1}`,
    state: {
      ...rosterDocumentFor(versionClients),
      assertionMethod: versionClients.map(
        client => `${CONTROLLER_DID}#${client.signingKeyMultibase}`
      )
    }
  })) as unknown as DIDLog
}

/**
 * A retired credential's public inventory (a passphrase-shaped one: its
 * key-agreement key is published as a commitment).
 *
 * @returns {StandingUnlockKeys}
 */
function standingKeys(): StandingUnlockKeys {
  return {
    keyAgreement: { commitment: 'zCommitmentOfRetiredCredential' },
    updateKeyMultibase: 'z6MkRetiredLadderRung'
  }
}

/**
 * A controller view per version of the account document.
 *
 * @param clients {RosterTestClient[][]}
 * @returns {WebvhResourceLogController}
 */
function controllerFor(
  clients: RosterTestClient[][]
): WebvhResourceLogController {
  return fakeController({
    versions: clients.map((versionClients, index) => ({
      versionId: `${index + 1}-v${index + 1}`,
      keys: versionClients.map(client => client.signingKeyMultibase)
    }))
  })
}

describe('retireUnlockCredential', () => {
  beforeEach(() => {
    vi.mocked(removeUnlockKey).mockReset()
    vi.mocked(readPublishedLogOrThrow).mockReset()
    vi.mocked(attributeUnlockLadderInventory).mockReset()
  })

  it('completes with nothing rotated on an account with no roster', async () => {
    const own = await makeRosterClient()
    const doc = { keyAgreement: [] }
    vi.mocked(removeUnlockKey).mockResolvedValue({
      doc
    } as unknown as Awaited<ReturnType<typeof removeUnlockKey>>)
    const rosterStore = memoryStore()

    const result = await retireUnlockCredential({
      idStore,
      updateKeys,
      unlockKeys: standingKeys(),
      rosterStore,
      clientKeyAgreementKey: own.kak,
      collections
    })

    // The inventory edit landed, so the credential IS retired: a completed
    // ceremony, not a failure, and no roster write was attempted.
    expect(result).toEqual({
      rotated: false,
      collections: { outcomes: {}, failed: [] },
      document: doc
    })
    expect(rosterStore.writes).toBe(0)
  })

  it('removes the inventory, rotates the roster off the credential, and adopts the fresh key', async () => {
    const own = await makeRosterClient()
    const credentialKak = await makeCredentialKak()
    const userKey = await mintUserKey()
    const rosterStore = memoryStore()
    await ensureUserKeyRoster({
      store: rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak
    })
    const credentialKid = rosterRecipientKid({
      signingKeyMultibase: 'z6MkRetiredCredentialSigningKey',
      keyAgreementKeyMultibase: credentialKak.publicKeyMultibase
    })
    await addUserKeyRosterRecipient({
      store: rosterStore,
      recipient: {
        id: credentialKid,
        publicKeyMultibase: credentialKak.publicKeyMultibase
      },
      ownerKeyAgreementKey: own.kak
    })

    // The document as the inventory edit left it: the credential's
    // key-agreement entry is gone, and this client's keys are still backed.
    const doc = rosterDocumentFor([own])
    const unlockKeys = standingKeys()
    vi.mocked(removeUnlockKey).mockResolvedValue({
      did: CONTROLLER_DID,
      doc,
      log: accountLogFor([[own]])
    } as unknown as Awaited<ReturnType<typeof removeUnlockKey>>)

    const calls: string[] = []
    const result = await retireUnlockCredential({
      idStore,
      updateKeys,
      unlockKeys,
      expectedDid: CONTROLLER_DID,
      verb: 'changing your passphrase',
      rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak,
      onUserKeyAdopted: async () => {
        calls.push('persisted')
      },
      collections,
      onRotationAdopted: async () => {
        calls.push('session')
      }
    })

    // The inventory edit ran first, with the caller's account pointer and verb
    // threaded to it.
    expect(vi.mocked(removeUnlockKey).mock.calls[0]![0]).toMatchObject({
      unlockKeys,
      expectedDid: CONTROLLER_DID,
      verb: 'changing your passphrase'
    })
    expect(result.rotated).toBe(true)
    expect(result.document).toBe(doc)
    expect(result.userKey!.id).not.toBe(userKey.id)
    // Persistence before the fan-out, the live session's adoption last.
    expect(calls).toEqual(['persisted', 'session'])
    const fresh = result.rosterDescriptor!.epochs!.find(
      epoch => epoch.id === result.rosterDescriptor!.currentEpoch
    )!
    expect(fresh.recipients.map(entry => entry.header.kid)).toEqual([
      own.kak.id
    ])
  })

  it('runs the client annex reach after the document edit and before the roster tail', async () => {
    const own = await makeRosterClient()
    const credentialKak = await makeCredentialKak()
    const userKey = await mintUserKey()
    const rosterStore = memoryStore()
    await ensureUserKeyRoster({
      store: rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak
    })
    await addUserKeyRosterRecipient({
      store: rosterStore,
      recipient: {
        id: rosterRecipientKid({
          signingKeyMultibase: 'z6MkRetiredCredentialSigningKey',
          keyAgreementKeyMultibase: credentialKak.publicKeyMultibase
        }),
        publicKeyMultibase: credentialKak.publicKeyMultibase
      },
      ownerKeyAgreementKey: own.kak
    })

    const doc = rosterDocumentFor([own])
    const calls: string[] = []
    vi.mocked(removeUnlockKey).mockImplementation(async () => {
      calls.push('document')
      return {
        did: CONTROLLER_DID,
        doc,
        log: accountLogFor([[own]])
      } as unknown as Awaited<ReturnType<typeof removeUnlockKey>>
    })

    const documents: object[] = []
    const result = await retireUnlockCredential({
      idStore,
      updateKeys,
      unlockKeys: standingKeys(),
      rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak,
      retireClientAnnexInventory: async ({ document }) => {
        documents.push(document)
        calls.push('clientAnnex')
        return { action: 'struck' }
      },
      onUserKeyAdopted: async () => {
        calls.push('persisted')
      },
      collections,
      onRotationAdopted: async () => {
        calls.push('session')
      }
    })

    // Stage 1b sits between the inventory edit and the roster tail, and reads
    // the post-edit document.
    expect(calls).toEqual(['document', 'clientAnnex', 'persisted', 'session'])
    expect(documents).toEqual([doc])
    expect(result.rotated).toBe(true)
    expect(result.clientAnnex).toEqual({ action: 'struck' })
  })

  it('maps a throwing client annex closure to the failed skip and still rotates the roster', async () => {
    const own = await makeRosterClient()
    const credentialKak = await makeCredentialKak()
    const userKey = await mintUserKey()
    const rosterStore = memoryStore()
    await ensureUserKeyRoster({
      store: rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak
    })
    await addUserKeyRosterRecipient({
      store: rosterStore,
      recipient: {
        id: rosterRecipientKid({
          signingKeyMultibase: 'z6MkRetiredCredentialSigningKey',
          keyAgreementKeyMultibase: credentialKak.publicKeyMultibase
        }),
        publicKeyMultibase: credentialKak.publicKeyMultibase
      },
      ownerKeyAgreementKey: own.kak
    })

    const doc = rosterDocumentFor([own])
    vi.mocked(removeUnlockKey).mockResolvedValue({
      did: CONTROLLER_DID,
      doc,
      log: accountLogFor([[own]])
    } as unknown as Awaited<ReturnType<typeof removeUnlockKey>>)

    const calls: string[] = []
    const result = await retireUnlockCredential({
      idStore,
      updateKeys,
      unlockKeys: standingKeys(),
      rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak,
      retireClientAnnexInventory: async () => {
        throw new Error('annex host unreachable')
      },
      onUserKeyAdopted: async () => {
        calls.push('persisted')
      },
      collections,
      onRotationAdopted: async () => {
        calls.push('session')
      }
    })

    // The throw is the closure's failure to report, not the ceremony's: the
    // roster rotation -- the essential remedy -- still runs.
    expect(result.clientAnnex).toEqual({ action: 'skipped', reason: 'failed' })
    expect(result.rotated).toBe(true)
    expect(calls).toEqual(['persisted', 'session'])
    const fresh = result.rosterDescriptor!.epochs!.find(
      epoch => epoch.id === result.rosterDescriptor!.currentEpoch
    )!
    expect(fresh.recipients.map(entry => entry.header.kid)).toEqual([
      own.kak.id
    ])
  })

  it('reports the client annex stage on the no-roster path, and omits it without a closure', async () => {
    const own = await makeRosterClient()
    const doc = { keyAgreement: [] }
    vi.mocked(removeUnlockKey).mockResolvedValue({
      doc
    } as unknown as Awaited<ReturnType<typeof removeUnlockKey>>)

    const withClosure = await retireUnlockCredential({
      idStore,
      updateKeys,
      unlockKeys: standingKeys(),
      rosterStore: memoryStore(),
      clientKeyAgreementKey: own.kak,
      collections,
      retireClientAnnexInventory: async () => ({
        action: 'skipped',
        reason: 'no-pointer'
      })
    })
    expect(withClosure.clientAnnex).toEqual({
      action: 'skipped',
      reason: 'no-pointer'
    })

    const without = await retireUnlockCredential({
      idStore,
      updateKeys,
      unlockKeys: standingKeys(),
      rosterStore: memoryStore(),
      clientKeyAgreementKey: own.kak,
      collections
    })
    expect('clientAnnex' in without).toBe(false)
  })

  /**
   * The pre-edit log read and ladder attribution stage 0 runs, stubbed: the
   * document as it stands before the edit, and the ladder VM ids this
   * retirement is about to strike.
   */
  function stubPreEditLog(ladderVmIds: string[]): { preDoc: object } {
    const preDoc = { keyAgreement: ['pre-edit'] }
    vi.mocked(readPublishedLogOrThrow).mockResolvedValue({
      did: CONTROLLER_DID,
      doc: preDoc,
      log: [] as unknown as DIDLog
    } as unknown as Awaited<ReturnType<typeof readPublishedLogOrThrow>>)
    vi.mocked(attributeUnlockLadderInventory).mockResolvedValue({
      revealedKeys: [],
      committedHashes: [],
      ladderVmIds
    })
    return { preDoc }
  }

  it('re-mints dependent records against the pre-edit document, before the edit', async () => {
    const own = await makeRosterClient()
    const doomed = `${CONTROLLER_DID}#z6MkDoomedLadderVm`
    const { preDoc } = stubPreEditLog([doomed])
    const doc = { keyAgreement: [] }
    const calls: string[] = []
    vi.mocked(removeUnlockKey).mockImplementation(async () => {
      calls.push('document')
      return { doc } as unknown as Awaited<ReturnType<typeof removeUnlockKey>>
    })

    const seen: Array<{ document: object; retiringKeyMultibases: string[] }> =
      []
    const result = await retireUnlockCredential({
      idStore,
      updateKeys,
      unlockKeys: standingKeys(),
      expectedDid: CONTROLLER_DID,
      rosterStore: memoryStore(),
      clientKeyAgreementKey: own.kak,
      collections,
      remintDependentRecords: async options => {
        calls.push('remint')
        seen.push(options)
        return { reminted: 1, skipped: 0 }
      }
    })

    expect(calls).toEqual(['remint', 'document'])
    expect(seen).toEqual([
      { document: preDoc, retiringKeyMultibases: [doomed] }
    ])
    expect(result.dependentRecords).toEqual({ reminted: 1, skipped: 0 })
  })

  it('ties the two log reads: the attributed list and the pins reach the edit', async () => {
    const own = await makeRosterClient()
    const doomed = `${CONTROLLER_DID}#z6MkDoomedLadderVm`
    stubPreEditLog([doomed])
    vi.mocked(removeUnlockKey).mockResolvedValue({
      doc: { keyAgreement: [] }
    } as unknown as Awaited<ReturnType<typeof removeUnlockKey>>)
    const pinStore = memoryResourceLogPinStore()
    const logId = 'space/urn:uuid:space/id/did.jsonl'

    await retireUnlockCredential({
      idStore,
      updateKeys,
      unlockKeys: standingKeys(),
      pinStore,
      logId,
      rosterStore: memoryStore(),
      clientKeyAgreementKey: own.kak,
      collections,
      remintDependentRecords: async () => undefined
    })

    // Stage 0's own read carries the pins ...
    expect(vi.mocked(readPublishedLogOrThrow).mock.calls[0]?.[0]).toMatchObject(
      {
        pinStore,
        logId
      }
    )
    // ... and the edit gets the same pins plus the list stage 0 attributed,
    // which is what refuses a strike that drifted from it.
    expect(vi.mocked(removeUnlockKey).mock.calls[0]?.[0]).toMatchObject({
      pinStore,
      logId,
      expectedLadderVmIds: [doomed]
    })
  })

  it('names no expected ladder VM set when no re-mint pass ran', async () => {
    const own = await makeRosterClient()
    vi.mocked(removeUnlockKey).mockResolvedValue({
      doc: { keyAgreement: [] }
    } as unknown as Awaited<ReturnType<typeof removeUnlockKey>>)

    await retireUnlockCredential({
      idStore,
      updateKeys,
      unlockKeys: standingKeys(),
      rosterStore: memoryStore(),
      clientKeyAgreementKey: own.kak,
      collections
    })

    // Nothing resolved a list, so nothing constrains the edit's attribution.
    expect(
      'expectedLadderVmIds' in
        (vi.mocked(removeUnlockKey).mock.calls[0]?.[0] ?? {})
    ).toBe(false)
  })

  it('reports the inventory edit ladder VM report', async () => {
    const own = await makeRosterClient()
    const stranded = `${CONTROLLER_DID}#z6MkUnclaimedLadderVm`
    vi.mocked(removeUnlockKey).mockResolvedValue({
      doc: { keyAgreement: [] },
      ladderVm: { struck: [], unclaimed: [stranded] }
    } as unknown as Awaited<ReturnType<typeof removeUnlockKey>>)

    const result = await retireUnlockCredential({
      idStore,
      updateKeys,
      unlockKeys: standingKeys(),
      rosterStore: memoryStore(),
      clientKeyAgreementKey: own.kak,
      collections
    })

    // A seedless strike that claimed nothing does not read as clean.
    expect(result.ladderVm).toEqual({ struck: [], unclaimed: [stranded] })
  })

  it('aborts before the document edit when the re-mint pass throws', async () => {
    const own = await makeRosterClient()
    stubPreEditLog([`${CONTROLLER_DID}#z6MkDoomedLadderVm`])
    const rosterStore = memoryStore()

    const refusal = await retireUnlockCredential({
      idStore,
      updateKeys,
      unlockKeys: standingKeys(),
      rosterStore,
      clientKeyAgreementKey: own.kak,
      collections,
      remintDependentRecords: async () => {
        throw new Error('a sibling record would not re-seal')
      }
    }).catch((err: unknown) => err)

    // Fail-closed: nothing published, nothing rotated, the credential still
    // standing -- the resting state a re-run converges from.
    expect(refusal).toBeInstanceOf(Error)
    expect((refusal as Error).message).toContain('would not re-seal')
    expect(vi.mocked(removeUnlockKey)).not.toHaveBeenCalled()
    expect(rosterStore.writes).toBe(0)
  })

  it('runs the pass with an empty list when no ladder VM stands, and skips it with no closure', async () => {
    const own = await makeRosterClient()
    stubPreEditLog([])
    const doc = { keyAgreement: [] }
    vi.mocked(removeUnlockKey).mockResolvedValue({
      doc
    } as unknown as Awaited<ReturnType<typeof removeUnlockKey>>)

    const lists: string[][] = []
    const withPass = await retireUnlockCredential({
      idStore,
      updateKeys,
      unlockKeys: standingKeys(),
      rosterStore: memoryStore(),
      clientKeyAgreementKey: own.kak,
      collections,
      remintDependentRecords: async ({ retiringKeyMultibases }) => {
        lists.push(retiringKeyMultibases)
        return undefined
      }
    })
    // Still called: the pass has an expiry axis of its own, so a near-lapse
    // sibling bridge is refreshed in the same window.
    expect(lists).toEqual([[]])
    expect('dependentRecords' in withPass).toBe(true)

    const without = await retireUnlockCredential({
      idStore,
      updateKeys,
      unlockKeys: standingKeys(),
      rosterStore: memoryStore(),
      clientKeyAgreementKey: own.kak,
      collections
    })
    expect('dependentRecords' in without).toBe(false)
    // The stage reads no log at all without a closure -- the no-WAS path.
    expect(vi.mocked(readPublishedLogOrThrow)).toHaveBeenCalledTimes(1)
  })

  it('anchors the roster at the post-edit document and converges on a re-run', async () => {
    const own = await makeRosterClient()
    const credential = await makeRosterClient()
    const userKey = await mintUserKey()

    // A log-governed roster store over a real in-memory log, with a mutable
    // controller view the stubbed inventory edit advances.
    const controllerRef: { current: WebvhResourceLogController } = {
      current: controllerFor([[own, credential]])
    }
    const log = memoryLogStore()
    const rosterStore = logGovernedDescriptorStore({
      log,
      resolveController: async () => controllerRef.current,
      pinStore: memoryResourceLogPinStore(),
      logId: ROSTER_LOG_ID,
      signer: own.logSigner
    })
    await ensureUserKeyRoster({
      store: rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak
    })
    const credentialKid = rosterRecipientKid({
      signingKeyMultibase: credential.signingKeyMultibase,
      keyAgreementKeyMultibase: credential.publicKeyMultibase
    })
    await addUserKeyRosterRecipient({
      store: rosterStore,
      recipient: {
        id: credentialKid,
        publicKeyMultibase: credential.publicKeyMultibase
      },
      ownerKeyAgreementKey: own.kak
    })
    const floorSpy = vi.spyOn(rosterStore, 'setControllerFloor')

    const doc = rosterDocumentFor([own])
    vi.mocked(removeUnlockKey).mockImplementation(async () => {
      // The inventory edit: the credential's key-agreement entry leaves at
      // version 2. A re-run finds it already settled and re-states the same
      // document and log.
      controllerRef.current = controllerFor([[own, credential], [own]])
      return {
        did: CONTROLLER_DID,
        doc,
        log: accountLogFor([[own, credential], [own]])
      } as unknown as Awaited<ReturnType<typeof removeUnlockKey>>
    })

    const result = await retireUnlockCredential({
      idStore,
      updateKeys,
      unlockKeys: standingKeys(),
      rosterStore,
      userKey,
      clientKeyAgreementKey: own.kak,
      collections
    })

    // The controller floor came from the edit's own post-edit log, so the
    // rotation anchored at the version that dropped the credential.
    expect(floorSpy).toHaveBeenCalledTimes(1)
    expect(result.rotated).toBe(true)
    expect(result.rosterSeal).toEqual({ outcome: 'noop' })
    const entries = log._getEntries()!
    expect(entries[entries.length - 1]!.proof[0]!.verificationMethod).toContain(
      '?versionId=2-v2'
    )

    // A naive full re-run converges: the inventory edit no-ops, and so does the
    // rotation -- every current-epoch recipient is document-backed already.
    const rerun = await retireUnlockCredential({
      idStore,
      updateKeys,
      unlockKeys: standingKeys(),
      rosterStore,
      userKey: result.userKey!,
      clientKeyAgreementKey: own.kak,
      collections
    })
    expect(rerun.rotated).toBe(false)
    expect(rerun.rosterSeal).toEqual({ outcome: 'noop' })
    expect(log._getEntries()!).toHaveLength(entries.length)
  })
})
