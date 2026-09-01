/**
 * Unit tests for the last-client forget (`src/clientAnnex/forgetLast.ts`)
 * over a real in-memory did:webvh account log, a real annex generation log,
 * and real epoch crypto: the strike-reinstall-revoke-remove shape (the
 * both-present transitional state visible to the pre-removal seam), the
 * ladder-signed one-append roster rotation anchored at the reinstall entry,
 * licensed over a roster head that already anchored at the pre-transition
 * version, the
 * history-walk revocations filtered to this ladder VM's still-unexpired
 * delegations, the forced ladder-signed delegation replacement, the other
 * unlock methods' ladder-signed record re-mint (the forgotten client named
 * as retiring; the re-sealed record's proof settling against the
 * post-removal document), convergence under a torn run's re-run, the
 * not-last refusal, and the honest generation skips (no pointer, uncommitted
 * rung).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { captureLogger } from '@interop/logger'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import {
  epochKeyIdFor,
  initRecipients,
  type EncryptionDescriptorStore
} from '@interop/was-client/edv'
import {
  defaultWebvhLogVerifier,
  deriveNextKeyHash,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import {
  forgetLastEnrolledClient,
  RecordRemintFailedError
} from '../../src/clientAnnex/forgetLast.js'
import {
  clientAnnexRung,
  generateLadderSeed,
  ladderRung,
  ladderVmKeyMultibase
} from '../../src/clientAnnex/ladder.js'
import {
  selfEnrollWebvhClient,
  strikeLadderVmWebvh
} from '../../src/clientAnnex/ladderAnchored.js'
import {
  createClientAnnexLog,
  embeddedGenerationDelegation,
  ensureGenerationDelegationCurrent,
  mintGenerationDelegation,
  mintGenerationId,
  setDelegatedClientsPointer
} from '../../src/clientAnnex/log.js'
import {
  ladderVmAgent,
  ladderVmZcapClient
} from '../../src/clientAnnex/zcap.js'
import { setLogger } from '../../src/log.js'
import { publishUnlockKey } from '../../src/unlock/standingWebvh.js'
import type {
  StandingUnlockKeys,
  UnlockLogStore
} from '../../src/unlock/standingWebvh.js'
import { mintUserKey } from '../../src/keys/userKey.js'
import {
  addUserKeyRosterRecipient,
  ensureUserKeyRoster,
  rosterRecipientKid,
  userKeyRosterLogSigner
} from '../../src/keys/userKeyRoster.js'
import { logGovernedDescriptorStore } from '../../src/keys/rosterLogStore.js'
import { userKeyRosterPinId } from '../../src/keys/rosterStore.js'
import {
  ResourceLogLicenseError,
  webvhResourceLogController
} from '../../src/resourceLog/index.js'
import { userKeyAsRecipient } from '../../src/keys/userKeyCascade.js'
import { ladderVmIds } from '../../src/resourceLog/document.js'
import type { DIDDoc, DIDLog } from '@interop/did-method-webvh'
import { delegationProofKeyId } from '../../src/webvh/standingZcap.js'
import {
  ensureDidWebvh,
  keyAgreementCommitment,
  mintClientWebvhUpdateKeys,
  putLogResource,
  updateKeyMultibase,
  updateKeySigner
} from '../../src/webvh/didWebvh.js'
import { relationIds } from '../../src/resourceLog/document.js'
import type { IZcap } from '@interop/data-integrity-core'
import {
  currentAccountRecordSigners,
  currentAccountSigningKeys
} from '../../src/clients/listing.js'
import type { VerifiedAccountLog } from '../../src/clients/listing.js'
import type { UnlockMethodsRemintReach } from '../../src/clientAnnex/forgetLast.js'
import {
  generateRecoveryCode,
  RECOVERY_KDF,
  recoveryClientFromCode
} from '../../src/recovery/recoveryCode.js'
import type { RecoveryDelegationEntry } from '../../src/recovery/recoveryDelegation.js'
import { deriveUnlockIdentity } from '../../src/keyring/kdf.js'
import { verifyRecordProof } from '../../src/keyring/record.js'
import { agentsFromSeed } from '../../src/identity/agents.js'
import {
  unwrapUnlockRecord,
  wrapUnlockRecord
} from '../../src/unlock/unlockRecord.js'
import {
  memoryResourceLogPinStore,
  parseVersionedVm,
  ResourceLogContinuityError
} from '@interop/vh-resource-log'
import { memoryLogStore } from '@interop/vh-resource-log/testing'
import { pinOfLog } from '../../src/webvh/didWebvh.js'
import { accountLogPinId } from '../../src/webvh/verifyLog.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'
import { truncatingLogStore } from './fixtures/truncatingLogStore.js'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-forget-last-ceremony'
const AUX_SPACE_ID = 'aux-space-forget-last'

/**
 * An in-memory descriptor store with a write counter and create-if-absent.
 *
 * @param [initial] {CollectionEncryption}
 * @returns {object}
 */
function memoryStore(
  initial?: CollectionEncryption
): EncryptionDescriptorStore & {
  state: { descriptor?: CollectionEncryption }
  writes: number
} {
  const holder = {
    state: { descriptor: initial },
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
 * A real X25519 key-agreement key in the self-describing did:key form.
 *
 * @returns {Promise<IKeyAgreementKey & { publicKeyMultibase: string }>}
 */
async function makeKak(): Promise<
  IKeyAgreementKey & { publicKeyMultibase: string }
> {
  const kak = await X25519KeyAgreementKey2020.generate()
  const did = `did:key:${kak.publicKeyMultibase}`
  kak.controller = did
  kak.id = `${did}#${kak.publicKeyMultibase}`
  return kak as IKeyAgreementKey & { publicKeyMultibase: string }
}

/**
 * The account log's pin slot for this suite's fixtures.
 */
const LOG_ID = accountLogPinId({ spaceId: SPACE_ID })

/**
 * A last-client account with the annex reach: a provisioned log whose ONLY
 * enrolled client is A, a bound standing credential (commitment
 * inventory, rung-0 hash committed), a pointed annex generation whose genesis
 * reveals this credential's annex rung, two embedded generation delegations
 * in the annex history (one signed by a FOREIGN ladder VM, then this
 * credential's own, which replaced it in the head entry), and a roster
 * wrapping the user key to the credential and to A.
 *
 * @param [options] {object}
 * @param [options.annexRungSeed] {Uint8Array}   the seed whose annex rung the
 *   generation's genesis reveals (defaults to the login credential's ladder
 *   seed; a different one makes the credential's rung uncommitted)
 * @param [options.withPointer] {boolean}
 * @returns {Promise<object>}
 */
async function forgetLastFixture(options?: {
  annexRungSeed?: Uint8Array
  withPointer?: boolean
}) {
  const withPointer = options?.withPointer ?? true
  const { idStore, log } = memoryIdStore()
  const updateKeys = await mintClientWebvhUpdateKeys()
  const { did } = await ensureDidWebvh({
    idStore,
    wasServerUrl: WAS_URL,
    spaceId: SPACE_ID,
    clientKeys: { ...CANONICAL_CLIENT_KEYS[0] },
    updateKeys
  })

  const ladderSeed = generateLadderSeed()
  const rung0 = await ladderRung({ ladderSeed, index: 0 })
  const credentialKak = await makeKak()
  const unlockKeys: StandingUnlockKeys = {
    keyAgreement: {
      commitment: await keyAgreementCommitment({
        keyAgreementKeyMultibase: credentialKak.publicKeyMultibase
      })
    },
    updateKeyMultibase: rung0.keyMultibase
  }
  await publishUnlockKey({ idStore, updateKeys, unlockKeys, ladderSeed })

  // The annex generation: genesis reveals the writing credential's rung.
  const generationId = mintGenerationId()
  const annexRungSeed = options?.annexRungSeed ?? ladderSeed
  const annexRung = await clientAnnexRung({
    ladderSeed: annexRungSeed,
    generationId
  })
  const created = await createClientAnnexLog({
    wasServerUrl: WAS_URL,
    spaceId: AUX_SPACE_ID,
    generationId,
    updateKeyPublicKeyMultibase: annexRung.keyMultibase,
    nextKeyHashes: [await deriveNextKeyHash(annexRung.keyMultibase)],
    signer: await updateKeySigner({ seed: annexRung.seed })
  })
  const annexFixture = memoryIdStore()
  await putLogResource({
    store: annexFixture.idStore,
    log: created.log,
    ifNoneMatch: true
  })

  // Two delegations into the history: a foreign ladder VM's first (standing
  // in for authority this credential's forget must NOT revoke), then this
  // credential's own, replacing it in the head service entry.
  const foreignSeed = generateLadderSeed()
  const foreignClient = await ladderVmZcapClient({
    accountDid: did,
    ladderSeed: foreignSeed
  })
  const foreign = await ensureGenerationDelegationCurrent({
    store: annexFixture.idStore,
    ladderSeed: annexRungSeed,
    generationId,
    mintGenerationDelegation: async ({ clientAnnexDid }) =>
      mintGenerationDelegation({
        zcapClient: foreignClient,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        clientAnnexDid
      }),
    expectedDid: created.did
  })
  const ownClient = await ladderVmZcapClient({ accountDid: did, ladderSeed })
  const own = await ensureGenerationDelegationCurrent({
    store: annexFixture.idStore,
    ladderSeed: annexRungSeed,
    generationId,
    mintGenerationDelegation: async ({ clientAnnexDid }) =>
      mintGenerationDelegation({
        zcapClient: ownClient,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        clientAnnexDid
      }),
    expectedDid: created.did,
    // The foreign VM's delegation is the one being replaced; naming it
    // retiring is what makes the healthy-looking standing entry stale.
    retiringKeyMultibases: [
      await ladderVmKeyMultibase({ ladderSeed: foreignSeed })
    ]
  })

  if (withPointer) {
    await setDelegatedClientsPointer({
      idStore,
      updateKeys,
      clientAnnexDid: created.did,
      expectedDid: did
    })
  }

  const userKey = await mintUserKey()
  const rosterStore = memoryStore()
  await ensureUserKeyRoster({
    store: rosterStore,
    userKey,
    clientKeyAgreementKey: credentialKak
  })
  const clientKeys = CANONICAL_CLIENT_KEYS[0]
  const forgottenKid = rosterRecipientKid({
    signingKeyMultibase: clientKeys.signingKeyMultibase,
    keyAgreementKeyMultibase: clientKeys.keyAgreementKeyMultibase
  })
  await addUserKeyRosterRecipient({
    store: rosterStore,
    recipient: {
      id: forgottenKid,
      publicKeyMultibase: clientKeys.keyAgreementKeyMultibase
    },
    ownerKeyAgreementKey: credentialKak
  })

  return {
    idStore,
    log,
    did,
    updateKeys,
    ladderSeed,
    credentialKak,
    userKey,
    rosterStore,
    forgottenKid,
    annexIdStore: annexFixture.idStore,
    annexLog: annexFixture.log,
    annexDid: created.did,
    generationId,
    foreignDelegationId: (foreign.delegation as { id?: string }).id!,
    ownDelegationId: (own.delegation as { id?: string }).id!,
    forgottenClient: {
      signingKeyMultibase: clientKeys.signingKeyMultibase,
      updateKeyMultibase: await updateKeyMultibase({
        seed: updateKeys.updateSeed
      })
    },
    forgottenKeyAgreementKeyMultibase: clientKeys.keyAgreementKeyMultibase
  }
}

/**
 * The ceremony's options with the fixture's wiring, overridable per test.
 */
function ceremonyOptions(
  fixture: Awaited<ReturnType<typeof forgetLastFixture>>,
  overrides?: {
    clientLogStore?: UnlockLogStore
    revoke?: (delegation: unknown) => Promise<void>
    collectionStore?: ReturnType<typeof memoryStore>
    onBeforeRemoval?: (published: { doc: object }) => Promise<void>
    unlockMethods?: UnlockMethodsRemintReach
    rosterStoreFor?: (options: {
      did: string
      log: DIDLog
    }) => EncryptionDescriptorStore
  }
) {
  const revokedIds: string[] = []
  const collectionStore = overrides?.collectionStore ?? memoryStore()
  const options: Parameters<typeof forgetLastEnrolledClient>[0] = {
    logStore: fixture.idStore,
    clientLogStore: overrides?.clientLogStore ?? fixture.idStore,
    ladderSeed: fixture.ladderSeed,
    forgottenClient: fixture.forgottenClient,
    forgottenKeyAgreementKeyMultibase:
      fixture.forgottenKeyAgreementKeyMultibase,
    expectedDid: fixture.did,
    rosterStoreFor: overrides?.rosterStoreFor ?? (() => fixture.rosterStore),
    credentialKeyAgreementKey: fixture.credentialKak,
    userKey: fixture.userKey,
    collections: {
      collectionIds: ['private-credentials'],
      storeFor: () => collectionStore
    },
    annex: {
      storeFor: () => fixture.annexIdStore,
      revoke:
        overrides?.revoke ??
        (async delegation => {
          revokedIds.push((delegation as { id: string }).id)
        }),
      wasServerUrl: WAS_URL,
      accountSpaceId: SPACE_ID
    },
    onBeforeRemoval: overrides?.onBeforeRemoval ?? (async () => {}),
    ...(overrides?.unlockMethods
      ? { unlockMethods: overrides.unlockMethods }
      : {})
  }
  return { options, revokedIds, collectionStore }
}

/**
 * The ceremony call with the fixture's wiring, overridable per test.
 */
async function runCeremony(
  fixture: Awaited<ReturnType<typeof forgetLastFixture>>,
  overrides?: Parameters<typeof ceremonyOptions>[1]
) {
  const { options, revokedIds, collectionStore } = ceremonyOptions(
    fixture,
    overrides
  )
  const result = await forgetLastEnrolledClient(options)
  return { result, revokedIds, collectionStore }
}

/**
 * Another unlock method's standing record and registry entry, its bridge and
 * `delegatedClients` sibling both signed by the forgotten client (the
 * ordinary bind-time state on a one-client account), plus the fetch stub
 * serving its unlock Space (GET the standing record, PUT captured).
 *
 * @param fixture {object}
 * @returns {Promise<object>}
 */
async function otherMethodFixture(
  fixture: Awaited<ReturnType<typeof forgetLastFixture>>
) {
  const code = generateRecoveryCode()
  const other = await recoveryClientFromCode({ code })
  const unlock = await deriveUnlockIdentity({
    secret: other.codeBytes,
    kdf: RECOVERY_KDF
  })
  const forgottenVm = `${fixture.did}#${fixture.forgottenClient.signingKeyMultibase}`
  const signedByForgotten = (id: string) =>
    ({ id, proof: { verificationMethod: forgottenVm } }) as unknown as IZcap
  const pointer = { did: fixture.did, spaceId: SPACE_ID, host: WAS_URL }
  const standingRecord = await wrapUnlockRecord({
    controller: fixture.did,
    pointer,
    delegation: signedByForgotten('urn:zcap:delegated:bridge-old'),
    delegatedClients: signedByForgotten('urn:zcap:delegated:sibling-old'),
    keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
    signer: unlock.recordSigner,
    bindingMacKey: other.bindingMacKey
  })
  // The still-standing client, invoking the entry's management zcap.
  const acting = await agentsFromSeed({ seed: new Uint8Array(32).fill(9) })
  const manageCapability = await unlock.zcapClient.delegate({
    invocationTarget: `${WAS_URL}/space/${unlock.spaceId}`,
    controller: acting.keyAgent.id,
    allowedActions: ['GET', 'PUT', 'DELETE']
  })
  const unlockKakPublic = unlock.keyAgreementKey as unknown as {
    id: string
    publicKeyMultibase: string
  }
  const farExpiry = new Date(
    Date.now() + 300 * 24 * 60 * 60 * 1000
  ).toISOString()
  const entry: RecoveryDelegationEntry = {
    label: 'Other method',
    unlockSpaceId: unlock.spaceId,
    manageCapability,
    delegationKeyId: forgottenVm,
    delegationExpires: farExpiry,
    delegatedClientsKeyId: forgottenVm,
    delegatedClientsExpires: farExpiry,
    recoveryClientDid: other.clientDid,
    unlockKeyAgreementKeyId: unlockKakPublic.id,
    unlockKeyAgreementKeyMultibase: unlockKakPublic.publicKeyMultibase
  }
  const puts: Array<{ url: string; body: unknown }> = []
  // While set, the unlock Space answers every record PUT with a 503 (the
  // zcap HTTP client retries a 503, so a single refused PUT would heal).
  const putFailure = { down: false }
  vi.stubGlobal(
    'fetch',
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const request =
        input instanceof Request ? input : new Request(input, init)
      if (request.method === 'GET') {
        return new Response(JSON.stringify(standingRecord), {
          status: 200,
          headers: { 'content-type': 'application/json' }
        })
      }
      if (request.method === 'PUT') {
        if (putFailure.down) {
          return new Response(null, { status: 503 })
        }
        puts.push({ url: request.url, body: await request.json() })
        return new Response(null, { status: 204 })
      }
      return new Response(null, { status: 405 })
    }
  )
  const recorded: RecoveryDelegationEntry[] = []
  const reach: UnlockMethodsRemintReach = {
    entries: [entry],
    pointer,
    storageServerUrl: WAS_URL,
    managementZcapClient: () => acting.zcapClient,
    recordEntry: async ({ entry: updated }) => {
      recorded.push(updated)
    }
  }
  return {
    other,
    unlock,
    pointer,
    entry,
    standingRecord,
    puts,
    putFailure,
    recorded,
    reach
  }
}

describe('forgetLastEnrolledClient', () => {
  // Several tests exercise a path that warns; a capture logger mutes the
  // fallback's console output the way the retired console spies did,
  // without asserting on it. vitest isolates modules per FILE, not per
  // test, so the restore in afterEach matters.
  let previousLogger: ReturnType<typeof setLogger>

  beforeEach(() => {
    previousLogger = setLogger(captureLogger().logger)
  })

  afterEach(() => {
    setLogger(previousLogger)
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('runs the transition: strike, reinstall, rotate, revoke, replace, remove', async () => {
    const fixture = await forgetLastFixture()
    const collectionStore = memoryStore()
    await initRecipients({
      store: collectionStore,
      recipients: [userKeyAsRecipient({ userKey: fixture.userKey })]
    })
    const entriesBefore = readLogFromString(fixture.log()!).length
    const rosterWritesBefore = fixture.rosterStore.writes
    const seamDocs: DIDDoc[] = []

    const { result, revokedIds } = await runCeremony(fixture, {
      collectionStore,
      onBeforeRemoval: async ({ doc }) => {
        seamDocs.push(doc as DIDDoc)
      }
    })

    // Three entries: the strike, the reinstall, and the removal.
    expect(result.reinstalled).toBe(true)
    const finalLog = readLogFromString(fixture.log()!)
    expect(finalLog.length).toBe(entriesBefore + 3)
    const resolved = await resolveDIDFromLog(finalLog, {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.meta.error).toBeUndefined()

    // The end state is the client-less, ladder-anchored account: the
    // client's whole inventory is out, the ladder VM stands under exactly
    // its two relations, and the rung is revealed with the client's update
    // key gone.
    const doc = resolved.doc as DIDDoc
    const ladderVmId = `${fixture.did}#${await ladderVmKeyMultibase({
      ladderSeed: fixture.ladderSeed
    })}`
    expect(relationIds(doc.capabilityInvocation)).toEqual([])
    expect(relationIds(doc.authentication)).toEqual([])
    expect(ladderVmIds({ doc })).toEqual([ladderVmId])
    expect(relationIds(doc.assertionMethod)).toContain(ladderVmId)
    const rung0 = await ladderRung({
      ladderSeed: fixture.ladderSeed,
      index: 0
    })
    expect(resolved.meta.updateKeys).toContain(rung0.keyMultibase)
    expect(resolved.meta.updateKeys).not.toContain(
      fixture.forgottenClient.updateKeyMultibase
    )

    // The pre-removal seam saw the both-present transitional state.
    expect(seamDocs).toHaveLength(1)
    const seamDoc = seamDocs[0]!
    expect(ladderVmIds({ doc: seamDoc })).toEqual([ladderVmId])
    expect(relationIds(seamDoc.capabilityInvocation)).toContain(
      `${fixture.did}#${fixture.forgottenClient.signingKeyMultibase}`
    )

    // The rotation was ONE append that retired the client's wrap; the fresh
    // key came back through the credential's standing wrap.
    expect(result.rotated).toBe(true)
    expect(fixture.rosterStore.writes).toBe(rosterWritesBefore + 1)
    expect(result.userKey!.id).not.toBe(fixture.userKey.id)
    const fresh = result.rosterDescriptor!.epochs!.find(
      epoch => epoch.id === result.rosterDescriptor!.currentEpoch
    )!
    expect(fresh.recipients.map(entry => entry.header.kid)).toEqual([
      fixture.credentialKak.id
    ])

    // The collection re-epoch'd onto the fresh key.
    expect(result.collections.outcomes['private-credentials']).toBe('rotated')
    const collectionEpoch = collectionStore.state.descriptor!.epochs!.find(
      epoch => epoch.id === collectionStore.state.descriptor!.currentEpoch
    )!
    expect(collectionEpoch.recipients.map(entry => entry.header.kid)).toContain(
      epochKeyIdFor(result.userKey!.id)
    )

    // The revocations covered exactly this ladder VM's history -- the
    // foreign delegation was left alone -- and the forced replacement left a
    // fresh ladder-signed delegation embedded.
    expect(result.generation.replaced).toBe(true)
    expect(result.generation.skipped).toBeUndefined()
    expect(revokedIds).toEqual([fixture.ownDelegationId])
    expect(result.generation.revoked).toEqual([fixture.ownDelegationId])
    const annexDoc = (
      await resolveDIDFromLog(readLogFromString(fixture.annexLog()!), {
        verifier: defaultWebvhLogVerifier
      })
    ).doc as DIDDoc
    const embedded = embeddedGenerationDelegation({ doc: annexDoc })!
    expect((embedded as { id?: string }).id).not.toBe(fixture.ownDelegationId)
    expect(delegationProofKeyId(embedded)).toBe(ladderVmId)

    // Calling again after completion is the finish-the-wipe state: nothing
    // runs, nothing is published.
    const again = await runCeremony(fixture)
    expect(again.result.reinstalled).toBe(false)
    expect(again.result.generation.skipped).toBe('already-removed')
    expect(readLogFromString(fixture.log()!).length).toBe(entriesBefore + 3)
  })

  it("ladder-signs the other unlock methods' records, the forgotten client named as retiring", async () => {
    const fixture = await forgetLastFixture()
    const method = await otherMethodFixture(fixture)
    const ladderVmId = `${fixture.did}#${await ladderVmKeyMultibase({
      ladderSeed: fixture.ladderSeed
    })}`

    const { result } = await runCeremony(fixture, {
      unlockMethods: method.reach
    })

    // The entry's bridge and sibling were signed by the forgotten client,
    // which the post-reinstall document still lists -- so only the retiring
    // axis marks them rotted. Both were re-minted in one pass, ladder-signed,
    // and the registry entry came back naming the ladder VM for both.
    expect(result.unlockMethods).toEqual({
      reminted: 1,
      skipped: 0,
      outcomes: [
        {
          label: 'Other method',
          unlockSpaceId: method.entry.unlockSpaceId,
          outcome: 'reminted'
        }
      ]
    })
    expect(method.recorded).toHaveLength(1)
    expect(method.recorded[0]!.delegationKeyId).toBe(ladderVmId)
    expect(method.recorded[0]!.delegatedClientsKeyId).toBe(ladderVmId)

    // The re-sealed record: binding verbatim, both fresh delegations inside
    // (the sibling targeting the pointed generation's annex Space), and the
    // frame signed by the ladder VM -- a mixed-signer proof that settles
    // against the POST-REMOVAL document through the record-signer allowlist
    // (the enrolled-client key set alone would refuse it, the account now
    // having no enrolled client).
    expect(method.puts).toHaveLength(1)
    const rewrapped = method.puts[0]!.body as Record<string, unknown>
    expect(rewrapped.binding).toBe(
      (method.standingRecord as unknown as { binding: string }).binding
    )
    const { contents, proofState } = await unwrapUnlockRecord({
      record: rewrapped,
      keyAgreementKey: method.unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: method.unlock.keyResolver,
      expectedKeyMultibase: method.unlock.recordSigner.keyMultibase,
      bindingMacKey: method.other.bindingMacKey
    })
    expect(contents.pointer).toEqual(method.pointer)
    expect(delegationProofKeyId(contents.delegation)).toBe(ladderVmId)
    expect(delegationProofKeyId(contents.delegatedClients!)).toBe(ladderVmId)
    expect(
      (contents.delegatedClients as { invocationTarget?: string })
        .invocationTarget
    ).toContain(`/space/${AUX_SPACE_ID}/`)
    expect(proofState).not.toBe('verified')

    const finalLog = readLogFromString(fixture.log()!)
    const resolved = await resolveDIDFromLog(finalLog, {
      verifier: defaultWebvhLogVerifier
    })
    const verifiedLog: VerifiedAccountLog = {
      doc: resolved.doc as DIDDoc,
      log: finalLog,
      updateKeys: resolved.meta.updateKeys ?? [],
      nextKeyHashes: resolved.meta.nextKeyHashes ?? []
    }
    const signers = await currentAccountRecordSigners({
      pointer: method.pointer,
      verifiedLog
    })
    expect([...signers]).toEqual([
      await ladderVmKeyMultibase({
        ladderSeed: fixture.ladderSeed
      })
    ])
    expect(
      await currentAccountSigningKeys({ pointer: method.pointer, verifiedLog })
    ).toEqual(new Set())
    await expect(
      verifyRecordProof({
        record: rewrapped,
        allowedKeyMultibases: [...signers],
        label: 'unlock'
      })
    ).resolves.toBeDefined()
  })

  it('refuses the removal entry over a failed record re-mint, and the re-run completes it', async () => {
    const fixture = await forgetLastFixture()
    const method = await otherMethodFixture(fixture)
    const entriesBefore = readLogFromString(fixture.log()!).length
    const forgottenVmId = `${fixture.did}#${fixture.forgottenClient.signingKeyMultibase}`

    // The other method's unlock Space is down for the first run.
    method.putFailure.down = true
    let refusal: RecordRemintFailedError | undefined
    try {
      await runCeremony(fixture, { unlockMethods: method.reach })
    } catch (err) {
      refusal = err as RecordRemintFailedError
    }
    expect(refusal?.name).toBe('RecordRemintFailedError')
    expect(refusal!.failed.map(outcome => outcome.label)).toEqual([
      'Other method'
    ])
    expect(refusal!.failed[0]!.error).toBeDefined()
    expect(refusal!.unlockMethods.reminted).toBe(0)
    expect(refusal!.unlockMethods.skipped).toBe(1)
    expect(refusal!.message).toContain('"Other method"')
    expect(method.puts).toHaveLength(0)
    expect(method.recorded).toHaveLength(0)

    // Only the strike and reinstall entries landed: the client still stands
    // and can still invoke, and the removal entry was not published.
    const tornLog = readLogFromString(fixture.log()!)
    expect(tornLog.length).toBe(entriesBefore + 2)
    const torn = await resolveDIDFromLog(tornLog, {
      verifier: defaultWebvhLogVerifier
    })
    expect(relationIds((torn.doc as DIDDoc).capabilityInvocation)).toEqual([
      forgottenVmId
    ])

    // The re-run resumes at the re-mint (the entry still names the
    // forgotten client, so it is still rotted), then lands the removal.
    method.putFailure.down = false
    const { result } = await runCeremony(fixture, {
      unlockMethods: method.reach
    })
    expect(result.reinstalled).toBe(false)
    expect(result.unlockMethods).toEqual({
      reminted: 1,
      skipped: 0,
      outcomes: [
        {
          label: 'Other method',
          unlockSpaceId: method.entry.unlockSpaceId,
          outcome: 'reminted'
        }
      ]
    })
    expect(method.puts).toHaveLength(1)
    expect(method.recorded).toHaveLength(1)
    const finalLog = readLogFromString(fixture.log()!)
    expect(finalLog.length).toBe(entriesBefore + 3)
    const resolved = await resolveDIDFromLog(finalLog, {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.meta.error).toBeUndefined()
    expect(relationIds((resolved.doc as DIDDoc).capabilityInvocation)).toEqual(
      []
    )
  })

  it('withholds the removal entry over a pending-shaped registry entry', async () => {
    const fixture = await forgetLastFixture()
    const method = await otherMethodFixture(fixture)
    const entriesBefore = readLogFromString(fixture.log()!).length
    const forgottenVmId = `${fixture.did}#${fixture.forgottenClient.signingKeyMultibase}`

    // The entry's identity members name a credential other than the one its
    // record is sealed to -- a passphrase change torn before its retirement.
    // The pass writes nothing for it, and the removal is refused: after the
    // removal nothing could ever re-sign that record's bridge, and the only
    // mender of the pending state is a remembered login.
    let refusal: RecordRemintFailedError | undefined
    try {
      await runCeremony(fixture, {
        unlockMethods: {
          ...method.reach,
          entries: [
            {
              ...method.entry,
              unlockKeyAgreementKeyMultibase: 'zOtherCredentialKak'
            }
          ]
        }
      })
    } catch (err) {
      refusal = err as RecordRemintFailedError
    }
    expect(refusal?.name).toBe('RecordRemintFailedError')
    expect(refusal!.failed.map(outcome => outcome.outcome)).toEqual([
      'pending-entry'
    ])
    expect(refusal!.message).toContain('"Other method"')
    expect(method.puts).toHaveLength(0)
    expect(method.recorded).toHaveLength(0)

    // Only the strike and reinstall entries landed; the client still stands.
    const tornLog = readLogFromString(fixture.log()!)
    expect(tornLog.length).toBe(entriesBefore + 2)
    const torn = await resolveDIDFromLog(tornLog, {
      verifier: defaultWebvhLogVerifier
    })
    expect(relationIds((torn.doc as DIDDoc).capabilityInvocation)).toEqual([
      forgottenVmId
    ])
  })

  it('converges on re-run after a run torn at the revocation POST', async () => {
    const fixture = await forgetLastFixture()
    const entriesBefore = readLogFromString(fixture.log()!).length

    // First run: the revocation POST dies (a network flap, rethrown
    // unchanged) AFTER the strike and reinstall entries, the rotation, and
    // the forced replacement have landed.
    await expect(
      runCeremony(fixture, {
        revoke: async () => {
          const err = new Error('connection reset')
          err.name = 'NetworkError'
          throw err
        }
      })
    ).rejects.toThrow('connection reset')
    const rosterWritesAfterTear = fixture.rosterStore.writes
    const entriesAfterTear = readLogFromString(fixture.log()!).length

    // Re-run: the strike-and-reinstall pair is skipped, no second roster
    // append is attempted,
    // the prior run's fresh delegation is revoked as history (with the torn
    // run's own target re-POSTed blind -- here answered already-revoked),
    // and the removal entry lands.
    const validationError = new Error('already revoked')
    validationError.name = 'ValidationError'
    const seen: string[] = []
    const { result } = await runCeremony(fixture, {
      revoke: async delegation => {
        seen.push((delegation as { id: string }).id)
        if ((delegation as { id: string }).id === fixture.ownDelegationId) {
          throw validationError
        }
      }
    })

    expect(result.reinstalled).toBe(false)
    expect(fixture.rosterStore.writes).toBe(rosterWritesAfterTear)
    expect(result.rotated).toBe(false)
    expect(seen).toContain(fixture.ownDelegationId)
    expect(seen).not.toContain(fixture.foreignDelegationId)
    // The torn run's replacement delegation is in the doomed set now; the
    // re-run's own replacement stays embedded.
    expect(seen.length).toBe(2)
    expect(result.generation.replaced).toBe(true)
    // The rotation is no longer owed, so the re-run publishes no second
    // strike-and-reinstall pair: the removal entry alone.
    expect(readLogFromString(fixture.log()!).length).toBe(entriesAfterTear + 1)
    expect(readLogFromString(fixture.log()!).length).toBe(entriesBefore + 3)
    const resolved = await resolveDIDFromLog(
      readLogFromString(fixture.log()!),
      {
        verifier: defaultWebvhLogVerifier
      }
    )
    expect(resolved.meta.error).toBeUndefined()
    expect(relationIds((resolved.doc as DIDDoc).capabilityInvocation)).toEqual(
      []
    )
  })

  it('refuses a call without the record re-bind seam before any read', async () => {
    const fixture = await forgetLastFixture()
    const entriesBefore = readLogFromString(fixture.log()!).length
    const rosterWritesBefore = fixture.rosterStore.writes
    const { onBeforeRemoval: _omitted, ...withoutSeam } =
      ceremonyOptions(fixture).options

    await expect(
      forgetLastEnrolledClient(
        withoutSeam as Parameters<typeof forgetLastEnrolledClient>[0]
      )
    ).rejects.toThrow(/onBeforeRemoval/)
    expect(readLogFromString(fixture.log()!).length).toBe(entriesBefore)
    expect(fixture.rosterStore.writes).toBe(rosterWritesBefore)
  })

  it('refuses when another enrolled client remains', async () => {
    const fixture = await forgetLastFixture()
    const enrolledSeeds = await mintClientWebvhUpdateKeys()
    const enrolledKeys = {
      ...CANONICAL_CLIENT_KEYS[3]!,
      updateKeyMultibase: await updateKeyMultibase({
        seed: enrolledSeeds.updateSeed
      }),
      stagedUpdateKeyMultibase: await updateKeyMultibase({
        seed: enrolledSeeds.stagedSeed
      })
    }
    await selfEnrollWebvhClient({
      store: fixture.idStore,
      ladderSeed: fixture.ladderSeed,
      newClientKeys: enrolledKeys,
      newClientUpdateSeeds: enrolledSeeds,
      onCommitted: async () => {},
      expectedDid: fixture.did
    })
    const entriesBefore = readLogFromString(fixture.log()!).length

    await expect(runCeremony(fixture)).rejects.toThrow(/ordinary forget/)
    expect(readLogFromString(fixture.log()!).length).toBe(entriesBefore)
  })

  it('completes with the generation stage skipped on an unpointed account', async () => {
    const fixture = await forgetLastFixture({ withPointer: false })
    const entriesBefore = readLogFromString(fixture.log()!).length

    const { result, revokedIds } = await runCeremony(fixture)

    expect(result.generation).toEqual({
      revoked: [],
      replaced: false,
      skipped: 'no-pointer'
    })
    expect(revokedIds).toEqual([])
    expect(result.rotated).toBe(true)
    expect(readLogFromString(fixture.log()!).length).toBe(entriesBefore + 3)
  })

  it('revokes but reports the honest skip when the annex rung is uncommitted', async () => {
    // The generation's genesis committed a DIFFERENT credential's rung, so
    // this credential cannot write the replacement entry -- the doomed
    // revocations still run, and the ceremony completes.
    const fixture = await forgetLastFixture({
      annexRungSeed: generateLadderSeed()
    })

    const { result, revokedIds } = await runCeremony(fixture)

    expect(result.generation.replaced).toBe(false)
    expect(result.generation.skipped).toBe('rung-uncommitted')
    expect(revokedIds).toEqual([fixture.ownDelegationId])
    const resolved = await resolveDIDFromLog(
      readLogFromString(fixture.log()!),
      {
        verifier: defaultWebvhLogVerifier
      }
    )
    expect(relationIds((resolved.doc as DIDDoc).capabilityInvocation)).toEqual(
      []
    )
  })
  it('advances the chain-head pin to the removal entry it published', async () => {
    const fixture = await forgetLastFixture()
    const pinStore = memoryResourceLogPinStore()
    const { options } = ceremonyOptions(fixture)

    await forgetLastEnrolledClient({ ...options, pinStore })

    // The strike and reinstall entries advanced the pin first; the removal
    // entry's head is what stands afterwards.
    expect(await pinStore.read({ logId: LOG_ID })).toEqual(
      pinOfLog(readLogFromString(fixture.log()!))
    )
  })

  it('refuses a served prefix of the pinned log before anything is published', async () => {
    const fixture = await forgetLastFixture()
    const pinStore = memoryResourceLogPinStore()
    await pinStore.write({
      logId: LOG_ID,
      pin: pinOfLog(readLogFromString(fixture.log()!))
    })
    const { store } = truncatingLogStore({
      idStore: fixture.idStore,
      dropEntries: 1
    })
    const { options } = ceremonyOptions(fixture)
    const writesBefore = fixture.rosterStore.writes
    const logBefore = fixture.log()

    let caught: unknown
    try {
      await forgetLastEnrolledClient({ ...options, logStore: store, pinStore })
    } catch (err) {
      caught = err
    }

    expect(caught).toBeInstanceOf(ResourceLogContinuityError)
    expect((caught as ResourceLogContinuityError).reason).toBe('rollback')
    expect(fixture.rosterStore.writes).toBe(writesBefore)
    expect(fixture.log()).toBe(logBefore)
  })

  it('refuses a prefix served only to the strike entry read', async () => {
    const fixture = await forgetLastFixture()
    const pinStore = memoryResourceLogPinStore()
    await pinStore.write({
      logId: LOG_ID,
      pin: pinOfLog(readLogFromString(fixture.log()!))
    })
    // The orchestrator's pre-read sees the full log; the strike entry's own
    // read inside the conflict-retry loop is served the prefix -- and the
    // strike entry is the ceremony's first write of any kind.
    const { store, counter } = truncatingLogStore({
      idStore: fixture.idStore,
      dropEntries: 1,
      fromRead: 2
    })
    const { options } = ceremonyOptions(fixture)
    const writesBefore = fixture.rosterStore.writes
    const logBefore = fixture.log()

    let caught: unknown
    try {
      await forgetLastEnrolledClient({
        ...options,
        logStore: store,
        clientLogStore: store,
        pinStore
      })
    } catch (err) {
      caught = err
    }

    expect(caught).toBeInstanceOf(ResourceLogContinuityError)
    expect((caught as ResourceLogContinuityError).reason).toBe('rollback')
    expect(counter.reads).toBeGreaterThan(1)
    expect(fixture.rosterStore.writes).toBe(writesBefore)
    expect(fixture.log()).toBe(logBefore)
  })

  it("strikes and reinstalls only this credential's ladder VM", async () => {
    const fixture = await forgetLastFixture()
    // A second standing credential, bound the way the first was: its own
    // ladder seed, its own VM in the document.
    const otherSeed = generateLadderSeed()
    const otherRung0 = await ladderRung({ ladderSeed: otherSeed, index: 0 })
    const otherKak = await makeKak()
    await publishUnlockKey({
      idStore: fixture.idStore,
      updateKeys: fixture.updateKeys,
      unlockKeys: {
        keyAgreement: {
          commitment: await keyAgreementCommitment({
            keyAgreementKeyMultibase: otherKak.publicKeyMultibase
          })
        },
        updateKeyMultibase: otherRung0.keyMultibase
      },
      ladderSeed: otherSeed
    })
    const ownVmId = `${fixture.did}#${await ladderVmKeyMultibase({
      ladderSeed: fixture.ladderSeed
    })}`
    const otherVmId = `${fixture.did}#${await ladderVmKeyMultibase({
      ladderSeed: otherSeed
    })}`
    const entriesBefore = readLogFromString(fixture.log()!).length

    const { result } = await runCeremony(fixture)

    expect(result.reinstalled).toBe(true)
    const finalLog = readLogFromString(fixture.log()!)
    expect(finalLog.length).toBe(entriesBefore + 3)
    const strikeDoc = finalLog[finalLog.length - 3]!.state as DIDDoc
    const reinstallDoc = finalLog[finalLog.length - 2]!.state as DIDDoc

    // The strike entry took THIS credential's VM out and left the other
    // credential's standing.
    expect(ladderVmIds({ doc: strikeDoc })).toEqual([otherVmId])
    expect(relationIds(strikeDoc.assertionMethod)).not.toContain(ownVmId)
    expect(relationIds(strikeDoc.capabilityDelegation)).not.toContain(ownVmId)

    // The reinstall entry republished the IDENTICAL id under exactly the two
    // relations a ladder VM carries.
    expect(ladderVmIds({ doc: reinstallDoc })).toContain(ownVmId)
    expect(relationIds(reinstallDoc.assertionMethod)).toContain(ownVmId)
    expect(relationIds(reinstallDoc.capabilityDelegation)).toContain(ownVmId)
    expect(relationIds(reinstallDoc.capabilityInvocation)).not.toContain(
      ownVmId
    )
    expect(relationIds(reinstallDoc.authentication)).not.toContain(ownVmId)

    // The other credential's VM came through the whole transition untouched.
    const resolved = await resolveDIDFromLog(finalLog, {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.meta.error).toBeUndefined()
    expect([...ladderVmIds({ doc: resolved.doc as DIDDoc })].sort()).toEqual(
      [ownVmId, otherVmId].sort()
    )
  })

  it('leaves a generation delegation a surviving sibling ladder signed', async () => {
    const fixture = await forgetLastFixture()
    // A second standing credential, and the annex head service entry moved
    // onto ITS delegation -- authority this transition neither revokes nor
    // replaces, since the sibling's VM outlives the ceremony.
    const siblingSeed = generateLadderSeed()
    const siblingRung0 = await ladderRung({ ladderSeed: siblingSeed, index: 0 })
    const siblingKak = await makeKak()
    await publishUnlockKey({
      idStore: fixture.idStore,
      updateKeys: fixture.updateKeys,
      unlockKeys: {
        keyAgreement: {
          commitment: await keyAgreementCommitment({
            keyAgreementKeyMultibase: siblingKak.publicKeyMultibase
          })
        },
        updateKeyMultibase: siblingRung0.keyMultibase
      },
      ladderSeed: siblingSeed
    })
    const siblingClient = await ladderVmZcapClient({
      accountDid: fixture.did,
      ladderSeed: siblingSeed
    })
    const sibling = await ensureGenerationDelegationCurrent({
      store: fixture.annexIdStore,
      ladderSeed: fixture.ladderSeed,
      generationId: fixture.generationId,
      mintGenerationDelegation: async ({ clientAnnexDid }) =>
        mintGenerationDelegation({
          zcapClient: siblingClient,
          wasServerUrl: WAS_URL,
          spaceId: SPACE_ID,
          clientAnnexDid
        }),
      expectedDid: fixture.annexDid,
      retiringKeyMultibases: [
        await ladderVmKeyMultibase({ ladderSeed: fixture.ladderSeed })
      ]
    })
    const siblingDelegationId = (sibling.delegation as { id: string }).id
    const annexEntriesBefore = readLogFromString(fixture.annexLog()!).length

    const { result, revokedIds } = await runCeremony(fixture)

    // Nothing was owed, so nothing was written: no replacement, no reason.
    expect(result.generation.replaced).toBe(false)
    expect(result.generation.skipped).toBeUndefined()
    expect(readLogFromString(fixture.annexLog()!).length).toBe(
      annexEntriesBefore
    )
    // And the revocation loop reaches only this credential's own past
    // delegation, never the sibling's standing one.
    expect(revokedIds).toEqual([fixture.ownDelegationId])
    expect(revokedIds).not.toContain(siblingDelegationId)
  })

  it("publishes the pair under the client's authority, so a ladder-signed bridge cannot brick it", async () => {
    const fixture = await forgetLastFixture()
    const ladderVmId = `${fixture.did}#${await ladderVmKeyMultibase({
      ladderSeed: fixture.ladderSeed
    })}`
    // The bridge as the readiness stage and stage 6 leave it: signed by this
    // credential's ladder VM, so the server authorizes its PUTs only while
    // that VM stands under `capabilityDelegation`. The strike removes it, so
    // a bridge-published reinstall would be refused and the account would be
    // left VM-less with no way back.
    const bridge: UnlockLogStore = {
      getIdResourceRaw: options => fixture.idStore.getIdResourceRaw(options),
      putIdResource: async options => {
        const served = fixture.log()
        if (served !== undefined) {
          const entries = readLogFromString(served)
          const doc = entries[entries.length - 1]!.state as DIDDoc
          if (!relationIds(doc.capabilityDelegation).includes(ladderVmId)) {
            throw new Error(
              'NotAllowedError: the bridge delegation no longer verifies ' +
                'against the current document.'
            )
          }
        }
        return fixture.idStore.putIdResource(options)
      }
    }

    const { options } = ceremonyOptions(fixture)
    const result = await forgetLastEnrolledClient({
      ...options,
      logStore: bridge
    })

    expect(result.reinstalled).toBe(true)
    const resolved = await resolveDIDFromLog(
      readLogFromString(fixture.log()!),
      {
        verifier: defaultWebvhLogVerifier
      }
    )
    expect(resolved.meta.error).toBeUndefined()
    expect(ladderVmIds({ doc: resolved.doc as DIDDoc })).toEqual([ladderVmId])
    expect(relationIds((resolved.doc as DIDDoc).capabilityInvocation)).toEqual(
      []
    )
  })

  it('refuses a call without the client-authority log store before any read', async () => {
    const fixture = await forgetLastFixture()
    const entriesBefore = readLogFromString(fixture.log()!).length
    const { clientLogStore: _omitted, ...withoutStore } =
      ceremonyOptions(fixture).options

    await expect(
      forgetLastEnrolledClient(
        withoutStore as Parameters<typeof forgetLastEnrolledClient>[0]
      )
    ).rejects.toThrow(/clientLogStore/)
    expect(readLogFromString(fixture.log()!).length).toBe(entriesBefore)
  })

  it('converges on re-run after a run torn between the strike and the reinstall', async () => {
    const fixture = await forgetLastFixture()
    const entriesBefore = readLogFromString(fixture.log()!).length
    const ladderVmId = `${fixture.did}#${await ladderVmKeyMultibase({
      ladderSeed: fixture.ladderSeed
    })}`

    // The tear: the strike entry landed and the reinstall never ran, so the
    // account stands VM-less with the client still enrolled.
    const struck = await strikeLadderVmWebvh({
      store: fixture.idStore,
      ladderSeed: fixture.ladderSeed,
      expectedDid: fixture.did
    })
    expect(struck.struck).toBe(true)
    expect(ladderVmIds({ doc: struck.doc })).toEqual([])

    // The re-run's strike no-ops on the missing VM and the reinstall
    // converges, so the transition completes with one entry fewer.
    const { result } = await runCeremony(fixture)

    expect(result.reinstalled).toBe(true)
    const finalLog = readLogFromString(fixture.log()!)
    expect(finalLog.length).toBe(entriesBefore + 3)
    const resolved = await resolveDIDFromLog(finalLog, {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.meta.error).toBeUndefined()
    expect(ladderVmIds({ doc: resolved.doc as DIDDoc })).toEqual([ladderVmId])
    expect(relationIds((resolved.doc as DIDDoc).capabilityInvocation)).toEqual(
      []
    )
  })

  it('anchors the ladder-signed rotation at the reinstall version, over a roster head that already anchored at the pre-transition version', async () => {
    const fixture = await forgetLastFixture()
    const ladderVmKey = await ladderVmKeyMultibase({
      ladderSeed: fixture.ladderSeed
    })

    // The roster over a REAL log, governed by the account document: the
    // ceremony-tail license runs on every append this test makes.
    const rosterLog = memoryLogStore()
    const rosterPins = memoryResourceLogPinStore()
    const ladderSigner = userKeyRosterLogSigner({
      keyAgent: await ladderVmAgent({ ladderSeed: fixture.ladderSeed })
    })
    const rosterStoreFor = ({ did, log }: { did: string; log: DIDLog }) =>
      logGovernedDescriptorStore({
        log: rosterLog,
        resolveController: async () => webvhResourceLogController({ did, log }),
        pinStore: rosterPins,
        logId: userKeyRosterPinId({ spaceId: SPACE_ID }),
        signer: ladderSigner
      })
    const currentLog = () => readLogFromString(fixture.log()!)
    const storeNow = () =>
      rosterStoreFor({ did: fixture.did, log: currentLog() })

    // The genesis append (the license's first-entry shape).
    await ensureUserKeyRoster({
      store: storeNow(),
      userKey: fixture.userKey,
      clientKeyAgreementKey: fixture.credentialKak
    })

    // A second credential's bind changes the inventory, which licenses the
    // client's wrap as a second ladder-signed append -- and leaves the roster
    // head anchored at the account document's CURRENT version, the state
    // that would foreclose the transition if the transition had no entry of
    // its own to anchor at.
    const otherSeed = generateLadderSeed()
    const otherRung0 = await ladderRung({ ladderSeed: otherSeed, index: 0 })
    const otherKak = await makeKak()
    await publishUnlockKey({
      idStore: fixture.idStore,
      updateKeys: fixture.updateKeys,
      unlockKeys: {
        keyAgreement: {
          commitment: await keyAgreementCommitment({
            keyAgreementKeyMultibase: otherKak.publicKeyMultibase
          })
        },
        updateKeyMultibase: otherRung0.keyMultibase
      },
      ladderSeed: otherSeed
    })
    await addUserKeyRosterRecipient({
      store: storeNow(),
      recipient: {
        id: fixture.forgottenKid,
        publicKeyMultibase: fixture.forgottenKeyAgreementKeyMultibase
      },
      ownerKeyAgreementKey: fixture.credentialKak
    })
    const preTransitionHead = currentLog()[currentLog().length - 1]!.versionId
    expect(
      parseVersionedVm(
        rosterLog._getEntries()![1]!.proof[0]!.verificationMethod
      )?.controllerVersionId
    ).toBe(preTransitionHead)

    const { result } = await runCeremony(fixture, { rosterStoreFor })

    expect(result.reinstalled).toBe(true)
    expect(result.rotated).toBe(true)

    // The rotation is one further append, anchored at the REINSTALL entry's
    // version -- a version the reinstall made inventory-changing, and one no
    // earlier append had reached -- and signed by the ladder VM the
    // post-removal document still lists.
    const rosterEntries = rosterLog._getEntries()!
    expect(rosterEntries).toHaveLength(3)
    const finalLog = readLogFromString(fixture.log()!)
    const reinstallVersion = finalLog[finalLog.length - 2]!.versionId
    const rotationVm = parseVersionedVm(
      rosterEntries[2]!.proof[0]!.verificationMethod
    )!
    expect(rotationVm.controllerVersionId).toBe(reinstallVersion)
    expect(rotationVm.keyMultibase).toBe(ladderVmKey)
    const resolved = await resolveDIDFromLog(finalLog, {
      verifier: defaultWebvhLogVerifier
    })
    expect(relationIds((resolved.doc as DIDDoc).assertionMethod)).toContain(
      `${fixture.did}#${ladderVmKey}`
    )
  })

  it("converges after a sibling ladder's spend at the reinstall version", async () => {
    // The pair mints a shot at the strike version and another at the
    // reinstall version. A sibling credential's ladder spends the reinstall
    // one -- the only spend that reaches the transition's rotation -- so the
    // run is foreclosed with a license refusal. It is not wedged: the client
    // still stands in the document, so it is still a recipient of the
    // sibling's epoch, `wrapped` stays true, and a re-run republishes the
    // pair to mint a fresh anchor.
    const fixture = await forgetLastFixture()
    const ladderVmKey = await ladderVmKeyMultibase({
      ladderSeed: fixture.ladderSeed
    })
    const ladderVmId = `${fixture.did}#${ladderVmKey}`

    const rosterLog = memoryLogStore()
    const rosterPins = memoryResourceLogPinStore()
    const currentLog = () => readLogFromString(fixture.log()!)
    const ownSigner = userKeyRosterLogSigner({
      keyAgent: await ladderVmAgent({ ladderSeed: fixture.ladderSeed })
    })
    const siblingSeed = generateLadderSeed()
    const siblingSigner = userKeyRosterLogSigner({
      keyAgent: await ladderVmAgent({ ladderSeed: siblingSeed })
    })
    const storeFor = (
      signer: ReturnType<typeof userKeyRosterLogSigner>,
      { did, log }: { did: string; log: DIDLog }
    ) =>
      logGovernedDescriptorStore({
        log: rosterLog,
        resolveController: async () => webvhResourceLogController({ did, log }),
        pinStore: rosterPins,
        logId: userKeyRosterPinId({ spaceId: SPACE_ID }),
        signer
      })

    // The genesis append, then the sibling credential's bind (an inventory
    // change of its own) licensing the client's wrap as a second append.
    await ensureUserKeyRoster({
      store: storeFor(ownSigner, { did: fixture.did, log: currentLog() }),
      userKey: fixture.userKey,
      clientKeyAgreementKey: fixture.credentialKak
    })
    const siblingRung0 = await ladderRung({ ladderSeed: siblingSeed, index: 0 })
    const siblingKak = await makeKak()
    await publishUnlockKey({
      idStore: fixture.idStore,
      updateKeys: fixture.updateKeys,
      unlockKeys: {
        keyAgreement: {
          commitment: await keyAgreementCommitment({
            keyAgreementKeyMultibase: siblingKak.publicKeyMultibase
          })
        },
        updateKeyMultibase: siblingRung0.keyMultibase
      },
      ladderSeed: siblingSeed
    })
    await addUserKeyRosterRecipient({
      store: storeFor(ownSigner, { did: fixture.did, log: currentLog() }),
      recipient: {
        id: fixture.forgottenKid,
        publicKeyMultibase: fixture.forgottenKeyAgreementKeyMultibase
      },
      ownerKeyAgreementKey: fixture.credentialKak
    })

    // The race: the first store the ceremony builds over a log the pair has
    // extended fires the sibling's licensed append at the reinstall version,
    // before the rotation the ceremony is about to attempt.
    const extraKak = await makeKak()
    const preRunLength = currentLog().length
    let spent = false
    const rosterStoreFor = ({ did, log }: { did: string; log: DIDLog }) => {
      const store = storeFor(ownSigner, { did, log })
      return {
        ...store,
        async read() {
          if (!spent && log.length > preRunLength) {
            spent = true
            await addUserKeyRosterRecipient({
              store: storeFor(siblingSigner, { did, log }),
              recipient: {
                id: 'urn:sibling-reader',
                publicKeyMultibase: extraKak.publicKeyMultibase
              },
              ownerKeyAgreementKey: fixture.credentialKak
            })
          }
          return store.read()
        }
      } as EncryptionDescriptorStore
    }

    await expect(
      runCeremony(fixture, { rosterStoreFor })
    ).rejects.toBeInstanceOf(ResourceLogLicenseError)
    expect(spent).toBe(true)

    // The foreclosed run's residue is the both-entries-published state a tear
    // leaves: the pair stands, the client is still enrolled.
    const afterFirst = currentLog()
    expect(afterFirst.length).toBe(preRunLength + 2)
    const midResolved = await resolveDIDFromLog(afterFirst, {
      verifier: defaultWebvhLogVerifier
    })
    expect(midResolved.meta.error).toBeUndefined()
    expect(ladderVmIds({ doc: midResolved.doc as DIDDoc })).toContain(
      ladderVmId
    )
    expect(
      relationIds((midResolved.doc as DIDDoc).capabilityInvocation)
    ).toEqual([`${fixture.did}#${fixture.forgottenClient.signingKeyMultibase}`])

    // The re-run converges: a fresh pair, a licensed rotation anchored at the
    // fresh reinstall entry, then the removal.
    const { result } = await runCeremony(fixture, { rosterStoreFor })
    expect(result.reinstalled).toBe(true)
    expect(result.rotated).toBe(true)
    const finalLog = currentLog()
    expect(finalLog.length).toBe(afterFirst.length + 3)
    const resolved = await resolveDIDFromLog(finalLog, {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.meta.error).toBeUndefined()
    expect(relationIds((resolved.doc as DIDDoc).capabilityInvocation)).toEqual(
      []
    )
    expect(ladderVmIds({ doc: resolved.doc as DIDDoc })).toContain(ladderVmId)

    // Two entries of the re-run's three precede the removal: the rotation
    // anchors at the second-to-last entry, this run's reinstall.
    const rosterEntries = rosterLog._getEntries()!
    expect(rosterEntries).toHaveLength(4)
    const rotationVm = parseVersionedVm(
      rosterEntries[3]!.proof[0]!.verificationMethod
    )!
    expect(rotationVm.keyMultibase).toBe(ladderVmKey)
    expect(rotationVm.controllerVersionId).toBe(
      finalLog[finalLog.length - 2]!.versionId
    )

    // The forgotten client is out of the current epoch.
    const finalRoster = await storeFor(ownSigner, {
      did: fixture.did,
      log: finalLog
    }).read()
    const currentEpoch = (finalRoster!.descriptor.epochs ?? []).find(
      epoch => epoch.id === finalRoster!.descriptor.currentEpoch
    )
    expect(
      currentEpoch!.recipients.some(
        entry => entry.header.kid === fixture.forgottenKid
      )
    ).toBe(false)
  })
})
