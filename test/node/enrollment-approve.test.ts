/**
 * Tests for the enrolling client's approval half of the ceremony
 * (`approveEnrollment`) over the log-governed roster store: the push order
 * (the user-key wrap lands as a signed log append BEFORE any did:webvh entry
 * -- decryption material before authorization), and convergence across a tear
 * between the two (re-running the same code appends no duplicate wrap), and
 * the ladder arm's post-add anchoring (the escrow append carries the add
 * entry's version even under a stale injected controller view). The
 * did:webvh half is mocked -- the log entries have their own suites; what is
 * proven here is the ceremony's ordering and idempotence through the roster
 * log.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { DIDLog } from '@interop/did-method-webvh'
import { logGovernedDescriptorStore } from '../../src/keys/rosterLogStore.js'
import { userKeyRosterPinId } from '../../src/keys/rosterStore.js'
import { mintUserKey } from '../../src/keys/userKey.js'
import {
  ensureUserKeyRoster,
  rosterRecipientKid
} from '../../src/keys/userKeyRoster.js'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import {
  approveEnrollment,
  mintEnrollmentRequest
} from '../../src/enrollment/enrollment.js'
import { enrollWebvhClient } from '../../src/webvh/enrollClient.js'
import {
  ensureDidWebvh,
  keyAgreementTwinMultibase,
  updateKeyMultibase
} from '../../src/webvh/didWebvh.js'
import type {
  ClientWebvhUpdateKeys,
  WebvhIdStore
} from '../../src/webvh/didWebvh.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'
import { truncatingLogStore } from './fixtures/truncatingLogStore.js'
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
const ACCOUNT_SPACE_ID = 'space-enroll-pin'

vi.mock('../../src/webvh/enrollClient.js', () => ({
  enrollWebvhClient: vi.fn()
}))

const idStore = {} as WebvhIdStore
const clientWebvhKeys = {} as ClientWebvhUpdateKeys
const ACCOUNT_DID = 'did:webvh:QmScid:example.com:space:abc:id'

/**
 * A fake account log, one version per client set, carrying what
 * `webvhResourceLogController` reads off a verified did:webvh log: each
 * entry's `versionId` and its resolved document with the version's
 * `assertionMethod` keys. Version ids match `fakeController`'s.
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
 * What the mocked entry writer hands back: the account DID and a post-add
 * log listing alice alone at version 1 and alice plus bob at version 2.
 *
 * @param options {object}
 * @param options.alice {RosterTestClient}
 * @param options.bob {RosterTestClient}
 * @returns {Awaited<ReturnType<typeof enrollWebvhClient>>}
 */
function enrolled({
  alice,
  bob
}: {
  alice: RosterTestClient
  bob: RosterTestClient
}): Awaited<ReturnType<typeof enrollWebvhClient>> {
  return { did: ACCOUNT_DID, log: accountLogFor([[alice], [alice, bob]]) }
}

/**
 * The enrolling side of one ceremony: alice's account with a log-governed
 * roster (one genesis epoch), and bob's connect-code request (public halves
 * only, as the code carries them).
 */
async function makeCeremony() {
  const alice = await makeRosterClient()
  const bob = await makeRosterClient()
  const controller = fakeController({
    versions: [{ versionId: '1-v1', keys: [alice.signingKeyMultibase] }]
  })
  const log = memoryLogStore()
  const store = logGovernedDescriptorStore({
    log,
    resolveController: async () => controller,
    pinStore: memoryResourceLogPinStore(),
    logId: ROSTER_LOG_ID,
    signer: alice.logSigner
  })
  const userKey = await mintUserKey()
  await ensureUserKeyRoster({
    store,
    userKey,
    clientKeyAgreementKey: alice.kak
  })
  const request = {
    signingKeyMultibase: bob.signingKeyMultibase,
    keyAgreementKeyMultibase: bob.publicKeyMultibase,
    updateKeyMultibase: 'z6MkEnrolleeUpdateKey',
    stagedUpdateKeyMultibase: 'z6MkEnrolleeStagedKey'
  }
  const bobKid = rosterRecipientKid({
    signingKeyMultibase: bob.signingKeyMultibase,
    keyAgreementKeyMultibase: bob.publicKeyMultibase
  })
  return { alice, bob, log, store, request, bobKid }
}

/**
 * The kids the roster log's verified head wraps the current epoch to.
 */
async function currentRecipients(store: {
  read(): Promise<{
    descriptor: {
      currentEpoch?: string
      epochs?: Array<{
        id: string
        recipients: Array<{ header: { kid: string } }>
      }>
    }
  } | null>
}): Promise<string[]> {
  const current = (await store.read())!
  const epoch = current.descriptor.epochs!.find(
    entry => entry.id === current.descriptor.currentEpoch
  )!
  return epoch.recipients.map(entry => entry.header.kid)
}

describe('approveEnrollment over the roster log', () => {
  beforeEach(() => {
    vi.mocked(enrollWebvhClient).mockReset()
  })

  it('lands the wrap as a log append BEFORE the did:webvh entries (push order)', async () => {
    const { alice, bob, log, store, request, bobKid } = await makeCeremony()
    let entriesAtEnrollTime = 0
    vi.mocked(enrollWebvhClient).mockImplementation(async () => {
      entriesAtEnrollTime = log._getEntries()!.length
      return enrolled({ alice, bob })
    })

    const result = await approveEnrollment({
      request,
      signer: { kind: 'client', updateKeys: clientWebvhKeys },
      clientKeyAgreementKey: alice.kak,
      userKeyRosterStore: store,
      idStore
    })

    // Genesis + the wrap append were both durable before the document half
    // ran: no authorized-but-blind window.
    expect(entriesAtEnrollTime).toBe(2)
    expect(await currentRecipients(store)).toContain(bobKid)
    expect(result.signingKeyMultibase).toBe(request.signingKeyMultibase)
  })

  it('refuses a non-canonical key-agreement key before the wrap is written', async () => {
    const { alice, log, store, request } = await makeCeremony()
    const entriesBefore = log._getEntries()!.length

    await expect(
      approveEnrollment({
        // Alice's own key-agreement key under Bob's signing key: publishing
        // it under Bob's controller marker would claim something untrue.
        request: {
          ...request,
          keyAgreementKeyMultibase: alice.publicKeyMultibase
        },
        signer: { kind: 'client', updateKeys: clientWebvhKeys },
        clientKeyAgreementKey: alice.kak,
        userKeyRosterStore: store,
        idStore
      })
    ).rejects.toThrow('canonical X25519 twin')

    // Nothing was written and the document half never ran.
    expect(log._getEntries()!).toHaveLength(entriesBefore)
    expect(vi.mocked(enrollWebvhClient)).not.toHaveBeenCalled()
  })

  it('runs the entries BEFORE the escrow on the ladder arm', async () => {
    const { alice, bob, log, store, request, bobKid } = await makeCeremony()
    const ladderSeed = new Uint8Array(32).fill(7)
    let entriesAtEnrollTime = 0
    let recipientsAtEnrollTime: string[] = []
    vi.mocked(enrollWebvhClient).mockImplementation(async () => {
      entriesAtEnrollTime = log._getEntries()!.length
      recipientsAtEnrollTime = await currentRecipients(store)
      return enrolled({ alice, bob })
    })

    await approveEnrollment({
      request,
      signer: { kind: 'ladder', ladderSeed },
      clientKeyAgreementKey: alice.kak,
      userKeyRosterStore: store,
      idStore
    })

    // The document half ran on the genesis roster alone: a ladder-signed
    // append is licensed only at the inventory-changing version the add entry
    // mints, so the escrow can only follow it (`decisions/0018`).
    expect(entriesAtEnrollTime).toBe(1)
    expect(recipientsAtEnrollTime).not.toContain(bobKid)
    // And the escrow did land, in the one-request window the branch states.
    expect(log._getEntries()!).toHaveLength(2)
    expect(await currentRecipients(store)).toContain(bobKid)
    // The ladder seed reached the entries rather than an update-key pair.
    expect(vi.mocked(enrollWebvhClient).mock.calls[0]![0]!.signer).toEqual({
      kind: 'ladder',
      ladderSeed
    })
  })

  it('anchors the ladder-arm escrow at the add entry under a stale controller view', async () => {
    // The store's injected `resolveController` keeps serving the view cached
    // before the entries -- an app whose session-verified log was primed by
    // the listing that opened the approval dialog. Without the minimum
    // controller version the escrow would carry version 1, the pre-add
    // head, and the ceremony-tail license would refuse it after the pivot.
    // `makeCeremony`'s controller IS that stale view (version 1 alone) and
    // never advances.
    const { alice, bob, log, store, request, bobKid } = await makeCeremony()
    vi.mocked(enrollWebvhClient).mockResolvedValue(enrolled({ alice, bob }))

    await approveEnrollment({
      request,
      signer: { kind: 'ladder', ladderSeed: new Uint8Array(32).fill(7) },
      clientKeyAgreementKey: alice.kak,
      userKeyRosterStore: store,
      idStore
    })

    // The escrow landed, anchored at the add entry's version rather than the
    // stale resolver's.
    expect(await currentRecipients(store)).toContain(bobKid)
    const entries = log._getEntries()!
    expect(entries).toHaveLength(2)
    expect(entries[1]!.proof[0]!.verificationMethod).toContain(
      '?versionId=2-v2'
    )
  })

  it('converges across a tear between the wrap and the log entries', async () => {
    const { alice, bob, log, store, request, bobKid } = await makeCeremony()
    vi.mocked(enrollWebvhClient).mockRejectedValueOnce(
      new TypeError('Failed to fetch')
    )
    await expect(
      approveEnrollment({
        request,
        signer: { kind: 'client', updateKeys: clientWebvhKeys },
        clientKeyAgreementKey: alice.kak,
        userKeyRosterStore: store,
        idStore
      })
    ).rejects.toThrow('Failed to fetch')
    // The tear left an orphan wrap -- invisible to authorization, harmless.
    expect(log._getEntries()!).toHaveLength(2)
    expect(await currentRecipients(store)).toContain(bobKid)

    // Re-running with the same code converges: the standing wrap is adopted
    // (no duplicate append) and the document half completes.
    vi.mocked(enrollWebvhClient).mockResolvedValue(enrolled({ alice, bob }))
    await approveEnrollment({
      request,
      signer: { kind: 'client', updateKeys: clientWebvhKeys },
      clientKeyAgreementKey: alice.kak,
      userKeyRosterStore: store,
      idStore
    })
    expect(log._getEntries()!).toHaveLength(2)
    expect(vi.mocked(enrollWebvhClient)).toHaveBeenCalledTimes(2)
  })
})

describe('approveEnrollment chain-head pin', () => {
  /**
   * A real one-client account log, provisioned through the shared in-memory
   * store: what the mocked entry writer stands in for everywhere else in this
   * suite, and what the pin below is held against.
   *
   * @returns {Promise<object>}
   */
  async function provisionedAccount() {
    const { idStore, log } = memoryIdStore({ spaceId: ACCOUNT_SPACE_ID })
    const first = await newClientRequest()
    await ensureDidWebvh({
      idStore,
      wasServerUrl: 'http://localhost:8080',
      spaceId: ACCOUNT_SPACE_ID,
      clientKeys: {
        signingKeyMultibase: first.request.signingKeyMultibase,
        keyAgreementKeyMultibase: first.request.keyAgreementKeyMultibase
      },
      updateKeys: first.updateKeys
    })
    return { idStore, log, updateKeys: first.updateKeys }
  }

  /**
   * A freshly minted client's public halves in the connect code's shape, plus
   * the update-key seeds behind them.
   *
   * @returns {Promise<object>}
   */
  async function newClientRequest() {
    const minted = await mintEnrollmentRequest()
    const signingKeyMultibase = minted.clientDid.slice('did:key:'.length)
    return {
      updateKeys: minted.webvhUpdateKeys,
      request: {
        signingKeyMultibase,
        keyAgreementKeyMultibase: keyAgreementTwinMultibase({
          signingKeyMultibase
        }),
        updateKeyMultibase: await updateKeyMultibase({
          seed: minted.webvhUpdateKeys.updateSeed
        }),
        stagedUpdateKeyMultibase: await updateKeyMultibase({
          seed: minted.webvhUpdateKeys.stagedSeed
        })
      }
    }
  }

  it('refuses a served prefix of the pinned account log, publishing no entry', async () => {
    const { alice, store } = await makeCeremony()
    // The did:webvh half runs for real here: what is under test is the read
    // the entry writer builds on, which the mock stands in for elsewhere.
    const actual = await vi.importActual<
      typeof import('../../src/webvh/enrollClient.js')
    >('../../src/webvh/enrollClient.js')
    vi.mocked(enrollWebvhClient).mockImplementation(actual.enrollWebvhClient)

    const account = await provisionedAccount()
    // A second entry past the genesis, so a valid prefix of the pinned log
    // exists; the enrollment's own publish advanced the store's pin to it.
    const earlier = await newClientRequest()
    await actual.enrollWebvhClient({
      idStore: account.idStore,
      signer: { kind: 'client', updateKeys: account.updateKeys },
      newClient: earlier.request
    })
    const { store: truncated } = truncatingLogStore({
      idStore: account.idStore,
      dropEntries: 1
    })
    const logBefore = account.log()
    const enrollee = await newClientRequest()

    const caught = (await approveEnrollment({
      request: enrollee.request,
      signer: { kind: 'client', updateKeys: account.updateKeys },
      clientKeyAgreementKey: alice.kak,
      userKeyRosterStore: store,
      idStore: truncated
    }).catch((err: unknown) => err)) as { name: string; reason: string }

    expect(caught.name).toBe('ResourceLogContinuityError')
    expect(caught.reason).toBe('rollback')
    // The truncation was refused on the read, so no entry was published.
    expect(account.log()).toBe(logBefore)
  })
})
