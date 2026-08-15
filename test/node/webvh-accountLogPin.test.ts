/**
 * Unit tests for the account log's chain-head pin: `verifyAccountLog` under a
 * `ResourceLogPinStore`. A served log that is a valid prefix of the real one
 * resolves to the same DID and passes every one-shot check, so the pin is the
 * only thing that catches it -- along with a fork off the pinned history and a
 * substituted log identity (SCID or method). Plus the trust-on-first-use
 * establishment, the advance, and the DID check `readPublishedLog` gained.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  ensureDidWebvh,
  enrollWebvhClient,
  readPublishedLog,
  updateKeyMultibase
} from '../../src/webvh/didWebvh.js'
import { keyAgreementTwinMultibase } from '../../src/webvh/didWebvh.js'
import { accountLogPinId, verifyAccountLog } from '../../src/webvh/verifyLog.js'
import {
  memoryResourceLogPinStore,
  type ResourceLogPinStore
} from '../../src/resourceLog/index.js'
import { mintEnrollmentRequest } from '../../src/enrollment/enrollment.js'
import { DID_LOG_RESOURCE } from '../../src/space/collections.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-pin'
const OTHER_SPACE_ID = 'space-pin-second-account'
const didWebFor = (spaceId: string) =>
  `did:web:localhost%3A8080:space:${spaceId}:id`
const ACCOUNT_LOG_ID = accountLogPinId({ spaceId: SPACE_ID })

/**
 * Provisions a one-client account and returns its store, DID, and the
 * genesis-only log text -- the branch point the fork below is built from.
 *
 * @param [options] {object}
 * @param [options.spaceId] {string}   the account's Space id, so a second
 *   account can be provisioned beside the first
 * @returns {Promise<object>}
 */
async function provisionedAccount({
  spaceId = SPACE_ID
}: { spaceId?: string } = {}) {
  const { idStore, log } = memoryIdStore()
  const first = await mintEnrollmentRequest()
  const signingKeyMultibase = first.clientDid.slice('did:key:'.length)
  await ensureDidWebvh({
    idStore,
    wasServerUrl: WAS_URL,
    spaceId,
    didWebKeys: {
      authentication: {
        vmId: `${didWebFor(spaceId)}#z6MkAuth`,
        kmsKeyId: 'kms/keys/auth'
      },
      keyAgreement: {
        vmId: `${didWebFor(spaceId)}#z6LSAgree`,
        kmsKeyId: 'kms/keys/agree'
      }
    },
    clientKeys: {
      signingKeyMultibase,
      keyAgreementKeyMultibase: keyAgreementTwinMultibase({
        signingKeyMultibase
      })
    },
    updateKeys: first.webvhUpdateKeys
  })
  const published = await readPublishedLog({ idStore })
  return {
    idStore,
    log,
    did: published!.did,
    genesisLogText: log()!,
    firstSeeds: first.webvhUpdateKeys
  }
}

/**
 * The public halves of a freshly minted client, in the shape the enrollment
 * entry takes.
 *
 * @returns {Promise<object>}
 */
async function newClientKeys() {
  const minted = await mintEnrollmentRequest()
  const signingKeyMultibase = minted.clientDid.slice('did:key:'.length)
  return {
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

/**
 * Stubs the global fetch so the world-readable log read serves `logText`.
 *
 * @param logText {string}
 * @returns {void}
 */
function serveLog(logText: string): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => ({
      status: 200,
      ok: true,
      text: async () => logText
    }))
  )
}

/**
 * An account whose log has grown past its genesis, plus a genuine fork of it:
 * the same genesis entry (so the same SCID and DID) continued by a DIFFERENT
 * enrollment, which is what a two-faced host would have to serve.
 *
 * @returns {Promise<object>}
 */
async function accountWithFork() {
  const account = await provisionedAccount()
  await enrollWebvhClient({
    idStore: account.idStore,
    updateKeys: account.firstSeeds,
    newClient: await newClientKeys()
  })
  const honestLogText = account.log()!

  // The fork: a second store replayed to the same genesis, then continued by
  // an enrollment of someone else entirely.
  const forked = memoryIdStore()
  await forked.idStore.putIdResource({
    resourceId: DID_LOG_RESOURCE,
    content: account.genesisLogText,
    ifNoneMatch: true
  })
  await enrollWebvhClient({
    idStore: forked.idStore,
    updateKeys: account.firstSeeds,
    newClient: await newClientKeys()
  })
  return { ...account, honestLogText, forkedLogText: forked.log()! }
}

/**
 * Verifies the account's log through a pin store, with the log served over a
 * stubbed fetch.
 *
 * @param options {object}
 * @param options.did {string}
 * @param options.logText {string}
 * @param options.pinStore {ResourceLogPinStore}
 * @param [options.spaceId] {string}   the account's Space id, which is what
 *   the pin slot is keyed by
 * @returns {Promise<unknown>}
 */
async function verifyServed({
  did,
  logText,
  pinStore,
  spaceId = SPACE_ID
}: {
  did: string
  logText: string
  pinStore: ResourceLogPinStore
  spaceId?: string
}) {
  serveLog(logText)
  return verifyAccountLog({ did, spaceId, host: WAS_URL, pinStore })
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('accountLogPinId', () => {
  it('names the account log slot in the world-readable id collection', () => {
    expect(accountLogPinId({ spaceId: 'urn:uuid:space' })).toBe(
      'space/urn:uuid:space/id/did.jsonl'
    )
  })

  it('gives two accounts distinct slots', () => {
    expect(accountLogPinId({ spaceId: SPACE_ID })).not.toBe(
      accountLogPinId({ spaceId: OTHER_SPACE_ID })
    )
  })
})

describe('verifyAccountLog chain-head pin', () => {
  it('pins under accountLogPinId, so one store serves two accounts unclobbered', async () => {
    const pinStore = memoryResourceLogPinStore()
    const first = await provisionedAccount()
    const second = await provisionedAccount({ spaceId: OTHER_SPACE_ID })

    await verifyServed({
      did: first.did,
      logText: first.genesisLogText,
      pinStore
    })
    await verifyServed({
      did: second.did,
      logText: second.genesisLogText,
      pinStore,
      spaceId: OTHER_SPACE_ID
    })

    // Each account's pin sits in its own slot, keyed by its own Space id.
    const firstPin = await pinStore.read({ logId: ACCOUNT_LOG_ID })
    const secondPin = await pinStore.read({
      logId: accountLogPinId({ spaceId: OTHER_SPACE_ID })
    })
    expect(firstPin).not.toBeNull()
    expect(secondPin).not.toBeNull()
    expect(secondPin!.scid).not.toBe(firstPin!.scid)

    // The second account's first contact left the first account's pin intact,
    // so a truncation of the first account's log is still refused.
    await enrollWebvhClient({
      idStore: first.idStore,
      updateKeys: first.firstSeeds,
      newClient: await newClientKeys()
    })
    await verifyServed({ did: first.did, logText: first.log()!, pinStore })
    await verifyServed({
      did: second.did,
      logText: second.genesisLogText,
      pinStore,
      spaceId: OTHER_SPACE_ID
    })
    const refusal = await verifyServed({
      did: first.did,
      logText: first.genesisLogText,
      pinStore
    }).catch((err: unknown) => err)
    expect((refusal as Error).name).toBe('ResourceLogContinuityError')
    expect((refusal as { reason: string }).reason).toBe('rollback')
  })

  it('establishes the pin at first contact and advances it as the log grows', async () => {
    const account = await provisionedAccount()
    const pinStore = memoryResourceLogPinStore()

    await verifyServed({
      did: account.did,
      logText: account.genesisLogText,
      pinStore
    })
    const first = await pinStore.read({ logId: ACCOUNT_LOG_ID })
    expect(first).not.toBeNull()
    expect(first!.method).toMatch(/^did:webvh:/)
    expect(first!.scid.length).toBeGreaterThan(0)
    expect(first!.head).toMatch(/^1-/)

    await enrollWebvhClient({
      idStore: account.idStore,
      updateKeys: account.firstSeeds,
      newClient: await newClientKeys()
    })
    await verifyServed({
      did: account.did,
      logText: account.log()!,
      pinStore
    })
    const advanced = await pinStore.read({ logId: ACCOUNT_LOG_ID })
    expect(advanced!.scid).toBe(first!.scid)
    expect(advanced!.head).toMatch(/^3-/)
  })

  it('refuses a truncated prefix of the pinned log, and never regresses the pin', async () => {
    const account = await provisionedAccount()
    await enrollWebvhClient({
      idStore: account.idStore,
      updateKeys: account.firstSeeds,
      newClient: await newClientKeys()
    })
    const fullLogText = account.log()!
    const pinStore = memoryResourceLogPinStore()
    await verifyServed({ did: account.did, logText: fullLogText, pinStore })
    const pinned = await pinStore.read({ logId: ACCOUNT_LOG_ID })

    // A valid prefix: same genesis, same SCID, resolves to the same DID -- and
    // erases the enrollment.
    const truncated =
      fullLogText.trim().split('\n').slice(0, 2).join('\n') + '\n'
    const refusal = await verifyServed({
      did: account.did,
      logText: truncated,
      pinStore
    }).catch((err: unknown) => err)

    expect((refusal as Error).name).toBe('ResourceLogContinuityError')
    expect((refusal as { reason: string }).reason).toBe('rollback')
    expect((refusal as { pinnedHead: string }).pinnedHead).toBe(pinned!.head)
    expect(await pinStore.read({ logId: ACCOUNT_LOG_ID })).toEqual(pinned)
  })

  it('refuses a fork off the pinned history, carrying the served entries as evidence', async () => {
    const { did, honestLogText, forkedLogText } = await accountWithFork()
    const pinStore = memoryResourceLogPinStore()
    await verifyServed({ did, logText: honestLogText, pinStore })
    const pinned = await pinStore.read({ logId: ACCOUNT_LOG_ID })

    const refusal = (await verifyServed({
      did,
      logText: forkedLogText,
      pinStore
    }).catch((err: unknown) => err)) as {
      name: string
      reason: string
      pinnedHead: string
      servedEntries?: unknown[]
    }

    expect(refusal.name).toBe('ResourceLogContinuityError')
    expect(refusal.reason).toBe('fork')
    expect(refusal.pinnedHead).toBe(pinned!.head)
    expect(refusal.servedEntries).toHaveLength(3)
    expect(await pinStore.read({ logId: ACCOUNT_LOG_ID })).toEqual(pinned)
  })

  it('refuses a served log whose SCID differs from the pinned one', async () => {
    const account = await provisionedAccount()
    const pinStore = memoryResourceLogPinStore()
    await verifyServed({
      did: account.did,
      logText: account.genesisLogText,
      pinStore
    })
    const pinned = (await pinStore.read({ logId: ACCOUNT_LOG_ID }))!
    await pinStore.write({
      logId: ACCOUNT_LOG_ID,
      pin: { ...pinned, scid: 'QmSomeOtherLogEntirely' }
    })

    const refusal = (await verifyServed({
      did: account.did,
      logText: account.genesisLogText,
      pinStore
    }).catch((err: unknown) => err)) as { name: string; reason: string }
    expect(refusal.name).toBe('ResourceLogContinuityError')
    expect(refusal.reason).toBe('scid-switch')
  })

  it('refuses a served log whose method differs from the pinned one', async () => {
    const account = await provisionedAccount()
    const pinStore = memoryResourceLogPinStore()
    await verifyServed({
      did: account.did,
      logText: account.genesisLogText,
      pinStore
    })
    const pinned = (await pinStore.read({ logId: ACCOUNT_LOG_ID }))!
    await pinStore.write({
      logId: ACCOUNT_LOG_ID,
      pin: { ...pinned, method: 'did:webvh:0.5' }
    })

    const refusal = (await verifyServed({
      did: account.did,
      logText: account.genesisLogText,
      pinStore
    }).catch((err: unknown) => err)) as { name: string; reason: string }
    expect(refusal.name).toBe('ResourceLogContinuityError')
    expect(refusal.reason).toBe('method-switch')
  })

  it('treats an unparseable pinned head as a fork rather than trusting it', async () => {
    const account = await provisionedAccount()
    const pinStore = memoryResourceLogPinStore()
    await verifyServed({
      did: account.did,
      logText: account.genesisLogText,
      pinStore
    })
    const pinned = (await pinStore.read({ logId: ACCOUNT_LOG_ID }))!
    await pinStore.write({
      logId: ACCOUNT_LOG_ID,
      pin: { ...pinned, head: 'not-an-ordinal' }
    })

    const refusal = (await verifyServed({
      did: account.did,
      logText: account.genesisLogText,
      pinStore
    }).catch((err: unknown) => err)) as { name: string; reason: string }
    expect(refusal.name).toBe('ResourceLogContinuityError')
    expect(refusal.reason).toBe('fork')
  })

  it('still refuses a substituted account before any pin check', async () => {
    const account = await provisionedAccount()
    serveLog(account.genesisLogText)
    await expect(
      verifyAccountLog({
        did: 'did:webvh:QmSomeoneElse:localhost%3A8080:space:other:id',
        spaceId: SPACE_ID,
        host: WAS_URL,
        pinStore: memoryResourceLogPinStore()
      })
    ).rejects.toThrow('different DID than the account pointer names')
  })

  it('leaves one-shot verification unchanged when no pin store is supplied', async () => {
    const account = await provisionedAccount()
    serveLog(account.genesisLogText)
    const verified = await verifyAccountLog({
      did: account.did,
      spaceId: SPACE_ID,
      host: WAS_URL
    })
    expect(verified.doc.id).toBe(account.did)
  })
})

describe('readPublishedLog expectedDid', () => {
  it('refuses a published log resolving to a different DID', async () => {
    const account = await provisionedAccount()
    await expect(
      readPublishedLog({
        idStore: account.idStore,
        expectedDid: 'did:webvh:QmSomeoneElse:localhost%3A8080:space:other:id'
      })
    ).rejects.toThrow('resolves to a different DID')
  })

  it('accepts the log the account pointer names', async () => {
    const account = await provisionedAccount()
    const published = await readPublishedLog({
      idStore: account.idStore,
      expectedDid: account.did
    })
    expect(published!.did).toBe(account.did)
  })
})
