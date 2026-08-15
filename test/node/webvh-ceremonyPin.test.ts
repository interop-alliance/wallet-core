/**
 * Unit tests for the ceremony-side reads of `did.jsonl`: the `expectedDid` and
 * chain-head-pin checks `readPublishedLog` applies, threaded through
 * `ensureDidWebvh`, `rotateWebvhUpdateKey`, and `repairKeyBindings`. A served
 * log that is a valid PREFIX of the real one resolves to the same DID and
 * passes every one-shot check, so without the pin a rotation happily
 * republishes the truncation plus its own entry as durable state.
 */
import { describe, expect, it } from 'vitest'
import type { KeystoreAgent } from '@interop/webkms-client'
import {
  ensureDidWebvh,
  enrollWebvhClient,
  readPublishedLog,
  repairKeyBindings,
  rotateWebvhUpdateKey,
  updateKeyMultibase,
  type ClientWebvhUpdateKeys,
  type DidWebKeyMapV2
} from '../../src/webvh/didWebvh.js'
import { keyAgreementTwinMultibase } from '../../src/webvh/didWebvh.js'
import { memoryResourceLogPinStore } from '../../src/resourceLog/index.js'
import { mintEnrollmentRequest } from '../../src/enrollment/enrollment.js'
import {
  DID_DOCUMENT_RESOURCE,
  DID_LOG_RESOURCE
} from '../../src/space/collections.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-ceremony-pin'
const DID_WEB = `did:web:localhost%3A8080:space:${SPACE_ID}:id`
const OTHER_DID = 'did:webvh:QmSomeoneElse:localhost%3A8080:space:other:id'

/**
 * The did:web relationship map every provisioning here runs against.
 *
 * @returns {DidWebKeyMapV2}
 */
function keyMap(): DidWebKeyMapV2 {
  return {
    authentication: {
      vmId: `${DID_WEB}#z6MkAuth`,
      kmsKeyId: 'kms/keys/auth'
    },
    keyAgreement: {
      vmId: `${DID_WEB}#z6LSAgree`,
      kmsKeyId: 'kms/keys/agree'
    }
  }
}

/**
 * Provisions a one-client account and returns its store, DID, this client's
 * update-key seeds, and the client's published key multibases.
 *
 * @param [options] {object}
 * @param [options.pinStore] {object}   pinned by the create path when supplied
 * @returns {Promise<object>}
 */
async function provisionedAccount({
  pinStore
}: {
  pinStore?: ReturnType<typeof memoryResourceLogPinStore>
} = {}) {
  const { idStore, log } = memoryIdStore()
  const first = await mintEnrollmentRequest()
  const signingKeyMultibase = first.clientDid.slice('did:key:'.length)
  const keyAgreementKeyMultibase = keyAgreementTwinMultibase({
    signingKeyMultibase
  })
  await ensureDidWebvh({
    idStore,
    wasServerUrl: WAS_URL,
    spaceId: SPACE_ID,
    didWebKeys: keyMap(),
    clientKeys: { signingKeyMultibase, keyAgreementKeyMultibase },
    updateKeys: first.webvhUpdateKeys,
    ...(pinStore ? { pinStore } : {})
  })
  const published = await readPublishedLog({ idStore })
  return {
    idStore,
    log,
    did: published!.did,
    firstSeeds: first.webvhUpdateKeys,
    clientKeys: { signingKeyMultibase, keyAgreementKeyMultibase }
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
 * Overwrites the stored `did.jsonl` with its first `entries` lines -- the
 * truncated prefix a two-faced host would serve.
 *
 * @param options {object}
 * @param options.account {object}   a provisioned account
 * @param options.entries {number}   how many log entries to keep
 * @returns {Promise<string>}   the truncated log text now stored
 */
async function truncateStoredLog({
  account,
  entries
}: {
  account: Awaited<ReturnType<typeof provisionedAccount>>
  entries: number
}): Promise<string> {
  const truncated =
    account.log()!.trim().split('\n').slice(0, entries).join('\n') + '\n'
  await account.idStore.putIdResource({
    resourceId: DID_LOG_RESOURCE,
    content: truncated
  })
  return truncated
}

/**
 * A persistence sink for the rotation ceremony's seeds.
 *
 * @returns {object}
 */
function seedSink() {
  const persisted: ClientWebvhUpdateKeys[] = []
  return {
    persisted,
    persistUpdateKeys: async (next: ClientWebvhUpdateKeys) => {
      persisted.push(next)
    }
  }
}

/**
 * A `KeystoreAgent` stub listing exactly the two public keys the repair path
 * matches the published `did.json`'s relationships against.
 *
 * @param options {object}
 * @param options.keyAgreementKeyMultibase {string}
 * @returns {KeystoreAgent}
 */
function keystoreStub({
  keyAgreementKeyMultibase
}: {
  keyAgreementKeyMultibase: string
}): KeystoreAgent {
  return {
    async listKeys() {
      return [
        { publicKeyMultibase: 'z6MkAuth', keyUrl: 'kms/keys/auth' },
        {
          publicKeyMultibase: keyAgreementKeyMultibase,
          keyUrl: 'kms/keys/agree'
        }
      ]
    }
  } as unknown as KeystoreAgent
}

describe('rotateWebvhUpdateKey chain-head pin', () => {
  it('refuses a truncated prefix of the pinned log and publishes nothing', async () => {
    const account = await provisionedAccount()
    await enrollWebvhClient({
      idStore: account.idStore,
      updateKeys: account.firstSeeds,
      newClient: await newClientKeys()
    })
    const pinStore = memoryResourceLogPinStore()
    await readPublishedLog({ idStore: account.idStore, pinStore })
    const pinned = (await pinStore.read())!

    // A valid prefix: same genesis, same SCID, resolves to the same DID -- and
    // erases the enrollment.
    const truncated = await truncateStoredLog({ account, entries: 2 })
    const sink = seedSink()
    const refusal = (await rotateWebvhUpdateKey({
      idStore: account.idStore,
      updateKeys: account.firstSeeds,
      persistUpdateKeys: sink.persistUpdateKeys,
      pinStore
    }).catch((err: unknown) => err)) as {
      name: string
      reason: string
      pinnedHead: string
    }

    expect(refusal.name).toBe('ResourceLogContinuityError')
    expect(refusal.reason).toBe('rollback')
    expect(refusal.pinnedHead).toBe(pinned.head)
    // Nothing was published, and no seed was rolled forward.
    expect(account.log()).toBe(truncated)
    expect(sink.persisted).toEqual([])
    expect(await pinStore.read()).toEqual(pinned)
  })

  it('refuses a log resolving to a different DID than expected', async () => {
    const account = await provisionedAccount()
    const sink = seedSink()
    await expect(
      rotateWebvhUpdateKey({
        idStore: account.idStore,
        updateKeys: account.firstSeeds,
        persistUpdateKeys: sink.persistUpdateKeys,
        expectedDid: OTHER_DID
      })
    ).rejects.toThrow('resolves to a different DID')
    expect(sink.persisted).toEqual([])
  })

  it('advances the pin to the head it just published', async () => {
    const account = await provisionedAccount()
    const pinStore = memoryResourceLogPinStore()
    await readPublishedLog({ idStore: account.idStore, pinStore })
    const before = (await pinStore.read())!
    expect(before.head).toMatch(/^1-/)

    const sink = seedSink()
    await rotateWebvhUpdateKey({
      idStore: account.idStore,
      updateKeys: account.firstSeeds,
      persistUpdateKeys: sink.persistUpdateKeys,
      expectedDid: account.did,
      pinStore
    })

    const published = await readPublishedLog({ idStore: account.idStore })
    const head = published!.log[published!.log.length - 1]!.versionId
    const after = (await pinStore.read())!
    expect(after.head).toBe(head)
    expect(after.head).toMatch(/^2-/)
    expect(after.scid).toBe(before.scid)
  })
})

describe('ensureDidWebvh chain-head pin and expectedDid', () => {
  it('refuses a truncated served log on the adoption path', async () => {
    const account = await provisionedAccount()
    await enrollWebvhClient({
      idStore: account.idStore,
      updateKeys: account.firstSeeds,
      newClient: await newClientKeys()
    })
    const pinStore = memoryResourceLogPinStore()
    await readPublishedLog({ idStore: account.idStore, pinStore })
    const pinned = (await pinStore.read())!
    const truncated = await truncateStoredLog({ account, entries: 2 })

    const refusal = (await ensureDidWebvh({
      idStore: account.idStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: keyMap(),
      clientKeys: account.clientKeys,
      updateKeys: account.firstSeeds,
      pinStore
    }).catch((err: unknown) => err)) as { name: string; reason: string }

    expect(refusal.name).toBe('ResourceLogContinuityError')
    expect(refusal.reason).toBe('rollback')
    expect(account.log()).toBe(truncated)
    expect(await pinStore.read()).toEqual(pinned)
  })

  it('refuses an absent log under a held pin instead of creating a fresh one', async () => {
    const account = await provisionedAccount()
    const pinStore = memoryResourceLogPinStore()
    await readPublishedLog({ idStore: account.idStore, pinStore })
    const pinned = (await pinStore.read())!

    // The same client meeting an empty Space: the log is gone, which under a
    // held pin is a full truncation rather than "not yet provisioned".
    const fresh = memoryIdStore()
    const refusal = (await ensureDidWebvh({
      idStore: fresh.idStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: keyMap(),
      clientKeys: account.clientKeys,
      updateKeys: account.firstSeeds,
      pinStore
    }).catch((err: unknown) => err)) as {
      name: string
      reason: string
      pinnedHead: string
    }

    expect(refusal.name).toBe('ResourceLogContinuityError')
    expect(refusal.reason).toBe('rollback')
    expect(refusal.pinnedHead).toBe(pinned.head)
    expect(fresh.log()).toBeUndefined()
  })

  it('refuses a published log the keys.json webvh block does not name', async () => {
    const account = await provisionedAccount()
    await expect(
      ensureDidWebvh({
        idStore: account.idStore,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        didWebKeys: { ...keyMap(), webvh: { did: OTHER_DID } },
        clientKeys: account.clientKeys,
        updateKeys: account.firstSeeds
      })
    ).rejects.toThrow('resolves to a different DID')
  })

  it('refuses a published log a caller-supplied expectedDid does not name', async () => {
    const account = await provisionedAccount()
    await expect(
      ensureDidWebvh({
        idStore: account.idStore,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        didWebKeys: keyMap(),
        clientKeys: account.clientKeys,
        updateKeys: account.firstSeeds,
        expectedDid: OTHER_DID
      })
    ).rejects.toThrow('resolves to a different DID')
  })

  it('establishes the pin on the create path from the log it minted', async () => {
    const pinStore = memoryResourceLogPinStore()
    const account = await provisionedAccount({ pinStore })
    const published = await readPublishedLog({ idStore: account.idStore })
    const head = published!.log[published!.log.length - 1]!.versionId

    const pin = await pinStore.read()
    expect(pin).not.toBeNull()
    expect(pin!.method).toMatch(/^did:webvh:/)
    expect(pin!.scid.length).toBeGreaterThan(0)
    expect(pin!.head).toBe(head)
  })

  it('adopts an unnamed log with no pin, the documented first-contact case', async () => {
    const account = await provisionedAccount()
    const adopted = await ensureDidWebvh({
      idStore: account.idStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: keyMap(),
      clientKeys: account.clientKeys,
      updateKeys: account.firstSeeds
    })
    expect(adopted.did).toBe(account.did)
  })
})

describe('repairKeyBindings expectedDid', () => {
  it('records the published did when the log resolves to the expected DID', async () => {
    const account = await provisionedAccount()
    const repaired = await repairKeyBindings({
      keystoreAgent: keystoreStub(account.clientKeys),
      idStore: account.idStore,
      expectedDid: account.did
    })
    expect(repaired.webvh).toEqual({ did: account.did })
  })

  it('refuses a published log resolving to a different DID', async () => {
    const account = await provisionedAccount()
    await expect(
      repairKeyBindings({
        keystoreAgent: keystoreStub(account.clientKeys),
        idStore: account.idStore,
        expectedDid: OTHER_DID
      })
    ).rejects.toThrow('resolves to a different DID')
  })

  it('refuses an absent log under a held pin', async () => {
    const account = await provisionedAccount()
    const pinStore = memoryResourceLogPinStore()
    await readPublishedLog({ idStore: account.idStore, pinStore })

    const fresh = memoryIdStore()
    await fresh.idStore.putIdResource({
      resourceId: DID_DOCUMENT_RESOURCE,
      content: (await account.idStore.getIdResource({
        resourceId: DID_DOCUMENT_RESOURCE
      })) as object
    })
    const refusal = (await repairKeyBindings({
      keystoreAgent: keystoreStub(account.clientKeys),
      idStore: fresh.idStore,
      pinStore
    }).catch((err: unknown) => err)) as { name: string; reason: string }

    expect(refusal.name).toBe('ResourceLogContinuityError')
    expect(refusal.reason).toBe('rollback')
  })
})
