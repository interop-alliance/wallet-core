/**
 * `collectionDescriptorStores` / `accountCollectionStores`: the
 * `(collectionId) => store` lookup builders over
 * `collectionDescriptorLogStore`. The generic one shares its resolver, pin
 * store, and signer across the stores it builds; the account one verifies
 * the account log once per lookup instance (a fan-out over several
 * collections fetches `did.jsonl` once), retries after a failed
 * verification, and fetches nothing when the caller hands the log over.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { readLogFromString } from '@interop/did-method-webvh'
import type { Collection } from '@interop/was-client'
import { agentsFromSeed } from '@interop/was-client/identity'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import {
  accountCollectionStores,
  collectionDescriptorStores
} from '../../src/keys/collectionLogStore.js'
import { userKeyRosterLogSigner } from '../../src/keys/userKeyRoster.js'
import { DID_LOG_RESOURCE } from '../../src/space/collections.js'
import { publishedAccount, stubFetch } from './fixtures/publishedAccount.js'
import { accountWithUnchangedEdit } from './fixtures/resourceLog.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-stores'
const LOG_URL = `${WAS_URL}/space/${SPACE_ID}/id/${DID_LOG_RESOURCE}`
const ACCOUNT = { wasServerUrl: WAS_URL, spaceId: SPACE_ID }

/**
 * Serves the account log at its URL and a 404 everywhere else (the
 * collection logs, read through the signing client), so a store read
 * resolves the controller and returns null.
 *
 * @param options {object}
 * @param options.serve {function}   `() => { status, body? }` per account-log
 *   fetch
 * @returns {{ accountLogFetches: () => number }}
 */
function stubAccountLog({
  serve
}: {
  serve: () => { status: number; body?: string }
}): { accountLogFetches: () => number } {
  const { fetchesOf } = stubFetch({
    serve: url => (url === LOG_URL ? serve() : { status: 404 })
  })
  return { accountLogFetches: () => fetchesOf(LOG_URL) }
}

/**
 * The bare parts an account-shaped lookup takes, over a fresh client.
 *
 * @returns {Promise<object>}
 */
async function bareParts() {
  const client = await agentsFromSeed({ seed: new Uint8Array(32).fill(5) })
  return {
    storageServerUrl: WAS_URL,
    zcapClient: client.zcapClient,
    spaceId: SPACE_ID,
    pinStore: memoryResourceLogPinStore(),
    signer: userKeyRosterLogSigner({ keyAgent: client.keyAgent })
  }
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('collectionDescriptorStores', () => {
  it('builds each store over the handle the reach returns, sharing the resolver', async () => {
    const { alice, beforeEdit } = await accountWithUnchangedEdit()
    const reached: string[] = []
    const resolveController = vi.fn(async () => beforeEdit)
    const storeFor = collectionDescriptorStores({
      collectionFor: collectionId => {
        reached.push(collectionId)
        return {
          id: collectionId,
          spaceId: SPACE_ID,
          getHistoryLog: async () => null
        } as unknown as Collection
      },
      resolveController,
      pinStore: memoryResourceLogPinStore(),
      signer: alice.logSigner
    })
    expect(reached).toEqual([])

    expect(await storeFor('a').read()).toBeNull()
    expect(await storeFor('b').read()).toBeNull()
    expect(reached).toEqual(['a', 'b'])
    expect(resolveController).toHaveBeenCalledTimes(2)
  })
})

describe('accountCollectionStores', () => {
  it('verifies the account log once for a lookup used over several collections', async () => {
    const { did, logText } = await publishedAccount(ACCOUNT)
    const { accountLogFetches } = stubAccountLog({
      serve: () => ({ status: 200, body: logText })
    })
    const storeFor = accountCollectionStores({ ...(await bareParts()), did })
    expect(accountLogFetches()).toBe(0)

    await Promise.all([
      storeFor('a').read(),
      storeFor('b').read(),
      storeFor('c').read()
    ])
    await storeFor('a').read()
    expect(accountLogFetches()).toBe(1)
  })

  it('retries the verification after a failed one', async () => {
    const { did, logText } = await publishedAccount(ACCOUNT)
    let served = 0
    const { accountLogFetches } = stubAccountLog({
      serve: () => {
        served += 1
        return served === 1 ? { status: 500 } : { status: 200, body: logText }
      }
    })
    const storeFor = accountCollectionStores({ ...(await bareParts()), did })

    await expect(storeFor('a').read()).rejects.toThrow(/HTTP 500/)
    expect(await storeFor('a').read()).toBeNull()
    expect(await storeFor('b').read()).toBeNull()
    expect(accountLogFetches()).toBe(2)
  })

  it('builds the view from a given log and never fetches did.jsonl', async () => {
    const { did, logText } = await publishedAccount(ACCOUNT)
    const { accountLogFetches } = stubAccountLog({
      serve: () => ({ status: 200, body: logText })
    })
    const storeFor = accountCollectionStores({
      ...(await bareParts()),
      did,
      log: readLogFromString(logText)
    })

    expect(await storeFor('a').read()).toBeNull()
    expect(await storeFor('b').read()).toBeNull()
    expect(accountLogFetches()).toBe(0)
  })
})
