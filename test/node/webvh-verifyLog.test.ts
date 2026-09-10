/**
 * Unit tests for the published-log verification step (`verifyAccountLog`):
 * a real one-client account log served over a stubbed fetch, the
 * substituted-account refusal, the absent-log signal, a transport failure,
 * and the unresolvable-log message (which must never render "undefined" when
 * the resolver reports no error of its own). Plus the caller-supplied head:
 * the fetch is skipped and the substituted-account refusal runs on it exactly
 * as on a served log (its chain-head half lives in the pin suite). And the
 * memoized resolver over it (`accountControllerResolver`): one verification
 * shared across calls, a retry after a failure, no fetch over a given log.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'

/**
 * The resolver seam, so the "no did/doc without an error string" branch --
 * unreachable through a real log, and exactly the branch that used to render
 * "undefined" -- can be exercised. `null` means "use the real resolver".
 */
const { resolveOverride } = vi.hoisted(() => ({
  resolveOverride: { value: null as null | (() => unknown) }
}))
vi.mock('@interop/did-method-webvh', async importOriginal => {
  const actual =
    await importOriginal<typeof import('@interop/did-method-webvh')>()
  return {
    ...actual,
    resolveDIDFromLog: async (...args: unknown[]) =>
      resolveOverride.value
        ? resolveOverride.value()
        : (
            actual.resolveDIDFromLog as unknown as (
              ...inner: unknown[]
            ) => unknown
          )(...args)
  }
})
import { readLogFromString } from '@interop/did-method-webvh'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import {
  accountControllerResolver,
  AccountLogMissingError,
  verifiedAccountLogOf,
  verifyAccountLog
} from '../../src/webvh/verifyLog.js'
import { readPublishedLog } from '../../src/webvh/didWebvh.js'
import { DID_LOG_RESOURCE } from '../../src/space/collections.js'
import { publishedAccount, stubFetch } from './fixtures/publishedAccount.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-verify'
const ACCOUNT = { wasServerUrl: WAS_URL, spaceId: SPACE_ID }

afterEach(() => {
  vi.unstubAllGlobals()
  resolveOverride.value = null
})

describe('verifyAccountLog', () => {
  it('fetches, resolves, and returns the document and log of the named DID', async () => {
    const { did, logText } = await publishedAccount(ACCOUNT)
    stubFetch({ serve: () => ({ status: 200, body: logText }) })

    const verified = await verifyAccountLog({
      did,
      spaceId: SPACE_ID,
      host: WAS_URL
    })
    expect(verified.doc.id).toBe(did)
    expect(verified.log.length).toBeGreaterThan(0)
    expect(verified.updateKeys.length).toBeGreaterThan(0)
    expect(verified.nextKeyHashes.length).toBeGreaterThan(0)
    // The log resource is read from the Space's world-readable `id`
    // collection, unauthenticated.
    const [url] = vi.mocked(fetch).mock.calls[0]!
    expect(String(url)).toBe(
      `${WAS_URL}/space/${SPACE_ID}/id/${DID_LOG_RESOURCE}`
    )
  })

  it('refuses a log that resolves to a different DID', async () => {
    const { logText } = await publishedAccount(ACCOUNT)
    stubFetch({ serve: () => ({ status: 200, body: logText }) })

    await expect(
      verifyAccountLog({
        did: 'did:webvh:QmSomeoneElse:localhost%3A8080:space:other:id',
        spaceId: SPACE_ID,
        host: WAS_URL
      })
    ).rejects.toThrow('resolves to a different DID')
  })

  it('signals an absent log distinctly', async () => {
    stubFetch({ serve: () => ({ status: 404 }) })
    await expect(
      verifyAccountLog({
        did: 'did:webvh:x:y',
        spaceId: SPACE_ID,
        host: WAS_URL
      })
    ).rejects.toThrow(AccountLogMissingError)
  })

  it('reports a transport failure with its status', async () => {
    stubFetch({ serve: () => ({ status: 503 }) })
    await expect(
      verifyAccountLog({
        did: 'did:webvh:x:y',
        spaceId: SPACE_ID,
        host: WAS_URL
      })
    ).rejects.toThrow('HTTP 503')
  })

  it('never renders "undefined" for a log that simply does not resolve', async () => {
    // The resolver returns no did/doc and reports no error string of its own.
    const { logText } = await publishedAccount(ACCOUNT)
    stubFetch({ serve: () => ({ status: 200, body: logText }) })
    resolveOverride.value = () => ({ meta: {} })
    await expect(
      verifyAccountLog({
        did: 'did:webvh:x:y',
        spaceId: SPACE_ID,
        host: WAS_URL
      })
    ).rejects.toThrow(
      /failed to resolve \(the resolver returned no DID document\)/
    )
  })
})

describe('verifyAccountLog over a caller-supplied head', () => {
  it('skips the fetch and returns the same shape', async () => {
    const account = await publishedAccount(ACCOUNT)
    const published = await readPublishedLog({ idStore: account.idStore })
    const fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)

    const verified = await verifyAccountLog({
      did: account.did,
      spaceId: SPACE_ID,
      host: WAS_URL,
      published: published!
    })

    expect(fetchSpy).not.toHaveBeenCalled()
    expect(verified).toEqual(verifiedAccountLogOf({ published: published! }))
    expect(verified.doc.id).toBe(account.did)
  })

  it('refuses a supplied head naming another DID', async () => {
    const account = await publishedAccount(ACCOUNT)
    const published = await readPublishedLog({ idStore: account.idStore })
    vi.stubGlobal('fetch', vi.fn())

    await expect(
      verifyAccountLog({
        did: 'did:webvh:another:account',
        spaceId: SPACE_ID,
        host: WAS_URL,
        published: published!
      })
    ).rejects.toThrow(/different DID/)
  })
})

describe('accountControllerResolver', () => {
  it('verifies once across calls and retries after a failure', async () => {
    const { did, logText } = await publishedAccount(ACCOUNT)
    let served = 0
    stubFetch({
      serve: () => {
        served += 1
        return served === 1 ? { status: 500 } : { status: 200, body: logText }
      }
    })
    const resolve = accountControllerResolver({
      did,
      spaceId: SPACE_ID,
      host: WAS_URL,
      pinStore: memoryResourceLogPinStore()
    })
    expect(served).toBe(0)

    await expect(resolve()).rejects.toThrow(/HTTP 500/)
    const [first, second] = await Promise.all([resolve(), resolve()])
    expect(first).toBe(second)
    expect(await resolve()).toBe(first)
    expect(served).toBe(2)
  })

  it('builds the view from a given log and never fetches', async () => {
    const { did, logText } = await publishedAccount(ACCOUNT)
    const fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)
    const resolve = accountControllerResolver({
      did,
      spaceId: SPACE_ID,
      host: WAS_URL,
      pinStore: memoryResourceLogPinStore(),
      log: readLogFromString(logText)
    })

    expect((await resolve()).did).toBe(did)
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
