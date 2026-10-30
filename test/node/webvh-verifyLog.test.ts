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
  accountLogPinId,
  AccountLogMissingError,
  discoverAccountLog,
  verifiedAccountLogOf,
  verifyAccountLog
} from '../../src/webvh/verifyLog.js'
import { readPublishedLog } from '../../src/webvh/didWebvh.js'
import { didWebvhLogLocation } from '../../src/webvh/logLocation.js'
import { DID_LOG_RESOURCE } from '../../src/space/collections.js'
import { publishedAccount, stubFetch } from './fixtures/publishedAccount.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-verify'
const SPACE_URL = `${WAS_URL}/space/${SPACE_ID}/`
const LOG_URL = `${SPACE_URL}id/${DID_LOG_RESOURCE}`
const ACCOUNT = { baseServerUrl: WAS_URL, spaceId: SPACE_ID }
// A well-formed SCID (the did:webvh parser checks for one) that no log here
// was minted under: a DID carrying it at the account's own location names
// another account published at the same place.
const OTHER_SCID = 'durCj2h8E75t8UAyyiZE6WBJwJuPasUm8C1d3KJcqZTfeu'
const OTHER_DID = `did:webvh:${OTHER_SCID}:localhost%3A8080:space:${SPACE_ID}:id`

afterEach(() => {
  vi.unstubAllGlobals()
  resolveOverride.value = null
})

describe('verifyAccountLog', () => {
  it('fetches, resolves, and returns the document and log of the named DID', async () => {
    const { did, logText } = await publishedAccount(ACCOUNT)
    stubFetch({
      serverUrl: WAS_URL,
      serve: () => ({ status: 200, body: logText })
    })

    const verified = await verifyAccountLog({ did })
    expect(verified.doc.id).toBe(did)
    expect(verified.log.length).toBeGreaterThan(0)
    expect(verified.updateKeys.length).toBeGreaterThan(0)
    expect(verified.nextKeyHashes.length).toBeGreaterThan(0)
    // The log resource is read from the Space's world-readable `id`
    // collection, unauthenticated, at the URL the DID itself encodes.
    const [url] = vi.mocked(fetch).mock.calls[0]!
    expect(String(url)).toBe(LOG_URL)
    expect(String(url)).toBe(didWebvhLogLocation({ did }).logUrl)
  })

  it('fetches the log at the URL the DID encodes', async () => {
    const { did, logText } = await publishedAccount(ACCOUNT)
    stubFetch({
      serverUrl: WAS_URL,
      serve: () => ({ status: 200, body: logText })
    })

    const verified = await verifyAccountLog({ did })
    expect(verified.doc.id).toBe(did)
    const [url] = vi.mocked(fetch).mock.calls[0]!
    expect(String(url)).toBe(LOG_URL)
  })

  it('refuses a log that resolves to a different DID', async () => {
    const { logText } = await publishedAccount(ACCOUNT)
    stubFetch({
      serverUrl: WAS_URL,
      serve: () => ({ status: 200, body: logText })
    })

    await expect(verifyAccountLog({ did: OTHER_DID })).rejects.toThrow(
      'resolves to a different DID'
    )
  })

  it('signals an absent log distinctly', async () => {
    stubFetch({ serverUrl: WAS_URL, serve: () => ({ status: 404 }) })
    await expect(verifyAccountLog({ did: OTHER_DID })).rejects.toThrow(
      AccountLogMissingError
    )
  })

  it('reports a transport failure with its status', async () => {
    stubFetch({ serverUrl: WAS_URL, serve: () => ({ status: 503 }) })
    await expect(verifyAccountLog({ did: OTHER_DID })).rejects.toThrow(
      'HTTP 503'
    )
  })

  it('never renders "undefined" for a log that simply does not resolve', async () => {
    // The resolver returns no did/doc and reports no error string of its own.
    const { logText } = await publishedAccount(ACCOUNT)
    stubFetch({
      serverUrl: WAS_URL,
      serve: () => ({ status: 200, body: logText })
    })
    resolveOverride.value = () => ({ meta: {} })
    await expect(verifyAccountLog({ did: OTHER_DID })).rejects.toThrow(
      /failed to resolve \(the resolver returned no DID document\)/
    )
  })
})

describe('discoverAccountLog', () => {
  it('resolves the owner of a Space from the log published there', async () => {
    const { did, logText } = await publishedAccount(ACCOUNT)
    stubFetch({
      serverUrl: WAS_URL,
      serve: () => ({ status: 200, body: logText })
    })

    const discovered = await discoverAccountLog({ spaceUrl: SPACE_URL })
    expect(discovered.did).toBe(did)
    expect(discovered.doc.id).toBe(did)
    expect(discovered.log.length).toBeGreaterThan(0)
    expect(discovered.updateKeys.length).toBeGreaterThan(0)
    const [url] = vi.mocked(fetch).mock.calls[0]!
    expect(String(url)).toBe(LOG_URL)
  })

  it('refuses a log published for another location and served here', async () => {
    // A genuine log, published for another Space, served under this one.
    const { did } = await publishedAccount(ACCOUNT)
    const other = await publishedAccount({
      baseServerUrl: WAS_URL,
      spaceId: 'space-elsewhere'
    })
    stubFetch({
      serverUrl: WAS_URL,
      serve: () => ({ status: 200, body: other.logText })
    })

    await expect(discoverAccountLog({ spaceUrl: SPACE_URL })).rejects.toThrow(
      /log location .* is not where it was served from/
    )
    // The expected-DID reader fetches at this DID's own location and runs the
    // same check ahead of its own, so the other account's log served there
    // is refused too.
    await expect(verifyAccountLog({ did })).rejects.toThrow(
      /not where it was served from/
    )
  })

  it('locates a log created under a sub-path base server URL through its DID', async () => {
    // The DID encodes the base server URL's path prefix as colon segments,
    // so a log created under `https://wallet.example/was/` is fetched at
    // `https://wallet.example/was/space/<id>/id/did.jsonl`.
    const subPathBase = 'https://wallet.example/was/'
    const { did, logText } = await publishedAccount({
      baseServerUrl: subPathBase,
      spaceId: SPACE_ID
    })
    expect(did).toMatch(
      new RegExp(`^did:webvh:[^:]+:wallet.example:was:space:${SPACE_ID}:id$`)
    )
    stubFetch({
      serverUrl: subPathBase,
      serve: () => ({ status: 200, body: logText })
    })

    const subPathSpaceUrl = `${subPathBase}space/${SPACE_ID}/`
    const discovered = await discoverAccountLog({ spaceUrl: subPathSpaceUrl })
    expect(discovered.did).toBe(did)
    const verified = await verifyAccountLog({ did })
    expect(verified.doc.id).toBe(did)
    for (const [url] of vi.mocked(fetch).mock.calls) {
      expect(String(url)).toBe(`${subPathSpaceUrl}id/${DID_LOG_RESOURCE}`)
    }
  })

  it('refuses a log served at another location than its DID encodes', async () => {
    // The same log, published for the sub-path base, served from an
    // origin-root mount: the resolved DID locates `/was/space/...`, not the
    // URL it was fetched from.
    const { logText } = await publishedAccount({
      baseServerUrl: 'https://wallet.example/was/',
      spaceId: SPACE_ID
    })
    stubFetch({
      serverUrl: 'https://wallet.example',
      serve: () => ({ status: 200, body: logText })
    })

    await expect(
      discoverAccountLog({
        spaceUrl: `https://wallet.example/space/${SPACE_ID}/`
      })
    ).rejects.toThrow(/log location .* is not where it was served from/)
  })

  it('refuses a tampered log', async () => {
    const { logText } = await publishedAccount(ACCOUNT)
    const entries = logText.trimEnd().split('\n')
    const head = JSON.parse(entries[entries.length - 1]!)
    head.state.service = [{ id: '#x', type: 'Planted', serviceEndpoint: 'x' }]
    entries[entries.length - 1] = JSON.stringify(head)
    stubFetch({
      serverUrl: WAS_URL,
      serve: () => ({ status: 200, body: entries.join('\n') + '\n' })
    })

    // The resolver refuses the broken hash chain itself, so no DID comes out.
    await expect(discoverAccountLog({ spaceUrl: SPACE_URL })).rejects.toThrow(
      /not derived from logEntryHash/
    )
  })

  it('signals an absent log distinctly', async () => {
    stubFetch({ serverUrl: WAS_URL, serve: () => ({ status: 404 }) })
    await expect(discoverAccountLog({ spaceUrl: SPACE_URL })).rejects.toThrow(
      AccountLogMissingError
    )
  })

  it('checks and advances the chain-head pin under the account log slot', async () => {
    const { logText } = await publishedAccount(ACCOUNT)
    stubFetch({
      serverUrl: WAS_URL,
      serve: () => ({ status: 200, body: logText })
    })
    const pinStore = memoryResourceLogPinStore()
    const discovered = await discoverAccountLog({
      spaceUrl: SPACE_URL,
      pinStore
    })
    const pin = await pinStore.read({
      logId: accountLogPinId({ spaceId: SPACE_ID })
    })
    expect(pin?.head).toBe(discovered.log[discovered.log.length - 1]!.versionId)
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
        did: OTHER_DID,
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
      serverUrl: WAS_URL,
      serve: () => {
        served += 1
        return served === 1 ? { status: 500 } : { status: 200, body: logText }
      }
    })
    const resolve = accountControllerResolver({
      did,
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
      pinStore: memoryResourceLogPinStore(),
      log: readLogFromString(logText)
    })

    expect((await resolve()).did).toBe(did)
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
