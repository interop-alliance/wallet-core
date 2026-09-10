/**
 * A provisioned one-client account and the fetch stub that serves its log:
 * the fixture every suite that verifies a published `did.jsonl` over the
 * world-readable fetch shares (log verification, the account-shaped store
 * builders), so the provisioning and the stub are stated once.
 */
import { vi } from 'vitest'
import {
  ensureDidWebvh,
  mintClientWebvhUpdateKeys
} from '../../../src/webvh/didWebvh.js'
import { memoryIdStore } from './memoryIdStore.js'
import { CANONICAL_CLIENT_KEYS } from './clientKeys.js'

/**
 * Provisions a one-client account over a fresh in-memory id store and
 * returns its DID, the published log text (what the world-readable fetch
 * would serve), and the store.
 *
 * @param options {object}
 * @param options.wasServerUrl {string}
 * @param options.spaceId {string}
 * @returns {Promise<object>}
 */
export async function publishedAccount({
  wasServerUrl,
  spaceId
}: {
  wasServerUrl: string
  spaceId: string
}): Promise<{
  did: string
  logText: string
  idStore: ReturnType<typeof memoryIdStore>['idStore']
}> {
  const { idStore, log } = memoryIdStore({ spaceId })
  const didWeb = `did:web:${encodeURIComponent(new URL(wasServerUrl).host)}:space:${spaceId}:id`
  const { did } = await ensureDidWebvh({
    idStore,
    wasServerUrl,
    spaceId,
    didWebKeys: {
      authentication: {
        vmId: `${didWeb}#z6MkAuth`,
        kmsKeyId: 'kms/keys/auth'
      }
    },
    clientKeys: { ...CANONICAL_CLIENT_KEYS[0] },
    updateKeys: mintClientWebvhUpdateKeys()
  })
  return { did, logText: log()!, idStore }
}

/**
 * Stubs the global fetch with `serve`, called per request with the URL, and
 * returns a per-URL call counter.
 *
 * @param options {object}
 * @param options.serve {function}   `(url) => { status, body? }`
 * @returns {{ fetchesOf: (url: string) => number }}
 */
export function stubFetch({
  serve
}: {
  serve: (url: string) => { status: number; body?: string }
}): { fetchesOf: (url: string) => number } {
  const fetches = new Map<string, number>()
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request) => {
      const url =
        typeof input === 'string'
          ? input
          : input instanceof URL
            ? input.href
            : input.url
      fetches.set(url, (fetches.get(url) ?? 0) + 1)
      const response = serve(url)
      return {
        status: response.status,
        ok: response.status < 400,
        headers: new Headers(),
        text: async () => response.body ?? '',
        json: async () => ({})
      }
    })
  )
  return { fetchesOf: url => fetches.get(url) ?? 0 }
}
