/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The unlock Space's keyring read and write: one request shape whether the
 * call is a root invocation by the unlock identity or rides the management
 * zcap the unlock identity delegated at bind time, so the capability only
 * changes the invocation form and never the URL or the body.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'
import { agentsFromSeed } from '@interop/was-client/identity'
import {
  KEYRING_COLLECTION,
  KEYRING_RESOURCE
} from '../../src/space/collections.js'
import {
  getUnlockKeyring,
  putUnlockKeyring
} from '../../src/keyring/unlockSpace.js'

const WAS_URL = 'https://storage.example/was'
const UNLOCK_SPACE_ID = 'unlock-space-1'
const KEYRING_URL = `${WAS_URL}/space/${UNLOCK_SPACE_ID}/${KEYRING_COLLECTION.id}/${KEYRING_RESOURCE}`
const RECORD = { version: 2, wrapped: 'ciphertext' }

/**
 * A deterministic 32-byte seed.
 */
function fixedSeed(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill)
}

/**
 * Captures every request sent and answers each with the given status and
 * JSON body.
 */
function stubFetch({ status, body }: { status: number; body?: object }) {
  const requests: Array<{
    url: string
    method: string
    contentType: string | null
    body: string | null
    invocation: string | null
  }> = []
  vi.stubGlobal(
    'fetch',
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const request =
        input instanceof Request ? input : new Request(input, init)
      requests.push({
        url: request.url,
        method: request.method,
        contentType: request.headers.get('content-type'),
        body: request.method === 'PUT' ? await request.text() : null,
        invocation: request.headers.get('capability-invocation')
      })
      return new Response(body === undefined ? null : JSON.stringify(body), {
        status,
        headers:
          body === undefined ? {} : { 'content-type': 'application/json' }
      })
    }
  )
  return requests
}

/**
 * The management zcap an unlock identity delegates to an enrolled client
 * at bind time, plus that client.
 */
async function delegatedFixture() {
  const unlock = await agentsFromSeed({ seed: fixedSeed(7) })
  const client = await agentsFromSeed({ seed: fixedSeed(3) })
  const capability = (await unlock.zcapClient.delegate({
    invocationTarget: `${WAS_URL}/space/${UNLOCK_SPACE_ID}`,
    controller: client.keyAgent.id,
    allowedActions: ['GET', 'PUT', 'DELETE'],
    expires: new Date(Date.now() + 60_000)
  })) as IZcap
  return { unlock, client, capability }
}

describe('getUnlockKeyring', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('reads the keyring by root invocation', async () => {
    const { unlock } = await delegatedFixture()
    const requests = stubFetch({ status: 200, body: RECORD })
    await expect(
      getUnlockKeyring({
        storageServerUrl: WAS_URL,
        zcapClient: unlock.zcapClient,
        spaceId: UNLOCK_SPACE_ID
      })
    ).resolves.toEqual(RECORD)
    expect(requests).toHaveLength(1)
    expect(requests[0]!.method).toBe('GET')
    expect(requests[0]!.url).toBe(KEYRING_URL)
    expect(requests[0]!.invocation).not.toMatch(/capability="/)
  })

  it('reads the keyring under the supplied capability', async () => {
    const { client, capability } = await delegatedFixture()
    const requests = stubFetch({ status: 200, body: RECORD })
    await expect(
      getUnlockKeyring({
        storageServerUrl: WAS_URL,
        zcapClient: client.zcapClient,
        spaceId: UNLOCK_SPACE_ID,
        capability
      })
    ).resolves.toEqual(RECORD)
    expect(requests).toHaveLength(1)
    expect(requests[0]!.url).toBe(KEYRING_URL)
    expect(requests[0]!.invocation).toMatch(/capability="/)
  })

  it('reports an absent record as null', async () => {
    const { client, capability } = await delegatedFixture()
    stubFetch({ status: 404 })
    await expect(
      getUnlockKeyring({
        storageServerUrl: WAS_URL,
        zcapClient: client.zcapClient,
        spaceId: UNLOCK_SPACE_ID,
        capability
      })
    ).resolves.toBeNull()
  })
})

describe('putUnlockKeyring', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('writes the same JSON body with and without a capability', async () => {
    const { unlock, client, capability } = await delegatedFixture()
    const requests = stubFetch({ status: 204 })
    await putUnlockKeyring({
      storageServerUrl: WAS_URL,
      zcapClient: unlock.zcapClient,
      spaceId: UNLOCK_SPACE_ID,
      record: RECORD
    })
    await putUnlockKeyring({
      storageServerUrl: WAS_URL,
      zcapClient: client.zcapClient,
      spaceId: UNLOCK_SPACE_ID,
      record: RECORD,
      capability
    })
    expect(requests).toHaveLength(2)
    for (const request of requests) {
      expect(request.method).toBe('PUT')
      expect(request.url).toBe(KEYRING_URL)
      expect(request.contentType).toBe('application/json')
      expect(request.body).toBe(JSON.stringify(RECORD))
    }
    expect(requests[0]!.invocation).not.toMatch(/capability="/)
    expect(requests[1]!.invocation).toMatch(/capability="/)
  })
})
