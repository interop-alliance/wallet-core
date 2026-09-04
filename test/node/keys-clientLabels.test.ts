/**
 * Unit tests for the enrolled-client display labels
 * (`src/keys/clientLabels.ts`): the tolerant read (missing, malformed, and
 * partly malformed records all degrade to usable label maps), set/rename,
 * the blank-label removal shorthand, and the write-nothing no-op removal --
 * plus the WAS adapter's optional invocation capability
 * (`src/keys/wasLabelsStore.ts`), which both the read and the write ride when
 * one is supplied.
 */
import { describe, expect, it } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { WasClient } from '@interop/was-client'
import {
  readClientLabels,
  removeClientLabel,
  setClientLabel,
  type ClientLabelsStore
} from '../../src/keys/clientLabels.js'
import { wasClientLabelsStore } from '../../src/keys/wasLabelsStore.js'

const WAS_URL = 'https://was.example'
const SPACE_ID = 'space-labels'

/**
 * A delegation stub: the fake server verifies no invocation, so only the
 * object's presence on each request matters.
 */
const DELEGATION = { id: 'urn:zcap:delegated:test' } as IZcap

/**
 * A `WasClient` over a fake server that records every request's method and
 * whether it carried an invocation capability, and serves the one
 * `client-labels.json` resource out of a closure variable.
 *
 * @returns {object}
 */
function recordingWas() {
  const calls: Array<{ method: string; hasCapability: boolean }> = []
  let stored: object | undefined

  const zcapClient = {
    invocationSigner: { id: 'did:example:annex#vm-1' },
    async request({
      method,
      body,
      capability
    }: {
      url: string
      method?: string
      body?: Uint8Array
      capability?: unknown
    }) {
      const verb = (method ?? 'GET').toUpperCase()
      calls.push({ method: verb, hasCapability: capability !== undefined })
      if (verb === 'PUT') {
        stored = JSON.parse(new TextDecoder().decode(body)) as object
        return {
          status: 204,
          headers: new Headers(),
          data: undefined,
          async json() {
            return undefined
          }
        } as unknown as Response
      }
      if (stored === undefined) {
        throw { status: 404, response: { status: 404 } }
      }
      return {
        status: 200,
        headers: new Headers({ 'content-type': 'application/json' }),
        data: stored,
        async json() {
          return stored
        }
      } as unknown as Response
    }
  } as unknown as ZcapClient

  return {
    calls,
    stored: () => stored,
    was: new WasClient({ serverUrl: WAS_URL, zcapClient })
  }
}

/**
 * An in-memory `ClientLabelsStore` that counts writes.
 *
 * @param [initial] {unknown}   the stored body to start from
 * @returns {object}
 */
function memoryLabelsStore(initial?: unknown) {
  let body = initial
  let writes = 0
  const store: ClientLabelsStore = {
    async get() {
      return body
    },
    async put({ content }: { content: object }) {
      body = content
      writes++
    }
  }
  return { store, body: () => body, writes: () => writes }
}

describe('readClientLabels', () => {
  it('degrades a missing record to an empty label map', async () => {
    const { store } = memoryLabelsStore(undefined)
    expect(await readClientLabels({ store })).toEqual({
      version: 1,
      labels: {}
    })
  })

  it('degrades malformed records and drops non-string entries', async () => {
    for (const broken of ['nope', 42, null, { version: 2, labels: {} }]) {
      const { store } = memoryLabelsStore(broken)
      expect((await readClientLabels({ store })).labels).toEqual({})
    }
    const { store } = memoryLabelsStore({
      version: 1,
      labels: { z6MkA: 'Laptop Firefox', z6MkB: 7 }
    })
    expect((await readClientLabels({ store })).labels).toEqual({
      z6MkA: 'Laptop Firefox'
    })
  })

  it('degrades a throwing store to an empty label map', async () => {
    const store: ClientLabelsStore = {
      async get() {
        throw new Error('offline')
      },
      async put() {}
    }
    expect((await readClientLabels({ store })).labels).toEqual({})
  })
})

describe('setClientLabel / removeClientLabel', () => {
  it('sets, renames, and trims labels', async () => {
    const { store, body } = memoryLabelsStore()
    await setClientLabel({
      store,
      signingKeyMultibase: 'z6MkA',
      label: '  Laptop Firefox  '
    })
    expect(body()).toEqual({ version: 1, labels: { z6MkA: 'Laptop Firefox' } })

    const renamed = await setClientLabel({
      store,
      signingKeyMultibase: 'z6MkA',
      label: 'Desk browser'
    })
    expect(renamed.labels).toEqual({ z6MkA: 'Desk browser' })
  })

  it('treats a blank label as removal', async () => {
    const { store } = memoryLabelsStore({
      version: 1,
      labels: { z6MkA: 'Laptop' }
    })
    const updated = await setClientLabel({
      store,
      signingKeyMultibase: 'z6MkA',
      label: '   '
    })
    expect(updated.labels).toEqual({})
  })

  it('removes one entry and writes nothing when it is already absent', async () => {
    const { store, writes } = memoryLabelsStore({
      version: 1,
      labels: { z6MkA: 'Laptop', z6MkB: 'Phone' }
    })
    const updated = await removeClientLabel({
      store,
      signingKeyMultibase: 'z6MkA'
    })
    expect(updated.labels).toEqual({ z6MkB: 'Phone' })
    expect(writes()).toBe(1)

    await removeClientLabel({ store, signingKeyMultibase: 'z6MkA' })
    expect(writes()).toBe(1)
  })
})

describe('wasClientLabelsStore', () => {
  it('rides a supplied capability on both the read and the write', async () => {
    const { was, calls, stored } = recordingWas()
    const store = wasClientLabelsStore({
      was,
      spaceId: SPACE_ID,
      capability: DELEGATION
    })

    await setClientLabel({
      store,
      signingKeyMultibase: 'z6MkA',
      label: 'Laptop Firefox'
    })
    expect(stored()).toEqual({
      version: 1,
      labels: { z6MkA: 'Laptop Firefox' }
    })
    expect(await readClientLabels({ store })).toEqual({
      version: 1,
      labels: { z6MkA: 'Laptop Firefox' }
    })

    // The set's own read-modify-write read, its write, and the read above:
    // every request a session holding only a generation delegation makes.
    expect(calls.length).toBeGreaterThanOrEqual(3)
    expect(calls.map(call => call.method)).toContain('PUT')
    expect(calls.every(call => call.hasCapability)).toBe(true)
  })

  it('invokes the root capability when none is supplied', async () => {
    const { was, calls } = recordingWas()
    const store = wasClientLabelsStore({ was, spaceId: SPACE_ID })

    await setClientLabel({
      store,
      signingKeyMultibase: 'z6MkA',
      label: 'Laptop Firefox'
    })
    await readClientLabels({ store })

    expect(calls.map(call => call.method)).toContain('PUT')
    expect(calls.some(call => call.hasCapability)).toBe(false)
  })
})
