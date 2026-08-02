/**
 * Unit tests for the enrolled-client display labels
 * (`src/keys/clientLabels.ts`): the tolerant read (missing, malformed, and
 * partly malformed records all degrade to usable label maps), set/rename,
 * the blank-label removal shorthand, and the write-nothing no-op removal.
 */
import { describe, expect, it } from 'vitest'
import {
  readClientLabels,
  removeClientLabel,
  setClientLabel,
  type ClientLabelsStore
} from '../../src/keys/clientLabels.js'

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
