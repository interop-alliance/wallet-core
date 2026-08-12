/**
 * Unit tests for the enrolled-client listing entry points
 * (`src/clients/listing.ts`): the log read and the label read running
 * together rather than in sequence, and the `verifiedLog` seam that lets a
 * caller holding an already-verified log skip the fetch-and-verify entirely
 * (proved by making any fetch fail).
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  currentAccountSigningKeys,
  listAccountClients,
  type AccountLogPointer,
  type VerifiedAccountLog
} from '../../src/clients/listing.js'
import { verifyAccountLog } from '../../src/webvh/verifyLog.js'
import { ensureDidWebvh, type WebvhIdStore } from '../../src/webvh/didWebvh.js'
import {
  mintEnrollmentRequest,
  parseEnrollmentRequest
} from '../../src/enrollment/enrollment.js'
import type { ClientLabelsStore } from '../../src/keys/clientLabels.js'
import { DID_LOG_RESOURCE } from '../../src/space/collections.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-listing'
const DID_WEB = `did:web:localhost%3A8080:space:${SPACE_ID}:id`

/**
 * Provisions an account with one real client key set and returns its pointer
 * plus the published log text (what the world-readable fetch would serve).
 *
 * @returns {Promise<object>}
 */
async function publishedAccount() {
  let currentLog: string | undefined
  const idStore: WebvhIdStore = {
    async putKeyMap() {},
    async getIdResource() {
      return undefined
    },
    async getIdResourceRaw({ resourceId }: { resourceId: string }) {
      if (resourceId !== DID_LOG_RESOURCE || currentLog === undefined) {
        return undefined
      }
      // No ETags: the listing's store stands in for a backend without
      // conditional writes, where the ceremonies publish unconditionally.
      return { text: currentLog }
    },
    async putIdResource({
      resourceId,
      content
    }: {
      resourceId: string
      content: object | string
      contentType?: string
    }) {
      // The did:web projection is irrelevant to the listing; only the log is
      // kept, since that is what the world-readable fetch serves.
      if (resourceId === DID_LOG_RESOURCE && typeof content === 'string') {
        currentLog = content
      }
    }
  }
  const minted = await mintEnrollmentRequest()
  const client = parseEnrollmentRequest({ code: minted.code })
  const { did } = await ensureDidWebvh({
    idStore,
    wasServerUrl: WAS_URL,
    spaceId: SPACE_ID,
    didWebKeys: {
      authentication: {
        vmId: `${DID_WEB}#z6MkAuth`,
        kmsKeyId: 'kms/keys/auth'
      },
      keyAgreement: { vmId: `${DID_WEB}#z6LSAgree`, kmsKeyId: 'kms/keys/agree' }
    },
    clientKeys: {
      signingKeyMultibase: client.signingKeyMultibase,
      keyAgreementKeyMultibase: client.keyAgreementKeyMultibase
    },
    updateKeys: minted.webvhUpdateKeys
  })
  const pointer: AccountLogPointer = {
    did,
    spaceId: SPACE_ID,
    host: WAS_URL
  }
  return { pointer, client, logText: currentLog! }
}

/**
 * Serves the published log over a stubbed `fetch`, holding the response until
 * the returned `release` is called.
 *
 * @param logText {string}
 * @returns {object}
 */
function heldLogFetch(logText: string) {
  let release = () => {}
  const held = new Promise<void>(resolve => {
    release = resolve
  })
  let started = false
  vi.stubGlobal('fetch', async () => {
    started = true
    await held
    return new Response(logText, { status: 200 })
  })
  return { release: () => release(), started: () => started }
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('listAccountClients', () => {
  it('reads the log and the labels in parallel', async () => {
    const { pointer, client, logText } = await publishedAccount()
    const { release } = heldLogFetch(logText)
    let labelsRead = false
    const labelsStore: ClientLabelsStore = {
      async get() {
        labelsRead = true
        return {
          version: 1,
          labels: { [client.signingKeyMultibase]: 'Laptop' }
        }
      },
      async put() {}
    }

    const listing = listAccountClients({ pointer, labelsStore })
    // The log fetch is still outstanding, and the label read has already
    // happened: the two reads did not queue behind one another.
    await Promise.resolve()
    await Promise.resolve()
    expect(labelsRead).toBe(true)

    release()
    const rows = await listing
    expect(rows).toHaveLength(1)
    expect(rows[0]!.label).toBe('Laptop')
  })

  it('skips the fetch and verify when handed an already-verified log', async () => {
    const { pointer, client, logText } = await publishedAccount()
    const { release } = heldLogFetch(logText)
    release()
    const verifiedLog: VerifiedAccountLog = await verifyAccountLog(pointer)

    // Any further fetch is a failure: the verified log must be reused as is.
    vi.stubGlobal('fetch', async () => {
      throw new Error('the listing re-fetched the log')
    })
    const rows = await listAccountClients({
      pointer,
      verifiedLog,
      ownSigningKeyMultibase: client.signingKeyMultibase
    })
    expect(rows).toHaveLength(1)
    expect(rows[0]!.signingKeyMultibase).toBe(client.signingKeyMultibase)
    expect(rows[0]!.isCurrent).toBe(true)
    expect(rows[0]!.label).toBeUndefined()
  })

  it('fetches and verifies by default (no verified log supplied)', async () => {
    const { pointer, client, logText } = await publishedAccount()
    const { release, started } = heldLogFetch(logText)
    release()

    const rows = await listAccountClients({ pointer })
    expect(started()).toBe(true)
    expect(rows.map(row => row.signingKeyMultibase)).toEqual([
      client.signingKeyMultibase
    ])
  })
})

describe('currentAccountSigningKeys', () => {
  it('skips the fetch and verify when handed an already-verified log', async () => {
    const { pointer, client, logText } = await publishedAccount()
    const { release } = heldLogFetch(logText)
    release()
    const verifiedLog = await verifyAccountLog(pointer)

    vi.stubGlobal('fetch', async () => {
      throw new Error('the key-set read re-fetched the log')
    })
    const keys = await currentAccountSigningKeys({ pointer, verifiedLog })
    expect([...keys]).toEqual([client.signingKeyMultibase])
  })

  it('fetches and verifies by default (no verified log supplied)', async () => {
    const { pointer, client, logText } = await publishedAccount()
    const { release, started } = heldLogFetch(logText)
    release()

    const keys = await currentAccountSigningKeys({ pointer })
    expect(started()).toBe(true)
    expect([...keys]).toEqual([client.signingKeyMultibase])
  })
})
