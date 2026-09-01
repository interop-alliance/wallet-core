/**
 * Unit tests for the client annex did:webvh machinery: generation identity
 * (`gen-<random>` generation ids), the annex genesis (static rung-0 update
 * authority, prerotation via rung-0 hash commitments, no witnesses,
 * portability off, a bare zero-VM document), the parameterized WAS log store
 * (an annex collection served without disturbing the account-log paths),
 * the delegated store's CAS/ETag discipline, the in-memory chain-head pin
 * a transient session keeps for annex continuity, and the `#DelegatedClients`
 * pointer-history walk over a verified account log.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { DIDLog } from '@interop/did-method-webvh'
import {
  defaultWebvhLogVerifier,
  deriveNextKeyHash,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { WasClient } from '@interop/was-client'
import {
  memoryResourceLogPinStore,
  ResourceLogContinuityError
} from '@interop/vh-resource-log'
import {
  assertGenerationId,
  CLIENT_ANNEX_SPACE_TYPE,
  clientAnnexLogPinId,
  clientAnnexLogStore,
  createClientAnnexLog,
  delegatedClientsSpaceHistory,
  ensureClientAnnexSpace,
  enrollClientAnnexTransientClient,
  GENERATION_ID_PREFIX,
  mintClientAnnexGeneration,
  mintCredentialClientAnnexGeneration,
  mintGenerationId
} from '../../src/clientAnnex/log.js'
import { clientAnnexRung } from '../../src/clientAnnex/ladder.js'
import { delegatedWebvhLogStore } from '../../src/webvh/delegatedLogStore.js'
import {
  putLogResource,
  readPublishedLog,
  updateKeyMultibase,
  updateKeySigner,
  WebvhLogConflictError,
  withLogConflictRetry
} from '../../src/webvh/didWebvh.js'
import type { WebvhIdStore } from '../../src/webvh/didWebvh.js'
import { wasWebvhIdStore } from '../../src/webvh/wasIdStore.js'

const WAS_URL = 'https://was.example'
const AUX_SPACE_ID = 'aux-space-clientAnnex'
const ACCOUNT_SPACE_ID = 'acct-space'

/**
 * A fresh Ed25519 update-key seed with its public multibase and signer -- the
 * shape of one standing credential's annex rung 0.
 */
async function mintedRungZero() {
  const seed = crypto.getRandomValues(new Uint8Array(32))
  return {
    seed,
    keyMultibase: await updateKeyMultibase({ seed }),
    signer: await updateKeySigner({ seed })
  }
}

/**
 * An annex genesis's update-authority inputs: the minting credential's
 * rung 0 plus one other standing credential's, with `nextKeyHashes` holding
 * both rung-0 hashes (the minting key's carry-over included).
 */
async function mintedGenesisAuthority() {
  const minting = await mintedRungZero()
  const other = await mintedRungZero()
  return {
    minting,
    other,
    nextKeyHashes: [
      await deriveNextKeyHash(minting.keyMultibase),
      await deriveNextKeyHash(other.keyMultibase)
    ]
  }
}

/**
 * The recorded shape of one signed request the fake server saw.
 */
interface RecordedCall {
  method: string
  url: string
  headers: Record<string, string>
  hasCapability: boolean
}

/**
 * An in-memory WAS server behind a fake ezcap client: Space and Collection
 * Descriptions as JSON rows, resources as versioned text rows whose version
 * is the ETag, `if-match` / `if-none-match` enforced with a bare
 * `{ status: 412 }` throw (what the raw signed request surfaces), and 404s
 * thrown as `{ status: 404 }`. Every call is recorded, so a test can assert
 * exactly which paths a store touched.
 */
function fakeServer() {
  const descriptions = new Map<string, object>()
  const resources = new Map<
    string,
    { text: string; version: number; contentType: string }
  >()
  const calls: RecordedCall[] = []

  const lowerHeaders = (headers?: Record<string, string>) =>
    Object.fromEntries(
      Object.entries(headers ?? {}).map(([key, value]) => [
        key.toLowerCase(),
        value
      ])
    )

  const jsonResponse = (data: unknown) =>
    ({
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      data,
      async json() {
        return data
      }
    }) as unknown as Response

  const okResponse = () =>
    ({
      status: 200,
      headers: new Headers(),
      data: undefined,
      async json() {
        return undefined
      }
    }) as unknown as Response

  const textResponse = (row: { text: string; version: number }) =>
    ({
      status: 200,
      headers: new Headers({
        'content-type': 'text/jsonl',
        etag: `"${row.version}"`
      }),
      async text() {
        return row.text
      },
      async blob() {
        return new Blob([row.text], { type: 'text/jsonl' })
      }
    }) as unknown as Response

  const zcapClient = {
    invocationSigner: { id: 'did:example:client#key-1' },
    async request({
      url,
      method,
      headers,
      json,
      body,
      capability
    }: {
      url: string
      method?: string
      headers?: Record<string, string>
      json?: object
      body?: Uint8Array
      capability?: unknown
    }) {
      const verb = (method ?? 'GET').toUpperCase()
      const lowered = lowerHeaders(headers)
      calls.push({
        method: verb,
        url,
        headers: lowered,
        hasCapability: capability !== undefined
      })
      const path = new URL(url).pathname
      const segments = path.split('/').filter(Boolean)
      // /space/<spaceId> and /space/<spaceId>/<collectionId> are Description
      // routes; /space/<spaceId>/<collectionId>/<resourceId> is a resource.
      if (segments[0] !== 'space') {
        throw new Error(`Unrouted path "${path}".`)
      }
      if (segments.length === 2 || segments.length === 3) {
        if (verb === 'PUT') {
          descriptions.set(path, json ?? {})
          return okResponse()
        }
        const description = descriptions.get(path)
        if (description === undefined) {
          throw { status: 404, response: { status: 404 } }
        }
        return jsonResponse(description)
      }
      if (segments.length === 4) {
        const row = resources.get(path)
        if (verb === 'GET') {
          if (row === undefined) {
            throw { status: 404, response: { status: 404 } }
          }
          return textResponse(row)
        }
        if (verb === 'PUT') {
          if (lowered['if-none-match'] === '*' && row !== undefined) {
            throw { status: 412, response: { status: 412 } }
          }
          const ifMatch = lowered['if-match']
          if (
            ifMatch !== undefined &&
            ifMatch !== `"${row?.version ?? 'absent'}"`
          ) {
            throw { status: 412, response: { status: 412 } }
          }
          resources.set(path, {
            text: new TextDecoder().decode(body),
            version: (row?.version ?? 0) + 1,
            contentType: lowered['content-type'] ?? 'application/octet-stream'
          })
          return okResponse()
        }
      }
      throw new Error(`Unrouted ${verb} "${path}".`)
    }
  } as unknown as ZcapClient

  return {
    calls,
    descriptions,
    resources,
    was: new WasClient({ serverUrl: WAS_URL, zcapClient }),
    zcapClient
  }
}

/**
 * A delegation stub: the fake server never verifies invocations, so only the
 * object's presence matters.
 */
const DELEGATION = { id: 'urn:zcap:delegated:test' } as IZcap

describe('generation ids', () => {
  it('mints "gen-" plus 16 base64url characters, 20 characters total', () => {
    const generationId = mintGenerationId()
    expect(generationId.startsWith(GENERATION_ID_PREFIX)).toBe(true)
    expect(generationId).toHaveLength(20)
    expect(() => assertGenerationId(generationId)).not.toThrow()
    // Inside the server's id allowlist: encodeURIComponent is the identity.
    expect(encodeURIComponent(generationId)).toBe(generationId)
  })

  it('mints distinct generation ids', () => {
    const minted = new Set(Array.from({ length: 32 }, () => mintGenerationId()))
    expect(minted.size).toBe(32)
  })

  it('refuses malformed generation ids', () => {
    for (const bad of [
      'gen-short',
      'gen-' + 'a'.repeat(17),
      'id',
      'gen-Ux3v0kQf9aPmB2h!',
      'GEN-Ux3v0kQf9aPmB2hZ'
    ]) {
      expect(() => assertGenerationId(bad)).toThrow(/generation id/)
    }
  })
})

describe('createClientAnnexLog', () => {
  it('publishes the client annex genesis configuration', async () => {
    const { minting, nextKeyHashes } = await mintedGenesisAuthority()
    const generationId = mintGenerationId()
    const created = await createClientAnnexLog({
      wasServerUrl: WAS_URL,
      spaceId: AUX_SPACE_ID,
      generationId,
      updateKeyPublicKeyMultibase: minting.keyMultibase,
      nextKeyHashes,
      signer: minting.signer
    })

    // The DID embeds the auxiliary Space id and the generation id.
    expect(created.did).toContain(`:space:${AUX_SPACE_ID}:${generationId}`)

    // The log resolves under full verification.
    const resolved = await resolveDIDFromLog(created.log, {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.meta.error).toBeUndefined()
    expect(resolved.did).toBe(created.did)

    // Genesis parameters: the minting credential's rung 0 as the sole update
    // key, every standing credential's rung-0 hash committed, portability
    // off, no witnesses.
    const genesis = created.log[0]!
    expect(genesis.parameters.updateKeys).toEqual([minting.keyMultibase])
    expect(genesis.parameters.nextKeyHashes).toEqual(nextKeyHashes)
    expect(genesis.parameters.portable).toBe(false)
    expect(genesis.parameters.witness ?? {}).toEqual({})

    // The document is bare: the DID core context only, no verification
    // methods, no relations, no services.
    const doc = resolved.doc as Record<string, unknown>
    expect(doc['@context']).toEqual(['https://www.w3.org/ns/did/v1'])
    for (const member of [
      'verificationMethod',
      'authentication',
      'assertionMethod',
      'keyAgreement',
      'capabilityInvocation',
      'capabilityDelegation',
      'service'
    ]) {
      expect(doc[member] ?? undefined).toBeUndefined()
    }
  })

  it("refuses a nextKeyHashes missing the minting key's carry-over hash", async () => {
    const { minting, other } = await mintedGenesisAuthority()
    await expect(
      createClientAnnexLog({
        wasServerUrl: WAS_URL,
        spaceId: AUX_SPACE_ID,
        generationId: mintGenerationId(),
        updateKeyPublicKeyMultibase: minting.keyMultibase,
        nextKeyHashes: [await deriveNextKeyHash(other.keyMultibase)],
        signer: minting.signer
      })
    ).rejects.toThrow(/carry-over/)
  })

  it('refuses a malformed generation id before creating anything', async () => {
    const { minting, nextKeyHashes } = await mintedGenesisAuthority()
    await expect(
      createClientAnnexLog({
        wasServerUrl: WAS_URL,
        spaceId: AUX_SPACE_ID,
        generationId: 'id',
        updateKeyPublicKeyMultibase: minting.keyMultibase,
        nextKeyHashes,
        signer: minting.signer
      })
    ).rejects.toThrow(/generation id/)
  })
})

describe('the parameterized WAS log store', () => {
  it('writes an annex collection without disturbing the account-log paths', async () => {
    const server = fakeServer()
    const generationId = mintGenerationId()
    const accountStore = wasWebvhIdStore({
      was: server.was,
      spaceId: ACCOUNT_SPACE_ID
    })
    const clientAnnexStore = clientAnnexLogStore({
      was: server.was,
      spaceId: AUX_SPACE_ID,
      generationId
    })

    await accountStore.putIdResource({
      resourceId: 'did.jsonl',
      content: 'account-log-line',
      contentType: 'text/jsonl'
    })
    await clientAnnexStore.putIdResource({
      resourceId: 'did.jsonl',
      content: 'clientAnnex-log-line',
      contentType: 'text/jsonl'
    })

    // Each store addressed exactly its own collection.
    const putUrls = server.calls
      .filter(call => call.method === 'PUT')
      .map(call => new URL(call.url).pathname)
    expect(putUrls).toEqual([
      `/space/${ACCOUNT_SPACE_ID}/id/did.jsonl`,
      `/space/${AUX_SPACE_ID}/${generationId}/did.jsonl`
    ])

    // Reads round-trip the right body and carry the ETag.
    const accountRead = await accountStore.getIdResourceRaw({
      resourceId: 'did.jsonl'
    })
    expect(accountRead?.text).toBe('account-log-line')
    expect(accountRead?.etag).toBe('"1"')
    const clientAnnexRead = await clientAnnexStore.getIdResourceRaw({
      resourceId: 'did.jsonl'
    })
    expect(clientAnnexRead?.text).toBe('clientAnnex-log-line')
  })

  it('refuses a malformed generation id at store construction', () => {
    const server = fakeServer()
    expect(() =>
      clientAnnexLogStore({
        was: server.was,
        spaceId: AUX_SPACE_ID,
        generationId: 'id'
      })
    ).toThrow(/generation id/)
  })
})

describe('delegatedWebvhLogStore', () => {
  it('reads through the delegation: absent is undefined, present carries the ETag', async () => {
    const server = fakeServer()
    const generationId = mintGenerationId()
    const store = delegatedWebvhLogStore({
      host: WAS_URL,
      spaceId: AUX_SPACE_ID,
      collectionId: generationId,
      delegation: DELEGATION,
      zcapClient: server.zcapClient
    })

    expect(await store.getIdResourceRaw({ resourceId: 'did.jsonl' })).toBe(
      undefined
    )

    server.resources.set(`/space/${AUX_SPACE_ID}/${generationId}/did.jsonl`, {
      text: 'line',
      version: 3,
      contentType: 'text/jsonl'
    })
    const read = await store.getIdResourceRaw({ resourceId: 'did.jsonl' })
    expect(read).toEqual({ text: 'line', etag: '"3"' })
    // Both reads invoked the delegation rather than fetching bare.
    expect(
      server.calls
        .filter(call => call.method === 'GET')
        .every(call => call.hasCapability)
    ).toBe(true)
  })

  it('maps a failed precondition on the delegated PUT to the seam contract', async () => {
    const server = fakeServer()
    const generationId = mintGenerationId()
    const path = `/space/${AUX_SPACE_ID}/${generationId}/did.jsonl`
    server.resources.set(path, {
      text: 'winner',
      version: 2,
      contentType: 'text/jsonl'
    })
    const store = delegatedWebvhLogStore({
      host: WAS_URL,
      spaceId: AUX_SPACE_ID,
      collectionId: generationId,
      delegation: DELEGATION,
      zcapClient: server.zcapClient
    })

    // A stale If-Match surfaces under the PreconditionFailedError name...
    await expect(
      store.putIdResource({
        resourceId: 'did.jsonl',
        content: 'loser',
        contentType: 'text/jsonl',
        ifMatch: '"1"'
      })
    ).rejects.toMatchObject({ name: 'PreconditionFailedError' })

    // ...so the shared publish maps the lost race to the conflict error.
    await expect(
      putLogResource({
        store,
        log: readLogFromString(
          '{"versionId":"1-x","versionTime":"2026-01-01T00:00:00Z",' +
            '"parameters":{},"state":{"id":"did:webvh:x:example"}}\n'
        ),
        ifMatch: '"1"'
      })
    ).rejects.toBeInstanceOf(WebvhLogConflictError)

    // The winner's entry was never overwritten.
    expect(server.resources.get(path)?.text).toBe('winner')
  })

  it('re-runs on the new head under withLogConflictRetry', async () => {
    const server = fakeServer()
    const generationId = mintGenerationId()
    const path = `/space/${AUX_SPACE_ID}/${generationId}/did.jsonl`
    server.resources.set(path, {
      text: 'head-1',
      version: 1,
      contentType: 'text/jsonl'
    })
    const store = delegatedWebvhLogStore({
      host: WAS_URL,
      spaceId: AUX_SPACE_ID,
      collectionId: generationId,
      delegation: DELEGATION,
      zcapClient: server.zcapClient
    })

    // A concurrent winner advances the log between this ceremony's first
    // read and its publish; the re-run reads the new head and lands on it.
    let raced = false
    const appended = await withLogConflictRetry(async () => {
      const read = await store.getIdResourceRaw({ resourceId: 'did.jsonl' })
      if (!raced) {
        raced = true
        server.resources.set(path, {
          text: 'head-2',
          version: 2,
          contentType: 'text/jsonl'
        })
      }
      const rebased = `${read!.text}+appended`
      try {
        await store.putIdResource({
          resourceId: 'did.jsonl',
          content: rebased,
          contentType: 'text/jsonl',
          ifMatch: read!.etag
        })
      } catch (err) {
        if ((err as Error).name === 'PreconditionFailedError') {
          throw new WebvhLogConflictError(undefined, { cause: err })
        }
        throw err
      }
      return rebased
    })
    expect(appended).toBe('head-2+appended')
    expect(server.resources.get(path)?.text).toBe('head-2+appended')
  })

  it('reads the world-readable log with an unauthenticated fetch', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('public-line', {
        status: 200,
        headers: { etag: '"7"' }
      })
    )
    const store = delegatedWebvhLogStore({
      host: WAS_URL,
      spaceId: ACCOUNT_SPACE_ID,
      collectionId: 'id',
      delegation: DELEGATION,
      zcapClient: fakeServer().zcapClient,
      publicRead: true
    })
    const read = await store.getIdResourceRaw({ resourceId: 'did.jsonl' })
    expect(read).toEqual({ text: 'public-line', etag: '"7"' })
    expect(fetchSpy).toHaveBeenCalledWith(
      `${WAS_URL}/space/${ACCOUNT_SPACE_ID}/id/did.jsonl`
    )
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })
})

describe('ensureClientAnnexSpace', () => {
  it('creates the auxiliary Space with the typed Description', async () => {
    const server = fakeServer()
    await ensureClientAnnexSpace({
      was: server.was,
      spaceId: AUX_SPACE_ID,
      controller: 'did:example:account'
    })
    expect(server.descriptions.get(`/space/${AUX_SPACE_ID}`)).toMatchObject({
      controller: 'did:example:account',
      type: CLIENT_ANNEX_SPACE_TYPE
    })
  })

  it('no-ops on an existing typed Space', async () => {
    const server = fakeServer()
    server.descriptions.set(`/space/${AUX_SPACE_ID}`, {
      id: AUX_SPACE_ID,
      type: CLIENT_ANNEX_SPACE_TYPE,
      controller: 'did:example:account'
    })
    await ensureClientAnnexSpace({
      was: server.was,
      spaceId: AUX_SPACE_ID,
      controller: 'did:example:account'
    })
    expect(server.calls.filter(call => call.method === 'PUT')).toHaveLength(0)
  })

  it('refuses an existing Space that is not the delegated-clients Space', async () => {
    const server = fakeServer()
    server.descriptions.set(`/space/${AUX_SPACE_ID}`, {
      id: AUX_SPACE_ID,
      type: ['Space'],
      controller: 'did:example:account'
    })
    await expect(
      ensureClientAnnexSpace({
        was: server.was,
        spaceId: AUX_SPACE_ID,
        controller: 'did:example:account'
      })
    ).rejects.toThrow(/not typed/)
  })
})

describe('mintClientAnnexGeneration', () => {
  it('publishes the annex log first and touches no account path', async () => {
    const server = fakeServer()
    const { minting, nextKeyHashes } = await mintedGenesisAuthority()
    const minted = await mintClientAnnexGeneration({
      was: server.was,
      wasServerUrl: WAS_URL,
      spaceId: AUX_SPACE_ID,
      controller: 'did:example:account',
      updateKeyPublicKeyMultibase: minting.keyMultibase,
      nextKeyHashes,
      signer: minting.signer
    })

    expect(minted.did).toContain(
      `:space:${AUX_SPACE_ID}:${minted.generationId}`
    )
    expect(() => assertGenerationId(minted.generationId)).not.toThrow()

    // The published log resolves to the returned DID.
    const stored = server.resources.get(
      `/space/${AUX_SPACE_ID}/${minted.generationId}/did.jsonl`
    )
    const resolved = await resolveDIDFromLog(readLogFromString(stored!.text), {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.did).toBe(minted.did)
    expect(stored!.contentType).toBe('text/jsonl')

    // The genesis publish was a create-if-absent.
    const logPut = server.calls.find(
      call => call.method === 'PUT' && call.url.endsWith('/did.jsonl')
    )
    expect(logPut?.headers['if-none-match']).toBe('*')

    // Pointer second: nothing here wrote outside the auxiliary Space -- the
    // account document's `#DelegatedClients` re-point is the caller's next
    // step, after the log is durable.
    const outside = server.calls.filter(
      call => !new URL(call.url).pathname.startsWith(`/space/${AUX_SPACE_ID}`)
    )
    expect(outside).toHaveLength(0)
  })
})

describe('mintCredentialClientAnnexGeneration', () => {
  it('mints a generation the same ladder seed can extend', async () => {
    const server = fakeServer()
    const ladderSeed = crypto.getRandomValues(new Uint8Array(32))
    const other = await mintedRungZero()
    const minted = await mintCredentialClientAnnexGeneration({
      was: server.was,
      wasServerUrl: WAS_URL,
      spaceId: AUX_SPACE_ID,
      controller: 'did:example:account',
      ladderSeed,
      extraNextKeyHashes: [await deriveNextKeyHash(other.keyMultibase)]
    })

    // Genesis update authority is the generation-id-bound annex rung 0 --
    // derivable only after the generation id exists, which is what this minter
    // is for -- with the carry-over commitment beside the extra credential's.
    const rung = await clientAnnexRung({
      ladderSeed,
      generationId: minted.generationId
    })
    const genesis = minted.log[0]!
    expect(genesis.parameters.updateKeys).toEqual([rung.keyMultibase])
    expect(genesis.parameters.nextKeyHashes).toEqual([
      await deriveNextKeyHash(rung.keyMultibase),
      await deriveNextKeyHash(other.keyMultibase)
    ])

    // The published log resolves to the returned DID.
    const stored = server.resources.get(
      `/space/${AUX_SPACE_ID}/${minted.generationId}/did.jsonl`
    )
    const resolved = await resolveDIDFromLog(readLogFromString(stored!.text), {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.did).toBe(minted.did)

    // The circularity is closed: the minting ladder seed extends the log.
    const transient = await mintedRungZero()
    const enrolled = await enrollClientAnnexTransientClient({
      store: clientAnnexLogStore({
        was: server.was,
        spaceId: AUX_SPACE_ID,
        generationId: minted.generationId
      }),
      ladderSeed,
      generationId: minted.generationId,
      transientKeyMultibase: transient.keyMultibase,
      expectedDid: minted.did
    })
    expect(enrolled.did).toBe(minted.did)
  })
})

describe('client annex pin continuity (the transient session)', () => {
  it('pins in memory and refuses a rolled-back annex log', async () => {
    const { minting, nextKeyHashes } = await mintedGenesisAuthority()
    const generationId = mintGenerationId()
    const created = await createClientAnnexLog({
      wasServerUrl: WAS_URL,
      spaceId: AUX_SPACE_ID,
      generationId,
      updateKeyPublicKeyMultibase: minting.keyMultibase,
      nextKeyHashes,
      signer: minting.signer
    })

    // A minimal served-log store whose contents the "host" can swap.
    let served: string | undefined = created.log
      .map(entry => JSON.stringify(entry))
      .join('\n')
    const store = {
      async getIdResourceRaw() {
        return served === undefined ? undefined : { text: served }
      }
    } as unknown as WebvhIdStore

    const pinStore = memoryResourceLogPinStore()
    const logId = clientAnnexLogPinId({ spaceId: AUX_SPACE_ID, generationId })

    const published = await readPublishedLog({
      idStore: store,
      expectedDid: created.did,
      pinStore,
      logId
    })
    expect(published?.did).toBe(created.did)
    expect(await pinStore.read({ logId })).not.toBeNull()

    // The host truncating the log to nothing is a rollback against the held
    // pin, not a fresh "not yet published".
    served = undefined
    await expect(
      readPublishedLog({ idStore: store, pinStore, logId })
    ).rejects.toBeInstanceOf(ResourceLogContinuityError)
  })
})

describe('delegatedClientsSpaceHistory', () => {
  const ACCOUNT_DID = 'did:webvh:QmScid:storage.example:space:account-space-1'
  const annexDid = ({
    spaceId,
    generationId,
    host = 'storage.example'
  }: {
    spaceId: string
    generationId: string
    host?: string
  }) => `did:webvh:QmAnnexScid:${host}:space:${spaceId}:${generationId}`

  /**
   * A synthetic account log: one entry per supplied pointer value, with
   * `undefined` standing for an entry that carries no pointer at all.
   */
  const logWithPointers = (pointers: Array<string | undefined>): DIDLog =>
    pointers.map(pointed => ({
      state: {
        id: ACCOUNT_DID,
        ...(pointed === undefined
          ? {}
          : {
              service: [
                {
                  id: `${ACCOUNT_DID}#delegated-clients`,
                  type: 'https://w3id.org/byoe#DelegatedClients',
                  serviceEndpoint: pointed
                }
              ]
            })
      }
    })) as unknown as DIDLog

  it('is empty for a log that never carried a pointer', () => {
    expect(
      delegatedClientsSpaceHistory({
        log: logWithPointers([undefined, undefined])
      })
    ).toEqual([])
  })

  it('reads the one Space a single pointer names, with its host', () => {
    const did = annexDid({
      spaceId: 'aux-1',
      generationId: 'gen-AAAAAAAAAAAAAAAA'
    })
    const log = logWithPointers([undefined, did])
    expect(delegatedClientsSpaceHistory({ log })).toEqual([
      { did, host: 'storage.example', spaceId: 'aux-1' }
    ])
  })

  it('names every superseded Space, oldest first', () => {
    const log = logWithPointers([
      undefined,
      annexDid({ spaceId: 'aux-1', generationId: 'gen-AAAAAAAAAAAAAAAA' }),
      annexDid({ spaceId: 'aux-2', generationId: 'gen-BBBBBBBBBBBBBBBB' }),
      annexDid({ spaceId: 'aux-3', generationId: 'gen-CCCCCCCCCCCCCCCC' })
    ])
    expect(
      delegatedClientsSpaceHistory({ log }).map(space => space.spaceId)
    ).toEqual(['aux-1', 'aux-2', 'aux-3'])
  })

  it('de-duplicates a Space named by several generations', () => {
    // The ordinary GC swap: a fresh generation inside the SAME Space, and a
    // later re-point back to a Space the account already used.
    const log = logWithPointers([
      annexDid({ spaceId: 'aux-1', generationId: 'gen-AAAAAAAAAAAAAAAA' }),
      annexDid({ spaceId: 'aux-1', generationId: 'gen-BBBBBBBBBBBBBBBB' }),
      annexDid({ spaceId: 'aux-2', generationId: 'gen-CCCCCCCCCCCCCCCC' }),
      annexDid({ spaceId: 'aux-1', generationId: 'gen-DDDDDDDDDDDDDDDD' })
    ])
    const history = delegatedClientsSpaceHistory({ log })
    expect(history.map(space => space.spaceId)).toEqual(['aux-1', 'aux-2'])
    // The entry that named the Space FIRST is the one kept.
    expect(history[0]!.did).toBe(
      annexDid({ spaceId: 'aux-1', generationId: 'gen-AAAAAAAAAAAAAAAA' })
    )
  })

  it('carries a foreign host through, percent-decoded', () => {
    // A migrated account: the caller compares the host and reports an entry
    // this deployment cannot address rather than deleting the id here.
    const log = logWithPointers([
      annexDid({
        spaceId: 'aux-1',
        generationId: 'gen-AAAAAAAAAAAAAAAA',
        host: 'old.example%3A8443'
      })
    ])
    expect(delegatedClientsSpaceHistory({ log })[0]!.host).toBe(
      'old.example:8443'
    )
  })

  it('skips an endpoint that is not a client annex DID', () => {
    const log = logWithPointers([
      'did:key:z6MkjKKJT4WoDXHnvQtvGmYRWQVDXNvKPXbCLxZDCumHFHTn',
      annexDid({ spaceId: 'aux-1', generationId: 'gen-AAAAAAAAAAAAAAAA' })
    ])
    expect(
      delegatedClientsSpaceHistory({ log }).map(space => space.spaceId)
    ).toEqual(['aux-1'])
  })

  it('skips an entry carrying no document state', () => {
    const log = [
      { versionId: '1-abc' },
      ...logWithPointers([
        annexDid({ spaceId: 'aux-1', generationId: 'gen-AAAAAAAAAAAAAAAA' })
      ])
    ] as unknown as DIDLog
    expect(
      delegatedClientsSpaceHistory({ log }).map(space => space.spaceId)
    ).toEqual(['aux-1'])
  })
})
