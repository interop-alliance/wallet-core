/**
 * Unit tests for the companion did:webvh machinery: generation identity
 * (`gen-<random>` segments), the companion genesis (static rung-0 update
 * authority, prerotation via rung-0 hash commitments, no witnesses,
 * portability off, a bare zero-VM document), the parameterized WAS log store
 * (a companion collection served without disturbing the account-log paths),
 * the delegated store's CAS/ETag discipline, and the in-memory chain-head pin
 * a transient session keeps for companion continuity.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  defaultWebvhLogVerifier,
  deriveNextKeyHash,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { WasClient } from '@interop/was-client'
import { ResourceLogContinuityError } from '../../src/resourceLog/errors.js'
import { memoryResourceLogPinStore } from '../../src/resourceLog/pin.js'
import {
  assertGenerationSegment,
  COMPANION_SPACE_TYPE,
  companionLogPinId,
  companionLogStore,
  createCompanionLog,
  ensureCompanionSpace,
  enrollCompanionTransientClient,
  GENERATION_SEGMENT_PREFIX,
  mintCompanionGeneration,
  mintCredentialCompanionGeneration,
  mintGenerationSegment
} from '../../src/webvh/companion.js'
import { companionRung } from '../../src/unlock/ladder.js'
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
const AUX_SPACE_ID = 'aux-space-companion'
const ACCOUNT_SPACE_ID = 'acct-space'

/**
 * A fresh Ed25519 update-key seed with its public multibase and signer -- the
 * shape of one standing credential's companion rung 0.
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
 * A companion genesis's update-authority inputs: the minting credential's
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

describe('generation segments', () => {
  it('mints "gen-" plus 16 base64url characters, 20 characters total', () => {
    const segment = mintGenerationSegment()
    expect(segment.startsWith(GENERATION_SEGMENT_PREFIX)).toBe(true)
    expect(segment).toHaveLength(20)
    expect(() => assertGenerationSegment(segment)).not.toThrow()
    // Inside the server's id allowlist: encodeURIComponent is the identity.
    expect(encodeURIComponent(segment)).toBe(segment)
  })

  it('mints distinct segments', () => {
    const minted = new Set(
      Array.from({ length: 32 }, () => mintGenerationSegment())
    )
    expect(minted.size).toBe(32)
  })

  it('refuses malformed segments', () => {
    for (const bad of [
      'gen-short',
      'gen-' + 'a'.repeat(17),
      'id',
      'gen-Ux3v0kQf9aPmB2h!',
      'GEN-Ux3v0kQf9aPmB2hZ'
    ]) {
      expect(() => assertGenerationSegment(bad)).toThrow(/generation segment/)
    }
  })
})

describe('createCompanionLog', () => {
  it('publishes the companion genesis posture', async () => {
    const { minting, nextKeyHashes } = await mintedGenesisAuthority()
    const segment = mintGenerationSegment()
    const created = await createCompanionLog({
      wasServerUrl: WAS_URL,
      spaceId: AUX_SPACE_ID,
      segment,
      updateKeyPublicKeyMultibase: minting.keyMultibase,
      nextKeyHashes,
      signer: minting.signer
    })

    // The DID embeds the auxiliary Space id and the generation segment.
    expect(created.did).toContain(`:space:${AUX_SPACE_ID}:${segment}`)

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
      createCompanionLog({
        wasServerUrl: WAS_URL,
        spaceId: AUX_SPACE_ID,
        segment: mintGenerationSegment(),
        updateKeyPublicKeyMultibase: minting.keyMultibase,
        nextKeyHashes: [await deriveNextKeyHash(other.keyMultibase)],
        signer: minting.signer
      })
    ).rejects.toThrow(/carry-over/)
  })

  it('refuses a malformed segment before creating anything', async () => {
    const { minting, nextKeyHashes } = await mintedGenesisAuthority()
    await expect(
      createCompanionLog({
        wasServerUrl: WAS_URL,
        spaceId: AUX_SPACE_ID,
        segment: 'id',
        updateKeyPublicKeyMultibase: minting.keyMultibase,
        nextKeyHashes,
        signer: minting.signer
      })
    ).rejects.toThrow(/generation segment/)
  })
})

describe('the parameterized WAS log store', () => {
  it('writes a companion collection without disturbing the account-log paths', async () => {
    const server = fakeServer()
    const segment = mintGenerationSegment()
    const accountStore = wasWebvhIdStore({
      was: server.was,
      spaceId: ACCOUNT_SPACE_ID
    })
    const companionStore = companionLogStore({
      was: server.was,
      spaceId: AUX_SPACE_ID,
      segment
    })

    await accountStore.putIdResource({
      resourceId: 'did.jsonl',
      content: 'account-log-line',
      contentType: 'text/jsonl'
    })
    await companionStore.putIdResource({
      resourceId: 'did.jsonl',
      content: 'companion-log-line',
      contentType: 'text/jsonl'
    })

    // Each store addressed exactly its own collection.
    const putUrls = server.calls
      .filter(call => call.method === 'PUT')
      .map(call => new URL(call.url).pathname)
    expect(putUrls).toEqual([
      `/space/${ACCOUNT_SPACE_ID}/id/did.jsonl`,
      `/space/${AUX_SPACE_ID}/${segment}/did.jsonl`
    ])

    // Reads round-trip the right body and carry the ETag.
    const accountRead = await accountStore.getIdResourceRaw({
      resourceId: 'did.jsonl'
    })
    expect(accountRead?.text).toBe('account-log-line')
    expect(accountRead?.etag).toBe('"1"')
    const companionRead = await companionStore.getIdResourceRaw({
      resourceId: 'did.jsonl'
    })
    expect(companionRead?.text).toBe('companion-log-line')
  })

  it('refuses a malformed segment at store construction', () => {
    const server = fakeServer()
    expect(() =>
      companionLogStore({
        was: server.was,
        spaceId: AUX_SPACE_ID,
        segment: 'id'
      })
    ).toThrow(/generation segment/)
  })
})

describe('delegatedWebvhLogStore', () => {
  it('reads through the delegation: absent is undefined, present carries the ETag', async () => {
    const server = fakeServer()
    const segment = mintGenerationSegment()
    const store = delegatedWebvhLogStore({
      host: WAS_URL,
      spaceId: AUX_SPACE_ID,
      collectionId: segment,
      delegation: DELEGATION,
      zcapClient: server.zcapClient
    })

    expect(await store.getIdResourceRaw({ resourceId: 'did.jsonl' })).toBe(
      undefined
    )

    server.resources.set(`/space/${AUX_SPACE_ID}/${segment}/did.jsonl`, {
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
    const segment = mintGenerationSegment()
    const path = `/space/${AUX_SPACE_ID}/${segment}/did.jsonl`
    server.resources.set(path, {
      text: 'winner',
      version: 2,
      contentType: 'text/jsonl'
    })
    const store = delegatedWebvhLogStore({
      host: WAS_URL,
      spaceId: AUX_SPACE_ID,
      collectionId: segment,
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
    const segment = mintGenerationSegment()
    const path = `/space/${AUX_SPACE_ID}/${segment}/did.jsonl`
    server.resources.set(path, {
      text: 'head-1',
      version: 1,
      contentType: 'text/jsonl'
    })
    const store = delegatedWebvhLogStore({
      host: WAS_URL,
      spaceId: AUX_SPACE_ID,
      collectionId: segment,
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

  it('reads the world-readable posture with an unauthenticated fetch', async () => {
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

describe('ensureCompanionSpace', () => {
  it('creates the auxiliary Space with the typed Description', async () => {
    const server = fakeServer()
    await ensureCompanionSpace({
      was: server.was,
      spaceId: AUX_SPACE_ID,
      controller: 'did:example:account'
    })
    expect(server.descriptions.get(`/space/${AUX_SPACE_ID}`)).toMatchObject({
      controller: 'did:example:account',
      type: COMPANION_SPACE_TYPE
    })
  })

  it('no-ops on an existing typed Space', async () => {
    const server = fakeServer()
    server.descriptions.set(`/space/${AUX_SPACE_ID}`, {
      id: AUX_SPACE_ID,
      type: COMPANION_SPACE_TYPE,
      controller: 'did:example:account'
    })
    await ensureCompanionSpace({
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
      ensureCompanionSpace({
        was: server.was,
        spaceId: AUX_SPACE_ID,
        controller: 'did:example:account'
      })
    ).rejects.toThrow(/not typed/)
  })
})

describe('mintCompanionGeneration', () => {
  it('publishes the companion log first and touches no account path', async () => {
    const server = fakeServer()
    const { minting, nextKeyHashes } = await mintedGenesisAuthority()
    const minted = await mintCompanionGeneration({
      was: server.was,
      wasServerUrl: WAS_URL,
      spaceId: AUX_SPACE_ID,
      controller: 'did:example:account',
      updateKeyPublicKeyMultibase: minting.keyMultibase,
      nextKeyHashes,
      signer: minting.signer
    })

    expect(minted.did).toContain(`:space:${AUX_SPACE_ID}:${minted.segment}`)
    expect(() => assertGenerationSegment(minted.segment)).not.toThrow()

    // The published log resolves to the returned DID.
    const stored = server.resources.get(
      `/space/${AUX_SPACE_ID}/${minted.segment}/did.jsonl`
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

describe('mintCredentialCompanionGeneration', () => {
  it('mints a generation the same ladder seed can extend', async () => {
    const server = fakeServer()
    const ladderSeed = crypto.getRandomValues(new Uint8Array(32))
    const other = await mintedRungZero()
    const minted = await mintCredentialCompanionGeneration({
      was: server.was,
      wasServerUrl: WAS_URL,
      spaceId: AUX_SPACE_ID,
      controller: 'did:example:account',
      ladderSeed,
      extraNextKeyHashes: [await deriveNextKeyHash(other.keyMultibase)]
    })

    // Genesis update authority is the segment-bound companion rung 0 --
    // derivable only after the segment exists, which is what this minter is
    // for -- with the carry-over commitment beside the extra credential's.
    const rung = await companionRung({ ladderSeed, segment: minted.segment })
    const genesis = minted.log[0]!
    expect(genesis.parameters.updateKeys).toEqual([rung.keyMultibase])
    expect(genesis.parameters.nextKeyHashes).toEqual([
      await deriveNextKeyHash(rung.keyMultibase),
      await deriveNextKeyHash(other.keyMultibase)
    ])

    // The published log resolves to the returned DID.
    const stored = server.resources.get(
      `/space/${AUX_SPACE_ID}/${minted.segment}/did.jsonl`
    )
    const resolved = await resolveDIDFromLog(readLogFromString(stored!.text), {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.did).toBe(minted.did)

    // The circularity is closed: the minting ladder seed extends the log.
    const transient = await mintedRungZero()
    const enrolled = await enrollCompanionTransientClient({
      store: companionLogStore({
        was: server.was,
        spaceId: AUX_SPACE_ID,
        segment: minted.segment
      }),
      ladderSeed,
      segment: minted.segment,
      transientKeyMultibase: transient.keyMultibase,
      expectedDid: minted.did
    })
    expect(enrolled.did).toBe(minted.did)
  })
})

describe('companion pin continuity (the transient session posture)', () => {
  it('pins in memory and refuses a rolled-back companion log', async () => {
    const { minting, nextKeyHashes } = await mintedGenesisAuthority()
    const segment = mintGenerationSegment()
    const created = await createCompanionLog({
      wasServerUrl: WAS_URL,
      spaceId: AUX_SPACE_ID,
      segment,
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
    const logId = companionLogPinId({ spaceId: AUX_SPACE_ID, segment })

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
