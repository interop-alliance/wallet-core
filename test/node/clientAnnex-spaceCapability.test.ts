/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Single-verb Space capabilities and the capability-authorized Space DELETE:
 * the three-link child's verbatim target copy and the guarantee that a child
 * never outlives its parent, the two-link child's bare Space URL on a
 * sub-path deployment, the ladder VM's signature under its document
 * verification-method id, the refusals to mint from an expired parent or one
 * that does not allow the verb, and the delete helper's 404-as-outcome
 * report.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'
import { rootCapabilityId, spacePath, toUrl } from '@interop/was-client/paths'
import { agentsFromSeed } from '../../src/identity/agents.js'
import {
  DELETION_ZCAP_TTL_MS,
  ExpiredParentCapabilityError,
  mintSpaceRootVerbCapability,
  mintSpaceVerbCapability
} from '../../src/clientAnnex/spaceCapability.js'
import { ladderVmKeyMultibase } from '../../src/clientAnnex/ladder.js'
import { ladderVmZcapClient } from '../../src/clientAnnex/zcap.js'
import { deleteSpaceWithCapability } from '../../src/space/deleteSpace.js'
import { deleteUnlockSpaceWithCapability } from '../../src/keyring/unlockSpace.js'

/** A sub-path deployment, so the path-join discipline is pinned. */
const WAS_URL = 'https://storage.example/was'
const ACCOUNT_DID = 'did:webvh:QmScidAccount:storage.example'
const UNLOCK_SPACE_ID = 'unlock-space-1'
const ACCOUNT_SPACE_ID = 'account-space-1'

const MINUTE_MS = 60 * 1000

/**
 * A deterministic 32-byte ladder seed.
 */
function fixedSeed(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill)
}

/**
 * The stored three-verb management zcap an unlock identity delegates to the
 * account at bind time -- the three-link mint's parent. Its target is written
 * as the deployment stored it, which the child must copy rather than rebuild.
 *
 * @param options {object}
 * @param options.expires {Date}
 * @param [options.now] {number}   the delegation's own clock, so a parent
 *   already expired can be built at all
 * @returns {Promise<IZcap>}
 */
async function manageCapability({
  expires,
  now
}: {
  expires: Date
  now?: number
}): Promise<IZcap> {
  const unlock = await agentsFromSeed({ seed: fixedSeed(7) })
  return (await unlock.zcapClient.delegate({
    invocationTarget: `${WAS_URL}/space/${UNLOCK_SPACE_ID}`,
    controller: ACCOUNT_DID,
    allowedActions: ['GET', 'PUT', 'DELETE'],
    expires,
    ...(now !== undefined ? { now } : {})
  })) as IZcap
}

/**
 * The ladder VM's delegating client, signing under its account-document
 * verification-method id.
 */
async function ladderClient(ladderSeed: Uint8Array) {
  return ladderVmZcapClient({ accountDid: ACCOUNT_DID, ladderSeed })
}

/** ezcap stores second precision. */
function toSeconds(ms: number): number {
  return Math.floor(ms / 1000) * 1000
}

describe('mintSpaceVerbCapability (three links, a stored parent)', () => {
  it('copies the parent target verbatim and carries one verb', async () => {
    const now = Date.now()
    const parent = await manageCapability({
      expires: new Date(now + 300 * 24 * 60 * MINUTE_MS)
    })
    const ladderSeed = fixedSeed(11)
    const child = (await mintSpaceVerbCapability({
      zcapClient: await ladderClient(ladderSeed),
      parent,
      verb: 'DELETE',
      controller: `did:key:z${'x'.repeat(10)}`,
      now
    })) as IZcap & {
      expires: string
      allowedAction: string[]
      parentCapability: string
      proof: { verificationMethod: string }
    }

    expect(child.invocationTarget).toBe(
      (parent as { invocationTarget: string }).invocationTarget
    )
    expect(child.invocationTarget).toBe(`${WAS_URL}/space/${UNLOCK_SPACE_ID}`)
    expect(child.allowedAction).toEqual(['DELETE'])
    expect(child.controller).toBe(`did:key:z${'x'.repeat(10)}`)
    expect(child.parentCapability).toBe((parent as { id: string }).id)
    expect(Date.parse(child.expires)).toBe(
      toSeconds(now + DELETION_ZCAP_TTL_MS)
    )
    expect(child.proof.verificationMethod).toBe(
      `${ACCOUNT_DID}#${await ladderVmKeyMultibase({ ladderSeed })}`
    )
  })

  it('never outlives a parent expiring inside the TTL', async () => {
    const now = Date.now()
    const parent = await manageCapability({
      expires: new Date(now + 3 * MINUTE_MS)
    })
    const child = (await mintSpaceVerbCapability({
      zcapClient: await ladderClient(fixedSeed(11)),
      parent,
      verb: 'DELETE',
      controller: ACCOUNT_DID,
      now
    })) as IZcap & { expires: string }

    expect(Date.parse(child.expires)).toBe(
      Date.parse((parent as { expires: string }).expires)
    )
    expect(Date.parse(child.expires)).toBeLessThan(now + DELETION_ZCAP_TTL_MS)
  })

  it('mints the GET-only probe child under the same shape', async () => {
    const now = Date.now()
    const parent = await manageCapability({
      expires: new Date(now + 300 * 24 * 60 * MINUTE_MS)
    })
    const child = (await mintSpaceVerbCapability({
      zcapClient: await ladderClient(fixedSeed(11)),
      parent,
      verb: 'GET',
      controller: ACCOUNT_DID,
      now
    })) as IZcap & { allowedAction: string[] }

    expect(child.allowedAction).toEqual(['GET'])
    expect(child.invocationTarget).toBe(
      (parent as { invocationTarget: string }).invocationTarget
    )
  })

  it('refuses a parent whose action set omits the verb', async () => {
    const now = Date.now()
    const unlock = await agentsFromSeed({ seed: fixedSeed(7) })
    // A read-only parent: the server would mask the refused DELETE as a 404,
    // so the mint refuses locally instead.
    const parent = (await unlock.zcapClient.delegate({
      invocationTarget: `${WAS_URL}/space/${UNLOCK_SPACE_ID}`,
      controller: ACCOUNT_DID,
      allowedActions: ['GET'],
      expires: new Date(now + 300 * 24 * 60 * MINUTE_MS)
    })) as IZcap
    await expect(
      mintSpaceVerbCapability({
        zcapClient: await ladderClient(fixedSeed(11)),
        parent,
        verb: 'DELETE',
        controller: ACCOUNT_DID,
        now
      })
    ).rejects.toThrow(/allows GET and not DELETE/)
  })

  it('refuses an already-expired parent before minting', async () => {
    const now = Date.now()
    const parent = await manageCapability({
      expires: new Date(now - MINUTE_MS),
      now: now - 5 * MINUTE_MS
    })
    // Classified by NAME rather than by `instanceof`: a second copy of this
    // package would throw a different class.
    const err = (await mintSpaceVerbCapability({
      zcapClient: await ladderClient(fixedSeed(11)),
      parent,
      verb: 'DELETE',
      controller: ACCOUNT_DID,
      now
    }).catch((thrown: unknown) => thrown)) as ExpiredParentCapabilityError

    expect(err.name).toBe('ExpiredParentCapabilityError')
    expect(err.message).toMatch(/expired/)
    expect(err.parentExpires).toBe(
      new Date(
        Date.parse((parent as { expires: string }).expires)
      ).toISOString()
    )
    expect(err.parentId).toBe((parent as { id: string }).id)
  })
})

describe('mintSpaceRootVerbCapability (two links, a Space root)', () => {
  it('targets the bare Space URL on a sub-path deployment', async () => {
    const now = Date.now()
    const ladderSeed = fixedSeed(11)
    const ladderKey = `did:key:z${'y'.repeat(10)}`
    const child = (await mintSpaceRootVerbCapability({
      zcapClient: await ladderClient(ladderSeed),
      storageServerUrl: WAS_URL,
      spaceId: ACCOUNT_SPACE_ID,
      verb: 'DELETE',
      controller: ladderKey,
      now
    })) as IZcap & {
      expires: string
      allowedAction: string[]
      parentCapability: string
      proof: { verificationMethod: string; capabilityChain: unknown[] }
    }

    const spaceUrl = toUrl({
      serverUrl: WAS_URL,
      path: spacePath(ACCOUNT_SPACE_ID)
    })
    expect(spaceUrl).toBe(`${WAS_URL}/space/${ACCOUNT_SPACE_ID}`)
    expect(child.invocationTarget).toBe(spaceUrl)
    expect(child.invocationTarget.endsWith('/')).toBe(false)
    expect(child.allowedAction).toEqual(['DELETE'])
    expect(child.controller).toBe(ladderKey)
    expect(child.parentCapability).toBe(rootCapabilityId(spaceUrl))
    expect(child.proof.capabilityChain).toEqual([rootCapabilityId(spaceUrl)])
    expect(Date.parse(child.expires)).toBe(
      toSeconds(now + DELETION_ZCAP_TTL_MS)
    )
    expect(child.proof.verificationMethod).toBe(
      `${ACCOUNT_DID}#${await ladderVmKeyMultibase({ ladderSeed })}`
    )
  })

  it('mints the GET-only probe child under the same shape', async () => {
    const child = (await mintSpaceRootVerbCapability({
      zcapClient: await ladderClient(fixedSeed(11)),
      storageServerUrl: WAS_URL,
      spaceId: ACCOUNT_SPACE_ID,
      verb: 'GET',
      controller: ACCOUNT_DID
    })) as IZcap & { allowedAction: string[] }

    expect(child.allowedAction).toEqual(['GET'])
  })
})

describe('deleteSpaceWithCapability', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  /**
   * Captures every request the helper sends and answers each with a fixed
   * status.
   */
  function stubFetch({ status }: { status: number }) {
    const requests: Array<{
      url: string
      method: string
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
          invocation: request.headers.get('capability-invocation')
        })
        return new Response(null, { status })
      }
    )
    return requests
  }

  /**
   * The DELETE-only child and the client that invokes it.
   */
  async function deleteFixture() {
    const invoker = await agentsFromSeed({ seed: fixedSeed(3) })
    const capability = await mintSpaceRootVerbCapability({
      zcapClient: await ladderClient(fixedSeed(11)),
      storageServerUrl: WAS_URL,
      spaceId: ACCOUNT_SPACE_ID,
      verb: 'DELETE',
      controller: invoker.keyAgent.id
    })
    return { invoker, capability }
  }

  it('sends the DELETE under the supplied capability', async () => {
    const { invoker, capability } = await deleteFixture()
    const requests = stubFetch({ status: 204 })
    const result = await deleteSpaceWithCapability({
      storageServerUrl: WAS_URL,
      zcapClient: invoker.zcapClient,
      spaceId: ACCOUNT_SPACE_ID,
      capability
    })

    expect(result).toEqual({ outcome: 'deleted' })
    expect(requests).toHaveLength(1)
    expect(requests[0]!.method).toBe('DELETE')
    expect(requests[0]!.url).toBe(`${WAS_URL}/space/${ACCOUNT_SPACE_ID}`)
    // The delegated invocation form -- the capability travels embedded,
    // rather than the root form's bare `id=`.
    expect(requests[0]!.invocation).toMatch(/capability="/)
  })

  it('reports a 404 as an outcome rather than success', async () => {
    const { invoker, capability } = await deleteFixture()
    stubFetch({ status: 404 })
    await expect(
      deleteSpaceWithCapability({
        storageServerUrl: WAS_URL,
        zcapClient: invoker.zcapClient,
        spaceId: ACCOUNT_SPACE_ID,
        capability
      })
    ).resolves.toEqual({ outcome: 'not-found' })
  })

  it('rethrows every other error', async () => {
    const { invoker, capability } = await deleteFixture()
    stubFetch({ status: 500 })
    await expect(
      deleteSpaceWithCapability({
        storageServerUrl: WAS_URL,
        zcapClient: invoker.zcapClient,
        spaceId: ACCOUNT_SPACE_ID,
        capability
      })
    ).rejects.toThrow()
  })

  it('reports the unlock Space delete the same way', async () => {
    const invoker = await agentsFromSeed({ seed: fixedSeed(3) })
    const capability = await mintSpaceRootVerbCapability({
      zcapClient: await ladderClient(fixedSeed(11)),
      storageServerUrl: WAS_URL,
      spaceId: UNLOCK_SPACE_ID,
      verb: 'DELETE',
      controller: invoker.keyAgent.id
    })
    stubFetch({ status: 404 })
    await expect(
      deleteUnlockSpaceWithCapability({
        storageServerUrl: WAS_URL,
        zcapClient: invoker.zcapClient,
        spaceId: UNLOCK_SPACE_ID,
        capability
      })
    ).resolves.toEqual({ outcome: 'not-found' })
  })
})
