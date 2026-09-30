/**
 * An append verifies its log once. Every entry write builds on a pinned read
 * that already resolved the log, and hands that read's resolution meta to
 * `updateDID` as `priorMeta`, so the library does not resolve the same bytes
 * a second time.
 *
 * Two probes. `resolveDIDFromLog` is wrapped with a counter, which sees every
 * resolve wallet-core itself runs. `updateDID` is wrapped to inject a counting
 * `verifier`. The library consults it once to self-check the new entry's
 * proof, and once more per prior entry when it resolves the prior log
 * itself, so a count of one means the internal resolve never ran. A control
 * case calls `updateDID` without `priorMeta` to show that probe is live.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type {
  DIDResolutionMeta,
  UpdateDIDInterface
} from '@interop/did-method-webvh'

const counts = vi.hoisted(() => ({
  resolves: 0,
  verifies: 0,
  priorMetas: [] as (DIDResolutionMeta | undefined)[]
}))

vi.mock('@interop/did-method-webvh', async importOriginal => {
  const actual =
    await importOriginal<typeof import('@interop/did-method-webvh')>()
  const countingVerifier = {
    async verify(
      signature: Uint8Array,
      message: Uint8Array,
      publicKey: Uint8Array
    ): Promise<boolean> {
      counts.verifies += 1
      return actual.defaultWebvhLogVerifier.verify(
        signature,
        message,
        publicKey
      )
    }
  }
  return {
    ...actual,
    resolveDIDFromLog: async (
      ...args: Parameters<typeof actual.resolveDIDFromLog>
    ) => {
      counts.resolves += 1
      return actual.resolveDIDFromLog(...args)
    },
    updateDID: async (options: UpdateDIDInterface) => {
      counts.priorMetas.push(options.priorMeta)
      return actual.updateDID({ ...options, verifier: countingVerifier })
    }
  }
})

import {
  deriveNextKeyHash,
  readLogFromString,
  updateDID
} from '@interop/did-method-webvh'
import { clientAnnexRung } from '../../src/clientAnnex/ladder.js'
import {
  createClientAnnexLog,
  enrollClientAnnexTransientClient,
  mintGenerationId
} from '../../src/clientAnnex/log.js'
import {
  accountEntryHead,
  signAccountEntry
} from '../../src/webvh/accountEntry.js'
import {
  ensureDidWebvh,
  mintClientWebvhUpdateKeys,
  putLogResource,
  readPublishedLogOrThrow,
  rotateWebvhUpdateKey,
  updateKeySigner
} from '../../src/webvh/didWebvh.js'
import type { ClientWebvhUpdateKeys } from '../../src/webvh/didWebvh.js'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'
import { resolved } from './fixtures/resolvedLog.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-prior-meta'

/**
 * Zeroes the probes, so a count covers only the call under test.
 */
function resetCounts(): void {
  counts.resolves = 0
  counts.verifies = 0
  counts.priorMetas = []
}

/**
 * An account provisioned for one enrolled client.
 */
async function clientAnchoredAccount() {
  const fixture = memoryIdStore({ spaceId: SPACE_ID })
  const updateKeys = mintClientWebvhUpdateKeys()
  const { did } = await ensureDidWebvh({
    idStore: fixture.idStore,
    wasServerUrl: WAS_URL,
    spaceId: SPACE_ID,
    clientKeys: { ...CANONICAL_CLIENT_KEYS[0] },
    updateKeys
  })
  return { ...fixture, updateKeys, did }
}

beforeEach(() => {
  resetCounts()
})

describe('an account-log append resolves the log once', () => {
  it('signAccountEntry hands updateDID the pinned read meta', async () => {
    const { idStore, log, updateKeys, did } = await clientAnchoredAccount()
    const committed = await deriveNextKeyHash(
      CANONICAL_CLIENT_KEYS[5]!.signingKeyMultibase
    )
    resetCounts()

    const outcome = await signAccountEntry({
      idStore,
      signer: { kind: 'enrolled', updateKeys },
      expectedDid: did,
      build: () => ({ commitHashes: [committed] })
    })

    expect(outcome.skipped).toBe(false)
    expect(counts.resolves).toBe(1)
    expect(counts.verifies).toBe(1)
    expect(counts.priorMetas).toHaveLength(1)
    expect(counts.priorMetas[0]).toBe(outcome.published.meta)

    // Outside the counted window: the written log still verifies, and its
    // head is the entry just built.
    const after = await resolved(log)
    expect(after.meta.versionId).toBe(outcome.updated!.meta.versionId)
    expect(after.meta.nextKeyHashes).toContain(committed)
  })

  it('a second entry built on the first entry head resolves nothing', async () => {
    const { idStore, log, updateKeys, did } = await clientAnchoredAccount()
    const first = await signAccountEntry({
      idStore,
      signer: { kind: 'enrolled', updateKeys },
      expectedDid: did,
      build: () => ({})
    })
    const head = accountEntryHead({ outcome: first })
    resetCounts()

    const second = await signAccountEntry({
      idStore,
      signer: { kind: 'enrolled', updateKeys },
      expectedDid: did,
      published: head,
      build: () => ({})
    })

    expect(second.skipped).toBe(false)
    expect(counts.resolves).toBe(0)
    expect(counts.verifies).toBe(1)
    expect(counts.priorMetas[0]).toBe(head.meta)
    const after = await resolved(log)
    expect(after.meta.versionId).toBe(second.updated!.meta.versionId)
  })

  it('rotateWebvhUpdateKey resolves the log once', async () => {
    const { idStore, log, updateKeys, did } = await clientAnchoredAccount()
    let persisted: ClientWebvhUpdateKeys = updateKeys
    resetCounts()

    await rotateWebvhUpdateKey({
      idStore,
      updateKeys,
      persistUpdateKeys: async next => {
        persisted = next
      },
      expectedDid: did
    })

    expect(counts.resolves).toBe(1)
    expect(counts.verifies).toBe(1)
    expect(counts.priorMetas).toHaveLength(1)
    expect(counts.priorMetas[0]).toBeDefined()
    const after = await resolved(log)
    expect(after.meta.updateKeys).toHaveLength(1)
    expect(persisted.updateSeed).toEqual(updateKeys.stagedSeed)
  })

  it('a client annex transient enrollment resolves the log once', async () => {
    const ladderSeed = new Uint8Array(32).fill(11)
    const generationId = mintGenerationId()
    const rung = await clientAnnexRung({ ladderSeed, generationId })
    const created = await createClientAnnexLog({
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      generationId,
      updateKeyPublicKeyMultibase: rung.keyMultibase,
      nextKeyHashes: [await deriveNextKeyHash(rung.keyMultibase)],
      signer: await updateKeySigner({ seed: rung.seed })
    })
    const fixture = memoryIdStore({ spaceId: SPACE_ID })
    await putLogResource({
      store: fixture.idStore,
      log: created.log,
      ifNoneMatch: true
    })
    resetCounts()

    await enrollClientAnnexTransientClient({
      store: fixture.idStore,
      ladderSeed,
      generationId,
      transientKeyMultibase: CANONICAL_CLIENT_KEYS[3]!.signingKeyMultibase,
      expectedDid: created.did
    })

    expect(counts.resolves).toBe(1)
    expect(counts.verifies).toBe(1)
    expect(counts.priorMetas[0]).toBeDefined()
    const after = await resolved(fixture.log)
    expect(after.meta.versionId).toMatch(/^2-/)
  })

  it('without priorMeta, updateDID resolves the prior log itself', async () => {
    const { idStore, updateKeys, did } = await clientAnchoredAccount()
    const published = await readPublishedLogOrThrow({
      idStore,
      expectedDid: did
    })
    resetCounts()

    const updated = await updateDID({
      log: readLogFromString(
        published.log.map(entry => JSON.stringify(entry)).join('\n')
      ),
      signer: await updateKeySigner({ seed: updateKeys.updateSeed }),
      updateKeys: published.updateKeys,
      nextKeyHashes: published.nextKeyHashes
    })

    expect(updated.meta.error).toBeUndefined()
    // The internal resolve verified the genesis entry's proof beside the new
    // entry's self-check, which is what makes the counts of one above
    // meaningful.
    expect(counts.verifies).toBe(2)
  })
})
