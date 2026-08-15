/**
 * Unit tests for the conditional `did.jsonl` publish: the compare-and-swap
 * every did:webvh ceremony writes its entry under, the typed
 * `WebvhLogConflictError` a lost race raises, and the rebase-by-re-run retry
 * that makes two interleaved ceremonies (a revocation and an enrollment
 * approval reading the same published version) BOTH land instead of one
 * silently erasing the other. Also covers the create race two concurrent
 * signups can run into, and the degradation on a backend that serves no
 * ETags.
 */
import { describe, expect, it } from 'vitest'
import {
  defaultWebvhLogVerifier,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import {
  ensureDidWebvh,
  enrollWebvhClient,
  mintClientWebvhUpdateKeys,
  publishWebvhLog,
  updateKeyMultibase,
  WebvhLogConflictError,
  type WebvhEnrollmentKeys,
  type WebvhIdStore
} from '../../src/webvh/didWebvh.js'
import { revokeWebvhClient } from '../../src/webvh/revokeClient.js'
import { DID_LOG_RESOURCE } from '../../src/space/collections.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-conflict'
const DID_WEB = `did:web:localhost%3A8080:space:${SPACE_ID}:id`

const DID_WEB_KEYS = {
  authentication: {
    vmId: `${DID_WEB}#z6MkAuth`,
    kmsKeyId: 'kms/keys/auth'
  },
  keyAgreement: { vmId: `${DID_WEB}#z6LSAgree`, kmsKeyId: 'kms/keys/agree' }
}

/**
 * The public halves of a client, over freshly minted update-key seeds.
 *
 * @param options {object}
 * @param options.signingKeyMultibase {string}
 * @param options.keyAgreementKeyMultibase {string}
 * @returns {Promise<object>}   the enrollment keys plus their seeds
 */
async function mintClient({
  signingKeyMultibase,
  keyAgreementKeyMultibase
}: {
  signingKeyMultibase: string
  keyAgreementKeyMultibase: string
}): Promise<{
  keys: WebvhEnrollmentKeys
  seeds: Awaited<ReturnType<typeof mintClientWebvhUpdateKeys>>
}> {
  const seeds = await mintClientWebvhUpdateKeys()
  return {
    seeds,
    keys: {
      signingKeyMultibase,
      keyAgreementKeyMultibase,
      updateKeyMultibase: await updateKeyMultibase({ seed: seeds.updateSeed }),
      stagedUpdateKeyMultibase: await updateKeyMultibase({
        seed: seeds.stagedSeed
      })
    }
  }
}

/**
 * Provisions an account holding two enrolled clients (the actor that runs the
 * ceremonies, and the one the revocation targets), plus a third client's key
 * set waiting to be enrolled.
 *
 * @param [options] {object}
 * @param [options.etags] {boolean}   whether the fake backend versions
 *   resources and enforces conditional writes
 * @returns {Promise<object>}
 */
async function accountWithPendingEnrollee({
  etags = true
}: { etags?: boolean } = {}) {
  const store = memoryIdStore({ etags })
  const { idStore, log } = store
  const first = await mintClient({
    ...CANONICAL_CLIENT_KEYS[0]
  })
  const { did } = await ensureDidWebvh({
    idStore,
    wasServerUrl: WAS_URL,
    spaceId: SPACE_ID,
    didWebKeys: DID_WEB_KEYS,
    clientKeys: {
      signingKeyMultibase: first.keys.signingKeyMultibase,
      keyAgreementKeyMultibase: first.keys.keyAgreementKeyMultibase
    },
    updateKeys: first.seeds
  })
  const second = await mintClient({
    ...CANONICAL_CLIENT_KEYS[1]
  })
  await enrollWebvhClient({
    idStore,
    updateKeys: first.seeds,
    newClient: second.keys
  })
  const third = await mintClient({
    ...CANONICAL_CLIENT_KEYS[2]
  })
  return { idStore, log, did, first, second, third }
}

/**
 * Wraps a store so the FIRST `did.jsonl` read serves the supplied stale
 * snapshot (the state a concurrently running ceremony had already read) while
 * every write, and every later read, goes to the live store -- the interleave
 * two ceremonies racing on one log produce.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.snapshot {object}   the stale `{ text, etag }` read
 * @returns {WebvhIdStore}
 */
function withStaleFirstRead({
  idStore,
  snapshot
}: {
  idStore: WebvhIdStore
  snapshot: { text: string; etag?: string }
}): WebvhIdStore {
  let served = false
  return {
    ...idStore,
    async getIdResourceRaw(options: { resourceId: string }) {
      if (!served && options.resourceId === DID_LOG_RESOURCE) {
        served = true
        return snapshot
      }
      return idStore.getIdResourceRaw(options)
    }
  }
}

/**
 * Resolves the store's current log with full verification.
 *
 * @param log {function}
 * @returns {Promise<object>}
 */
async function resolved(log: () => string | undefined) {
  const result = await resolveDIDFromLog(readLogFromString(log()!), {
    verifier: defaultWebvhLogVerifier
  })
  expect(result.meta.error).toBeUndefined()
  return result
}

/**
 * The `publicKeyMultibase` values the resolved document publishes.
 *
 * @param log {function}
 * @returns {Promise<string[]>}
 */
async function publishedMultibases(log: () => string | undefined) {
  const state = await resolved(log)
  return (state.doc!.verificationMethod ?? []).map(
    (method: { publicKeyMultibase?: string }) => method.publicKeyMultibase
  )
}

describe('conditional did.jsonl publish', () => {
  it('refuses a publish whose ifMatch is stale, as a WebvhLogConflictError', async () => {
    const { idStore, log, first, third } = await accountWithPendingEnrollee()
    const stale = await idStore.getIdResourceRaw({
      resourceId: DID_LOG_RESOURCE
    })
    // Another ceremony moves the log on, invalidating the captured validator.
    await enrollWebvhClient({
      idStore,
      updateKeys: first.seeds,
      newClient: third.keys
    })

    const conflict = await publishWebvhLog({
      idStore,
      log: readLogFromString(log()!),
      webDoc: { id: 'did:web:example' },
      ifMatch: stale!.etag
    }).catch((err: unknown) => err)
    expect(conflict).toBeInstanceOf(WebvhLogConflictError)
    expect((conflict as { cause?: { name?: string } }).cause?.name).toBe(
      'PreconditionFailedError'
    )
  })

  it('lands BOTH an enrollment and a revocation that read the same version (enrollment first)', async () => {
    const { idStore, log, first, second, third } =
      await accountWithPendingEnrollee()
    // Both ceremonies read this version; the enrollment publishes first.
    const shared = (await idStore.getIdResourceRaw({
      resourceId: DID_LOG_RESOURCE
    }))!

    await enrollWebvhClient({
      idStore,
      updateKeys: first.seeds,
      newClient: third.keys
    })
    // The revocation still holds the pre-enrollment snapshot: its publish
    // loses the compare-and-swap and the retry rebases it on the new head.
    await revokeWebvhClient({
      idStore: withStaleFirstRead({ idStore, snapshot: shared }),
      updateKeys: first.seeds,
      revokedClient: second.keys
    })

    const multibases = await publishedMultibases(log)
    expect(multibases).toContain(third.keys.signingKeyMultibase)
    expect(multibases).toContain(third.keys.keyAgreementKeyMultibase)
    expect(multibases).not.toContain(second.keys.signingKeyMultibase)
    expect(multibases).not.toContain(second.keys.keyAgreementKeyMultibase)
    const state = await resolved(log)
    expect(state.meta.updateKeys).toContain(third.keys.updateKeyMultibase)
    expect(state.meta.updateKeys).not.toContain(second.keys.updateKeyMultibase)
  })

  it('lands BOTH an enrollment and a revocation that read the same version (revocation first)', async () => {
    const { idStore, log, first, second, third } =
      await accountWithPendingEnrollee()
    const shared = (await idStore.getIdResourceRaw({
      resourceId: DID_LOG_RESOURCE
    }))!

    await revokeWebvhClient({
      idStore,
      updateKeys: first.seeds,
      revokedClient: second.keys
    })
    // The approval still holds the pre-revocation snapshot: without the
    // compare-and-swap its entry would restore the revoked client's
    // verification methods wholesale.
    await enrollWebvhClient({
      idStore: withStaleFirstRead({ idStore, snapshot: shared }),
      updateKeys: first.seeds,
      newClient: third.keys
    })

    const multibases = await publishedMultibases(log)
    expect(multibases).toContain(third.keys.signingKeyMultibase)
    expect(multibases).not.toContain(second.keys.signingKeyMultibase)
    expect(multibases).not.toContain(second.keys.keyAgreementKeyMultibase)
    const state = await resolved(log)
    expect(state.meta.updateKeys).toContain(third.keys.updateKeyMultibase)
    expect(state.meta.updateKeys).not.toContain(second.keys.updateKeyMultibase)
  })

  it('refuses the losing side of a create race instead of overwriting the winner', async () => {
    const store = memoryIdStore()
    const { idStore, log } = store
    const winner = await mintClient({
      ...CANONICAL_CLIENT_KEYS[3]
    })
    await ensureDidWebvh({
      idStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: DID_WEB_KEYS,
      clientKeys: {
        signingKeyMultibase: winner.keys.signingKeyMultibase,
        keyAgreementKeyMultibase: winner.keys.keyAgreementKeyMultibase
      },
      updateKeys: winner.seeds
    })
    const published = log()

    // The loser started before the winner published, so it still sees no log.
    let served = false
    const staleStore: WebvhIdStore = {
      ...idStore,
      async getIdResourceRaw(options: { resourceId: string }) {
        if (!served && options.resourceId === DID_LOG_RESOURCE) {
          served = true
          return undefined
        }
        return idStore.getIdResourceRaw(options)
      }
    }
    const loser = await mintClient({
      ...CANONICAL_CLIENT_KEYS[4]
    })
    // Its create-if-absent loses; the retry re-reads and takes the adoption
    // path, which refuses because the winner's log holds none of its seeds.
    await expect(
      ensureDidWebvh({
        idStore: staleStore,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        didWebKeys: DID_WEB_KEYS,
        clientKeys: {
          signingKeyMultibase: loser.keys.signingKeyMultibase,
          keyAgreementKeyMultibase: loser.keys.keyAgreementKeyMultibase
        },
        updateKeys: loser.seeds
      })
    ).rejects.toThrow(/authorizes none of this client's update keys/)
    expect(log()).toBe(published)
  })

  it('degrades to unconditional writes on a backend that serves no ETags', async () => {
    const { idStore, log, first, second, third } =
      await accountWithPendingEnrollee({ etags: false })
    const read = await idStore.getIdResourceRaw({
      resourceId: DID_LOG_RESOURCE
    })
    expect(read?.etag).toBeUndefined()

    await enrollWebvhClient({
      idStore,
      updateKeys: first.seeds,
      newClient: third.keys
    })
    await revokeWebvhClient({
      idStore,
      updateKeys: first.seeds,
      revokedClient: second.keys
    })

    const multibases = await publishedMultibases(log)
    expect(multibases).toContain(third.keys.signingKeyMultibase)
    expect(multibases).not.toContain(second.keys.signingKeyMultibase)
  })
})
