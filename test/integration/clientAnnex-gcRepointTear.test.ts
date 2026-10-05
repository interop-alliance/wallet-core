/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The client-annex GC swap torn by a dropped re-point response, against the
 * real server. The swap mints a fresh generation, installs its delegation,
 * revokes the old one, and re-points the account document. The re-point's
 * `PUT` of `did.jsonl` lands, and the client never sees the answer. The
 * collect fan-out that follows must compare against the pointer the host now
 * serves, re-read from the account log, and not against the caller's
 * pre-pass view. That view names the old generation, and collecting the
 * fresh one would leave the account pointing at a deleted generation.
 *
 * Each pass runs with every generation GC-quiet, the fresh one included, so
 * the quiet guard cannot be what keeps the fresh generation. Only the re-read
 * pointer can. Two tears, one per case, each over its own account:
 *
 * - One response dropped (`times: 1`): the HTTP client underneath ezcap (ky)
 *   retries a `PUT` on a network failure. The retry is answered 412, the
 *   conflict retry re-reads, finds the pointer already moved, and adopts it.
 *   The swap converges within the run.
 * - Every response dropped (`times: Infinity`): the retry's 412 is dropped
 *   too, so the swap reports `failed`. The fan-out still reads the moved
 *   pointer and keeps the fresh generation, and a second pass finds nothing
 *   to do.
 */
import { WasClient } from '@interop/was-client'
import { resourcePath } from '@interop/was-client/paths'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it
} from 'vitest'

import {
  clientAnnexDidParts,
  delegatedClientsPointer,
  GENERATION_GC_PERIOD_MS,
  GENERATION_ID_PREFIX,
  GENERATION_QUIET_BOUND_MS,
  GENERATION_QUIET_GRACE_MS,
  runClientAnnexGc
} from '../../src/clientAnnex/index.js'
import type { ClientAnnexGcReport } from '../../src/clientAnnex/index.js'
import { setLogger } from '../../src/log.js'
import { ID_COLLECTION } from '../../src/space/index.js'
import { buildEnrolledClientAccount } from '../../src/testing/index.js'
import { verifyAccountLog, wasWebvhIdStore } from '../../src/webvh/index.js'
import {
  bootServer,
  transientVisit
} from './fixtures/credentialAnchoredAccount.js'

/**
 * How far past now a clock is past the quiet bound: every generation written
 * now, the one a pass mints included, is GC-quiet at it. Adding the GC period
 * makes the swap due as well.
 */
const PAST_QUIET_MS =
  GENERATION_QUIET_BOUND_MS + GENERATION_QUIET_GRACE_MS + 60_000

describe('the client-annex GC swap torn by a dropped re-point response', () => {
  let server: Awaited<ReturnType<typeof bootServer>>
  let previousLogger: ReturnType<typeof setLogger>

  beforeAll(async () => {
    server = await bootServer()
  })

  beforeEach(() => {
    server.faults.reset()
    // The torn ceremony's diagnostics stay out of the test output.
    const ignore = () => undefined
    previousLogger = setLogger({
      debug: ignore,
      info: ignore,
      warn: ignore,
      error: ignore
    })
  })

  afterEach(() => {
    setLogger(previousLogger)
  })

  afterAll(async () => {
    await server.close()
  })

  /**
   * A fresh enrolled-client account, acting as its enrolled client: the
   * storage client, the account log's id store, the log path, and the
   * pointed generation's id.
   *
   * @returns {Promise<object>}
   */
  async function enrolledSession() {
    const account = await buildEnrolledClientAccount({
      serverUrl: server.serverUrl
    })
    const { serverUrl, spaceId, accountDid, annexSpaceId, client } = account
    const pinStore = memoryResourceLogPinStore()
    const was = new WasClient({ serverUrl, zcapClient: client.zcapClient })
    const idStore = wasWebvhIdStore({ was, spaceId, pinStore })
    const logPath = resourcePath(spaceId, ID_COLLECTION.id, 'did.jsonl')

    /**
     * The account log as the server serves it now, verified under this
     * client's pin.
     *
     * @returns {Promise<object>}
     */
    async function verified() {
      return verifyAccountLog({
        did: accountDid,
        spaceId,
        host: serverUrl,
        pinStore
      })
    }

    /**
     * The generation id the served account document points at.
     *
     * @returns {Promise<string>}
     */
    async function pointedGenerationId() {
      const pointed = delegatedClientsPointer({ doc: (await verified()).doc })
      expect(pointed).toBeDefined()
      return clientAnnexDidParts({ did: pointed! }).generationId
    }

    /**
     * The ids of every `gen-` collection in the annex Space.
     *
     * @returns {Promise<string[]>}
     */
    async function generationIds() {
      const ids: string[] = []
      for await (const page of was.space(annexSpaceId).collectionsPages()) {
        for (const item of page.items) {
          if (item.id.startsWith(GENERATION_ID_PREFIX)) {
            ids.push(item.id)
          }
        }
      }
      return ids
    }

    /**
     * One GC pass over the account log as the server serves it now.
     *
     * @param options {object}
     * @param options.now {number}
     * @returns {Promise<object>}   the pass's report
     */
    async function gcPass({ now }: { now: number }) {
      const { doc, log } = await verified()
      return runClientAnnexGc({
        was,
        wasServerUrl: serverUrl,
        accountSpaceId: spaceId,
        account: { did: accountDid, doc, log },
        idStore,
        updateKeys: client.webvhUpdateKeys,
        zcapClient: client.zcapClient,
        ladderSeed: account.ladderSeed,
        recordDigest: async () => undefined,
        now
      })
    }

    /**
     * The status and fault of every `PUT` of the account log the server has
     * recorded since the last `reset()`, in arrival order.
     *
     * @returns {Array<{ status?: number, fault?: string }>}
     */
    function logPuts() {
      return server.faults.requests
        .filter(record => record.method === 'PUT' && record.path === logPath)
        .map(({ status, fault }) => ({ status, fault }))
    }

    /**
     * The `DELETE` requests the server has recorded on a generation's path
     * since the last `reset()`.
     *
     * @param options {object}
     * @param options.generationId {string}
     * @returns {Array<object>}
     */
    function deletesOf({ generationId }: { generationId: string }) {
      return server.faults.requests.filter(
        record =>
          record.method === 'DELETE' && record.path.includes(generationId)
      )
    }

    return {
      account,
      logPath,
      oldId: await pointedGenerationId(),
      pointedGenerationId,
      generationIds,
      gcPass,
      logPuts,
      deletesOf
    }
  }

  /**
   * The post-pass shape both tears converge to: the host serves a pointer
   * at a fresh generation, the report compared against it, the old
   * generation alone was collected, and the fresh one was never deleted.
   *
   * @param options {object}
   * @param options.session {object}   an {@link enrolledSession}
   * @param options.report {ClientAnnexGcReport}
   * @returns {Promise<string>}   the fresh generation's id
   */
  async function expectFreshPointed({
    session,
    report
  }: {
    session: Awaited<ReturnType<typeof enrolledSession>>
    report: ClientAnnexGcReport
  }) {
    const freshId = await session.pointedGenerationId()
    expect(freshId).not.toBe(session.oldId)
    expect(clientAnnexDidParts({ did: report.pointedDid! }).generationId).toBe(
      freshId
    )
    expect(report.collected).toEqual([session.oldId])
    expect(await session.generationIds()).toEqual([freshId])
    expect(session.deletesOf({ generationId: freshId })).toEqual([])
    return freshId
  }

  it('a single dropped re-point response converges within the run by adopting the landed pointer', async () => {
    const session = await enrolledSession()
    const { logPath } = session

    server.faults.reset()
    server.faults.dropResponse({ match: { method: 'PUT', path: logPath } })
    const report = await session.gcPass({
      now: Date.now() + GENERATION_GC_PERIOD_MS + PAST_QUIET_MS
    })

    expect(report.swap).toBe('replaced')
    expect(report.failed).toEqual([])
    // The re-point landed unseen, and the HTTP client's retry of it was
    // refused by the compare-and-swap. The conflict retry adopted the
    // landed pointer and wrote nothing more to the log.
    expect(session.logPuts()).toEqual([
      { status: 204, fault: 'dropped' },
      { status: 412 }
    ])
    await expectFreshPointed({ session, report })
  })

  it('a re-point whose every response is dropped reports the swap failed and still keeps the pointed generation', async () => {
    const session = await enrolledSession()
    const { logPath } = session

    server.faults.reset()
    server.faults.dropResponse({
      match: { method: 'PUT', path: logPath },
      times: Infinity
    })
    const report = await session.gcPass({
      now: Date.now() + GENERATION_GC_PERIOD_MS + PAST_QUIET_MS
    })

    expect(report.swap).toBe('failed')
    expect(report.failed.map(({ generationId }) => generationId)).toEqual([
      session.oldId
    ])
    expect(session.logPuts()[0]).toEqual({ status: 204, fault: 'dropped' })

    // The re-point landed: the host serves a pointer at a fresh generation,
    // and the fan-out compared against it.
    const freshId = await expectFreshPointed({ session, report })

    // A second pass, quiet but not a period past the fresh pointer entry.
    server.faults.reset()
    const second = await session.gcPass({ now: Date.now() + PAST_QUIET_MS })
    expect(second.swap).toBe('not-due')
    expect(second.collected).toEqual([])
    expect(second.deferred).toEqual([])
    expect(second.failed).toEqual([])
    expect(await session.generationIds()).toEqual([freshId])

    const visit = await transientVisit({ account: session.account })
    expect(await visit.readRoster()).toBe(200)
  })
})
