/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The credential-anchored establishment torn by a dropped response, against
 * the real server: the genesis entry's `PUT` of `did.jsonl` lands, and the
 * client never sees the answer. The genesis stage publishes create-if-absent
 * (`ifNoneMatch`), and a re-run adopts a published log iff the credential's
 * ladder attributes it, so the landed log is adopted rather than re-minted.
 * A re-mint would carry a different SCID, since `createDID` timestamps the
 * genesis entry.
 *
 * Two tears, one per case. The fault matches every `PUT` on the account's
 * `did.jsonl`, the pointer entry's included, so each case arms it before the
 * genesis entry and decides how far it reaches:
 *
 * - Every attempt dropped (`times: Infinity`): the HTTP client's own retries
 *   land as 412s and are dropped too, so the run rejects. The fault is
 *   `reset()` before the re-run, which then converges.
 * - One attempt dropped (`times: 1`): the HTTP client underneath ezcap (ky)
 *   retries a `PUT` on a network failure by default. The retry is answered
 *   412, which surfaces as a log conflict, and the conflict retry re-reads
 *   and adopts. The run converges within itself.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { resourcePath } from '@interop/was-client/paths'

import { setLogger } from '../../src/log.js'
import { ID_COLLECTION } from '../../src/space/index.js'
import {
  bootServer,
  establishAccount,
  mintCredential,
  transientVisit
} from './fixtures/credentialAnchoredAccount.js'

/**
 * Installs a logger that keeps the `'ceremony stage'` events' data and drops
 * everything else, so a torn run's error-level outcome stays out of the test
 * output.
 *
 * @returns {{ stages: Array<Record<string, unknown>>, restore: () => void }}
 */
function captureStageEvents() {
  const stages: Array<Record<string, unknown>> = []
  const ignore = () => undefined
  const previous = setLogger({
    debug: (msg, data) => {
      if (msg === 'ceremony stage' && data !== undefined) {
        stages.push(data)
      }
    },
    info: ignore,
    warn: ignore,
    error: ignore
  })
  return { stages, restore: () => setLogger(previous) }
}

describe('the credential-anchored establishment torn by a dropped response', () => {
  let server: Awaited<ReturnType<typeof bootServer>>

  beforeAll(async () => {
    server = await bootServer()
  })

  beforeEach(() => {
    server.faults.reset()
  })

  afterAll(async () => {
    await server.close()
  })

  /**
   * The account log as the server serves it to anyone (the `id` collection is
   * world-readable): its first line, the genesis entry, and the DID it names.
   *
   * @param options {object}
   * @param options.logPath {string}
   * @returns {Promise<{ genesisLine: string, did: string }>}
   */
  async function servedGenesis({ logPath }: { logPath: string }) {
    const response = await fetch(`${server.serverUrl}${logPath}`)
    expect(response.status).toBe(200)
    const genesisLine = (await response.text()).split('\n')[0]!
    const entry = JSON.parse(genesisLine) as { state: { id: string } }
    return { genesisLine, did: entry.state.id }
  }

  /**
   * The status and fault of every `PUT` of the account log the server has
   * recorded since the last `reset()`, in arrival order.
   *
   * @param options {object}
   * @param options.logPath {string}
   * @returns {Array<{ status?: number, fault?: string }>}
   */
  function logPuts({ logPath }: { logPath: string }) {
    return server.faults.requests
      .filter(record => record.method === 'PUT' && record.path === logPath)
      .map(({ status, fault }) => ({ status, fault }))
  }

  it('converges a run torn on every attempt by re-running it', async () => {
    const credential = await mintCredential()
    const logPath = resourcePath(
      credential.spaceId,
      ID_COLLECTION.id,
      'did.jsonl'
    )
    const capture = captureStageEvents()
    try {
      server.faults.dropResponse({
        match: { method: 'PUT', path: logPath },
        times: Infinity
      })
      await expect(
        establishAccount({ serverUrl: server.serverUrl, credential })
      ).rejects.toMatchObject({ cause: expect.any(TypeError) })

      // The genesis entry landed. Every retry the HTTP client sent after it
      // was refused create-if-absent, and its answer was dropped too.
      const [genesis, ...retries] = logPuts({ logPath })
      expect(genesis).toEqual({ status: 204, fault: 'dropped' })
      expect(retries.length).toBeGreaterThan(0)
      for (const retry of retries) {
        expect(retry).toEqual({ status: 412, fault: 'dropped' })
      }
      const landed = await servedGenesis({ logPath })

      // The re-run, with the same credential and no fault armed.
      server.faults.reset()
      capture.stages.length = 0
      const account = await establishAccount({
        serverUrl: server.serverUrl,
        credential
      })
      expect(account.accountDid).toBe(landed.did)
      expect(
        capture.stages.find(event => event.stage === 'webvh-genesis')
      ).toMatchObject({ prior: true })
      // The genesis entry stands byte for byte, and no create was refused:
      // the re-run's only log write is its pointer entry.
      expect((await servedGenesis({ logPath })).genesisLine).toBe(
        landed.genesisLine
      )
      expect(logPuts({ logPath })).toEqual([{ status: 204 }])

      const visit = await transientVisit({ account })
      expect(await visit.readRoster()).toBe(200)
    } finally {
      capture.restore()
    }
  })

  it('converges a single dropped response within the run', async () => {
    const credential = await mintCredential()
    const logPath = resourcePath(
      credential.spaceId,
      ID_COLLECTION.id,
      'did.jsonl'
    )
    const capture = captureStageEvents()
    try {
      server.faults.dropResponse({ match: { method: 'PUT', path: logPath } })
      const account = await establishAccount({
        serverUrl: server.serverUrl,
        credential
      })

      // The genesis entry landed unseen, the HTTP client's retry of it was
      // refused create-if-absent, and the pointer entry published after the
      // adoption.
      expect(logPuts({ logPath })).toEqual([
        { status: 204, fault: 'dropped' },
        { status: 412 },
        { status: 204 }
      ])
      expect(
        capture.stages.find(event => event.stage === 'webvh-genesis')
      ).toMatchObject({ prior: true })
      expect(account.accountDid).toBe((await servedGenesis({ logPath })).did)

      const visit = await transientVisit({ account })
      expect(await visit.readRoster()).toBe(200)
    } finally {
      capture.restore()
    }
  })
})
