/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The delegated did:webvh log store: the narrow read-and-publish seam
 * ({@link DelegatedWebvhLogStore}) served through a pre-minted delegation
 * rather than controller authority. Two credential-held bridges write
 * through it: the unlock record's `did.jsonl` bridge into the account log
 * (world-readable, so its reads stay unauthenticated), and the companion
 * sibling delegation into a generation's capability-gated `gen-` collection
 * (GET and PUT, so its reads invoke the same delegation).
 *
 * URLs are built with was-client's paths helpers, so a sub-path deployment
 * addresses exactly the resource the delegation's target names -- the
 * root-anchored form is drift this store must not reintroduce.
 *
 * The delegated PUT carries the same CAS/ETag conditional-publish discipline
 * as a controller-signed log write: `ifMatch` / `ifNoneMatch` ride as HTTP
 * preconditions, and a failed precondition (HTTP 412) is rethrown as
 * was-client's `PreconditionFailedError` -- the `name` the `WebvhIdStore`
 * seam contract requires -- so `putLogResource` maps a lost race to
 * `WebvhLogConflictError` and the ceremony re-runs on the new head. The
 * mapping is done here explicitly because the raw signed request
 * (`WasClient.request`) applies no error mapping of its own: it surfaces a
 * bare HTTP error whose `status` is all the store has to dispatch on.
 */
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { PreconditionFailedError, WasClient } from '@interop/was-client'
import { resourcePath, toUrl } from '@interop/was-client/paths'
import type { WebvhIdStore } from './didWebvh.js'

/**
 * The narrow store shape a delegated bridge serves: the log read plus the
 * conditional `did.jsonl` publish. A subset of {@link WebvhIdStore}, so it
 * satisfies the ceremony seams (`UnlockLogStore`, `RecoveryLogStore`, and the
 * companion ceremonies) structurally.
 */
export type DelegatedWebvhLogStore = Pick<
  WebvhIdStore,
  'getIdResourceRaw' | 'putIdResource'
>

/**
 * The `status` of a raw signed-request error, when it carries one.
 *
 * @param err {unknown}
 * @returns {number | undefined}
 */
function statusOf(err: unknown): number | undefined {
  const status = (err as { status?: unknown })?.status
  return typeof status === 'number' ? status : undefined
}

/**
 * Builds a delegated log store over one collection of one Space.
 *
 * Reads: with `publicRead` the GET is an unauthenticated fetch of the
 * world-readable resource (the account log's posture -- the bridge delegation
 * allows PUT only); without it the GET invokes the same delegation (the
 * companion posture -- the collection is capability-gated and the sibling
 * delegation allows GET and PUT). Either way a 404 reads as "not published"
 * and the response's ETag rides back as the compare-and-swap token.
 *
 * @param options {object}
 * @param options.host {string}   the storage server's base URL
 * @param options.spaceId {string}   the Space holding the collection
 * @param options.collectionId {string}   the collection holding the log
 * @param options.delegation {IZcap}   the pre-minted delegation the writes
 *   (and, without `publicRead`, the reads) invoke
 * @param options.zcapClient {ZcapClient}   the ezcap client holding the
 *   invoking signer
 * @param [options.publicRead] {boolean}   read with an unauthenticated fetch
 *   instead of invoking the delegation (default `false`)
 * @returns {DelegatedWebvhLogStore}
 */
export function delegatedWebvhLogStore({
  host,
  spaceId,
  collectionId,
  delegation,
  zcapClient,
  publicRead = false
}: {
  host: string
  spaceId: string
  collectionId: string
  delegation: IZcap
  zcapClient: ZcapClient
  publicRead?: boolean
}): DelegatedWebvhLogStore {
  const was = new WasClient({ serverUrl: host, zcapClient })
  const pathOf = (resourceId: string) =>
    resourcePath(spaceId, collectionId, resourceId)

  return {
    async getIdResourceRaw({ resourceId }: { resourceId: string }) {
      if (publicRead) {
        const response = await fetch(
          toUrl({ serverUrl: host, path: pathOf(resourceId) })
        )
        if (response.status === 404) {
          return undefined
        }
        if (!response.ok) {
          throw new Error(
            `Fetching "${resourceId}" failed (HTTP ${response.status}).`
          )
        }
        return {
          text: await response.text(),
          etag: response.headers.get('etag') ?? undefined
        }
      }
      let response
      try {
        response = await was.request({
          path: pathOf(resourceId),
          method: 'GET',
          capability: delegation
        })
      } catch (err) {
        if (statusOf(err) === 404) {
          return undefined
        }
        throw err
      }
      return {
        text: await response.text(),
        etag: response.headers.get('etag') ?? undefined
      }
    },
    async putIdResource({
      resourceId,
      content,
      contentType,
      ifMatch,
      ifNoneMatch
    }: {
      resourceId: string
      content: object | string
      contentType?: string
      ifMatch?: string
      ifNoneMatch?: boolean
    }) {
      const serialized =
        typeof content === 'string' ? content : JSON.stringify(content)
      const headers: Record<string, string> = {
        'content-type': contentType ?? 'application/json'
      }
      if (ifMatch !== undefined) {
        headers['if-match'] = ifMatch
      }
      if (ifNoneMatch) {
        headers['if-none-match'] = '*'
      }
      try {
        await was.request({
          path: pathOf(resourceId),
          method: 'PUT',
          headers,
          body: new TextEncoder().encode(serialized),
          capability: delegation
        })
      } catch (err) {
        // The raw signed request applies no error mapping, so a failed
        // precondition surfaces as a bare HTTP 412; rethrow it under the
        // name the seam contract requires for the ceremony's rebase.
        if (statusOf(err) === 412) {
          throw new PreconditionFailedError(
            `"${resourceId}" has moved on (stale precondition).`,
            { status: 412, cause: err }
          )
        }
        throw err
      }
    }
  }
}
