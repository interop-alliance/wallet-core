/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The delegated did:webvh log store: the narrow read-and-publish seam
 * ({@link DelegatedWebvhLogStore}) served through a pre-minted delegation
 * rather than controller authority. Two credential-held bridges write
 * through it: the unlock record's `did.jsonl` bridge into the account log
 * (world-readable, so its reads stay unauthenticated), and the client
 * annex sibling delegation into a generation's capability-gated `gen-`
 * collection (GET and PUT, so its reads invoke the same delegation). Which
 * read a store performs is decided here from the wallet Space layout, never
 * by the caller: a world-readable roster collection (`isPublic` on its
 * provisioning spec) is fetched unauthenticated, and every other collection
 * -- an annex generation included, which the roster never lists -- is read
 * through the delegation. An unauthenticated GET at a capability-gated
 * resource, or a delegated GET under a PUT-only bridge, would each fail only
 * at the server.
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
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import { PreconditionFailedError, WasClient } from '@interop/was-client'
import { resourcePath, toUrl } from '@interop/was-client/paths'
import { WALLET_SPACE_PROVISION_ROSTER } from '../space/collections.js'
import type { WebvhIdStore } from './didWebvh.js'
import { logResourcePinId } from './verifyLog.js'

/**
 * The narrow store shape a delegated bridge serves: the log read plus the
 * conditional `did.jsonl` publish. A subset of {@link WebvhIdStore}, so it
 * satisfies the ceremony seams (`UnlockLogStore`, `RecoveryLogStore`, and the
 * annex ceremonies) structurally.
 */
export type DelegatedWebvhLogStore = Pick<
  WebvhIdStore,
  'getIdResourceRaw' | 'putIdResource' | 'pin'
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
 * Whether a collection of the wallet Space is world-readable, per its
 * provisioning spec. A collection the roster does not list (an annex
 * generation's `gen-` collection) is capability-gated.
 *
 * @param options {object}
 * @param options.collectionId {string}
 * @returns {boolean}
 */
function collectionIsPublic({
  collectionId
}: {
  collectionId: string
}): boolean {
  return (
    WALLET_SPACE_PROVISION_ROSTER.find(
      spec => spec.collectionId === collectionId
    )?.isPublic ?? false
  )
}

/**
 * Builds a delegated log store over one collection of one Space.
 *
 * Reads: on a world-readable collection (the `id` collection's account log
 * -- the bridge delegation allows PUT only) the GET is an unauthenticated
 * fetch; on every other collection it invokes the same delegation (the annex
 * inventory -- the generation collection is capability-gated and the sibling
 * delegation allows GET and PUT). The choice is read off the wallet Space
 * roster (`isPublic`), so no caller states it. Either way a 404 reads as
 * "not published" and the response's ETag rides back as the compare-and-swap
 * token.
 *
 * @param options {object}
 * @param options.host {string}   the storage server's base URL
 * @param options.spaceId {string}   the Space holding the collection
 * @param options.collectionId {string}   the collection holding the log
 * @param options.delegation {IZcap}   the pre-minted delegation the writes
 *   (and, on a capability-gated collection, the reads) invoke
 * @param options.zcapClient {ZcapClient}   the ezcap client holding the
 *   invoking signer
 * @param options.pinStore {ResourceLogPinStore}   this client's chain-head
 *   pins; the log's slot is derived here from the collection
 *   (`logResourcePinId`)
 * @returns {DelegatedWebvhLogStore}
 */
export function delegatedWebvhLogStore({
  host,
  spaceId,
  collectionId,
  delegation,
  zcapClient,
  pinStore
}: {
  host: string
  spaceId: string
  collectionId: string
  delegation: IZcap
  zcapClient: ZcapClient
  pinStore: ResourceLogPinStore
}): DelegatedWebvhLogStore {
  const publicRead = collectionIsPublic({ collectionId })
  const was = new WasClient({ serverUrl: host, zcapClient })
  const pathOf = (resourceId: string) =>
    resourcePath(spaceId, collectionId, resourceId)

  return {
    pin: {
      store: pinStore,
      logId: logResourcePinId({ spaceId, collectionId })
    },
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
      let response
      try {
        response = await was.request({
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
      // The PUT's own response carries the stored resource's new validator,
      // handed back as the root store hands it back: a ceremony that
      // publishes through the bridge can then build its next entry on the
      // head it just wrote, under a compare-and-swap, instead of re-reading.
      const etag = response.headers.get('etag') ?? undefined
      return etag !== undefined ? { etag } : {}
    }
  }
}
