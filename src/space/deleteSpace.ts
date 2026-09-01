/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The one capability-authorized Space DELETE. Every Space a wallet destroys
 * with an explicitly attached capability -- an unlock Space under its stored
 * management zcap, the account Space or an auxiliary annex Space under a
 * single-verb child of that Space's root -- sends the same request through
 * this helper.
 *
 * The 404 is REPORTED rather than decided here. An already-absent Space is
 * idempotent success to one caller and a case the deletion walk records to
 * another, so the outcome travels back to the caller and only a non-404
 * error propagates.
 *
 * What `not-found` means is exactly "the server answered 404", which covers
 * absent AND unauthorized: was-teaching-server masks a refused invocation as
 * 404, and the two are indistinguishable on the wire. No caller may read the
 * outcome as absence on its own; a caller that needs absence must establish
 * it by its own prior discovery.
 */
import { WasClient } from '@interop/was-client'
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'

/**
 * Deletes a Space with an explicitly attached capability, rather than by root
 * invocation. The `zcapClient`'s invocation signer must be a controller of
 * the attached capability; the capability itself is what authorizes the
 * DELETE against the Space.
 *
 * @param options {object}
 * @param options.storageServerUrl {string}
 * @param options.zcapClient {ZcapClient}   the invoking client
 * @param options.spaceId {string}   the Space to delete
 * @param options.capability {IZcap}   the attached capability (must allow
 *   DELETE on the Space's own URL)
 * @returns {Promise<{ outcome: 'deleted' | 'not-found' }>}   `not-found` when
 *   the server answered 404, which is absent OR unauthorized -- the two are
 *   indistinguishable on the wire, so this is not a statement of absence.
 *   Every other error propagates unchanged
 */
export async function deleteSpaceWithCapability({
  storageServerUrl,
  zcapClient,
  spaceId,
  capability
}: {
  storageServerUrl: string
  zcapClient: ZcapClient
  spaceId: string
  capability: IZcap
}): Promise<{ outcome: 'deleted' | 'not-found' }> {
  const was = new WasClient({ serverUrl: storageServerUrl, zcapClient })
  return was.space(spaceId, { capability }).deleteWithOutcome()
}
