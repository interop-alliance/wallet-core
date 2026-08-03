/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The account's published-log verification step: fetch the world-readable
 * did:webvh log out of the Space's `id` collection, resolve it locally, and
 * refuse a log that resolves to a different DID than the account pointer
 * names. Every ceremony that reads or edits the document -- listing the
 * enrolled clients, approving a connect code, disconnecting a client,
 * rotating the wrap-set roster -- runs it first, so it lives here once
 * instead of once per wallet.
 *
 * The fetch is unauthenticated on purpose: the log is world-readable by
 * policy, and its own hash chain (SCID-pinned, prerotation-checked,
 * update-key signed) is what makes it trustworthy, not the channel. The
 * caller supplies the DID it expects; a resolved DID that does not match is
 * the substituted-account refusal, and the only thing the transport could
 * ever buy back.
 */
import { readLogFromString, resolveDIDFromLog } from '@interop/did-method-webvh'
import type { DIDDoc, DIDLog } from '@interop/did-method-webvh'
import { DID_LOG_RESOURCE, ID_COLLECTION } from '../space/collections.js'

/**
 * Thrown when the account has published no DID log at all (the resource is
 * absent). Distinguished from every other failure because it is the one
 * expected state of an in-flight ceremony -- a client completing its
 * enrollment before the other side has approved it reads this as "not yet",
 * not as a broken account.
 */
export class AccountLogMissingError extends Error {
  constructor(message = 'The account has no published DID log.') {
    super(message)
    this.name = 'AccountLogMissingError'
  }
}

/**
 * Fetches and locally verifies the account's world-readable DID log.
 *
 * Throws {@link AccountLogMissingError} when the log resource is absent, and
 * an ordinary error when the fetch fails, the log does not resolve, or it
 * resolves to a DID other than the one named.
 *
 * @param options {object}
 * @param options.did {string}   the account's did:webvh, as the caller's
 *   stored account pointer names it
 * @param options.spaceId {string}   the account's Space id
 * @param options.host {string}   the storage server the account lives on
 * @returns {Promise<object>}   the resolved document, the raw log, and the
 *   log's effective `updateKeys` / `nextKeyHashes`
 */
export async function verifyAccountLog({
  did,
  spaceId,
  host
}: {
  did: string
  spaceId: string
  host: string
}): Promise<{
  doc: DIDDoc
  log: DIDLog
  updateKeys: string[]
  nextKeyHashes: string[]
}> {
  const url = new URL(
    `/space/${spaceId}/${ID_COLLECTION.id}/${DID_LOG_RESOURCE}`,
    host
  )
  const response = await fetch(url)
  if (response.status === 404) {
    throw new AccountLogMissingError()
  }
  if (!response.ok) {
    throw new Error(
      `Fetching the account's DID log failed (HTTP ${response.status}).`
    )
  }
  const log = readLogFromString(await response.text())
  const resolved = await resolveDIDFromLog(log)
  if (resolved.meta.error || !resolved.did || !resolved.doc) {
    throw new Error(
      `The account's DID log failed to resolve (${
        resolved.meta.error ?? 'the resolver returned no DID document'
      }).`
    )
  }
  if (resolved.did !== did) {
    throw new Error(
      'The published DID log resolves to a different DID than the account ' +
        'pointer names.'
    )
  }
  return {
    doc: resolved.doc,
    log,
    updateKeys: resolved.meta.updateKeys ?? [],
    nextKeyHashes: resolved.meta.nextKeyHashes ?? []
  }
}
