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
 *
 * Resolution alone is one-shot verification, though: a host serving a valid
 * PREFIX of the real log serves the same SCID and the same DID, so a
 * truncated history passes every check above and a ceremony built on it
 * republishes erased enrollments and undone revocations as durable state. The
 * remedy is the same chain-head pin the governed resource logs carry, and
 * literally the same seam and refusal class: a caller that supplies a
 * {@link ResourceLogPinStore} gets a served log refused when it is a
 * rollback, a fork, or an SCID/method switch relative to the pinned head.
 */
import { readLogFromString, resolveDIDFromLog } from '@interop/did-method-webvh'
import type { DIDDoc, DIDLog } from '@interop/did-method-webvh'
import { resourcePath, toUrl } from '@interop/was-client/paths'
import { DID_LOG_RESOURCE, ID_COLLECTION } from '../space/collections.js'
import {
  ResourceLogContinuityError,
  resourceLogPinId,
  type ResourceLogHeadPin,
  type ResourceLogPinStore
} from '@interop/vh-resource-log'

/**
 * The pin-slot key for an account's did:webvh log (`id/did.jsonl`) -- what a
 * ceremony taking its own read of the log names its pin by, and what
 * {@link verifyAccountLog} derives internally.
 *
 * @param options {object}
 * @param options.spaceId {string}   the account's Space id
 * @returns {string}
 */
export function accountLogPinId({ spaceId }: { spaceId: string }): string {
  return resourceLogPinId({
    spaceId,
    collectionId: ID_COLLECTION.id,
    resourceId: DID_LOG_RESOURCE
  })
}

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
 * Refuses a served log that conflicts with the pinned head, and returns the
 * pin the served log establishes. A method or SCID that differs from the pin
 * is a substituted log under the account's location; a served history shorter
 * than the pinned ordinal is a rollback; a differing `versionId` at the pinned
 * ordinal is a fork, whose served entries ride along as evidence (every entry
 * is signed, so a conflicting pair under one SCID is transferable proof of
 * equivocation). A pin whose head does not parse as `N-<hash>` is treated as
 * a fork rather than trusted.
 *
 * Exported for the ceremony-side reads in `didWebvh.ts`, which take the same
 * check on their own read of `did.jsonl`; it is deliberately absent from the
 * module barrel.
 *
 * @param options {object}
 * @param options.log {DIDLog}   the served, already-resolved log
 * @param options.pin {ResourceLogHeadPin | null}   the pin held for this log
 * @returns {ResourceLogHeadPin}   the pin the served log establishes
 */
export function checkAccountLogContinuity({
  log,
  pin
}: {
  log: DIDLog
  pin: ResourceLogHeadPin | null
}): ResourceLogHeadPin {
  const genesis = log[0]
  const head = log[log.length - 1]
  if (!genesis || !head) {
    throw new Error('The account DID log is empty.')
  }
  const method = genesis.parameters.method ?? ''
  const scid = genesis.parameters.scid ?? ''
  if (pin) {
    if (pin.method !== method) {
      throw new ResourceLogContinuityError({
        reason: 'method-switch',
        pinnedHead: pin.head
      })
    }
    if (pin.scid !== scid) {
      throw new ResourceLogContinuityError({
        reason: 'scid-switch',
        pinnedHead: pin.head
      })
    }
    const pinnedOrdinal = Number.parseInt(pin.head, 10)
    if (!Number.isInteger(pinnedOrdinal) || pinnedOrdinal < 1) {
      throw new ResourceLogContinuityError({
        reason: 'fork',
        pinnedHead: pin.head,
        servedEntries: log
      })
    }
    if (log.length < pinnedOrdinal) {
      throw new ResourceLogContinuityError({
        reason: 'rollback',
        pinnedHead: pin.head
      })
    }
    if (log[pinnedOrdinal - 1]!.versionId !== pin.head) {
      throw new ResourceLogContinuityError({
        reason: 'fork',
        pinnedHead: pin.head,
        servedEntries: log
      })
    }
  }
  return { method, scid, head: head.versionId }
}

/**
 * Checks a served account log against the pin held for it and advances the
 * pin to the served head, which the check has just proven is genuinely ahead.
 *
 * The one implementation of the account log's check-and-advance step, shared
 * by {@link verifyAccountLog} and by the ceremony-side reads in `didWebvh.ts`:
 * a rollback, a fork, or an SCID / method switch refuses inside
 * {@link checkAccountLogContinuity}, so nothing that is not ahead ever
 * reaches the write.
 *
 * @param options {object}
 * @param options.pinStore {ResourceLogPinStore}
 * @param options.logId {string}   this log's slot in the store
 * @param options.log {DIDLog}   the served, already-resolved log
 * @returns {Promise<void>}
 */
export async function checkAndAdvanceAccountLogPin({
  pinStore,
  logId,
  log
}: {
  pinStore: ResourceLogPinStore
  logId: string
  log: DIDLog
}): Promise<void> {
  const pin = await pinStore.read({ logId })
  const served = checkAccountLogContinuity({ log, pin })
  // Advanced only when the served head is genuinely ahead of the pin: the
  // continuity check has already refused everything that is not.
  if (!pin || pin.head !== served.head) {
    await pinStore.write({ logId, pin: served })
  }
}

/**
 * Fetches and locally verifies the account's world-readable DID log.
 *
 * Throws {@link AccountLogMissingError} when the log resource is absent, and
 * an ordinary error when the fetch fails, the log does not resolve, or it
 * resolves to a DID other than the one named.
 *
 * Supplied a `pinStore`, the resolved log is additionally checked for
 * continuity against this client's chain-head pin and refused with a
 * {@link ResourceLogContinuityError} when it is a rollback, a fork, or an
 * SCID/method switch; the pin is established at first contact
 * (trust-on-first-use) and advanced only by a log that verifies past it,
 * never regressed. A `rollback` is the one refusal that may be nothing worse
 * than replication lag, exactly as on a governed resource log: nothing
 * rolled back is ever adopted here, and a caller holding a cached view of the
 * document may treat that reason as a transport hiccup and carry on with what
 * it has. Every other reason is a security signal. No `pinStore`, no
 * continuity check -- the pin lives app-side beside the account-pointer pin,
 * and a caller that has none keeps one-shot verification.
 *
 * @param options {object}
 * @param options.did {string}   the account's did:webvh, as the caller's
 *   stored account pointer names it
 * @param options.spaceId {string}   the account's Space id
 * @param options.host {string}   the storage server the account lives on
 * @param [options.pinStore] {ResourceLogPinStore}   this client's chain-head
 *   pins; the account log's slot is keyed by {@link accountLogPinId} over the
 *   `spaceId` above
 * @returns {Promise<object>}   the resolved document, the raw log, and the
 *   log's effective `updateKeys` / `nextKeyHashes`
 */
export async function verifyAccountLog({
  did,
  spaceId,
  host,
  pinStore
}: {
  did: string
  spaceId: string
  host: string
  pinStore?: ResourceLogPinStore
}): Promise<{
  doc: DIDDoc
  log: DIDLog
  updateKeys: string[]
  nextKeyHashes: string[]
}> {
  const url = toUrl({
    serverUrl: host,
    path: resourcePath(spaceId, ID_COLLECTION.id, DID_LOG_RESOURCE)
  })
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
  if (pinStore) {
    await checkAndAdvanceAccountLogPin({
      pinStore,
      logId: accountLogPinId({ spaceId }),
      log
    })
  }
  return {
    doc: resolved.doc,
    log,
    updateKeys: resolved.meta.updateKeys ?? [],
    nextKeyHashes: resolved.meta.nextKeyHashes ?? []
  }
}
