/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The append path (App Connect spec `#log-append`): read the full log and
 * verify it (an entry is never built on an unverified head), build the new
 * entry against the verified head anchored at the writer's current verified
 * controller head, write compare-and-swapped on the read's validator, and on
 * conflict re-read, re-verify, rebase, retry. A write acknowledgement is a
 * promise, not a fact: every append is confirmed by reading the log back and
 * re-verifying the extended history before the append -- or any ceremony step
 * gated on it -- is treated as durable. The chain-head pin advances on every
 * successful verification along the way, and only ever forward.
 */
import { PreconditionFailedError } from '@interop/was-client'
import {
  confirmAppend,
  type ResourceLogEntry,
  type ResourceLogStore
} from '@interop/was-client/log'
import type { ResourceLogController } from './controller.js'
import { ResourceLogClosedError } from './errors.js'
import {
  buildResourceLogEntry,
  buildResourceLogGenesis,
  type ResourceLogSigner
} from './entry.js'
import type { ResourceLogPinStore } from './pin.js'
import { verifyResourceLog, type VerifiedResourceLog } from './verify.js'

/**
 * Reads and fully verifies a log through the store seam, advancing the
 * chain-head pin. Resolves `null` when the log resource does not exist yet
 * (the pre-genesis state). The one read entry point every consumer -- a
 * login-time roster read, a pre-append verification, a first-contact
 * bootstrap -- goes through, so the pin rules cannot be bypassed by reading
 * around them.
 *
 * @param options {object}
 * @param options.store {ResourceLogStore}   the log's transport seam
 * @param options.controller {ResourceLogController}   the verified controller
 *   view
 * @param options.expectedMethod {string}   the format identifier expected
 *   (also confirming any `history` dispatch hint the caller followed)
 * @param options.pinStore {ResourceLogPinStore}   this client's pin for this
 *   log
 * @param options.logId {string}   the pin-slot key for this log, from
 *   `resourceLogPinId`
 * @returns {Promise<{ verified: VerifiedResourceLog; etag?: string } | null>}
 */
export async function readResourceLog({
  store,
  controller,
  expectedMethod,
  pinStore,
  logId
}: {
  store: ResourceLogStore
  controller: ResourceLogController
  expectedMethod: string
  pinStore: ResourceLogPinStore
  logId: string
}): Promise<{ verified: VerifiedResourceLog; etag?: string } | null> {
  const current = await store.read()
  if (current === null) {
    return null
  }
  const pin = await pinStore.read({ logId })
  const verified = await verifyResourceLog({
    entries: current.entries,
    controller,
    expectedMethod,
    pin
  })
  await pinStore.write({ logId, pin: verified.pin })
  return { verified, etag: current.etag }
}

/**
 * Appends one state change: verify, build against the verified head, CAS,
 * rebase-and-retry on conflict, confirm by read-back. `buildState` is the
 * rebase hook -- it is called with the current verified log on every attempt
 * and returns the full next state built on THAT head's state (or `null` to
 * signal the change is already present, making a re-run converge instead of
 * duplicating an entry). Refuses a log whose verified head is a terminal
 * handover entry ({@link ResourceLogClosedError}).
 *
 * @param options {object}
 * @param options.store {ResourceLogStore}
 * @param options.controller {ResourceLogController}
 * @param options.expectedMethod {string}
 * @param options.pinStore {ResourceLogPinStore}
 * @param options.logId {string}   the pin-slot key for this log, from
 *   `resourceLogPinId`
 * @param options.signer {ResourceLogSigner}
 * @param options.buildState {function}   `(verified) => state | null` -- the
 *   full next state rebased on the verified head, or `null` when the head
 *   already carries the change
 * @param [options.versionTime] {string}   RFC3339 UTC; defaults to now
 * @param [options.maxAttempts] {number}   CAS attempts before giving up
 *   (default 3)
 * @returns {Promise<VerifiedResourceLog>}   the read-back, re-verified log
 *   (whether or not this call appended)
 */
export async function appendResourceLog({
  store,
  controller,
  expectedMethod,
  pinStore,
  logId,
  signer,
  buildState,
  versionTime,
  maxAttempts = 3
}: {
  store: ResourceLogStore
  controller: ResourceLogController
  expectedMethod: string
  pinStore: ResourceLogPinStore
  logId: string
  signer: ResourceLogSigner
  buildState: (
    verified: VerifiedResourceLog
  ) =>
    Promise<ResourceLogEntry['state'] | null> | ResourceLogEntry['state'] | null
  versionTime?: string
  maxAttempts?: number
}): Promise<VerifiedResourceLog> {
  let lastConflict: unknown
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const current = await readResourceLog({
      store,
      controller,
      expectedMethod,
      pinStore,
      logId
    })
    if (current === null) {
      throw new Error(
        'Cannot append to the resource log: the log does not exist yet ' +
          '(create it with its genesis entry first).'
      )
    }
    const { verified, etag } = current
    if (verified.terminal) {
      throw new ResourceLogClosedError({ nextLog: verified.terminal })
    }
    if (etag === undefined) {
      throw new Error(
        'Cannot append to the resource log: the backend returned no ' +
          'validator, and the profile forbids an unconditional write.'
      )
    }
    const state = await buildState(verified)
    if (state === null) {
      // The head already carries the change -- a torn earlier run landed it,
      // or a concurrent writer did. Converged.
      return verified
    }
    const entry = await buildResourceLogEntry({
      head: verified.head,
      state,
      controller,
      signer,
      versionTime
    })
    try {
      await store.append(entry, { ifMatch: etag })
    } catch (err) {
      if (err instanceof PreconditionFailedError) {
        // A concurrent append won the CAS: re-read, re-verify, rebase, retry.
        lastConflict = err
        continue
      }
      throw err
    }
    const readBack = await confirmAppend({ store, entry })
    const confirmed = await verifyResourceLog({
      entries: readBack.entries,
      controller,
      expectedMethod,
      pin: await pinStore.read({ logId })
    })
    await pinStore.write({ logId, pin: confirmed.pin })
    return confirmed
  }
  throw new Error(
    `Appending to the resource log lost the compare-and-swap race ` +
      `${maxAttempts} times in a row.`,
    { cause: lastConflict }
  )
}

/**
 * Creates a log with its genesis entry, guarded create-if-absent, and
 * confirms by read-back. Losing the create race to a concurrent provisioner
 * adopts the winner's log (the create is CAS, never clobbering): the served
 * log is verified and pinned, and the caller reconciles its intended state
 * through an ordinary {@link appendResourceLog}. First contact is where the
 * pin is established, so the pin store is written either way.
 *
 * @param options {object}
 * @param options.store {ResourceLogStore}
 * @param options.controller {ResourceLogController}
 * @param options.method {string}   the format identifier to declare
 * @param options.pinStore {ResourceLogPinStore}
 * @param options.logId {string}   the pin-slot key for this log, from
 *   `resourceLogPinId`
 * @param options.signer {ResourceLogSigner}
 * @param options.state {ResourceLogEntry['state']}   the full initial state
 * @param [options.previousLog] {object}   handover successors only
 * @param [options.versionTime] {string}   RFC3339 UTC; defaults to now
 * @returns {Promise<{ verified: VerifiedResourceLog; created: boolean }>}
 *   the verified log as it now stands, and whether this call created it
 */
export async function createResourceLog({
  store,
  controller,
  method,
  pinStore,
  logId,
  signer,
  state,
  previousLog,
  versionTime
}: {
  store: ResourceLogStore
  controller: ResourceLogController
  method: string
  pinStore: ResourceLogPinStore
  logId: string
  signer: ResourceLogSigner
  state: ResourceLogEntry['state']
  previousLog?: { scid: string; head: string }
  versionTime?: string
}): Promise<{ verified: VerifiedResourceLog; created: boolean }> {
  const genesis = await buildResourceLogGenesis({
    state,
    method,
    controller,
    signer,
    previousLog,
    versionTime
  })
  let created = true
  try {
    await store.create(genesis)
  } catch (err) {
    if (!(err instanceof PreconditionFailedError)) {
      throw err
    }
    created = false
  }
  const current = created
    ? await confirmAppend({ store, entry: genesis })
    : await store.read()
  if (current === null) {
    throw new Error(
      'The resource log create lost its guarded-create race, but no log ' +
        'was served on re-read.'
    )
  }
  const verified = await verifyResourceLog({
    entries: current.entries,
    controller,
    expectedMethod: method,
    pin: await pinStore.read({ logId })
  })
  await pinStore.write({ logId, pin: verified.pin })
  return { verified, created }
}
