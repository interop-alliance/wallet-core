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
 * The same fetch runs in the other direction for a reader holding no DID at
 * all ({@link discoverAccountLog}): a requester granted a collection and
 * nothing that names the Space owner reads the log at the Space's `id`
 * collection and takes the owner from it. What stands in for the expected-DID
 * check there is the location check: a did:webvh identifier encodes where its
 * log is published, so the resolved DID must map back to the URL the log was
 * fetched from. Both readers run that check, so a log published for another
 * location and served under this one is refused whichever way it is read.
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
import type {
  DIDDoc,
  DIDLog,
  DIDResolutionMeta
} from '@interop/did-method-webvh'
import { accountLogUrl, didWebvhLogLocation } from './logLocation.js'
import type { PublishedWebvhLog } from './didWebvh.js'
import {
  webvhResourceLogController,
  type WebvhResourceLogController
} from '../resourceLog/controller.js'
import { DID_LOG_RESOURCE, ID_COLLECTION } from '../space/collections.js'
import {
  ResourceLogContinuityError,
  resourceLogPinId,
  type ResourceLogHeadPin,
  type ResourceLogPinStore
} from '@interop/vh-resource-log'

/**
 * The pin-slot key for the did:webvh log (`did.jsonl`) of one collection --
 * the one derivation every log store shares, so the root-invoked and the
 * delegated store families over the same collection check the same slot.
 * Host-free like every pin-slot key.
 *
 * @param options {object}
 * @param options.spaceId {string}   the Space holding the collection
 * @param options.collectionId {string}   the collection holding the log (the
 *   account's `id` collection, or an annex generation's `gen-` collection)
 * @returns {string}
 */
export function logResourcePinId({
  spaceId,
  collectionId
}: {
  spaceId: string
  collectionId: string
}): string {
  return resourceLogPinId({
    spaceId,
    collectionId,
    resourceId: DID_LOG_RESOURCE
  })
}

/**
 * The pin-slot key for an account's did:webvh log (`id/did.jsonl`) -- what
 * {@link verifyAccountLog}, which fetches by URL and holds no store, derives
 * internally.
 *
 * @param options {object}
 * @param options.spaceId {string}   the account's Space id
 * @returns {string}
 */
export function accountLogPinId({ spaceId }: { spaceId: string }): string {
  return logResourcePinId({ spaceId, collectionId: ID_COLLECTION.id })
}

/**
 * The substituted-account refusal on its own: a resolved head that is not the
 * DID the caller expected is refused rather than built on. Stated once so a
 * fresh read and a caller-threaded head refuse identically.
 *
 * A ceremony that takes an already-read head from its caller (the transient
 * visit's one-read composition, where the readiness stage hands its verified
 * head to the enrollment) runs this explicitly: the read that would otherwise
 * have run it never happened, and a head resolving to another DID must not
 * become the entry's basis just because it arrived by parameter.
 *
 * @param options {object}
 * @param options.published {PublishedWebvhLog}   the resolved head
 * @param [options.expectedDid] {string}   the DID it must resolve to; absent,
 *   the head is accepted (the caller discovering the DID from the log itself)
 * @returns {PublishedWebvhLog}   the head verbatim
 */
export function assertPublishedLogDid({
  published,
  expectedDid
}: {
  published: PublishedWebvhLog
  expectedDid?: string
}): PublishedWebvhLog {
  if (expectedDid !== undefined && published.did !== expectedDid) {
    throw new Error(
      'did:webvh: the published did.jsonl resolves to a different DID ' +
        `(${published.did}) than expected (${expectedDid}).`
    )
  }
  return published
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
 * an ordinary error when the fetch fails, the log does not resolve, the
 * resolved DID names another log location than the URL it was served from,
 * or it resolves to a DID other than the one named. The same reader with no
 * expected DID is {@link discoverAccountLog}.
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
 * and a caller that has none keeps one-shot verification. This is the one
 * reader that takes the pin store as an argument: it fetches by URL and holds
 * no {@link WebvhIdStore}, whose `pin` member is where every ceremony read
 * and publish finds it. A ceremony that holds a store hands this function
 * that store's pin store.
 *
 * @param options {object}
 * @param options.did {string}   the account's did:webvh, as the caller's
 *   stored account pointer names it; it locates its own log
 *   ({@link didWebvhLogLocation})
 * @param [options.pinStore] {ResourceLogPinStore}   this client's chain-head
 *   pins; the account log's slot is keyed by {@link accountLogPinId} over the
 *   Space id the DID names
 * @param [options.published] {PublishedWebvhLog}   a head this same run
 *   already read and resolved (an establishment handing its `accountLog`
 *   forward), reused in place of the fetch. Every check below still runs on
 *   it: the substituted-account refusal, and the chain-head check-and-advance
 *   under the same slot, so a supplied head behind the pin is refused with a
 *   {@link ResourceLogContinuityError} exactly as a served one would be.
 *   Reuse is only ever WITHIN one run or visit, never across writers: the
 *   head is evidence of what this client itself just saw or published, and a
 *   head carried in from anywhere else would defeat the freshness the fetch
 *   exists for
 * @returns {Promise<VerifiedAccountLog>}   the resolved document, the raw
 *   log, and the log's effective `updateKeys` / `nextKeyHashes`
 */
export async function verifyAccountLog({
  did,
  pinStore,
  published
}: {
  did: string
  pinStore?: ResourceLogPinStore
  published?: PublishedWebvhLog
}): Promise<VerifiedAccountLog> {
  const location = didWebvhLogLocation({ did })
  const read =
    published === undefined
      ? await readAccountLog({ logUrl: location.logUrl })
      : { published, spaceId: location.spaceId }
  await adoptAccountLog({
    published: read.published,
    expectedDid: did,
    spaceId: read.spaceId,
    pinStore
  })
  return verifiedAccountLogOf({ published: read.published })
}

/**
 * Resolves the account published at a Space with no DID known in advance:
 * fetches the world-readable log out of the Space's `id` collection, resolves
 * it locally, and returns the DID it resolves to beside the verified view.
 *
 * The caller that needs it is a requester holding per-collection grants and
 * nothing that names the Space owner (the grant chain's root is an opaque
 * URN, and the Space Description needs a Space-scoped capability App Connect
 * never delegates). The log is self-certifying, so the owner is the DID whose
 * log is published there and whose identifier maps back to that URL, the
 * location check `readAccountLog` runs. {@link verifyAccountLog} is this same
 * reader plus the expected-DID check.
 *
 * Throws {@link AccountLogMissingError} when the log resource is absent, and
 * an ordinary error when the fetch fails, the log does not resolve, or the
 * resolved DID names another location. A `pinStore` adds the same chain-head
 * check-and-advance {@link verifyAccountLog} runs, under the same slot.
 *
 * @param options {object}
 * @param options.spaceUrl {string}   the Space whose owner is wanted
 * @param [options.pinStore] {ResourceLogPinStore}   this client's chain-head
 *   pins, keyed by {@link accountLogPinId} over the Space's id
 * @returns {Promise<PublishedWebvhLog>}   the owner's DID, the resolved
 *   document, the raw log, and the log's effective update-key parameters
 */
export async function discoverAccountLog({
  spaceUrl,
  pinStore
}: {
  spaceUrl: string
  pinStore?: ResourceLogPinStore
}): Promise<PublishedWebvhLog> {
  const { published, spaceId } = await readAccountLog({
    logUrl: accountLogUrl({ spaceUrl })
  })
  return adoptAccountLog({ published, spaceId, pinStore })
}

/**
 * The checks both readers run on a resolved head, in the one order: the
 * expected-DID refusal (when a DID is expected) before the chain-head
 * check-and-advance, so a substituted account never advances the pin.
 *
 * @param options {object}
 * @param options.published {PublishedWebvhLog}
 * @param options.spaceId {string}
 * @param [options.expectedDid] {string}
 * @param [options.pinStore] {ResourceLogPinStore}
 * @returns {Promise<PublishedWebvhLog>}   the same head
 */
async function adoptAccountLog({
  published,
  spaceId,
  expectedDid,
  pinStore
}: {
  published: PublishedWebvhLog
  spaceId: string
  expectedDid?: string
  pinStore?: ResourceLogPinStore
}): Promise<PublishedWebvhLog> {
  assertPublishedLogDid({ published, expectedDid })
  if (pinStore) {
    await checkAndAdvanceAccountLogPin({
      pinStore,
      logId: accountLogPinId({ spaceId }),
      log: published.log
    })
  }
  return published
}

/**
 * The one fetch-parse-resolve body both readers share: fetch `did.jsonl`
 * unauthenticated, parse and resolve it, and refuse a resolved DID whose
 * published log location is not the URL it was served from. The location
 * check compares the log URL the resolved DID encodes
 * ({@link didWebvhLogLocation}) against the fetched URL; anything else is a
 * log published for another location and served here.
 *
 * @param options {object}
 * @param options.logUrl {string}   the `did.jsonl` URL to fetch
 * @returns {Promise<{ published: PublishedWebvhLog, spaceId: string }>}
 *   the resolved head, with no ETag (the read is a plain fetch, not a store
 *   read), beside the Space id its DID locates, read in the location check
 */
async function readAccountLog({
  logUrl: url
}: {
  logUrl: string
}): Promise<{ published: PublishedWebvhLog; spaceId: string }> {
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
  const location = didWebvhLogLocation({ did: resolved.did })
  if (location.logUrl !== new URL(url).href) {
    throw new Error(
      `did:webvh: the published did.jsonl resolves to ${resolved.did}, ` +
        `whose log location (${location.logUrl}) is not where it was ` +
        `served from (${url}).`
    )
  }
  return {
    published: {
      did: resolved.did,
      doc: resolved.doc,
      log,
      updateKeys: resolved.meta.updateKeys ?? [],
      nextKeyHashes: resolved.meta.nextKeyHashes ?? [],
      meta: resolved.meta
    },
    spaceId: location.spaceId
  }
}

/**
 * What {@link verifyAccountLog} returns: the account document as the log
 * resolves it, the raw log, and the log's effective update-key parameters.
 * Named because it is also what a caller seeds a session-scoped verified-log
 * memo with, from a head a ceremony handed it.
 */
export interface VerifiedAccountLog {
  doc: DIDDoc
  log: DIDLog
  updateKeys: string[]
  nextKeyHashes: string[]
  /**
   * The resolver's meta for exactly the entries in `log`.
   */
  meta: DIDResolutionMeta
}

/**
 * The {@link VerifiedAccountLog} view of a head a ceremony already read or
 * published -- a projection, not a check. The caller that seeds a memo from
 * an establishment's own `accountLog` uses it rather than re-fetching the log
 * that run just wrote; a caller wanting the DID and pin checks too calls
 * {@link verifyAccountLog} with the head instead.
 *
 * @param options {object}
 * @param options.published {PublishedWebvhLog}   the resolved head
 * @returns {VerifiedAccountLog}
 */
export function verifiedAccountLogOf({
  published
}: {
  published: PublishedWebvhLog
}): VerifiedAccountLog {
  return {
    doc: published.doc,
    log: published.log,
    updateKeys: published.updateKeys,
    nextKeyHashes: published.nextKeyHashes,
    meta: published.meta
  }
}

/**
 * Builds the memoized controller resolver an account-shaped store builder
 * takes ({@link userKeyRosterDescriptorStore}'s `resolveController`, and
 * `accountCollectionStores`' own): the account's verified controller view,
 * resolved once for the life of the resolver and shared by every store
 * built over it, so a roster store and its per-collection twin built from
 * the same parts verify the account log once between them.
 *
 * Nothing runs until the first call. With `log` given, the view is built
 * from it and `did.jsonl` is never fetched: it is what the run itself
 * published or adopted, so a fetch could only serve something the run has
 * not built on. Otherwise the first call runs one {@link verifyAccountLog}
 * under the pin store handed in, memoized as the in-flight promise; a failed
 * verification clears the memo, so the next call retries rather than
 * replaying the refusal.
 *
 * @param options {object}
 * @param options.did {string}   the account's did:webvh
 * @param options.pinStore {ResourceLogPinStore}   the account log's
 *   chain-head pin, checked and advanced when the log is fetched here
 * @param [options.log] {DIDLog}   the account log this run already stands on
 *   (a ceremony that just read or published it); given, no fetch runs
 * @returns {function}   `() => Promise<WebvhResourceLogController>`
 */
export function accountControllerResolver({
  did,
  pinStore,
  log
}: {
  did: string
  pinStore: ResourceLogPinStore
  log?: DIDLog
}): () => Promise<WebvhResourceLogController> {
  let pending: Promise<WebvhResourceLogController> | undefined
  return async () => {
    pending ??= (
      log === undefined
        ? verifyAccountLog({ did, pinStore }).then(({ log: served }) => served)
        : Promise.resolve(log)
    ).then(
      served => webvhResourceLogController({ did, log: served }),
      err => {
        pending = undefined
        throw err
      }
    )
    return await pending
  }
}
