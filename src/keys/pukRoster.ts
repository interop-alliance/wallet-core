/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The PUK wrap set: the `key-map/puk.json` roster resource. Its body is a
 * `CollectionEncryption` descriptor verbatim, whose current epoch IS the
 * current
 * per-user key -- the epoch id is the PUK's did:key and the wrapped secret is
 * the PUK's raw 32-byte key, wrapped to each enrolled client's key-agreement
 * key. The roster is the delivery channel for PUK rotation: each client keeps
 * the PUK in its own local state under the unlock layer, and the roster's
 * epoch stamp marks a cached copy stale.
 *
 * Everything mutates through was-client's descriptor-store seam (the
 * plain-resource adapter): read-with-etag, compare-and-swap writes, and a
 * guarded create for the initially-absent roster. No descriptor logic is
 * reimplemented here.
 *
 * A resource-hosted descriptor gets NONE of the server-side epoch invariants a
 * Collection Description enforces (append-only epochs, monotone
 * `currentEpoch`), so three client-side compensations are load-bearing alone
 * against a tampering host:
 *
 * - **`epochsMac`** -- the epoch configuration is authenticated under the
 *   current epoch's secret, which the server never holds; a fabricated
 *   configuration fails the MAC (`PukRosterIntegrityError`).
 * - **The epoch pin** -- the latest-seen roster epoch is pinned locally by the
 *   consuming app (beside the account-pointer pin); a served
 *   roster that rolls back behind the pin is refused
 *   (`PukRosterContinuityError`) rather than followed. Stale-roster replay
 *   thereby lands in the same accepted continuity class as a substituted
 *   account pointer.
 * - **The roster delivers, never sources** -- the recipient-key source of
 *   record is the locally verified did:webvh document (one `keyAgreement`
 *   verification method per enrolled client). When an epoch rotates, each
 *   remaining recipient's key is resolved from that document
 *   (`pukRosterRecipientResolver`); a roster entry with no matching document
 *   verification method is dropped and never receives a wrap, so a
 *   server-injected entry sits ignored. Wraps are minted only by enrolled
 *   clients, against log-verified keys.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import {
  addRecipient,
  initRecipients,
  ownerRecipient,
  unwrapEpochSecret,
  verifyEpochsMac,
  type EncryptionDescriptorStore,
  type RecipientPublicKey
} from '@interop/was-client/edv'
import type { Puk } from './puk.js'

/**
 * Thrown when a served roster fails its client-side authentication: a
 * missing/unsupported/invalid `epochsMac`, or a descriptor whose `currentEpoch`
 * names no epoch in its own list. The server (or whoever can write to it) has
 * produced a configuration no enrolled client authenticated.
 */
export class PukRosterIntegrityError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'PukRosterIntegrityError'
  }
}

/**
 * Thrown when a served roster conflicts with the locally pinned latest-seen
 * epoch -- the epochs list no longer contains the pinned epoch, or
 * `currentEpoch` precedes it in the (append-only) list. A rollback/replay of
 * an older consistent configuration, which a valid `epochsMac` alone cannot
 * catch; refused rather than followed.
 */
export class PukRosterContinuityError extends Error {
  pinnedEpochId: string
  constructor({ pinnedEpochId }: { pinnedEpochId: string }) {
    super(
      'The PUK roster no longer carries the epoch this client has pinned -- ' +
        'a rolled-back or replayed roster.'
    )
    this.name = 'PukRosterContinuityError'
    this.pinnedEpochId = pinnedEpochId
  }
}

/**
 * Thrown when this client holds no usable wrap in the roster's current epoch
 * (no recipient entry for its key-agreement key, or the entry fails to
 * unwrap). The client cannot obtain the current PUK -- it may have been
 * rotated off the roster.
 */
export class PukRosterUnwrapError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'PukRosterUnwrapError'
  }
}

/**
 * The subset of a resolved DID document the recipient resolver consumes: the
 * `keyAgreement` relation (VM references or embedded VMs) and the
 * `verificationMethod` list references resolve against.
 */
export interface RosterRecipientDocument {
  keyAgreement?: Array<string | { id?: string; publicKeyMultibase?: string }>
  verificationMethod?: Array<{ id?: string; publicKeyMultibase?: string }>
}

/**
 * The fragment after the last `#` of a key/VM id -- for the ids this roster
 * handles (did:key KAK ids, `<did>#<multibase>` VM ids) that fragment is the
 * key's public multibase, which is what makes kid-to-VM matching key-material
 * equality rather than string equality across id formats.
 *
 * @param id {string}
 * @returns {string | undefined}
 */
function multibaseFragmentOf(id: string): string | undefined {
  const hash = id.lastIndexOf('#')
  return hash === -1 ? undefined : id.slice(hash + 1)
}

/**
 * Builds the recipient resolver for roster rotations, backed by a locally
 * verified did:webvh document -- the enforcement point for "the roster
 * delivers, never sources". Given a remaining recipient's `kid`, it answers
 * with that recipient's public key ONLY when the document carries a matching
 * `keyAgreement` verification method (matched on the public-key multibase, so
 * a did:key-form kid matches its `<did:webvh>#<multibase>` VM); otherwise it
 * resolves `null` -- the was-client skip contract -- so the entry is dropped
 * from the fresh epoch and never receives a wrap.
 *
 * @param options {object}
 * @param options.document {RosterRecipientDocument}   the locally verified
 *   did:webvh document (never a server-supplied roster field)
 * @returns {function}   a `resolveRecipientKey` for `removeRecipient`
 */
export function pukRosterRecipientResolver({
  document
}: {
  document: RosterRecipientDocument
}): (kid: string) => Promise<RecipientPublicKey | null> {
  // Materialize the document's keyAgreement VMs once: embedded VMs verbatim,
  // string references resolved against `verificationMethod`.
  const byId = new Map<string, { id?: string; publicKeyMultibase?: string }>()
  for (const method of document.verificationMethod ?? []) {
    if (typeof method?.id === 'string') {
      byId.set(method.id, method)
    }
  }
  const keyAgreementMethods: Array<{
    id?: string
    publicKeyMultibase?: string
  }> = []
  for (const entry of document.keyAgreement ?? []) {
    const method = typeof entry === 'string' ? byId.get(entry) : entry
    if (method && typeof method.publicKeyMultibase === 'string') {
      keyAgreementMethods.push(method)
    }
  }
  return async function resolveRecipientKey(
    kid: string
  ): Promise<RecipientPublicKey | null> {
    const fragment = multibaseFragmentOf(kid)
    if (!fragment) {
      return null
    }
    const match = keyAgreementMethods.find(
      method =>
        method.publicKeyMultibase === fragment ||
        (typeof method.id === 'string' &&
          multibaseFragmentOf(method.id) === fragment)
    )
    if (!match) {
      // No document verification method backs this roster entry: drop it.
      return null
    }
    return { id: kid, publicKeyMultibase: match.publicKeyMultibase! }
  }
}

/**
 * Ensures the roster exists, create-if-absent: an absent roster is
 * initialized with the account's existing PUK installed as the first epoch,
 * wrapped to this client's key-agreement key; an existing roster is returned
 * as-is (authentication is the read path's job, and provisioning must never
 * clobber an established roster). Idempotent -- losing the guarded-create
 * race to a concurrent first init converges on the winner's roster.
 *
 * @param options {object}
 * @param options.store {EncryptionDescriptorStore}   the roster's descriptor
 *   store
 * @param options.puk {Puk}   the account's per-user key
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key -- the roster recipient
 * @returns {Promise<CollectionEncryption>}   the roster descriptor
 */
export async function ensurePukRoster({
  store,
  puk,
  clientKeyAgreementKey
}: {
  store: EncryptionDescriptorStore
  puk: Puk
  clientKeyAgreementKey: IKeyAgreementKey
}): Promise<CollectionEncryption> {
  const current = await store.read()
  if (current !== null) {
    return current.descriptor
  }
  return initRecipients({
    store,
    recipients: [ownerRecipient({ keyAgreementKey: clientKeyAgreementKey })],
    epoch: { epochId: puk.id, secret: puk.secret }
  })
}

/**
 * Wraps the PUK to a client being enrolled -- the roster half of the
 * enrollment ceremony, and deliberately its FIRST write (decryption material
 * before authorization, the push order): the wrap lands before the did:webvh
 * log entries, so no enrolled client is ever authorized but blind, and a tear
 * right after this write leaves only an orphan wrap -- invisible to
 * authorization, harmless, resumed by re-running the ceremony.
 *
 * Escrow semantics ride on was-client's `addRecipient`: the new client
 * receives EVERY epoch's key, current and prior, so it decrypts
 * pre-enrollment history. The recipient key arrives over the point-to-point
 * enrollment channel and is verified there by the enrolling client (the
 * document VM it writes next comes from the same exchange) -- never sourced
 * from the roster. Idempotent: a wrap already standing in the current epoch
 * is returned as-is.
 *
 * @param options {object}
 * @param options.store {EncryptionDescriptorStore}   the roster's descriptor
 *   store
 * @param options.recipient {RecipientPublicKey}   the enrollee's public
 *   key-agreement key; `id` is the kid its own roster reads will look for
 * @param options.ownerKeyAgreementKey {IKeyAgreementKey}   the enrolling
 *   client's own (identity) key-agreement key, unwrapping each epoch for
 *   re-wrapping
 * @returns {Promise<CollectionEncryption>}   the refreshed roster descriptor
 */
export async function addPukRosterRecipient({
  store,
  recipient,
  ownerKeyAgreementKey
}: {
  store: EncryptionDescriptorStore
  recipient: RecipientPublicKey
  ownerKeyAgreementKey: IKeyAgreementKey
}): Promise<CollectionEncryption> {
  const current = await store.read()
  if (current === null) {
    throw new Error(
      'The PUK roster does not exist yet; the account must finish ' +
        'provisioning before a client can be enrolled.'
    )
  }
  const descriptor = current.descriptor
  const currentEpoch = (descriptor.epochs ?? []).find(
    epoch => epoch.id === descriptor.currentEpoch
  )
  const wrapped = currentEpoch?.recipients.some(
    entry => entry.header.kid === recipient.id
  )
  if (wrapped) {
    // A completed (or torn-after-the-wrap) earlier run: addRecipient writes
    // every epoch's wrap in one descriptor write, so the current epoch
    // standing means the escrow set is complete.
    return descriptor
  }
  return addRecipient({
    store,
    recipient,
    owner: { keyAgreementKey: ownerKeyAgreementKey }
  })
}

/**
 * What a roster read resolves to: the authenticated descriptor, the current
 * PUK (the cached one confirmed current, or a fresh one unwrapped from a
 * rotated epoch -- `rotated` says which), and the epoch id the caller must pin
 * as the new latest-seen.
 */
export interface PukRosterReadResult {
  descriptor: CollectionEncryption
  puk: Puk
  rotated: boolean
  latestEpochId: string
}

/**
 * Reads and authenticates the roster -- the direct read at login and on epoch
 * mismatch. Resolves `null` when the roster does not exist yet (an account
 * provisioned before the roster, or provisioning still in flight); otherwise:
 *
 * 1. **Continuity**: the served epochs must contain the pinned latest-seen
 *    epoch, and `currentEpoch` must not precede it in the append-only list
 *    (`PukRosterContinuityError` -- the rollback/replay refusal).
 * 2. **Possession**: `currentEpoch === puk.id` confirms the cached PUK
 *    current; otherwise the current epoch was rotated by another client and
 *    this client's wrap is unwrapped with its own key-agreement key
 *    (`PukRosterUnwrapError` when it holds none).
 * 3. **Authentication**: the descriptor's `epochsMac` is verified under the
 *    current epoch's secret (`PukRosterIntegrityError` on any mismatch -- a
 *    fabricated configuration).
 *
 * A rotated read returns the fresh PUK; its Ed25519 signing seed does not
 * travel through the roster (the roster wraps the key-agreement secret
 * alone), so the returned PUK carries none.
 *
 * A caller with no cached PUK at all -- a freshly enrolled client making its
 * first post-enrollment read -- omits `puk` and always takes the unwrap path;
 * the result's `rotated` is then true (the PUK was adopted from the roster).
 *
 * @param options {object}
 * @param options.store {EncryptionDescriptorStore}   the roster's descriptor
 *   store
 * @param [options.puk] {Puk}   this client's cached PUK, when it holds one
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key, unwrapping a rotated epoch
 * @param [options.pinnedEpochId] {string}   the locally pinned latest-seen
 *   roster epoch, when this client has seen the roster before
 * @returns {Promise<PukRosterReadResult | null>}
 */
export async function readPukRoster({
  store,
  puk,
  clientKeyAgreementKey,
  pinnedEpochId
}: {
  store: EncryptionDescriptorStore
  puk?: Puk
  clientKeyAgreementKey: IKeyAgreementKey
  pinnedEpochId?: string | null
}): Promise<PukRosterReadResult | null> {
  const current = await store.read()
  if (current === null) {
    return null
  }
  const descriptor = current.descriptor

  const epochIds = (descriptor.epochs ?? []).map(epoch => epoch.id)
  const currentIndex = descriptor.currentEpoch
    ? epochIds.indexOf(descriptor.currentEpoch)
    : -1
  if (currentIndex === -1) {
    throw new PukRosterIntegrityError(
      'The PUK roster names no current epoch in its own epoch list.'
    )
  }
  if (pinnedEpochId) {
    const pinnedIndex = epochIds.indexOf(pinnedEpochId)
    if (pinnedIndex === -1 || currentIndex < pinnedIndex) {
      throw new PukRosterContinuityError({ pinnedEpochId })
    }
  }

  // The epochsMac construction's own version/alg are the caller's to check.
  const epochsMac = descriptor.epochsMac
  if (!epochsMac || epochsMac.v !== 1 || epochsMac.alg !== 'HS256') {
    throw new PukRosterIntegrityError(
      'The PUK roster carries no supported epoch-configuration MAC.'
    )
  }

  let currentPuk: Puk
  let rotated: boolean
  if (puk && descriptor.currentEpoch === puk.id) {
    currentPuk = puk
    rotated = false
  } else {
    // Rotated by another client: unwrap this client's entry in the current
    // epoch with its own key-agreement key (rotation delivery).
    const entry = descriptor.epochs![currentIndex]!.recipients.find(
      recipient => recipient.header.kid === clientKeyAgreementKey.id
    )
    if (!entry) {
      throw new PukRosterUnwrapError(
        'The PUK roster current epoch carries no wrap for this client.'
      )
    }
    const secret = await unwrapEpochSecret({
      entry,
      keyAgreementKey: clientKeyAgreementKey
    })
    if (!secret) {
      throw new PukRosterUnwrapError(
        "This client's PUK roster entry failed to unwrap."
      )
    }
    currentPuk = { id: descriptor.currentEpoch!, secret }
    rotated = true
  }

  if (
    !(await verifyEpochsMac({ descriptor, epochSecret: currentPuk.secret }))
  ) {
    throw new PukRosterIntegrityError(
      'The PUK roster epoch configuration failed authentication.'
    )
  }

  return {
    descriptor,
    puk: currentPuk,
    rotated,
    latestEpochId: descriptor.currentEpoch!
  }
}
