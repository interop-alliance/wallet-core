/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The user key wrap set: the roster governed by `key-map/user-key.jsonl`. Its state
 * is a `CollectionEncryption` descriptor verbatim, whose current epoch IS the
 * current user key -- the epoch id is the user key's did:key and the wrapped
 * secret is the user key's raw 32-byte key, wrapped to each enrolled client's
 * key-agreement key. The roster is the delivery channel for user key rotation:
 * each client keeps the user key in its own local state under the unlock layer,
 * and the roster's epoch stamp marks a cached copy stale.
 *
 * Everything mutates through was-client's descriptor-store seam -- since the
 * roster became log-governed, the log-backed adapter
 * (`logGovernedDescriptorStore`): reads resolve to the roster log's VERIFIED
 * head state, writes append signed entries. No descriptor logic is
 * reimplemented here.
 *
 * A resource-hosted descriptor gets NONE of the server-side epoch invariants a
 * Collection Description enforces (append-only epochs, monotone
 * `currentEpoch`), so the client-side compensations are load-bearing alone
 * against a tampering host:
 *
 * - **The resource log** -- the roster is governed by a hash-linked log whose
 *   every entry is signed by an enrolled client's key, anchored in the
 *   locally verified did:webvh document, and continuity-checked against the
 *   client's chain-head pin (the `resourceLog` module). A fabricated roster
 *   fails entry-proof verification (`ResourceLogIntegrityError`); a rolled
 *   back, forked, or format-switched log fails continuity
 *   (`ResourceLogContinuityError`). This is the successor of the retired
 *   detached `epochsSig`: the entry proof covers the whole configuration, on
 *   every read instead of only the adopt path. (The `epochsMac`
 *   epoch-configuration MAC that used to sit beneath it is retired stack-wide:
 *   on a log-governed resource its coverage was a strict subset of chain
 *   verification.)
 * - **The epoch pin** -- the latest-seen roster epoch is pinned locally by the
 *   consuming app (beside the account-pointer pin); a served
 *   roster that rolls back behind the pin is refused
 *   (`UserKeyRosterContinuityError`) rather than followed, even where the
 *   chain-head pin was lost with a reinstalled client.
 * - **The roster delivers, never sources** -- the recipient-key source of
 *   record is the locally verified did:webvh document (one `keyAgreement`
 *   verification method per enrolled client). When an epoch rotates, each
 *   remaining recipient's key is resolved from that document
 *   (`userKeyRosterRecipientResolver`); a roster entry with no matching document
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
  removeRecipient,
  replaceRecipient,
  unwrapEpochSecret,
  type EncryptionDescriptorStore,
  type RecipientPublicKey
} from '@interop/was-client/edv'
import { vmFragmentOf, type ResourceLogSigner } from '@interop/vh-resource-log'
import {
  commitmentMatcher,
  MULTIKEY_COMMITMENT_VM_TYPE
} from '../webvh/didWebvh.js'
import { resolvedKeyAgreementMethods } from '../resourceLog/document.js'
import type { KeyAgreementDocument } from '../resourceLog/document.js'
import {
  clientSigningKeyMultibase,
  type ICapabilityAgent
} from '../webvh/zcap.js'
import type { UserKey } from './userKey.js'

/**
 * Thrown when a served roster fails its client-side consistency checks: a
 * descriptor whose `currentEpoch` names no epoch in its own list. The server
 * (or whoever can write to it) has produced a configuration no enrolled
 * client authenticated.
 */
export class UserKeyRosterIntegrityError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'UserKeyRosterIntegrityError'
  }
}

/**
 * Thrown when a served roster conflicts with the locally pinned latest-seen
 * epoch -- the epochs list no longer contains the pinned epoch, or
 * `currentEpoch` precedes it in the (append-only) list. A rollback/replay of
 * an older consistent configuration; refused rather than followed.
 */
export class UserKeyRosterContinuityError extends Error {
  pinnedEpochId: string
  constructor({ pinnedEpochId }: { pinnedEpochId: string }) {
    super(
      'The user key roster no longer carries the epoch this client has pinned -- ' +
        'a rolled-back or replayed roster.'
    )
    this.name = 'UserKeyRosterContinuityError'
    this.pinnedEpochId = pinnedEpochId
  }
}

/**
 * Thrown when this client holds no usable wrap in the roster's current epoch
 * (no recipient entry for its key-agreement key, or the entry fails to
 * unwrap). The client cannot obtain the current user key -- it may have been
 * rotated off the roster.
 */
export class UserKeyRosterUnwrapError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'UserKeyRosterUnwrapError'
  }
}

/**
 * The roster's log signer: signs each roster log append with this client's
 * own Ed25519 signing key, named by its public multibase -- exactly the
 * string enrolled as this client's verification method in the did:webvh
 * document, so a reader resolves the entry proof against the document rather
 * than anything the roster (or the server) supplies. Successor of the retired
 * `epochsSig` signer under the log design.
 *
 * @param options {object}
 * @param options.keyAgent {ICapabilityAgent}   this client's signing key
 *   agent (the `keyAgent` of `agentsFromSeed`)
 * @returns {ResourceLogSigner}   the signer for the log-governed store's
 *   appends
 */
export function userKeyRosterLogSigner({
  keyAgent
}: {
  keyAgent: ICapabilityAgent
}): ResourceLogSigner {
  const keyMultibase = clientSigningKeyMultibase({ keyAgent })
  const signer = keyAgent.getSigner()
  return {
    keyMultibase,
    async sign({ data }: { data: Uint8Array }): Promise<Uint8Array> {
      const signature = await signer.sign({ data })
      // Re-wrap as a plain Uint8Array: a signer may return a Node Buffer (or
      // a cross-realm view), which the kernel's strict byte check rejects.
      return new Uint8Array(
        signature.buffer,
        signature.byteOffset,
        signature.byteLength
      )
    }
  }
}

/**
 * A wallet client's roster kid: its key-agreement key's id exactly as
 * `agentsFromSeed` derives it at the client's own logins
 * (`did:key:<ed-multibase>#<x-multibase>`). One builder for the whole
 * lifecycle -- the wrap the enrollment ceremony mints, the entry a roster read
 * looks for, and the recipient a rotation retires are the same string by
 * construction rather than by three copies agreeing.
 *
 * @param options {object}
 * @param options.signingKeyMultibase {string}   the client's Ed25519 signing
 *   key
 * @param options.keyAgreementKeyMultibase {string}   its X25519 twin
 * @returns {string}
 */
export function rosterRecipientKid({
  signingKeyMultibase,
  keyAgreementKeyMultibase
}: {
  signingKeyMultibase: string
  keyAgreementKeyMultibase: string
}): string {
  return `did:key:${signingKeyMultibase}#${keyAgreementKeyMultibase}`
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
 * The match is over EVERY key-agreement method the document publishes
 * ({@link resolvedKeyAgreementMethods}), deliberately including the unmarked
 * ones. That is where this predicate parts company with
 * `markedKeyAgreementMethods`, which hard-requires a client's controller
 * marker: a recovery code's or standing unlock credential's key-agreement
 * method is published unmarked by design, so that client listings and
 * revocations never match it, and it must keep its user key wrap through every
 * rotation. Filtering by the marker here would drop every such credential from
 * each rotated epoch.
 *
 * Two branches back an entry, and a method's `type` selects exactly one. A
 * method that is not a `MultikeyCommitment` and carries the key verbatim
 * (`publicKeyMultibase`) matches on the multibase (so a did:key-form kid
 * matches its `<did:webvh>#<multibase>` VM). A `MultikeyCommitment` method's
 * hash commitment (`publicKeyCommitment` -- a low-entropy-derived standing
 * credential, whose key material the document withholds) matches when it
 * commits to the roster entry's own key: the roster carries the real key, the
 * document vouches for it, and a server-injected entry can neither meet a
 * standing commitment nor add one. The type split means a hybrid method
 * carrying both properties backs at most one recipient -- the flavor its
 * `type` declares -- never two.
 *
 * @param options {object}
 * @param options.document {KeyAgreementDocument}   the locally verified
 *   did:webvh document (never a server-supplied roster field)
 * @returns {function}   a `resolveRecipientKey` for `removeRecipient`
 */
export function userKeyRosterRecipientResolver({
  document
}: {
  document: KeyAgreementDocument
}): (kid: string) => Promise<RecipientPublicKey | null> {
  const methods = resolvedKeyAgreementMethods({ doc: document })
  const verbatimMethods = methods.filter(
    method =>
      method.type !== MULTIKEY_COMMITMENT_VM_TYPE &&
      typeof method.publicKeyMultibase === 'string'
  )
  const commitmentBacked = commitmentMatcher({
    commitments: methods
      .filter(method => method.type === MULTIKEY_COMMITMENT_VM_TYPE)
      .map(method => method.publicKeyCommitment)
      .filter((value): value is string => typeof value === 'string')
  })
  return async function resolveRecipientKey(
    kid: string
  ): Promise<RecipientPublicKey | null> {
    const fragment = vmFragmentOf(kid)
    if (!fragment) {
      return null
    }
    const match = verbatimMethods.find(
      method =>
        method.publicKeyMultibase === fragment ||
        (typeof method.id === 'string' && vmFragmentOf(method.id) === fragment)
    )
    if (match) {
      return { id: kid, publicKeyMultibase: match.publicKeyMultibase! }
    }
    // The commitment branch: the roster entry's key is document-backed iff a
    // published `MultikeyCommitment` method commits to it. The matcher
    // pre-decoded the commitments (a malformed one matches nothing).
    if (commitmentBacked(fragment)) {
      return { id: kid, publicKeyMultibase: fragment }
    }
    // No document verification method backs this roster entry: drop it.
    return null
  }
}

/**
 * Ensures the roster exists, create-if-absent: an absent roster is initialized
 * with the account's existing user key installed as the first epoch, wrapped to
 * this client's key-agreement key; an existing roster is returned as-is
 * (authentication is the read path's job, and provisioning must never clobber
 * an established roster). Idempotent -- losing the guarded-create race to a
 * concurrent first init converges on the winner's roster.
 *
 * @param options {object}
 * @param options.store {EncryptionDescriptorStore}   the roster's descriptor
 *   store
 * @param options.userKey {UserKey}   the account's user key
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key -- the roster recipient
 * @returns {Promise<CollectionEncryption>}   the roster descriptor
 */
export async function ensureUserKeyRoster({
  store,
  userKey,
  clientKeyAgreementKey
}: {
  store: EncryptionDescriptorStore
  userKey: UserKey
  clientKeyAgreementKey: IKeyAgreementKey
}): Promise<CollectionEncryption> {
  const current = await store.read()
  if (current !== null) {
    return current.descriptor
  }
  return initRecipients({
    store,
    recipients: [ownerRecipient({ keyAgreementKey: clientKeyAgreementKey })],
    epoch: { epochId: userKey.id, secret: userKey.secret }
  })
}

/**
 * Wraps the user key to a client being enrolled -- the roster half of the
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
export async function addUserKeyRosterRecipient({
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
      'The user key roster does not exist yet; the account must finish ' +
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
 * Rotates the user key roster off one recipient -- the roster half of revoking
 * an enrolled wallet client or a recovery code. A thin, deliberate composition
 * of was-client's `removeRecipient` with the two roster-specific choices
 * spelled once: the remaining recipients are resolved from the locally verified
 * did:webvh document ("the roster delivers, never sources" -- an entry with no
 * matching `keyAgreement` verification method is dropped and never receives a
 * wrap), and the pull axis is a no-op, because for a roster recipient the pull
 * axis IS the document edit the caller performed first -- under the
 * current-key-set rule the removed party's server-side access died the moment
 * its verification method left the document.
 *
 * @param options {object}
 * @param options.store {EncryptionDescriptorStore}   the roster's descriptor
 *   store
 * @param options.document {KeyAgreementDocument}   the locally verified
 *   did:webvh document, AFTER the removal edit
 * @param options.retireRecipientId {string}   the removed recipient's roster
 *   kid
 * @returns {Promise<CollectionEncryption>}   the rotated roster descriptor
 */
export async function rotateUserKeyRoster({
  store,
  document,
  retireRecipientId
}: {
  store: EncryptionDescriptorStore
  document: KeyAgreementDocument
  retireRecipientId: string
}): Promise<CollectionEncryption> {
  return removeRecipient({
    store,
    recipientId: retireRecipientId,
    resolveRecipientKey: userKeyRosterRecipientResolver({ document }),
    pull: async () => {}
  })
}

/**
 * Rotates the roster off one or more recipients while escrowing incoming ones,
 * in ONE descriptor write -- the transient-recovery continuation's mandatory
 * rotation. The shape is forced by the ceremony-tail license: on a client-less
 * account the only roster signer is the ladder VM, whose append is one-shot at
 * the continuation's inventory-changing document entry, so the retiring wrap
 * (the spent code's), the incoming recipients (the fresh credential's standing
 * key and the replacement code's), and the fresh-epoch mint must all land in a
 * single append. Composition of was-client's `replaceRecipient` with the same
 * two roster choices {@link rotateUserKeyRoster} spells: recipients resolved
 * from the locally verified document, and a no-op pull axis (the document edit
 * the caller performed first IS the pull axis).
 *
 * The incoming recipients' keys are supplied by the caller (it derived them);
 * the document must already back them -- the continuation's own entry
 * published their inventory -- or the next rotation would drop them.
 *
 * @param options {object}
 * @param options.store {EncryptionDescriptorStore}   the roster's descriptor
 *   store
 * @param options.document {KeyAgreementDocument}   the locally verified
 *   did:webvh document, AFTER the continuation's entry
 * @param options.retireRecipientIds {string[]}   the retiring roster kids: the
 *   spent code's, and every other pre-recovery credential's, since the
 *   continuation's entry retires them all in one go
 *   ({@link rosterRecipientsToRetire} names them). The document-backed
 *   resolver is the backstop rather than the mechanism -- a recipient the
 *   post-entry document no longer keys is dropped from the fresh epoch
 *   whether or not it is named here
 * @param options.recipients {RecipientPublicKey[]}   the incoming readers'
 *   public key-agreement keys; each `id` is the kid its own roster reads will
 *   look for
 * @param options.ownerKeyAgreementKey {IKeyAgreementKey}   a key-agreement key
 *   holding a wrap in every epoch (the spent code's qualifies), unwrapping
 *   each epoch for the escrow
 * @returns {Promise<CollectionEncryption>}   the rotated roster descriptor
 */
export async function replaceUserKeyRosterRecipients({
  store,
  document,
  retireRecipientIds,
  recipients,
  ownerKeyAgreementKey
}: {
  store: EncryptionDescriptorStore
  document: KeyAgreementDocument
  retireRecipientIds: string[]
  recipients: RecipientPublicKey[]
  ownerKeyAgreementKey: IKeyAgreementKey
}): Promise<CollectionEncryption> {
  return replaceRecipient({
    store,
    retire: retireRecipientIds,
    recipient: recipients,
    owner: { keyAgreementKey: ownerKeyAgreementKey },
    resolveRecipientKey: userKeyRosterRecipientResolver({ document }),
    pull: async () => {}
  })
}

/**
 * The current epoch's recipient kids minus the ones to keep -- what a
 * recovery continuation hands `replaceUserKeyRosterRecipients` as
 * `retireRecipientIds` once its entry has retired several credentials at
 * once. Pure and synchronous: it reads the descriptor the caller already
 * holds and decides nothing about who deserves a wrap.
 *
 * The keep set is the caller's: the fresh credential's kid, the replacement
 * code's, and every surviving enrolled client's
 * ({@link rosterRecipientKid} over the post-entry document). Naming a
 * retiring kid is belt and braces -- the document-backed resolver
 * ({@link userKeyRosterRecipientResolver}) already drops any recipient the
 * post-entry document no longer keys -- but it keeps the retirement explicit
 * in the one append the ceremony-tail license admits.
 *
 * @param options {object}
 * @param options.descriptor {CollectionEncryption}   the roster descriptor
 *   the rotation is about to replace
 * @param options.keepRecipientIds {string[]}   the kids that stay
 * @returns {string[]}   the current epoch's other kids, in epoch order
 */
export function rosterRecipientsToRetire({
  descriptor,
  keepRecipientIds
}: {
  descriptor: CollectionEncryption
  keepRecipientIds: string[]
}): string[] {
  const currentEpoch = (descriptor.epochs ?? []).find(
    epoch => epoch.id === descriptor.currentEpoch
  )
  if (!currentEpoch) {
    throw new UserKeyRosterIntegrityError(
      'The user key roster names no current epoch in its own epoch list.'
    )
  }
  const keep = new Set(keepRecipientIds)
  return [
    ...new Set(
      currentEpoch.recipients
        .map(entry => entry.header.kid)
        .filter(kid => !keep.has(kid))
    )
  ]
}

/**
 * Converges the roster onto the account document: the standing detector for a
 * revocation cascade torn between its two halves. The cascade edits the
 * document first and rotates the roster second, so a client that crashes in
 * between leaves a roster that keeps wrapping the CURRENT user key to a
 * recipient the document no longer keys -- durable, silent, and permanent,
 * since the revoked client's document edit will never be re-run.
 *
 * The detection is pure durable state: a current-epoch recipient the
 * document-backed resolver cannot answer for is exactly a recipient the
 * document no longer keys, so a healthy account reads the descriptor and
 * writes nothing. When any such recipient is found the roster is rotated away
 * from ALL of them at once -- a single {@link rotateUserKeyRoster} suffices,
 * because the resolver drops every unbacked entry from the fresh epoch, not
 * just the one named as retiring.
 *
 * Rotating onto nobody is refused: a current epoch in which NO recipient is
 * backed by the document is a mismatched pair (a stale document, the wrong
 * account), not a cascade to finish, and completing it would lock every
 * client out of the account.
 *
 * The fresh user key itself is not returned: the caller adopts it the
 * ordinary way, by re-reading the roster ({@link readUserKeyRoster}) once
 * `rotated` says there is something to adopt, and then runs the collection
 * fan-out.
 *
 * @param options {object}
 * @param options.store {EncryptionDescriptorStore}   the roster's descriptor
 *   store
 * @param options.document {KeyAgreementDocument}   the locally verified
 *   did:webvh document -- the recipient source of record
 * @param [options.descriptor] {CollectionEncryption}   a descriptor the caller
 *   has just read (a login-time roster read), to save a re-read; omitted, the
 *   roster is read fresh
 * @returns {Promise<object>}   whether the roster rotated on this call, the
 *   stale recipient kids found, and the roster descriptor as it now stands
 *   (`null` when the account has no roster yet)
 */
export async function convergeUserKeyRosterToDocument({
  store,
  document,
  descriptor
}: {
  store: EncryptionDescriptorStore
  document: KeyAgreementDocument
  descriptor?: CollectionEncryption
}): Promise<{
  rotated: boolean
  staleRecipientIds: string[]
  descriptor: CollectionEncryption | null
}> {
  let roster = descriptor
  if (!roster) {
    const read = await store.read()
    if (read === null) {
      return { rotated: false, staleRecipientIds: [], descriptor: null }
    }
    roster = read.descriptor
  }
  const currentEpochId = roster.currentEpoch
  const currentEpoch = (roster.epochs ?? []).find(
    epoch => epoch.id === currentEpochId
  )
  if (!currentEpoch) {
    throw new UserKeyRosterIntegrityError(
      'The user key roster names no current epoch in its own epoch list.'
    )
  }

  const resolveRecipientKey = userKeyRosterRecipientResolver({ document })
  const staleRecipientIds: string[] = []
  let backed = 0
  for (const entry of currentEpoch.recipients) {
    const kid = entry.header.kid
    if ((await resolveRecipientKey(kid)) === null) {
      staleRecipientIds.push(kid)
    } else {
      backed++
    }
  }
  if (staleRecipientIds.length === 0) {
    return { rotated: false, staleRecipientIds, descriptor: roster }
  }
  if (backed === 0) {
    throw new UserKeyRosterIntegrityError(
      'No user key roster recipient is keyed by the account document; refusing ' +
        'to rotate the roster onto no one.'
    )
  }

  // One rotation retires them all: the fresh epoch is wrapped only to the
  // recipients the resolver answers for.
  const rotated = await rotateUserKeyRoster({
    store,
    document,
    retireRecipientId: staleRecipientIds[0]!
  })
  return { rotated: true, staleRecipientIds, descriptor: rotated }
}

/**
 * What a roster read resolves to: the authenticated descriptor, the current
 * user key (the cached one confirmed current, or a fresh one unwrapped from a
 * rotated epoch -- `rotated` says which), and the epoch id the caller must pin
 * as the new latest-seen.
 */
export interface UserKeyRosterReadResult {
  descriptor: CollectionEncryption
  userKey: UserKey
  rotated: boolean
  latestEpochId: string
}

/**
 * Reads and authenticates the roster -- the direct read at login and on epoch
 * mismatch. Resolves `null` when the roster does not exist yet (an account
 * provisioned before the roster, or provisioning still in flight); otherwise:
 *
 * 1. **Provenance** is the store's: a log-governed store resolves the read
 *    from the roster log's verified head -- entry proofs checked against the
 *    locally verified did:webvh document, chain-head pin enforced -- so
 *    every epoch this read can deliver was signed onto the log by an
 *    enrolled client. (The detached `epochsSig` this step used to verify on
 *    the adopt path is retired; the entry proof covers every read.)
 * 2. **Continuity**: the served epochs must contain the pinned latest-seen
 *    epoch, and `currentEpoch` must not precede it in the append-only list
 *    (`UserKeyRosterContinuityError` -- the rollback/replay refusal).
 * 3. **Possession**: `currentEpoch === userKey.id` confirms the cached user key
 *    current; otherwise the current epoch was rotated by another client and
 *    this client's wrap is unwrapped with its own key-agreement key
 *    (`UserKeyRosterUnwrapError` when it holds none).
 *
 * A rotated read returns the fresh user key; its Ed25519 signing seed does not
 * travel through the roster (the roster wraps the key-agreement secret
 * alone), so the returned user key carries none.
 *
 * A caller with no cached user key at all -- a freshly enrolled client making
 * its first post-enrollment read -- omits `userKey` and always takes the unwrap
 * path; the result's `rotated` is then true (the user key was adopted from the
 * roster).
 *
 * A caller that just performed a verified roster operation on the same store
 * -- a rotation, or a read moments ago -- may thread that operation's
 * descriptor in as `descriptor`, skipping this read's own fetch: provenance
 * (step 1) is then the earlier operation's, while continuity and possession
 * still run here. That is a within-one-operation reuse, not a cache -- a
 * genuinely distinct acquisition reads the store and re-verifies as always.
 *
 * @param options {object}
 * @param options.store {EncryptionDescriptorStore}   the roster's descriptor
 *   store
 * @param [options.descriptor] {CollectionEncryption}   a descriptor a verified
 *   operation on the same store just resolved (the return of
 *   {@link rotateUserKeyRoster}); supplied, the store is not read
 * @param [options.userKey] {UserKey}   this client's cached user key, when it holds one
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key, unwrapping a rotated epoch
 * @param [options.pinnedEpochId] {string}   the locally pinned latest-seen
 *   roster epoch, when this client has seen the roster before
 * @returns {Promise<UserKeyRosterReadResult | null>}   `null` only on an
 *   absent roster, which a supplied `descriptor` rules out
 */
export async function readUserKeyRoster(options: {
  store: EncryptionDescriptorStore
  descriptor: CollectionEncryption
  userKey?: UserKey
  clientKeyAgreementKey: IKeyAgreementKey
  pinnedEpochId?: string | null
}): Promise<UserKeyRosterReadResult>
export async function readUserKeyRoster(options: {
  store: EncryptionDescriptorStore
  descriptor?: CollectionEncryption
  userKey?: UserKey
  clientKeyAgreementKey: IKeyAgreementKey
  pinnedEpochId?: string | null
}): Promise<UserKeyRosterReadResult | null>
export async function readUserKeyRoster({
  store,
  descriptor: knownDescriptor,
  userKey,
  clientKeyAgreementKey,
  pinnedEpochId
}: {
  store: EncryptionDescriptorStore
  descriptor?: CollectionEncryption
  userKey?: UserKey
  clientKeyAgreementKey: IKeyAgreementKey
  pinnedEpochId?: string | null
}): Promise<UserKeyRosterReadResult | null> {
  let descriptor = knownDescriptor
  if (!descriptor) {
    const current = await store.read()
    if (current === null) {
      return null
    }
    descriptor = current.descriptor
  }

  const epochIds = (descriptor.epochs ?? []).map(epoch => epoch.id)
  const currentIndex = descriptor.currentEpoch
    ? epochIds.indexOf(descriptor.currentEpoch)
    : -1
  if (currentIndex === -1) {
    throw new UserKeyRosterIntegrityError(
      'The user key roster names no current epoch in its own epoch list.'
    )
  }
  if (pinnedEpochId) {
    const pinnedIndex = epochIds.indexOf(pinnedEpochId)
    if (pinnedIndex === -1 || currentIndex < pinnedIndex) {
      throw new UserKeyRosterContinuityError({ pinnedEpochId })
    }
  }

  let currentUserKey: UserKey
  let rotated: boolean
  if (userKey && descriptor.currentEpoch === userKey.id) {
    currentUserKey = userKey
    rotated = false
  } else {
    // Rotated by another client (or this client's first read): the epoch
    // being adopted traces to a root of trust the server cannot mint through
    // the store itself -- a log-governed read only ever resolves to a head
    // whose entry proofs the locally verified account document backs.
    // Unwrap this client's entry in the current epoch with its own
    // key-agreement key (rotation delivery).
    const entry = descriptor.epochs![currentIndex]!.recipients.find(
      recipient => recipient.header.kid === clientKeyAgreementKey.id
    )
    if (!entry) {
      throw new UserKeyRosterUnwrapError(
        'The user key roster current epoch carries no wrap for this client.'
      )
    }
    const secret = await unwrapEpochSecret({
      entry,
      keyAgreementKey: clientKeyAgreementKey
    })
    if (!secret) {
      throw new UserKeyRosterUnwrapError(
        "This client's user key roster entry failed to unwrap."
      )
    }
    currentUserKey = { id: descriptor.currentEpoch!, secret }
    rotated = true
  }

  return {
    descriptor,
    userKey: currentUserKey,
    rotated,
    latestEpochId: descriptor.currentEpoch!
  }
}
