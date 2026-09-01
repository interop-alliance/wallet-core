/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The client-annex generation ensure a TRANSIENT visit runs -- a session
 * holding nothing but a standing unlock credential (its ladder seed, its
 * `delegatedClients` sibling delegation, and the standing-client identity
 * derived from the typed secret). Six durable states cut such a visit off
 * from the annex, or from the account log the annex is pointed at: the
 * account document carries no `#DelegatedClients` pointer; the pointed
 * auxiliary Space is gone from the server; the pointed
 * generation's log is gone (GC'd, or never minted); the embedded generation
 * delegation is expired, inside its renewal window, or signed by a key the
 * document no longer lists; the record carries no sibling delegation, or its
 * sibling targets another Space; the record's bridge delegation is expired,
 * inside its renewal window, or signed by a key the document no longer
 * lists. On a ladder-anchored account -- the ladder VM a document
 * verification method, the ladder's rungs the log's update keys -- the visit
 * itself can mend all five, and this module is the orchestrator: a
 * converging ensure that detects each state from durable state, mends it
 * with the existing annex primitives, and reports what ran.
 *
 * The ordering rules are the established ones, composed rather than
 * re-decided:
 *
 * - RENEW PRECEDES MINT: a live, verifiable pointed generation is renewed in
 *   place (`ensureGenerationDelegationCurrent`, the ladder-signed minter);
 *   only a dead generation -- or one whose log does not commit this
 *   credential's annex rung (`ClientAnnexRungUncommittedError`, the same
 *   escape the GC swap's no-committed-survivor arm takes) -- gets a fresh
 *   mint.
 * - The PRE-FLIGHT RUNG ATTRIBUTION precedes any mint that will need a
 *   pointer entry: when no current account-log update key is a rung of this
 *   ladder, nothing is minted at all -- a generation the pointer entry could
 *   not then name would only widen the orphan window.
 * - A fresh generation in an EXISTING Space mirrors the GC swap's stage
 *   order minus its revoke stage (mint, install the delegation, re-point --
 *   no transient reach could invoke the old delegation's revocation; the
 *   pointer move retires it on a conforming server and it otherwise rots on
 *   its TTL); a fresh SPACE is created under the ladder VM's bare did:key,
 *   the one identity a create may name, and its controller is flipped to the
 *   account DID in the next request, before anything publishes into it. The
 *   stranding window is therefore one request wide: a run torn inside it
 *   leaves a did:key-controlled Space no server orphan sweep can reap, and a
 *   run torn past the flip leaves an account-controlled one that a sweep
 *   can. The generation then mints in that Space exactly as it does in an
 *   existing one, under the ladder-signed sibling delegation, which is why
 *   the flip must precede the mint.
 * - A POINTED SPACE THAT IS GONE is decided before any write, and by TWO
 *   reads rather than one, since a storage server masks an unauthorized read
 *   as the same 404 an absent Space answers: a ladder-signed GET-only child
 *   of the Space's root, then a root invocation as the ladder VM's bare
 *   did:key (the controller a torn establishment leaves behind). Only when
 *   both answer a real 404 is the Space gone. Status alone decides, so a 2xx
 *   is present whatever its body says and every other answer throws. The
 *   first probe presupposes a server admitting the ladder delegation
 *   clause's single-verb predicate; against an older one both reads are
 *   refused alike and a live Space reads as gone.
 * - The BRIDGE RENEWAL PRECEDES EVERY ARM: the record's bridge delegation is
 *   the credential's one write path into the account log, so a stale one is
 *   replaced before any arm runs and the caller's account-log store is built
 *   over the usable bridge (the `idStoreFor` factory). A pointer entry in
 *   either minting arm would otherwise ride a delegation the server refuses.
 * - Pointer entries go through the caller's account-log store with
 *   `logOnly: true`: a bridge-delegated writer has no `did.json` projection
 *   rights, and the log is the source of truth.
 *
 * Both renewable record delegations -- the bridge, and the sibling (minted
 * when the record carries none, when it targets another Space, or when it is
 * stale) -- are handed back through the REQUIRED `onRebindRecord` seam after
 * the generation and pointer are durable. The seam always receives BOTH
 * usable delegations, whichever of them was freshly minted, so the caller
 * re-seals the unlock record from one pair; a run torn before that re-seal
 * re-derives everything from the ladder seed at the next visit. A re-seal
 * that fails is fatal when the sibling was fresh and is reported on the
 * outcome's `bridgeResealError` when only the bridge was, since the fresh
 * bridge already served this visit and the next visit re-mints it.
 */
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { WasClient } from '@interop/was-client'
import { spacePath } from '@interop/was-client/paths'
import type { ResourceLogPinStore } from '@interop/vh-resource-log'
import {
  currentLogParameters,
  readPublishedLog,
  readPublishedLogOrThrow,
  WebvhLogConflictError,
  withLogConflictRetry
} from '../webvh/didWebvh.js'
import type {
  ClientWebvhUpdateKeys,
  PublishedWebvhLog,
  WebvhIdStore
} from '../webvh/didWebvh.js'
import { ladderVmIds } from '../resourceLog/document.js'
import type { PublishedKeyDocument } from '../webvh/listClients.js'
import { standingZcapStale } from '../webvh/standingZcap.js'
import { delegateLogWrite } from '../recovery/recoveryDelegation.js'
import { accountLogPinId } from '../webvh/verifyLog.js'
import { mintSpaceId } from '../genesis/accountGenesis.js'
import type { ICapabilityAgent } from '../webvh/zcap.js'
import {
  attributeLadderRung,
  ladderRung,
  ladderVmKeyMultibase
} from './ladder.js'
import { revealLadderRungWebvh } from './ladderAnchored.js'
import { ladderVmAgent, ladderVmZcapClient } from './zcap.js'
import { mintSpaceRootVerbCapability } from './spaceCapability.js'
import {
  clientAnnexDidParts,
  clientAnnexLogPinId,
  clientAnnexLogStore,
  delegatedClientsDelegationSpaceId,
  delegatedClientsPointer,
  ensureClientAnnexSpace,
  ensureGenerationDelegationCurrent,
  mintCredentialClientAnnexGeneration,
  mintDelegatedClientsDelegation,
  mintGenerationDelegation,
  setDelegatedClientsPointerOnce
} from './log.js'

/**
 * The HTTP status a raw signed request's rejection carries, when it carries
 * one. `WasClient.request` applies no error mapping, so the status is all a
 * caller has to dispatch on, and different transports hang it in different
 * places (`status`, or `response.status`).
 *
 * @param err {unknown}
 * @returns {number | undefined}
 */
function rawRequestStatus(err: unknown): number | undefined {
  const raw = err as { status?: unknown; response?: { status?: unknown } }
  const status = raw?.status ?? raw?.response?.status
  return typeof status === 'number' ? status : undefined
}

/**
 * Why the visit cannot mend the annex.
 *
 * `'ladder-vm-not-anchored'`: this credential's ladder VM is not a
 * verification method of the account document, so nothing ladder-signed can
 * verify. A standing credential's VM stands for as long as the credential
 * does -- enrollment leaves it alone -- so this is the backstop for a
 * document that never carried it: a credential whose establishment was torn
 * before its document entry, or a visit by a credential to an account
 * another credential's ladder anchors (a passkey visiting an account the
 * passphrase established).
 *
 * `'update-key-not-attributable'`: a pointer entry is needed, but the account
 * log carries no rung of this ladder at all -- no revealed key and no
 * committed hash -- or the attribution is ambiguous, so the entry could not
 * be signed. A merely committed rung is not this state: the pointer move
 * reveals it first.
 */
export type ClientAnnexGenerationUnavailableReason =
  'ladder-vm-not-anchored' | 'update-key-not-attributable'

/**
 * The typed refusal of {@link ensureCredentialClientAnnexGeneration}: the
 * account is not in a shape this visit can mend, and nothing was written.
 * Matched on `name` -- error classes do not survive crossing package copies.
 */
export class ClientAnnexGenerationUnavailableError extends Error {
  readonly reason: ClientAnnexGenerationUnavailableReason

  constructor({
    reason,
    message
  }: {
    reason: ClientAnnexGenerationUnavailableReason
    message: string
  }) {
    super(message)
    this.name = 'ClientAnnexGenerationUnavailableError'
    this.reason = reason
  }
}

/**
 * The ladder-signed generation-delegation minter: the
 * `mintGenerationDelegation` closure shape `ensureGenerationDelegationCurrent`
 * takes, signing with the credential's ladder VM (`ladderVmZcapClient`) --
 * the renewal must not depend on the very delegation it replaces, and on a
 * ladder-anchored account the ladder VM is the one licensed delegator.
 * Exported on its own: the transient App Connect approval's blocking renewal
 * stage consumes the same closure.
 *
 * @param options {object}
 * @param options.accountDid {string}   the account did:webvh
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed, from
 *   its unlock record
 * @param options.wasServerUrl {string}   the ACCOUNT Space's storage server
 * @param options.spaceId {string}   the ACCOUNT Space's id (the delegation's
 *   target subtree)
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {Function}   `({ clientAnnexDid }) => Promise<IZcap>`
 */
export function ladderSignedGenerationDelegationMinter({
  accountDid,
  ladderSeed,
  wasServerUrl,
  spaceId,
  now
}: {
  accountDid: string
  ladderSeed: Uint8Array
  wasServerUrl: string
  spaceId: string
  now?: number
}): (options: { clientAnnexDid: string }) => Promise<IZcap> {
  return async ({ clientAnnexDid }: { clientAnnexDid: string }) => {
    const zcapClient = await ladderVmZcapClient({ accountDid, ladderSeed })
    return mintGenerationDelegation({
      zcapClient,
      wasServerUrl,
      spaceId,
      clientAnnexDid,
      ...(now !== undefined ? { now } : {})
    })
  }
}

/**
 * What one ensure pass did. Honest skips never throw: a `false` member means
 * the durable state was already current, not that a stage failed. A
 * superseded generation's own delegation is never revoked here (no transient
 * reach could invoke the revocation); the pointer move retires it on a
 * conforming server, and it otherwise rots on its TTL.
 */
export interface ClientAnnexGenerationEnsureOutcome {
  clientAnnexDid: string
  generationDelegation: IZcap
  /**
   * The usable bridge delegation -- the record's own, or the fresh one
   * `onRebindRecord` was handed.
   */
  delegation: IZcap
  /**
   * The usable sibling delegation -- the record's own, or the fresh one
   * `onRebindRecord` was handed.
   */
  delegatedClients: IZcap
  generationMinted: boolean
  spaceMinted: boolean
  /**
   * Which arm minted the Space: set when the account document's pointer
   * named an auxiliary Space the server no longer has, so a fresh one was
   * minted and pointed at in its place. `spaceMinted` is set with it.
   */
  pointedSpaceMissing: boolean
  delegationRenewed: boolean
  siblingReminted: boolean
  bridgeReminted: boolean
  /**
   * Set when the re-seal of a renewed bridge failed and nothing else needed
   * the re-seal; the fresh bridge still served this visit, and the next
   * visit re-mints.
   */
  bridgeResealError?: unknown
}

/**
 * Ensures a transient visit can reach a live client-annex generation with a
 * current generation delegation and a usable sibling delegation, mending
 * from durable state alone (see the module doc for the states and the stage
 * orders). A healthy account is a pure no-op report.
 *
 * Known residue: the pre-flight rung attribution runs against the SUPPLIED
 * account view, while the pointer entry's own publish re-reads the log. The
 * no-orphan guarantee therefore holds against that view; a concurrent
 * ceremony advancing the rung between the two makes the pointer entry fail
 * loudly AFTER the mint, leaving an inert unpointed generation this ensure
 * does not reuse -- the next run converges on a fresh generation, and the
 * orphan is the standing collect fan-out's to pick up.
 *
 * @param options {object}
 * @param options.wasServerUrl {string}   the account pointer's host
 * @param options.spaceId {string}   the ACCOUNT Space's id
 * @param options.account {object}   the VERIFIED account log view
 *   (`{ did, doc, log }` -- the caller's `verifyAccountLog` read; never
 *   re-fetched here)
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed, from
 *   its unlock record
 * @param options.standingClient {object}   the standing-client identity
 *   derived from the typed secret: `did` (the sibling delegation's
 *   controller) and `zcapClient` (its signer, which invokes annex requests
 *   under the sibling capability)
 * @param options.bootstrapWasFor {Function}   `({ keyAgent }) => WasClient`
 *   -- the storage client for the fresh-Space arm, signing as the ladder
 *   VM's bare did:key (the caller wires the transport; the agent is derived
 *   here from the ladder seed)
 * @param options.delegation {IZcap}   the record's bridge delegation (PUT on
 *   the account's `did.jsonl`), renewed here when it is stale
 * @param options.idStoreFor {Function}
 *   `({ delegation }) => WebvhIdStore` -- builds the ACCOUNT log's store over
 *   the usable bridge (a bridge-delegated store suffices: pointer entries
 *   publish with `logOnly: true`). Called once, after the bridge renewal, so
 *   a pointer entry never rides a lapsed delegation
 * @param options.onRebindRecord {Function}
 *   `({ delegation, delegatedClients }) => Promise<void>` -- REQUIRED:
 *   re-seals the unlock record with the usable bridge and sibling
 *   delegations; called whenever either was freshly minted, after the
 *   generation and pointer are durable
 * @param [options.delegatedClients] {IZcap}   the record's sibling
 *   delegation, when the record carries one
 * @param [options.pinStore] {ResourceLogPinStore}   chain-head pins (a
 *   transient session passes an in-memory store); slot keys are derived here
 *   per log
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {Promise<ClientAnnexGenerationEnsureOutcome>}
 */
export function ensureCredentialClientAnnexGeneration(options: {
  wasServerUrl: string
  spaceId: string
  account: Pick<PublishedWebvhLog, 'did' | 'doc' | 'log'>
  ladderSeed: Uint8Array
  standingClient: { did: string; zcapClient: ZcapClient }
  bootstrapWasFor: (options: { keyAgent: ICapabilityAgent }) => WasClient
  delegation: IZcap
  idStoreFor: (options: { delegation: IZcap }) => WebvhIdStore
  onRebindRecord: (options: {
    delegation: IZcap
    delegatedClients: IZcap
  }) => Promise<void>
  delegatedClients?: IZcap
  pinStore?: ResourceLogPinStore
  now?: number
}): Promise<ClientAnnexGenerationEnsureOutcome> {
  // Refused synchronously, before any read: a fresh sibling nothing re-seals
  // into the record would strand the very credential this ensure serves.
  if (typeof options.onRebindRecord !== 'function') {
    throw new TypeError(
      'ensureCredentialClientAnnexGeneration requires onRebindRecord: a ' +
        'fresh bridge or sibling delegation must be re-sealed into the ' +
        'unlock record.'
    )
  }
  return ensureCredentialClientAnnexGenerationChecked(options)
}

/**
 * The checked body of {@link ensureCredentialClientAnnexGeneration}.
 *
 * @param options {object}   see {@link ensureCredentialClientAnnexGeneration}
 * @returns {Promise<ClientAnnexGenerationEnsureOutcome>}
 */
async function ensureCredentialClientAnnexGenerationChecked({
  wasServerUrl,
  spaceId,
  account,
  ladderSeed,
  standingClient,
  bootstrapWasFor,
  delegation,
  idStoreFor,
  onRebindRecord,
  delegatedClients,
  pinStore,
  now
}: {
  wasServerUrl: string
  spaceId: string
  account: Pick<PublishedWebvhLog, 'did' | 'doc' | 'log'>
  ladderSeed: Uint8Array
  standingClient: { did: string; zcapClient: ZcapClient }
  bootstrapWasFor: (options: { keyAgent: ICapabilityAgent }) => WasClient
  delegation: IZcap
  idStoreFor: (options: { delegation: IZcap }) => WebvhIdStore
  onRebindRecord: (options: {
    delegation: IZcap
    delegatedClients: IZcap
  }) => Promise<void>
  delegatedClients?: IZcap
  pinStore?: ResourceLogPinStore
  now?: number
}): Promise<ClientAnnexGenerationEnsureOutcome> {
  // The gate: everything below signs as the ladder (the delegations as the
  // ladder VM, the annex entries as its per-generation rung), so unless THIS
  // ladder's VM stands in the document under the ladder-VM relation
  // asymmetry (`capabilityDelegation` without `capabilityInvocation` -- the
  // authority the mends actually exercise, which mere key presence says
  // nothing about), every mend is unverifiable. The honest refusal, before
  // anything is written. A standing credential's VM stands whether or not the
  // account has enrolled clients, so this fires only for a document that
  // never carried it -- a torn establishment, or another credential's
  // account.
  const vmKey = await ladderVmKeyMultibase({ ladderSeed })
  if (!ladderVmIds({ doc: account.doc }).includes(`${account.did}#${vmKey}`)) {
    throw new ClientAnnexGenerationUnavailableError({
      reason: 'ladder-vm-not-anchored',
      message:
        "This credential's ladder VM is not a verification method of the " +
        'account document, so a transient visit cannot mend the client annex.'
    })
  }

  // The annex Space, in the settled resolution order (the one statement of
  // the rule, shared with the establishment's stage-3 primitive).
  const { pointer, siblingSpaceId, annexSpaceId } = resolveClientAnnexSpaceId({
    doc: account.doc,
    ...(delegatedClients !== undefined ? { delegatedClients } : {})
  })

  const ladderClient = await ladderVmZcapClient({
    accountDid: account.did,
    ladderSeed
  })
  const mintDelegation = ladderSignedGenerationDelegationMinter({
    accountDid: account.did,
    ladderSeed,
    wasServerUrl,
    spaceId,
    ...(now !== undefined ? { now } : {})
  })

  // THE BRIDGE RENEWAL, before any arm. The bridge is the credential's one
  // write path into the account log, and both minting arms end in a pointer
  // entry that rides it. A stale one is replaced with a ladder-VM-signed
  // delegation (the gate above proved the VM a document verification
  // method), and the caller's account-log store is built over whichever
  // bridge is usable.
  let bridgeReminted = false
  let usableBridge = delegation
  if (
    standingZcapStale({
      zcap: delegation,
      doc: account.doc as PublishedKeyDocument,
      ...(now !== undefined ? { now } : {})
    })
  ) {
    usableBridge = await delegateLogWrite({
      zcapClient: ladderClient,
      pointer: { did: account.did, spaceId, host: wasServerUrl },
      recoveryClientDid: standingClient.did,
      ...(now !== undefined ? { now } : {})
    })
    bridgeReminted = true
  }
  const idStore = idStoreFor({ delegation: usableBridge })

  /**
   * The record re-seal, through the required `onRebindRecord` seam: the one
   * call site for every arm, run once the generation and pointer are
   * durable. It fires whenever either recorded delegation was freshly
   * minted, and grades a failure by which one that was. A fresh sibling
   * nothing re-seals would strand the credential, so that throw propagates.
   * A bridge-only renewal needs nothing from the re-seal: the fresh bridge
   * is minted offline and already served this visit, so a lost re-seal
   * leaves no wrong state behind and the next visit re-mints. It is reported
   * on the outcome instead.
   *
   * @param options {object}
   * @param options.delegatedClients {IZcap}   the usable sibling delegation
   * @param options.siblingReminted {boolean}   whether that sibling is fresh
   * @returns {Promise<object>}   the outcome's `bridgeResealError` member,
   *   present only when a bridge-only re-seal failed
   */
  async function resealRecord({
    delegatedClients: usableSibling,
    siblingReminted
  }: {
    delegatedClients: IZcap
    siblingReminted: boolean
  }): Promise<{ bridgeResealError?: unknown }> {
    if (!siblingReminted && !bridgeReminted) {
      return {}
    }
    try {
      await onRebindRecord({
        delegation: usableBridge,
        delegatedClients: usableSibling
      })
    } catch (err) {
      if (siblingReminted) {
        throw err
      }
      return { bridgeResealError: err }
    }
    return {}
  }

  /**
   * The fresh-Space stage, controller-first past the create. The create
   * itself must name the ladder VM's bare did:key: a storage server
   * authorizes a Space create against the controller the request body names,
   * and a root invocation must be signed by that very DID, so a create
   * naming the account did:webvh is refused. The controller is flipped to
   * the account DID in the very next request, before anything publishes into
   * the Space.
   *
   * So the stranding window is one request wide. Inside it the stranded
   * Space is did:key-controlled, which no server orphan sweep can reap,
   * since a did:key resolves from its own bytes forever. Past the flip it is
   * account-controlled and reapable. Narrowing the window to that one
   * request is what this ordering buys; it does not close it.
   *
   * The flip preceding the generation mint is load-bearing rather than
   * cosmetic. The mint and the delegation embed ride the ladder-signed
   * sibling delegation, and the server admits that chain only once the
   * Space's controller is the account DID whose document lists the ladder
   * VM. Minting first and flipping afterwards would need the bootstrap key's
   * own root invocations, which is the ordering this stage replaced.
   *
   * @returns {Promise<string>}   the fresh auxiliary Space's id
   */
  async function mintFreshAnnexSpace(): Promise<string> {
    const freshSpaceId = mintSpaceId()
    const keyAgent = await ladderVmAgent({ ladderSeed })
    const bootstrapWas = bootstrapWasFor({ keyAgent })
    await ensureClientAnnexSpace({
      was: bootstrapWas,
      spaceId: freshSpaceId,
      controller: keyAgent.id
    })
    await bootstrapWas
      .space(freshSpaceId)
      .configure({ controller: account.did, force: true })
    return freshSpaceId
  }

  /**
   * One Space Description read, judged by its HTTP STATUS alone. A 404 is
   * `'not-found'`; a 2xx is `'present'`, whatever its body says, since a
   * Space served with an unreadable body is a present Space and reading it
   * as absence is exactly what would re-point a live account. Every other
   * answer -- a transport failure, a 5xx, a 4xx that is not 404 -- throws,
   * so nothing but a real 404 can ever reach the absence decision.
   *
   * The read goes through the raw signed request rather than the
   * `describe()` handle, whose null-on-404 translation also swallows 401 and
   * 403 and an unparseable body.
   *
   * @param options {object}
   * @param options.was {WasClient}   the client whose signer invokes
   * @param options.annexSpaceId {string}
   * @param [options.capability] {IZcap}   the attached capability; absent
   *   means a root invocation
   * @returns {Promise<'present' | 'not-found'>}
   */
  async function readSpaceDescription({
    was,
    annexSpaceId,
    capability
  }: {
    was: WasClient
    annexSpaceId: string
    capability?: IZcap
  }): Promise<'present' | 'not-found'> {
    let status: number | undefined
    try {
      const response = await was.request({
        path: spacePath(annexSpaceId),
        method: 'GET',
        ...(capability !== undefined ? { capability } : {})
      })
      status = response.status
    } catch (err) {
      if (rawRequestStatus(err) === 404) {
        return 'not-found'
      }
      throw err
    }
    if (status >= 200 && status < 300) {
      return 'present'
    }
    if (status === 404) {
      return 'not-found'
    }
    throw new Error(
      `client annex: the Space Description read for "${annexSpaceId}" ` +
        `answered ${status}; the visit cannot tell whether the Space is gone.`
    )
  }

  /**
   * Whether the auxiliary Space itself is gone from the server, asked only
   * when the pointed generation's log did not read back. A storage server
   * masks an unauthorized read as the same 404 an absent Space answers, so
   * ONE 404 is not absence: it is "absent, or this reader has no authority
   * here". Absence is therefore corroborated by two independent readers, and
   * the Space is gone only when both answer a real 404.
   *
   * The first reader is a ladder-signed GET-only child of the Space's own
   * root, which the account DID's document backs. The sibling delegation
   * cannot carry the question: it targets the items subtree beneath the
   * Space and says nothing about the Space Description.
   *
   * The second is a root invocation as the ladder VM's BARE did:key, the
   * controller a torn establishment leaves behind when its flip never
   * landed. That reader answers 2xx on exactly the Space the first reader
   * has no authority over, so the pair covers both controllers a live annex
   * Space of this credential's can have.
   *
   * The residual bound, stated because no read can close it: a server that
   * does not admit the ladder delegation clause's single-verb predicate
   * refuses the first probe with the same masked 404, and on an
   * account-controlled Space the second probe is refused too. Both readers
   * then say `'not-found'` about a live Space. That is a server older than
   * the one this arm was built against, and the arm's cost there is a
   * re-point of a live generation.
   *
   * @param options {object}
   * @param options.annexSpaceId {string}
   * @param options.was {WasClient}   the standing client's storage client
   * @returns {Promise<boolean>}
   */
  async function annexSpaceAbsent({
    annexSpaceId,
    was
  }: {
    annexSpaceId: string
    was: WasClient
  }): Promise<boolean> {
    const probe = await mintSpaceRootVerbCapability({
      zcapClient: ladderClient,
      storageServerUrl: wasServerUrl,
      spaceId: annexSpaceId,
      verb: 'GET',
      controller: standingClient.did,
      ...(now !== undefined ? { now } : {})
    })
    const delegated = await readSpaceDescription({
      was,
      annexSpaceId,
      capability: probe
    })
    if (delegated === 'present') {
      return false
    }
    const bootstrapWas = bootstrapWasFor({
      keyAgent: await ladderVmAgent({ ladderSeed })
    })
    const asBootstrap = await readSpaceDescription({
      was: bootstrapWas,
      annexSpaceId
    })
    return asBootstrap === 'not-found'
  }

  let spaceMinted = false
  let pointedSpaceMissing = false

  /**
   * The arms that run inside one auxiliary Space: the sibling delegation,
   * the pointed generation's renewal, and the fresh-generation mint with its
   * pointer move. Called once on the resolved Space, and once more on a
   * fresh Space when the pointed one turns out to be gone -- the replacement
   * is decided before any write, so nothing is stranded by the re-run.
   *
   * @param options {object}
   * @param options.annexSpaceId {string}   the Space this run works in
   * @param options.allowSpaceReplacement {boolean}   whether an absent
   *   pointed generation may be checked against the Space itself, and a
   *   fresh Space minted when the Space is gone. False on the run that
   *   already works in a Space this visit created
   * @param [options.pointer] {string}   the pointed annex DID, when the
   *   document names one and this run works in its Space
   * @returns {Promise<ClientAnnexGenerationEnsureOutcome>}
   */
  async function runInAnnexSpace({
    annexSpaceId,
    allowSpaceReplacement,
    pointer
  }: {
    annexSpaceId: string
    allowSpaceReplacement: boolean
    pointer?: string
  }): Promise<ClientAnnexGenerationEnsureOutcome> {
    // A usable sibling first: absent, targeting a different Space than this
    // run works in, or stale on either of the standing-zcap axes -- expiry
    // (past, or inside the renewal window) and signer death (its proof key
    // no longer under `capabilityDelegation` in the verified account
    // document, the current-key-set rule) -- a fresh sibling is minted
    // (local ladder-VM signing, which verifies because the gate above proved
    // the VM a document verification method) so every annex request below
    // can ride it.
    let sibling = delegatedClients
    let siblingReminted = false
    const siblingStale =
      sibling !== undefined &&
      standingZcapStale({
        zcap: sibling,
        doc: account.doc as PublishedKeyDocument,
        ...(now !== undefined ? { now } : {})
      })
    if (
      sibling === undefined ||
      siblingSpaceId !== annexSpaceId ||
      siblingStale
    ) {
      sibling = await mintDelegatedClientsDelegation({
        zcapClient: ladderClient,
        wasServerUrl,
        clientAnnexSpaceId: annexSpaceId,
        controller: standingClient.did,
        ...(now !== undefined ? { now } : {})
      })
      siblingReminted = true
    }
    const usableSibling = sibling
    const standingWas = new WasClient({
      serverUrl: wasServerUrl,
      zcapClient: standingClient.zcapClient
    })
    const storeFor = (generationId: string) =>
      clientAnnexLogStore({
        was: standingWas,
        spaceId: annexSpaceId,
        generationId,
        capability: usableSibling
      })
    const annexPin = (generationId: string) =>
      pinStore !== undefined
        ? {
            pinStore,
            logId: clientAnnexLogPinId({ spaceId: annexSpaceId, generationId })
          }
        : {}

    // RENEW PRECEDES MINT: a live, verifiable pointed generation is renewed
    // in place; only a rung this generation never committed falls through to
    // the fresh mint (the GC swap's no-committed-survivor escape).
    if (pointer !== undefined) {
      const parts = clientAnnexDidParts({ did: pointer })
      const pointedLog = await readPublishedLog({
        idStore: storeFor(parts.generationId),
        expectedDid: pointer,
        ...annexPin(parts.generationId)
      })
      if (pointedLog !== undefined) {
        try {
          const ensured = await ensureGenerationDelegationCurrent({
            store: storeFor(parts.generationId),
            ladderSeed,
            generationId: parts.generationId,
            mintGenerationDelegation: mintDelegation,
            expectedDid: pointer,
            accountDoc: account.doc as PublishedKeyDocument,
            ...annexPin(parts.generationId),
            ...(now !== undefined ? { now } : {})
          })
          const resealed = await resealRecord({
            delegatedClients: usableSibling,
            siblingReminted
          })
          return {
            clientAnnexDid: pointer,
            generationDelegation: ensured.delegation,
            delegation: usableBridge,
            delegatedClients: usableSibling,
            generationMinted: false,
            spaceMinted,
            pointedSpaceMissing,
            delegationRenewed: ensured.renewed,
            siblingReminted,
            bridgeReminted,
            ...resealed
          }
        } catch (err) {
          if (
            (err as { name?: string }).name !==
            'ClientAnnexRungUncommittedError'
          ) {
            throw err
          }
          // This credential's rung was never committed into the pointed
          // generation (bound mid-generation): fall through to the fresh
          // mint, which commits it with the fresh genesis.
        }
      } else if (
        allowSpaceReplacement &&
        (await annexSpaceAbsent({ annexSpaceId, was: standingWas }))
      ) {
        // THE POINTED SPACE IS GONE. A missing generation log inside a live
        // Space is the fresh-generation arm's case; a missing SPACE is not,
        // since every write below would land in a Space that does not exist
        // and the visit would fail on something other than the typed
        // refusal. The Space is re-minted and the run starts over in it,
        // before anything has been written.
        await assertPointerEntryAttributable({ ladderSeed, log: account.log })
        const freshSpaceId = await mintFreshAnnexSpace()
        spaceMinted = true
        pointedSpaceMissing = true
        return runInAnnexSpace({
          annexSpaceId: freshSpaceId,
          allowSpaceReplacement: false
        })
      }
    }

    // THE FRESH-GENERATION ARM: pre-flight attribution first (never mint a
    // generation the pointer entry cannot then name), then the GC swap's
    // stage order minus its revoke -- mint, install the delegation,
    // re-point. The fresh genesis commits only the acting credential's annex
    // rung; other standing credentials' per-generation rungs are re-committed
    // only by their own later ceremonies (a property of every generation
    // swap).
    await assertPointerEntryAttributable({ ladderSeed, log: account.log })
    const minted = await mintCredentialClientAnnexGeneration({
      was: standingWas,
      wasServerUrl,
      spaceId: annexSpaceId,
      controller: account.did,
      ladderSeed,
      capability: usableSibling
    })
    const ensured = await ensureGenerationDelegationCurrent({
      store: storeFor(minted.generationId),
      ladderSeed,
      generationId: minted.generationId,
      mintGenerationDelegation: mintDelegation,
      expectedDid: minted.did,
      ...annexPin(minted.generationId),
      ...(now !== undefined ? { now } : {})
    })

    // No revocation of the superseded generation's delegation is attempted:
    // a transient visit has no reach that could invoke it (the standing
    // client is neither the Space controller nor in that delegation's
    // chain). The pointer move itself retires it on a conforming server --
    // the inspector clause compares the delegation's controller against the
    // document's pointer -- and it otherwise rots on its TTL.
    await movePointerAsLadder({
      idStore,
      ladderSeed,
      clientAnnexDid: minted.did,
      accountDid: account.did,
      ...(pinStore !== undefined
        ? { pinStore, logId: accountLogPinId({ spaceId }) }
        : {})
    })
    const resealed = await resealRecord({
      delegatedClients: usableSibling,
      siblingReminted
    })
    return {
      clientAnnexDid: minted.did,
      generationDelegation: ensured.delegation,
      delegation: usableBridge,
      delegatedClients: usableSibling,
      generationMinted: true,
      spaceMinted,
      pointedSpaceMissing,
      delegationRenewed: false,
      siblingReminted,
      bridgeReminted,
      ...resealed
    }
  }

  if (annexSpaceId === undefined) {
    // NEITHER THE POINTER NOR A SIBLING NAMES A SPACE. The pre-flight
    // attribution runs before any Space or generation is minted (a bridge
    // delegation mint writes nothing durable).
    await assertPointerEntryAttributable({ ladderSeed, log: account.log })
    const freshSpaceId = await mintFreshAnnexSpace()
    spaceMinted = true
    return runInAnnexSpace({
      annexSpaceId: freshSpaceId,
      allowSpaceReplacement: false
    })
  }

  return runInAnnexSpace({
    annexSpaceId,
    allowSpaceReplacement: true,
    ...(pointer !== undefined ? { pointer } : {})
  })
}

/**
 * The annex Space, in the settled resolution order: the account document's
 * `#DelegatedClients` pointer names it; else the record's sibling
 * delegation's target does (converging a torn establishment onto its own
 * stranded Space instead of minting another orphan); else nothing does and
 * the caller mints fresh. The one statement of the rule, shared by the
 * transient visit's ensure here and the establishment's stage-3 primitive.
 *
 * @param options {object}
 * @param options.doc {object}   the VERIFIED account document
 * @param [options.delegatedClients] {IZcap}   the record's sibling
 *   delegation, when the record carries one
 * @returns {object}   `pointer` (the pointed annex DID), `siblingSpaceId`
 *   (the sibling's target Space), and `annexSpaceId` (the resolved Space, or
 *   `undefined` when a fresh one must be minted)
 */
export function resolveClientAnnexSpaceId({
  doc,
  delegatedClients
}: {
  doc: PublishedWebvhLog['doc']
  delegatedClients?: IZcap
}): {
  pointer?: string
  siblingSpaceId?: string
  annexSpaceId?: string
} {
  const pointer = delegatedClientsPointer({ doc })
  const siblingSpaceId =
    delegatedClients === undefined
      ? undefined
      : delegatedClientsDelegationSpaceId({ delegation: delegatedClients })
  const annexSpaceId =
    pointer !== undefined
      ? clientAnnexDidParts({ did: pointer }).spaceId
      : siblingSpaceId
  return {
    ...(pointer !== undefined ? { pointer } : {}),
    ...(siblingSpaceId !== undefined ? { siblingSpaceId } : {}),
    ...(annexSpaceId !== undefined ? { annexSpaceId } : {})
  }
}

/**
 * The pre-flight rung attribution: the `{ updateSeed, stagedSeed }` pair the
 * pointer entry signs with, recovered from the verified account log's
 * current parameters. The signer must be a REVEALED rung (the entry verifies
 * against the log's `updateKeys`), with the next rung staged per the
 * carry-over convention. No rung of this ladder standing -- or only a
 * committed hash, which cannot sign -- refuses with
 * {@link ClientAnnexGenerationUnavailableError} before anything is minted.
 * Exported for the establishment's stage-3 primitive, whose pointer entry
 * signs by the same attribution.
 *
 * @param options {object}
 * @param options.ladderSeed {Uint8Array}
 * @param options.log {DIDLog}   the VERIFIED account log
 * @returns {Promise<ClientWebvhUpdateKeys>}
 */
export async function pointerEntryUpdateKeys({
  ladderSeed,
  log
}: {
  ladderSeed: Uint8Array
  log: PublishedWebvhLog['log']
}): Promise<ClientWebvhUpdateKeys> {
  const current = currentLogParameters({ log })
  const unattributable = () =>
    new ClientAnnexGenerationUnavailableError({
      reason: 'update-key-not-attributable',
      message:
        "No current account-log update key is a rung of this credential's " +
        'ladder; the pointer entry could not be signed, so nothing is minted.'
    })
  let attributed: Awaited<ReturnType<typeof attributeLadderRung>>
  try {
    attributed = await attributeLadderRung({ ladderSeed, published: current })
  } catch (err) {
    if ((err as { name?: string }).name === 'LadderAttributionError') {
      throw unattributable()
    }
    throw err
  }
  if (attributed.state !== 'revealed') {
    throw unattributable()
  }
  const staged = await ladderRung({
    ladderSeed,
    index: attributed.rung.index + 1
  })
  return { updateSeed: attributed.rung.seed, stagedSeed: staged.seed }
}
/**
 * The pre-flight the pointer-moving arms run before minting anything: this
 * ladder has a rung the pointer entry will be able to sign with, either
 * standing in `updateKeys` already or committed in `nextKeyHashes` and
 * revealable by {@link movePointerAsLadder}. A ladder the log carries no rung
 * of at all, and an ambiguous attribution, refuse here with
 * {@link ClientAnnexGenerationUnavailableError} before a generation or a
 * Space is minted.
 *
 * @param options {object}
 * @param options.ladderSeed {Uint8Array}
 * @param options.log {DIDLog}   the VERIFIED account log
 * @returns {Promise<void>}
 */
async function assertPointerEntryAttributable({
  ladderSeed,
  log
}: {
  ladderSeed: Uint8Array
  log: PublishedWebvhLog['log']
}): Promise<void> {
  const current = currentLogParameters({ log })
  try {
    await attributeLadderRung({ ladderSeed, published: current })
  } catch (err) {
    if ((err as { name?: string }).name === 'LadderAttributionError') {
      throw new ClientAnnexGenerationUnavailableError({
        reason: 'update-key-not-attributable',
        message:
          "The account log carries no rung of this credential's ladder, or " +
          'the attribution is ambiguous; the pointer entry could not be ' +
          'signed, so nothing is minted.'
      })
    }
    throw err
  }
}

/**
 * The `#DelegatedClients` pointer move as a credential-only visit makes it:
 * reveal this ladder's rung when only its hash stands committed, re-read, and
 * write the pointer entry signed by the now-revealed rung.
 *
 * A self-enrollment's add entry spends the revealed rung, so on any account
 * that has ever self-enrolled the rung is merely committed and the reveal is
 * what makes the pointer entry signable at all.
 *
 * ACCEPTED CONSEQUENCE (design FW-356, finding R3): the reveal retires
 * nothing, and the pointer entry re-states `updateKeys` verbatim, so the
 * acting rung stands in the account log's `updateKeys` afterwards. The price
 * of a pointer move is therefore a standing account update key in the
 * credential's hand -- direct document-edit authority through the bridge with
 * no further reveal -- retired at that credential's next self-enrollment
 * (whose add entry drops the attributed rung) or at its retirement. This is
 * documented rather than prevented.
 *
 * Both entries run inside ONE conflict retry, and every attempt re-reads the
 * head and re-attributes the rung from it, so a racing ceremony that consumes
 * the rung climbs to the winner's committed rung instead of refusing
 * `update-key-not-attributable` on a rung that is no longer current.
 *
 * Three things make that hold. A rung the winner consumed between this
 * attempt's reveal and its re-read reads back as
 * `update-key-not-attributable`, which inside this loop is staleness rather
 * than a refusal -- the pre-flight already found a rung -- so it is raised as
 * a conflict and the next attempt reveals the winner's committed rung. The pointer entry runs as
 * {@link setDelegatedClientsPointerOnce} rather than through its retrying
 * wrapper: the wrapper's inner loop would re-invoke the attempt with the
 * attribution's stale `updateKeys`, and a rung the racing winner consumed
 * cannot become authorized by re-reading, so the attempt would end on the
 * plain not-authorized refusal, which the outer loop does not retry. And the
 * attempt is handed the very head this attempt attributed against, so a
 * racing entry landing between the attribution and the PUT loses the CAS and
 * surfaces as a `WebvhLogConflictError` -- the refusal the outer loop
 * re-attributes from. The pre-flight guard
 * ({@link assertPointerEntryAttributable}) therefore cannot fire from
 * staleness here: it runs on the caller's snapshot before anything is minted,
 * while every entry this function publishes is built on a head it read
 * itself.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}   the account log's store, from the
 *   record's bridge delegation
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed
 * @param options.clientAnnexDid {string}   the generation to point at
 * @param options.accountDid {string}   the account DID the log must resolve to
 * @param [options.pinStore] {ResourceLogPinStore}   the visit's chain-head pins
 * @param [options.logId] {string}   the account log's pin slot; required
 *   whenever a `pinStore` is supplied
 * @returns {Promise<void>}
 */
async function movePointerAsLadder({
  idStore,
  ladderSeed,
  clientAnnexDid,
  accountDid,
  pinStore,
  logId
}: {
  idStore: WebvhIdStore
  ladderSeed: Uint8Array
  clientAnnexDid: string
  accountDid: string
  pinStore?: ResourceLogPinStore
  logId?: string
}): Promise<void> {
  const pin =
    pinStore !== undefined && logId !== undefined ? { pinStore, logId } : {}
  await withLogConflictRetry(async () => {
    await revealLadderRungWebvh({
      store: idStore,
      ladderSeed,
      expectedDid: accountDid,
      ...pin
    })
    // The head the reveal entry just published (or the unchanged head, when
    // the rung was revealed already), under the same pin.
    const published = await readPublishedLogOrThrow({
      idStore,
      expectedDid: accountDid,
      ...pin,
      missingMessage:
        'did:webvh: did.jsonl is missing; nothing to point at a client annex.'
    })
    // A racing ceremony that consumed the rung between this reveal and this
    // read leaves the ladder committed-only again, which the attribution
    // reports as `update-key-not-attributable`. Inside this loop that is a
    // staleness signal rather than a refusal -- the pre-flight already found
    // a rung, and a fresh reveal is exactly what the next attempt does -- so
    // it becomes a conflict for the retry to re-run.
    let updateKeys: ClientWebvhUpdateKeys
    try {
      updateKeys = await pointerEntryUpdateKeys({
        ladderSeed,
        log: published.log
      })
    } catch (err) {
      if (
        (err as { name?: string }).name ===
          'ClientAnnexGenerationUnavailableError' &&
        (err as ClientAnnexGenerationUnavailableError).reason ===
          'update-key-not-attributable'
      ) {
        throw new WebvhLogConflictError(
          'did:webvh: a concurrent ceremony consumed the rung this pointer ' +
            'move just revealed; the move re-runs from a fresh reveal.',
          { cause: err }
        )
      }
      throw err
    }
    await setDelegatedClientsPointerOnce({
      idStore,
      updateKeys,
      clientAnnexDid,
      expectedDid: accountDid,
      logOnly: true,
      published,
      ...pin
    })
  })
}
