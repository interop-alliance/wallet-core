/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The Resource Log Profile's verification algorithm (App Connect spec,
 * `#log-verification`), end-to-end and fail-closed: entry-shape parse checks,
 * SCID recomputation, chain-hash recomputation (never a stated head), proof
 * verification through the did:webvh log kernel, the external-authorization
 * rule (anchor resolution against the independently verified controller
 * document, `assertionMethod` membership at the anchored version, anchor
 * monotonicity), terminal-entry recognition, and continuity against the
 * chain-head pin. Any failure rejects the LOG, not just the failing entry,
 * and nothing served -- a stated head, a digest, a count -- is ever accepted
 * in place of recomputation.
 */
import {
  buildVersionId,
  canonicalizeStrict,
  defaultWebvhLogVerifier,
  deriveHash,
  parseAndValidateVersionId,
  SCID_PLACEHOLDER,
  verifyEntryProofs
} from '@interop/did-method-webvh'
import type {
  ResourceLogEntry,
  ResourceLogEntryProof
} from '@interop/was-client/log'
import type { ResourceLogController } from './controller.js'
import {
  ResourceLogContinuityError,
  ResourceLogIntegrityError
} from './errors.js'
import type { ResourceLogHeadPin } from './pin.js'

/**
 * The five members a log entry carries, exactly.
 */
const ENTRY_MEMBERS = [
  'versionId',
  'versionTime',
  'parameters',
  'state',
  'proof'
]

/**
 * What full verification resolves to. `state` is the profile's definition of
 * the resource's current state -- the verified head entry's `state` -- and
 * `pin` is the record the caller must store as its new chain-head pin.
 * `terminal` is the head's `nextLog` when the log is closed by a handover
 * entry (appends must be refused), `previousLog` the genesis back-reference
 * when this log is a handover successor.
 */
export interface VerifiedResourceLog {
  entries: ResourceLogEntry[]
  method: string
  scid: string
  head: ResourceLogEntry
  state: ResourceLogEntry['state']
  pin: ResourceLogHeadPin
  terminal: { method: string; scid: string } | null
  previousLog: { scid: string; head: string } | null
}

/**
 * Whether an entry is a terminal handover entry: its `parameters` carry a
 * `nextLog` member. Position, exact member set, and state equality are the
 * verifier's checks; this is only the discriminant.
 *
 * @param entry {ResourceLogEntry}
 * @returns {boolean}
 */
export function isTerminalResourceLogEntry(entry: ResourceLogEntry): boolean {
  return (
    typeof entry.parameters === 'object' &&
    entry.parameters !== null &&
    'nextLog' in entry.parameters
  )
}

/**
 * Structural check of one member of an entry's `proof` array against the
 * profile's fixed shape, before any cryptography runs.
 *
 * @param proof {unknown}
 * @param ordinal {number}   the owning entry's 1-based position
 * @returns {ResourceLogEntryProof}
 */
function checkProofShape(
  proof: unknown,
  ordinal: number
): ResourceLogEntryProof {
  const candidate = proof as Partial<ResourceLogEntryProof> | null
  if (
    candidate === null ||
    typeof candidate !== 'object' ||
    candidate.type !== 'DataIntegrityProof' ||
    candidate.cryptosuite !== 'eddsa-jcs-2022' ||
    candidate.proofPurpose !== 'assertionMethod' ||
    typeof candidate.verificationMethod !== 'string' ||
    typeof candidate.proofValue !== 'string'
  ) {
    throw new ResourceLogIntegrityError(
      `Resource log entry ${ordinal} carries a proof outside the profile's ` +
        `fixed shape (DataIntegrityProof / eddsa-jcs-2022 / assertionMethod).`
    )
  }
  return candidate as ResourceLogEntryProof
}

/**
 * Shape-checks one entry (the profile's parse step): exactly the five
 * members, `versionId` ordinal at its 1-based position, an RFC3339 UTC
 * `versionTime` (format only -- temporal refusals are forbidden), the
 * per-position `parameters` rules fail-closed, a `state` carrying `type` and
 * no `history`, and a non-empty fixed-shape `proof` array.
 *
 * @param entry {ResourceLogEntry}
 * @param index {number}   the entry's 0-based position
 */
function checkEntryShape(entry: ResourceLogEntry, index: number): void {
  const ordinal = index + 1
  const members = Object.keys(entry)
  if (
    members.length !== ENTRY_MEMBERS.length ||
    ENTRY_MEMBERS.some(member => !(member in entry))
  ) {
    throw new ResourceLogIntegrityError(
      `Resource log entry ${ordinal} does not carry exactly the profile's ` +
        `five members (versionId, versionTime, parameters, state, proof).`
    )
  }
  try {
    parseAndValidateVersionId(entry.versionId, ordinal)
  } catch (err) {
    throw new ResourceLogIntegrityError(
      `Resource log entry ${ordinal} has a malformed or misplaced versionId.`,
      { cause: err }
    )
  }
  if (
    typeof entry.versionTime !== 'string' ||
    !entry.versionTime.endsWith('Z') ||
    Number.isNaN(Date.parse(entry.versionTime))
  ) {
    throw new ResourceLogIntegrityError(
      `Resource log entry ${ordinal} has a malformed versionTime (RFC3339 ` +
        `UTC required; the value itself is advisory).`
    )
  }
  const parameters = entry.parameters
  if (parameters === null || typeof parameters !== 'object') {
    throw new ResourceLogIntegrityError(
      `Resource log entry ${ordinal} has a non-object parameters member.`
    )
  }
  const parameterMembers = Object.keys(parameters)
  if (index === 0) {
    const genesis = parameters as {
      method?: unknown
      scid?: unknown
      previousLog?: { scid?: unknown; head?: unknown }
    }
    const allowed = parameterMembers.every(member =>
      ['method', 'scid', 'previousLog'].includes(member)
    )
    if (
      !allowed ||
      typeof genesis.method !== 'string' ||
      typeof genesis.scid !== 'string' ||
      (genesis.previousLog !== undefined &&
        (genesis.previousLog === null ||
          typeof genesis.previousLog !== 'object' ||
          typeof genesis.previousLog.scid !== 'string' ||
          typeof genesis.previousLog.head !== 'string' ||
          Object.keys(genesis.previousLog).length !== 2))
    ) {
      throw new ResourceLogIntegrityError(
        'The resource log genesis parameters must carry method and scid ' +
          '(plus, on a handover successor only, previousLog) and nothing else.'
      )
    }
  } else if (parameterMembers.length !== 0) {
    // The only non-genesis entry with parameters is a terminal handover
    // entry, exactly { nextLog: { method, scid } }. Anything else -- the
    // deleted did:webvh key-management parameters in particular -- is refused
    // fail-closed.
    const terminal = parameters as {
      nextLog?: { method?: unknown; scid?: unknown }
    }
    if (
      parameterMembers.length !== 1 ||
      terminal.nextLog === undefined ||
      terminal.nextLog === null ||
      typeof terminal.nextLog !== 'object' ||
      typeof terminal.nextLog.method !== 'string' ||
      typeof terminal.nextLog.scid !== 'string' ||
      Object.keys(terminal.nextLog).length !== 2
    ) {
      throw new ResourceLogIntegrityError(
        `Resource log entry ${ordinal} carries parameters this profile does ` +
          `not define for its position (only a terminal entry's nextLog is ` +
          `permitted past genesis).`
      )
    }
  }
  const state = entry.state
  if (
    state === null ||
    typeof state !== 'object' ||
    typeof (state as { type?: unknown }).type !== 'string'
  ) {
    throw new ResourceLogIntegrityError(
      `Resource log entry ${ordinal} has no state.type schema identifier.`
    )
  }
  if ('history' in state) {
    throw new ResourceLogIntegrityError(
      `Resource log entry ${ordinal} carries a history member inside its ` +
        `state (the profile reserves that member name).`
    )
  }
  if (!Array.isArray(entry.proof) || entry.proof.length === 0) {
    throw new ResourceLogIntegrityError(
      `Resource log entry ${ordinal} carries no proof array.`
    )
  }
  for (const proof of entry.proof) {
    checkProofShape(proof, ordinal)
  }
}

/**
 * Deep-clones a JSON value, replacing every string equal to the SCID with the
 * `{SCID}` placeholder -- the inverse of genesis construction, used to
 * recompute the SCID from a served genesis entry.
 *
 * @param value {unknown}
 * @param scid {string}
 * @returns {unknown}
 */
function substituteScid(value: unknown, scid: string): unknown {
  if (typeof value === 'string') {
    return value === scid ? SCID_PLACEHOLDER : value
  }
  if (Array.isArray(value)) {
    return value.map(item => substituteScid(item, scid))
  }
  if (value !== null && typeof value === 'object') {
    const result: Record<string, unknown> = {}
    for (const [key, member] of Object.entries(value)) {
      result[key] = substituteScid(member, scid)
    }
    return result
  }
  return value
}

/**
 * The hash input of entry `n`: the entry with `proof` removed and `versionId`
 * replaced by the predecessor's `versionId` (the SCID for the genesis entry).
 *
 * @param entry {ResourceLogEntry}
 * @param predecessorVersionId {string}
 * @returns {object}
 */
function hashInputOf(
  entry: ResourceLogEntry,
  predecessorVersionId: string
): object {
  return {
    versionId: predecessorVersionId,
    versionTime: entry.versionTime,
    parameters: entry.parameters,
    state: entry.state
  }
}

/**
 * Splits a proof's `verificationMethod` DID URL into its base DID, its
 * `versionId` DID parameter (the entry anchor), and its fragment (the signing
 * key's multibase).
 *
 * @param verificationMethod {string}
 * @param ordinal {number}   the owning entry's 1-based position
 * @returns {object}
 */
function parseAnchoredVm(
  verificationMethod: string,
  ordinal: number
): { did: string; anchor?: string; keyMultibase: string } {
  const hashIndex = verificationMethod.lastIndexOf('#')
  if (hashIndex === -1 || hashIndex === verificationMethod.length - 1) {
    throw new ResourceLogIntegrityError(
      `Resource log entry ${ordinal} has a proof verificationMethod without ` +
        `a key fragment.`
    )
  }
  const keyMultibase = verificationMethod.slice(hashIndex + 1)
  const didUrl = verificationMethod.slice(0, hashIndex)
  const queryIndex = didUrl.indexOf('?')
  if (queryIndex === -1) {
    return { did: didUrl, keyMultibase }
  }
  const did = didUrl.slice(0, queryIndex)
  const params = new URLSearchParams(didUrl.slice(queryIndex + 1))
  const anchor = params.get('versionId') ?? undefined
  return { did, anchor, keyMultibase }
}

/**
 * Runs the profile's full verification over a parsed log, in order: parse
 * shape, genesis (SCID recomputation, format identifier), chain-hash
 * recomputation, per-entry proofs, the external-authorization rule with
 * anchor monotonicity, termination, and continuity against the chain-head
 * pin. Throws {@link ResourceLogIntegrityError} on fabrication-class
 * failures, {@link ResourceLogContinuityError} on pin conflicts; any failure
 * rejects the whole log.
 *
 * The controller view is the independently verified controller document --
 * never material served beside the log. An unversioned controller (empty
 * `versionIds`) degrades every anchor rule to current-document verification
 * and requires anchorless proofs.
 *
 * @param options {object}
 * @param options.entries {ResourceLogEntry[]}   the parsed served log
 * @param options.controller {ResourceLogController}   the verified controller
 *   view ({@link webvhResourceLogController})
 * @param options.expectedMethod {string}   the format identifier this caller
 *   expects (`WAS_RESOURCE_LOG_METHOD`; also confirmed against any `history`
 *   dispatch hint the caller followed)
 * @param [options.pin] {ResourceLogHeadPin}   the held chain-head pin, when
 *   this client has verified the log before
 * @returns {Promise<VerifiedResourceLog>}
 */
export async function verifyResourceLog({
  entries,
  controller,
  expectedMethod,
  pin
}: {
  entries: ResourceLogEntry[]
  controller: ResourceLogController
  expectedMethod: string
  pin?: ResourceLogHeadPin | null
}): Promise<VerifiedResourceLog> {
  if (entries.length === 0) {
    throw new ResourceLogIntegrityError(
      'The resource log is empty (a log carries at least its genesis entry).'
    )
  }

  // 1. Parse: per-entry shape, parameters rules, ordinal positions.
  entries.forEach((entry, index) => {
    checkEntryShape(entry, index)
  })

  // 2. Genesis: format identifier, then SCID recomputation.
  const genesisParameters = entries[0]!.parameters as {
    method: string
    scid: string
    previousLog?: { scid: string; head: string }
  }
  const { method, scid } = genesisParameters
  if (method !== expectedMethod) {
    throw new ResourceLogIntegrityError(
      `The resource log declares format "${method}", not the expected ` +
        `"${expectedMethod}".`
    )
  }
  const preliminary = substituteScid(
    hashInputOf(entries[0]!, SCID_PLACEHOLDER),
    scid
  )
  if ((await deriveHash(preliminary)) !== scid) {
    throw new ResourceLogIntegrityError(
      'The resource log SCID does not verify against its genesis content.'
    )
  }

  // 3. Chain: recompute every entry hash from the predecessor-substituted
  // input; never accept a stated head.
  let predecessorVersionId = scid
  for (const [index, entry] of entries.entries()) {
    const entryHash = await deriveHash(hashInputOf(entry, predecessorVersionId))
    if (entry.versionId !== buildVersionId(index + 1, entryHash)) {
      throw new ResourceLogIntegrityError(
        `Resource log entry ${index + 1} does not hash-chain to its ` +
          `predecessor.`
      )
    }
    predecessorVersionId = entry.versionId
  }

  // 4 + 5. Proofs and authorization, entry by entry, with anchor
  // monotonicity carried along the log.
  const versioned = controller.versionIds.length > 0
  let anchorFloor = 0
  for (const [index, entry] of entries.entries()) {
    const ordinal = index + 1
    let entryAnchorIndex = anchorFloor
    const authorize = async (proof: {
      verificationMethod?: string
    }): Promise<void> => {
      const { did, anchor, keyMultibase } = parseAnchoredVm(
        proof.verificationMethod ?? '',
        ordinal
      )
      if (did !== controller.did) {
        throw new ResourceLogIntegrityError(
          `Resource log entry ${ordinal} is signed under a different ` +
            `controller than this log's account.`
        )
      }
      if (versioned && anchor === undefined) {
        throw new ResourceLogIntegrityError(
          `Resource log entry ${ordinal} carries no entry anchor against a ` +
            `version-resolvable controller.`
        )
      }
      if (!versioned && anchor !== undefined) {
        throw new ResourceLogIntegrityError(
          `Resource log entry ${ordinal} anchors a version on an unversioned ` +
            `controller.`
        )
      }
      let anchorIndex = 0
      if (anchor !== undefined) {
        anchorIndex = controller.versionIds.indexOf(anchor)
        if (anchorIndex === -1) {
          throw new ResourceLogIntegrityError(
            `Resource log entry ${ordinal} anchors an unknown controller ` +
              `document version.`
          )
        }
        if (anchorIndex < anchorFloor) {
          throw new ResourceLogIntegrityError(
            `Resource log entry ${ordinal} anchors behind its predecessor ` +
              `(anchors must be monotone along the log).`
          )
        }
      }
      const assertionKeys = await controller.assertionKeysAt(anchor)
      if (!assertionKeys.has(keyMultibase)) {
        throw new ResourceLogIntegrityError(
          `Resource log entry ${ordinal} is signed by a key the controller ` +
            `document does not list under assertionMethod at the anchored ` +
            `version.`
        )
      }
      entryAnchorIndex = Math.max(entryAnchorIndex, anchorIndex)
    }
    try {
      // The wire proof type narrows the kernel's (fixed purpose, optional
      // created); the shape check above already enforced the profile form.
      await verifyEntryProofs(
        entry as Parameters<typeof verifyEntryProofs>[0],
        {
          verifier: defaultWebvhLogVerifier,
          authorize,
          resolveVM: async verificationMethod => ({
            publicKeyMultibase: parseAnchoredVm(verificationMethod, ordinal)
              .keyMultibase
          })
        }
      )
    } catch (err) {
      if (err instanceof ResourceLogIntegrityError) {
        throw err
      }
      throw new ResourceLogIntegrityError(
        `Resource log entry ${ordinal} failed proof verification.`,
        { cause: err }
      )
    }
    anchorFloor = entryAnchorIndex
  }

  // 6. Termination: a terminal entry closes the log -- it must be last, must
  // not be the genesis, and must change no state.
  let terminal: { method: string; scid: string } | null = null
  for (const [index, entry] of entries.entries()) {
    if (!isTerminalResourceLogEntry(entry) || index === 0) {
      continue
    }
    if (index !== entries.length - 1) {
      throw new ResourceLogIntegrityError(
        'The resource log continues past a terminal handover entry.'
      )
    }
    const predecessorState = entries[index - 1]!.state
    if (
      canonicalizeStrict(entry.state) !== canonicalizeStrict(predecessorState)
    ) {
      throw new ResourceLogIntegrityError(
        "The terminal handover entry's state differs from its " +
          "predecessor's (a handover changes no resource state)."
      )
    }
    terminal = (
      entry.parameters as { nextLog: { method: string; scid: string } }
    ).nextLog
  }

  // 7. Continuity against the chain-head pin, where one is held.
  const head = entries[entries.length - 1]!
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
        servedEntries: entries
      })
    }
    if (entries.length < pinnedOrdinal) {
      throw new ResourceLogContinuityError({
        reason: 'rollback',
        pinnedHead: pin.head
      })
    }
    if (entries[pinnedOrdinal - 1]!.versionId !== pin.head) {
      throw new ResourceLogContinuityError({
        reason: 'fork',
        pinnedHead: pin.head,
        servedEntries: entries
      })
    }
  }

  return {
    entries,
    method,
    scid,
    head,
    state: head.state,
    pin: { method, scid, head: head.versionId },
    terminal,
    previousLog: genesisParameters.previousLog ?? null
  }
}

/**
 * Verifies a handover link from both sides: the prior log's terminal entry
 * and the successor log's genesis back-reference. Both logs must already have
 * passed {@link verifyResourceLog}. Checks: the terminal `nextLog` names the
 * successor's SCID and method; the successor's `previousLog` names the prior
 * log's SCID; and the successor's `previousLog.head` is the `versionId` of
 * the terminal entry's immediate predecessor -- the terminal entry chains
 * directly off the head the successor references. A verified handover is the
 * one transition that replaces a chain-head pin wholesale (the caller stores
 * `successor.pin`).
 *
 * @param options {object}
 * @param options.prior {VerifiedResourceLog}   the closed log
 * @param options.successor {VerifiedResourceLog}   the log its terminal entry
 *   names
 * @returns {void}
 */
export function verifyResourceLogHandover({
  prior,
  successor
}: {
  prior: VerifiedResourceLog
  successor: VerifiedResourceLog
}): void {
  if (!prior.terminal) {
    throw new ResourceLogContinuityError({
      reason: 'scid-switch',
      pinnedHead: prior.pin.head
    })
  }
  const predecessor = prior.entries[prior.entries.length - 2]
  if (
    prior.terminal.scid !== successor.scid ||
    prior.terminal.method !== successor.method ||
    successor.previousLog?.scid !== prior.scid ||
    predecessor === undefined ||
    successor.previousLog.head !== predecessor.versionId
  ) {
    throw new ResourceLogContinuityError({
      reason: 'scid-switch',
      pinnedHead: prior.pin.head,
      servedEntries: successor.entries
    })
  }
}
