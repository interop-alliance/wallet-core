/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The client enrollment ceremony: connecting a second wallet client (a fresh
 * browser profile, another app install) to an existing account without any
 * secret ever leaving either side. The new client mints its whole key set
 * locally -- client seed, did:webvh update-key seeds -- and only PUBLIC halves
 * travel, as a compact "connect code" carried point-to-point (pasted between
 * two browsers in the room today; the same payload renders as a QR for a
 * camera-holding wallet). Nothing travels back over the channel: the account
 * pointer comes out of the keyring (the enrollee holds the unlock secret), and
 * the user key comes back through the wrap-set roster.
 *
 * Push, not pull, in the recovery-anchor order (decryption material before
 * authorization): the enrolling client wraps the user key to the new client's
 * key-agreement key in `key-map/user-key.jsonl` FIRST, then writes the two
 * did:webvh log entries (commit, then add-VMs-and-update-key). No
 * authorized-but-blind window exists at any point, and both tear points
 * resume by re-running the ceremony with the same code -- a tear after the
 * roster write leaves an orphan wrap (invisible to authorization), a tear
 * between the log entries is detected from the published commitments.
 *
 * The new client's first roster read happens post-enrollment, signed with its
 * `<did:webvh>#<multibase>` key -- the server authorizes it under the
 * current-key-set rule the moment the add entry publishes. Persisting the key
 * set under the app's own unlock layer is the caller's job: this module hands
 * back the user key and the roster epoch to pin, and stops there.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import {
  decodeMultikey,
  MultikeyCodec
} from '@interop/data-integrity-core/multihash'
import { base64urlnopad } from '@scure/base'
import { agentsFromSeed } from '../identity/agents.js'
import {
  enrollWebvhClient,
  keyAgreementTwinMultibase,
  mintClientWebvhUpdateKeys,
  updateKeyMultibase
} from '../webvh/didWebvh.js'
import type {
  ClientWebvhUpdateKeys,
  WebvhEnrollmentKeys,
  WebvhIdStore
} from '../webvh/didWebvh.js'
import {
  clientSigningKeyMultibase,
  isWebvhDid,
  webvhZcapClient
} from '../webvh/zcap.js'
import { AccountLogMissingError, verifyAccountLog } from '../webvh/verifyLog.js'
import { addUserKeyRosterRecipient } from '../keys/userKeyRoster.js'
import {
  readUserKeyRoster,
  rosterRecipientKid,
  userKeyRosterLogSigner
} from '../keys/userKeyRoster.js'
import { userKeyRosterDescriptorStore } from '../keys/rosterStore.js'
import {
  memoryResourceLogPinStore,
  type ResourceLogPinStore
} from '@interop/vh-resource-log'
import { webvhResourceLogController } from '../resourceLog/index.js'
import type { UserKey } from '../keys/userKey.js'
import type { AccountPointer } from '../keyring/record.js'
import { CONNECT_CODE_PREFIX } from './connectCode.js'

/**
 * The connect-code payload version this build mints and accepts.
 */
const CONNECT_CODE_VERSION = 1

/**
 * The public halves a connect code carries -- the same four multibases
 * `enrollWebvhClient` publishes into the document, minted by the enrollee and
 * verified point-to-point by the person running the ceremony.
 */
export type EnrollmentRequest = WebvhEnrollmentKeys

/**
 * Thrown by the enrollee's completion step while the enrolling side has not
 * (yet) published the add entry -- the "not approved yet" state, retried by
 * completing again once the other client finishes.
 */
export class EnrollmentPendingError extends Error {
  constructor(
    message = 'This browser is not enrolled yet; approve the connect code ' +
      'from an already-connected browser, then try again.'
  ) {
    super(message)
    this.name = 'EnrollmentPendingError'
  }
}

/**
 * The multicodec multibase prefixes of the two key types a connect code
 * carries: Ed25519 (`z6Mk`) and X25519 (`z6LS`) public keys.
 */
const ED25519_MULTIBASE_PREFIX = 'z6Mk'
const X25519_MULTIBASE_PREFIX = 'z6LS'

/**
 * Validates one connect-code key all the way down to its bytes: the multibase
 * prefix, then a real base58btc decode with the multicodec header and key
 * length enforced by `decodeMultikey`. The prefix alone is worth nothing here
 * -- these keys are signed into an append-only did:webvh log, where a key
 * that only LOOKS like a multibase is published forever. The prefix check
 * stays alongside the decode: it is a stricter, deliberate spelling
 * constraint (`z6Mk` / `z6LS` exactly) the codec-level decode does not cover.
 *
 * @param options {object}
 * @param options.value {unknown}   the payload member
 * @param options.prefix {string}   the expected multibase prefix
 * @param options.expectedCodec {MultikeyCodec}   the expected multicodec
 * @param options.name {string}   the key's name, for the error message
 * @returns {string}   the key, verbatim
 */
function requireConnectCodeKey({
  value,
  prefix,
  expectedCodec,
  name
}: {
  value: unknown
  prefix: string
  expectedCodec: MultikeyCodec
  name: string
}): string {
  if (typeof value !== 'string' || !value.startsWith(prefix)) {
    throw new Error(`The connect code carries a malformed ${name}.`)
  }
  try {
    decodeMultikey({ multikey: value, expectedCodec })
  } catch (err) {
    throw new Error(`The connect code carries a malformed ${name}.`, {
      cause: err
    })
  }
  return value
}

/**
 * Encodes an enrollment request as a connect code.
 *
 * @param options {object}
 * @param options.request {EnrollmentRequest}
 * @returns {string}
 */
export function encodeEnrollmentRequest({
  request
}: {
  request: EnrollmentRequest
}): string {
  const payload = JSON.stringify({ v: CONNECT_CODE_VERSION, ...request })
  return `${CONNECT_CODE_PREFIX}${base64urlnopad.encode(
    new TextEncoder().encode(payload)
  )}`
}

/**
 * Parses and validates a connect code: the prefix, the payload version, and
 * each key decoded to its bytes (Ed25519 multibase for the signing and update
 * keys, X25519 for the key-agreement key), plus the canonicality of the
 * key-agreement key ({@link assertCanonicalEnrollmentKeys}), so the refusal
 * reaches the approver's consent screen rather than the ceremony. Throws on
 * anything malformed -- a
 * code is typed or scanned, so a clear refusal beats a half-parsed ceremony,
 * and the approving client signs these keys into an append-only log where a
 * corrupted one would be published permanently.
 *
 * @param options {object}
 * @param options.code {string}   the pasted/scanned connect code
 * @returns {EnrollmentRequest}
 */
export function parseEnrollmentRequest({
  code
}: {
  code: string
}): EnrollmentRequest {
  const trimmed = code.trim()
  if (!trimmed.startsWith(CONNECT_CODE_PREFIX)) {
    throw new Error('Not a wallet connect code.')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(
      new TextDecoder().decode(
        base64urlnopad.decode(trimmed.slice(CONNECT_CODE_PREFIX.length))
      )
    )
  } catch (err) {
    throw new Error('The connect code payload is malformed.', { cause: err })
  }
  if (parsed === null || typeof parsed !== 'object') {
    throw new Error('The connect code payload is malformed.')
  }
  const {
    v,
    signingKeyMultibase,
    keyAgreementKeyMultibase,
    updateKeyMultibase: updateKey,
    stagedUpdateKeyMultibase
  } = parsed as Record<string, unknown>
  if (v !== CONNECT_CODE_VERSION) {
    throw new Error(`Unsupported connect code version "${String(v)}".`)
  }
  const request: EnrollmentRequest = {
    signingKeyMultibase: requireConnectCodeKey({
      value: signingKeyMultibase,
      prefix: ED25519_MULTIBASE_PREFIX,
      expectedCodec: MultikeyCodec.ED25519_PUB,
      name: 'signing key'
    }),
    keyAgreementKeyMultibase: requireConnectCodeKey({
      value: keyAgreementKeyMultibase,
      prefix: X25519_MULTIBASE_PREFIX,
      expectedCodec: MultikeyCodec.X25519_PUB,
      name: 'key-agreement key'
    }),
    updateKeyMultibase: requireConnectCodeKey({
      value: updateKey,
      prefix: ED25519_MULTIBASE_PREFIX,
      expectedCodec: MultikeyCodec.ED25519_PUB,
      name: 'update key'
    }),
    stagedUpdateKeyMultibase: requireConnectCodeKey({
      value: stagedUpdateKeyMultibase,
      prefix: ED25519_MULTIBASE_PREFIX,
      expectedCodec: MultikeyCodec.ED25519_PUB,
      name: 'staged update key'
    })
  }
  assertCanonicalEnrollmentKeys({ request })
  return request
}

/**
 * Refuses a connect code whose key-agreement key is not the canonical X25519
 * twin of its signing key.
 *
 * The document publishes a client's key-agreement method under the controller
 * marker `did:key:<signing multibase>` -- a claim that the key belongs to
 * that signing key -- and every reader (the client listing, the revocation
 * removal, the roster's recipient resolver) trusts it. This check is what
 * makes the claim true: without it an enrollee could supply a key-agreement
 * key nobody else can pair with its signing key, and publishing it under the
 * marker would state something the account cannot back.
 *
 * It runs here so the refusal reaches the approver's consent screen before
 * anything is published; the write sites enforce the same rule as a backstop,
 * through `markedVerificationMethodPair`.
 *
 * @param options {object}
 * @param options.request {EnrollmentRequest}
 * @returns {void}
 */
export function assertCanonicalEnrollmentKeys({
  request
}: {
  request: EnrollmentRequest
}): void {
  const { signingKeyMultibase, keyAgreementKeyMultibase } = request
  if (
    keyAgreementKeyMultibase !==
    keyAgreementTwinMultibase({ signingKeyMultibase })
  ) {
    throw new Error(
      "The connect code's key-agreement key is not the canonical X25519 " +
        'twin of its signing key; this wallet cannot be connected. Generate ' +
        'a fresh connect code on the other wallet and try again.'
    )
  }
}

/**
 * The did:key a connect code's signing key derives -- shown on BOTH screens
 * so the person running the ceremony can compare them before approving (the
 * point-to-point verification the wrap and the document VM then inherit).
 *
 * @param options {object}
 * @param options.request {EnrollmentRequest}
 * @returns {string}
 */
export function enrollmentClientDid({
  request
}: {
  request: EnrollmentRequest
}): string {
  return `did:key:${request.signingKeyMultibase}`
}

/**
 * The kid of the enrollee's roster entry: its key-agreement key's id exactly
 * as `agentsFromSeed` will derive it at the enrollee's own logins
 * (`did:key:<ed-multibase>#<x-multibase>`), so the wrap minted here is the
 * one its first roster read looks for.
 *
 * @param options {object}
 * @param options.request {EnrollmentRequest}
 * @returns {string}
 */
export function enrollmentRecipientKid({
  request
}: {
  request: EnrollmentRequest
}): string {
  return rosterRecipientKid({
    signingKeyMultibase: request.signingKeyMultibase,
    keyAgreementKeyMultibase: request.keyAgreementKeyMultibase
  })
}

/**
 * ENROLLEE, step one: mints the new client's whole key set locally and
 * returns it alongside the connect code to display. The caller holds the
 * seeds in memory until the completion step persists them -- nothing is
 * durable before the ceremony succeeds, so abandoning it leaks at most an
 * orphan wrap on the enrolling side.
 *
 * @returns {Promise<object>}   the in-memory key set, the code, and the
 *   client did:key to display beside it for comparison
 */
export async function mintEnrollmentRequest(): Promise<{
  clientSeed: Uint8Array
  webvhUpdateKeys: ClientWebvhUpdateKeys
  code: string
  clientDid: string
}> {
  const clientSeed = crypto.getRandomValues(new Uint8Array(32))
  const { keyAgent, keyAgreementKey } = await agentsFromSeed({
    seed: clientSeed
  })
  const { publicKeyMultibase: keyAgreementKeyMultibase } =
    keyAgreementKey as unknown as { publicKeyMultibase?: string }
  if (!keyAgreementKeyMultibase) {
    throw new Error('The minted key-agreement key has no public multibase.')
  }
  const webvhUpdateKeys = await mintClientWebvhUpdateKeys()
  const request: EnrollmentRequest = {
    signingKeyMultibase: clientSigningKeyMultibase({ keyAgent }),
    keyAgreementKeyMultibase,
    updateKeyMultibase: await updateKeyMultibase({
      seed: webvhUpdateKeys.updateSeed
    }),
    stagedUpdateKeyMultibase: await updateKeyMultibase({
      seed: webvhUpdateKeys.stagedSeed
    })
  }
  return {
    clientSeed,
    webvhUpdateKeys,
    code: encodeEnrollmentRequest({ request }),
    clientDid: keyAgent.id
  }
}

/**
 * ENROLLING CLIENT: the whole approval, in the push order -- the user key
 * wrapped into the roster first (escrow: every epoch, so the new client reads
 * pre-enrollment history), then the two log entries. Quorum-of-one: this
 * client's own update key signs both entries. Idempotent at every stage, so
 * re-approving the same code after any tear converges. A request whose
 * key-agreement key is not its signing key's canonical twin is refused before
 * anything is written ({@link assertCanonicalEnrollmentKeys}).
 *
 * @param options {object}
 * @param options.request {EnrollmentRequest}   the parsed connect code
 * @param options.clientWebvhKeys {ClientWebvhUpdateKeys}   the approving
 *   client's own did:webvh update-key seeds
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   the approving
 *   client's own (identity) key-agreement key, unwrapping each epoch for
 *   re-wrapping
 * @param options.userKeyRosterStore {EncryptionDescriptorStore}   the account's
 *   `key-map/user-key.jsonl` descriptor store
 * @param options.idStore {WebvhIdStore}   the account's `id` collection
 * @returns {Promise<object>}   the account's did:webvh, plus the enrollee's
 *   own identity as this call already knows it: its did:key and its signing-key
 *   multibase (the key a label or a listing row is filed under), so the caller
 *   needs no second parse of the connect code
 */
export async function approveEnrollment({
  request,
  clientWebvhKeys,
  clientKeyAgreementKey,
  userKeyRosterStore,
  idStore
}: {
  request: EnrollmentRequest
  clientWebvhKeys: ClientWebvhUpdateKeys
  clientKeyAgreementKey: IKeyAgreementKey
  userKeyRosterStore: EncryptionDescriptorStore
  idStore: WebvhIdStore
}): Promise<{ did: string; clientDid: string; signingKeyMultibase: string }> {
  // Re-checked here rather than trusted from the parse: this is the one seam
  // every approval path runs through, and it is what publishes the key under
  // the controller marker.
  assertCanonicalEnrollmentKeys({ request })

  // Decryption material before authorization: the wrap lands first, so no
  // enrolled client is ever authorized but blind.
  await addUserKeyRosterRecipient({
    store: userKeyRosterStore,
    recipient: {
      id: enrollmentRecipientKid({ request }),
      publicKeyMultibase: request.keyAgreementKeyMultibase
    },
    ownerKeyAgreementKey: clientKeyAgreementKey
  })

  const { did } = await enrollWebvhClient({
    idStore,
    updateKeys: clientWebvhKeys,
    newClient: request
  })
  return {
    did,
    clientDid: enrollmentClientDid({ request }),
    signingKeyMultibase: request.signingKeyMultibase
  }
}

/**
 * ENROLLEE, step two (after the other client approves): verifies the
 * enrollment from the world-readable log and performs this client's first
 * roster read -- signed with its just-published `<did:webvh>#<multibase>`
 * key -- to obtain the user key.
 *
 * The portable core of the completion step: the caller supplies the account
 * pointer (from its own keyring lookup) and persists what comes back -- the
 * user key, the roster epoch to pin, and the key set itself -- under its own
 * unlock layer. After that, an ordinary unlock finds an enrolled client.
 *
 * Throws `EnrollmentPendingError` while the add entry is not published yet
 * (complete again once the other client finishes); any integrity failure
 * (a log that resolves to a different DID than the account pointer names, a
 * missing roster wrap) throws its own error.
 *
 * @param options {object}
 * @param options.clientSeed {Uint8Array}   from `mintEnrollmentRequest`
 * @param options.webvhUpdateKeys {ClientWebvhUpdateKeys}   from
 *   `mintEnrollmentRequest`
 * @param options.pointer {AccountPointer}   the account pointer the enrollee's
 *   keyring lookup recovered
 * @param [options.accountLogPinStore] {ResourceLogPinStore}   this client's
 *   chain-head pin for the account log. A freshly enrolling client normally
 *   has none (this read is its first contact), which is exactly the pin's
 *   trust-on-first-use establishment
 * @returns {Promise<{ userKey: UserKey, latestEpochId: string }>}
 */
export async function completeEnrollmentCore({
  clientSeed,
  webvhUpdateKeys,
  pointer,
  accountLogPinStore
}: {
  clientSeed: Uint8Array
  webvhUpdateKeys: ClientWebvhUpdateKeys
  pointer: AccountPointer
  accountLogPinStore?: ResourceLogPinStore
}): Promise<{ userKey: UserKey; latestEpochId: string }> {
  const did = pointer.did
  if (!did || !isWebvhDid(did)) {
    throw new Error(
      'The account pointer names no did:webvh; only a promoted account can ' +
        'enroll additional clients.'
    )
  }

  const { keyAgent, keyAgreementKey } = await agentsFromSeed({
    seed: clientSeed
  })

  // Verify the enrollment from the world-readable, self-certifying log: it
  // must resolve to exactly the DID the account pointer names, and its
  // document must list this client's keys -- the add entry has published. An
  // absent log is the same "not yet" state as an unpublished add entry.
  let verified
  try {
    verified = await verifyAccountLog({
      did,
      spaceId: pointer.spaceId,
      host: pointer.host,
      ...(accountLogPinStore ? { pinStore: accountLogPinStore } : {})
    })
  } catch (err) {
    if (err instanceof AccountLogMissingError) {
      throw new EnrollmentPendingError()
    }
    throw err
  }
  const signingMultibase = clientSigningKeyMultibase({ keyAgent })
  const updateKey = await updateKeyMultibase({
    seed: webvhUpdateKeys.updateSeed
  })
  const enrolled =
    (verified.doc.verificationMethod ?? []).some(
      method => method.publicKeyMultibase === signingMultibase
    ) && verified.updateKeys.includes(updateKey)
  if (!enrolled) {
    throw new EnrollmentPendingError()
  }

  // The first roster read: signed with the `<did:webvh>#<multibase>` keyId
  // the add entry just published, unwrapping the user key the enrolling client
  // escrowed to this client's key-agreement key. The account log just
  // verified above is the controller the roster log's entry proofs are
  // checked against -- a first read adopts whatever head the log serves, so
  // every entry must trace to keys the document backs, not to the served
  // descriptor's own MAC. First contact: the chain-head pin this read
  // establishes is session-local here; the app's durable pin is established
  // by its own first login read.
  const zcapClient = webvhZcapClient({ keyAgent, did })
  const store = userKeyRosterDescriptorStore({
    storageServerUrl: pointer.host,
    zcapClient,
    spaceId: pointer.spaceId,
    resolveController: async () =>
      webvhResourceLogController({ did, log: verified.log }),
    pinStore: memoryResourceLogPinStore(),
    signer: userKeyRosterLogSigner({ keyAgent })
  })
  const read = await readUserKeyRoster({
    store,
    clientKeyAgreementKey: keyAgreementKey
  })
  if (!read) {
    throw new Error(
      'The account has no user key roster; it must finish provisioning before ' +
        'a client can be enrolled.'
    )
  }
  return { userKey: read.userKey, latestEpochId: read.latestEpochId }
}
