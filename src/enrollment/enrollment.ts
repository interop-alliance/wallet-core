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
 * the PUK comes back through the wrap-set roster.
 *
 * Push, not pull, in the recovery-anchor order (decryption material before
 * authorization): the enrolling client wraps the PUK to the new client's
 * key-agreement key in `key-map/puk.json` FIRST, then writes the two
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
 * back the PUK and the roster epoch to pin, and stops there.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import { base64urlnopad } from '@scure/base'
import {
  multibaseDecode,
  MULTICODEC_X25519_PUB_HEADER
} from '@interop/x25519-key-agreement-key'
import { agentsFromSeed } from '../identity/agents.js'
import {
  enrollWebvhClient,
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
import { addPukRosterRecipient } from '../keys/pukRoster.js'
import { readPukRoster, rosterRecipientKid } from '../keys/pukRoster.js'
import { pukRosterDescriptorStore } from '../keys/rosterStore.js'
import type { Puk } from '../keys/puk.js'
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
 * The multicodec varint header of an `ed25519-pub` value, the registry
 * constant the `z6Mk` prefix renders. The X25519 counterpart is imported from
 * the key suite that owns it; there is no exported Ed25519 equivalent.
 */
const MULTICODEC_ED25519_PUB_HEADER = new Uint8Array([0xed, 0x01])

/**
 * The byte length of both public key types a connect code carries.
 */
const PUBLIC_KEY_BYTES = 32

/**
 * Validates one connect-code key all the way down to its bytes: the multibase
 * prefix, a real base58btc decode, the multicodec header, and the key length.
 * The prefix alone is worth nothing here -- these keys are signed into an
 * append-only did:webvh log, where a key that only LOOKS like a multibase is
 * published forever.
 *
 * @param options {object}
 * @param options.value {unknown}   the payload member
 * @param options.prefix {string}   the expected multibase prefix
 * @param options.header {Uint8Array}   the expected multicodec header bytes
 * @param options.name {string}   the key's name, for the error message
 * @returns {string}   the key, verbatim
 */
function requireConnectCodeKey({
  value,
  prefix,
  header,
  name
}: {
  value: unknown
  prefix: string
  header: Uint8Array
  name: string
}): string {
  if (typeof value !== 'string' || !value.startsWith(prefix)) {
    throw new Error(`The connect code carries a malformed ${name}.`)
  }
  let bytes: Uint8Array
  try {
    bytes = multibaseDecode(header, value)
  } catch (err) {
    throw new Error(`The connect code carries a malformed ${name}.`, {
      cause: err
    })
  }
  if (bytes.length !== PUBLIC_KEY_BYTES) {
    throw new Error(`The connect code carries a malformed ${name}.`)
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
 * keys, X25519 for the key-agreement key). Throws on anything malformed -- a
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
  return {
    signingKeyMultibase: requireConnectCodeKey({
      value: signingKeyMultibase,
      prefix: ED25519_MULTIBASE_PREFIX,
      header: MULTICODEC_ED25519_PUB_HEADER,
      name: 'signing key'
    }),
    keyAgreementKeyMultibase: requireConnectCodeKey({
      value: keyAgreementKeyMultibase,
      prefix: X25519_MULTIBASE_PREFIX,
      header: MULTICODEC_X25519_PUB_HEADER,
      name: 'key-agreement key'
    }),
    updateKeyMultibase: requireConnectCodeKey({
      value: updateKey,
      prefix: ED25519_MULTIBASE_PREFIX,
      header: MULTICODEC_ED25519_PUB_HEADER,
      name: 'update key'
    }),
    stagedUpdateKeyMultibase: requireConnectCodeKey({
      value: stagedUpdateKeyMultibase,
      prefix: ED25519_MULTIBASE_PREFIX,
      header: MULTICODEC_ED25519_PUB_HEADER,
      name: 'staged update key'
    })
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
 * ENROLLING CLIENT: the whole approval, in the push order -- the PUK wrapped
 * into the roster first (escrow: every epoch, so the new client reads
 * pre-enrollment history), then the two log entries. Quorum-of-one: this
 * client's own update key signs both entries. Idempotent at every stage, so
 * re-approving the same code after any tear converges.
 *
 * @param options {object}
 * @param options.request {EnrollmentRequest}   the parsed connect code
 * @param options.clientWebvhKeys {ClientWebvhUpdateKeys}   the approving
 *   client's own did:webvh update-key seeds
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   the approving
 *   client's own (identity) key-agreement key, unwrapping each epoch for
 *   re-wrapping
 * @param options.pukRosterStore {EncryptionDescriptorStore}   the account's
 *   `key-map/puk.json` descriptor store
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
  pukRosterStore,
  idStore
}: {
  request: EnrollmentRequest
  clientWebvhKeys: ClientWebvhUpdateKeys
  clientKeyAgreementKey: IKeyAgreementKey
  pukRosterStore: EncryptionDescriptorStore
  idStore: WebvhIdStore
}): Promise<{ did: string; clientDid: string; signingKeyMultibase: string }> {
  // Decryption material before authorization: the wrap lands first, so no
  // enrolled client is ever authorized but blind.
  await addPukRosterRecipient({
    store: pukRosterStore,
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
 * key -- to obtain the PUK.
 *
 * The portable core of the completion step: the caller supplies the account
 * pointer (from its own keyring lookup) and persists what comes back -- the
 * PUK, the roster epoch to pin, and the key set itself -- under its own unlock
 * layer. After that, an ordinary unlock finds an enrolled client.
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
 * @returns {Promise<{ puk: Puk, latestEpochId: string }>}
 */
export async function completeEnrollmentCore({
  clientSeed,
  webvhUpdateKeys,
  pointer
}: {
  clientSeed: Uint8Array
  webvhUpdateKeys: ClientWebvhUpdateKeys
  pointer: AccountPointer
}): Promise<{ puk: Puk; latestEpochId: string }> {
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
      host: pointer.host
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
  // the add entry just published, unwrapping the PUK the enrolling client
  // escrowed to this client's key-agreement key. The verified document just
  // resolved above is what the roster's epoch-configuration signature is
  // checked against -- a first read adopts whatever epoch the roster serves,
  // so it must trace to a key the document backs, not to the served
  // descriptor's own MAC.
  const zcapClient = webvhZcapClient({ keyAgent, did })
  const store = pukRosterDescriptorStore({
    storageServerUrl: pointer.host,
    zcapClient,
    spaceId: pointer.spaceId
  })
  const read = await readPukRoster({
    store,
    clientKeyAgreementKey: keyAgreementKey,
    document: verified.doc
  })
  if (!read) {
    throw new Error(
      'The account has no PUK roster; it must finish provisioning before ' +
        'a client can be enrolled.'
    )
  }
  return { puk: read.puk, latestEpochId: read.latestEpochId }
}
