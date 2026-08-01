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
import { readLogFromString, resolveDIDFromLog } from '@interop/did-method-webvh'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import { base64urlnopad } from '@scure/base'
import { agentsFromSeed } from '../identity/agents.js'
import { DID_LOG_RESOURCE, ID_COLLECTION } from '../space/collections.js'
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
import { addPukRosterRecipient } from '../keys/pukRoster.js'
import { readPukRoster } from '../keys/pukRoster.js'
import { pukRosterDescriptorStore } from '../keys/rosterStore.js'
import type { Puk } from '../keys/puk.js'
import type { AccountPointer } from '../keyring/record.js'

/**
 * The connect-code prefix; the payload after it is base64url(JSON) of an
 * `EnrollmentRequest` plus a `v` version stamp.
 */
const CONNECT_CODE_PREFIX = 'freewallet-connect:'

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
 * the shape of each key (Ed25519 multibase for the signing and update keys,
 * X25519 for the key-agreement key). Throws on anything malformed -- a code
 * is typed or scanned, so a clear refusal beats a half-parsed ceremony.
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
  const requireKey = (value: unknown, prefix: string, name: string): string => {
    if (typeof value !== 'string' || !value.startsWith(prefix)) {
      throw new Error(`The connect code carries a malformed ${name}.`)
    }
    return value
  }
  return {
    signingKeyMultibase: requireKey(
      signingKeyMultibase,
      ED25519_MULTIBASE_PREFIX,
      'signing key'
    ),
    keyAgreementKeyMultibase: requireKey(
      keyAgreementKeyMultibase,
      X25519_MULTIBASE_PREFIX,
      'key-agreement key'
    ),
    updateKeyMultibase: requireKey(
      updateKey,
      ED25519_MULTIBASE_PREFIX,
      'update key'
    ),
    stagedUpdateKeyMultibase: requireKey(
      stagedUpdateKeyMultibase,
      ED25519_MULTIBASE_PREFIX,
      'staged update key'
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
  return `${enrollmentClientDid({ request })}#${request.keyAgreementKeyMultibase}`
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
 * @returns {Promise<{ did: string }>}   the account's did:webvh
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
}): Promise<{ did: string }> {
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

  return enrollWebvhClient({
    idStore,
    updateKeys: clientWebvhKeys,
    newClient: request
  })
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
  // document must list this client's keys -- the add entry has published.
  const logUrl = new URL(
    `/space/${pointer.spaceId}/${ID_COLLECTION.id}/${DID_LOG_RESOURCE}`,
    pointer.host
  )
  const response = await fetch(logUrl)
  if (response.status === 404) {
    throw new EnrollmentPendingError()
  }
  if (!response.ok) {
    throw new Error(
      `Fetching the account's DID log failed (HTTP ${response.status}).`
    )
  }
  const resolved = await resolveDIDFromLog(
    readLogFromString(await response.text())
  )
  if (resolved.meta.error || !resolved.did || !resolved.doc) {
    throw new Error(
      `The account's DID log failed to resolve (${resolved.meta.error}).`
    )
  }
  if (resolved.did !== did) {
    throw new Error(
      'The published DID log resolves to a different DID than the account ' +
        'pointer names.'
    )
  }
  const signingMultibase = clientSigningKeyMultibase({ keyAgent })
  const updateKey = await updateKeyMultibase({
    seed: webvhUpdateKeys.updateSeed
  })
  const enrolled =
    (resolved.doc.verificationMethod ?? []).some(
      method => method.publicKeyMultibase === signingMultibase
    ) && (resolved.meta.updateKeys ?? []).includes(updateKey)
  if (!enrolled) {
    throw new EnrollmentPendingError()
  }

  // The first roster read: signed with the `<did:webvh>#<multibase>` keyId
  // the add entry just published, unwrapping the PUK the enrolling client
  // escrowed to this client's key-agreement key.
  const zcapClient = webvhZcapClient({ keyAgent, did })
  const store = pukRosterDescriptorStore({
    storageServerUrl: pointer.host,
    zcapClient,
    spaceId: pointer.spaceId
  })
  const read = await readPukRoster({
    store,
    clientKeyAgreementKey: keyAgreementKey
  })
  if (!read) {
    throw new Error(
      'The account has no PUK roster; it must finish provisioning before ' +
        'a client can be enrolled.'
    )
  }
  return { puk: read.puk, latestEpochId: read.latestEpochId }
}
