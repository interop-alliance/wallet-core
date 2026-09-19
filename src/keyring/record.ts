/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The keyring record codec: the `{ version, encryption, wrapped, proof }`
 * envelope stored as the one resource of an account's unlock Space. Its
 * plaintext carries the account controller, the email captured at bind time,
 * the account pointer, and the bind timestamp -- and deliberately no key
 * material of any kind, so the record locates an account without authorizing
 * anything against it.
 *
 * The envelope half (the record's own key epoch, its ciphers, the frame and
 * plaintext parsing) is `recordEnvelope.ts`. This file is the authenticity
 * layer over it, plus the keyring wrap and unwrap that need both halves.
 *
 * The authenticity layer is the `proof` member, and it is load-bearing: the
 * unlock KAK's public half is derivable from the unlock did:key the server
 * stores as the unlock Space's controller, so a malicious storage host can
 * seal a record of its own that decrypts perfectly. Confidentiality was never
 * the missing property. So a record carries an eddsa-jcs-2022 Data Integrity
 * proof over its sibling members (`version`, `encryption`, `wrapped`), signed
 * by the unlock identity's Ed25519 key -- which derives from the unlock secret,
 * so a fresh client holds the verification prior by construction and the
 * server never holds the signing key. The proof is verified BEFORE the record
 * is decrypted, and there is no unwrap path that skips it. Because the
 * signature covers the ciphertext, the encrypted bind timestamp is covered
 * transitively while staying inside the plaintext, so bind times do not leak
 * to a reader of the unlock Space.
 */
import {
  createDataIntegrityProofTemplate,
  defaultWebvhLogVerifier,
  signDataIntegrityProof,
  signerFromExternalKey,
  verifyEntryProofs
} from '@interop/did-method-webvh'
import type { SignableDocument } from '@interop/did-method-webvh'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import { vmFragmentOf } from '@interop/vh-resource-log'
import {
  KEYRING_RECORD_VERSION,
  RecordProofError,
  checkRecordProofShape,
  mintRecordEncryption,
  parseRecordCreatedAt,
  parseRecordFrame,
  parseRecordPointer,
  recordCipher,
  recordCreatedAtStamp,
  recordEnvelopeId,
  recordSealCipher
} from './recordEnvelope.js'
import type {
  AccountPointer,
  KeyringRecordContents,
  RecordProof,
  SignedRecord
} from './recordEnvelope.js'

/**
 * The record signer's seam: the signing key's public multibase (which names
 * the key in the proof's `verificationMethod`) and a raw detached-signature
 * hook over it. Structurally the resource log's `ResourceLogSigner`, so one
 * adapter feeds both, deliberately restated here rather than imported -- a
 * record is not a log, and the keyring module keeps its own vocabulary.
 */
export interface RecordSigner {
  keyMultibase: string
  sign(input: { data: Uint8Array }): Promise<Uint8Array>
}

/**
 * Adapts a signing key agent (the unlock identity's `CapabilityAgent`, or an
 * enrolled client's own key agent) to the record signer seam: the agent's
 * did:key id supplies the public multibase, its signer the raw signature.
 *
 * @param options {object}
 * @param options.keyAgent {object}   a did:key `CapabilityAgent`-shaped agent
 * @returns {RecordSigner}
 */
export function recordSignerFromAgent({
  keyAgent
}: {
  keyAgent: {
    id: string
    getSigner: () => {
      sign: (input: { data: Uint8Array }) => Promise<Uint8Array>
    }
  }
}): RecordSigner {
  const [scheme, method, keyMultibase] = keyAgent.id.split(':')
  if (scheme !== 'did' || method !== 'key' || !keyMultibase) {
    throw new Error(`Not a did:key agent id: "${keyAgent.id}".`)
  }
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
 * Adapts a raw 32-byte Ed25519 seed to the record signer seam, for a signing
 * key that is derived on demand rather than held by an agent -- the user key's
 * signing half (`userKeyRecordSigner` in `keys/userKey.ts`) is the one such
 * key today. The seed IS the key material, so the same seed always names the
 * same `keyMultibase`, and a reader that can derive the seed holds the
 * verification prior by construction.
 *
 * @param options {object}
 * @param options.seed {Uint8Array}   the 32-byte Ed25519 seed
 * @returns {Promise<RecordSigner>}
 */
export async function recordSignerFromSeed({
  seed
}: {
  seed: Uint8Array
}): Promise<RecordSigner> {
  const keyPair = await Ed25519VerificationKey.generate({ seed })
  return recordSignerFromAgent({
    keyAgent: {
      id: `did:key:${keyPair.publicKeyMultibase}`,
      getSigner: () => keyPair.didKeySigner()
    }
  })
}

/**
 * Signs a record's frame members and returns the stored signed record. Shared
 * by the keyring and recovery wrap paths (and available to an app's own record
 * kinds), so one construction produces every signed record: the proof covers
 * `{ version, encryption, wrapped }` plus any record-kind members under JCS
 * canonicalization.
 *
 * @param options {object}
 * @param options.version {number}   the frame version to stamp
 * @param options.encryption {CollectionEncryption}   the record's descriptor
 * @param options.wrapped {unknown}   the sealed envelope
 * @param options.signer {RecordSigner}   the signing key
 * @param [options.members] {object}   additional record-kind frame members the
 *   proof must cover (e.g. the recovery record's `binding`)
 * @returns {Promise<SignedRecord>}
 */
export async function signRecordFrame({
  version,
  encryption,
  wrapped,
  signer,
  members
}: {
  version: number
  encryption: CollectionEncryption
  wrapped: unknown
  signer: RecordSigner
  members?: Record<string, unknown>
}): Promise<SignedRecord> {
  const frame = { version, encryption, wrapped, ...(members ?? {}) }
  const proofTemplate = createDataIntegrityProofTemplate({
    verificationMethod: `did:key:${signer.keyMultibase}#${signer.keyMultibase}`
  })
  const proof = await signDataIntegrityProof(
    // The kernel types its signable documents as did:webvh artifacts, but the
    // construction is generic (JCS canonicalization over whatever it is
    // handed), so the record frame rides through as one.
    frame as unknown as SignableDocument,
    proofTemplate,
    signerFromExternalKey({
      publicKeyMultibase: signer.keyMultibase,
      sign: signer.sign
    })
  )
  return { ...frame, proof: proof as RecordProof }
}

/**
 * The signing key's public multibase named by a proof's `verificationMethod`:
 * its fragment. The signer emits `did:key:<multibase>#<multibase>`; the DID
 * half is not what authorizes anything -- the multibase IS the key, and the
 * caller's allowlist decides whether it may sign this record.
 *
 * @param options {object}
 * @param options.verificationMethod {string}
 * @param options.label {string}   names the record kind in the refusal
 * @returns {string}
 */
export function recordProofKeyMultibase({
  verificationMethod,
  label
}: {
  verificationMethod: string
  label: string
}): string {
  const keyMultibase = vmFragmentOf(verificationMethod)
  if (!keyMultibase) {
    throw new RecordProofError(
      `The ${label} record's proof names a verification method with no key ` +
        `fragment.`
    )
  }
  return keyMultibase
}

/**
 * Verifies a stored record's proof: the fixed proof shape, the signing key
 * against the caller's allowlist, and the signature over the record's sibling
 * members (everything except `proof`, JCS-canonicalized). Refuses with
 * {@link RecordProofError} in every failing case -- a class of its own, so an
 * app tells "the host forged or tampered with this record" apart from a wrong
 * unlock secret or an unusable version.
 *
 * Standalone as well as internal, because the recovery record's re-minted
 * signer is only knowable after the record is decrypted (see
 * `unwrapRecoveryRecord`).
 *
 * @param options {object}
 * @param options.record {unknown}   the stored record, proof included
 * @param options.allowedKeyMultibases {string | string[]}   the signing keys
 *   this caller accepts, as public multibases or as verification-method ids
 *   whose fragment is one
 * @param [options.label] {string}   names the record kind in refusals;
 *   defaults to the keyring record
 * @returns {Promise<string>}   the verified signing key's public multibase
 */
export async function verifyRecordProof({
  record,
  allowedKeyMultibases,
  label = 'keyring'
}: {
  record: unknown
  allowedKeyMultibases: string | string[]
  label?: string
}): Promise<string> {
  if (record === null || typeof record !== 'object') {
    throw new RecordProofError(`Malformed ${label} record.`)
  }
  const { proof, ...frame } = record as { proof?: unknown }
  const checked = checkRecordProofShape({ proof, label })
  const keyMultibase = recordProofKeyMultibase({
    verificationMethod: checked.verificationMethod,
    label
  })
  const allowed = new Set(
    (typeof allowedKeyMultibases === 'string'
      ? [allowedKeyMultibases]
      : allowedKeyMultibases
    ).map(entry => vmFragmentOf(entry) ?? entry)
  )
  if (!allowed.has(keyMultibase)) {
    throw new RecordProofError(
      `The ${label} record is signed by a key this client does not accept ` +
        `for it ("${keyMultibase}").`
    )
  }
  try {
    await verifyEntryProofs(
      { ...frame, proof: checked } as Parameters<typeof verifyEntryProofs>[0],
      {
        verifier: defaultWebvhLogVerifier,
        // Authorization is the allowlist check above, made before any
        // cryptography runs; the key material resolves from the proof's own
        // verification method, which that check has already pinned.
        authorize: () => {},
        resolveVM: async () => ({ publicKeyMultibase: keyMultibase })
      }
    )
  } catch (err) {
    throw new RecordProofError(
      `The ${label} record's proof does not verify over its contents.`,
      { cause: err }
    )
  }
  return keyMultibase
}

/**
 * Wraps the account-pointer contents into a keyring record: the controller,
 * email, and pointer (+ timestamp) sealed under a freshly minted record epoch
 * whose key is wrapped to the unlock KAK, then signed by the unlock identity's
 * signing key. Deliberately carries no key material of any kind.
 *
 * The timestamp stays inside the plaintext (the signature covers the
 * ciphertext, so it is covered transitively), so bind times do not leak to a
 * reader of the unlock Space.
 *
 * @param options {object}
 * @param options.controller {string}   the account did:key
 * @param [options.email] {string}   the account email, when known
 * @param [options.pointer] {AccountPointer}   the account pointer (absent on
 *   no-WAS deployments)
 * @param options.keyAgreementKey {IKeyAgreementKey}   the unlock KAK (its
 *   public half is all the wrap uses: sealing needs no key-agreement secret)
 * @param options.signer {RecordSigner}   the unlock identity's signing key
 *   (`recordSignerFromAgent` over the unlock agent)
 * @param [options.createdAt] {string}   the bind timestamp to stamp, as an ISO
 *   string; defaults to now. Supplied by a caller that pins record freshness,
 *   so it knows the stamp without unwrapping the record it just wrote.
 * @returns {Promise<SignedRecord>}
 */
export async function wrapKeyringRecord({
  controller,
  email,
  pointer,
  keyAgreementKey,
  signer,
  createdAt
}: {
  controller: string
  email?: string
  pointer?: AccountPointer
  keyAgreementKey: IKeyAgreementKey
  signer: RecordSigner
  createdAt?: string
}): Promise<SignedRecord> {
  const encryption = await mintRecordEncryption({ keyAgreementKey })
  const cipher = await recordSealCipher({ encryption })
  const { envelope } = await cipher.encrypt({
    data: {
      controller,
      ...(email ? { email } : {}),
      ...(pointer
        ? {
            pointer: {
              ...(pointer.did ? { did: pointer.did } : {}),
              spaceId: pointer.spaceId,
              host: pointer.host
            }
          }
        : {}),
      createdAt: recordCreatedAtStamp({ createdAt })
    }
  })
  return signRecordFrame({
    version: KEYRING_RECORD_VERSION,
    encryption,
    wrapped: envelope,
    signer
  })
}

/**
 * Unwraps and validates a keyring record. Verifies the record's proof against
 * the unlock identity's own signing key BEFORE decrypting -- there is no
 * unwrap path that skips it, so a record the storage host substituted is
 * refused ({@link RecordProofError}) rather than decrypted and inspected.
 * Rejects a record whose `version` is not the current one (accounts are
 * re-provisioned, not migrated), and sanity-checks the decrypted plaintext
 * (non-empty controller, well-formed pointer when present, a parseable
 * `createdAt`).
 *
 * @param options {object}
 * @param options.record {unknown}
 * @param options.keyAgreementKey {IKeyAgreementKey}   the unlock KAK
 * @param options.keyResolver {IKeyResolver}
 * @param options.expectedKeyMultibase {string}   the unlock identity's signing
 *   key multibase, derived from the typed secret -- the only key that may have
 *   signed this record
 * @returns {Promise<KeyringRecordContents>}
 */
export async function unwrapKeyringRecord({
  record,
  keyAgreementKey,
  keyResolver,
  expectedKeyMultibase
}: {
  record: unknown
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  expectedKeyMultibase: string
}): Promise<KeyringRecordContents> {
  const { encryption, wrapped } = parseRecordFrame({
    record,
    label: 'keyring'
  })
  await verifyRecordProof({
    record,
    allowedKeyMultibases: expectedKeyMultibase,
    label: 'keyring'
  })
  const cipher = await recordCipher({
    keyAgreementKey,
    keyResolver,
    encryption
  })
  const plaintext = (await cipher.decrypt({
    id: recordEnvelopeId({ wrapped, label: 'keyring' }),
    envelope: wrapped as never
  })) as {
    controller?: unknown
    email?: unknown
    pointer?: unknown
    createdAt?: unknown
  }

  if (typeof plaintext.controller !== 'string' || !plaintext.controller) {
    throw new Error('Keyring record is missing a controller.')
  }
  const pointer = parseRecordPointer(plaintext.pointer)
  const createdAt = parseRecordCreatedAt({
    value: plaintext.createdAt,
    label: 'Keyring'
  })

  return {
    controller: plaintext.controller,
    createdAt,
    // A record bound without an email simply has no email; anything
    // non-string is ignored, not fatal.
    ...(typeof plaintext.email === 'string' && plaintext.email
      ? { email: plaintext.email }
      : {}),
    ...(pointer ? { pointer } : {})
  }
}
