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
 * The wrap is an EDV document envelope sealed under the record's own key
 * epoch: every EDV envelope seals to an epoch key, so the record carries its
 * one-epoch descriptor in its `encryption` member, epoch[0] wrapped to the
 * unlock key-agreement key. The record stays self-contained -- unlock KAK in,
 * contents out. The cipher's `keyring` collection context labels errors only
 * (the codec is agnostic to it).
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
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import {
  createEdvDocCipher,
  initRecipients,
  ownerRecipient,
  type DocCipher,
  type EncryptionDescriptorStore
} from '@interop/was-client/edv'
import { KEYRING_COLLECTION } from '../space/collections.js'

/**
 * The version stamped on the stored `{ version, encryption, wrapped, proof }`
 * keyring envelope: the signed record, whose envelope seals under the record's
 * own key epoch (the `encryption` member) and whose sibling members carry a
 * Data Integrity proof by the unlock identity's signing key. Any other version
 * is refused as unusable -- such accounts are re-provisioned, not migrated.
 */
export const KEYRING_RECORD_VERSION = 2

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
 * The fixed proof shape a signed record carries: an eddsa-jcs-2022 Data
 * Integrity proof over the record's sibling members, `assertionMethod`
 * purpose, with the signing key named by a `did:key:<multibase>#<multibase>`
 * verification method.
 */
export interface RecordProof {
  type: 'DataIntegrityProof'
  cryptosuite: 'eddsa-jcs-2022'
  verificationMethod: string
  proofPurpose: 'assertionMethod'
  created?: string
  proofValue: string
}

/**
 * A stored signed record: the frame members the proof secures, plus the proof
 * itself.
 */
export interface SignedRecord {
  version: number
  encryption: CollectionEncryption
  wrapped: unknown
  proof: RecordProof
}

/**
 * A record's proof is absent, malformed, signed by a key this client does not
 * accept, or does not verify over the record's own members. Its own class,
 * distinct from a decrypt failure or an unusable-version refusal: this is the
 * refusal that says the storage host forged or tampered with the record, which
 * an app maps to its own login copy.
 */
export class RecordProofError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'RecordProofError'
  }
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
    getSigner: () => { sign: (input: { data: Uint8Array }) => Promise<Uint8Array> }
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
 * Signs a record's frame members and returns the stored signed record. Shared
 * by the keyring and recovery wrap paths (and available to an app's own record
 * kinds), so one construction produces every signed record: the proof covers
 * exactly `{ version, encryption, wrapped }` under JCS canonicalization.
 *
 * @param options {object}
 * @param options.version {number}   the frame version to stamp
 * @param options.encryption {CollectionEncryption}   the record's descriptor
 * @param options.wrapped {unknown}   the sealed envelope
 * @param options.signer {RecordSigner}   the signing key
 * @returns {Promise<SignedRecord>}
 */
export async function signRecordFrame({
  version,
  encryption,
  wrapped,
  signer
}: {
  version: number
  encryption: CollectionEncryption
  wrapped: unknown
  signer: RecordSigner
}): Promise<SignedRecord> {
  const frame = { version, encryption, wrapped }
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
 * Structural check of a record's `proof` member against the fixed shape,
 * before any cryptography runs.
 *
 * @param options {object}
 * @param options.proof {unknown}
 * @param options.label {string}   names the record kind in the refusal
 * @returns {RecordProof}
 */
function checkRecordProofShape({
  proof,
  label
}: {
  proof: unknown
  label: string
}): RecordProof {
  const candidate = proof as Partial<RecordProof> | null
  if (
    candidate === null ||
    typeof candidate !== 'object' ||
    candidate.type !== 'DataIntegrityProof' ||
    candidate.cryptosuite !== 'eddsa-jcs-2022' ||
    candidate.proofPurpose !== 'assertionMethod' ||
    typeof candidate.verificationMethod !== 'string' ||
    typeof candidate.proofValue !== 'string'
  ) {
    throw new RecordProofError(
      `The ${label} record carries no proof in the fixed shape ` +
        `(DataIntegrityProof / eddsa-jcs-2022 / assertionMethod).`
    )
  }
  return candidate as RecordProof
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
  const hashIndex = verificationMethod.lastIndexOf('#')
  const keyMultibase =
    hashIndex === -1 ? '' : verificationMethod.slice(hashIndex + 1)
  if (!keyMultibase) {
    throw new RecordProofError(
      `The ${label} record's proof names a verification method with no key ` +
        `fragment.`
    )
  }
  return keyMultibase
}

/**
 * Mints the one-epoch descriptor a fresh record is sealed under: epoch[0]
 * wrapped to the given KAK alone, built through `initRecipients` against a
 * throwaway in-memory store (the descriptor's home is the record itself).
 * Exported for any consumer sealing a self-contained
 * `{ version, encryption, wrapped }` record -- the keyring and recovery
 * records here, and a wallet app's own locally stored records (e.g.
 * freewallet's client-key record and unlock-methods registry).
 *
 * @param options {object}
 * @param options.keyAgreementKey {IKeyAgreementKey}   the wrapping KAK (for
 *   the keyring record, the unlock KAK)
 * @returns {Promise<CollectionEncryption>}
 */
export async function mintRecordEncryption({
  keyAgreementKey
}: {
  keyAgreementKey: IKeyAgreementKey
}): Promise<CollectionEncryption> {
  let stored: CollectionEncryption | null = null
  const store: EncryptionDescriptorStore = {
    async read() {
      return stored ? { descriptor: stored } : null
    },
    async replace(next) {
      stored = next
    },
    async create(next) {
      stored = next
    }
  }
  return initRecipients({
    store,
    recipients: [ownerRecipient({ keyAgreementKey })]
  })
}

/**
 * Builds the record cipher: an EDV cipher over the record's own descriptor.
 * Shared by the wrap and unwrap paths (and by the recovery record, which
 * reuses the keyring cipher context verbatim); an app's own record kind
 * passes its own `collectionId` so its failures name the record kind. The
 * context labels errors only -- the codec is agnostic to it, so a record
 * kind's real swap protection is its contents validation on unwrap.
 *
 * @param options {object}
 * @param options.keyAgreementKey {IKeyAgreementKey}   the wrapping KAK (for
 *   the keyring record, the unlock KAK)
 * @param options.keyResolver {IKeyResolver}
 * @param options.encryption {CollectionEncryption}   the record's descriptor
 * @param [options.collectionId] {string}   the cipher context failures are
 *   labeled with; defaults to the keyring context
 * @returns {Promise<DocCipher>}
 */
export async function recordCipher({
  keyAgreementKey,
  keyResolver,
  encryption,
  collectionId = KEYRING_COLLECTION.id
}: {
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  encryption: CollectionEncryption
  collectionId?: string
}): Promise<DocCipher> {
  return createEdvDocCipher({
    keyAgreementKey,
    keyResolver,
    collectionId,
    encryption
  })
}

/**
 * Validates the common `{ version, encryption, wrapped }` frame of a stored
 * record (keyring or recovery -- `label` names the refusals) and returns its
 * members, the `proof` among them for the signed frame. Exported so an app's
 * own record kinds open their records through the same frame validation the
 * codec here seals with, rather than re-deriving the version and shape checks.
 *
 * A frame at the keyring record version is the signed frame, so it must carry
 * a fixed-shape proof; a record kind stamping its own version is unaffected
 * (its authenticity story is its own). Validating the shape here does not
 * verify it -- {@link verifyRecordProof} does, and every unwrap path in this
 * module runs it before decrypting.
 *
 * @param options {object}
 * @param options.record {unknown}
 * @param options.label {string}   `'keyring'`, `'recovery'`, or an app record
 *   kind's own label
 * @param [options.version] {number}   the version the frame must carry;
 *   defaults to the keyring record version
 * @returns {{ encryption: CollectionEncryption, wrapped: unknown,
 *   proof?: RecordProof }}
 */
export function parseRecordFrame({
  record,
  label,
  version = KEYRING_RECORD_VERSION
}: {
  record: unknown
  label: string
  version?: number
}): {
  encryption: CollectionEncryption
  wrapped: unknown
  proof?: RecordProof
} {
  if (record === null || typeof record !== 'object') {
    throw new Error(`Malformed ${label} record.`)
  }
  const {
    version: recordVersion,
    encryption,
    wrapped,
    proof
  } = record as {
    version?: unknown
    encryption?: unknown
    wrapped?: unknown
    proof?: unknown
  }
  if (recordVersion !== version) {
    // Two retired version-1 shapes are named rather than reported as an
    // unsupported number, so neither refusal is read as corruption: the
    // pre-extraction record (a data-seed wrap with no descriptor) and the
    // unsigned envelope this version's proof replaced. Both are unusable.
    if (version === KEYRING_RECORD_VERSION && recordVersion === 1) {
      if (encryption === undefined) {
        throw new Error(
          `The ${label} record uses the retired pre-extraction version 1 ` +
            'shape (a data-seed wrap with no encryption descriptor); such ' +
            'accounts are re-provisioned, not migrated.'
        )
      }
      throw new Error(
        `The ${label} record uses the retired unsigned version 1 shape (no ` +
          'proof over its frame, so a storage host could substitute it); ' +
          'such accounts are re-provisioned, not migrated.'
      )
    }
    throw new Error(
      `Unsupported ${label} record version "${String(recordVersion)}".`
    )
  }
  if (wrapped === undefined || wrapped === null) {
    throw new Error(`Malformed ${label} record.`)
  }
  if (encryption === null || typeof encryption !== 'object') {
    throw new Error(`The ${label} record is missing its encryption descriptor.`)
  }
  return {
    encryption: encryption as CollectionEncryption,
    wrapped,
    ...(version === KEYRING_RECORD_VERSION
      ? { proof: checkRecordProofShape({ proof, label }) }
      : {})
  }
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
    ).map(entry => {
      const hashIndex = entry.lastIndexOf('#')
      return hashIndex === -1 ? entry : entry.slice(hashIndex + 1)
    })
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
 * The account pointer a keyring record carries in place of the retired data
 * seed: where the account lives (`spaceId` + `host`, the WAS server origin)
 * and, once provisioning has published it, the account's stable did:webvh id.
 * Discovery only -- holding the pointer authorizes nothing.
 */
export interface AccountPointer {
  did?: string
  spaceId: string
  host: string
}

/**
 * The unwrapped contents of a keyring record: the account controller (the
 * first enrolled client's did:key today), the account email captured at bind
 * time (when one was given -- carried so any unlock method recovers it; a
 * passkey login has no login form to ask on), and the account pointer (absent
 * only on no-WAS deployments, where there is no Space to point at).
 */
export interface KeyringRecordContents {
  controller: string
  email?: string
  pointer?: AccountPointer
  createdAt: string
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
 * @param options.keyAgreementKey {IKeyAgreementKey}   the unlock KAK
 * @param options.keyResolver {IKeyResolver}
 * @param options.signer {RecordSigner}   the unlock identity's signing key
 *   (`recordSignerFromAgent` over the unlock agent)
 * @returns {Promise<SignedRecord>}
 */
export async function wrapKeyringRecord({
  controller,
  email,
  pointer,
  keyAgreementKey,
  keyResolver,
  signer
}: {
  controller: string
  email?: string
  pointer?: AccountPointer
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  signer: RecordSigner
}): Promise<SignedRecord> {
  const encryption = await mintRecordEncryption({ keyAgreementKey })
  const cipher = await recordCipher({
    keyAgreementKey,
    keyResolver,
    encryption
  })
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
      createdAt: new Date().toISOString()
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

/**
 * Parses and validates the required `createdAt` member of a record plaintext:
 * the moment the record was bound, as an ISO timestamp that must parse. Apps
 * pin freshness on it, so a record that cannot state its own bind time is
 * refused rather than defaulted.
 *
 * @param options {object}
 * @param options.value {unknown}   the plaintext's `createdAt` member
 * @param options.label {string}   names the record kind in the refusal
 * @returns {string}
 */
export function parseRecordCreatedAt({
  value,
  label
}: {
  value: unknown
  label: string
}): string {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} record has no valid createdAt timestamp.`)
  }
  return value
}

/**
 * Parses and validates the optional `pointer` member of a keyring record
 * plaintext. An absent member is a no-WAS record (returns undefined); a
 * present-but-malformed one throws -- a record that claims a pointer but
 * cannot state where the account lives is unusable.
 *
 * @param value {unknown}   the record's `pointer` member
 * @returns {AccountPointer | undefined}
 */
export function parseRecordPointer(value: unknown): AccountPointer | undefined {
  if (value === undefined) {
    return undefined
  }
  if (value === null || typeof value !== 'object') {
    throw new Error('Keyring record has a malformed account pointer.')
  }
  const { did, spaceId, host } = value as {
    did?: unknown
    spaceId?: unknown
    host?: unknown
  }
  if (typeof spaceId !== 'string' || !spaceId) {
    throw new Error('Keyring record account pointer is missing its spaceId.')
  }
  if (typeof host !== 'string' || !host) {
    throw new Error('Keyring record account pointer is missing its host.')
  }
  if (did !== undefined && (typeof did !== 'string' || !did)) {
    throw new Error('Keyring record account pointer has a malformed did.')
  }
  return { ...(did ? { did } : {}), spaceId, host }
}
