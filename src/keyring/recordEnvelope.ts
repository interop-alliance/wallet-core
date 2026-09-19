/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The record envelope: the `{ version, encryption, wrapped }` frame every
 * sealed record shares, without its authenticity layer. It mints the record's
 * one-epoch descriptor, builds the sealing and reading ciphers over it, reads
 * the envelope's addressed id, validates a stored frame's shape, and parses the
 * keyring plaintext's members.
 *
 * The wrap is an EDV document envelope sealed under the record's own key
 * epoch: every EDV envelope seals to an epoch key, so the record carries its
 * one-epoch descriptor in its `encryption` member, epoch[0] wrapped to the
 * unlock key-agreement key. The record stays self-contained -- unlock KAK in,
 * contents out. The cipher's `keyring` collection context labels errors only
 * (the codec is agnostic to it).
 *
 * This file's runtime imports are was-client's EDV subpath and the system
 * collections leaf, and they stay that way. A consumer that opens sealed
 * records offline loads it without the signing and did:webvh graph.
 * Signing and verifying the frame's `proof` member is `record.ts`, which
 * imports this file; nothing here imports it back.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import {
  createEdvDocCipher,
  createEdvEncryptOnlyDocCipher,
  initRecipients,
  ownerRecipient,
  type DocCipher,
  type EncryptionDescriptorStore
} from '@interop/was-client/edv/cipher'
import { KEYRING_COLLECTION } from '../space/systemCollections.js'

/**
 * The version stamped on the stored `{ version, encryption, wrapped, proof }`
 * keyring envelope: the signed record, whose envelope seals under the record's
 * own key epoch (the `encryption` member) and whose sibling members carry a
 * Data Integrity proof by the unlock identity's signing key. Any other version
 * is refused as unusable -- such accounts are re-provisioned, not migrated.
 */
export const KEYRING_RECORD_VERSION = 2

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
 * Checks the shape of a record's `proof` member against the fixed shape.
 * Verifies nothing: no cryptography runs here, so a match says only that
 * the member could be a proof, not that it is genuine.
 *
 * @param options {object}
 * @param options.proof {unknown}
 * @param options.label {string}   names the record kind in the refusal
 * @returns {RecordProof}
 */
export function checkRecordProofShape({
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
 * Builds the record's reading cipher: an EDV cipher over the record's own
 * descriptor, from the reader's key-agreement key. The unwrap paths' cipher
 * (and the recovery record's, which reuses the keyring cipher context
 * verbatim); the wrap paths seal through {@link recordSealCipher} instead. An
 * app's own record kind passes its own `collectionId` so its failures name
 * the record kind. The context labels errors only -- the codec is agnostic to
 * it, so a record kind's real swap protection is its contents validation on
 * unwrap.
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
 * Builds the record's sealing cipher: an encrypt-only EDV cipher over the
 * record's own descriptor, needing no key-agreement secret -- a write seals to
 * the descriptor's epoch public key, reconstructed from the epoch id. This is
 * what lets the recovery re-mint, which holds only the code's unlock KAK
 * public half, re-seal a record it can never open; the issuance wraps go
 * through the same construction and produce the same envelope shape. Decrypt
 * on it refuses with was-client's typed `EncryptOnlyCipherError`.
 *
 * @param options {object}
 * @param options.encryption {CollectionEncryption}   the record's descriptor
 * @param [options.collectionId] {string}   the cipher context failures are
 *   labeled with; defaults to the keyring context
 * @returns {Promise<DocCipher>}
 */
export async function recordSealCipher({
  encryption,
  collectionId = KEYRING_COLLECTION.id
}: {
  encryption: CollectionEncryption
  collectionId?: string
}): Promise<DocCipher> {
  return createEdvEncryptOnlyDocCipher({ collectionId, encryption })
}

/**
 * Reads the addressed id a stored record envelope must be decrypted under.
 *
 * A record's members seal through {@link recordSealCipher}, which builds on
 * was-client's default content-derived id mode: the id does not exist until
 * after encryption, so the codec computes it from the JWE ciphertext and
 * stamps it onto the cleartext envelope afterwards. That stamped member is
 * the only value {@link recordCipher}'s decrypt accepts -- the record's own
 * well-known resource id does not verify, and the sealed members of an unlock
 * record have no resource id of their own at all.
 *
 * The check this id feeds is therefore inert here, and deliberately so. In
 * content-derived mode the id is a hash of the ciphertext, so a substituted
 * envelope carries a matching stamp and the comparison always passes. It
 * detects corruption rather than substitution. A record's protection against a
 * substituting storage host is the frame's `eddsa-jcs-2022` proof over
 * `wrapped` and every sealed member, verified by `record.ts`'s
 * `verifyRecordProof` before any unwrap path decrypts. Do not read this id
 * as a security boundary.
 *
 * @param options {object}
 * @param options.wrapped {unknown}   the stored envelope
 * @param options.label {string}   `'keyring'`, `'recovery'`, or an app record
 *   kind's own label, naming the refusal
 * @returns {string}   the envelope's addressed id
 */
export function recordEnvelopeId({
  wrapped,
  label
}: {
  wrapped: unknown
  label: string
}): string {
  const id =
    wrapped !== null && typeof wrapped === 'object'
      ? (wrapped as { id?: unknown }).id
      : undefined
  if (typeof id !== 'string' || !id) {
    throw new Error(
      `Malformed ${label} record: the sealed envelope carries no id.`
    )
  }
  return id
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
 * verify it -- `record.ts`'s `verifyRecordProof` does, and every unwrap path
 * there runs it before decrypting.
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
 * The account pointer a keyring record carries in place of the retired data
 * seed: where the account lives (`spaceId` + `host`, the WAS server's base
 * URL, which carries a base path when the server is deployed under a
 * sub-path) and, once provisioning has published it, the account's stable
 * did:webvh id. Discovery only -- holding the pointer authorizes nothing.
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
 * The bind timestamp a wrap path stamps into a record's plaintext: the
 * caller's, validated as a parseable ISO timestamp, or now. A caller supplies
 * one when it pins record freshness, so it knows the stamp of the record it is
 * writing without reading it back.
 *
 * @param options {object}
 * @param [options.createdAt] {string}   the caller's timestamp
 * @returns {string}
 */
export function recordCreatedAtStamp({
  createdAt
}: {
  createdAt?: string
}): string {
  if (createdAt === undefined) {
    return new Date().toISOString()
  }
  if (typeof createdAt !== 'string' || Number.isNaN(Date.parse(createdAt))) {
    throw new Error(`Invalid record createdAt timestamp "${createdAt}".`)
  }
  return createdAt
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
