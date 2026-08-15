/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The recovery keyring record codec: the `{ version, encryption, wrapped,
 * proof }` envelope stored as the one resource of a recovery code's unlock
 * Space. Its plaintext is the ordinary keyring record's (controller, email,
 * account pointer) PLUS the pre-minted PUT-on-`did.jsonl` delegation -- the
 * narrow zcap bridge that lets the code-derived client write its
 * self-enrolling log continuation. It carries **no key material of any kind**: never a seed,
 * never a user key wrap (wraps live doc-and-roster only), so the record stays
 * a pure pointer.
 *
 * The wrap reuses the keyring record construction verbatim (cipher context,
 * record-own epoch, and signed frame alike), so a recovery record IS a keyring
 * record to every generic consumer -- only the recovery flow demands the
 * delegation.
 *
 * Its signer, though, is mixed. At issuance the record is signed by the
 * code-derived unlock key, the one a typed code re-derives, so recovery
 * verifies the proof before decrypting. The revocation cascade's re-mint path
 * holds only the code's KAK public half plus an enrolled client's account key,
 * so it re-PUTs the record signed by that client's account verification method
 * instead. This codec is agnostic -- it signs with what it is given -- and the
 * reader carries the policy: a proof by the expected unlock key verifies
 * up front, and anything else comes back marked unverified, for the caller to
 * check against the account's verified did:webvh document once the decrypted
 * pointer says which account that is.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver,
  IZcap
} from '@interop/data-integrity-core'
import {
  KEYRING_RECORD_VERSION,
  mintRecordEncryption,
  parseRecordCreatedAt,
  parseRecordFrame,
  parseRecordPointer,
  recordCipher,
  recordCreatedAtStamp,
  recordProofKeyMultibase,
  signRecordFrame,
  verifyRecordProof
} from '../keyring/record.js'
import type {
  AccountPointer,
  RecordSigner,
  SignedRecord
} from '../keyring/record.js'

/**
 * The unwrapped contents of a recovery keyring record: the ordinary record
 * members plus the required delegation. `pointer` is required -- a recovery
 * record exists only on WAS deployments (there is nothing to recover toward
 * without a Space).
 */
export interface RecoveryRecordContents {
  controller: string
  email?: string
  pointer: AccountPointer
  delegation: IZcap
  createdAt: string
}

/**
 * Where a recovery record's proof stands after the unwrap: `'verified'` when
 * the code-derived unlock key signed it (checked before decryption), or a
 * pending marker naming the signer the caller must still check against the
 * account's verified did:webvh document -- the re-mint case, where an enrolled
 * client signed on the code's behalf. The pending case is a value the caller
 * cannot ignore by accident: nothing about the record is trustworthy until
 * `verifyRecordProof` is run against the document-listed keys.
 */
export type RecoveryRecordProofState =
  'verified' | { pending: { verificationMethod: string; keyMultibase: string } }

/**
 * Wraps the recovery record: controller, email, pointer, and the pre-minted
 * `did.jsonl` PUT delegation, encrypted under the code's unlock KAK via the
 * keyring EDV cipher context, then signed into the same frame the keyring
 * record uses. Issuance passes the code-derived unlock signer; the revocation
 * cascade's re-mint path passes an enrolled client's account signer (see this
 * module's header for the policy the reader applies to the two).
 *
 * @param options {object}
 * @param options.controller {string}   the account did:key
 * @param [options.email] {string}   the account email, when known
 * @param options.pointer {AccountPointer}   the account pointer
 * @param options.delegation {IZcap}   the PUT-on-`did.jsonl` delegation to the
 *   code-derived signing DID
 * @param options.keyAgreementKey {IKeyAgreementKey}   the code's unlock KAK
 * @param options.keyResolver {IKeyResolver}
 * @param options.signer {RecordSigner}   the signing key: the code's unlock
 *   key at issuance, an enrolled client's account key on a re-mint
 * @param [options.createdAt] {string}   the bind timestamp to stamp, as an ISO
 *   string; defaults to now. Supplied by a caller that pins record freshness.
 * @returns {Promise<SignedRecord>}
 */
export async function wrapRecoveryRecord({
  controller,
  email,
  pointer,
  delegation,
  keyAgreementKey,
  keyResolver,
  signer,
  createdAt
}: {
  controller: string
  email?: string
  pointer: AccountPointer
  delegation: IZcap
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  signer: RecordSigner
  createdAt?: string
}): Promise<SignedRecord> {
  const encryption = await mintRecordEncryption({ keyAgreementKey })
  const cipher = await recordCipher({
    keyAgreementKey,
    keyResolver,
    encryption
  })
  const data = {
    controller,
    ...(email ? { email } : {}),
    pointer: {
      ...(pointer.did ? { did: pointer.did } : {}),
      spaceId: pointer.spaceId,
      host: pointer.host
    },
    delegation,
    createdAt: recordCreatedAtStamp({ createdAt })
  }
  const { envelope } = await cipher.encrypt({
    data: data as unknown as Parameters<typeof cipher.encrypt>[0]['data']
  })
  return signRecordFrame({
    version: KEYRING_RECORD_VERSION,
    encryption,
    wrapped: envelope,
    signer
  })
}

/**
 * Unwraps and validates a recovery record: the ordinary keyring-record checks
 * plus the required pointer and delegation. A record without a delegation is
 * not a recovery record (an ordinary keyring record found under a code's
 * unlock Space would mean a corrupted issuance) and is refused.
 *
 * Proof verification is mixed-signer and ordered deliberately. A proof by the
 * code's own unlock key is verified BEFORE decryption -- the strong path,
 * where the typed code alone establishes what may have signed the record. A
 * proof by any other key can only be checked after decryption, because the
 * re-minting client is knowable only once the plaintext's pointer says which
 * account this is and that account's log has been verified; the contents come
 * back with a pending proof state naming the signer, and the caller completes
 * the check with {@link verifyRecordProof} against the document's keys. That
 * second phase is what makes an unexpected signer refuse: a record whose proof
 * belongs to neither class ends in a `RecordProofError` there.
 *
 * @param options {object}
 * @param options.record {unknown}   the stored `{ version, encryption,
 *   wrapped, proof }` envelope
 * @param options.keyAgreementKey {IKeyAgreementKey}   the code's unlock KAK
 * @param options.keyResolver {IKeyResolver}
 * @param options.expectedKeyMultibase {string}   the code-derived unlock
 *   signing key's multibase
 * @returns {Promise<{ contents: RecoveryRecordContents,
 *   proofState: RecoveryRecordProofState }>}
 */
export async function unwrapRecoveryRecord({
  record,
  keyAgreementKey,
  keyResolver,
  expectedKeyMultibase
}: {
  record: unknown
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  expectedKeyMultibase: string
}): Promise<{
  contents: RecoveryRecordContents
  proofState: RecoveryRecordProofState
}> {
  const { encryption, wrapped, proof } = parseRecordFrame({
    record,
    label: 'recovery'
  })
  // `parseRecordFrame` shape-checks the proof of a current-version frame, so
  // it is present here.
  const verificationMethod = proof!.verificationMethod
  const keyMultibase = recordProofKeyMultibase({
    verificationMethod,
    label: 'recovery'
  })
  let proofState: RecoveryRecordProofState = {
    pending: { verificationMethod, keyMultibase }
  }
  if (keyMultibase === expectedKeyMultibase) {
    await verifyRecordProof({
      record,
      allowedKeyMultibases: expectedKeyMultibase,
      label: 'recovery'
    })
    proofState = 'verified'
  }
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
    delegation?: unknown
    createdAt?: unknown
  }

  if (typeof plaintext.controller !== 'string' || !plaintext.controller) {
    throw new Error('Recovery record is missing a controller.')
  }
  const pointer = parseRecordPointer(plaintext.pointer)
  if (!pointer) {
    throw new Error('Recovery record is missing its account pointer.')
  }
  if (
    plaintext.delegation === null ||
    typeof plaintext.delegation !== 'object'
  ) {
    throw new Error('Recovery record is missing its did.jsonl delegation.')
  }
  const createdAt = parseRecordCreatedAt({
    value: plaintext.createdAt,
    label: 'Recovery'
  })

  return {
    contents: {
      controller: plaintext.controller,
      ...(typeof plaintext.email === 'string' && plaintext.email
        ? { email: plaintext.email }
        : {}),
      pointer,
      delegation: plaintext.delegation as IZcap,
      createdAt
    },
    proofState
  }
}
