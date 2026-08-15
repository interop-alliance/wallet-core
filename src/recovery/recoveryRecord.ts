/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The recovery keyring record codec: the `{ version, encryption, wrapped,
 * binding, proof }` envelope stored as the one resource of a recovery code's
 * unlock Space. Its plaintext is the ordinary keyring record's (controller,
 * account pointer) PLUS the pre-minted PUT-on-`did.jsonl` delegation -- the
 * narrow zcap bridge that lets the code-derived client write its
 * self-enrolling log continuation. It carries **no key material of any
 * kind**: never a seed, never a user key wrap (wraps live doc-and-roster
 * only), so the record stays a pure pointer.
 *
 * The wrap reuses the keyring record construction (cipher context,
 * record-own epoch, and signed frame alike), so a recovery record IS a
 * keyring record to every generic consumer -- only the recovery flow demands
 * the delegation and the binding.
 *
 * The record splits into a code-authenticated core and a re-mintable shell.
 * The core is the account binding `{ controller, pointer }`, authenticated by
 * the `binding` frame member: an HMAC tag under a key derived from the code
 * bytes, computed at issuance and verified at recovery BEFORE the pointer is
 * trusted. Only the issuer and the code holder ever hold that key -- the
 * storage host never does -- so a host-forged record pointing recovery at
 * another account fails the tag however it is encrypted or signed. The tag
 * rides the frame in the clear (it reveals nothing) so the re-mint path,
 * which cannot decrypt the record or recompute the tag, preserves it
 * verbatim; the binding values themselves stay inside the plaintext. The
 * consequence: a re-mint can never change the pointer, and an account that
 * moves hosts must re-issue its codes.
 *
 * The shell is the delegation and the frame proof, and its signer is mixed.
 * At issuance the record is signed by the code-derived unlock key, the one a
 * typed code re-derives, so recovery verifies the proof before decrypting.
 * The revocation cascade's re-mint path holds only the code's KAK public
 * half plus an enrolled client's account key, so it re-PUTs the record
 * signed by that client's account verification method instead. This codec is
 * agnostic -- it signs with what it is given -- and the reader carries the
 * policy: a proof by the expected unlock key verifies up front, and anything
 * else comes back marked unverified, for the caller to check against the
 * verified did:webvh document of the account the code-authenticated pointer
 * names.
 */
import { base64urlnopad } from '@scure/base'
import { equalBytes } from '@noble/ciphers/utils.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
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
  recordSealCipher,
  signRecordFrame,
  verifyRecordProof
} from '../keyring/record.js'
import type {
  AccountPointer,
  RecordSigner,
  SignedRecord
} from '../keyring/record.js'

/**
 * The context label mixed into the binding MAC input, versioning the tag
 * construction. Permanent -- changing it orphans every issued code.
 */
const RECOVERY_BINDING_CONTEXT = 'freewallet/recovery/binding/v1'

/**
 * A recovery record's account binding is absent, malformed, or does not
 * verify under the typed code's binding MAC key. Its own class, distinct from
 * a proof or decrypt failure: this is the refusal that says the record's
 * `{ controller, pointer }` core was not written by a holder of this code --
 * a forged record redirecting recovery at another account, or a record from
 * before the account moved hosts (either way the code cannot recover here
 * and must be re-issued).
 */
export class RecoveryBindingError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RecoveryBindingError'
  }
}

/**
 * The unwrapped contents of a recovery keyring record: the code-authenticated
 * account binding (controller + pointer) plus the delegation and bind
 * timestamp. `pointer` is required -- a recovery record exists only on WAS
 * deployments (there is nothing to recover toward without a Space).
 */
export interface RecoveryRecordContents {
  controller: string
  pointer: AccountPointer
  delegation: IZcap
  createdAt: string
}

/**
 * A stored recovery record: the shared signed frame plus the account-binding
 * tag the frame proof also covers.
 */
export interface SignedRecoveryRecord extends SignedRecord {
  binding: string
}

/**
 * Where a recovery record's proof stands after the unwrap: `'verified'` when
 * the code-derived unlock key signed it (checked before decryption), or a
 * pending marker naming the signer the caller must still check against the
 * account's verified did:webvh document -- the re-mint case, where an enrolled
 * client signed on the code's behalf. The pending case is a value the caller
 * cannot ignore by accident: the shell is not trustworthy until
 * `verifyRecordProof` is run against the document-listed keys. The account
 * the document belongs to is the one the code-authenticated pointer names --
 * the binding is verified either way, so the pending state defers the shell's
 * authenticity only, never the account identity.
 */
export type RecoveryRecordProofState =
  'verified' | { pending: { verificationMethod: string; keyMultibase: string } }

/**
 * The deterministic MAC input over a record's account binding: a JSON array
 * of the context label and the binding values, so no delimiter ambiguity can
 * make two bindings collide.
 */
function bindingMacInput({
  controller,
  pointer
}: {
  controller: string
  pointer: AccountPointer
}): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify([
      RECOVERY_BINDING_CONTEXT,
      controller,
      pointer.did ?? '',
      pointer.spaceId,
      pointer.host
    ])
  )
}

/**
 * Computes the account-binding tag: HMAC-SHA-256 over the binding values
 * under the code-derived binding MAC key, base64url (no pad). Issuance calls
 * it to stamp the record; recovery recomputes it to verify.
 *
 * @param options {object}
 * @param options.bindingMacKey {Uint8Array}   the code-derived MAC key
 * @param options.controller {string}   the account did:key
 * @param options.pointer {AccountPointer}   the account pointer
 * @returns {string}
 */
export function computeRecoveryBinding({
  bindingMacKey,
  controller,
  pointer
}: {
  bindingMacKey: Uint8Array
  controller: string
  pointer: AccountPointer
}): string {
  return base64urlnopad.encode(
    hmac(sha256, bindingMacKey, bindingMacInput({ controller, pointer }))
  )
}

/**
 * Reads the `binding` frame member off a stored recovery record without
 * decrypting anything. The re-mint path uses it to carry the tag forward
 * verbatim -- it cannot recompute the tag (no code bytes) and does not need
 * to. Refuses a record with no binding: such a record predates the
 * code-authenticated core and cannot be re-minted -- its code must be
 * re-issued.
 *
 * @param options {object}
 * @param options.record {unknown}   the stored record envelope
 * @returns {string}
 */
export function recoveryRecordBinding({ record }: { record: unknown }): string {
  const { binding } = (record ?? {}) as { binding?: unknown }
  if (typeof binding !== 'string' || !binding) {
    throw new RecoveryBindingError(
      'The recovery record carries no code-authenticated account binding; ' +
        'the recovery code must be re-issued.'
    )
  }
  return binding
}

/**
 * Wraps the recovery record: controller, pointer, and the pre-minted
 * `did.jsonl` PUT delegation, encrypted under the code's unlock KAK via the
 * keyring EDV cipher context, then signed into the same frame the keyring
 * record uses -- with the account-binding tag as one more frame member the
 * proof covers. Issuance passes the code-derived `bindingMacKey` (the tag is
 * computed here) and the code-derived unlock signer; the revocation cascade's
 * re-mint path passes the standing record's `binding` verbatim and an
 * enrolled client's account signer (see this module's header for the policy
 * the reader applies to the two). Exactly one of the two binding inputs must
 * be given.
 *
 * @param options {object}
 * @param options.controller {string}   the account did:key
 * @param options.pointer {AccountPointer}   the account pointer
 * @param options.delegation {IZcap}   the PUT-on-`did.jsonl` delegation to the
 *   code-derived signing DID
 * @param options.keyAgreementKey {IKeyAgreementKey}   the code's unlock KAK --
 *   its public half is all the wrap uses (sealing needs no key-agreement
 *   secret), which is exactly what lets the re-mint path re-seal a record it
 *   can never open
 * @param options.signer {RecordSigner}   the signing key: the code's unlock
 *   key at issuance, an enrolled client's account key on a re-mint
 * @param [options.bindingMacKey] {Uint8Array}   the code-derived binding MAC
 *   key -- the issuance path, which computes the tag
 * @param [options.binding] {string}   the standing record's tag, carried
 *   forward verbatim -- the re-mint path, which cannot recompute it
 * @param [options.createdAt] {string}   the bind timestamp to stamp, as an ISO
 *   string; defaults to now. Supplied by a caller that pins record freshness.
 * @returns {Promise<SignedRecoveryRecord>}
 */
export async function wrapRecoveryRecord({
  controller,
  pointer,
  delegation,
  keyAgreementKey,
  signer,
  bindingMacKey,
  binding,
  createdAt
}: {
  controller: string
  pointer: AccountPointer
  delegation: IZcap
  keyAgreementKey: IKeyAgreementKey
  signer: RecordSigner
  bindingMacKey?: Uint8Array
  binding?: string
  createdAt?: string
}): Promise<SignedRecoveryRecord> {
  if ((bindingMacKey === undefined) === (binding === undefined)) {
    throw new Error(
      'Exactly one of bindingMacKey (issuance) or binding (re-mint) is ' +
        'required.'
    )
  }
  const tag =
    bindingMacKey !== undefined
      ? computeRecoveryBinding({ bindingMacKey, controller, pointer })
      : binding!
  const encryption = await mintRecordEncryption({ keyAgreementKey })
  const cipher = await recordSealCipher({ encryption })
  const data = {
    controller,
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
  return (await signRecordFrame({
    version: KEYRING_RECORD_VERSION,
    encryption,
    wrapped: envelope,
    signer,
    members: { binding: tag }
  })) as SignedRecoveryRecord
}

/**
 * Unwraps and validates a recovery record: the ordinary keyring-record checks
 * plus the required pointer, delegation, and account binding. A record
 * without a delegation is not a recovery record (an ordinary keyring record
 * found under a code's unlock Space would mean a corrupted issuance) and is
 * refused.
 *
 * The account binding is verified before the contents are returned: the
 * decrypted `{ controller, pointer }` must carry the tag the code-derived
 * MAC key computes over them, or the record is refused as forged
 * ({@link RecoveryBindingError}) -- the check that closes the host-forgery
 * redirect, since the host never holds the MAC key. Nothing downstream may
 * trust the pointer before this returns.
 *
 * Proof verification is mixed-signer and ordered deliberately. A proof by the
 * code's own unlock key is verified BEFORE decryption -- the strong path,
 * where the typed code alone establishes what may have signed the record. A
 * proof by any other key can only be checked after decryption, because the
 * re-minting client is knowable only once the code-authenticated pointer says
 * which account this is and that account's log has been verified; the
 * contents come back with a pending proof state naming the signer, and the
 * caller completes the check with {@link verifyRecordProof} against the
 * document's keys. That second phase is what makes an unexpected signer
 * refuse: a record whose proof belongs to neither class ends in a
 * `RecordProofError` there.
 *
 * @param options {object}
 * @param options.record {unknown}   the stored `{ version, encryption,
 *   wrapped, binding, proof }` envelope
 * @param options.keyAgreementKey {IKeyAgreementKey}   the code's unlock KAK
 * @param options.keyResolver {IKeyResolver}
 * @param options.expectedKeyMultibase {string}   the code-derived unlock
 *   signing key's multibase
 * @param options.bindingMacKey {Uint8Array}   the code-derived binding MAC
 *   key the record's account binding must verify under
 * @returns {Promise<{ contents: RecoveryRecordContents,
 *   proofState: RecoveryRecordProofState }>}
 */
export async function unwrapRecoveryRecord({
  record,
  keyAgreementKey,
  keyResolver,
  expectedKeyMultibase,
  bindingMacKey
}: {
  record: unknown
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  expectedKeyMultibase: string
  bindingMacKey: Uint8Array
}): Promise<{
  contents: RecoveryRecordContents
  proofState: RecoveryRecordProofState
}> {
  const { encryption, wrapped, proof } = parseRecordFrame({
    record,
    label: 'recovery'
  })
  const binding = recoveryRecordBinding({ record })
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

  const expectedTag = hmac(
    sha256,
    bindingMacKey,
    bindingMacInput({ controller: plaintext.controller, pointer })
  )
  let servedTag: Uint8Array | null
  try {
    servedTag = base64urlnopad.decode(binding)
  } catch {
    servedTag = null
  }
  // `equalBytes` is @noble/ciphers' authentication-tag comparison (no early
  // exit), so the check leaks nothing through timing.
  if (servedTag === null || !equalBytes(servedTag, expectedTag)) {
    throw new RecoveryBindingError(
      "The recovery record's account binding does not verify under this " +
        'code; the record is refused as forged.'
    )
  }

  return {
    contents: {
      controller: plaintext.controller,
      pointer,
      delegation: plaintext.delegation as IZcap,
      createdAt
    },
    proofState
  }
}
