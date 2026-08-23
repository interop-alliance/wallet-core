/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The unlock record codec for credentials with standing authority: the
 * envelope stored as the one resource of a credential's unlock Space, for
 * every unlock method in the standing configuration -- a passphrase, a passkey PRF
 * output, or a recovery code. Its frame is the ordinary keyring record's
 * (`{ version, encryption, wrapped, proof }`), extended with three
 * record-kind members the proof also covers:
 *
 * - `wrapped` (the SHELL): the account core -- controller, optional email,
 *   pointer, bind timestamp -- sealed to the credential's unlock KAK. Carried
 *   VERBATIM through every re-mint, so the bind timestamp (which apps pin
 *   freshness on) and the email survive a re-mint that cannot decrypt them.
 * - `bridge`: the pre-minted PUT-on-`did.jsonl` delegation, sealed in its own
 *   self-contained `{ encryption, wrapped }` member. Re-mintable: revoking
 *   the client that signed the delegation rots it, and the revocation
 *   cascade re-seals a fresh one to the credential's unlock KAK public half
 *   ({@link remintUnlockRecordDelegations}).
 * - `delegatedClients` (standing credentials only): the pre-minted GET+PUT
 *   delegation over the auxiliary client-annex Space's items subtree, sealed as
 *   its own self-contained member -- what lets a transient login reach the
 *   annex (delegated-clients) log with nothing but the credential. It
 *   rots on exactly the bridge's axis (same signer, same current-key-set
 *   rule), so the re-mint reseals both members in one pass. Absent on a
 *   recovery code, which needs no annex authority; parsed with `ladder`'s
 *   tolerant handling, not `bridge`'s hard refusal. The `binding` MAC does
 *   not cover it (the v2 context label stays): like the bridge it mirrors,
 *   it sits under the frame proof only, and a host-swapped member is bounded
 *   by the account document's independent service entry plus the fact that a
 *   wrong Space yields nothing the transient login's self-computed ladder
 *   keys verify.
 * - `ladder` (standing credentials only): the random 32-byte update-key
 *   ladder seed (`./ladder`), sealed in its own `{ encryption, wrapped }`
 *   member and carried VERBATIM through re-mints -- a re-mint can never read
 *   or replace a credential's update authority. A recovery code carries none
 *   (its single update key derives from the code bytes).
 *
 * The record splits into a credential-authenticated core and a re-mintable
 * shell exactly as the recovery record did. The core is the account binding
 * plus the ladder seed, authenticated by the `binding` frame member: an HMAC
 * tag under a key derived from the credential itself, computed at bind time
 * and verified BEFORE the pointer is trusted. Only the binder and the
 * credential holder ever hold that key -- the storage host never does -- so a
 * host-forged record redirecting login (or a host-substituted ladder seed)
 * fails the tag however it is encrypted or signed. The tag rides the frame in
 * the clear (it reveals nothing), so the re-mint path, which cannot decrypt
 * the record or recompute the tag, preserves it verbatim. The consequence: a
 * re-mint can never move the record to another account, and an account that
 * moves hosts must rebind its credentials.
 *
 * The shell's signer is mixed, as before: at bind time the record is signed
 * by the credential-derived unlock key (verified before decryption); a
 * re-mint signs with the acting client's account verification method, which
 * comes back as a pending proof state the caller settles against the account
 * document the credential-authenticated pointer names.
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
import type { CollectionEncryption } from '@interop/was-client'
import { vmFragmentOf } from '@interop/vh-resource-log'
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
 * The byte length of a ladder seed: 32 random bytes, minted at bind time and
 * carried only inside the unlock record's sealed ladder member. Declared
 * here because the record format owns its member sizes; the ladder module's
 * derivations import it from this codec.
 */
export const LADDER_SEED_BYTES = 32

/**
 * The context label mixed into the binding MAC input, versioning the tag
 * construction. Permanent -- changing it orphans every bound credential.
 * Supersedes the recovery record's `freewallet/recovery/binding/v1` (the
 * standing layout is a re-provision boundary; issued codes are re-issued).
 */
const UNLOCK_BINDING_CONTEXT = 'freewallet/unlock/binding/v2'

/**
 * An unlock record's account binding is absent, malformed, or does not verify
 * under the credential's binding MAC key. Its own class, distinct from a
 * proof or decrypt failure: this is the refusal that says the record's
 * account core (and ladder seed, where one rides) was not written by a holder
 * of this credential -- a forged record redirecting login at another account,
 * or a record from before the account moved hosts (either way the credential
 * must be rebound).
 */
export class UnlockBindingError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'UnlockBindingError'
  }
}

/**
 * A self-contained sealed record member: its own one-epoch descriptor plus
 * the envelope sealed under it. Self-containment is what lets a member travel
 * VERBATIM through a re-mint that re-seals its siblings -- each member
 * decrypts against its own descriptor, not the frame's.
 */
export interface SealedRecordMember {
  encryption: CollectionEncryption
  wrapped: unknown
}

/**
 * The unwrapped contents of an unlock record: the credential-authenticated
 * account core (controller + pointer, plus the ladder seed where the
 * credential is a standing method), the bridge delegation, the optional
 * annex Space delegation (`delegatedClients` -- a standing credential's
 * pre-minted GET+PUT over the auxiliary annex Space's items subtree),
 * the optional bind email, and the bind timestamp. `pointer` is required --
 * the record exists only on WAS deployments.
 */
export interface UnlockRecordContents {
  controller: string
  email?: string
  pointer: AccountPointer
  delegation: IZcap
  delegatedClients?: IZcap
  ladderSeed?: Uint8Array
  createdAt: string
}

/**
 * A stored unlock record: the shared signed frame plus the record-kind
 * members the frame proof also covers.
 */
export interface SignedUnlockRecord extends SignedRecord {
  binding: string
  bridge: SealedRecordMember
  delegatedClients?: SealedRecordMember
  ladder?: SealedRecordMember
}

/**
 * Where an unlock record's proof stands after the unwrap: `'verified'` when
 * the credential-derived unlock key signed it (checked before decryption), or
 * a pending marker naming the signer the caller must still check against the
 * account's verified did:webvh document -- the re-mint case, where an
 * enrolled client signed on the credential's behalf. The pending case defers
 * the shell's authenticity only, never the account identity: the binding is
 * verified either way.
 */
export type UnlockRecordProofState =
  'verified' | { pending: { verificationMethod: string; keyMultibase: string } }

/**
 * The deterministic MAC input over a record's credential-authenticated core:
 * a JSON array of the context label, the binding values, and the ladder seed
 * (base64url, empty for a credential that carries none), so no delimiter
 * ambiguity can make two cores collide.
 */
function bindingMacInput({
  controller,
  pointer,
  ladderSeed
}: {
  controller: string
  pointer: AccountPointer
  ladderSeed?: Uint8Array
}): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify([
      UNLOCK_BINDING_CONTEXT,
      controller,
      pointer.did ?? '',
      pointer.spaceId,
      pointer.host,
      ladderSeed ? base64urlnopad.encode(ladderSeed) : ''
    ])
  )
}

/**
 * Computes the account-binding tag: HMAC-SHA-256 over the core values under
 * the credential-derived binding MAC key, base64url (no pad). Bind time calls
 * it to stamp the record; login recomputes it to verify.
 *
 * @param options {object}
 * @param options.bindingMacKey {Uint8Array}   the credential-derived MAC key
 * @param options.controller {string}   the account controller
 * @param options.pointer {AccountPointer}   the account pointer
 * @param [options.ladderSeed] {Uint8Array}   the ladder seed, for a standing
 *   credential
 * @returns {string}
 */
export function computeUnlockBinding({
  bindingMacKey,
  controller,
  pointer,
  ladderSeed
}: {
  bindingMacKey: Uint8Array
  controller: string
  pointer: AccountPointer
  ladderSeed?: Uint8Array
}): string {
  return base64urlnopad.encode(
    hmac(
      sha256,
      bindingMacKey,
      bindingMacInput({
        controller,
        pointer,
        ...(ladderSeed ? { ladderSeed } : {})
      })
    )
  )
}

/**
 * Reads the `binding` frame member off a stored unlock record without
 * decrypting anything. The re-mint path uses it to confirm the record is
 * re-mintable before touching it. Refuses a record with no binding: such a
 * record predates the credential-authenticated core and cannot be re-minted
 * -- its credential must be rebound.
 *
 * @param options {object}
 * @param options.record {unknown}   the stored record envelope
 * @returns {string}
 */
export function unlockRecordBinding({ record }: { record: unknown }): string {
  const { binding } = (record ?? {}) as { binding?: unknown }
  if (typeof binding !== 'string' || !binding) {
    throw new UnlockBindingError(
      'The unlock record carries no credential-authenticated account ' +
        'binding; the credential must be rebound.'
    )
  }
  return binding
}

/**
 * The key-agreement keys a stored unlock record is currently sealed to: the
 * `kid` fragments of its frame descriptor's current-epoch recipients (a
 * record's descriptor carries one epoch, minted by
 * {@link mintRecordEncryption}, so the current epoch is the whole roster).
 * Public halves only -- nothing here is secret, and reading them decrypts
 * nothing. A descriptor with no epochs, or whose `currentEpoch` names no
 * epoch it lists, is refused rather than read as an empty recipient set.
 *
 * @param options {object}
 * @param options.record {unknown}   the stored record envelope
 * @returns {string[]}   the recipients' key multibases
 */
export function recordSealedRecipientKeys({
  record
}: {
  record: unknown
}): string[] {
  const { encryption } = parseRecordFrame({ record, label: 'unlock' })
  const epochs = encryption.epochs ?? []
  const epoch = epochs.find(
    candidate => candidate.id === encryption.currentEpoch
  )
  // Fail closed, as the roster read's own integrity refusal does: a
  // descriptor with no epochs, or whose `currentEpoch` names none of the
  // epochs it lists, is a broken record, not a record sealed to someone
  // else. Answering "not sealed to you" would let a host turn a degenerate
  // descriptor into a caller's benign skip.
  if (!epoch) {
    throw new Error(
      "The unlock record's encryption descriptor names no current key " +
        'epoch among the epochs it lists; the record is unusable.'
    )
  }
  return (epoch.recipients ?? [])
    .map(recipient => recipient?.header?.kid)
    .filter((kid): kid is string => typeof kid === 'string' && kid.length > 0)
    .map(kid => vmFragmentOf(kid) ?? kid)
}

/**
 * Whether a stored unlock record is sealed to the named credential's unlock
 * key-agreement key. The detector behind the pending-shaped registry entry:
 * a passphrase change torn before its retirement landed leaves an entry whose
 * `unlockSpaceId` and `manageCapability` are the NEW credential's while its
 * identity members are the OLD credential's, so the record fetched at that
 * Space is sealed to a key the entry does not name. Compared on the key
 * multibase, since a `kid` and a recorded key id may be spelled differently.
 * Throws on a record whose frame or descriptor is unusable, so a caller
 * never reads a broken record as a pending-shaped one.
 *
 * @param options {object}
 * @param options.record {unknown}   the stored record envelope
 * @param options.keyAgreementKeyMultibase {string}   the credential's unlock
 *   KAK public multibase, as the registry entry records it
 * @returns {boolean}
 */
export function unlockRecordSealedTo({
  record,
  keyAgreementKeyMultibase
}: {
  record: unknown
  keyAgreementKeyMultibase: string
}): boolean {
  const multibase =
    vmFragmentOf(keyAgreementKeyMultibase) ?? keyAgreementKeyMultibase
  return recordSealedRecipientKeys({ record }).includes(multibase)
}

/**
 * Shape-checks a sealed record member (`{ encryption, wrapped }`).
 *
 * @param options {object}
 * @param options.value {unknown}   the frame member
 * @param options.name {string}   names the member in the refusal
 * @returns {SealedRecordMember}
 */
function parseSealedMember({
  value,
  name
}: {
  value: unknown
  name: string
}): SealedRecordMember {
  const member = value as Partial<SealedRecordMember> | null
  if (
    member === null ||
    typeof member !== 'object' ||
    member.encryption === null ||
    typeof member.encryption !== 'object' ||
    member.wrapped === undefined ||
    member.wrapped === null
  ) {
    throw new Error(`The unlock record's ${name} member is malformed.`)
  }
  return member as SealedRecordMember
}

/**
 * Seals one self-contained record member to a KAK: a fresh one-epoch
 * descriptor plus the envelope. Sealing needs no key-agreement secret, which
 * is what lets the re-mint path (holding only the credential's unlock KAK
 * public half) build a fresh bridge member.
 *
 * @param options {object}
 * @param options.data {object}   the member plaintext
 * @param options.keyAgreementKey {IKeyAgreementKey}   the credential's unlock
 *   KAK (public half suffices)
 * @returns {Promise<SealedRecordMember>}
 */
async function sealMember({
  data,
  keyAgreementKey
}: {
  data: object
  keyAgreementKey: IKeyAgreementKey
}): Promise<SealedRecordMember> {
  const encryption = await mintRecordEncryption({ keyAgreementKey })
  const cipher = await recordSealCipher({ encryption })
  const { envelope } = await cipher.encrypt({
    data: data as unknown as Parameters<typeof cipher.encrypt>[0]['data']
  })
  return { encryption, wrapped: envelope }
}

/**
 * Opens one self-contained record member with the credential's unlock KAK.
 *
 * @param options {object}
 * @param options.member {SealedRecordMember}
 * @param options.keyAgreementKey {IKeyAgreementKey}
 * @param options.keyResolver {IKeyResolver}
 * @returns {Promise<unknown>}   the member plaintext
 */
async function openMember({
  member,
  keyAgreementKey,
  keyResolver
}: {
  member: SealedRecordMember
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}): Promise<unknown> {
  const cipher = await recordCipher({
    keyAgreementKey,
    keyResolver,
    encryption: member.encryption
  })
  return cipher.decrypt({ envelope: member.wrapped as never })
}

/**
 * Wraps an unlock record at bind time: the shell (controller, optional
 * email, pointer, timestamp) sealed to the credential's unlock KAK, the
 * bridge delegation and the optional ladder seed sealed as their own
 * members, the credential-authenticated binding computed over the core, and
 * the whole frame signed -- by the credential-derived unlock key at bind
 * time, or by an acting client's account key where a ceremony rebuilds a
 * record whole (the reader settles the mixed-signer policy either way).
 *
 * @param options {object}
 * @param options.controller {string}   the account controller
 * @param [options.email] {string}   the account email, when known
 * @param options.pointer {AccountPointer}   the account pointer
 * @param options.delegation {IZcap}   the PUT-on-`did.jsonl` delegation to
 *   the credential-derived signing DID
 * @param [options.delegatedClients] {IZcap}   the annex Space delegation
 *   (GET+PUT over the auxiliary Space's items subtree), for a standing
 *   credential (a recovery code carries none)
 * @param [options.ladderSeed] {Uint8Array}   the update-key ladder seed, for
 *   a standing credential (a recovery code carries none)
 * @param options.keyAgreementKey {IKeyAgreementKey}   the credential's unlock
 *   KAK -- its public half is all the wrap uses
 * @param options.signer {RecordSigner}   the signing key
 * @param options.bindingMacKey {Uint8Array}   the credential-derived binding
 *   MAC key
 * @param [options.createdAt] {string}   the bind timestamp to stamp, as an
 *   ISO string; defaults to now. Supplied by a caller that pins record
 *   freshness.
 * @returns {Promise<SignedUnlockRecord>}
 */
export async function wrapUnlockRecord({
  controller,
  email,
  pointer,
  delegation,
  delegatedClients,
  ladderSeed,
  keyAgreementKey,
  signer,
  bindingMacKey,
  createdAt
}: {
  controller: string
  email?: string
  pointer: AccountPointer
  delegation: IZcap
  delegatedClients?: IZcap
  ladderSeed?: Uint8Array
  keyAgreementKey: IKeyAgreementKey
  signer: RecordSigner
  bindingMacKey: Uint8Array
  createdAt?: string
}): Promise<SignedUnlockRecord> {
  if (ladderSeed && ladderSeed.length !== LADDER_SEED_BYTES) {
    throw new Error('The ladder seed must be 32 bytes.')
  }
  const binding = computeUnlockBinding({
    bindingMacKey,
    controller,
    pointer,
    ...(ladderSeed ? { ladderSeed } : {})
  })
  const shell = await sealMember({
    data: {
      controller,
      ...(email ? { email } : {}),
      pointer: {
        ...(pointer.did ? { did: pointer.did } : {}),
        spaceId: pointer.spaceId,
        host: pointer.host
      },
      createdAt: recordCreatedAtStamp({ createdAt })
    },
    keyAgreementKey
  })
  const bridge = await sealMember({ data: { delegation }, keyAgreementKey })
  const sealedDelegatedClients = delegatedClients
    ? await sealMember({
        data: { delegation: delegatedClients },
        keyAgreementKey
      })
    : undefined
  const ladder = ladderSeed
    ? await sealMember({
        data: { ladderSeed: base64urlnopad.encode(ladderSeed) },
        keyAgreementKey
      })
    : undefined
  return (await signRecordFrame({
    version: KEYRING_RECORD_VERSION,
    encryption: shell.encryption,
    wrapped: shell.wrapped,
    signer,
    members: {
      binding,
      bridge,
      ...(sealedDelegatedClients
        ? { delegatedClients: sealedDelegatedClients }
        : {}),
      ...(ladder ? { ladder } : {})
    }
  })) as SignedUnlockRecord
}

/**
 * Unwraps and validates an unlock record: the ordinary keyring-record frame
 * checks plus the required pointer, bridge delegation, and
 * credential-authenticated binding. A record without a bridge member is not
 * an unlock record in the standing layout (an ordinary keyring record found
 * under a credential's unlock Space would mean a torn bind) and is refused.
 *
 * The binding is verified before the contents are returned: the decrypted
 * core must carry the tag the credential-derived MAC key computes over it, or
 * the record is refused as forged ({@link UnlockBindingError}) -- the check
 * that closes the host-forgery redirect, since the host never holds the MAC
 * key. Nothing downstream may trust the pointer (or the ladder seed) before
 * this returns.
 *
 * Proof verification is mixed-signer and ordered deliberately, exactly as the
 * recovery record's was: a proof by the credential's own unlock key is
 * verified BEFORE decryption; a proof by any other key comes back as a
 * pending state naming the signer, for the caller to settle with
 * `verifyRecordProof` against the verified document of the account the
 * credential-authenticated pointer names.
 *
 * @param options {object}
 * @param options.record {unknown}   the stored record envelope
 * @param options.keyAgreementKey {IKeyAgreementKey}   the credential's unlock
 *   KAK
 * @param options.keyResolver {IKeyResolver}
 * @param options.expectedKeyMultibase {string}   the credential-derived
 *   unlock signing key's multibase
 * @param options.bindingMacKey {Uint8Array}   the credential-derived binding
 *   MAC key the record's account binding must verify under
 * @returns {Promise<{ contents: UnlockRecordContents,
 *   proofState: UnlockRecordProofState }>}
 */
export async function unwrapUnlockRecord({
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
  contents: UnlockRecordContents
  proofState: UnlockRecordProofState
}> {
  const { encryption, wrapped, proof } = parseRecordFrame({
    record,
    label: 'unlock'
  })
  const binding = unlockRecordBinding({ record })
  const {
    bridge: rawBridge,
    delegatedClients: rawDelegatedClients,
    ladder: rawLadder
  } = record as {
    bridge?: unknown
    delegatedClients?: unknown
    ladder?: unknown
  }
  if (rawBridge === undefined) {
    throw new Error(
      'The unlock record carries no bridge member; it predates the standing ' +
        'layout and the credential must be rebound.'
    )
  }
  const bridge = parseSealedMember({ value: rawBridge, name: 'bridge' })
  const delegatedClients =
    rawDelegatedClients === undefined
      ? undefined
      : parseSealedMember({
          value: rawDelegatedClients,
          name: 'delegatedClients'
        })
  const ladder =
    rawLadder === undefined
      ? undefined
      : parseSealedMember({ value: rawLadder, name: 'ladder' })

  // `parseRecordFrame` shape-checks the proof of a current-version frame, so
  // it is present here.
  const verificationMethod = proof!.verificationMethod
  const keyMultibase = recordProofKeyMultibase({
    verificationMethod,
    label: 'unlock'
  })
  let proofState: UnlockRecordProofState = {
    pending: { verificationMethod, keyMultibase }
  }
  if (keyMultibase === expectedKeyMultibase) {
    await verifyRecordProof({
      record,
      allowedKeyMultibases: expectedKeyMultibase,
      label: 'unlock'
    })
    proofState = 'verified'
  }

  const shell = (await openMember({
    member: { encryption, wrapped },
    keyAgreementKey,
    keyResolver
  })) as {
    controller?: unknown
    email?: unknown
    pointer?: unknown
    createdAt?: unknown
  }
  if (typeof shell.controller !== 'string' || !shell.controller) {
    throw new Error('Unlock record is missing a controller.')
  }
  const pointer = parseRecordPointer(shell.pointer)
  if (!pointer) {
    throw new Error('Unlock record is missing its account pointer.')
  }
  const createdAt = parseRecordCreatedAt({
    value: shell.createdAt,
    label: 'Unlock'
  })

  const bridgePlaintext = (await openMember({
    member: bridge,
    keyAgreementKey,
    keyResolver
  })) as { delegation?: unknown }
  if (
    bridgePlaintext.delegation === null ||
    typeof bridgePlaintext.delegation !== 'object'
  ) {
    throw new Error('Unlock record is missing its did.jsonl delegation.')
  }

  let delegatedClientsDelegation: IZcap | undefined
  if (delegatedClients) {
    const plaintext = (await openMember({
      member: delegatedClients,
      keyAgreementKey,
      keyResolver
    })) as { delegation?: unknown }
    if (
      plaintext.delegation === null ||
      typeof plaintext.delegation !== 'object'
    ) {
      throw new Error('Unlock record has a malformed delegatedClients member.')
    }
    delegatedClientsDelegation = plaintext.delegation as IZcap
  }

  let ladderSeed: Uint8Array | undefined
  if (ladder) {
    const ladderPlaintext = (await openMember({
      member: ladder,
      keyAgreementKey,
      keyResolver
    })) as { ladderSeed?: unknown }
    if (typeof ladderPlaintext.ladderSeed !== 'string') {
      throw new Error('Unlock record has a malformed ladder member.')
    }
    try {
      ladderSeed = base64urlnopad.decode(ladderPlaintext.ladderSeed)
    } catch {
      throw new Error('Unlock record has a malformed ladder member.')
    }
    if (ladderSeed.length !== LADDER_SEED_BYTES) {
      throw new Error('Unlock record has a malformed ladder member.')
    }
  }

  const expectedTag = hmac(
    sha256,
    bindingMacKey,
    bindingMacInput({
      controller: shell.controller,
      pointer,
      ...(ladderSeed ? { ladderSeed } : {})
    })
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
    throw new UnlockBindingError(
      "The unlock record's account binding does not verify under this " +
        'credential; the record is refused as forged.'
    )
  }

  return {
    contents: {
      controller: shell.controller,
      ...(typeof shell.email === 'string' && shell.email
        ? { email: shell.email }
        : {}),
      pointer,
      delegation: bridgePlaintext.delegation as IZcap,
      ...(delegatedClientsDelegation
        ? { delegatedClients: delegatedClientsDelegation }
        : {}),
      ...(ladderSeed ? { ladderSeed } : {}),
      createdAt
    },
    proofState
  }
}

/**
 * Re-mints an unlock record's pre-minted delegations: the revocation-cascade
 * path that replaces a rotted or expiring bridge (and, where the record
 * carries one, its annex Space sibling) while touching nothing else. The
 * shell, the ladder member, and the binding are carried VERBATIM (the re-mint
 * cannot decrypt any of them and does not need to -- each is self-contained
 * and the binding covers the core), the fresh delegations are sealed to the
 * credential's unlock KAK public half, and the frame is re-signed by the
 * acting client's account key -- the mixed-signer case the reader settles
 * against the verified document.
 *
 * The two members rot on one axis (same signer, same current-key-set rule,
 * same renewal window), so a re-mint pass reseals both atomically; a
 * `delegatedClients` member the caller supplies no fresh delegation for is
 * carried verbatim, sealed as it stands (self-contained, like the ladder) --
 * the fallback for a pass that cannot rebuild the annex target, never
 * the intended steady state.
 *
 * A record with no binding cannot be re-minted ({@link UnlockBindingError});
 * its credential must be rebound.
 *
 * @param options {object}
 * @param options.record {unknown}   the standing stored record
 * @param options.delegation {IZcap}   the freshly minted `did.jsonl`
 *   delegation
 * @param [options.delegatedClients] {IZcap}   the freshly minted
 *   annex Space delegation; when absent, an existing `delegatedClients`
 *   member travels verbatim
 * @param options.keyAgreementKey {IKeyAgreementKey}   the credential's unlock
 *   KAK, public half only
 * @param options.signer {RecordSigner}   the acting client's account key
 * @returns {Promise<SignedUnlockRecord>}
 */
export async function remintUnlockRecordDelegations({
  record,
  delegation,
  delegatedClients,
  keyAgreementKey,
  signer
}: {
  record: unknown
  delegation: IZcap
  delegatedClients?: IZcap
  keyAgreementKey: IKeyAgreementKey
  signer: RecordSigner
}): Promise<SignedUnlockRecord> {
  const { encryption, wrapped } = parseRecordFrame({
    record,
    label: 'unlock'
  })
  const binding = unlockRecordBinding({ record })
  const { delegatedClients: rawDelegatedClients, ladder: rawLadder } =
    record as { delegatedClients?: unknown; ladder?: unknown }
  const ladder =
    rawLadder === undefined
      ? undefined
      : parseSealedMember({ value: rawLadder, name: 'ladder' })
  const bridge = await sealMember({ data: { delegation }, keyAgreementKey })
  const sealedDelegatedClients = delegatedClients
    ? await sealMember({
        data: { delegation: delegatedClients },
        keyAgreementKey
      })
    : rawDelegatedClients === undefined
      ? undefined
      : parseSealedMember({
          value: rawDelegatedClients,
          name: 'delegatedClients'
        })
  return (await signRecordFrame({
    version: KEYRING_RECORD_VERSION,
    encryption,
    wrapped,
    signer,
    members: {
      binding,
      bridge,
      ...(sealedDelegatedClients
        ? { delegatedClients: sealedDelegatedClients }
        : {}),
      ...(ladder ? { ladder } : {})
    }
  })) as SignedUnlockRecord
}
