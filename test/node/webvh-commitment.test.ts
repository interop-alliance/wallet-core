/**
 * Unit tests for the `MultikeyCommitment` wire rule
 * (`src/webvh/didWebvh.ts`): the exact commitment encoding (a bare sha2-256
 * multihash, base64url no-pad, over a key's DECODED multikey bytes), the
 * decode-based verification that makes the scheme hash-agile, and the byoe
 * context the account document carries so the commitment's terms are
 * defined.
 */
import { describe, expect, it } from 'vitest'
import {
  createMultihash,
  decodeMultihash,
  MultihashAlgorithm
} from '@interop/data-integrity-core/multihash'
import {
  BASE_CONTEXT,
  defaultWebvhLogVerifier,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import { sha256, sha384 } from '@noble/hashes/sha2.js'
import { base58, base64urlnopad } from '@scure/base'
import { generateLadderSeed, ladderRung } from '../../src/clientAnnex/ladder.js'
import { publishUnlockKey } from '../../src/unlock/standingWebvh.js'
import {
  BYOE_CONTEXT_URL,
  commitmentMatchesKey,
  ensureDidWebvh,
  keyAgreementCommitment,
  mintClientWebvhUpdateKeys,
  MULTIKEY_COMMITMENT_VM_TYPE,
  rotateWebvhUpdateKey
} from '../../src/webvh/didWebvh.js'
import { unlockKeyVmId } from '../../src/unlock/standingWebvh.js'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-commitment'
const KEY_AGREEMENT_MULTIBASE =
  CANONICAL_CLIENT_KEYS[9].keyAgreementKeyMultibase

describe('the key-agreement commitment encoding', () => {
  it('is the base64url no-pad multihash of the decoded multikey bytes', async () => {
    // Computed from first principles here: strip the multibase prefix,
    // base58btc-decode to the multicodec prefix + raw key, sha2-256 those
    // bytes, and prepend the multihash header (0x12, 32).
    const decoded = base58.decode(KEY_AGREEMENT_MULTIBASE.slice(1))
    const digest = sha256(decoded)
    const expected = base64urlnopad.encode(
      new Uint8Array([0x12, digest.length, ...digest])
    )
    const commitment = await keyAgreementCommitment({
      keyAgreementKeyMultibase: KEY_AGREEMENT_MULTIBASE
    })
    expect(commitment).toBe(expected)
    // No multibase prefix, and the header really is what the multihash
    // codec produces.
    expect(commitment.startsWith('z')).toBe(false)
    expect(base64urlnopad.decode(commitment)).toEqual(
      createMultihash(digest, MultihashAlgorithm.SHA2_256)
    )
    const { algorithm } = decodeMultihash(base64urlnopad.decode(commitment))
    expect(algorithm).toBe(MultihashAlgorithm.SHA2_256)
  })

  it('hashes the decoded bytes, not the multibase string', async () => {
    // The preimage is deliberately encoding-independent, which is exactly
    // what parts it from the `nextKeyHashes` rule.
    const overTheString = base64urlnopad.encode(
      createMultihash(
        sha256(new TextEncoder().encode(KEY_AGREEMENT_MULTIBASE)),
        MultihashAlgorithm.SHA2_256
      )
    )
    expect(
      await keyAgreementCommitment({
        keyAgreementKeyMultibase: KEY_AGREEMENT_MULTIBASE
      })
    ).not.toBe(overTheString)
  })

  it('refuses a key that is not base58btc multibase', async () => {
    await expect(
      keyAgreementCommitment({ keyAgreementKeyMultibase: 'mAAAA' })
    ).rejects.toThrow(/base58btc/)
  })

  it('refuses a key that is not an X25519 multikey', async () => {
    // The multicodec header is enforced at mint time: committing to the
    // Ed25519 signing key where its X25519 twin was meant must fail here,
    // not as an opaque wrap error at the next epoch rotation. The check is
    // delegated to data-integrity-core's decodeMultikey, whose expected-codec
    // mismatch rides along as the refusal's cause.
    const refusal = await keyAgreementCommitment({
      keyAgreementKeyMultibase: CANONICAL_CLIENT_KEYS[9].signingKeyMultibase
    }).then(
      () => undefined,
      (err: unknown) => err as Error
    )
    expect(refusal?.message).toMatch(/X25519/)
    expect((refusal?.cause as Error)?.message).toMatch(/0xec/)
  })
})

describe('commitment verification', () => {
  it('matches the committed key and nothing else', async () => {
    const commitment = await keyAgreementCommitment({
      keyAgreementKeyMultibase: KEY_AGREEMENT_MULTIBASE
    })
    expect(
      commitmentMatchesKey({
        commitment,
        keyAgreementKeyMultibase: KEY_AGREEMENT_MULTIBASE
      })
    ).toBe(true)
    expect(
      commitmentMatchesKey({
        commitment,
        keyAgreementKeyMultibase:
          CANONICAL_CLIENT_KEYS[8].keyAgreementKeyMultibase
      })
    ).toBe(false)
  })

  it('treats a malformed or unsupported commitment as a non-match', () => {
    const decoded = base58.decode(KEY_AGREEMENT_MULTIBASE.slice(1))
    // A well-formed multihash under an algorithm with no implementation
    // here: the header names it, so it is a clean non-match rather than a
    // parse failure.
    const unsupported = base64urlnopad.encode(
      createMultihash(sha384(decoded), MultihashAlgorithm.SHA2_384)
    )
    for (const commitment of ['', 'not a multihash!!', 'AA', unsupported]) {
      expect(
        commitmentMatchesKey({
          commitment,
          keyAgreementKeyMultibase: KEY_AGREEMENT_MULTIBASE
        })
      ).toBe(false)
    }
    // A candidate key in another encoding cannot match either.
    expect(
      commitmentMatchesKey({
        commitment: base64urlnopad.encode(
          createMultihash(sha256(decoded), MultihashAlgorithm.SHA2_256)
        ),
        keyAgreementKeyMultibase: `m${KEY_AGREEMENT_MULTIBASE.slice(1)}`
      })
    ).toBe(false)
  })
})

describe("the account document's context", () => {
  // Genesis owns the context invariant: it installs the byoe context once,
  // and every later entry carries `@context` forward verbatim. No update call
  // site appends it, so the invariant must survive edits that pass no
  // context at all, not only the commitment publish.
  it('carries the byoe context at genesis and through every update', async () => {
    const { idStore, log } = memoryIdStore()
    const updateKeys = await mintClientWebvhUpdateKeys()
    const { did } = await ensureDidWebvh({
      idStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      clientKeys: { ...CANONICAL_CLIENT_KEYS[0] },
      updateKeys
    })
    const genesis = await resolveDIDFromLog(readLogFromString(log()!), {
      verifier: defaultWebvhLogVerifier
    })
    expect(genesis.doc?.['@context']).toEqual([
      ...BASE_CONTEXT,
      BYOE_CONTEXT_URL
    ])

    // The inventory edit publishes a commitment verification method; the
    // context that defines its terms survives the update, unduplicated.
    const ladderSeed = generateLadderSeed()
    const rung0 = await ladderRung({ ladderSeed, index: 0 })
    const unlockKeys = {
      keyAgreement: {
        commitment: await keyAgreementCommitment({
          keyAgreementKeyMultibase: KEY_AGREEMENT_MULTIBASE
        })
      },
      updateKeyMultibase: rung0.keyMultibase
    }
    await publishUnlockKey({
      idStore,
      signer: { kind: 'client', updateKeys },
      unlockKeys,
      ladderSeed
    })
    const updated = await resolveDIDFromLog(readLogFromString(log()!), {
      verifier: defaultWebvhLogVerifier
    })
    expect(updated.doc?.['@context']).toEqual(genesis.doc?.['@context'])

    // A rotation entry states no context of its own; the carry-forward alone
    // keeps the byoe context in place.
    await rotateWebvhUpdateKey({
      idStore,
      updateKeys,
      persistUpdateKeys: async () => {}
    })
    const rotated = await resolveDIDFromLog(readLogFromString(log()!), {
      verifier: defaultWebvhLogVerifier
    })
    expect(readLogFromString(log()!).length).toBe(3)
    expect(rotated.doc?.['@context']).toEqual(genesis.doc?.['@context'])
    const method = updated.doc?.verificationMethod?.find(
      entry =>
        entry.id ===
        unlockKeyVmId({ did, keyAgreement: unlockKeys.keyAgreement })
    ) as { type?: string } | undefined
    expect(method?.type).toBe(MULTIKEY_COMMITMENT_VM_TYPE)
  })
})
