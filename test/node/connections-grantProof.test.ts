/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the recorded-grant proof check
 * (`src/connections/grantProof.ts`). The grants are signed for real, by the
 * same clients the library mints delegations with, so the check is exercised
 * over the proof shape the wire carries: a listed signer with a forged
 * signature is refused, a tampered capability is refused, and a genuine
 * annex-arm grant under a generation a GC collected passes.
 */
import { describe, expect, it } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { rootCapabilityId } from '@interop/was-client/paths'
import { agentsFromSeed } from '@interop/was-client/identity'
import { ladderVmZcapClient } from '../../src/clientAnnex/zcap.js'
import { webvhZcapClient } from '../../src/webvh/zcap.js'
import type { PublishedKeyDocument } from '../../src/webvh/index.js'
import { verifyRecordedGrantProof } from '../../src/connections/index.js'
import type { ConnectionZcap } from '../../src/connections/index.js'

const SPACE_URL = 'https://was.example/space/space-1'
const ROOT_ID = rootCapabilityId(SPACE_URL)
const ACCOUNT_DID = 'did:webvh:zQmScid:was.example:space:space-1:id'
const ANNEX_DID =
  'did:webvh:zQmScid:was.example:space:space-1:gen-AAAAAAAAAAAAAAAA'
const COLLECTED_ANNEX_DID =
  'did:webvh:zQmScid:was.example:space:space-1:gen-BBBBBBBBBBBBBBBB'
const OTHER_SPACE_ANNEX_DID =
  'did:webvh:zQmScid:was.example:space:space-2:gen-CCCCCCCCCCCCCCCC'
const AGENT = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

function fixedSeed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte)
}

type Proof = {
  verificationMethod: string
  proofValue: string
  type: string
  cryptosuite: string
  proofPurpose: string
}

function proofOf(zcap: object): Proof {
  return (zcap as { proof: Proof }).proof
}

/**
 * A document listing the given verification-method ids under
 * `capabilityDelegation`, each with the key its fragment names.
 */
function documentListing(keyIds: string[]): PublishedKeyDocument {
  return {
    verificationMethod: keyIds.map(id => ({
      id,
      publicKeyMultibase: id.slice(id.indexOf('#') + 1)
    })),
    capabilityDelegation: keyIds
  }
}

/**
 * A grant to the agent over the Space's `audience` collection, delegated
 * off `capability` by `client`.
 */
async function grant(
  client: ZcapClient,
  capability: string | IZcap = ROOT_ID
): Promise<ConnectionZcap> {
  return (await client.delegate({
    capability,
    invocationTarget: `${SPACE_URL}/audience/`,
    controller: AGENT,
    allowedActions: ['GET', 'HEAD']
  })) as unknown as ConnectionZcap
}

async function enrolledClient(byte: number) {
  const { keyAgent } = await agentsFromSeed({ seed: fixedSeed(byte) })
  return webvhZcapClient({ keyAgent, did: ACCOUNT_DID })
}

async function rootArmGrant() {
  const zcap = await grant(await enrolledClient(1))
  const signer = proofOf(zcap).verificationMethod
  return { zcap, signer, doc: documentListing([signer]) }
}

/**
 * The annex arm: a generation delegation the ladder VM minted to an annex
 * DID, re-delegated by a per-visit key the account document never lists.
 */
async function annexArmGrant(annexDid = ANNEX_DID) {
  const ladder = await ladderVmZcapClient({
    accountDid: ACCOUNT_DID,
    ladderSeed: fixedSeed(4)
  })
  const parent = (await ladder.delegate({
    capability: ROOT_ID,
    invocationTarget: `${SPACE_URL}/`,
    controller: annexDid,
    allowedActions: ['GET', 'HEAD', 'POST', 'PUT', 'DELETE']
  })) as IZcap
  const { keyAgent } = await agentsFromSeed({ seed: fixedSeed(6) })
  const visit = webvhZcapClient({ keyAgent, did: annexDid })
  const zcap = await grant(visit, parent)
  const parentSigner = proofOf(parent).verificationMethod
  return { zcap, parentSigner, doc: documentListing([parentSigner]) }
}

/**
 * The same capability with its proof's `proofValue` replaced by another
 * proof's: the signer's name kept, the signature forged.
 */
function withProofValue<Zcap extends object>(
  zcap: Zcap,
  proofValue: string
): Zcap {
  const copy = structuredClone(zcap)
  proofOf(copy).proofValue = proofValue
  return copy
}

/**
 * A capability's `proof.capabilityChain`, as the delegation suite wrote it.
 */
function chainOf(zcap: object): unknown[] {
  return (zcap as unknown as { proof: { capabilityChain: unknown[] } }).proof
    .capabilityChain
}

/**
 * The same capability with its embedded parent replaced.
 */
function withParent(zcap: ConnectionZcap, parent: object): ConnectionZcap {
  const copy = structuredClone(zcap)
  const chain = chainOf(copy)
  chain[chain.length - 1] = parent
  return copy
}

describe('verifyRecordedGrantProof, the root arm', () => {
  it('verifies a grant an enrolled client signed under a listed key', async () => {
    const { zcap, signer, doc } = await rootArmGrant()
    expect(
      await verifyRecordedGrantProof({ zcap, signerCheck: { doc } })
    ).toEqual({ verified: true, signerKeyId: signer })
  })

  it('refuses a listed signer whose signature is forged', async () => {
    const { zcap, doc } = await rootArmGrant()
    // The host plants a grant naming a current key, signed by nobody it
    // controls: here, another grant's signature over other bytes.
    const other = await grant(await enrolledClient(2))
    const forged = withProofValue(zcap, proofOf(other).proofValue)
    expect(
      await verifyRecordedGrantProof({ zcap: forged, signerCheck: { doc } })
    ).toEqual({ verified: false, reason: 'signature-invalid' })
  })

  it('refuses a capability edited after signing', async () => {
    const { zcap, doc } = await rootArmGrant()
    const widened = { ...zcap, allowedAction: ['GET', 'HEAD', 'POST'] }
    expect(
      await verifyRecordedGrantProof({ zcap: widened, signerCheck: { doc } })
    ).toEqual({ verified: false, reason: 'signature-invalid' })
  })

  it('refuses a signer the document does not list under capabilityDelegation', async () => {
    const { zcap, signer } = await rootArmGrant()
    const unlisted = documentListing([`${ACCOUNT_DID}#z6MkOther`])
    expect(
      await verifyRecordedGrantProof({ zcap, signerCheck: { doc: unlisted } })
    ).toEqual({ verified: false, reason: 'signer-unlisted' })
    // Listed, but not for delegation.
    const wrongRelation: PublishedKeyDocument = {
      ...documentListing([signer]),
      capabilityDelegation: []
    }
    expect(
      await verifyRecordedGrantProof({
        zcap,
        signerCheck: { doc: wrongRelation }
      })
    ).toEqual({ verified: false, reason: 'signer-unlisted' })
  })

  it('verifies under the key the named member publishes, not its fragment', async () => {
    const { zcap, signer } = await rootArmGrant()
    const multibase = signer.slice(signer.indexOf('#') + 1)
    // The fragment is an opaque selector. A proof naming a member by a
    // non-key fragment dereferences to that member and verifies under the
    // key it publishes; here the renamed key id is covered by the signature,
    // so the listed key refuses the signature rather than the listing. The
    // original proof names `#<multibase>`, which this document has no member
    // for, so it is unlisted even though the key itself is published.
    const namedId = `${ACCOUNT_DID}#key-1`
    const byName: PublishedKeyDocument = {
      verificationMethod: [{ id: namedId, publicKeyMultibase: multibase }],
      capabilityDelegation: [namedId]
    }
    const renamed = structuredClone(zcap)
    proofOf(renamed).verificationMethod = namedId
    expect(
      await verifyRecordedGrantProof({
        zcap: renamed,
        signerCheck: { doc: byName }
      })
    ).toEqual({ verified: false, reason: 'signature-invalid' })
    expect(
      await verifyRecordedGrantProof({ zcap, signerCheck: { doc: byName } })
    ).toEqual({ verified: false, reason: 'signer-unlisted' })
    // A member whose fragment is the signer's key but whose published key is
    // another is listed, and the signature does not verify under the
    // published key.
    const disagreeing: PublishedKeyDocument = {
      verificationMethod: [{ id: signer, publicKeyMultibase: 'z6MkOther' }],
      capabilityDelegation: [signer]
    }
    expect(
      await verifyRecordedGrantProof({
        zcap,
        signerCheck: { doc: disagreeing }
      })
    ).toEqual({ verified: false, reason: 'signature-invalid' })
    // A member that publishes no key lists nothing, fragment or not.
    const unbacked: PublishedKeyDocument = { capabilityDelegation: [signer] }
    expect(
      await verifyRecordedGrantProof({ zcap, signerCheck: { doc: unbacked } })
    ).toEqual({ verified: false, reason: 'signer-unlisted' })
  })

  it('accepts the did:key form of a listed key', async () => {
    const { zcap, signer, doc } = await rootArmGrant()
    const multibase = signer.slice(signer.indexOf('#') + 1)
    const didKeyForm = `did:key:${multibase}#${multibase}`
    const renamed = structuredClone(zcap)
    proofOf(renamed).verificationMethod = didKeyForm
    // The key id is covered by the signature, so renaming it refuses; the
    // document match itself is on the multibase.
    expect(
      await verifyRecordedGrantProof({ zcap: renamed, signerCheck: { doc } })
    ).toEqual({ verified: false, reason: 'signature-invalid' })
    const { keyAgent } = await agentsFromSeed({ seed: fixedSeed(1) })
    const didKeyGrant = await grant(
      webvhZcapClient({ keyAgent, did: `did:key:${multibase}` })
    )
    expect(
      await verifyRecordedGrantProof({
        zcap: didKeyGrant,
        signerCheck: { doc }
      })
    ).toEqual({ verified: true, signerKeyId: didKeyForm })
  })

  it('refuses an unsigned grant and a foreign suite', async () => {
    const { zcap, doc } = await rootArmGrant()
    const { proof: _proof, ...unsigned } = zcap as ConnectionZcap & {
      proof: unknown
    }
    expect(
      await verifyRecordedGrantProof({
        zcap: unsigned as ConnectionZcap,
        signerCheck: { doc }
      })
    ).toEqual({ verified: false, reason: 'unsigned' })
    const nameless = structuredClone(zcap)
    delete (proofOf(nameless) as Partial<Proof>).verificationMethod
    expect(
      await verifyRecordedGrantProof({ zcap: nameless, signerCheck: { doc } })
    ).toEqual({ verified: false, reason: 'unsigned' })
    const legacy = structuredClone(zcap)
    proofOf(legacy).type = 'Ed25519Signature2020'
    expect(
      await verifyRecordedGrantProof({ zcap: legacy, signerCheck: { doc } })
    ).toEqual({ verified: false, reason: 'unsupported-suite' })
    const assertion = structuredClone(zcap)
    proofOf(assertion).proofPurpose = 'assertionMethod'
    expect(
      await verifyRecordedGrantProof({ zcap: assertion, signerCheck: { doc } })
    ).toEqual({ verified: false, reason: 'unsupported-suite' })
  })
})

describe('verifyRecordedGrantProof, the annex arm', () => {
  it('verifies the parent under a listed ladder VM, the pointed generation or a collected one', async () => {
    const { zcap, parentSigner, doc } = await annexArmGrant()
    expect(
      await verifyRecordedGrantProof({
        zcap,
        signerCheck: { doc, clientAnnexDid: ANNEX_DID }
      })
    ).toEqual({ verified: true, signerKeyId: parentSigner })
    // The account has moved on to another generation of the same Space.
    expect(
      await verifyRecordedGrantProof({
        zcap,
        signerCheck: { doc, clientAnnexDid: COLLECTED_ANNEX_DID }
      })
    ).toEqual({ verified: true, signerKeyId: parentSigner })
  })

  it('refuses a parent delegated to another Space, or with no pointed generation', async () => {
    const { zcap, doc } = await annexArmGrant()
    expect(
      await verifyRecordedGrantProof({
        zcap,
        signerCheck: { doc, clientAnnexDid: OTHER_SPACE_ANNEX_DID }
      })
    ).toEqual({ verified: false, reason: 'parent-not-annex' })
    expect(
      await verifyRecordedGrantProof({ zcap, signerCheck: { doc } })
    ).toEqual({ verified: false, reason: 'parent-not-annex' })
    const foreign = await annexArmGrant(OTHER_SPACE_ANNEX_DID)
    expect(
      await verifyRecordedGrantProof({
        zcap: foreign.zcap,
        signerCheck: { doc: foreign.doc, clientAnnexDid: ANNEX_DID }
      })
    ).toEqual({ verified: false, reason: 'parent-not-annex' })
    const notAnnex = withParent(zcap, {
      ...(chainOf(zcap)[1] as object),
      controller: ACCOUNT_DID
    })
    expect(
      await verifyRecordedGrantProof({
        zcap: notAnnex,
        signerCheck: { doc, clientAnnexDid: ANNEX_DID }
      })
    ).toEqual({ verified: false, reason: 'parent-not-annex' })
  })

  it('refuses a parent whose signature is forged or whose signer is unlisted', async () => {
    const { zcap, doc } = await annexArmGrant()
    const parent = chainOf(zcap)[1] as object
    const { zcap: other } = await rootArmGrant()
    const forgedParent = withProofValue(parent, proofOf(other).proofValue)
    expect(
      await verifyRecordedGrantProof({
        zcap: withParent(zcap, forgedParent),
        signerCheck: { doc, clientAnnexDid: ANNEX_DID }
      })
    ).toEqual({ verified: false, reason: 'signature-invalid' })
    const retired = documentListing([`${ACCOUNT_DID}#z6MkOther`])
    expect(
      await verifyRecordedGrantProof({
        zcap,
        signerCheck: { doc: retired, clientAnnexDid: ANNEX_DID }
      })
    ).toEqual({ verified: false, reason: 'signer-unlisted' })
  })

  it('does not verify the leaf, whose per-visit key the document never lists', async () => {
    const { zcap, doc } = await annexArmGrant()
    const { zcap: other } = await annexArmGrant()
    const forgedLeaf = withProofValue(zcap, proofOf(other).proofValue)
    expect(
      await verifyRecordedGrantProof({
        zcap: forgedLeaf,
        signerCheck: { doc, clientAnnexDid: ANNEX_DID }
      })
    ).toMatchObject({ verified: true })
  })
})
