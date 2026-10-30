/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the recorded-grant proof check
 * (`src/connections/grantProof.ts`). The grants are signed for real, by the
 * same clients the library mints delegations with, so the check is exercised
 * over the proof shape the wire carries: a listed signer with a forged
 * signature is refused, a tampered capability is refused, and on the annex
 * arm the leaf is verified against the generation's annex document, so a
 * forged leaf under a genuine generation delegation is refused and a grant
 * whose generation a GC collected is refused rather than renewed.
 */
import { describe, expect, it } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { rootCapabilityId } from '@interop/pws-client/paths'
import { agentsFromSeed } from '@interop/pws-client/identity'
import { ladderVmZcapClient } from '../../src/clientAnnex/zcap.js'
import { webvhZcapClient } from '../../src/webvh/zcap.js'
import type { PublishedKeyDocument } from '../../src/webvh/index.js'
import { verifyRecordedGrantProof } from '../../src/connections/index.js'
import type {
  AnnexDocumentResolver,
  ConnectionZcap
} from '../../src/connections/index.js'
import { fixedSeed } from './fixtures/fixedSeed.js'

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

/**
 * The check under test over one `signerCheck`. The root arm never consults
 * the annex, so the resolver defaults to one that resolves nothing.
 */
function verify({
  zcap,
  doc,
  clientAnnexDid,
  annexDocument = async () => undefined
}: {
  zcap: ConnectionZcap
  doc: PublishedKeyDocument
  clientAnnexDid?: string
  annexDocument?: AnnexDocumentResolver
}) {
  return verifyRecordedGrantProof({
    zcap,
    signerCheck: { doc, clientAnnexDid, annexDocument }
  })
}

async function rootArmGrant() {
  const zcap = await grant(await enrolledClient(1))
  const signer = proofOf(zcap).verificationMethod
  return { zcap, signer, doc: documentListing([signer]) }
}

/**
 * The annex arm: a generation delegation the ladder VM minted to an annex
 * DID, re-delegated by a per-visit key the account document never lists
 * but the generation's annex document does, under `capabilityDelegation`.
 * `annexDocument` resolves that document for the generation alone, as the
 * wallet's resolver does for a standing generation, and `undefined` for any
 * other (collected).
 */
async function annexArmGrant(annexDid = ANNEX_DID, visitSeed = 6) {
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
  const { keyAgent } = await agentsFromSeed({ seed: fixedSeed(visitSeed) })
  const visit = webvhZcapClient({ keyAgent, did: annexDid })
  const zcap = await grant(visit, parent)
  const parentSigner = proofOf(parent).verificationMethod
  const leafSigner = proofOf(zcap).verificationMethod
  const annexDocument: AnnexDocumentResolver = async ({ clientAnnexDid }) =>
    clientAnnexDid === annexDid ? documentListing([leafSigner]) : undefined
  return {
    zcap,
    parentSigner,
    leafSigner,
    doc: documentListing([parentSigner]),
    annexDocument
  }
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
    expect(await verify({ zcap, doc })).toEqual({
      verified: true,
      signerKeyId: signer
    })
  })

  it('refuses a listed signer whose signature is forged', async () => {
    const { zcap, doc } = await rootArmGrant()
    // The host plants a grant naming a current key, signed by nobody it
    // controls: here, another grant's signature over other bytes.
    const other = await grant(await enrolledClient(2))
    const forged = withProofValue(zcap, proofOf(other).proofValue)
    expect(await verify({ zcap: forged, doc })).toEqual({
      verified: false,
      reason: 'signature-invalid'
    })
  })

  it('refuses a capability edited after signing', async () => {
    const { zcap, doc } = await rootArmGrant()
    const widened = { ...zcap, allowedAction: ['GET', 'HEAD', 'POST'] }
    expect(await verify({ zcap: widened, doc })).toEqual({
      verified: false,
      reason: 'signature-invalid'
    })
  })

  it('refuses a signer the document does not list under capabilityDelegation', async () => {
    const { zcap, signer } = await rootArmGrant()
    const unlisted = documentListing([`${ACCOUNT_DID}#z6MkOther`])
    expect(await verify({ zcap, doc: unlisted })).toEqual({
      verified: false,
      reason: 'signer-unlisted'
    })
    // Listed, but not for delegation.
    const wrongRelation: PublishedKeyDocument = {
      ...documentListing([signer]),
      capabilityDelegation: []
    }
    expect(await verify({ zcap, doc: wrongRelation })).toEqual({
      verified: false,
      reason: 'signer-unlisted'
    })
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
    expect(await verify({ zcap: renamed, doc: byName })).toEqual({
      verified: false,
      reason: 'signature-invalid'
    })
    expect(await verify({ zcap, doc: byName })).toEqual({
      verified: false,
      reason: 'signer-unlisted'
    })
    // A member whose fragment is the signer's key but whose published key is
    // another is listed, and the signature does not verify under the
    // published key.
    const disagreeing: PublishedKeyDocument = {
      verificationMethod: [{ id: signer, publicKeyMultibase: 'z6MkOther' }],
      capabilityDelegation: [signer]
    }
    expect(await verify({ zcap, doc: disagreeing })).toEqual({
      verified: false,
      reason: 'signature-invalid'
    })
    // A member that publishes no key lists nothing, fragment or not.
    const unbacked: PublishedKeyDocument = { capabilityDelegation: [signer] }
    expect(await verify({ zcap, doc: unbacked })).toEqual({
      verified: false,
      reason: 'signer-unlisted'
    })
  })

  it('accepts the did:key form of a listed key', async () => {
    const { zcap, signer, doc } = await rootArmGrant()
    const multibase = signer.slice(signer.indexOf('#') + 1)
    const didKeyForm = `did:key:${multibase}#${multibase}`
    const renamed = structuredClone(zcap)
    proofOf(renamed).verificationMethod = didKeyForm
    // The key id is covered by the signature, so renaming it refuses; the
    // document match itself is on the multibase.
    expect(await verify({ zcap: renamed, doc })).toEqual({
      verified: false,
      reason: 'signature-invalid'
    })
    const { keyAgent } = await agentsFromSeed({ seed: fixedSeed(1) })
    const didKeyGrant = await grant(
      webvhZcapClient({ keyAgent, did: `did:key:${multibase}` })
    )
    expect(await verify({ zcap: didKeyGrant, doc })).toEqual({
      verified: true,
      signerKeyId: didKeyForm
    })
  })

  it('refuses an unsigned grant and a foreign suite', async () => {
    const { zcap, doc } = await rootArmGrant()
    const { proof: _proof, ...unsigned } = zcap as ConnectionZcap & {
      proof: unknown
    }
    expect(await verify({ zcap: unsigned as ConnectionZcap, doc })).toEqual({
      verified: false,
      reason: 'unsigned'
    })
    const nameless = structuredClone(zcap)
    delete (proofOf(nameless) as Partial<Proof>).verificationMethod
    expect(await verify({ zcap: nameless, doc })).toEqual({
      verified: false,
      reason: 'unsigned'
    })
    const legacy = structuredClone(zcap)
    proofOf(legacy).type = 'Ed25519Signature2020'
    expect(await verify({ zcap: legacy, doc })).toEqual({
      verified: false,
      reason: 'unsupported-suite'
    })
    const assertion = structuredClone(zcap)
    proofOf(assertion).proofPurpose = 'assertionMethod'
    expect(await verify({ zcap: assertion, doc })).toEqual({
      verified: false,
      reason: 'unsupported-suite'
    })
  })
})

describe('verifyRecordedGrantProof, the annex arm', () => {
  it('verifies the parent under a listed ladder VM and the leaf under the generation document', async () => {
    const { zcap, parentSigner, doc, annexDocument } = await annexArmGrant()
    expect(
      await verify({ zcap, doc, clientAnnexDid: ANNEX_DID, annexDocument })
    ).toEqual({ verified: true, signerKeyId: parentSigner })
    // The account has moved on to another generation of the same Space,
    // and the grant's own generation still stands (not yet collected).
    expect(
      await verify({
        zcap,
        doc,
        clientAnnexDid: COLLECTED_ANNEX_DID,
        annexDocument
      })
    ).toEqual({ verified: true, signerKeyId: parentSigner })
  })

  it('refuses a parent delegated to another Space, or with no pointed generation', async () => {
    const { zcap, doc, annexDocument } = await annexArmGrant()
    expect(
      await verify({
        zcap,
        doc,
        clientAnnexDid: OTHER_SPACE_ANNEX_DID,
        annexDocument
      })
    ).toEqual({ verified: false, reason: 'parent-not-annex' })
    expect(await verify({ zcap, doc, annexDocument })).toEqual({
      verified: false,
      reason: 'parent-not-annex'
    })
    const foreign = await annexArmGrant(OTHER_SPACE_ANNEX_DID)
    expect(
      await verify({
        zcap: foreign.zcap,
        doc: foreign.doc,
        clientAnnexDid: ANNEX_DID,
        annexDocument: foreign.annexDocument
      })
    ).toEqual({ verified: false, reason: 'parent-not-annex' })
    const notAnnex = withParent(zcap, {
      ...(chainOf(zcap)[1] as object),
      controller: ACCOUNT_DID
    })
    expect(
      await verify({
        zcap: notAnnex,
        doc,
        clientAnnexDid: ANNEX_DID,
        annexDocument
      })
    ).toEqual({ verified: false, reason: 'parent-not-annex' })
  })

  it('refuses a parent whose signature is forged or whose signer is unlisted, before any annex read', async () => {
    const { zcap, doc } = await annexArmGrant()
    const annexDocument = async () => {
      throw new Error('the annex must not be read for a refused parent')
    }
    const parent = chainOf(zcap)[1] as object
    const { zcap: other } = await rootArmGrant()
    const forgedParent = withProofValue(parent, proofOf(other).proofValue)
    expect(
      await verify({
        zcap: withParent(zcap, forgedParent),
        doc,
        clientAnnexDid: ANNEX_DID,
        annexDocument
      })
    ).toEqual({ verified: false, reason: 'signature-invalid' })
    const retired = documentListing([`${ACCOUNT_DID}#z6MkOther`])
    expect(
      await verify({
        zcap,
        doc: retired,
        clientAnnexDid: ANNEX_DID,
        annexDocument
      })
    ).toEqual({ verified: false, reason: 'signer-unlisted' })
  })

  it('refuses a forged leaf planted under a genuine generation delegation', async () => {
    const { zcap, doc, leafSigner, annexDocument } = await annexArmGrant()
    // The host copies the genuine parent out of the annex log under a leaf
    // naming a planted agent, with the genuine visit's key named as the
    // signer and another grant's signature as its proof.
    const { zcap: other } = await annexArmGrant(ANNEX_DID, 7)
    const planted = withParent(
      withProofValue(other, proofOf(zcap).proofValue),
      chainOf(zcap)[1] as object
    )
    proofOf(planted).verificationMethod = leafSigner
    expect(
      await verify({
        zcap: planted,
        doc,
        clientAnnexDid: ANNEX_DID,
        annexDocument
      })
    ).toEqual({ verified: false, reason: 'leaf-signature-invalid' })
    // The same leaf signed by a visit key the generation never listed.
    expect(
      await verify({
        zcap: withParent(other, chainOf(zcap)[1] as object),
        doc,
        clientAnnexDid: ANNEX_DID,
        annexDocument
      })
    ).toEqual({ verified: false, reason: 'leaf-signer-unlisted' })
    // A junk proof under the genuine parent, and a leaf edited after signing.
    const junk = withProofValue(zcap, 'z3junk')
    expect(
      await verify({
        zcap: junk,
        doc,
        clientAnnexDid: ANNEX_DID,
        annexDocument
      })
    ).toEqual({ verified: false, reason: 'leaf-signature-invalid' })
    const widened = { ...zcap, allowedAction: ['GET', 'HEAD', 'POST'] }
    expect(
      await verify({
        zcap: widened,
        doc,
        clientAnnexDid: ANNEX_DID,
        annexDocument
      })
    ).toEqual({ verified: false, reason: 'leaf-signature-invalid' })
  })

  it('refuses a leaf whose per-visit key the generation document does not list', async () => {
    const { zcap, doc, leafSigner } = await annexArmGrant()
    const otherVisit = documentListing([`${ANNEX_DID}#z6MkOther`])
    expect(
      await verify({
        zcap,
        doc,
        clientAnnexDid: ANNEX_DID,
        annexDocument: async () => otherVisit
      })
    ).toEqual({ verified: false, reason: 'leaf-signer-unlisted' })
    // Listed, but not for delegation.
    const invocationOnly: PublishedKeyDocument = {
      ...documentListing([leafSigner]),
      capabilityDelegation: []
    }
    expect(
      await verify({
        zcap,
        doc,
        clientAnnexDid: ANNEX_DID,
        annexDocument: async () => invocationOnly
      })
    ).toEqual({ verified: false, reason: 'leaf-signer-unlisted' })
  })

  it('refuses an unsigned leaf, or one on a foreign suite, under a genuine parent', async () => {
    const { zcap, doc, annexDocument } = await annexArmGrant()
    const nameless = structuredClone(zcap)
    delete (proofOf(nameless) as Partial<Proof>).verificationMethod
    expect(
      await verify({
        zcap: nameless,
        doc,
        clientAnnexDid: ANNEX_DID,
        annexDocument
      })
    ).toEqual({ verified: false, reason: 'leaf-unsigned' })
    const foreignSuite = structuredClone(zcap)
    proofOf(foreignSuite).cryptosuite = 'eddsa-rdfc-2022'
    expect(
      await verify({
        zcap: foreignSuite,
        doc,
        clientAnnexDid: ANNEX_DID,
        annexDocument
      })
    ).toEqual({ verified: false, reason: 'leaf-unsupported-suite' })
  })

  it('resolves each generation once per signerCheck object, across concurrent grants', async () => {
    const { zcap, doc, parentSigner, annexDocument } = await annexArmGrant()
    const { zcap: second } = await annexArmGrant(ANNEX_DID, 6)
    const other = await annexArmGrant(COLLECTED_ANNEX_DID, 8)
    const calls: string[] = []
    const counting: AnnexDocumentResolver = async options => {
      calls.push(options.clientAnnexDid)
      return (await annexDocument(options)) ?? other.annexDocument(options)
    }
    const signerCheck = {
      doc,
      clientAnnexDid: ANNEX_DID,
      annexDocument: counting
    }
    const results = await Promise.all(
      [zcap, second, zcap, other.zcap].map(grant =>
        verifyRecordedGrantProof({ zcap: grant, signerCheck })
      )
    )
    expect(results.map(result => result.verified)).toEqual([
      true,
      true,
      true,
      true
    ])
    expect(results[0]).toEqual({ verified: true, signerKeyId: parentSigner })
    // One read per generation, the second one only for the other generation.
    expect(calls).toEqual([ANNEX_DID, COLLECTED_ANNEX_DID])
    // A later check under the same object reads nothing more.
    await verifyRecordedGrantProof({ zcap, signerCheck })
    expect(calls).toHaveLength(2)
    // Another signerCheck object reads again.
    await verifyRecordedGrantProof({
      zcap,
      signerCheck: { ...signerCheck }
    })
    expect(calls).toHaveLength(3)
    // A rejected read is not kept: the checks in flight share it, and the
    // next check under the same object asks again.
    let attempts = 0
    const flaky: AnnexDocumentResolver = async options => {
      attempts += 1
      if (attempts === 1) {
        throw new Error('annex unreadable')
      }
      return annexDocument(options)
    }
    const retried = { doc, clientAnnexDid: ANNEX_DID, annexDocument: flaky }
    const outcomes = await Promise.allSettled(
      [zcap, second].map(grant =>
        verifyRecordedGrantProof({ zcap: grant, signerCheck: retried })
      )
    )
    expect(outcomes.map(outcome => outcome.status)).toEqual([
      'rejected',
      'rejected'
    ])
    expect(attempts).toBe(1)
    expect(
      await verifyRecordedGrantProof({ zcap, signerCheck: retried })
    ).toEqual({ verified: true, signerKeyId: parentSigner })
    expect(attempts).toBe(2)
  })

  it('refuses a grant whose generation was collected', async () => {
    const { zcap, doc } = await annexArmGrant()
    let resolvedFor: string | undefined
    const collected: AnnexDocumentResolver = async ({ clientAnnexDid }) => {
      resolvedFor = clientAnnexDid
      return undefined
    }
    expect(
      await verify({
        zcap,
        doc,
        clientAnnexDid: COLLECTED_ANNEX_DID,
        annexDocument: collected
      })
    ).toEqual({ verified: false, reason: 'leaf-generation-collected' })
    // The resolver is asked for the parent's generation, not the pointed one.
    expect(resolvedFor).toBe(ANNEX_DID)
    // A resolver that throws (the log could not be read) propagates.
    await expect(
      verify({
        zcap,
        doc,
        clientAnnexDid: ANNEX_DID,
        annexDocument: async () => {
          throw new Error('annex unreadable')
        }
      })
    ).rejects.toThrow('annex unreadable')
  })
})
