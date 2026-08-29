/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The cryptosuite this library's four `ZcapClient` construction sites sign
 * delegation proofs with: `eddsa-jcs-2022`, which canonicalizes with JCS
 * rather than URDNA2015, so minting a grant runs no JSON-LD canonicalization
 * and needs no document loader at signing time.
 *
 * These sign for real rather than asserting over a stub, because the question
 * the swap raises is whether signing survives the loader the client actually
 * gets: all four build their client internally and pass none, so ezcap falls
 * through to `@interop/zcap`'s default loader, which serves the zcap context
 * and jsigs' strict loader and nothing else. `EddsaJcs2022` exposes no static
 * `CONTEXT` / `CONTEXT_URL`, so ezcap's auto-loader branch never fires either.
 *
 * Chain verification (a chain mixing both suites across its links, either
 * order) is pinned in `@interop/was-client`'s `delegation-suite.test.ts` over
 * the same ezcap and jsigs machinery; what is wallet-core's own is which
 * suite these four sites hand it, and that a chain minted here re-delegates.
 */
import { describe, expect, it } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { ZcapClient } from '@interop/ezcap'
import { rootCapabilityId } from '@interop/was-client/paths'
import { ladderVmZcapClient } from '../../src/clientAnnex/zcap.js'
import { agentsFromSeed } from '../../src/identity/agents.js'
import { didKeyZcapClient, webvhZcapClient } from '../../src/webvh/zcap.js'

const SPACE_URL = 'https://was.example/space/space-1'
const TARGET_URL = `${SPACE_URL}/notes/`
const ACCOUNT_DID = 'did:webvh:zQmScid:was.example:space:space-1:id'
const ROOT_ID = rootCapabilityId(SPACE_URL)

/**
 * The one delegation proof on a signed zcap. `IZcap.proof` allows a proof set;
 * ezcap signs exactly one.
 *
 * @param zcap {IZcap}
 * @returns {object}
 */
function delegationProof(zcap: IZcap): {
  type: string
  cryptosuite?: string
  verificationMethod: string
  capabilityChain: unknown[]
} {
  const { proof } = zcap as IZcap & { proof: unknown }
  return (Array.isArray(proof) ? proof[0] : proof) as {
    type: string
    cryptosuite?: string
    verificationMethod: string
    capabilityChain: unknown[]
  }
}

/**
 * Delegates a grant off the account Space's root capability with `client`.
 *
 * @param client {ZcapClient}
 * @param [capability] {string|IZcap}   the parent, the root id by default
 * @returns {Promise<IZcap>}
 */
async function grant(
  client: ZcapClient,
  capability: string | IZcap = ROOT_ID
): Promise<IZcap> {
  return (await client.delegate({
    capability,
    invocationTarget: TARGET_URL,
    controller: 'did:example:grantee',
    allowedActions: ['GET']
  })) as IZcap
}

function fixedSeed(byte: number): Uint8Array {
  return new Uint8Array(32).fill(byte)
}

describe('delegation-proof cryptosuite', () => {
  it('the enrolled client root client signs eddsa-jcs-2022', async () => {
    const { zcapClient } = await agentsFromSeed({ seed: fixedSeed(1) })

    const zcap = await grant(zcapClient)

    expect(delegationProof(zcap).type).toBe('DataIntegrityProof')
    expect(delegationProof(zcap).cryptosuite).toBe('eddsa-jcs-2022')
    // The suite appends its context to the signed zcap even though JCS
    // canonicalization never asks for it.
    expect(zcap['@context']).toContain(
      'https://w3id.org/security/data-integrity/v2'
    )
  })

  it('the did:webvh-keyId client signs eddsa-jcs-2022', async () => {
    const { keyAgent } = await agentsFromSeed({ seed: fixedSeed(2) })

    const zcap = await grant(webvhZcapClient({ keyAgent, did: ACCOUNT_DID }))

    expect(delegationProof(zcap).cryptosuite).toBe('eddsa-jcs-2022')
    expect(delegationProof(zcap).verificationMethod).toContain(ACCOUNT_DID)
  })

  it('the bare did:key client signs eddsa-jcs-2022', async () => {
    const { keyAgent } = await agentsFromSeed({ seed: fixedSeed(3) })

    const zcap = await grant(didKeyZcapClient({ keyAgent }))

    expect(delegationProof(zcap).cryptosuite).toBe('eddsa-jcs-2022')
  })

  it('the ladder VM client signs eddsa-jcs-2022', async () => {
    const client = await ladderVmZcapClient({
      accountDid: ACCOUNT_DID,
      ladderSeed: fixedSeed(4)
    })

    const zcap = await grant(client)

    expect(delegationProof(zcap).cryptosuite).toBe('eddsa-jcs-2022')
  })

  it('re-delegates a JCS-signed parent, embedded chain included', async () => {
    // The account's own re-delegation shape: the generation delegation a
    // transient visit rides is minted by the ladder VM client and re-delegated
    // by the visit's `webvhZcapClient`, with the parent embedded in the
    // child's `proof.capabilityChain`.
    const parent = await grant(
      await ladderVmZcapClient({
        accountDid: ACCOUNT_DID,
        ladderSeed: fixedSeed(5)
      })
    )
    const { keyAgent } = await agentsFromSeed({ seed: fixedSeed(6) })

    const child = await grant(
      webvhZcapClient({ keyAgent, did: ACCOUNT_DID }),
      parent
    )

    expect(delegationProof(child).cryptosuite).toBe('eddsa-jcs-2022')
    const { capabilityChain: chain } = delegationProof(child)
    expect(chain).toHaveLength(2)
    expect(chain[1]).toMatchObject({ id: parent.id })
  })

  it('pins the reverse mixed link: an Ed25519Signature2020 client cannot re-delegate a JCS-signed parent on its default loader', async () => {
    // URDNA2015 expands the parent embedded in `proof.capabilityChain`, which
    // now carries the data-integrity context, and neither ezcap's auto-loader
    // branch nor jsigs' strict loader serves it. The throw is at signing time
    // on the old-suite client, before any server sees the chain, so a server
    // verifying both suites does not cover it: each old-suite re-delegator is
    // bumped or given a loader that serves that context. No such client is
    // left in this library -- this asserts the hazard for the ones outside it,
    // and flipping to a pass means the hazard is gone.
    const parent = await grant(
      await ladderVmZcapClient({
        accountDid: ACCOUNT_DID,
        ladderSeed: fixedSeed(7)
      })
    )
    const { keyAgent } = await agentsFromSeed({ seed: fixedSeed(8) })
    const signer = keyAgent.getSigner()
    const legacyClient = new ZcapClient({
      SuiteClass: Ed25519Signature2020,
      invocationSigner: signer,
      delegationSigner: signer
    })

    await expect(grant(legacyClient, parent)).rejects.toThrow(
      'https://w3id.org/security/data-integrity/v2'
    )
  })
})
