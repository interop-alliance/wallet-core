/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The one-reader agreement over a delegation signer: every reader that
 * decides whether a recorded delegation's signer still stands in the account
 * document (`delegationSignerKey`, `delegationKeyInDocument`,
 * `delegationSignerGone`, `recordedZcapStale`, `agentGrantDue`,
 * `deriveGrantSignerState`, `classifyGrantRevocationRefusal`,
 * `agentConnectionsSignedBy`, `verifyRecordedGrantProof`) names the same key
 * over one document. The document carries a `capabilityDelegation` member
 * whose id fragment and `publicKeyMultibase` disagree, so a reader that read
 * the fragment as the key would answer differently from one that took the
 * published key; the DID Core reading is the published key, and the fragment
 * is an opaque selector.
 */
import { describe, expect, it } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'
import { zcapClientForSigner } from '@interop/pws-client'
import { rootCapabilityId } from '@interop/pws-client/paths'
import { agentsFromSeed } from '@interop/pws-client/identity'
import { webvhSigner, webvhZcapClient } from '../../src/webvh/zcap.js'
import {
  clientSigningKeyMultibase,
  delegationKeyInDocument,
  delegationSignerGone,
  delegationSignerKey,
  recordedZcapStale
} from '../../src/webvh/index.js'
import type { PublishedKeyDocument } from '../../src/webvh/index.js'
import { deriveGrantSignerState } from '../../src/clients/index.js'
import { classifyGrantRevocationRefusal } from '../../src/clientAnnex/grantRevocation.js'
import {
  AGENT_GRANT_RENEWAL_WINDOW_MS,
  agentConnectionsSignedBy,
  agentGrantDue,
  parseConnectionEntry,
  verifyRecordedGrantProof
} from '../../src/connections/index.js'
import type { ConnectionZcap } from '../../src/connections/index.js'
import { fixedSeed } from './fixtures/fixedSeed.js'

const SPACE_URL = 'https://was.example/space/space-1/'
const ROOT_ID = rootCapabilityId(SPACE_URL)
const ACCOUNT_DID = 'did:webvh:zQmScid:was.example:space:space-1:id'
const AGENT = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const STAMP = '2026-10-01T00:00:00.000Z'
const NOW = Date.parse(STAMP)

/**
 * A grant to the agent over the Space's `audience` collection, delegated off
 * the root by a client signing under `signerKeyId` with its own key.
 */
async function grantSignedAs({
  signerKeyId,
  seed
}: {
  signerKeyId: string
  seed: number
}): Promise<ConnectionZcap> {
  const { keyAgent } = await agentsFromSeed({ seed: fixedSeed(seed) })
  const signer = {
    ...webvhSigner({ keyAgent, did: ACCOUNT_DID }),
    id: signerKeyId
  }
  return (await zcapClientForSigner({ signer }).delegate({
    capability: ROOT_ID,
    invocationTarget: `${SPACE_URL}audience/`,
    controller: AGENT,
    allowedActions: ['GET', 'HEAD'],
    expires: new Date(NOW + AGENT_GRANT_RENEWAL_WINDOW_MS + 86_400_000)
  })) as unknown as ConnectionZcap
}

function agentEntryHolding(zcap: ConnectionZcap) {
  const entry = parseConnectionEntry({
    version: 1,
    kind: 'agent',
    id: AGENT,
    firstSeen: STAMP,
    lastSeen: STAMP,
    grants: [{ zcap, grantKind: 'grant', grantedAt: STAMP }],
    writers: []
  })
  if (entry === undefined) {
    throw new Error('fixture did not parse')
  }
  return entry
}

describe('every delegation-signer reader agrees over one document', async () => {
  const { keyAgent } = await agentsFromSeed({ seed: fixedSeed(1) })
  const key = clientSigningKeyMultibase({ keyAgent })
  // The member's id fragment is a selector unrelated to the key it
  // publishes.
  const SELECTOR_ID = `${ACCOUNT_DID}#selector`
  const FRAGMENT_ID = `${ACCOUNT_DID}#${key}`
  const DID_KEY_ID = `did:key:${key}#${key}`
  const doc: PublishedKeyDocument = {
    verificationMethod: [{ id: SELECTOR_ID, publicKeyMultibase: key }],
    capabilityDelegation: [SELECTOR_ID]
  }

  const bySelector = await grantSignedAs({ signerKeyId: SELECTOR_ID, seed: 1 })
  const byFragment = await grantSignedAs({ signerKeyId: FRAGMENT_ID, seed: 1 })
  const byDidKey = (await webvhZcapClient({
    keyAgent,
    did: `did:key:${key}`
  }).delegate({
    capability: ROOT_ID,
    invocationTarget: `${SPACE_URL}audience/`,
    controller: AGENT,
    allowedActions: ['GET', 'HEAD'],
    expires: new Date(NOW + AGENT_GRANT_RENEWAL_WINDOW_MS + 86_400_000)
  })) as unknown as ConnectionZcap

  const signerCheck = {
    accountDid: ACCOUNT_DID,
    doc,
    annexDocument: async () => undefined
  }

  it.each([
    ['the member id', SELECTOR_ID, bySelector, true],
    ['the did:key form of the published key', DID_KEY_ID, byDidKey, true],
    [
      'the published key as a fragment under the account DID',
      FRAGMENT_ID,
      byFragment,
      false
    ]
  ])(
    'reads a signer named by %s the same way everywhere',
    async (_, signerKeyId, zcap, listed) => {
      expect(delegationSignerKey({ doc, signerKeyId })).toBe(
        listed ? key : undefined
      )
      expect(
        delegationKeyInDocument({ doc, delegationKeyId: signerKeyId })
      ).toBe(listed)
      expect(
        delegationSignerGone({ zcap: zcap as unknown as IZcap, doc })
      ).toBe(!listed)
      expect(
        recordedZcapStale({
          doc,
          delegationKeyId: signerKeyId,
          expires: zcap.expires,
          now: NOW
        })
      ).toBe(!listed)
      expect(
        deriveGrantSignerState({
          signerKeyIds: [signerKeyId],
          accountDid: ACCOUNT_DID,
          doc
        })
      ).toBe(listed ? 'active' : 'orphaned')
      expect(
        classifyGrantRevocationRefusal({
          zcap: zcap as unknown as IZcap,
          signerCheck,
          now: NOW
        })
      ).toBe(listed ? undefined : 'orphaned')
      const entries = [agentEntryHolding(zcap)]
      // Attribution by the signer's exact id always finds the grant; by the
      // bare key, only when the id names that key.
      expect(
        agentConnectionsSignedBy({
          entries,
          keyId: signerKeyId,
          spaceUrl: SPACE_URL,
          doc
        })
      ).toEqual(entries)
      expect(
        agentConnectionsSignedBy({
          entries,
          keyId: key,
          spaceUrl: SPACE_URL,
          doc
        })
      ).toEqual(listed ? entries : [])
      const proof = await verifyRecordedGrantProof({ zcap, signerCheck })
      expect(proof).toEqual(
        listed
          ? { verified: true, signerKeyId }
          : { verified: false, reason: 'signer-unlisted' }
      )
      // A grant with no embedded parent is never due on the signer axis, and
      // an embedded parent signed the same way reads through the same reader.
      expect(agentGrantDue({ zcap, doc, now: NOW })).toBe(false)
    }
  )

  it('reads an embedded generation delegation through the same reader', () => {
    const generation = (signerKeyId: string): ConnectionZcap =>
      ({
        ...bySelector,
        id: 'urn:zcap:leaf',
        parentCapability: 'urn:zcap:generation',
        proof: {
          ...(bySelector as unknown as { proof: object }).proof,
          capabilityChain: [
            ROOT_ID,
            {
              id: 'urn:zcap:generation',
              controller:
                'did:webvh:zQmScid:was.example:space:space-1:gen-AAAAAAAAAAAAAAAA',
              parentCapability: ROOT_ID,
              proof: { verificationMethod: signerKeyId }
            }
          ]
        }
      }) as unknown as ConnectionZcap
    expect(
      agentGrantDue({
        zcap: generation(SELECTOR_ID),
        pointedDelegationId: 'urn:zcap:other',
        doc,
        now: NOW
      })
    ).toBe(true)
    expect(
      agentGrantDue({
        zcap: generation(FRAGMENT_ID),
        pointedDelegationId: 'urn:zcap:other',
        doc,
        now: NOW
      })
    ).toBe(false)
  })
})
