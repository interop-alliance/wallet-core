/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The replica grants: the pull delegation's permanent wire shape (the
 * Space's canonical container URL as target on a sub-path deployment, the
 * replica server's DID as sole controller, `['GET']`, the Space-rooted
 * two-link chain, the 365-day expiry) under both signers the session kinds
 * hold, the same shape aimed at the auxiliary Space, the refusal of a grantee
 * that is not a replica server DID, and the replicas-route maintenance grant
 * (the bare replicas container URL on the replica server, the four-verb
 * vocabulary, the ladder VM's bare did:key as controller, the ten-minute
 * default and a caller's shorter lifetime, the refusal of a controller that is
 * not a bare did:key and of a lifetime past the bound).
 */
import { describe, expect, it } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'
import { agentsFromSeed } from '@interop/pws-client/identity'
import { rootCapabilityId, spaceUrlById } from '@interop/pws-client/paths'
import {
  mintReplicaPullDelegation,
  mintReplicasMaintenanceGrant,
  REPLICA_PULL_ACTIONS,
  REPLICA_PULL_TTL_MS,
  REPLICAS_MAINTENANCE_ACTIONS,
  REPLICAS_MAINTENANCE_TTL_MS
} from '../../src/clientAnnex/replicaGrants.js'
import {
  ladderVmAgent,
  ladderVmZcapClient
} from '../../src/clientAnnex/zcap.js'
import { ladderVmKeyMultibase } from '../../src/webvh/ladderDerivation.js'
import {
  clientSigningKeyMultibase,
  webvhZcapClient
} from '../../src/webvh/zcap.js'
import { STANDING_ZCAP_TTL_MS } from '../../src/webvh/standingZcap.js'
import { fixedSeed } from './fixtures/fixedSeed.js'

/**
 * A sub-path deployment, so the path-join discipline is pinned.
 */
const WAS_URL = 'https://storage.example/was'
const ACCOUNT_SPACE_ID = 'account-space-1'
const AUX_SPACE_ID = 'aux-space-1'
const ACCOUNT_DID = 'did:webvh:QmScidAccount:storage.example'

/**
 * The replica server, on its own sub-path deployment.
 */
const REPLICA_URL = 'https://replica.example/pws'
const REPLICA_SPACE_ID = 'replica-space-1'
const REPLICA_SERVER_DID =
  'did:webvh:QmRepLicaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:replica.example:space:server:id'

const MINUTE_MS = 60 * 1000

/**
 * One ladder seed serves every test; nothing here persists across tests.
 */
const LADDER_SEED = fixedSeed(31)

type DelegatedShape = IZcap & {
  expires: string
  allowedAction: string[]
  parentCapability: string
  proof: { verificationMethod: string; capabilityChain: unknown[] }
}

/**
 * ezcap stores second precision.
 */
function toSeconds(ms: number): number {
  return Math.floor(ms / 1000) * 1000
}

/**
 * The ladder VM under its account-document id, and as its bare did:key.
 */
async function ladderSigner() {
  const [zcapClient, agent, ladderKey] = await Promise.all([
    ladderVmZcapClient({ accountDid: ACCOUNT_DID, ladderSeed: LADDER_SEED }),
    ladderVmAgent({ ladderSeed: LADDER_SEED }),
    ladderVmKeyMultibase({ ladderSeed: LADDER_SEED })
  ])
  return { zcapClient, controller: agent.id, ladderKey }
}

async function mintPull(
  options: Omit<Parameters<typeof mintReplicaPullDelegation>[0], 'spaceId'> & {
    spaceId?: string
  }
): Promise<DelegatedShape> {
  return (await mintReplicaPullDelegation({
    spaceId: ACCOUNT_SPACE_ID,
    ...options
  })) as DelegatedShape
}

async function mintMaintenance(
  options: Omit<
    Parameters<typeof mintReplicasMaintenanceGrant>[0],
    'baseServerUrl' | 'spaceId'
  >
): Promise<DelegatedShape> {
  return (await mintReplicasMaintenanceGrant({
    baseServerUrl: REPLICA_URL,
    spaceId: REPLICA_SPACE_ID,
    ...options
  })) as DelegatedShape
}

describe('mintReplicaPullDelegation', () => {
  it(
    'mints the permanent wire shape under the ladder VM: canonical Space ' +
      'URL, server DID controller, GET only, Space-rooted, 365 days',
    async () => {
      const { zcapClient, ladderKey } = await ladderSigner()
      const now = Date.now()
      const delegation = await mintPull({
        zcapClient,
        baseServerUrl: WAS_URL,
        serverDid: REPLICA_SERVER_DID,
        now
      })

      expect(delegation.invocationTarget).toBe(
        'https://storage.example/was/space/account-space-1/'
      )
      expect(delegation.controller).toBe(REPLICA_SERVER_DID)
      expect(REPLICA_PULL_ACTIONS).toEqual(['GET'])
      expect(delegation.allowedAction).toEqual(REPLICA_PULL_ACTIONS)

      const spaceUrl = spaceUrlById({
        baseServerUrl: WAS_URL,
        spaceId: ACCOUNT_SPACE_ID
      })
      expect(delegation.parentCapability).toBe(rootCapabilityId(spaceUrl))
      expect(delegation.proof.capabilityChain).toEqual([
        rootCapabilityId(spaceUrl)
      ])

      expect(REPLICA_PULL_TTL_MS).toBe(STANDING_ZCAP_TTL_MS)
      expect(Date.parse(delegation.expires)).toBe(
        toSeconds(now + REPLICA_PULL_TTL_MS)
      )

      // Signed under the ladder VM's document id, the key the source
      // server's sixth predicate attributes to the pointed annex.
      expect(delegation.proof.verificationMethod).toBe(
        `${ACCOUNT_DID}#${ladderKey}`
      )
    }
  )

  it('signs the same shape under an enrolled client promoted signer', async () => {
    const { keyAgent } = await agentsFromSeed({ seed: fixedSeed(32) })
    const zcapClient = webvhZcapClient({ keyAgent, did: ACCOUNT_DID })
    const delegation = await mintPull({
      zcapClient,
      baseServerUrl: WAS_URL,
      serverDid: REPLICA_SERVER_DID
    })
    expect(delegation.proof.verificationMethod).toBe(
      `${ACCOUNT_DID}#${clientSigningKeyMultibase({ keyAgent })}`
    )
  })

  it('aims the same shape at the auxiliary annex Space', async () => {
    const { zcapClient } = await ladderSigner()
    const delegation = await mintPull({
      zcapClient,
      baseServerUrl: WAS_URL,
      spaceId: AUX_SPACE_ID,
      serverDid: REPLICA_SERVER_DID
    })
    const auxUrl = spaceUrlById({
      baseServerUrl: WAS_URL,
      spaceId: AUX_SPACE_ID
    })
    expect(delegation.invocationTarget).toBe(
      'https://storage.example/was/space/aux-space-1/'
    )
    expect(delegation.parentCapability).toBe(rootCapabilityId(auxUrl))
  })

  it('refuses a grantee that is not a replica server DID before signing', async () => {
    const { zcapClient } = await ladderSigner()
    for (const serverDid of [
      'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      ACCOUNT_DID,
      'did:webvh:QmX:replica.example:space:other:id'
    ]) {
      await expect(
        mintPull({ zcapClient, baseServerUrl: WAS_URL, serverDid })
      ).rejects.toThrow(/replica server DID/)
    }
  })
})

describe('mintReplicasMaintenanceGrant', () => {
  it(
    'mints the ladder VM to its own bare did:key: replicas route target on ' +
      'the replica server, four verbs, replica-Space-rooted, ten minutes',
    async () => {
      const { zcapClient, controller, ladderKey } = await ladderSigner()
      const now = Date.now()
      const grant = await mintMaintenance({ zcapClient, controller, now })

      // The bare replicas container URL, no trailing slash, on the replica
      // server's sub-path deployment.
      expect(grant.invocationTarget).toBe(
        'https://replica.example/pws/space/replica-space-1/replicas'
      )
      expect(REPLICAS_MAINTENANCE_ACTIONS).toEqual([
        'GET',
        'POST',
        'PUT',
        'DELETE'
      ])
      expect(grant.allowedAction).toEqual(REPLICAS_MAINTENANCE_ACTIONS)

      // Delegatee and delegator are one key under two ids: the bare did:key
      // the wallet invokes as, and the account-document method that signs.
      expect(grant.controller).toBe(`did:key:${ladderKey}`)
      expect(grant.proof.verificationMethod).toBe(`${ACCOUNT_DID}#${ladderKey}`)

      const replicaSpaceUrl = spaceUrlById({
        baseServerUrl: REPLICA_URL,
        spaceId: REPLICA_SPACE_ID
      })
      expect(grant.parentCapability).toBe(rootCapabilityId(replicaSpaceUrl))
      expect(grant.proof.capabilityChain).toEqual([
        rootCapabilityId(replicaSpaceUrl)
      ])

      expect(REPLICAS_MAINTENANCE_TTL_MS).toBe(10 * MINUTE_MS)
      expect(Date.parse(grant.expires)).toBe(
        toSeconds(now + REPLICAS_MAINTENANCE_TTL_MS)
      )
    }
  )

  it('takes a shorter caller lifetime', async () => {
    const { zcapClient, controller } = await ladderSigner()
    const now = Date.now()
    const grant = await mintMaintenance({
      zcapClient,
      controller,
      ttlMs: 2 * MINUTE_MS,
      now
    })
    expect(Date.parse(grant.expires)).toBe(toSeconds(now + 2 * MINUTE_MS))
  })

  it('refuses a lifetime past the ten-minute bound or not positive', async () => {
    const { zcapClient, controller } = await ladderSigner()
    for (const ttlMs of [REPLICAS_MAINTENANCE_TTL_MS + 1, 0, -MINUTE_MS, NaN]) {
      await expect(
        mintMaintenance({ zcapClient, controller, ttlMs })
      ).rejects.toThrow(/ttlMs/)
    }
  })

  it('refuses a controller that is not a bare did:key before signing', async () => {
    const { zcapClient, ladderKey } = await ladderSigner()
    for (const controller of [
      ACCOUNT_DID,
      `${ACCOUNT_DID}#${ladderKey}`,
      `did:key:${ladderKey}#${ladderKey}`,
      REPLICA_SERVER_DID,
      '',
      'did:key:',
      `did:key:${ladderKey}/path`,
      `did:key:${ladderKey}?query=1`
    ]) {
      await expect(mintMaintenance({ zcapClient, controller })).rejects.toThrow(
        /bare did:key/
      )
    }
  })
})
