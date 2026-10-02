/**
 * Unit tests for the account log's DID readers (`src/webvh/documentDids.ts`):
 * the did:key a signing-key multibase names, and the one walk over every
 * entry that collects each enrolled client's and each ladder VM's did:key,
 * a since-revoked client's included, skipping a method whose id carries no
 * fragment and an entry carrying no document state.
 */
import { describe, expect, it } from 'vitest'
import type { DIDLog } from '@interop/did-method-webvh'
import {
  accountLogDids,
  walletClientDid
} from '../../src/webvh/documentDids.js'
import { signingKeyMultibaseOfDid } from '../../src/connections/didKey.js'

const ACCOUNT_DID = 'did:webvh:QmScid:storage.example:space:s:id'

/**
 * One log entry: enrolled clients under `capabilityInvocation` (and
 * `capabilityDelegation`), ladder VMs under `capabilityDelegation` alone.
 *
 * @param options {object}
 * @param [options.clients] {string[]}   enrolled clients' key multibases
 * @param [options.ladders] {string[]}   ladder VMs' key multibases
 * @returns {object}
 */
function logEntry({
  clients = [],
  ladders = []
}: {
  clients?: string[]
  ladders?: string[]
}) {
  const vmId = (multibase: string) => `${ACCOUNT_DID}#${multibase}`
  const clientVms = clients.map(vmId)
  const ladderVms = ladders.map(vmId)
  return {
    state: {
      id: ACCOUNT_DID,
      capabilityInvocation: clientVms,
      capabilityDelegation: [...clientVms, ...ladderVms]
    }
  }
}

describe('walletClientDid', () => {
  it('is the inverse of signingKeyMultibaseOfDid', () => {
    const signingKeyMultibase =
      'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    const did = walletClientDid({ signingKeyMultibase })
    expect(did).toBe(`did:key:${signingKeyMultibase}`)
    expect(signingKeyMultibaseOfDid({ did })).toBe(signingKeyMultibase)
  })
})

describe('accountLogDids', () => {
  it('collects every client and ladder VM any entry listed, a revoked client included', () => {
    const log = [
      logEntry({ ladders: ['z6MkLadder'] }),
      logEntry({
        clients: ['z6MkFirst', 'z6MkRevoked'],
        ladders: ['z6MkLadder']
      }),
      logEntry({ clients: ['z6MkFirst'], ladders: ['z6MkLadder'] })
    ] as unknown as DIDLog
    expect(accountLogDids({ log })).toEqual({
      clientDids: new Set(['did:key:z6MkFirst', 'did:key:z6MkRevoked']),
      ladderDids: new Set(['did:key:z6MkLadder'])
    })
  })

  it('skips a method id with no fragment and an entry with no state', () => {
    const log = [
      { state: null },
      {
        state: {
          id: ACCOUNT_DID,
          capabilityInvocation: [ACCOUNT_DID, `${ACCOUNT_DID}#z6MkOnly`]
        }
      }
    ] as unknown as DIDLog
    expect(accountLogDids({ log })).toEqual({
      clientDids: new Set(['did:key:z6MkOnly']),
      ladderDids: new Set()
    })
  })
})
