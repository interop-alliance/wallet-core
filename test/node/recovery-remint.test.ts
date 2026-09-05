/**
 * Unit tests for the recovery-delegation module (`recoveryDelegation.ts`):
 * the shared PUT-on-`did.jsonl` delegation builder (target URL, action set,
 * TTL), the delegation-proof key-id reader, and the house expiry predicate --
 * plus the annex Space sibling delegation minted beside the bridge.
 */
import { describe, expect, it } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import {
  delegateLogWrite,
  delegationProofKeyId,
  RECOVERY_DELEGATION_TTL_MS,
  ZCAP_RENEWAL_WINDOW_MS,
  zcapExpiring
} from '../../src/recovery/recoveryDelegation.js'
import type { AccountPointer } from '../../src/keyring/record.js'
import {
  DELEGATED_CLIENTS_DELEGATION_TTL_MS,
  delegatedClientsDelegationSpaceId,
  mintDelegatedClientsDelegation
} from '../../src/clientAnnex/log.js'

const POINTER: AccountPointer = {
  did: 'did:webvh:QmScid:was.example:space:space-1:id',
  spaceId: 'space-1',
  host: 'https://was.example'
}

/**
 * A fake delegating ZcapClient: returns a shaped delegation carrying the
 * given verification method in its proof and records the delegate() call.
 */
function fakeDelegatingClient({
  verificationMethod
}: {
  verificationMethod: string
}): { zcapClient: ZcapClient; calls: Array<Record<string, unknown>> } {
  const calls: Array<Record<string, unknown>> = []
  const zcapClient = {
    async delegate(options: Record<string, unknown>) {
      calls.push(options)
      return {
        id: `urn:zcap:delegated:${calls.length}`,
        invocationTarget: options.invocationTarget,
        controller: options.controller,
        allowedAction: options.allowedActions,
        expires: (options.expires as Date).toISOString(),
        proof: { verificationMethod }
      } as unknown as IZcap
    }
  } as unknown as ZcapClient
  return { zcapClient, calls }
}

describe('delegateLogWrite', () => {
  it('delegates PUT on the one did.jsonl resource with the shared TTL', async () => {
    const { zcapClient, calls } = fakeDelegatingClient({
      verificationMethod: 'did:key:zIssuer#zIssuer'
    })
    const before = Date.now()
    const delegation = await delegateLogWrite({
      zcapClient,
      pointer: POINTER,
      recoveryClientDid: 'did:key:zRecovery'
    })
    expect(calls).toHaveLength(1)
    expect(calls[0]!.invocationTarget).toBe(
      'https://was.example/space/space-1/id/did.jsonl'
    )
    expect(calls[0]!.controller).toBe('did:key:zRecovery')
    expect(calls[0]!.allowedActions).toEqual(['PUT'])
    const expires = (calls[0]!.expires as Date).getTime()
    expect(expires).toBeGreaterThanOrEqual(before + RECOVERY_DELEGATION_TTL_MS)
    expect(expires).toBeLessThanOrEqual(Date.now() + RECOVERY_DELEGATION_TTL_MS)
    expect(delegationProofKeyId(delegation)).toBe('did:key:zIssuer#zIssuer')
  })

  it('keeps the base path of a sub-path deployment in the target', async () => {
    const { zcapClient, calls } = fakeDelegatingClient({
      verificationMethod: 'did:key:zIssuer#zIssuer'
    })
    await delegateLogWrite({
      zcapClient,
      pointer: { ...POINTER, host: 'https://was.example/was' },
      recoveryClientDid: 'did:key:zRecovery'
    })
    expect(calls[0]!.invocationTarget).toBe(
      'https://was.example/was/space/space-1/id/did.jsonl'
    )
  })

  it('does not duplicate a trailing slash on the base path', async () => {
    const { zcapClient, calls } = fakeDelegatingClient({
      verificationMethod: 'did:key:zIssuer#zIssuer'
    })
    await delegateLogWrite({
      zcapClient,
      pointer: { ...POINTER, host: 'https://was.example/was/' },
      recoveryClientDid: 'did:key:zRecovery'
    })
    expect(calls[0]!.invocationTarget).toBe(
      'https://was.example/was/space/space-1/id/did.jsonl'
    )
  })

  it('leaves a bare-origin pointer host unchanged', async () => {
    const { zcapClient, calls } = fakeDelegatingClient({
      verificationMethod: 'did:key:zIssuer#zIssuer'
    })
    await delegateLogWrite({
      zcapClient,
      pointer: { ...POINTER, host: 'https://was.example/' },
      recoveryClientDid: 'did:key:zRecovery'
    })
    expect(calls[0]!.invocationTarget).toBe(
      'https://was.example/space/space-1/id/did.jsonl'
    )
  })
})

describe('delegationProofKeyId', () => {
  it('reads a single proof, the first of a proof array, and absent', () => {
    expect(
      delegationProofKeyId({
        proof: { verificationMethod: 'did:key:zA#zA' }
      } as unknown as IZcap)
    ).toBe('did:key:zA#zA')
    expect(
      delegationProofKeyId({
        proof: [
          { verificationMethod: 'did:key:zFirst#zFirst' },
          { verificationMethod: 'did:key:zSecond#zSecond' }
        ]
      } as unknown as IZcap)
    ).toBe('did:key:zFirst#zFirst')
    expect(delegationProofKeyId({} as unknown as IZcap)).toBeUndefined()
  })
})

describe('zcapExpiring', () => {
  it('treats absent, unparseable, past, and in-window expiries as stale', () => {
    const now = Date.parse('2026-08-15T00:00:00Z')
    expect(zcapExpiring({ now })).toBe(true)
    expect(zcapExpiring({ expires: 'not-a-date', now })).toBe(true)
    expect(
      zcapExpiring({
        expires: new Date(now - 1000).toISOString(),
        now
      })
    ).toBe(true)
    expect(
      zcapExpiring({
        expires: new Date(now + ZCAP_RENEWAL_WINDOW_MS - 1000).toISOString(),
        now
      })
    ).toBe(true)
    expect(
      zcapExpiring({
        expires: new Date(now + ZCAP_RENEWAL_WINDOW_MS + 1000).toISOString(),
        now
      })
    ).toBe(false)
  })
})

describe('mintDelegatedClientsDelegation', () => {
  it('delegates GET+PUT on the auxiliary Space items subtree, rooted in its Space', async () => {
    const { zcapClient, calls } = fakeDelegatingClient({
      verificationMethod: 'did:key:zIssuer#zIssuer'
    })
    const before = Date.now()
    const delegation = await mintDelegatedClientsDelegation({
      zcapClient,
      wasServerUrl: 'https://was.example',
      clientAnnexSpaceId: 'clientAnnex-space-1',
      controller: 'did:key:zCredential'
    })
    expect(calls).toHaveLength(1)
    // The trailing slash is load-bearing: generation-id-bounded attenuation
    // over the flat gen- collection names.
    expect(calls[0]!.invocationTarget).toBe(
      'https://was.example/space/clientAnnex-space-1/'
    )
    expect(calls[0]!.capability).toBe(
      `urn:zcap:root:${encodeURIComponent(
        'https://was.example/space/clientAnnex-space-1'
      )}`
    )
    expect(calls[0]!.controller).toBe('did:key:zCredential')
    expect(calls[0]!.allowedActions).toEqual(['GET', 'PUT'])
    const expires = (calls[0]!.expires as Date).getTime()
    expect(expires).toBeGreaterThanOrEqual(
      before + DELEGATED_CLIENTS_DELEGATION_TTL_MS
    )
    expect(expires).toBeLessThanOrEqual(
      Date.now() + DELEGATED_CLIENTS_DELEGATION_TTL_MS
    )
    // The one reader of the embedded Space id round-trips it.
    expect(delegatedClientsDelegationSpaceId({ delegation })).toBe(
      'clientAnnex-space-1'
    )
  })

  it('keeps the base path of a sub-path deployment in the target', async () => {
    const { zcapClient, calls } = fakeDelegatingClient({
      verificationMethod: 'did:key:zIssuer#zIssuer'
    })
    const delegation = await mintDelegatedClientsDelegation({
      zcapClient,
      wasServerUrl: 'https://was.example/was',
      clientAnnexSpaceId: 'clientAnnex-space-1',
      controller: 'did:key:zCredential'
    })
    expect(calls[0]!.invocationTarget).toBe(
      'https://was.example/was/space/clientAnnex-space-1/'
    )
    expect(delegatedClientsDelegationSpaceId({ delegation })).toBe(
      'clientAnnex-space-1'
    )
  })

  it('reads no Space id off a non-subtree target', () => {
    expect(
      delegatedClientsDelegationSpaceId({
        delegation: {
          invocationTarget: 'https://was.example/space/space-1/id/did.jsonl'
        } as unknown as IZcap
      })
    ).toBeUndefined()
    expect(
      delegatedClientsDelegationSpaceId({
        delegation: {
          invocationTarget: 'not a url'
        } as unknown as IZcap
      })
    ).toBeUndefined()
  })
})
