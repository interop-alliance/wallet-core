/**
 * Unit tests for the recovery-delegation module (`recoveryDelegation.ts`):
 * the shared PUT-on-`did.jsonl` delegation builder (target URL, action set,
 * TTL), the delegation-proof key-id reader, and the revocation cascade's
 * re-mint core -- the rot check against the document, the skip policy for
 * pre-re-mint entries and binding-less records, and the full re-mint path
 * (binding carried forward verbatim, fresh delegation inside, the acting
 * client's account key as the mixed-signer proof, the registry entry handed
 * back with the fresh `delegationKeyId`) -- driven over a stubbed fetch, with
 * the standing and re-wrapped records real `wrapRecoveryRecord` envelopes.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import {
  delegateLogWrite,
  delegationProofKeyId,
  RECOVERY_DELEGATION_TTL_MS,
  remintRecoveryDelegations,
  ZCAP_RENEWAL_WINDOW_MS,
  zcapExpiring
} from '../../src/recovery/recoveryDelegation.js'
import type { RecoveryDelegationEntry } from '../../src/recovery/recoveryDelegation.js'
import {
  generateRecoveryCode,
  RECOVERY_KDF,
  recoveryClientFromCode
} from '../../src/recovery/recoveryCode.js'
import {
  unwrapRecoveryRecord,
  wrapRecoveryRecord
} from '../../src/recovery/recoveryRecord.js'
import {
  recordSignerFromAgent,
  verifyRecordProof
} from '../../src/keyring/record.js'
import { deriveUnlockIdentity } from '../../src/keyring/kdf.js'
import { agentsFromSeed } from '../../src/identity/agents.js'
import type { AccountPointer } from '../../src/keyring/record.js'

const POINTER: AccountPointer = {
  did: 'did:webvh:QmScid:was.example:space:space-1:id',
  spaceId: 'space-1',
  host: 'https://was.example'
}
const CONTROLLER = 'did:key:zAccountController'
const STORAGE_URL = 'https://was.example'

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

describe('remintRecoveryDelegations', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  /**
   * A code's identities plus a real issuance-signed standing record, and an
   * acting (enrolled) client whose account key signs the re-mint.
   */
  async function remintFixture() {
    const code = generateRecoveryCode()
    const client = await recoveryClientFromCode({ code })
    const unlock = await deriveUnlockIdentity({
      secret: client.codeBytes,
      kdf: RECOVERY_KDF
    })
    const acting = await agentsFromSeed({
      seed: new Uint8Array(32).fill(7)
    })
    const actingSigner = recordSignerFromAgent({ keyAgent: acting.keyAgent })
    const standingDelegation = {
      id: 'urn:zcap:delegated:standing',
      proof: { verificationMethod: 'did:key:zRevoked#zRevoked' }
    } as unknown as IZcap
    const standingRecord = await wrapRecoveryRecord({
      controller: CONTROLLER,
      pointer: POINTER,
      delegation: standingDelegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: client.bindingMacKey
    })
    const unlockKakPublic = unlock.keyAgreementKey as unknown as {
      id: string
      publicKeyMultibase: string
    }
    // A real management delegation, as `delegateUnlockManagement` mints it at
    // bind time -- the invocation signing refuses a shapeless stand-in.
    const manageCapability = await unlock.zcapClient.delegate({
      invocationTarget: `${STORAGE_URL}/space/${unlock.spaceId}`,
      controller: acting.keyAgent.id,
      allowedActions: ['GET', 'PUT', 'DELETE']
    })
    const entry: RecoveryDelegationEntry = {
      label: 'Code one',
      unlockSpaceId: unlock.spaceId,
      manageCapability,
      delegationKeyId: 'did:key:zRevoked#zRevoked',
      delegationExpires: new Date(
        Date.now() + RECOVERY_DELEGATION_TTL_MS
      ).toISOString(),
      recoveryClientDid: client.clientDid,
      unlockKeyAgreementKeyId: unlockKakPublic.id,
      unlockKeyAgreementKeyMultibase: unlockKakPublic.publicKeyMultibase
    }
    return { code, client, unlock, acting, actingSigner, standingRecord, entry }
  }

  /**
   * Routes the two unlock-Space requests the re-mint makes: GET serves the
   * standing record, PUT captures the re-wrapped one.
   */
  function stubUnlockSpaceFetch({
    standingRecord
  }: {
    standingRecord: unknown
  }): { puts: Array<{ url: string; body: unknown }> } {
    const puts: Array<{ url: string; body: unknown }> = []
    vi.stubGlobal(
      'fetch',
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const request =
          input instanceof Request ? input : new Request(input, init)
        if (request.method === 'GET') {
          return new Response(JSON.stringify(standingRecord), {
            status: 200,
            headers: { 'content-type': 'application/json' }
          })
        }
        if (request.method === 'PUT') {
          puts.push({ url: request.url, body: await request.json() })
          return new Response(null, { status: 204 })
        }
        return new Response(null, { status: 405 })
      }
    )
    return { puts }
  }

  it('leaves a standing delegation untouched', async () => {
    const { actingSigner, acting, entry, standingRecord } =
      await remintFixture()
    const { puts } = stubUnlockSpaceFetch({ standingRecord })
    const recorded: RecoveryDelegationEntry[] = []
    const result = await remintRecoveryDelegations({
      // The document still publishes the delegation's signing key.
      doc: {
        verificationMethod: [{ id: 'did:key:zRevoked#zRevoked' }]
      },
      entries: [entry],
      pointer: POINTER,
      controller: CONTROLLER,
      storageServerUrl: STORAGE_URL,
      zcapClient: fakeDelegatingClient({
        verificationMethod: 'unused'
      }).zcapClient,
      recordSigner: actingSigner,
      managementZcapClient: () => acting.zcapClient,
      recordEntry: async ({ entry: updated }) => {
        recorded.push(updated)
      }
    })
    expect(result).toEqual({ reminted: 0, skipped: 0 })
    expect(puts).toHaveLength(0)
    expect(recorded).toHaveLength(0)
  })

  it('re-mints a standing delegation inside the renewal window', async () => {
    const { acting, actingSigner, entry, standingRecord } =
      await remintFixture()
    const { puts } = stubUnlockSpaceFetch({ standingRecord })
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const actingVm = `${acting.keyAgent.id}#${acting.keyAgent.id.split(':')[2]}`
    const { zcapClient, calls } = fakeDelegatingClient({
      verificationMethod: actingVm
    })
    const recorded: RecoveryDelegationEntry[] = []
    const before = Date.now()
    const result = await remintRecoveryDelegations({
      // The signing key still stands; only the expiry is near.
      doc: {
        verificationMethod: [{ id: 'did:key:zRevoked#zRevoked' }]
      },
      entries: [
        {
          ...entry,
          delegationExpires: new Date(Date.now() + 1000).toISOString()
        }
      ],
      pointer: POINTER,
      controller: CONTROLLER,
      storageServerUrl: STORAGE_URL,
      zcapClient,
      recordSigner: actingSigner,
      managementZcapClient: () => acting.zcapClient,
      recordEntry: async ({ entry: updated }) => {
        recorded.push(updated)
      }
    })
    expect(result).toEqual({ reminted: 1, skipped: 0 })
    expect(calls).toHaveLength(1)
    expect(puts).toHaveLength(1)
    // The registry entry came back stamped with the fresh delegation's
    // full-TTL expiry.
    expect(recorded).toHaveLength(1)
    const stamped = Date.parse(recorded[0]!.delegationExpires!)
    expect(stamped).toBeGreaterThanOrEqual(before + RECOVERY_DELEGATION_TTL_MS)
    expect(stamped).toBeLessThanOrEqual(Date.now() + RECOVERY_DELEGATION_TTL_MS)
  })

  it('skips a rotted entry that predates the re-mint fields', async () => {
    const { actingSigner, acting, entry, standingRecord } =
      await remintFixture()
    const { puts } = stubUnlockSpaceFetch({ standingRecord })
    const { recoveryClientDid, ...preRemint } = entry
    void recoveryClientDid
    const result = await remintRecoveryDelegations({
      doc: { verificationMethod: [] },
      entries: [preRemint],
      pointer: POINTER,
      controller: CONTROLLER,
      storageServerUrl: STORAGE_URL,
      zcapClient: fakeDelegatingClient({
        verificationMethod: 'unused'
      }).zcapClient,
      recordSigner: actingSigner,
      managementZcapClient: () => acting.zcapClient,
      recordEntry: async () => {}
    })
    expect(result).toEqual({ reminted: 0, skipped: 1 })
    expect(puts).toHaveLength(0)
  })

  it('skips a rotted entry whose standing record carries no binding', async () => {
    const { actingSigner, acting, entry, standingRecord } =
      await remintFixture()
    const { binding, ...bindingless } = standingRecord as unknown as Record<
      string,
      unknown
    >
    void binding
    const { puts } = stubUnlockSpaceFetch({ standingRecord: bindingless })
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const result = await remintRecoveryDelegations({
      doc: { verificationMethod: [] },
      entries: [entry],
      pointer: POINTER,
      controller: CONTROLLER,
      storageServerUrl: STORAGE_URL,
      zcapClient: fakeDelegatingClient({
        verificationMethod: 'unused'
      }).zcapClient,
      recordSigner: actingSigner,
      managementZcapClient: () => acting.zcapClient,
      recordEntry: async () => {}
    })
    expect(result).toEqual({ reminted: 0, skipped: 1 })
    expect(puts).toHaveLength(0)
  })

  it('re-mints a rotted delegation: binding verbatim, fresh delegation, account-key proof, registry update', async () => {
    const { client, unlock, acting, actingSigner, entry, standingRecord } =
      await remintFixture()
    const { puts } = stubUnlockSpaceFetch({ standingRecord })
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const actingVm = `${acting.keyAgent.id}#${acting.keyAgent.id.split(':')[2]}`
    const { zcapClient, calls } = fakeDelegatingClient({
      verificationMethod: actingVm
    })
    const recorded: RecoveryDelegationEntry[] = []
    const result = await remintRecoveryDelegations({
      // The revoked signer's key has left the document; the acting client's
      // key is what the re-wrapped record's proof must verify against.
      doc: {
        verificationMethod: [{ id: actingVm }]
      },
      entries: [entry],
      pointer: POINTER,
      controller: CONTROLLER,
      storageServerUrl: STORAGE_URL,
      zcapClient,
      recordSigner: actingSigner,
      managementZcapClient: () => acting.zcapClient,
      recordEntry: async ({ entry: updated }) => {
        recorded.push(updated)
      }
    })
    expect(result).toEqual({ reminted: 1, skipped: 0 })

    // The fresh delegation names the code-derived signing DID.
    expect(calls).toHaveLength(1)
    expect(calls[0]!.controller).toBe(client.clientDid)

    // The re-wrapped record went to the code's unlock Space...
    expect(puts).toHaveLength(1)
    expect(puts[0]!.url).toContain(entry.unlockSpaceId)
    const rewrapped = puts[0]!.body as Record<string, unknown>

    // ...with the code-authenticated binding carried forward verbatim.
    expect(rewrapped.binding).toBe(
      (standingRecord as unknown as { binding: string }).binding
    )

    // The typed code still opens it: same unlock KAK recipient, the fresh
    // delegation inside, and the binding verifying under the code's MAC key.
    const { contents, proofState } = await unwrapRecoveryRecord({
      record: rewrapped,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: unlock.recordSigner.keyMultibase,
      bindingMacKey: client.bindingMacKey
    })
    expect(contents.pointer).toEqual(POINTER)
    expect(contents.controller).toBe(CONTROLLER)
    expect((contents.delegation as { id?: string }).id).toBe(
      'urn:zcap:delegated:1'
    )

    // Mixed signer: the acting client's account key signed the re-mint, so
    // the proof comes back pending and settles against that key.
    expect(proofState).not.toBe('verified')
    await verifyRecordProof({
      record: rewrapped,
      allowedKeyMultibases: [actingSigner.keyMultibase],
      label: 'recovery'
    })

    // The registry entry came back with the fresh delegation's key id, other
    // members untouched.
    expect(recorded).toHaveLength(1)
    expect(recorded[0]!.delegationKeyId).toBe(actingVm)
    expect(recorded[0]!.label).toBe(entry.label)
    expect(recorded[0]!.recoveryClientDid).toBe(entry.recoveryClientDid)
  })
})
