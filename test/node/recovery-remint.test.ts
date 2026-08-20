/**
 * Unit tests for the recovery-delegation module (`recoveryDelegation.ts`):
 * the shared PUT-on-`did.jsonl` delegation builder (target URL, action set,
 * TTL), the delegation-proof key-id reader, and the revocation cascade's
 * re-mint core -- the rot check against the document, the skip policy for
 * pre-re-mint entries and binding-less records, and the full re-mint path
 * (shell and binding carried forward verbatim, a fresh bridge delegation
 * inside, the acting client's account key as the mixed-signer proof, the
 * registry entry handed back with the fresh `delegationKeyId`) -- driven over
 * a stubbed fetch, with the standing and re-wrapped records real
 * `wrapUnlockRecord` envelopes.
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
  unwrapUnlockRecord,
  wrapUnlockRecord
} from '../../src/unlock/unlockRecord.js'
import {
  recordSignerFromAgent,
  verifyRecordProof
} from '../../src/keyring/record.js'
import { deriveUnlockIdentity } from '../../src/keyring/kdf.js'
import { agentsFromSeed } from '../../src/identity/agents.js'
import type { AccountPointer } from '../../src/keyring/record.js'
import {
  DELEGATED_CLIENTS_DELEGATION_ACTIONS,
  DELEGATED_CLIENTS_DELEGATION_TTL_MS,
  delegatedClientsDelegationSpaceId,
  delegatedClientsServiceEntry,
  mintDelegatedClientsDelegation
} from '../../src/webvh/companion.js'

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

describe('remintRecoveryDelegations', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  /**
   * A code's identities plus a real issuance-signed standing record, and an
   * acting (enrolled) client whose account key signs the re-mint.
   */
  async function remintFixture({
    delegatedClients
  }: { delegatedClients?: IZcap } = {}) {
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
    const standingRecord = await wrapUnlockRecord({
      controller: CONTROLLER,
      pointer: POINTER,
      delegation: standingDelegation,
      ...(delegatedClients ? { delegatedClients } : {}),
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
    const { contents, proofState } = await unwrapUnlockRecord({
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

  const COMPANION_SPACE_ID = 'companion-space-1'
  const COMPANION_DID =
    `did:webvh:QmScid:was.example:space:${COMPANION_SPACE_ID}:` +
    'gen-Ux3v0kQf9aPmB2hZ'
  const OLD_SIBLING = {
    id: 'urn:zcap:delegated:companion-old',
    invocationTarget: `https://was.example/space/${COMPANION_SPACE_ID}/`,
    allowedAction: ['GET', 'PUT'],
    proof: { verificationMethod: 'did:key:zRevoked#zRevoked' }
  } as unknown as IZcap

  it('reseals BOTH members and rewrites the registry once when the sibling rots', async () => {
    // The atomic-pass regression: a re-mint handling only the bridge is
    // incomplete. The bridge's key still stands and its expiry is far; only
    // the sibling's recorded key has left the document -- and the pass still
    // reseals both, in one record PUT and one registry-entry rewrite.
    const { client, unlock, acting, actingSigner, entry, standingRecord } =
      await remintFixture({ delegatedClients: OLD_SIBLING })
    const { puts } = stubUnlockSpaceFetch({ standingRecord })
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const actingVm = `${acting.keyAgent.id}#${acting.keyAgent.id.split(':')[2]}`
    const { zcapClient, calls } = fakeDelegatingClient({
      verificationMethod: actingVm
    })
    const recorded: RecoveryDelegationEntry[] = []
    const doc = {
      // The bridge's signing key still stands; the sibling's does not.
      verificationMethod: [{ id: entry.delegationKeyId! }, { id: actingVm }],
      service: [
        delegatedClientsServiceEntry({
          accountDid: POINTER.did!,
          companionDid: COMPANION_DID
        })
      ]
    }
    const result = await remintRecoveryDelegations({
      doc,
      entries: [
        {
          ...entry,
          delegatedClientsKeyId: 'did:key:zGone#zGone',
          delegatedClientsExpires: new Date(
            Date.now() + DELEGATED_CLIENTS_DELEGATION_TTL_MS
          ).toISOString()
        }
      ],
      pointer: POINTER,
      storageServerUrl: STORAGE_URL,
      zcapClient,
      recordSigner: actingSigner,
      managementZcapClient: () => acting.zcapClient,
      recordEntry: async ({ entry: updated }) => {
        recorded.push(updated)
      }
    })
    expect(result).toEqual({ reminted: 1, skipped: 0 })

    // Two fresh delegations: the bridge, then the companion-Space sibling.
    expect(calls).toHaveLength(2)
    expect(calls[0]!.invocationTarget).toBe(
      'https://was.example/space/space-1/id/did.jsonl'
    )
    expect(calls[1]!.invocationTarget).toBe(
      `https://was.example/space/${COMPANION_SPACE_ID}/`
    )
    expect(calls[1]!.controller).toBe(client.clientDid)
    expect(calls[1]!.allowedActions).toEqual(
      DELEGATED_CLIENTS_DELEGATION_ACTIONS
    )

    // One record PUT, both members resealed, binding verbatim.
    expect(puts).toHaveLength(1)
    const rewrapped = puts[0]!.body as Record<string, unknown>
    expect(rewrapped.binding).toBe(
      (standingRecord as unknown as { binding: string }).binding
    )
    const { contents } = await unwrapUnlockRecord({
      record: rewrapped,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: unlock.recordSigner.keyMultibase,
      bindingMacKey: client.bindingMacKey
    })
    expect((contents.delegation as { id?: string }).id).toBe(
      'urn:zcap:delegated:1'
    )
    expect((contents.delegatedClients as { id?: string }).id).toBe(
      'urn:zcap:delegated:2'
    )

    // One registry rewrite carrying BOTH fresh scalar pairs.
    expect(recorded).toHaveLength(1)
    expect(recorded[0]!.delegationKeyId).toBe(actingVm)
    expect(recorded[0]!.delegatedClientsKeyId).toBe(actingVm)
    expect(recorded[0]!.delegatedClientsExpires).toBeDefined()
    expect(Date.parse(recorded[0]!.delegatedClientsExpires!)).toBeGreaterThan(
      Date.now()
    )
  })

  it('carries the sibling verbatim when the document points at no generation', async () => {
    // A standing record whose sibling cannot be rebuilt (no delegated-clients
    // service entry to read the companion Space id from): the bridge still
    // re-mints, the old sealed sibling travels verbatim, and the entry's
    // sibling pair stays untouched for the health check to keep flagging.
    const { client, unlock, acting, actingSigner, entry, standingRecord } =
      await remintFixture({ delegatedClients: OLD_SIBLING })
    const { puts } = stubUnlockSpaceFetch({ standingRecord })
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const actingVm = `${acting.keyAgent.id}#${acting.keyAgent.id.split(':')[2]}`
    const { zcapClient, calls } = fakeDelegatingClient({
      verificationMethod: actingVm
    })
    const recorded: RecoveryDelegationEntry[] = []
    const result = await remintRecoveryDelegations({
      doc: { verificationMethod: [{ id: actingVm }] },
      entries: [
        {
          ...entry,
          delegatedClientsKeyId: 'did:key:zGone#zGone',
          delegatedClientsExpires: new Date(Date.now() + 1000).toISOString()
        }
      ],
      pointer: POINTER,
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
    const rewrapped = puts[0]!.body as Record<string, unknown>
    const { contents } = await unwrapUnlockRecord({
      record: rewrapped,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: unlock.recordSigner.keyMultibase,
      bindingMacKey: client.bindingMacKey
    })
    expect((contents.delegatedClients as { id?: string }).id).toBe(
      'urn:zcap:delegated:companion-old'
    )
    expect(recorded[0]!.delegatedClientsKeyId).toBe('did:key:zGone#zGone')
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
      companionSpaceId: 'companion-space-1',
      controller: 'did:key:zCredential'
    })
    expect(calls).toHaveLength(1)
    // The trailing slash is load-bearing: generation-id-bounded attenuation
    // over the flat gen- collection names.
    expect(calls[0]!.invocationTarget).toBe(
      'https://was.example/space/companion-space-1/'
    )
    expect(calls[0]!.capability).toBe(
      `urn:zcap:root:${encodeURIComponent(
        'https://was.example/space/companion-space-1'
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
      'companion-space-1'
    )
  })

  it('keeps the base path of a sub-path deployment in the target', async () => {
    const { zcapClient, calls } = fakeDelegatingClient({
      verificationMethod: 'did:key:zIssuer#zIssuer'
    })
    const delegation = await mintDelegatedClientsDelegation({
      zcapClient,
      wasServerUrl: 'https://was.example/was',
      companionSpaceId: 'companion-space-1',
      controller: 'did:key:zCredential'
    })
    expect(calls[0]!.invocationTarget).toBe(
      'https://was.example/was/space/companion-space-1/'
    )
    expect(delegatedClientsDelegationSpaceId({ delegation })).toBe(
      'companion-space-1'
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
