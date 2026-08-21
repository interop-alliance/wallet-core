/**
 * Unit tests for the unlock record codec's standing-credential members
 * (`src/unlock/unlockRecord.ts`): the ladder member round trip beside the
 * shell and bridge, the binding covering the ladder seed (a substituted
 * ladder member refuses), the optional `delegatedClients` sibling member
 * (round trip, tolerant absence, the accepted outside-the-MAC bound), and
 * the delegation re-mint carrying shell, ladder,
 * binding, email, and bind timestamp verbatim while replacing the bridge
 * and (when supplied) the sibling. The recovery-shaped (ladder-less) paths
 * are covered by the recovery suites.
 */
import { describe, expect, it } from 'vitest'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'
import { deriveUnlockIdentity, KEYRING_KDF } from '../../src/keyring/kdf.js'
import { unwrapKeyringRecord } from '../../src/keyring/record.js'
import { generateLadderSeed } from '../../src/clientAnnex/ladder.js'
import { standingClientFromUnlockSeed } from '../../src/unlock/standingClient.js'
import {
  remintUnlockRecordDelegations,
  UnlockBindingError,
  unwrapUnlockRecord,
  wrapUnlockRecord
} from '../../src/unlock/unlockRecord.js'

const POINTER = {
  did: 'did:webvh:QmScid:was.example:space:space-1:id',
  spaceId: 'space-1',
  host: 'https://was.example'
}
const DELEGATION = {
  id: 'urn:zcap:delegated:standing',
  invocationTarget: 'https://was.example/space/space-1/id/did.jsonl',
  allowedAction: ['PUT']
} as unknown as IZcap
const DELEGATED_CLIENTS = {
  id: 'urn:zcap:delegated:clientAnnex',
  invocationTarget: 'https://was.example/space/clientAnnex-1/',
  allowedAction: ['GET', 'PUT']
} as unknown as IZcap

/**
 * A passphrase-shaped standing credential: its unlock identity (KAK, record
 * signer, resolver) plus its client-side binding MAC key and a fresh ladder.
 */
async function standingUnlock(secret: string) {
  const unlock = await deriveUnlockIdentity({ secret, kdf: KEYRING_KDF })
  // The unlock seed is not exposed by deriveUnlockIdentity; for the codec
  // tests any deterministic 32 bytes stand in for it.
  const { bindingMacKey } = await standingClientFromUnlockSeed({
    unlockSeed: new TextEncoder().encode(secret.padEnd(32, '.')).slice(0, 32)
  })
  return { ...unlock, bindingMacKey, ladderSeed: generateLadderSeed() }
}

describe('the standing unlock record', () => {
  it('round-trips shell, bridge, ladder, and email', async () => {
    const unlock = await standingUnlock('a standing passphrase secret')
    const record = await wrapUnlockRecord({
      controller: 'did:key:z6MkAccountController',
      email: 'user@example.com',
      pointer: POINTER,
      delegation: DELEGATION,
      ladderSeed: unlock.ladderSeed,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey,
      createdAt: '2026-08-15T12:00:00.000Z'
    })
    const { contents, proofState } = await unwrapUnlockRecord({
      record,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: unlock.recordSigner.keyMultibase,
      bindingMacKey: unlock.bindingMacKey
    })
    expect(proofState).toBe('verified')
    expect(contents.controller).toBe('did:key:z6MkAccountController')
    expect(contents.email).toBe('user@example.com')
    expect(contents.pointer).toEqual(POINTER)
    expect(contents.delegation).toEqual(DELEGATION)
    // Tolerant absence: a record wrapped without the sibling member unwraps
    // with none, no refusal.
    expect(contents.delegatedClients).toBeUndefined()
    expect(Array.from(contents.ladderSeed!)).toEqual(
      Array.from(unlock.ladderSeed)
    )
    expect(contents.createdAt).toBe('2026-08-15T12:00:00.000Z')

    // An unlock record IS a keyring record to the generic codec: an ordinary
    // unwrap recovers the shell and ignores the standing members.
    const generic = await unwrapKeyringRecord({
      record,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: unlock.recordSigner.keyMultibase
    })
    expect(generic.pointer).toEqual(POINTER)
    expect(generic.email).toBe('user@example.com')
    expect(generic.createdAt).toBe('2026-08-15T12:00:00.000Z')
  })

  it('refuses a substituted ladder member (the binding covers the seed)', async () => {
    const unlock = await standingUnlock('a standing passphrase secret')
    const record = await wrapUnlockRecord({
      controller: 'did:key:z6MkAccountController',
      pointer: POINTER,
      delegation: DELEGATION,
      ladderSeed: unlock.ladderSeed,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })
    // The host seals a ladder of its own choosing to the credential's public
    // KAK and splices it in (re-signing is moot: a host-served frame with a
    // pending-signer proof still reaches the binding check). The seed no
    // longer matches the credential-authenticated core, so the record
    // refuses before anything downstream trusts the ladder.
    const hostLadder = await wrapUnlockRecord({
      controller: 'did:key:z6MkAccountController',
      pointer: POINTER,
      delegation: DELEGATION,
      ladderSeed: generateLadderSeed(),
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })
    await expect(
      unwrapUnlockRecord({
        record: { ...record, ladder: hostLadder.ladder },
        keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
        keyResolver: unlock.keyResolver,
        // The splice breaks the frame proof too; drop to the pending-signer
        // path to show the binding alone refuses it.
        expectedKeyMultibase: 'z6MkNotTheUnlockKey',
        bindingMacKey: unlock.bindingMacKey
      })
    ).rejects.toThrow(UnlockBindingError)
  })

  it('re-mints the bridge only: shell, ladder, binding, email survive verbatim', async () => {
    const unlock = await standingUnlock('a standing passphrase secret')
    const acting = await deriveUnlockIdentity({
      secret: 'an enrolled client key',
      kdf: KEYRING_KDF
    })
    const issued = await wrapUnlockRecord({
      controller: 'did:key:z6MkAccountController',
      email: 'user@example.com',
      pointer: POINTER,
      delegation: DELEGATION,
      ladderSeed: unlock.ladderSeed,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey,
      createdAt: '2026-08-15T12:00:00.000Z'
    })
    const freshDelegation = {
      ...DELEGATION,
      id: 'urn:zcap:delegated:fresh'
    } as unknown as IZcap
    const reminted = await remintUnlockRecordDelegations({
      record: issued,
      delegation: freshDelegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: acting.recordSigner
    })
    // Verbatim members; only the bridge and the proof changed.
    expect(reminted.wrapped).toEqual(issued.wrapped)
    expect(reminted.encryption).toEqual(issued.encryption)
    expect(reminted.ladder).toEqual(issued.ladder)
    expect(reminted.binding).toBe(issued.binding)
    expect(reminted.bridge).not.toEqual(issued.bridge)

    const { contents, proofState } = await unwrapUnlockRecord({
      record: reminted,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: unlock.recordSigner.keyMultibase,
      bindingMacKey: unlock.bindingMacKey
    })
    expect(proofState).toEqual({
      pending: {
        verificationMethod: `did:key:${acting.recordSigner.keyMultibase}#${acting.recordSigner.keyMultibase}`,
        keyMultibase: acting.recordSigner.keyMultibase
      }
    })
    expect((contents.delegation as { id?: string }).id).toBe(
      'urn:zcap:delegated:fresh'
    )
    expect(contents.email).toBe('user@example.com')
    expect(contents.createdAt).toBe('2026-08-15T12:00:00.000Z')
    expect(Array.from(contents.ladderSeed!)).toEqual(
      Array.from(unlock.ladderSeed)
    )
  })

  it('refuses a record with no bridge member', async () => {
    const unlock = await standingUnlock('a standing passphrase secret')
    const record = await wrapUnlockRecord({
      controller: 'did:key:z6MkAccountController',
      pointer: POINTER,
      delegation: DELEGATION,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })
    const { bridge, ...stripped } = record
    void bridge
    await expect(
      unwrapUnlockRecord({
        record: stripped,
        keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
        keyResolver: unlock.keyResolver,
        expectedKeyMultibase: unlock.recordSigner.keyMultibase,
        bindingMacKey: unlock.bindingMacKey
      })
    ).rejects.toThrow(/no bridge member/)
  })

  it('round-trips the delegatedClients sibling member', async () => {
    const unlock = await standingUnlock('a standing passphrase secret')
    const record = await wrapUnlockRecord({
      controller: 'did:key:z6MkAccountController',
      pointer: POINTER,
      delegation: DELEGATION,
      delegatedClients: DELEGATED_CLIENTS,
      ladderSeed: unlock.ladderSeed,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })
    expect(record.delegatedClients).toBeDefined()
    const { contents } = await unwrapUnlockRecord({
      record,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: unlock.recordSigner.keyMultibase,
      bindingMacKey: unlock.bindingMacKey
    })
    expect(contents.delegatedClients).toEqual(DELEGATED_CLIENTS)
    expect(contents.delegation).toEqual(DELEGATION)
  })

  it('does not cover delegatedClients with the binding MAC (the accepted bound)', async () => {
    // Decision 0005's stated residue: a hostile host can swap the sealed
    // sibling without tripping the MAC -- the bound is the account
    // document's service entry plus key-verification failure. This test
    // pins that a swapped sibling passes the binding check (via the
    // pending-signer path, since the splice does break the frame proof).
    const unlock = await standingUnlock('a standing passphrase secret')
    const record = await wrapUnlockRecord({
      controller: 'did:key:z6MkAccountController',
      pointer: POINTER,
      delegation: DELEGATION,
      delegatedClients: DELEGATED_CLIENTS,
      ladderSeed: unlock.ladderSeed,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })
    const swapped = {
      ...DELEGATED_CLIENTS,
      invocationTarget: 'https://host.example/space/attacker-space/'
    } as unknown as IZcap
    const hostRecord = await wrapUnlockRecord({
      controller: 'did:key:z6MkAccountController',
      pointer: POINTER,
      delegation: DELEGATION,
      delegatedClients: swapped,
      ladderSeed: unlock.ladderSeed,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })
    const { contents, proofState } = await unwrapUnlockRecord({
      record: { ...record, delegatedClients: hostRecord.delegatedClients },
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: 'z6MkNotTheUnlockKey',
      bindingMacKey: unlock.bindingMacKey
    })
    expect(proofState).not.toBe('verified')
    expect(contents.delegatedClients).toEqual(swapped)
  })

  it('re-mints both delegations when a fresh sibling is supplied', async () => {
    const unlock = await standingUnlock('a standing passphrase secret')
    const acting = await deriveUnlockIdentity({
      secret: 'an enrolled client key',
      kdf: KEYRING_KDF
    })
    const issued = await wrapUnlockRecord({
      controller: 'did:key:z6MkAccountController',
      pointer: POINTER,
      delegation: DELEGATION,
      delegatedClients: DELEGATED_CLIENTS,
      ladderSeed: unlock.ladderSeed,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })
    const freshBridge = {
      ...DELEGATION,
      id: 'urn:zcap:delegated:fresh'
    } as unknown as IZcap
    const freshSibling = {
      ...DELEGATED_CLIENTS,
      id: 'urn:zcap:delegated:clientAnnex-fresh'
    } as unknown as IZcap
    const reminted = await remintUnlockRecordDelegations({
      record: issued,
      delegation: freshBridge,
      delegatedClients: freshSibling,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: acting.recordSigner
    })
    expect(reminted.wrapped).toEqual(issued.wrapped)
    expect(reminted.ladder).toEqual(issued.ladder)
    expect(reminted.binding).toBe(issued.binding)
    expect(reminted.bridge).not.toEqual(issued.bridge)
    expect(reminted.delegatedClients).not.toEqual(issued.delegatedClients)
    const { contents } = await unwrapUnlockRecord({
      record: reminted,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: 'z6MkNotTheUnlockKey',
      bindingMacKey: unlock.bindingMacKey
    })
    expect((contents.delegation as { id?: string }).id).toBe(
      'urn:zcap:delegated:fresh'
    )
    expect((contents.delegatedClients as { id?: string }).id).toBe(
      'urn:zcap:delegated:clientAnnex-fresh'
    )
  })

  it('carries an existing delegatedClients member verbatim when no fresh one is supplied', async () => {
    const unlock = await standingUnlock('a standing passphrase secret')
    const acting = await deriveUnlockIdentity({
      secret: 'an enrolled client key',
      kdf: KEYRING_KDF
    })
    const issued = await wrapUnlockRecord({
      controller: 'did:key:z6MkAccountController',
      pointer: POINTER,
      delegation: DELEGATION,
      delegatedClients: DELEGATED_CLIENTS,
      ladderSeed: unlock.ladderSeed,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })
    const reminted = await remintUnlockRecordDelegations({
      record: issued,
      delegation: {
        ...DELEGATION,
        id: 'urn:zcap:delegated:fresh'
      } as unknown as IZcap,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: acting.recordSigner
    })
    expect(reminted.delegatedClients).toEqual(issued.delegatedClients)
    const { contents } = await unwrapUnlockRecord({
      record: reminted,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: 'z6MkNotTheUnlockKey',
      bindingMacKey: unlock.bindingMacKey
    })
    expect(contents.delegatedClients).toEqual(DELEGATED_CLIENTS)
  })
})
