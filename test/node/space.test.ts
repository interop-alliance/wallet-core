/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The wallet Space layout contract: collection ids + specs, the public-credential
 * URL derivation, and the pure `wallet-activity` payload builders. These are the
 * byte-significant values both wallet replicas must agree on.
 */
import { describe, it, expect } from 'vitest'

import {
  PRIVATE_CREDENTIALS_COLLECTION,
  PUBLIC_CREDENTIALS_COLLECTION,
  WALLET_ACTIVITY_COLLECTION,
  PRIVATE_CREDENTIALS_COLLECTION_SPEC,
  PUBLIC_CREDENTIALS_COLLECTION_SPEC,
  WALLET_ACTIVITY_COLLECTION_SPEC,
  WALLET_SPACE_COLLECTION_SPECS,
  publicCredentialUrl,
  addHistoryNewAccount,
  addHistorySpaceCreated,
  addHistoryCredentialCreated,
  addHistoryCredentialDeleted,
  addHistoryCredentialShared,
  addHistoryCredentialUnshared,
  addHistoryLogin,
  addHistoryAppRevoke,
  ACTIVITY_TYPE
} from '../../src/space/index.js'

describe('space collection ids + specs', () => {
  it('pins the shared collection ids', () => {
    expect(PRIVATE_CREDENTIALS_COLLECTION).toBe('private-credentials')
    expect(PUBLIC_CREDENTIALS_COLLECTION).toBe('public-credentials')
    expect(WALLET_ACTIVITY_COLLECTION).toBe('wallet-activity')
  })

  it('describes private-credentials as immutable content-addressed EDV', () => {
    expect(PRIVATE_CREDENTIALS_COLLECTION_SPEC).toEqual({
      collectionId: 'private-credentials',
      idDerivation: 'content',
      mutable: false,
      encryption: 'edv',
      isPublic: false
    })
  })

  it('describes public-credentials as plaintext world-readable', () => {
    expect(PUBLIC_CREDENTIALS_COLLECTION_SPEC).toEqual({
      collectionId: 'public-credentials',
      idDerivation: 'content',
      mutable: false,
      encryption: 'plaintext',
      isPublic: true
    })
  })

  it('describes wallet-activity as append-only EDV', () => {
    expect(WALLET_ACTIVITY_COLLECTION_SPEC).toEqual({
      collectionId: 'wallet-activity',
      idDerivation: 'content',
      mutable: false,
      encryption: 'edv',
      isPublic: false
    })
  })

  it('lists the three wallet Space specs in provision order', () => {
    expect(WALLET_SPACE_COLLECTION_SPECS.map(s => s.collectionId)).toEqual([
      'private-credentials',
      'public-credentials',
      'wallet-activity'
    ])
  })
})

describe('publicCredentialUrl', () => {
  it('derives {serverUrl}/space/{spaceId}/public-credentials/{cid}', () => {
    expect(
      publicCredentialUrl({
        serverUrl: 'https://storage.example',
        spaceId: 'SPACE',
        cid: 'CID'
      })
    ).toBe('https://storage.example/space/SPACE/public-credentials/CID')
  })

  it('resolves the path against a server URL that has a trailing path', () => {
    // The URL is absolute-rooted, so it replaces any base path.
    expect(
      publicCredentialUrl({
        serverUrl: 'https://storage.example/ignored/',
        spaceId: 'S',
        cid: 'C'
      })
    ).toBe('https://storage.example/space/S/public-credentials/C')
  })
})

describe('wallet-activity payload builders', () => {
  it('builds a new-account Create activity with injected id/created', () => {
    const activity = addHistoryNewAccount({
      user: { email: 'a@b.c', id: 'did:key:z123' },
      id: 'RID',
      created: '2026-01-01T00:00:00.000Z'
    })
    expect(activity).toEqual({
      id: 'RID',
      type: ['Create'],
      summary: 'Account Sign Up. did:key DID generated.',
      actor: { email: 'a@b.c' },
      object: 'did:key:z123',
      created: '2026-01-01T00:00:00.000Z'
    })
  })

  it('defaults id via crypto.randomUUID and created via ISO timestamp', () => {
    const before = Date.now()
    const activity = addHistoryCredentialCreated({
      cid: 'CID',
      user: { email: 'a@b.c' }
    })
    expect(typeof activity.id).toBe('string')
    expect((activity.id as string).length).toBeGreaterThan(0)
    const createdMs = Date.parse(activity.created as string)
    expect(Number.isNaN(createdMs)).toBe(false)
    expect(createdMs).toBeGreaterThanOrEqual(before - 1000)
  })

  it('builds the four credential activities with matching type + verb', () => {
    const args = { cid: 'CID', user: { email: 'a@b.c' }, id: 'r', created: 't' }
    expect(addHistoryCredentialCreated(args)).toMatchObject({
      type: ['Create'],
      summary: 'Credential created: CID',
      object: 'CID'
    })
    expect(addHistoryCredentialDeleted(args)).toMatchObject({
      type: ['Delete'],
      summary: 'Credential deleted: CID'
    })
    expect(addHistoryCredentialShared(args)).toMatchObject({
      type: ['Share'],
      summary: 'Credential shared: CID'
    })
    expect(addHistoryCredentialUnshared(args)).toMatchObject({
      type: ['Unshare'],
      summary: 'Credential unshared: CID'
    })
  })

  it('builds a space-created activity with remote vs local summary', () => {
    const remote = addHistorySpaceCreated({
      actor: 'did:key:z1',
      object: [{ type: ['Space'], id: 'https://s/space/x' }],
      remote: true,
      id: 'r',
      created: 't'
    })
    expect(remote.summary).toBe(
      'Account space created on remote storage server, collections initialized.'
    )
    expect(remote.type).toEqual(['Create'])

    const local = addHistorySpaceCreated({
      actor: 'did:key:z1',
      object: [],
      id: 'r',
      created: 't'
    })
    expect(local.summary).toBe(
      'Wallet collections initialized in local storage.'
    )
  })

  it('builds a login activity, with and without App Connect', () => {
    const grants = [
      {
        id: 'g1',
        target: 'https://s/space/x/c',
        allowedActions: ['GET'],
        expires: 't'
      }
    ]
    const plain = addHistoryLogin({
      user: { email: 'a@b.c' },
      origin: 'https://rp.example',
      grants,
      id: 'r',
      created: 't'
    })
    expect(plain.type).toEqual(['Login'])
    expect(plain.summary).toBe('Logged in to https://rp.example with wallet.')
    expect(plain.object).toEqual({
      origin: 'https://rp.example',
      zcaps: grants
    })

    const app = addHistoryLogin({
      user: { email: 'a@b.c' },
      origin: 'https://app.example',
      grants,
      appConnect: { name: 'Demo App', firstRun: true },
      id: 'r',
      created: 't'
    })
    expect(app.summary).toBe(
      'Connected Demo App (https://app.example) to wallet, minting a new app key.'
    )
    expect(app.object).toEqual({
      origin: 'https://app.example',
      zcaps: grants,
      appConnect: { name: 'Demo App', firstRun: true }
    })
  })

  it('builds an app-revoke activity with grant counts', () => {
    const counted = addHistoryAppRevoke({
      user: { email: 'a@b.c' },
      origin: 'https://app.example',
      name: 'Demo App',
      revoked: 2,
      skipped: 1,
      id: 'r',
      created: 't'
    })
    expect(counted.type).toEqual(['Revoke'])
    expect(counted.summary).toBe(
      'Revoked Demo App (https://app.example) app access: 2 grant(s) revoked, 1 skipped.'
    )

    const plain = addHistoryAppRevoke({
      user: { email: 'a@b.c' },
      origin: 'https://app.example',
      name: 'Demo App',
      id: 'r',
      created: 't'
    })
    expect(plain.summary).toBe(
      'Revoked Demo App (https://app.example) app access.'
    )
  })

  it('exposes the wire activity type strings', () => {
    expect(ACTIVITY_TYPE).toEqual({
      Create: 'Create',
      Delete: 'Delete',
      Share: 'Share',
      Unshare: 'Unshare',
      Login: 'Login',
      Revoke: 'Revoke',
      CollectionShare: 'CollectionShare',
      CollectionUnshare: 'CollectionUnshare'
    })
  })
})
