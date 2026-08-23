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
  CONTACTS_SPACE_COLLECTION_SPEC,
  CONTACTS_HISTORY_SPACE_COLLECTION_SPEC,
  APP_CONNECTIONS_COLLECTION,
  APP_CONNECTIONS_COLLECTION_SPEC,
  ID_COLLECTION_SPEC,
  KEY_MAP_COLLECTION_SPEC,
  UNLOCK_METHODS_COLLECTION_SPEC,
  WALLET_SPACE_SYNCED_SPECS,
  WALLET_SPACE_SYSTEM_SPECS,
  WALLET_SPACE_PROVISION_ROSTER,
  publicCredentialUrl,
  addHistoryNewAccount,
  addHistorySpaceCreated,
  addHistoryCredentialCreated,
  addHistoryCredentialDeleted,
  addHistoryCredentialShared,
  addHistoryCredentialUnshared,
  addHistoryLogin,
  addHistoryWalletLogin,
  addHistoryAppRevoke,
  addHistoryClientRevoked,
  ACTIVITY_TYPE
} from '../../src/space/index.js'

describe('space collection ids + specs', () => {
  it('pins the shared collection ids', () => {
    expect(PRIVATE_CREDENTIALS_COLLECTION).toBe('private-credentials')
    expect(PUBLIC_CREDENTIALS_COLLECTION).toBe('public-credentials')
    expect(WALLET_ACTIVITY_COLLECTION).toBe('wallet-activity')
    expect(APP_CONNECTIONS_COLLECTION).toBe('app-connections')
  })

  it('describes private-credentials as immutable content-addressed EDV', () => {
    expect(PRIVATE_CREDENTIALS_COLLECTION_SPEC).toEqual({
      collectionId: 'private-credentials',
      name: 'Verifiable Credentials',
      idDerivation: 'content',
      mutable: false,
      encryption: 'edv',
      isPublic: false,
      shareable: true
    })
  })

  it('describes public-credentials as plaintext world-readable', () => {
    expect(PUBLIC_CREDENTIALS_COLLECTION_SPEC).toEqual({
      collectionId: 'public-credentials',
      name: 'Verifiable Credentials (Publicly Shared)',
      idDerivation: 'content',
      mutable: false,
      encryption: 'plaintext',
      isPublic: true,
      shareable: false
    })
  })

  it('describes wallet-activity as append-only EDV', () => {
    expect(WALLET_ACTIVITY_COLLECTION_SPEC).toEqual({
      collectionId: 'wallet-activity',
      name: 'Wallet Activity Log',
      idDerivation: 'content',
      mutable: false,
      encryption: 'edv',
      isPublic: false,
      shareable: true
    })
  })

  it('describes app-connections as immutable unshareable EDV', () => {
    expect(APP_CONNECTIONS_COLLECTION_SPEC).toEqual({
      collectionId: 'app-connections',
      name: 'App Connections',
      idDerivation: 'content',
      mutable: false,
      encryption: 'edv',
      isPublic: false,
      shareable: false
    })
  })

  it('spreads the social-core contacts identity contract into Space specs', () => {
    expect(CONTACTS_SPACE_COLLECTION_SPEC).toEqual({
      collectionId: 'contacts',
      name: 'Contacts',
      idDerivation: 'random',
      mutable: true,
      encryption: 'edv',
      isPublic: false,
      shareable: true
    })
    expect(CONTACTS_HISTORY_SPACE_COLLECTION_SPEC).toEqual({
      collectionId: 'contacts-history',
      name: 'Contacts History',
      idDerivation: 'content',
      mutable: false,
      encryption: 'edv',
      isPublic: false,
      shareable: true
    })
  })

  it('describes id as public plaintext and key-map as private plaintext', () => {
    expect(ID_COLLECTION_SPEC).toEqual({
      collectionId: 'id',
      name: 'Identity',
      encryption: 'plaintext',
      isPublic: true
    })
    expect(KEY_MAP_COLLECTION_SPEC).toEqual({
      collectionId: 'key-map',
      name: 'Key Map',
      encryption: 'plaintext',
      isPublic: false
    })
  })

  it('describes unlock-methods as private plaintext', () => {
    expect(UNLOCK_METHODS_COLLECTION_SPEC).toEqual({
      collectionId: 'unlock-methods',
      name: 'Unlock Methods',
      encryption: 'plaintext',
      isPublic: false
    })
  })

  it('lists the six synced feeds in provision order', () => {
    expect(WALLET_SPACE_SYNCED_SPECS.map(s => s.collectionId)).toEqual([
      'private-credentials',
      'public-credentials',
      'wallet-activity',
      'contacts',
      'contacts-history',
      'app-connections'
    ])
  })

  it('marks exactly the shareable synced feeds', () => {
    const shareable = WALLET_SPACE_SYNCED_SPECS.filter(
      spec => spec.shareable
    ).map(spec => spec.collectionId)
    expect(shareable).toEqual([
      'private-credentials',
      'wallet-activity',
      'contacts',
      'contacts-history'
    ])
  })

  it('keeps the system collections outside the synced feeds', () => {
    expect(WALLET_SPACE_SYSTEM_SPECS.map(s => s.collectionId)).toEqual([
      'id',
      'key-map',
      'unlock-methods'
    ])
  })

  it('rosters the full Space layout, synced feeds first', () => {
    expect(WALLET_SPACE_PROVISION_ROSTER).toEqual([
      ...WALLET_SPACE_SYNCED_SPECS,
      ...WALLET_SPACE_SYSTEM_SPECS
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

  it('keeps a sub-path deployment base-path prefix', () => {
    // The path is joined onto the server URL's base path, so the prefix the
    // client writes under survives into the shared link.
    expect(
      publicCredentialUrl({
        serverUrl: 'https://storage.example/ignored/',
        spaceId: 'S',
        cid: 'C'
      })
    ).toBe('https://storage.example/ignored/space/S/public-credentials/C')
  })

  it('percent-encodes path segments', () => {
    expect(
      publicCredentialUrl({
        serverUrl: 'https://storage.example',
        spaceId: 'S',
        cid: 'a b'
      })
    ).toBe('https://storage.example/space/S/public-credentials/a%20b')
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

  it('puts a supplied title into the summary and the object', () => {
    const args = {
      cid: 'CID',
      title: 'My Diploma',
      user: { email: 'a@b.c' },
      id: 'r',
      created: 't'
    }
    expect(addHistoryCredentialCreated(args)).toMatchObject({
      type: ['Create'],
      summary: 'Credential created: My Diploma',
      object: { cid: 'CID', title: 'My Diploma' }
    })
    expect(addHistoryCredentialDeleted(args)).toMatchObject({
      summary: 'Credential deleted: My Diploma',
      object: { cid: 'CID', title: 'My Diploma' }
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

    const withAppUrl = addHistoryLogin({
      user: { email: 'a@b.c' },
      origin: 'https://app.example',
      grants,
      appConnect: {
        name: 'Demo App',
        firstRun: false,
        appUrl: 'https://app.example/wallet'
      },
      id: 'r',
      created: 't'
    })
    expect(withAppUrl.summary).toBe(
      'Connected Demo App (https://app.example) to wallet.'
    )
    expect(withAppUrl.object).toEqual({
      origin: 'https://app.example',
      zcaps: grants,
      appConnect: {
        name: 'Demo App',
        firstRun: false,
        appUrl: 'https://app.example/wallet'
      }
    })

    const agent = addHistoryLogin({
      user: { email: 'a@b.c' },
      origin: 'n/a (API request)',
      grants,
      actor: { name: 'research-bot' },
      id: 'r',
      created: 't'
    })
    expect(agent.summary).toBe('Logged in to n/a (API request) with wallet.')
    expect(agent.actor).toEqual({ email: 'a@b.c' })
    expect(agent.object).toEqual({
      origin: 'n/a (API request)',
      zcaps: grants,
      actor: { name: 'research-bot' }
    })
  })

  it('builds a wallet-login activity, with and without an actor', () => {
    const anonymous = addHistoryWalletLogin({ id: 'r', created: 't' })
    expect(anonymous).toEqual({
      id: 'r',
      type: ['Login'],
      summary: 'Logged in to wallet.',
      created: 't'
    })

    const withUser = addHistoryWalletLogin({
      user: { email: 'a@b.c' },
      id: 'r',
      created: 't'
    })
    expect(withUser.actor).toEqual({ email: 'a@b.c' })

    const defaulted = addHistoryWalletLogin()
    expect(typeof defaulted.id).toBe('string')
    expect(Number.isNaN(Date.parse(defaulted.created as string))).toBe(false)
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

  it('builds a client-revoke activity, label preferred over the key', () => {
    const labeled = addHistoryClientRevoked({
      user: { email: 'a@b.c' },
      signingKeyMultibase: 'z6MkRevoked',
      label: 'Old laptop',
      rotated: 3,
      failed: 1,
      id: 'r',
      created: 't'
    })
    expect(labeled.type).toEqual(['ClientRevoke'])
    expect(labeled.summary).toBe('Disconnected wallet client Old laptop.')
    expect(labeled.object).toEqual({
      signingKeyMultibase: 'z6MkRevoked',
      label: 'Old laptop',
      rotated: 3,
      failed: 1
    })

    const unlabeled = addHistoryClientRevoked({
      user: { email: 'a@b.c' },
      signingKeyMultibase: 'z6MkRevoked',
      id: 'r',
      created: 't'
    })
    expect(unlabeled.summary).toBe('Disconnected wallet client z6MkRevoked.')
  })

  it('exposes the wire activity type strings', () => {
    expect(ACTIVITY_TYPE).toEqual({
      Create: 'Create',
      Delete: 'Delete',
      Share: 'Share',
      Unshare: 'Unshare',
      Login: 'Login',
      Revoke: 'Revoke',
      ClientRevoke: 'ClientRevoke',
      CollectionShare: 'CollectionShare',
      CollectionUnshare: 'CollectionUnshare',
      GenerationCollect: 'GenerationCollect'
    })
  })
})
