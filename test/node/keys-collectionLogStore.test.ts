/**
 * `collectionDescriptorLogStore`: the sealable descriptor store over ONE
 * encrypted collection's governing history log (its `meta/log`
 * sub-resource). The builder derives its own chain-head pin slot from the
 * collection handle, so no caller names a `logId`; the epoch[0] install
 * through it IS the log's guarded genesis and a re-run adopts the served log
 * without a second write; a recipient escrow appends the full next state;
 * and the store carries this log's own class, so a ladder-signed append the
 * roster's ceremony-tail license would refuse is admitted here.
 */
import { describe, expect, it } from 'vitest'
import { PreconditionFailedError } from '@interop/was-client'
import type { Collection, CollectionEncryption } from '@interop/was-client'
import { addRecipient } from '@interop/was-client/edv'
import {
  memoryResourceLogPinStore,
  parseResourceLog
} from '@interop/vh-resource-log'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { collectionDescriptorLogStore } from '../../src/keys/collectionLogStore.js'
import {
  EPOCH_CONFIGURATION_STATE_TYPE,
  isSealableDescriptorStore
} from '../../src/keys/rosterLogStore.js'
import { collectionDescriptorLogPinId } from '../../src/descriptors/logSource.js'
import { ensureIndexedFirstEpoch } from '../../src/keys/spaceEpochs.js'
import { mintUserKey } from '../../src/keys/userKey.js'
import { userKeyAsRecipient } from '../../src/keys/userKeyCascade.js'
import { userKeyVaultKeys } from '../../src/keys/userKey.js'
import type { WebvhResourceLogController } from '../../src/resourceLog/index.js'
import { accountWithUnchangedEdit } from './fixtures/resourceLog.js'

const SPACE_ID = 'space-under-test'
const COLLECTION_ID = 'private-credentials'

/**
 * An in-memory fake of the Collection surface the log transport drives: the
 * `meta/log` sub-resource, read and written verbatim with real etag and
 * guarded-create semantics.
 *
 * @returns {object}
 */
function fakeCollection() {
  const state = {
    body: undefined as string | undefined,
    version: 0,
    puts: [] as Array<{ ifMatch?: string; ifNoneMatch?: boolean }>
  }
  const etag = () => `"v${state.version}"`
  const collection = {
    id: COLLECTION_ID,
    spaceId: SPACE_ID,
    getHistoryLog: async () =>
      state.body === undefined ? null : { body: state.body, etag: etag() },
    putHistoryLog: async (
      body: string,
      options: { ifMatch?: string; ifNoneMatch?: boolean } = {}
    ) => {
      state.puts.push(options)
      if (options.ifNoneMatch && state.body !== undefined) {
        throw new PreconditionFailedError('exists', { status: 412 })
      }
      if (options.ifMatch !== undefined && options.ifMatch !== etag()) {
        throw new PreconditionFailedError('stale', { status: 412 })
      }
      state.body = body
      state.version += 1
      return { etag: etag() }
    }
  }
  return {
    collection: collection as unknown as Collection,
    entries: () =>
      state.body === undefined ? [] : parseResourceLog(state.body),
    puts: state.puts
  }
}

/**
 * A grantee's key-agreement key, with `publicKeyMultibase` still visible (the
 * widened `IKeyAgreementKey` drops it) so a recipient entry can be minted.
 *
 * @returns {Promise<IKeyAgreementKey & { publicKeyMultibase: string }>}
 */
async function makeGranteeKak(): Promise<
  IKeyAgreementKey & { publicKeyMultibase: string }
> {
  const kak = await X25519KeyAgreementKey2020.generate()
  const did = `did:key:${kak.publicKeyMultibase}`
  kak.controller = did
  kak.id = `${did}#${kak.publicKeyMultibase}`
  return kak as IKeyAgreementKey & { publicKeyMultibase: string }
}

/**
 * The store under test, over a fresh fake collection.
 *
 * @param options {object}
 * @param options.controller {WebvhResourceLogController}
 * @param options.signer {object}   the log signer
 * @returns {object}
 */
function storeOver({
  controller,
  signer,
  host = fakeCollection(),
  pinStore = memoryResourceLogPinStore()
}: {
  controller: WebvhResourceLogController
  signer: Parameters<typeof collectionDescriptorLogStore>[0]['signer']
  host?: ReturnType<typeof fakeCollection>
  pinStore?: ReturnType<typeof memoryResourceLogPinStore>
}) {
  return {
    host,
    pinStore,
    store: collectionDescriptorLogStore({
      collection: host.collection,
      resolveController: async () => controller,
      pinStore,
      signer
    })
  }
}

describe('collectionDescriptorLogStore', () => {
  it('derives its pin slot from the collection handle', async () => {
    const { alice, beforeEdit } = await accountWithUnchangedEdit()
    const pinStore = memoryResourceLogPinStore()
    const { store, host } = storeOver({
      controller: beforeEdit,
      signer: alice.logSigner,
      pinStore
    })
    const userKey = await mintUserKey()

    await ensureIndexedFirstEpoch({
      store,
      recipients: [userKeyAsRecipient({ userKey })]
    })

    // The pin landed under the library-named slot for this collection's own
    // `meta/log`, which no caller passed in.
    const slot = collectionDescriptorLogPinId({
      spaceId: SPACE_ID,
      collectionId: COLLECTION_ID
    })
    expect(slot).toBe(`space/${SPACE_ID}/${COLLECTION_ID}/meta/log`)
    expect(host.entries()).toHaveLength(1)
    // The verified read advances the chain-head pin under that slot.
    await store.read()
    expect(await pinStore.read({ logId: slot })).not.toBeNull()
  })

  it('is sealable', async () => {
    const { alice, beforeEdit } = await accountWithUnchangedEdit()
    const { store } = storeOver({
      controller: beforeEdit,
      signer: alice.logSigner
    })
    expect(isSealableDescriptorStore(store)).toBe(true)
  })

  it("installs epoch[0] as the log's guarded genesis, and adopts it on a re-run", async () => {
    const { alice, beforeEdit } = await accountWithUnchangedEdit()
    const { store, host } = storeOver({
      controller: beforeEdit,
      signer: alice.logSigner
    })
    const userKey = await mintUserKey()

    const first = await ensureIndexedFirstEpoch({
      store,
      recipients: [userKeyAsRecipient({ userKey })]
    })

    expect(first.installed).toBe(true)
    // The genesis is one guarded create; nothing was replaced.
    expect(host.puts).toEqual([{ ifNoneMatch: true }])
    expect(host.entries()).toHaveLength(1)
    const genesisState = host.entries()[0]!.state as unknown as {
      type?: string
    }
    expect(genesisState.type).toBe(EPOCH_CONFIGURATION_STATE_TYPE)
    expect(first.descriptor.epochs).toHaveLength(1)
    expect(first.descriptor.currentEpoch).toBe(first.descriptor.epochs![0]!.id)
    // A fresh random epoch key, never the user key generation itself.
    expect(first.descriptor.currentEpoch).not.toBe(userKey.id)
    expect(first.descriptor.hmac).toBeDefined()

    // A second store over the same log adopts the served head untouched.
    const rerun = await ensureIndexedFirstEpoch({
      store: storeOver({
        controller: beforeEdit,
        signer: alice.logSigner,
        host
      }).store,
      recipients: [userKeyAsRecipient({ userKey })]
    })

    expect(rerun.installed).toBe(false)
    // The served head carries the state-document type the store stamps on;
    // everything the install settled comes back unchanged.
    expect(rerun.descriptor).toMatchObject(first.descriptor)
    expect(rerun.descriptor.type).toBe(EPOCH_CONFIGURATION_STATE_TYPE)
    expect(host.puts).toHaveLength(1)
    expect(host.entries()).toHaveLength(1)
  })

  it('appends the full next state when a recipient is escrowed', async () => {
    const { alice, beforeEdit } = await accountWithUnchangedEdit()
    const { store, host } = storeOver({
      controller: beforeEdit,
      signer: alice.logSigner
    })
    const userKey = await mintUserKey()
    const installed = await ensureIndexedFirstEpoch({
      store,
      recipients: [userKeyAsRecipient({ userKey })]
    })
    const grantee = await makeGranteeKak()

    await addRecipient({
      store,
      recipient: {
        id: grantee.id,
        publicKeyMultibase: grantee.publicKeyMultibase
      },
      owner: { keyAgreementKey: userKeyVaultKeys({ userKey }).keyAgreementKey }
    })

    expect(host.entries()).toHaveLength(2)
    const head = host.entries()[1]!.state as unknown as CollectionEncryption
    // Full state, not a delta: the epoch roster is carried forward whole.
    expect(head.currentEpoch).toBe(installed.descriptor.currentEpoch)
    expect(
      head.epochs![0]!.recipients.map(entry => entry.header.kid).sort()
    ).toEqual([userKeyAsRecipient({ userKey }).id, grantee.id].sort())
  })

  it('admits a ladder-signed append the roster class would refuse', async () => {
    // The class the builder states: `assertionMethod` membership at the
    // anchored version is the whole rule, so a ladder-signed rotation
    // against a document version that changed nothing lands.
    const { ladder, beforeEdit, unchangedEdit } =
      await accountWithUnchangedEdit()
    const host = fakeCollection()
    const pinStore = memoryResourceLogPinStore()
    let controller: WebvhResourceLogController = beforeEdit
    const store = collectionDescriptorLogStore({
      collection: host.collection,
      resolveController: async () => controller,
      pinStore,
      signer: ladder.logSigner
    })
    const userKey = await mintUserKey()
    await ensureIndexedFirstEpoch({
      store,
      recipients: [userKeyAsRecipient({ userKey })]
    })

    controller = unchangedEdit
    const grantee = await makeGranteeKak()
    await addRecipient({
      store,
      recipient: {
        id: grantee.id,
        publicKeyMultibase: grantee.publicKeyMultibase
      },
      owner: { keyAgreementKey: userKeyVaultKeys({ userKey }).keyAgreementKey }
    })

    expect(host.entries()).toHaveLength(2)
    expect(
      (await store.read())!.descriptor.epochs![0]!.recipients
    ).toHaveLength(2)
  })
})
