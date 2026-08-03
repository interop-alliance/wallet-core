/**
 * Unit tests for the enrolled-client listing (`listEnrolledWebvhClients`):
 * enumeration keyed on `capabilityInvocation` over real minted key sets, the
 * X25519 twin derivation matching the enrollment ceremony's own key
 * agreement multibase, update-key attribution across an enrollment and a
 * self-rotation (the listed client feeding `revokeWebvhClient` directly),
 * the revoked client leaving the listing, and the recovery key's structural
 * exclusion (a `keyAgreement`-only method never appears).
 *
 * Plus the current-key-set predicate that lives beside the listing
 * (`delegationKeyInDocument`): a published key holds in either DID spelling, a
 * revoked client's key stops holding with its verification method, and an
 * absent delegation key id reads as not-in-the-document.
 */
import { describe, expect, it } from 'vitest'
import { readLogFromString } from '@interop/did-method-webvh'
import {
  ensureDidWebvh,
  enrollWebvhClient,
  readPublishedLog,
  rotateWebvhUpdateKey,
  updateKeyMultibase,
  type ClientWebvhUpdateKeys,
  type WebvhIdStore
} from '../../src/webvh/didWebvh.js'
import {
  delegationKeyInDocument,
  documentKeyMultibases,
  keyAgreementTwinMultibase,
  listEnrolledWebvhClients
} from '../../src/webvh/listClients.js'
import { revokeWebvhClient } from '../../src/webvh/revokeClient.js'
import { publishRecoveryKey } from '../../src/recovery/recoveryWebvh.js'
import {
  mintEnrollmentRequest,
  parseEnrollmentRequest
} from '../../src/enrollment/enrollment.js'
import {
  DID_DOCUMENT_RESOURCE,
  DID_LOG_RESOURCE
} from '../../src/space/collections.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-list'
const DID_WEB = `did:web:localhost%3A8080:space:${SPACE_ID}:id`

/**
 * The in-memory `WebvhIdStore` the ceremonies run against.
 *
 * @returns {object}
 */
function memoryIdStore() {
  let currentLog: string | undefined
  let currentDidDoc: object | undefined
  let currentKeys: object = {}
  const idStore: WebvhIdStore & { getKeyMap(): Promise<object> } = {
    async getKeyMap() {
      return currentKeys
    },
    async putKeyMap({ content }: { content: object }) {
      currentKeys = content
    },
    async getIdResource({ resourceId }: { resourceId: string }) {
      return resourceId === DID_DOCUMENT_RESOURCE ? currentDidDoc : undefined
    },
    async getIdResourceRaw({ resourceId }: { resourceId: string }) {
      return resourceId === DID_LOG_RESOURCE ? currentLog : undefined
    },
    async putIdResource({
      resourceId,
      content
    }: {
      resourceId: string
      content: object | string
      contentType?: string
    }) {
      if (resourceId === DID_LOG_RESOURCE && typeof content === 'string') {
        currentLog = content
      }
      if (resourceId === DID_DOCUMENT_RESOURCE && typeof content === 'object') {
        currentDidDoc = content
      }
    }
  }
  return { idStore, log: () => currentLog }
}

/**
 * Provisions an account whose first client's key set is REAL (minted by the
 * enrollment codec), so the listing's X25519 twin derivation has genuine key
 * material to work on.
 *
 * @returns {Promise<object>}
 */
async function accountWithRealFirstClient() {
  const { idStore, log } = memoryIdStore()
  const first = await mintEnrollmentRequest()
  const firstRequest = parseEnrollmentRequest({ code: first.code })
  await ensureDidWebvh({
    idStore,
    wasServerUrl: WAS_URL,
    spaceId: SPACE_ID,
    didWebKeys: {
      authentication: {
        vmId: `${DID_WEB}#z6MkAuth`,
        kmsKeyId: 'kms/keys/auth'
      },
      assertionMethod: {
        vmId: `${DID_WEB}#z6MkAssert`,
        kmsKeyId: 'kms/keys/assert'
      },
      keyAgreement: { vmId: `${DID_WEB}#z6LSAgree`, kmsKeyId: 'kms/keys/agree' }
    },
    clientKeys: {
      signingKeyMultibase: firstRequest.signingKeyMultibase,
      keyAgreementKeyMultibase: firstRequest.keyAgreementKeyMultibase
    },
    updateKeys: first.webvhUpdateKeys
  })
  return {
    idStore,
    log,
    firstClient: firstRequest,
    firstSeeds: first.webvhUpdateKeys
  }
}

/**
 * Parses the store's current log.
 *
 * @param log {function}
 * @returns {object}
 */
function currentLogEntries(log: () => string | undefined) {
  return readLogFromString(log()!)
}

describe('listEnrolledWebvhClients', () => {
  it('lists the genesis client with its twin, active update key, and addedAt', async () => {
    const { log, firstClient, firstSeeds } = await accountWithRealFirstClient()
    const entries = currentLogEntries(log)

    const clients = listEnrolledWebvhClients({ log: entries })
    expect(clients).toHaveLength(1)
    const [client] = clients
    expect(client!.signingKeyMultibase).toBe(firstClient.signingKeyMultibase)
    // The derived Montgomery twin equals the multibase the mint itself
    // published under keyAgreement.
    expect(client!.keyAgreementKeyMultibase).toBe(
      firstClient.keyAgreementKeyMultibase
    )
    expect(client!.updateKeyMultibase).toBe(
      await updateKeyMultibase({ seed: firstSeeds.updateSeed })
    )
    expect(client!.addedAt).toBe(entries[0]!.versionTime)
  })

  it('lists an enrolled second client in enrollment order, attributing its update key', async () => {
    const { idStore, log, firstClient, firstSeeds } =
      await accountWithRealFirstClient()
    const second = await mintEnrollmentRequest()
    const secondRequest = {
      signingKeyMultibase: second.clientDid.slice('did:key:'.length),
      keyAgreementKeyMultibase: keyAgreementTwinMultibase({
        signingKeyMultibase: second.clientDid.slice('did:key:'.length)
      }),
      updateKeyMultibase: await updateKeyMultibase({
        seed: second.webvhUpdateKeys.updateSeed
      }),
      stagedUpdateKeyMultibase: await updateKeyMultibase({
        seed: second.webvhUpdateKeys.stagedSeed
      })
    }
    await enrollWebvhClient({
      idStore,
      updateKeys: firstSeeds,
      newClient: secondRequest
    })

    const entries = currentLogEntries(log)
    const clients = listEnrolledWebvhClients({ log: entries })
    expect(clients.map(client => client.signingKeyMultibase)).toEqual([
      firstClient.signingKeyMultibase,
      secondRequest.signingKeyMultibase
    ])
    expect(clients[1]!.keyAgreementKeyMultibase).toBe(
      secondRequest.keyAgreementKeyMultibase
    )
    expect(clients[1]!.updateKeyMultibase).toBe(
      secondRequest.updateKeyMultibase
    )
    // The add entry is the last of the enrollment's two; its versionTime is
    // the client's enrollment moment.
    expect(clients[1]!.addedAt).toBe(entries[entries.length - 1]!.versionTime)
  })

  it('follows a self-rotation and the listed keys feed revokeWebvhClient directly', async () => {
    const { idStore, log, firstSeeds } = await accountWithRealFirstClient()
    const second = await mintEnrollmentRequest()
    const signingKeyMultibase = second.clientDid.slice('did:key:'.length)
    await enrollWebvhClient({
      idStore,
      updateKeys: firstSeeds,
      newClient: {
        signingKeyMultibase,
        keyAgreementKeyMultibase: keyAgreementTwinMultibase({
          signingKeyMultibase
        }),
        updateKeyMultibase: await updateKeyMultibase({
          seed: second.webvhUpdateKeys.updateSeed
        }),
        stagedUpdateKeyMultibase: await updateKeyMultibase({
          seed: second.webvhUpdateKeys.stagedSeed
        })
      }
    })
    // The second client self-rotates: the listing must attribute the ROTATED
    // active key, not the enrollment-time one.
    let rolled: ClientWebvhUpdateKeys = second.webvhUpdateKeys
    await rotateWebvhUpdateKey({
      idStore,
      updateKeys: second.webvhUpdateKeys,
      persistUpdateKeys: async next => {
        rolled = next
      }
    })
    const rotatedActive = await updateKeyMultibase({ seed: rolled.updateSeed })

    const listed = listEnrolledWebvhClients({
      log: currentLogEntries(log)
    }).find(client => client.signingKeyMultibase === signingKeyMultibase)
    expect(listed?.updateKeyMultibase).toBe(rotatedActive)

    // The listed row is a complete RevokedClientKeys: revocation succeeds
    // from it verbatim.
    await revokeWebvhClient({
      idStore,
      updateKeys: firstSeeds,
      revokedClient: {
        signingKeyMultibase: listed!.signingKeyMultibase,
        keyAgreementKeyMultibase: listed!.keyAgreementKeyMultibase,
        updateKeyMultibase: listed!.updateKeyMultibase!
      }
    })
    const after = listEnrolledWebvhClients({ log: currentLogEntries(log) })
    expect(after.map(client => client.signingKeyMultibase)).not.toContain(
      signingKeyMultibase
    )
    expect(after).toHaveLength(1)
  })

  it('never lists a recovery key (keyAgreement-only, structurally excluded)', async () => {
    const { idStore, log, firstSeeds } = await accountWithRealFirstClient()
    await publishRecoveryKey({
      idStore,
      updateKeys: firstSeeds,
      recovery: {
        keyAgreementKeyMultibase: 'z6LSRecoveryAgreementKey999999',
        updateKeyMultibase: 'z6MkRecoveryUpdateKey999999999'
      }
    })
    const published = await readPublishedLog({ idStore })
    // The recovery VM is in the document...
    expect(JSON.stringify(published!.doc)).toContain(
      'z6LSRecoveryAgreementKey999999'
    )
    // ...and the listing still shows exactly the one enrolled client.
    expect(
      listEnrolledWebvhClients({ log: currentLogEntries(log) })
    ).toHaveLength(1)
  })

  it('returns an empty listing for an empty log', () => {
    expect(listEnrolledWebvhClients({ log: [] })).toEqual([])
  })
})

describe('delegationKeyInDocument (the current-key-set rule for one delegation)', () => {
  it('holds for a key the document publishes, in either DID spelling', async () => {
    const { idStore, firstClient } = await accountWithRealFirstClient()
    const published = await readPublishedLog({ idStore })
    const doc = published!.doc

    // The did:webvh spelling the promoted account signs under...
    expect(
      delegationKeyInDocument({
        doc,
        delegationKeyId: `${doc.id}#${firstClient.signingKeyMultibase}`
      })
    ).toBe(true)
    // ...and the did:key spelling of the same key agree.
    expect(
      delegationKeyInDocument({
        doc,
        delegationKeyId:
          `did:key:${firstClient.signingKeyMultibase}` +
          `#${firstClient.signingKeyMultibase}`
      })
    ).toBe(true)
  })

  it('fails for a key the document no longer publishes (a revoked signer)', async () => {
    const { idStore, firstSeeds } = await accountWithRealFirstClient()
    const second = await mintEnrollmentRequest()
    const signingKeyMultibase = second.clientDid.slice('did:key:'.length)
    await enrollWebvhClient({
      idStore,
      updateKeys: firstSeeds,
      newClient: {
        signingKeyMultibase,
        keyAgreementKeyMultibase: keyAgreementTwinMultibase({
          signingKeyMultibase
        }),
        updateKeyMultibase: await updateKeyMultibase({
          seed: second.webvhUpdateKeys.updateSeed
        }),
        stagedUpdateKeyMultibase: await updateKeyMultibase({
          seed: second.webvhUpdateKeys.stagedSeed
        })
      }
    })
    const delegationKeyId = `did:key:${signingKeyMultibase}#${signingKeyMultibase}`
    const enrolled = await readPublishedLog({ idStore })
    expect(
      delegationKeyInDocument({ doc: enrolled!.doc, delegationKeyId })
    ).toBe(true)

    await revokeWebvhClient({
      idStore,
      updateKeys: firstSeeds,
      revokedClient: {
        signingKeyMultibase,
        keyAgreementKeyMultibase: keyAgreementTwinMultibase({
          signingKeyMultibase
        }),
        updateKeyMultibase: await updateKeyMultibase({
          seed: second.webvhUpdateKeys.updateSeed
        })
      }
    })
    const revoked = await readPublishedLog({ idStore })
    // The delegation that client signed stopped chaining with its VM.
    expect(
      delegationKeyInDocument({ doc: revoked!.doc, delegationKeyId })
    ).toBe(false)
  })

  it('reports an ABSENT delegation key id as not in the document', () => {
    const doc = {
      verificationMethod: [
        { id: 'did:webvh:x#z6MkOne', publicKeyMultibase: 'z6MkOne' }
      ]
    }
    // The decision taken once: a record that does not say which key signed it
    // cannot be checked, so it does not stand (it gets the health nudge).
    expect(delegationKeyInDocument({ doc, delegationKeyId: undefined })).toBe(
      false
    )
    expect(delegationKeyInDocument({ doc, delegationKeyId: '' })).toBe(false)
    // A bare id with no fragment is equally uncheckable.
    expect(delegationKeyInDocument({ doc, delegationKeyId: '#' })).toBe(false)
  })

  it('collects both the publicKeyMultibase and the id fragment of every method', () => {
    const multibases = documentKeyMultibases({
      doc: {
        verificationMethod: [
          { id: 'did:webvh:x#z6MkFragment', publicKeyMultibase: 'z6MkKey' },
          { id: 'did:webvh:x#z6MkNoKeyMaterial' },
          { publicKeyMultibase: 'z6MkNoId' }
        ]
      }
    })
    expect([...multibases].sort()).toEqual([
      'z6MkFragment',
      'z6MkKey',
      'z6MkNoId',
      'z6MkNoKeyMaterial'
    ])
    expect(documentKeyMultibases({ doc: {} }).size).toBe(0)
  })
})
