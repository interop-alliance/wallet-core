/**
 * Unit tests for the enrolled-client listing (`listEnrolledWebvhClients`):
 * enumeration keyed on `capabilityInvocation` over real minted key sets, the
 * key-agreement key read off the document's controller marker (and left
 * undefined, never guessed, when no marked method backs it), update-key
 * attribution across an enrollment and a self-rotation (the listed client
 * feeding `revokeWebvhClient` directly), the revoked client leaving the
 * listing, and the recovery key's structural exclusion (a `keyAgreement`-only
 * method never appears).
 *
 * Plus the current-key-set predicate that lives beside the listing
 * (`delegationKeyInDocument`): a published key holds in either DID form, a
 * revoked client's key stops holding with its verification method, a key that
 * survives under another relation but has left `capabilityDelegation` does
 * not hold, and an absent delegation key id reads as not-in-the-document.
 */
import { describe, expect, it } from 'vitest'
import { readLogFromString, updateDID } from '@interop/did-method-webvh'
import {
  clientKeyAgreementController,
  ensureDidWebvh,
  enrollWebvhClient,
  keyAgreementTwinMultibase,
  MULTIKEY_VM_TYPE,
  publishUpdatedLog,
  readPublishedLog,
  relationIds,
  rotateWebvhUpdateKey,
  updateKeyMultibase,
  updateKeySigner,
  type ClientWebvhUpdateKeys,
  type WebvhIdStore
} from '../../src/webvh/didWebvh.js'
import {
  delegationKeyInDocument,
  documentKeyMultibases,
  listEnrolledWebvhClients
} from '../../src/webvh/listClients.js'
import { revokeWebvhClient } from '../../src/webvh/revokeClient.js'
import { publishRecoveryKey } from '../../src/recovery/recoveryWebvh.js'
import {
  mintEnrollmentRequest,
  parseEnrollmentRequest
} from '../../src/enrollment/enrollment.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-list'
const DID_WEB = `did:web:localhost%3A8080:space:${SPACE_ID}:id`

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

/**
 * Publishes one more `keyAgreement` verification method under a client's
 * controller marker -- the shape a client with several published
 * key-agreement keys leaves in the document, which no ordinary ceremony
 * produces (enrollment is idempotent on the client's signing key).
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.updateKeys {ClientWebvhUpdateKeys}   the publishing client's
 *   own update-key seeds
 * @param options.signingKeyMultibase {string}   the client the marker names
 * @param options.keyAgreementKeyMultibase {string}   the extra key
 * @returns {Promise<void>}
 */
async function publishMarkedKeyAgreement({
  idStore,
  updateKeys,
  signingKeyMultibase,
  keyAgreementKeyMultibase
}: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  signingKeyMultibase: string
  keyAgreementKeyMultibase: string
}): Promise<void> {
  const published = (await readPublishedLog({ idStore }))!
  const { did, doc, log, etag } = published
  const vmId = `${did}#${keyAgreementKeyMultibase}`
  const updated = await updateDID({
    log,
    signer: await updateKeySigner({ seed: updateKeys.updateSeed }),
    alsoKnownAsWeb: true,
    updateKeys: published.updateKeys,
    nextKeyHashes: published.nextKeyHashes,
    verificationMethods: [
      ...(doc.verificationMethod ?? []),
      {
        id: vmId,
        type: MULTIKEY_VM_TYPE,
        controller: clientKeyAgreementController({ signingKeyMultibase }),
        publicKeyMultibase: keyAgreementKeyMultibase
      }
    ],
    authentication: relationIds(doc.authentication),
    assertionMethod: relationIds(doc.assertionMethod),
    keyAgreement: [...relationIds(doc.keyAgreement), vmId],
    capabilityInvocation: relationIds(doc.capabilityInvocation),
    capabilityDelegation: relationIds(doc.capabilityDelegation)
  })
  await publishUpdatedLog({ idStore, updated, ifMatch: etag })
}

describe('listEnrolledWebvhClients', () => {
  it('lists the genesis client with its twin, active update key, and addedAt', async () => {
    const { log, firstClient, firstSeeds } = await accountWithRealFirstClient()
    const entries = currentLogEntries(log)

    const clients = listEnrolledWebvhClients({ log: entries })
    expect(clients).toHaveLength(1)
    const [client] = clients
    expect(client!.signingKeyMultibase).toBe(firstClient.signingKeyMultibase)
    // Read off the document's controller marker, not derived: the multibase
    // the genesis published under keyAgreement.
    expect(client!.keyAgreementKeyMultibases).toEqual([
      firstClient.keyAgreementKeyMultibase
    ])
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
    expect(clients[1]!.keyAgreementKeyMultibases).toEqual([
      secondRequest.keyAgreementKeyMultibase
    ])
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

  it('leaves the key-agreement key undefined when no marked method backs it', async () => {
    const { log, firstClient } = await accountWithRealFirstClient()
    const entries = currentLogEntries(log)
    // The same document with every controller marker rewritten to the
    // account DID: the client's key-agreement method is still published, but
    // nothing says whose it is.
    const last = entries[entries.length - 1]!
    const unmarked = {
      ...last,
      state: {
        ...last.state,
        verificationMethod: (last.state.verificationMethod ?? []).map(
          (method: { controller?: string }) =>
            method.controller?.startsWith('did:key:')
              ? { ...method, controller: last.state.id }
              : method
        )
      }
    } as (typeof entries)[number]

    const listed = listEnrolledWebvhClients({
      log: [...entries.slice(0, -1), unmarked]
    })
    expect(listed).toHaveLength(1)
    expect(listed[0]!.signingKeyMultibase).toBe(firstClient.signingKeyMultibase)
    // Refuse, do not guess: the canonical twin is NOT substituted, even
    // though it would be right here.
    expect(listed[0]!.keyAgreementKeyMultibases).toEqual([])
    expect(
      keyAgreementTwinMultibase({
        signingKeyMultibase: firstClient.signingKeyMultibase
      })
    ).toBe(firstClient.keyAgreementKeyMultibase)
  })

  it('lists every marked key-agreement method a client published, in document order', async () => {
    const { idStore, log, firstClient, firstSeeds } =
      await accountWithRealFirstClient()
    const extraAgreementKey = 'z6LSFirstClientExtraAgreement2'
    await publishMarkedKeyAgreement({
      idStore,
      updateKeys: firstSeeds,
      signingKeyMultibase: firstClient.signingKeyMultibase,
      keyAgreementKeyMultibase: extraAgreementKey
    })

    const clients = listEnrolledWebvhClients({
      log: currentLogEntries(log)
    })
    expect(clients).toHaveLength(1)
    // Document order, the full set -- not the first match.
    expect(clients[0]!.keyAgreementKeyMultibases).toEqual([
      firstClient.keyAgreementKeyMultibase,
      extraAgreementKey
    ])
  })

  it('returns an empty listing for an empty log', () => {
    expect(listEnrolledWebvhClients({ log: [] })).toEqual([])
  })
})

describe('delegationKeyInDocument (the current-key-set rule for one delegation)', () => {
  it('holds for a key the document publishes, in either DID form', async () => {
    const { idStore, firstClient } = await accountWithRealFirstClient()
    const published = await readPublishedLog({ idStore })
    const doc = published!.doc

    // The did:webvh form the promoted account signs under...
    expect(
      delegationKeyInDocument({
        doc,
        delegationKeyId: `${doc.id}#${firstClient.signingKeyMultibase}`
      })
    ).toBe(true)
    // ...and the did:key form of the same key agree.
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

  it('fails for a key kept under another relation only', () => {
    // The key is a document verification method and stands under
    // `authentication`, but the delegation relation no longer names it: every
    // delegation it signed fails the server's purpose check, so the predicate
    // must read it as rotted.
    const doc = {
      verificationMethod: [
        { id: 'did:webvh:x#z6MkOther', publicKeyMultibase: 'z6MkOther' },
        { id: 'did:webvh:x#z6MkDelegator', publicKeyMultibase: 'z6MkDelegator' }
      ],
      authentication: ['did:webvh:x#z6MkOther'],
      capabilityDelegation: ['did:webvh:x#z6MkDelegator']
    }
    expect(
      delegationKeyInDocument({
        doc,
        delegationKeyId: 'did:key:z6MkOther#z6MkOther'
      })
    ).toBe(false)
    // The coarse membership test still finds it -- that is the difference.
    expect(documentKeyMultibases({ doc }).has('z6MkOther')).toBe(true)
  })

  it('holds for an embedded delegation member and for a string reference', () => {
    const embedded = {
      capabilityDelegation: [
        { id: 'did:webvh:x#z6MkEmbedded', publicKeyMultibase: 'z6MkEmbedded' }
      ]
    }
    expect(
      delegationKeyInDocument({
        doc: embedded,
        delegationKeyId: 'did:key:z6MkEmbedded#z6MkEmbedded'
      })
    ).toBe(true)

    // A string reference resolves through the document's `verificationMethod`
    // entry, whose id fragment and key multibase both answer.
    const referenced = {
      verificationMethod: [
        { id: 'did:webvh:x#keys-1', publicKeyMultibase: 'z6MkReferenced' }
      ],
      capabilityDelegation: ['did:webvh:x#keys-1']
    }
    expect(
      delegationKeyInDocument({
        doc: referenced,
        delegationKeyId: 'did:key:z6MkReferenced#z6MkReferenced'
      })
    ).toBe(true)
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
