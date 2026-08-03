/**
 * Unit tests for did:webvh hosting: the client-held update-key seams, the
 * log-URL / DID mapping, the enrolled-client document shape, the idempotent
 * provisioning flow, the per-client rotation ceremony and its crash recovery,
 * the two-entry client enrollment ceremony, the lost-`keys.json` repair path,
 * plus the sparse-`updateDID` document preservation the rotation ceremony
 * depends on. Driven by in-memory fakes (no KMS, no WAS server).
 */
import { describe, it, expect } from 'vitest'
import type { KeystoreAgent } from '@interop/webkms-client'
import {
  createDID,
  defaultWebvhLogVerifier,
  deriveNextKeyHash,
  getFileUrl,
  readLogFromString,
  resolveDIDFromLog,
  signerFromExternalKey,
  updateDID
} from '@interop/did-method-webvh'
import type { DIDDoc, Signer } from '@interop/did-method-webvh'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import {
  didWebvhControllerTemplate,
  enrollWebvhClient,
  ensureDidWebvh,
  mintClientWebvhUpdateKeys,
  repairKeyBindings,
  rotateWebvhUpdateKey,
  updateKeyMultibase,
  type ClientWebvhUpdateKeys,
  type DidWebKeyMapV2,
  type WebvhClientKeys,
  type WebvhEnrollmentKeys,
  type WebvhIdStore
} from '../../src/webvh/didWebvh.js'
import {
  multibaseOf,
  type DidWebKey,
  type DidWebKeyMap
} from '../../src/webvh/didWeb.js'
import {
  DID_DOCUMENT_RESOURCE,
  DID_KEYS_RESOURCE,
  DID_LOG_RESOURCE
} from '../../src/space/collections.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-abc'
const DID_WEB = 'did:web:localhost%3A8080:space:space-abc:id'

/**
 * The public halves of one enrolled client's key set. Only the multibase
 * strings reach the document, so plain fixtures suffice.
 */
const CLIENT_KEYS: WebvhClientKeys = {
  signingKeyMultibase: 'z6MkClientSigningKeyExample',
  keyAgreementKeyMultibase: 'z6LSClientAgreementKeyExample'
}

function keyMap(): DidWebKeyMap {
  return {
    authentication: { vmId: `${DID_WEB}#z6MkAuth`, kmsKeyId: 'kms/keys/auth' },
    assertionMethod: {
      vmId: `${DID_WEB}#z6MkAssert`,
      kmsKeyId: 'kms/keys/assert'
    },
    keyAgreement: { vmId: `${DID_WEB}#z6LSAgree`, kmsKeyId: 'kms/keys/agree' }
  }
}

/**
 * The did:web document a key map projects to -- the fixture the `keys.json`
 * repair path matches verification methods back to keystore keys through.
 */
function didWebDocument({
  did,
  keys
}: {
  did: string
  keys: DidWebKeyMap
}): object {
  const method = (key: DidWebKey, type: string) => ({
    id: key.vmId,
    type,
    controller: did,
    publicKeyMultibase: multibaseOf(key.vmId)
  })
  return {
    id: did,
    verificationMethod: [
      method(keys.authentication, 'Ed25519VerificationKey2020'),
      method(keys.assertionMethod, 'Ed25519VerificationKey2020'),
      method(keys.keyAgreement, 'X25519KeyAgreementKey2020')
    ],
    authentication: [keys.authentication.vmId],
    assertionMethod: [keys.assertionMethod.vmId],
    keyAgreement: [keys.keyAgreement.vmId]
  }
}

/**
 * A deterministic 32-byte update-key seed, so a test can re-derive the same
 * update key across two in-memory stores.
 */
function fixedSeed(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill)
}

/**
 * The client-held seed pair the provisioning tests start from.
 */
function fixedUpdateKeys(): ClientWebvhUpdateKeys {
  return { updateSeed: fixedSeed(1), stagedSeed: fixedSeed(2) }
}

/**
 * A local Ed25519 signer over a seed, mirroring the module-private signer the
 * ceremony uses -- for the library-behavior pins that call createDID/updateDID
 * directly.
 */
async function seedSigner(seed: Uint8Array): Promise<Signer> {
  const keyPair = await Ed25519VerificationKey.generate({ seed })
  const { publicKeyMultibase } = keyPair
  keyPair.id = `did:key:${publicKeyMultibase}#${publicKeyMultibase}`
  const keySigner = keyPair.signer()
  return signerFromExternalKey({
    publicKeyMultibase,
    sign: async ({ data }: { data: Uint8Array }) => {
      const signature = await keySigner.sign({ data })
      return new Uint8Array(
        signature.buffer,
        signature.byteOffset,
        signature.byteLength
      )
    }
  })
}

describe('getFileUrl (library-owned did -> did.jsonl mapping)', () => {
  it('maps a wallet-shaped did:webvh id to its world-readable log URL', () => {
    // The library owns the DID-to-URL mapping; this thin sanity pins the shape
    // a wallet relies on when it links to a published log. localhost keeps
    // http; the port rides the host segment.
    expect(
      getFileUrl(
        `did:webvh:z6MkScidExample:localhost%3A8080:space:${SPACE_ID}:id`
      )
    ).toBe('http://localhost:8080/space/space-abc/id/did.jsonl')
  })

  it('uses https for a non-local host', () => {
    expect(
      getFileUrl(`did:webvh:z6MkScidExample:example.com:space:${SPACE_ID}:id`)
    ).toBe('https://example.com/space/space-abc/id/did.jsonl')
  })
})

describe('didWebvhControllerTemplate', () => {
  it('percent-encodes a host with a port and keeps the {SCID} placeholder', () => {
    expect(
      didWebvhControllerTemplate({ wasServerUrl: WAS_URL, spaceId: SPACE_ID })
    ).toBe('did:webvh:{SCID}:localhost%3A8080:space:space-abc:id')
  })

  it('leaves a plain host unencoded', () => {
    expect(
      didWebvhControllerTemplate({
        wasServerUrl: 'https://example.com',
        spaceId: SPACE_ID
      })
    ).toBe('did:webvh:{SCID}:example.com:space:space-abc:id')
  })
})

describe('client-held update keys', () => {
  it('mints two distinct 32-byte seeds and no pending seed', async () => {
    const minted = await mintClientWebvhUpdateKeys()
    expect(minted.updateSeed).toHaveLength(32)
    expect(minted.stagedSeed).toHaveLength(32)
    expect(minted.updateSeed).not.toEqual(minted.stagedSeed)
    expect(minted.pendingStagedSeed).toBeUndefined()
  })

  it('derives a stable Ed25519 multibase from a seed', async () => {
    const publicKeyMultibase = await updateKeyMultibase({ seed: fixedSeed(9) })
    expect(publicKeyMultibase.startsWith('z6Mk')).toBe(true)
    expect(await updateKeyMultibase({ seed: fixedSeed(9) })).toBe(
      publicKeyMultibase
    )
    expect(await updateKeyMultibase({ seed: fixedSeed(8) })).not.toBe(
      publicKeyMultibase
    )
  })
})

/**
 * An in-memory keystore fake serving only the List Keys projection the
 * `repairKeyBindings` path matches did:web bindings through. Update keys are
 * client-held now, so the fake mints nothing.
 */
class KmsFake {
  listed: Array<{
    id: string
    keyUrl: string
    publicKeyMultibase?: string
    type: string
  }> = []

  /**
   * Every key's public description plus `keyUrl`, the canonical invocation URL
   * the repair path matches bindings through.
   */
  async listKeys() {
    return this.listed
  }
}

/**
 * A `WebvhIdStore` fake: records writes, serves the
 * in-memory `did.jsonl` back (as a real published log would), and reports
 * missing resources as `undefined`.
 */
function webvhFakes({
  webvh,
  logText,
  didDoc,
  kms = new KmsFake()
}: {
  webvh?: DidWebKeyMapV2['webvh']
  logText?: string
  didDoc?: object
  kms?: KmsFake
} = {}) {
  const puts: Array<{
    resourceId: string
    contentType?: string
    content: unknown
  }> = []
  let currentLog = logText
  let currentDidDoc = didDoc

  const didWebKeys: DidWebKeyMapV2 = {
    ...keyMap(),
    ...(webvh ? { webvh } : {})
  }
  // The mutable keys.json the store serves back through getKeyMap -- the key
  // map lives in the `key-map` collection.
  let currentKeys: DidWebKeyMapV2 = didWebKeys

  const idStore = {
    async getKeyMap() {
      return currentKeys
    },
    async putKeyMap({ content }: { content: object }) {
      // The key map is the `key-map` collection's single `keys.json` resource;
      // record it under DID_KEYS_RESOURCE so write-ordering assertions read
      // naturally.
      puts.push({
        resourceId: DID_KEYS_RESOURCE,
        contentType: undefined,
        content
      })
      currentKeys = content as DidWebKeyMapV2
    },
    async getIdResource({ resourceId }: { resourceId: string }) {
      return resourceId === DID_DOCUMENT_RESOURCE ? currentDidDoc : undefined
    },
    async getIdResourceRaw({ resourceId }: { resourceId: string }) {
      return resourceId === DID_LOG_RESOURCE ? currentLog : undefined
    },
    async putIdResource({
      resourceId,
      content,
      contentType
    }: {
      resourceId: string
      content: object | string
      contentType?: string
    }) {
      puts.push({ resourceId, contentType, content })
      if (resourceId === DID_LOG_RESOURCE && typeof content === 'string') {
        currentLog = content
      }
      if (resourceId === DID_DOCUMENT_RESOURCE && typeof content === 'object') {
        currentDidDoc = content
      }
    },
    storageServerUrl: WAS_URL,
    spaceId: SPACE_ID
  } as unknown as WebvhIdStore

  return {
    idStore,
    keystoreAgent: kms as unknown as KeystoreAgent,
    kms,
    didWebKeys,
    puts,
    log: () => currentLog,
    keys: () => currentKeys,
    didDoc: () => currentDidDoc
  }
}

/**
 * Seeds a KmsFake's List Keys projection with the three did:web keys from
 * {@link keyMap}, so the repair path can match `did.json`'s verification
 * methods back to their kmsKeyIds.
 */
function listKmsKeys(kms: KmsFake): void {
  for (const key of Object.values(keyMap())) {
    kms.listed.push({
      id: key.vmId,
      keyUrl: key.kmsKeyId,
      publicKeyMultibase: key.vmId.slice(key.vmId.lastIndexOf('#') + 1),
      type: 'Ed25519VerificationKey2020'
    })
  }
}

/**
 * Provisions a Space from the fixed seeds and returns the fakes plus the
 * published did, so a test can start from a real, verifiable steady state.
 */
async function seedPublishedLog(updateKeys = fixedUpdateKeys()) {
  const fakes = webvhFakes()
  const { did } = await ensureDidWebvh({
    idStore: fakes.idStore,
    wasServerUrl: WAS_URL,
    spaceId: SPACE_ID,
    didWebKeys: fakes.didWebKeys,
    clientKeys: CLIENT_KEYS,
    updateKeys
  })
  return { fakes, did }
}

describe('ensureDidWebvh', () => {
  it('fresh (no log): creates, publishes, and records the did in keys.json', async () => {
    const fakes = webvhFakes()
    const updateKeys = fixedUpdateKeys()
    const { did } = await ensureDidWebvh({
      idStore: fakes.idStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: fakes.didWebKeys,
      clientKeys: CLIENT_KEYS,
      updateKeys
    })

    expect(did.startsWith('did:webvh:')).toBe(true)
    // Publish order: did.jsonl -> did.json -> keys.json (the did is recorded
    // only once the log it names is public).
    expect(fakes.puts.map(put => put.resourceId)).toEqual([
      DID_LOG_RESOURCE,
      DID_DOCUMENT_RESOURCE,
      DID_KEYS_RESOURCE
    ])
    expect(fakes.puts[0]!.contentType).toBe('text/jsonl')

    // keys.json carries the narrowed block: the did and nothing else (the
    // update keys are client-held seeds and never reach a Space resource).
    const written = fakes.puts[2]!.content as DidWebKeyMapV2
    expect(written.webvh).toEqual({ did })
    expect(written.authentication).toEqual(keyMap().authentication)

    // The log's authority is the client-held update key. nextKeyHashes
    // commits BOTH the active key (the carry-over commitment that lets a
    // later non-rotating entry -- an enrollment commit -- re-state it) and
    // the staged prerotation key.
    const resolved = await resolveDIDFromLog(readLogFromString(fakes.log()!), {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.meta.error).toBeUndefined()
    expect(resolved.did).toBe(did)
    expect(resolved.meta.updateKeys).toEqual([
      await updateKeyMultibase({ seed: updateKeys.updateSeed })
    ])
    expect(resolved.meta.nextKeyHashes).toEqual([
      await deriveNextKeyHash(
        await updateKeyMultibase({ seed: updateKeys.updateSeed })
      ),
      await deriveNextKeyHash(
        await updateKeyMultibase({ seed: updateKeys.stagedSeed })
      )
    ])
  })

  it('publishes the enrolled client as the document roster (and no KMS keyAgreement key)', async () => {
    const { fakes, did } = await seedPublishedLog()
    const resolved = await resolveDIDFromLog(readLogFromString(fakes.log()!))
    const doc = resolved.doc as DIDDoc
    const vmId = (multibase: string) => `${did}#${multibase}`
    const signingVm = vmId(CLIENT_KEYS.signingKeyMultibase)
    const agreementVm = vmId(CLIENT_KEYS.keyAgreementKeyMultibase)

    // The client's Ed25519 key is published under all four Ed25519
    // relationships; its X25519 twin is the sole keyAgreement entry.
    expect(doc.authentication).toContain(signingVm)
    expect(doc.assertionMethod).toContain(signingVm)
    expect(doc.capabilityInvocation).toEqual([signingVm])
    expect(doc.capabilityDelegation).toEqual([signingVm])
    expect(doc.keyAgreement).toEqual([agreementVm])

    // The KMS authentication/assertionMethod keys stay as server-side
    // conveniences.
    expect(doc.authentication).toContain(vmId('z6MkAuth'))
    expect(doc.assertionMethod).toContain(vmId('z6MkAssert'))

    // Both client verification methods are Multikey entries controlled by the
    // did:webvh id, with the multibase itself as the fragment.
    const methods = doc.verificationMethod ?? []
    for (const multibase of [
      CLIENT_KEYS.signingKeyMultibase,
      CLIENT_KEYS.keyAgreementKeyMultibase
    ]) {
      const method = methods.find(entry => entry.id === vmId(multibase))
      expect(method).toBeTruthy()
      expect(method?.type).toBe('Multikey')
      expect(method?.controller).toBe(did)
      expect(method?.publicKeyMultibase).toBe(multibase)
    }

    // No server-held key may be a wrap target: the KMS keyAgreement key
    // appears nowhere in the document.
    expect(JSON.stringify(doc)).not.toContain('z6LSAgree')

    // The did:web projection published as did.json mirrors all of it.
    const webDoc = fakes.didDoc() as DIDDoc
    expect(webDoc.id?.startsWith('did:web:')).toBe(true)
    expect(webDoc.alsoKnownAs).toContain(did)
    expect(
      webDoc.verificationMethod?.some(
        method =>
          method.publicKeyMultibase === CLIENT_KEYS.keyAgreementKeyMultibase
      )
    ).toBe(true)
    expect(JSON.stringify(webDoc)).not.toContain('z6LSAgree')
  })

  it('steady state (did recorded, log published): publishes nothing', async () => {
    const { fakes, did } = await seedPublishedLog()
    const steady = webvhFakes({ webvh: { did }, logText: fakes.log() })

    const result = await ensureDidWebvh({
      idStore: steady.idStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: steady.didWebKeys,
      clientKeys: CLIENT_KEYS,
      updateKeys: fixedUpdateKeys()
    })

    expect(result.did).toBe(did)
    expect(steady.puts).toEqual([])
  })

  it('adopts an already-published log (keys.json lost): records the did, creates nothing', async () => {
    const { fakes, did } = await seedPublishedLog()
    // A fresh store holding only the published log, given the same seeds.
    const adopting = webvhFakes({ logText: fakes.log() })

    const result = await ensureDidWebvh({
      idStore: adopting.idStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: adopting.didWebKeys,
      clientKeys: CLIENT_KEYS,
      updateKeys: fixedUpdateKeys()
    })

    expect(result.did).toBe(did)
    expect(adopting.puts.map(put => put.resourceId)).toEqual([
      DID_KEYS_RESOURCE
    ])
    expect((adopting.keys() as DidWebKeyMapV2).webvh).toEqual({ did })
  })

  it('adopts a log whose updateKeys sit at the staged key (rotation in flight)', async () => {
    const { fakes, did } = await seedPublishedLog()
    // Rotate so the log advances to the staged key, then present the ORIGINAL
    // seeds: the staged role still matches, so adoption succeeds.
    await rotateWebvhUpdateKey({
      idStore: fakes.idStore,
      updateKeys: fixedUpdateKeys(),
      persistUpdateKeys: async () => {}
    })
    const adopting = webvhFakes({ logText: fakes.log() })

    const result = await ensureDidWebvh({
      idStore: adopting.idStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: adopting.didWebKeys,
      clientKeys: CLIENT_KEYS,
      updateKeys: fixedUpdateKeys()
    })
    expect(result.did).toBe(did)
  })

  it('throws when the published log authorizes none of this client’s seeds', async () => {
    const { fakes } = await seedPublishedLog()
    const lost = webvhFakes({ logText: fakes.log() })

    await expect(
      ensureDidWebvh({
        idStore: lost.idStore,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        didWebKeys: lost.didWebKeys,
        clientKeys: CLIENT_KEYS,
        updateKeys: { updateSeed: fixedSeed(200), stagedSeed: fixedSeed(201) }
      })
    ).rejects.toThrow(/authorizes none of this client's update keys/)
    expect(lost.puts).toEqual([])
  })
})

describe('rotateWebvhUpdateKey', () => {
  it('reveal dance: the staged key becomes active, a fresh next key is committed, the document is preserved', async () => {
    const { fakes, did } = await seedPublishedLog()
    const before = await resolveDIDFromLog(readLogFromString(fakes.log()!))
    const persisted: ClientWebvhUpdateKeys[] = []

    const rotated = await rotateWebvhUpdateKey({
      idStore: fakes.idStore,
      updateKeys: fixedUpdateKeys(),
      persistUpdateKeys: async next => {
        persisted.push(next)
      }
    })

    expect(rotated.did).toBe(did)
    const after = await resolveDIDFromLog(readLogFromString(fakes.log()!), {
      verifier: defaultWebvhLogVerifier
    })
    expect(after.meta.error).toBeUndefined()
    expect(after.meta.updateKeys).toEqual([
      await updateKeyMultibase({ seed: fixedSeed(2) })
    ])

    // Seeds roll forward: staged becomes active, the freshly minted seed is
    // staged, and the pending role is cleared.
    expect(persisted).toHaveLength(2)
    const [anchored, finalized] = persisted as ClientWebvhUpdateKeys[]
    expect(anchored!.pendingStagedSeed).toBeTruthy()
    expect(finalized!.updateSeed).toEqual(fixedSeed(2))
    expect(finalized!.stagedSeed).toEqual(anchored!.pendingStagedSeed)
    expect(finalized!.pendingStagedSeed).toBeUndefined()

    // The new nextKeyHashes drops the retired key's hash and commits the now
    // active key (the carry-over commitment) plus the newly staged seed.
    expect(after.meta.nextKeyHashes).toEqual([
      await deriveNextKeyHash(await updateKeyMultibase({ seed: fixedSeed(2) })),
      await deriveNextKeyHash(
        await updateKeyMultibase({ seed: finalized!.stagedSeed })
      )
    ])

    // A key-only rotation leaves the document's verification methods intact.
    expect(after.doc?.verificationMethod).toEqual(
      before.doc?.verificationMethod
    )
    expect(after.doc?.verificationMethod).toBeTruthy()

    // keys.json is untouched by the rotation (only the provisioning run that
    // seeded this Space wrote it): the update keys never leave the client.
    expect(fakes.puts.map(put => put.resourceId)).toEqual([
      DID_LOG_RESOURCE,
      DID_DOCUMENT_RESOURCE,
      DID_KEYS_RESOURCE,
      DID_LOG_RESOURCE,
      DID_DOCUMENT_RESOURCE
    ])
  })

  it('persists the pending seed BEFORE the extended log is published', async () => {
    const { fakes } = await seedPublishedLog()
    const logAtCreate = fakes.log()
    let logWhenPendingPersisted: string | undefined
    let logWhenFinalized: string | undefined

    await rotateWebvhUpdateKey({
      idStore: fakes.idStore,
      updateKeys: fixedUpdateKeys(),
      persistUpdateKeys: async next => {
        if (next.pendingStagedSeed) {
          logWhenPendingPersisted = fakes.log()
        } else {
          logWhenFinalized = fakes.log()
        }
      }
    })

    // The store still holds the pre-rotation log when the pending seed is
    // durably persisted -- no published entry ever depends on a seed that is
    // not yet durable.
    expect(logWhenPendingPersisted).toBe(logAtCreate)
    expect(logWhenFinalized).not.toBe(logAtCreate)
  })

  it('crash recovery (log advanced, seeds not rolled forward): finalizes locally, no new entry', async () => {
    const { fakes, did } = await seedPublishedLog()
    // Run a rotation, capturing the mid-ceremony (anchored) seed state, then
    // replay from it -- exactly what a crash between publish and finalize
    // leaves behind.
    let anchored: ClientWebvhUpdateKeys | undefined
    await rotateWebvhUpdateKey({
      idStore: fakes.idStore,
      updateKeys: fixedUpdateKeys(),
      persistUpdateKeys: async next => {
        if (next.pendingStagedSeed) {
          anchored = next
        }
      }
    })
    const advancedLog = fakes.log()
    const putsBefore = fakes.puts.length
    const persisted: ClientWebvhUpdateKeys[] = []

    const recovered = await rotateWebvhUpdateKey({
      idStore: fakes.idStore,
      updateKeys: anchored!,
      persistUpdateKeys: async next => {
        persisted.push(next)
      }
    })

    expect(recovered.did).toBe(did)
    // No new log entry: the roles are finalized locally.
    expect(fakes.log()).toBe(advancedLog)
    expect(fakes.puts).toHaveLength(putsBefore)
    expect(persisted).toEqual([
      {
        updateSeed: anchored!.stagedSeed,
        stagedSeed: anchored!.pendingStagedSeed
      }
    ])
  })

  it('throws on a diverged log (another client rotated it away)', async () => {
    const { fakes } = await seedPublishedLog()
    const putsBefore = fakes.puts.length

    await expect(
      rotateWebvhUpdateKey({
        idStore: fakes.idStore,
        updateKeys: { updateSeed: fixedSeed(200), stagedSeed: fixedSeed(201) },
        persistUpdateKeys: async () => {}
      })
    ).rejects.toThrow(/diverged/)
    // Nothing minted, nothing written.
    expect(fakes.puts).toHaveLength(putsBefore)
  })

  it('throws on a diverged STAGED key before writing anything durable', async () => {
    const { fakes } = await seedPublishedLog()
    const putsBefore = fakes.puts.length
    const persisted: ClientWebvhUpdateKeys[] = []

    // The active key still stands, but this client's staged key is not the
    // one the log committed as its next key -- the reveal could never verify.
    await expect(
      rotateWebvhUpdateKey({
        idStore: fakes.idStore,
        updateKeys: { updateSeed: fixedSeed(1), stagedSeed: fixedSeed(202) },
        persistUpdateKeys: async next => {
          persisted.push(next)
        }
      })
    ).rejects.toThrow(/staged key is not the log-committed next key/)
    // Refused before any durable write: no persisted seeds, no published log.
    expect(persisted).toEqual([])
    expect(fakes.puts).toHaveLength(putsBefore)
  })

  it('throws when there is no published log to rotate', async () => {
    const fakes = webvhFakes()
    await expect(
      rotateWebvhUpdateKey({
        idStore: fakes.idStore,
        updateKeys: fixedUpdateKeys(),
        persistUpdateKeys: async () => {}
      })
    ).rejects.toThrow(/did\.jsonl is missing/)
  })
})

/**
 * The second client's held seeds and the public halves a connect code would
 * carry -- real seeds, so the tests can later rotate AS the enrolled client.
 */
function secondClientUpdateKeys(): ClientWebvhUpdateKeys {
  return { updateSeed: fixedSeed(11), stagedSeed: fixedSeed(12) }
}

async function secondClientKeys(): Promise<WebvhEnrollmentKeys> {
  const held = secondClientUpdateKeys()
  return {
    signingKeyMultibase: 'z6MkSecondClientSigningKeyFixt',
    keyAgreementKeyMultibase: 'z6LSSecondClientAgreementFixt',
    updateKeyMultibase: await updateKeyMultibase({ seed: held.updateSeed }),
    stagedUpdateKeyMultibase: await updateKeyMultibase({
      seed: held.stagedSeed
    })
  }
}

describe('enrollWebvhClient (the two-entry enrollment ceremony)', () => {
  it('appends a verifying commit + add pair: VMs under the right relations, the update key authorized', async () => {
    const { fakes, did } = await seedPublishedLog()
    const newClient = await secondClientKeys()

    const enrolled = await enrollWebvhClient({
      idStore: fakes.idStore,
      updateKeys: fixedUpdateKeys(),
      newClient
    })
    expect(enrolled.did).toBe(did)

    const log = readLogFromString(fakes.log()!)
    expect(log).toHaveLength(3)
    const resolved = await resolveDIDFromLog(log, {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.meta.error).toBeUndefined()
    expect(resolved.did).toBe(did)

    // Both clients' update keys are authorized, and both clients' staged keys
    // (plus the actives' carry-over commitments) stand in nextKeyHashes.
    expect(resolved.meta.updateKeys).toEqual([
      await updateKeyMultibase({ seed: fixedSeed(1) }),
      newClient.updateKeyMultibase
    ])
    expect(resolved.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(newClient.stagedUpdateKeyMultibase)
    )

    // The new client's Ed25519 key joins all four signing relationships; its
    // X25519 twin joins keyAgreement. The first client's VMs are preserved.
    const doc = resolved.doc as DIDDoc
    const vmId = (multibase: string) => `${did}#${multibase}`
    const signingVm = vmId(newClient.signingKeyMultibase)
    const agreementVm = vmId(newClient.keyAgreementKeyMultibase)
    expect(doc.authentication).toContain(signingVm)
    expect(doc.assertionMethod).toContain(signingVm)
    expect(doc.capabilityInvocation).toEqual([
      vmId(CLIENT_KEYS.signingKeyMultibase),
      signingVm
    ])
    expect(doc.capabilityDelegation).toEqual([
      vmId(CLIENT_KEYS.signingKeyMultibase),
      signingVm
    ])
    expect(doc.keyAgreement).toEqual([
      vmId(CLIENT_KEYS.keyAgreementKeyMultibase),
      agreementVm
    ])
    expect(doc.verificationMethod?.map(method => method.id)).toEqual(
      expect.arrayContaining([signingVm, agreementVm])
    )
  })

  it('is idempotent: re-enrolling the same client extends nothing', async () => {
    const { fakes } = await seedPublishedLog()
    const newClient = await secondClientKeys()
    await enrollWebvhClient({
      idStore: fakes.idStore,
      updateKeys: fixedUpdateKeys(),
      newClient
    })
    const settled = fakes.log()

    await enrollWebvhClient({
      idStore: fakes.idStore,
      updateKeys: fixedUpdateKeys(),
      newClient
    })
    expect(fakes.log()).toBe(settled)
  })

  it('a tear between the two entries resumes from the published commit', async () => {
    const { fakes, did } = await seedPublishedLog()
    const newClient = await secondClientKeys()

    // Fault injection: the add entry's log write (the second did.jsonl put of
    // the ceremony) fails once, leaving the commit entry published alone.
    const store = fakes.idStore as unknown as {
      putIdResource: (options: {
        resourceId: string
        content: object | string
        contentType?: string
      }) => Promise<void>
    }
    const originalPut = store.putIdResource.bind(store)
    let logWrites = 0
    store.putIdResource = async options => {
      if (options.resourceId === DID_LOG_RESOURCE) {
        logWrites++
        if (logWrites === 2) {
          throw new Error('injected: connection lost mid-ceremony')
        }
      }
      return originalPut(options)
    }

    await expect(
      enrollWebvhClient({
        idStore: fakes.idStore,
        updateKeys: fixedUpdateKeys(),
        newClient
      })
    ).rejects.toThrow('injected')

    // The torn state: the commit entry published, the add entry did not.
    expect(readLogFromString(fakes.log()!)).toHaveLength(2)

    // Re-running the ceremony converges without forking the log: the commit
    // is detected from the standing nextKeyHashes and only the add entry is
    // appended.
    store.putIdResource = originalPut
    const enrolled = await enrollWebvhClient({
      idStore: fakes.idStore,
      updateKeys: fixedUpdateKeys(),
      newClient
    })
    expect(enrolled.did).toBe(did)
    const resolved = await resolveDIDFromLog(readLogFromString(fakes.log()!), {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.meta.error).toBeUndefined()
    expect(readLogFromString(fakes.log()!)).toHaveLength(3)
    expect(resolved.meta.updateKeys).toContain(newClient.updateKeyMultibase)
  })

  it('either client can rotate afterwards without de-authorizing the other', async () => {
    const { fakes, did } = await seedPublishedLog()
    const newClient = await secondClientKeys()
    await enrollWebvhClient({
      idStore: fakes.idStore,
      updateKeys: fixedUpdateKeys(),
      newClient
    })

    // The enrolling client rotates: its staged key activates, the second
    // client's update key must survive.
    const firstRotated = await rotateWebvhUpdateKey({
      idStore: fakes.idStore,
      updateKeys: fixedUpdateKeys(),
      persistUpdateKeys: async () => {}
    })
    expect(firstRotated.did).toBe(did)
    let resolved = await resolveDIDFromLog(readLogFromString(fakes.log()!), {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.meta.error).toBeUndefined()
    expect(resolved.meta.updateKeys).toEqual([
      newClient.updateKeyMultibase,
      await updateKeyMultibase({ seed: fixedSeed(2) })
    ])

    // The enrolled client rotates with its own held seeds: the first
    // client's (now rotated) key survives in turn.
    await rotateWebvhUpdateKey({
      idStore: fakes.idStore,
      updateKeys: secondClientUpdateKeys(),
      persistUpdateKeys: async () => {}
    })
    resolved = await resolveDIDFromLog(readLogFromString(fakes.log()!), {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.meta.error).toBeUndefined()
    expect(resolved.meta.updateKeys).toEqual([
      await updateKeyMultibase({ seed: fixedSeed(2) }),
      await updateKeyMultibase({ seed: fixedSeed(12) })
    ])
  })

  it('refuses a log minted before the carry-over commitment convention', async () => {
    // A legacy genesis: nextKeyHashes commits ONLY the staged key, so a
    // non-rotating entry could never re-state the active updateKeys.
    const updateKeys = fixedUpdateKeys()
    const signer = await seedSigner(updateKeys.updateSeed)
    const controllerTemplate = didWebvhControllerTemplate({
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID
    })
    const legacy = await createDID({
      address: 'localhost%3A8080',
      paths: ['space', SPACE_ID, 'id'],
      signer,
      updateKeys: [await updateKeyMultibase({ seed: updateKeys.updateSeed })],
      nextKeyHashes: [
        await deriveNextKeyHash(
          await updateKeyMultibase({ seed: updateKeys.stagedSeed })
        )
      ],
      verificationMethods: [
        {
          id: `${controllerTemplate}#${CLIENT_KEYS.signingKeyMultibase}`,
          type: 'Multikey',
          controller: controllerTemplate,
          publicKeyMultibase: CLIENT_KEYS.signingKeyMultibase
        }
      ],
      alsoKnownAsWeb: true,
      portable: true
    })
    const fakes = webvhFakes()
    await fakes.idStore.putIdResource({
      resourceId: DID_LOG_RESOURCE,
      content: (await import('@interop/did-method-webvh')).logToJsonlString(
        legacy.log
      ),
      contentType: 'text/jsonl'
    })

    await expect(
      enrollWebvhClient({
        idStore: fakes.idStore,
        updateKeys,
        newClient: await secondClientKeys()
      })
    ).rejects.toThrow('carry-over')
  })
})

describe('repairKeyBindings', () => {
  it('rebinds the three did:web verification methods and records the published did', async () => {
    const { fakes, did } = await seedPublishedLog()
    const kms = new KmsFake()
    listKmsKeys(kms)
    // The did:web document (the KMS relationship map's own projection) plus the
    // published log, with keys.json entirely lost.
    const repairing = webvhFakes({
      didDoc: didWebDocument({ did: DID_WEB, keys: keyMap() }),
      logText: fakes.log(),
      kms
    })

    const repaired = await repairKeyBindings({
      keystoreAgent: repairing.keystoreAgent,
      idStore: repairing.idStore
    })

    expect(repaired.authentication).toEqual(keyMap().authentication)
    expect(repaired.assertionMethod).toEqual(keyMap().assertionMethod)
    expect(repaired.keyAgreement).toEqual(keyMap().keyAgreement)
    // The narrowed webvh block: the did recovered from the published log.
    expect(repaired.webvh).toEqual({ did })
    // The rebuilt anchor is persisted in one write.
    expect(repairing.puts.map(put => put.resourceId)).toEqual([
      DID_KEYS_RESOURCE
    ])
  })

  it('rebuilds a Space with no log: key map without a webvh block', async () => {
    const kms = new KmsFake()
    listKmsKeys(kms)
    const fakes = webvhFakes({
      didDoc: didWebDocument({ did: DID_WEB, keys: keyMap() }),
      kms
    })
    const repaired = await repairKeyBindings({
      keystoreAgent: fakes.keystoreAgent,
      idStore: fakes.idStore
    })
    expect(repaired.authentication).toEqual(keyMap().authentication)
    expect(repaired.webvh).toBeUndefined()
  })

  it('throws when did.json is not published (nothing to repair from)', async () => {
    const fakes = webvhFakes()
    await expect(
      repairKeyBindings({
        keystoreAgent: fakes.keystoreAgent,
        idStore: fakes.idStore
      })
    ).rejects.toThrow(/did\.json is not published/)
  })

  it('throws when a did.json verification method matches no keystore key', async () => {
    const fakes = webvhFakes({
      didDoc: didWebDocument({ did: DID_WEB, keys: keyMap() })
    })
    await expect(
      repairKeyBindings({
        keystoreAgent: fakes.keystoreAgent,
        idStore: fakes.idStore
      })
    ).rejects.toThrow(/no keystore key matches the authentication/)
  })
})

/**
 * The rotation-ceremony correctness pin: `updateDID` clones the prior entry's
 * document and overlays only supplied directives, so a key-only update
 * (updateKeys + nextKeyHashes, no verificationMethods) must leave the
 * document's verification methods intact -- the caller need NOT re-supply the
 * VMs.
 */
describe('updateDID sparse semantics (rotation pin)', () => {
  it('key-only update preserves the document verification methods', async () => {
    const activeSeed = fixedSeed(11)
    const stagedSeed = fixedSeed(12)
    const newStagedSeed = fixedSeed(13)
    const controllerTemplate = `did:webvh:{SCID}:localhost%3A8080:space:${SPACE_ID}:id`
    const created = await createDID({
      address: 'localhost:8080',
      paths: ['space', SPACE_ID, 'id'],
      signer: await seedSigner(activeSeed),
      updateKeys: [await updateKeyMultibase({ seed: activeSeed })],
      nextKeyHashes: [
        await deriveNextKeyHash(await updateKeyMultibase({ seed: stagedSeed }))
      ],
      verificationMethods: [
        {
          id: `${controllerTemplate}#z6MkAuth`,
          type: 'Multikey',
          controller: controllerTemplate,
          publicKeyMultibase: 'z6MkAuth'
        },
        {
          id: `${controllerTemplate}#z6MkAssert`,
          type: 'Multikey',
          controller: controllerTemplate,
          publicKeyMultibase: 'z6MkAssert'
        }
      ],
      authentication: [`${controllerTemplate}#z6MkAuth`],
      assertionMethod: [`${controllerTemplate}#z6MkAssert`],
      portable: true
    })
    const vmsBefore = created.doc.verificationMethod

    // Key-only rotation: reveal the staged key (it signs its own activation)
    // and commit a fresh next key. No document directives supplied.
    const updated = await updateDID({
      log: created.log,
      signer: await seedSigner(stagedSeed),
      updateKeys: [await updateKeyMultibase({ seed: stagedSeed })],
      nextKeyHashes: [
        await deriveNextKeyHash(
          await updateKeyMultibase({ seed: newStagedSeed })
        )
      ]
    })

    expect(updated.doc.verificationMethod).toEqual(vmsBefore)
    expect(updated.doc.verificationMethod).toHaveLength(2)
    // The log still verifies after the sparse update.
    const resolved = await resolveDIDFromLog(updated.log, {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.meta.error).toBeUndefined()
  })
})
