/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Transient enrollment and the delegated-clients pointer: the client annex
 * rung
 * HKDF label family (disjoint from the account-rung and ladder-VM labels
 * under the one salt), the atomic static-rung-0 enrollment entry (reveal at
 * first write, `nextKeyHashes` restated explicitly on every entry, the
 * transient VM under `capabilityInvocation` and `capabilityDelegation`,
 * same-key CAS retry, the
 * mid-generation lockout refusal), the account document's
 * `#DelegatedClients` service entry (type-IRI dispatch, non-semantic stable
 * fragment, DID-string endpoint), and the enrollee's GC-race closure (the
 * post-append pointer re-read and fresh-generation re-enroll). Plus the
 * caller-threaded head: the first attempt reads nothing, a lost CAS re-reads
 * under the pin and builds on the winner's head with the retry's whole
 * budget still unspent, an expectedDid mismatch is refused, and the GC-race
 * closure rides the head only for the generation the pointer names. Plus the
 * post-publish pin advance.
 */
import { describe, expect, it } from 'vitest'
import {
  defaultWebvhLogVerifier,
  deriveNextKeyHash,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import type { DIDDoc } from '@interop/did-method-webvh'
import {
  clientAnnexRung,
  clientAnnexRungSeed,
  generateLadderSeed,
  ladderRungSeed,
  ladderVmSeed
} from '../../src/clientAnnex/ladder.js'
import {
  commitClientAnnexRung,
  clientAnnexDidParts,
  clientAnnexLogPinId,
  ClientAnnexRungUncommittedError,
  createClientAnnexLog,
  DELEGATED_CLIENTS_SERVICE_TYPE,
  delegatedClientsPointer,
  delegatedClientsServiceEntry,
  enrollClientAnnexTransientClient,
  enrollTransientClient,
  mintGenerationId,
  retireClientAnnexRung,
  setDelegatedClientsPointer
} from '../../src/clientAnnex/log.js'
import type { ClientAnnexWriteStore } from '../../src/clientAnnex/log.js'
import {
  ensureDidWebvh,
  pinOfLog,
  putLogResource,
  readPublishedLog,
  updateKeySigner
} from '../../src/webvh/didWebvh.js'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'
import { PreconditionFailedError } from '@interop/was-client'

const WAS_URL = 'https://storage.example'
const SPACE_ID = 'aux-space-1'

/**
 * A deterministic 32-byte ladder seed, so two derivations agree across
 * helpers.
 */
function fixedSeed(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill)
}

/**
 * A transient visit key: any real Ed25519 public multibase serves (the entry
 * publishes it verbatim; only the SIGNING key is exercised cryptographically).
 */
const TRANSIENT_KEY = CANONICAL_CLIENT_KEYS[3]!.signingKeyMultibase
const SECOND_TRANSIENT_KEY = CANONICAL_CLIENT_KEYS[4]!.signingKeyMultibase

/**
 * Mints and publishes one annex generation into a fresh in-memory store:
 * credential A is the minting writer (its rung-0 key revealed at genesis),
 * credential B stands committed only.
 */
async function clientAnnexFixture() {
  const ladderSeedA = fixedSeed(11)
  const ladderSeedB = fixedSeed(22)
  const generationId = mintGenerationId()
  const rungA = await clientAnnexRung({ ladderSeed: ladderSeedA, generationId })
  const rungB = await clientAnnexRung({ ladderSeed: ladderSeedB, generationId })
  const hashA = await deriveNextKeyHash(rungA.keyMultibase)
  const hashB = await deriveNextKeyHash(rungB.keyMultibase)
  const created = await createClientAnnexLog({
    wasServerUrl: WAS_URL,
    spaceId: SPACE_ID,
    generationId,
    updateKeyPublicKeyMultibase: rungA.keyMultibase,
    nextKeyHashes: [hashA, hashB],
    signer: await updateKeySigner({ seed: rungA.seed })
  })
  const fixture = memoryIdStore()
  await putLogResource({
    store: fixture.idStore,
    log: created.log,
    ifNoneMatch: true
  })
  return {
    ladderSeedA,
    ladderSeedB,
    generationId,
    rungA,
    rungB,
    hashA,
    hashB,
    did: created.did,
    fixture
  }
}

/**
 * The published annex log's entries, parsed off the store.
 */
function logEntries(fixture: ReturnType<typeof memoryIdStore>) {
  const text = fixture.log()
  if (text === undefined) {
    throw new Error('no log published')
  }
  return text
    .trim()
    .split('\n')
    .map(
      line =>
        JSON.parse(line) as {
          parameters: { updateKeys?: string[]; nextKeyHashes?: string[] }
          state: DIDDoc
        }
    )
}

describe('client annex rung derivation', () => {
  it(
    'derives under the generation-id-prefixed info label, disjoint from the ' +
      'account-rung and ladder-VM families',
    async () => {
      const ladderSeed = generateLadderSeed()
      const generationId = mintGenerationId()
      const seed = clientAnnexRungSeed({ ladderSeed, generationId })
      expect(seed).toHaveLength(32)
      // Deterministic, and distinct per generation id.
      expect(clientAnnexRungSeed({ ladderSeed, generationId })).toEqual(seed)
      expect(
        clientAnnexRungSeed({ ladderSeed, generationId: mintGenerationId() })
      ).not.toEqual(seed)
      // Disjoint from `rung/<n>` and `vm` under the same salt and seed.
      expect(seed).not.toEqual(ladderRungSeed({ ladderSeed, index: 0 }))
      expect(seed).not.toEqual(ladderVmSeed({ ladderSeed }))
      const rung = await clientAnnexRung({ ladderSeed, generationId })
      expect(rung.seed).toEqual(seed)
      expect(rung.keyMultibase).toMatch(/^z/)
    }
  )
})

describe('enrollClientAnnexTransientClient', () => {
  it(
    'publishes one atomic entry: VM under capabilityInvocation and ' +
      'capabilityDelegation, updateKeys re-stated, nextKeyHashes re-stated ' +
      'verbatim',
    async () => {
      const { ladderSeedA, generationId, rungA, hashA, hashB, did, fixture } =
        await clientAnnexFixture()
      const enrolled = await enrollClientAnnexTransientClient({
        store: fixture.idStore,
        ladderSeed: ladderSeedA,
        generationId,
        transientKeyMultibase: TRANSIENT_KEY,
        expectedDid: did
      })
      expect(enrolled.did).toBe(did)
      const entries = logEntries(fixture)
      expect(entries).toHaveLength(2)
      const entry = entries[1]!
      // The minting credential's key was already revealed at genesis: the
      // re-statement carries it once, and nothing else joins.
      expect(entry.parameters.updateKeys).toEqual([rungA.keyMultibase])
      // Restated explicitly on the entry, never inherited (the inheritance
      // trap as a regression).
      expect(entry.parameters.nextKeyHashes).toEqual([hashA, hashB])
      // The transient VM: invocation AND delegation, both stated explicitly
      // (decision 0013 -- the visit invokes the generation delegation and
      // delegates its App Connect and share grants under the same parent).
      // No authentication, no assertionMethod, no keyAgreement twin, no
      // update key of its own.
      const vmId = `${did}#${TRANSIENT_KEY}`
      const doc = entry.state
      expect((doc.verificationMethod ?? []).map(method => method.id)).toEqual([
        vmId
      ])
      expect(doc.capabilityInvocation).toEqual([vmId])
      expect(doc.capabilityDelegation).toEqual([vmId])
      expect(doc.authentication ?? []).toEqual([])
      expect(doc.assertionMethod ?? []).toEqual([])
      expect(doc.keyAgreement ?? []).toEqual([])
      // The whole log still verifies with the real verifier.
      const resolved = await resolveDIDFromLog(enrolled.log, {
        verifier: defaultWebvhLogVerifier
      })
      expect(resolved.meta.error).toBeFalsy()
      expect(resolved.did).toBe(did)
    }
  )

  it(
    "reveals a committed credential's rung-0 key at its first write and " +
      'keeps every standing hash',
    async () => {
      const {
        ladderSeedB,
        generationId,
        rungA,
        rungB,
        hashA,
        hashB,
        did,
        fixture
      } = await clientAnnexFixture()
      await enrollClientAnnexTransientClient({
        store: fixture.idStore,
        ladderSeed: ladderSeedB,
        generationId,
        transientKeyMultibase: TRANSIENT_KEY,
        expectedDid: did
      })
      const entry = logEntries(fixture)[1]!
      expect(entry.parameters.updateKeys).toEqual([
        rungA.keyMultibase,
        rungB.keyMultibase
      ])
      // The revealed key's own hash stays as the carry-over commitment.
      expect(entry.parameters.nextKeyHashes).toEqual([hashA, hashB])
      // A second write by the same credential re-signs with the SAME key --
      // static rung 0 has no advancement.
      await enrollClientAnnexTransientClient({
        store: fixture.idStore,
        ladderSeed: ladderSeedB,
        generationId,
        transientKeyMultibase: SECOND_TRANSIENT_KEY,
        expectedDid: did
      })
      const second = logEntries(fixture)[2]!
      expect(second.parameters.updateKeys).toEqual([
        rungA.keyMultibase,
        rungB.keyMultibase
      ])
      expect(second.parameters.nextKeyHashes).toEqual([hashA, hashB])
    }
  )

  it(
    'refuses a credential whose rung 0 is neither revealed nor committed ' +
      '(the mid-generation lockout)',
    async () => {
      const { generationId, did, fixture } = await clientAnnexFixture()
      await expect(
        enrollClientAnnexTransientClient({
          store: fixture.idStore,
          ladderSeed: fixedSeed(33),
          generationId,
          transientKeyMultibase: TRANSIENT_KEY,
          expectedDid: did
        })
      ).rejects.toThrow(ClientAnnexRungUncommittedError)
    }
  )

  it('is idempotent: a VM already present appends nothing', async () => {
    const { ladderSeedA, generationId, did, fixture } =
      await clientAnnexFixture()
    await enrollClientAnnexTransientClient({
      store: fixture.idStore,
      ladderSeed: ladderSeedA,
      generationId,
      transientKeyMultibase: TRANSIENT_KEY,
      expectedDid: did
    })
    const before = logEntries(fixture).length
    await enrollClientAnnexTransientClient({
      store: fixture.idStore,
      ladderSeed: ladderSeedA,
      generationId,
      transientKeyMultibase: TRANSIENT_KEY,
      expectedDid: did
    })
    expect(logEntries(fixture)).toHaveLength(before)
  })

  it(
    're-signs with the same key through the ordinary conflict retry on a ' +
      'lost CAS race',
    async () => {
      const { ladderSeedA, generationId, did, fixture } =
        await clientAnnexFixture()
      // A store whose first conditional PUT loses the race; the retry re-reads
      // and re-signs with the same rung-0 key.
      let failed = false
      const racingStore: ClientAnnexWriteStore = {
        getIdResourceRaw: options => fixture.idStore.getIdResourceRaw(options),
        putIdResource: async options => {
          if (!failed) {
            failed = true
            throw new PreconditionFailedError('lost the race')
          }
          return fixture.idStore.putIdResource(options)
        }
      }
      await enrollClientAnnexTransientClient({
        store: racingStore,
        ladderSeed: ladderSeedA,
        generationId,
        transientKeyMultibase: TRANSIENT_KEY,
        expectedDid: did
      })
      expect(failed).toBe(true)
      const entries = logEntries(fixture)
      expect(entries).toHaveLength(2)
      expect(
        (entries[1]!.state.verificationMethod ?? []).map(method => method.id)
      ).toEqual([`${did}#${TRANSIENT_KEY}`])
    }
  )
})

describe('the delegated-clients service entry', () => {
  it(
    'builds the typed entry with a stable non-semantic fragment and a ' +
      'DID-string endpoint',
    () => {
      const entry = delegatedClientsServiceEntry({
        accountDid: 'did:webvh:scid:host:space:s:id',
        clientAnnexDid: 'did:webvh:cscid:host:space:aux:gen-AAAAAAAAAAAAAAAA'
      })
      expect(entry).toEqual({
        id: 'did:webvh:scid:host:space:s:id#delegated-clients',
        type: DELEGATED_CLIENTS_SERVICE_TYPE,
        serviceEndpoint: 'did:webvh:cscid:host:space:aux:gen-AAAAAAAAAAAAAAAA'
      })
    }
  )

  it(
    'dispatches on the type IRI, string or array, and only accepts a ' +
      'string endpoint',
    () => {
      const clientAnnexDid = 'did:webvh:c:h:space:aux:gen-AAAAAAAAAAAAAAAA'
      const doc = (service: unknown) =>
        ({ id: 'did:x', service }) as unknown as DIDDoc
      expect(
        delegatedClientsPointer({
          doc: doc([
            { id: '#a', type: 'SomethingElse', serviceEndpoint: 'x' },
            {
              id: '#whatever',
              type: DELEGATED_CLIENTS_SERVICE_TYPE,
              serviceEndpoint: clientAnnexDid
            }
          ])
        })
      ).toBe(clientAnnexDid)
      expect(
        delegatedClientsPointer({
          doc: doc([
            {
              id: '#b',
              type: ['Other', DELEGATED_CLIENTS_SERVICE_TYPE],
              serviceEndpoint: clientAnnexDid
            }
          ])
        })
      ).toBe(clientAnnexDid)
      // A non-string endpoint never counts, and no entry means no pointer.
      expect(
        delegatedClientsPointer({
          doc: doc([
            {
              id: '#c',
              type: DELEGATED_CLIENTS_SERVICE_TYPE,
              serviceEndpoint: { did: clientAnnexDid }
            }
          ])
        })
      ).toBeUndefined()
      expect(
        delegatedClientsPointer({ doc: { id: 'did:x' } as DIDDoc })
      ).toBeUndefined()
    }
  )

  it('parses the host, Space id and generation id out of a client annex DID', async () => {
    const { did, generationId } = await clientAnnexFixture()
    expect(clientAnnexDidParts({ did })).toEqual({
      host: new URL(WAS_URL).host,
      spaceId: SPACE_ID,
      generationId
    })
    expect(() =>
      clientAnnexDidParts({ did: 'did:webvh:scid:host:space:s:id' })
    ).toThrow(/Not a generation id/)
    expect(() => clientAnnexDidParts({ did: 'did:key:z6Mk' })).toThrow(
      /Not a client annex did:webvh/
    )
  })
})

describe('setDelegatedClientsPointer', () => {
  /**
   * A provisioned account log in a fresh in-memory store, enrolled with the
   * canonical first client.
   */
  async function accountFixture() {
    const fixture = memoryIdStore()
    const updateKeys = {
      updateSeed: fixedSeed(1),
      stagedSeed: fixedSeed(2)
    }
    const { did } = await ensureDidWebvh({
      idStore: fixture.idStore,
      wasServerUrl: WAS_URL,
      spaceId: 'account-space-1',
      clientKeys: CANONICAL_CLIENT_KEYS[0]!,
      updateKeys
    })
    return { fixture, updateKeys, did }
  }

  it(
    'installs the entry, preserving the document, and re-points in place ' +
      'keeping the fragment id',
    async () => {
      const { fixture, updateKeys, did } = await accountFixture()
      const clientAnnexA = (await clientAnnexFixture()).did
      const clientAnnexB = (await clientAnnexFixture()).did
      const before = await readPublishedLog({ idStore: fixture.idStore })
      const beforeMethods = (before!.doc.verificationMethod ?? []).length

      await setDelegatedClientsPointer({
        idStore: fixture.idStore,
        updateKeys,
        clientAnnexDid: clientAnnexA,
        expectedDid: did
      })
      let published = await readPublishedLog({ idStore: fixture.idStore })
      expect(delegatedClientsPointer({ doc: published!.doc })).toBe(
        clientAnnexA
      )
      const entry = (published!.doc.service ?? [])[0]!
      expect(entry.id).toBe(`${did}#delegated-clients`)
      expect(entry.type).toBe(DELEGATED_CLIENTS_SERVICE_TYPE)
      // The document's keys and relations rode through untouched.
      expect(published!.doc.verificationMethod ?? []).toHaveLength(
        beforeMethods
      )
      expect(published!.updateKeys).toEqual(before!.updateKeys)
      expect(published!.nextKeyHashes).toEqual(before!.nextKeyHashes)

      // Idempotent: pointing at the same DID appends nothing.
      const entriesBefore = fixture.log()!.trim().split('\n').length
      await setDelegatedClientsPointer({
        idStore: fixture.idStore,
        updateKeys,
        clientAnnexDid: clientAnnexA,
        expectedDid: did
      })
      expect(fixture.log()!.trim().split('\n')).toHaveLength(entriesBefore)

      // The GC re-point replaces the endpoint in place, id preserved.
      await setDelegatedClientsPointer({
        idStore: fixture.idStore,
        updateKeys,
        clientAnnexDid: clientAnnexB,
        expectedDid: did
      })
      published = await readPublishedLog({ idStore: fixture.idStore })
      expect(published!.doc.service ?? []).toHaveLength(1)
      expect(delegatedClientsPointer({ doc: published!.doc })).toBe(
        clientAnnexB
      )
      expect((published!.doc.service ?? [])[0]!.id).toBe(
        `${did}#delegated-clients`
      )
    }
  )

  it('refuses a malformed client annex DID before touching the log', async () => {
    const { fixture, updateKeys, did } = await accountFixture()
    const entriesBefore = fixture.log()!.trim().split('\n').length
    await expect(
      setDelegatedClientsPointer({
        idStore: fixture.idStore,
        updateKeys,
        clientAnnexDid: 'did:web:example.com',
        expectedDid: did
      })
    ).rejects.toThrow(/Not a client annex did:webvh/)
    expect(fixture.log()!.trim().split('\n')).toHaveLength(entriesBefore)
  })
})

describe('enrollTransientClient (the GC-race closure)', () => {
  it(
    're-reads the pointer after its append and re-enrolls into a fresh ' +
      'generation on a mismatch',
    async () => {
      const generationA = await clientAnnexFixture()
      // The racing GC swap's fresh generation, written by the same credential.
      const generationB = await clientAnnexFixture()
      const stores = new Map<string, ClientAnnexWriteStore>([
        [generationA.generationId, generationA.fixture.idStore],
        [generationB.generationId, generationB.fixture.idStore]
      ])
      const pointerDoc = (clientAnnexDid: string) =>
        ({
          id: 'did:webvh:acct:host:space:s:id',
          service: [
            {
              id: '#delegated-clients',
              type: DELEGATED_CLIENTS_SERVICE_TYPE,
              serviceEndpoint: clientAnnexDid
            }
          ]
        }) as unknown as DIDDoc
      // Read 1 points at A; the post-append re-read finds the pointer moved to
      // B (the concurrent GC); the round-2 re-read confirms B stable.
      const reads = [
        pointerDoc(generationA.did),
        pointerDoc(generationB.did),
        pointerDoc(generationB.did),
        pointerDoc(generationB.did)
      ]
      const result = await enrollTransientClient({
        readAccountDocument: async () => {
          const next = reads.shift()
          if (!next) {
            throw new Error('unexpected extra account-document read')
          }
          return next
        },
        storeForGenerationId: generationId => {
          const store = stores.get(generationId)
          if (!store) {
            throw new Error(`unexpected generation id ${generationId}`)
          }
          return store
        },
        ladderSeed: generationA.ladderSeedA,
        transientKeyMultibase: TRANSIENT_KEY
      })
      expect(result.clientAnnexDid).toBe(generationB.did)
      // The enrollment stands in the fresh generation; the abandoned one keeps
      // its (authorization-inert) entry.
      expect(
        (
          logEntries(generationB.fixture)[1]!.state.verificationMethod ?? []
        ).map(method => method.id)
      ).toEqual([`${generationB.did}#${TRANSIENT_KEY}`])
      expect(logEntries(generationA.fixture)).toHaveLength(2)
    }
  )

  it('refuses an account document with no delegated-clients entry', async () => {
    await expect(
      enrollTransientClient({
        readAccountDocument: async () => ({ id: 'did:webvh:acct' }) as DIDDoc,
        storeForGenerationId: () => {
          throw new Error('unreachable')
        },
        ladderSeed: generateLadderSeed(),
        transientKeyMultibase: TRANSIENT_KEY
      })
    ).rejects.toThrow(/no delegated-clients service entry/)
  })
})

describe('retireClientAnnexRung', () => {
  it(
    "strikes the retired credential's revealed key and standing hash in " +
      'one entry signed by a distinct committed rung',
    async () => {
      const {
        ladderSeedA,
        ladderSeedB,
        generationId,
        rungA,
        rungB,
        hashA,
        hashB,
        did,
        fixture
      } = await clientAnnexFixture()
      // Credential A wrote the generation (its rung-0 key stands revealed at
      // genesis); credential B is committed only and acts.
      const { struck } = await retireClientAnnexRung({
        store: fixture.idStore,
        retiredLadderSeed: ladderSeedA,
        actingLadderSeed: ladderSeedB,
        generationId,
        expectedDid: did
      })
      expect(struck).toBe(true)

      const entries = logEntries(fixture)
      expect(entries).toHaveLength(2)
      const entry = entries[1]!
      // A's key is gone and B's revealed in its place; A's standing hash is
      // gone and B's carry-over commitment stands.
      expect(entry.parameters.updateKeys).toEqual([rungB.keyMultibase])
      expect(entry.parameters.updateKeys).not.toContain(rungA.keyMultibase)
      expect(entry.parameters.nextKeyHashes).toEqual([hashB])
      expect(entry.parameters.nextKeyHashes).not.toContain(hashA)

      // The struck log still verifies, and it still resolves to the same
      // annex DID.
      const published = await readPublishedLog({
        idStore: fixture.idStore,
        expectedDid: did
      })
      expect(published!.updateKeys).toEqual([rungB.keyMultibase])
      expect(published!.nextKeyHashes).toEqual([hashB])
    }
  )

  it('no-ops on a log already clean of the retired inventory', async () => {
    const { ladderSeedA, generationId, did, fixture } =
      await clientAnnexFixture()
    const before = fixture.log()
    // Credential C never minted or wrote this generation, so it holds no
    // inventory in it at all.
    const { struck } = await retireClientAnnexRung({
      store: fixture.idStore,
      retiredLadderSeed: fixedSeed(33),
      actingLadderSeed: ladderSeedA,
      generationId,
      expectedDid: did
    })
    expect(struck).toBe(false)
    expect(fixture.log()).toBe(before)
  })

  it('refuses a self-strike: the retired rung cannot sign its own removal', async () => {
    const { ladderSeedA, generationId, did, fixture } =
      await clientAnnexFixture()
    const before = fixture.log()
    await expect(
      retireClientAnnexRung({
        store: fixture.idStore,
        retiredLadderSeed: ladderSeedA,
        actingLadderSeed: ladderSeedA,
        generationId,
        expectedDid: did
      })
    ).rejects.toThrow(ClientAnnexRungUncommittedError)
    expect(fixture.log()).toBe(before)
  })

  it('refuses an acting credential the log commits nowhere', async () => {
    const { ladderSeedA, generationId, did, fixture } =
      await clientAnnexFixture()
    const before = fixture.log()
    await expect(
      retireClientAnnexRung({
        store: fixture.idStore,
        retiredLadderSeed: ladderSeedA,
        // Credential C: bound after genesis, its rung-0 hash committed
        // nowhere -- the swap fallback's trigger.
        actingLadderSeed: fixedSeed(33),
        generationId,
        expectedDid: did
      })
    ).rejects.toThrow(ClientAnnexRungUncommittedError)
    expect(fixture.log()).toBe(before)
  })
})

describe('commitClientAnnexRung', () => {
  it(
    "commits a freshly bound credential's rung-0 hash in one " +
      'hash-restating entry, closing its mid-generation lockout',
    async () => {
      const { ladderSeedA, generationId, rungA, hashA, hashB, did, fixture } =
        await clientAnnexFixture()
      // Credential C: bound after genesis, locked out of this generation.
      const ladderSeedC = fixedSeed(33)
      const rungC = await clientAnnexRung({
        ladderSeed: ladderSeedC,
        generationId
      })
      const hashC = await deriveNextKeyHash(rungC.keyMultibase)
      await expect(
        enrollClientAnnexTransientClient({
          store: fixture.idStore,
          ladderSeed: ladderSeedC,
          generationId,
          transientKeyMultibase: TRANSIENT_KEY,
          expectedDid: did
        })
      ).rejects.toThrow(ClientAnnexRungUncommittedError)

      // The bind ceremony's commit entry, signed by the session's committed
      // login credential (A, revealed at genesis).
      const { committed } = await commitClientAnnexRung({
        store: fixture.idStore,
        boundLadderSeed: ladderSeedC,
        actingLadderSeed: ladderSeedA,
        generationId,
        expectedDid: did
      })
      expect(committed).toBe(true)

      const entries = logEntries(fixture)
      expect(entries).toHaveLength(2)
      const entry = entries[1]!
      // One atomic hash-restating entry: A's revealed key restated, every
      // standing hash restated, C's hash appended.
      expect(entry.parameters.updateKeys).toEqual([rungA.keyMultibase])
      expect(entry.parameters.nextKeyHashes).toEqual([hashA, hashB, hashC])

      // The lockout is closed: C now writes the annex.
      const enrolled = await enrollClientAnnexTransientClient({
        store: fixture.idStore,
        ladderSeed: ladderSeedC,
        generationId,
        transientKeyMultibase: TRANSIENT_KEY,
        expectedDid: did
      })
      expect(enrolled.did).toBe(did)
    }
  )

  it('reveals a committed-but-unrevealed acting rung at its first write', async () => {
    const { ladderSeedB, generationId, rungA, rungB, did, fixture } =
      await clientAnnexFixture()
    // B stands committed only; its commit entry for C is its first annex
    // write, so its rung-0 key reveals here.
    const { committed } = await commitClientAnnexRung({
      store: fixture.idStore,
      boundLadderSeed: fixedSeed(33),
      actingLadderSeed: ladderSeedB,
      generationId,
      expectedDid: did
    })
    expect(committed).toBe(true)
    const entry = logEntries(fixture)[1]!
    expect(entry.parameters.updateKeys).toEqual([
      rungA.keyMultibase,
      rungB.keyMultibase
    ])
  })

  it('no-ops when the bound rung already stands committed', async () => {
    const { ladderSeedA, ladderSeedB, generationId, did, fixture } =
      await clientAnnexFixture()
    const before = fixture.log()
    // B's hash stands committed since genesis.
    const { committed } = await commitClientAnnexRung({
      store: fixture.idStore,
      boundLadderSeed: ladderSeedB,
      actingLadderSeed: ladderSeedA,
      generationId,
      expectedDid: did
    })
    expect(committed).toBe(false)
    expect(fixture.log()).toBe(before)
  })

  it('converges on a re-run: the second commit is a no-op', async () => {
    const { ladderSeedA, generationId, did, fixture } =
      await clientAnnexFixture()
    const options = {
      store: fixture.idStore,
      boundLadderSeed: fixedSeed(33),
      actingLadderSeed: ladderSeedA,
      generationId,
      expectedDid: did
    }
    expect((await commitClientAnnexRung(options)).committed).toBe(true)
    const after = fixture.log()
    expect((await commitClientAnnexRung(options)).committed).toBe(false)
    expect(fixture.log()).toBe(after)
  })

  it('refuses an acting credential the log commits nowhere', async () => {
    const { generationId, did, fixture } = await clientAnnexFixture()
    const before = fixture.log()
    await expect(
      commitClientAnnexRung({
        store: fixture.idStore,
        boundLadderSeed: fixedSeed(33),
        // Credential D: itself uncommitted, so it cannot sign the commit --
        // the bind ceremony maps this to an honest skip.
        actingLadderSeed: fixedSeed(44),
        generationId,
        expectedDid: did
      })
    ).rejects.toThrow(ClientAnnexRungUncommittedError)
    expect(fixture.log()).toBe(before)
  })
})

describe("the enrollment's threaded head", () => {
  /**
   * A store wrapping the fixture's, counting the log reads that reach it.
   *
   * @param store {ClientAnnexWriteStore}
   * @returns {object}   the wrapping `store` and its `reads` counter
   */
  function countingStore(store: ClientAnnexWriteStore): {
    store: ClientAnnexWriteStore
    reads: () => number
  } {
    let reads = 0
    return {
      store: {
        getIdResourceRaw: options => {
          reads++
          return store.getIdResourceRaw(options)
        },
        putIdResource: options => store.putIdResource(options)
      },
      reads: () => reads
    }
  }

  it('builds the entry on the head handed in, reading nothing', async () => {
    const { ladderSeedA, generationId, did, fixture } =
      await clientAnnexFixture()
    const head = await readPublishedLog({
      idStore: fixture.idStore,
      expectedDid: did
    })
    const counted = countingStore(fixture.idStore)

    await enrollClientAnnexTransientClient({
      store: counted.store,
      ladderSeed: ladderSeedA,
      generationId,
      transientKeyMultibase: TRANSIENT_KEY,
      expectedDid: did,
      ...(head !== undefined ? { published: head } : {})
    })

    expect(counted.reads()).toBe(0)
    const entries = logEntries(fixture)
    expect(entries).toHaveLength(2)
    expect(
      (entries[1]!.state.verificationMethod ?? []).map(method => method.id)
    ).toEqual([`${did}#${TRANSIENT_KEY}`])
  })

  it(
    'a lost CAS on the threaded head re-reads under the pin and lands on ' +
      "the winner's head",
    async () => {
      const { ladderSeedA, generationId, did, fixture } =
        await clientAnnexFixture()
      const head = await readPublishedLog({
        idStore: fixture.idStore,
        expectedDid: did
      })
      const pinStore = memoryResourceLogPinStore()
      const logId = clientAnnexLogPinId({ spaceId: SPACE_ID, generationId })

      // The first PUT loses the race to a concurrent visit, which lands its
      // own entry; the head threaded in is stale from that moment.
      let reads = 0
      let raced = false
      const racingStore: ClientAnnexWriteStore = {
        getIdResourceRaw: options => {
          reads++
          return fixture.idStore.getIdResourceRaw(options)
        },
        putIdResource: async options => {
          if (!raced) {
            raced = true
            await enrollClientAnnexTransientClient({
              store: fixture.idStore,
              ladderSeed: ladderSeedA,
              generationId,
              transientKeyMultibase: SECOND_TRANSIENT_KEY,
              expectedDid: did
            })
            throw new PreconditionFailedError('lost the race')
          }
          return fixture.idStore.putIdResource(options)
        }
      }

      await enrollClientAnnexTransientClient({
        store: racingStore,
        ladderSeed: ladderSeedA,
        generationId,
        transientKeyMultibase: TRANSIENT_KEY,
        expectedDid: did,
        pinStore,
        logId,
        ...(head !== undefined ? { published: head } : {})
      })

      expect(raced).toBe(true)
      // Exactly one read: none on the first attempt, one on the retry.
      expect(reads).toBe(1)
      const entries = logEntries(fixture)
      expect(entries).toHaveLength(3)
      // Both visits stand: the retry built on the winner's head rather than
      // republishing the threaded prefix.
      expect(
        (entries[2]!.state.verificationMethod ?? []).map(method => method.id)
      ).toEqual([`${did}#${SECOND_TRANSIENT_KEY}`, `${did}#${TRANSIENT_KEY}`])
      // The retry read the winner's head, built on it, and advanced the pin
      // past its own entry -- never back to the prefix threaded in.
      expect((await pinStore.read({ logId }))?.head).toBe(
        (entries[2] as unknown as { versionId: string }).versionId
      )
    }
  )

  it('refuses a threaded head resolving to another DID', async () => {
    const { ladderSeedA, generationId, did, fixture } =
      await clientAnnexFixture()
    const head = await readPublishedLog({
      idStore: fixture.idStore,
      expectedDid: did
    })
    const counted = countingStore(fixture.idStore)

    await expect(
      enrollClientAnnexTransientClient({
        store: counted.store,
        ladderSeed: ladderSeedA,
        generationId,
        transientKeyMultibase: TRANSIENT_KEY,
        expectedDid: 'did:webvh:QmSomeOtherScid:storage.example',
        ...(head !== undefined ? { published: head } : {})
      })
    ).rejects.toThrow(/resolves to a different DID/)
    expect(counted.reads()).toBe(0)
    expect(logEntries(fixture)).toHaveLength(1)
  })

  it(
    'enrollTransientClient rides the head only for the generation the ' +
      'pointer names',
    async () => {
      const pointed = await clientAnnexFixture()
      const other = await clientAnnexFixture()
      const pointerDoc = {
        id: 'did:webvh:acct:host:space:s:id',
        service: [
          {
            id: '#delegated-clients',
            type: DELEGATED_CLIENTS_SERVICE_TYPE,
            serviceEndpoint: pointed.did
          }
        ]
      } as unknown as DIDDoc

      const matching = await readPublishedLog({
        idStore: pointed.fixture.idStore,
        expectedDid: pointed.did
      })
      const foreign = await readPublishedLog({
        idStore: other.fixture.idStore,
        expectedDid: other.did
      })

      // The matching head: round 0 reads the generation log not at all.
      const matched = countingStore(pointed.fixture.idStore)
      await enrollTransientClient({
        readAccountDocument: async () => pointerDoc,
        storeForGenerationId: () => matched.store,
        ladderSeed: pointed.ladderSeedA,
        transientKeyMultibase: TRANSIENT_KEY,
        ...(matching !== undefined ? { published: matching } : {})
      })
      expect(matched.reads()).toBe(0)

      // A head for ANOTHER generation is ignored, and the round reads fresh.
      const ignored = countingStore(pointed.fixture.idStore)
      await enrollTransientClient({
        readAccountDocument: async () => pointerDoc,
        storeForGenerationId: () => ignored.store,
        ladderSeed: pointed.ladderSeedA,
        transientKeyMultibase: SECOND_TRANSIENT_KEY,
        ...(foreign !== undefined ? { published: foreign } : {})
      })
      expect(ignored.reads()).toBe(1)
      expect(logEntries(pointed.fixture)).toHaveLength(3)
    }
  )

  it('a threaded attempt that loses leaves the retry budget whole', async () => {
    const { ladderSeedA, generationId, did, fixture } =
      await clientAnnexFixture()
    const head = await readPublishedLog({
      idStore: fixture.idStore,
      expectedDid: did
    })

    // Four PUTs: the threaded attempt, then the retry's three. The first
    // three lose; the last lands. A threaded attempt counted against the
    // budget would have given up before this one.
    let reads = 0
    let puts = 0
    const losingStore: ClientAnnexWriteStore = {
      getIdResourceRaw: options => {
        reads++
        return fixture.idStore.getIdResourceRaw(options)
      },
      putIdResource: async options => {
        puts++
        if (puts < 4) {
          throw new PreconditionFailedError('lost the race')
        }
        return fixture.idStore.putIdResource(options)
      }
    }

    await enrollClientAnnexTransientClient({
      store: losingStore,
      ladderSeed: ladderSeedA,
      generationId,
      transientKeyMultibase: TRANSIENT_KEY,
      expectedDid: did,
      ...(head !== undefined ? { published: head } : {})
    })

    expect(puts).toBe(4)
    // One read per fresh attempt; the threaded one read nothing.
    expect(reads).toBe(3)
    expect(logEntries(fixture)).toHaveLength(2)
  })

  it('advances the pin past the entry it just published', async () => {
    const { ladderSeedA, generationId, did, fixture } =
      await clientAnnexFixture()
    const pinStore = memoryResourceLogPinStore()
    const logId = clientAnnexLogPinId({ spaceId: SPACE_ID, generationId })
    const genesis = fixture.log()!

    await enrollClientAnnexTransientClient({
      store: fixture.idStore,
      ladderSeed: ladderSeedA,
      generationId,
      transientKeyMultibase: TRANSIENT_KEY,
      expectedDid: did,
      pinStore,
      logId
    })

    const after = await readPublishedLog({
      idStore: fixture.idStore,
      expectedDid: did
    })
    expect(await pinStore.read({ logId })).toEqual(pinOfLog(after!.log))
    expect((await pinStore.read({ logId }))?.head).toBe(
      (logEntries(fixture)[1] as unknown as { versionId: string }).versionId
    )

    // A host serving the pre-enrollment log straight afterwards is refused
    // as a rollback rather than accepted as equal to the pin.
    const truncated: ClientAnnexWriteStore = {
      getIdResourceRaw: async () => ({ text: genesis }),
      putIdResource: options => fixture.idStore.putIdResource(options)
    }
    await expect(
      readPublishedLog({
        idStore: truncated,
        expectedDid: did,
        pinStore,
        logId
      })
    ).rejects.toMatchObject({ name: 'ResourceLogContinuityError' })
  })
})
