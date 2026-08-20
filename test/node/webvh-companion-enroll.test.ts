/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Transient enrollment and the delegated-clients pointer: the companion rung
 * HKDF label family (disjoint from the account-rung and ladder-VM labels
 * under the one salt), the atomic static-rung-0 enrollment entry (reveal at
 * first write, `nextKeyHashes` restated explicitly on every entry, the
 * transient VM under `capabilityInvocation` only, same-key CAS retry, the
 * mid-generation lockout refusal), the account document's
 * `#DelegatedClients` service entry (type-IRI dispatch, non-semantic stable
 * fragment, DID-string endpoint), and the enrollee's GC-race closure (the
 * post-append pointer re-read and fresh-generation re-enroll).
 */
import { describe, expect, it } from 'vitest'
import {
  defaultWebvhLogVerifier,
  deriveNextKeyHash,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import type { DIDDoc } from '@interop/did-method-webvh'
import {
  companionRung,
  companionRungSeed,
  generateLadderSeed,
  ladderRungSeed,
  ladderVmSeed
} from '../../src/unlock/ladder.js'
import {
  companionDidParts,
  CompanionRungUncommittedError,
  createCompanionLog,
  DELEGATED_CLIENTS_SERVICE_TYPE,
  delegatedClientsPointer,
  delegatedClientsServiceEntry,
  enrollCompanionTransientClient,
  enrollTransientClient,
  mintGenerationId,
  setDelegatedClientsPointer
} from '../../src/webvh/companion.js'
import type { CompanionWriteStore } from '../../src/webvh/companion.js'
import {
  ensureDidWebvh,
  putLogResource,
  readPublishedLog,
  updateKeySigner
} from '../../src/webvh/didWebvh.js'
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
 * Mints and publishes one companion generation into a fresh in-memory store:
 * credential A is the minting writer (its rung-0 key revealed at genesis),
 * credential B stands committed only.
 */
async function companionFixture() {
  const ladderSeedA = fixedSeed(11)
  const ladderSeedB = fixedSeed(22)
  const generationId = mintGenerationId()
  const rungA = await companionRung({ ladderSeed: ladderSeedA, generationId })
  const rungB = await companionRung({ ladderSeed: ladderSeedB, generationId })
  const hashA = await deriveNextKeyHash(rungA.keyMultibase)
  const hashB = await deriveNextKeyHash(rungB.keyMultibase)
  const created = await createCompanionLog({
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
 * The published companion log's entries, parsed off the store.
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

describe('companion rung derivation', () => {
  it(
    'derives under the generation-id-prefixed info label, disjoint from the ' +
      'account-rung and ladder-VM families',
    async () => {
      const ladderSeed = generateLadderSeed()
      const generationId = mintGenerationId()
      const seed = companionRungSeed({ ladderSeed, generationId })
      expect(seed).toHaveLength(32)
      // Deterministic, and distinct per generation id.
      expect(companionRungSeed({ ladderSeed, generationId })).toEqual(seed)
      expect(
        companionRungSeed({ ladderSeed, generationId: mintGenerationId() })
      ).not.toEqual(seed)
      // Disjoint from `rung/<n>` and `vm` under the same salt and seed.
      expect(seed).not.toEqual(ladderRungSeed({ ladderSeed, index: 0 }))
      expect(seed).not.toEqual(ladderVmSeed({ ladderSeed }))
      const rung = await companionRung({ ladderSeed, generationId })
      expect(rung.seed).toEqual(seed)
      expect(rung.keyMultibase).toMatch(/^z/)
    }
  )
})

describe('enrollCompanionTransientClient', () => {
  it(
    'publishes one atomic entry: VM under capabilityInvocation only, ' +
      'updateKeys re-stated, nextKeyHashes re-stated verbatim',
    async () => {
      const { ladderSeedA, generationId, rungA, hashA, hashB, did, fixture } =
        await companionFixture()
      const enrolled = await enrollCompanionTransientClient({
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
      // The transient VM: capabilityInvocation only, stated explicitly, no
      // keyAgreement twin, no update key of its own.
      const vmId = `${did}#${TRANSIENT_KEY}`
      const doc = entry.state
      expect((doc.verificationMethod ?? []).map(method => method.id)).toEqual([
        vmId
      ])
      expect(doc.capabilityInvocation).toEqual([vmId])
      expect(doc.authentication ?? []).toEqual([])
      expect(doc.assertionMethod ?? []).toEqual([])
      expect(doc.keyAgreement ?? []).toEqual([])
      expect(doc.capabilityDelegation ?? []).toEqual([])
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
      } = await companionFixture()
      await enrollCompanionTransientClient({
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
      await enrollCompanionTransientClient({
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
      const { generationId, did, fixture } = await companionFixture()
      await expect(
        enrollCompanionTransientClient({
          store: fixture.idStore,
          ladderSeed: fixedSeed(33),
          generationId,
          transientKeyMultibase: TRANSIENT_KEY,
          expectedDid: did
        })
      ).rejects.toThrow(CompanionRungUncommittedError)
    }
  )

  it('is idempotent: a VM already present appends nothing', async () => {
    const { ladderSeedA, generationId, did, fixture } = await companionFixture()
    await enrollCompanionTransientClient({
      store: fixture.idStore,
      ladderSeed: ladderSeedA,
      generationId,
      transientKeyMultibase: TRANSIENT_KEY,
      expectedDid: did
    })
    const before = logEntries(fixture).length
    await enrollCompanionTransientClient({
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
        await companionFixture()
      // A store whose first conditional PUT loses the race; the retry re-reads
      // and re-signs with the same rung-0 key.
      let failed = false
      const racingStore: CompanionWriteStore = {
        getIdResourceRaw: options => fixture.idStore.getIdResourceRaw(options),
        putIdResource: async options => {
          if (!failed) {
            failed = true
            throw new PreconditionFailedError('lost the race')
          }
          return fixture.idStore.putIdResource(options)
        }
      }
      await enrollCompanionTransientClient({
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
        companionDid: 'did:webvh:cscid:host:space:aux:gen-AAAAAAAAAAAAAAAA'
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
      const companionDid = 'did:webvh:c:h:space:aux:gen-AAAAAAAAAAAAAAAA'
      const doc = (service: unknown) =>
        ({ id: 'did:x', service }) as unknown as DIDDoc
      expect(
        delegatedClientsPointer({
          doc: doc([
            { id: '#a', type: 'SomethingElse', serviceEndpoint: 'x' },
            {
              id: '#whatever',
              type: DELEGATED_CLIENTS_SERVICE_TYPE,
              serviceEndpoint: companionDid
            }
          ])
        })
      ).toBe(companionDid)
      expect(
        delegatedClientsPointer({
          doc: doc([
            {
              id: '#b',
              type: ['Other', DELEGATED_CLIENTS_SERVICE_TYPE],
              serviceEndpoint: companionDid
            }
          ])
        })
      ).toBe(companionDid)
      // A non-string endpoint never counts, and no entry means no pointer.
      expect(
        delegatedClientsPointer({
          doc: doc([
            {
              id: '#c',
              type: DELEGATED_CLIENTS_SERVICE_TYPE,
              serviceEndpoint: { did: companionDid }
            }
          ])
        })
      ).toBeUndefined()
      expect(
        delegatedClientsPointer({ doc: { id: 'did:x' } as DIDDoc })
      ).toBeUndefined()
    }
  )

  it('parses the Space id and generation id out of a companion DID', async () => {
    const { did, generationId } = await companionFixture()
    expect(companionDidParts({ did })).toEqual({
      spaceId: SPACE_ID,
      generationId
    })
    expect(() =>
      companionDidParts({ did: 'did:webvh:scid:host:space:s:id' })
    ).toThrow(/Not a generation id/)
    expect(() => companionDidParts({ did: 'did:key:z6Mk' })).toThrow(
      /Not a companion did:webvh/
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
      const companionA = (await companionFixture()).did
      const companionB = (await companionFixture()).did
      const before = await readPublishedLog({ idStore: fixture.idStore })
      const beforeMethods = (before!.doc.verificationMethod ?? []).length

      await setDelegatedClientsPointer({
        idStore: fixture.idStore,
        updateKeys,
        companionDid: companionA,
        expectedDid: did
      })
      let published = await readPublishedLog({ idStore: fixture.idStore })
      expect(delegatedClientsPointer({ doc: published!.doc })).toBe(companionA)
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
        companionDid: companionA,
        expectedDid: did
      })
      expect(fixture.log()!.trim().split('\n')).toHaveLength(entriesBefore)

      // The GC re-point replaces the endpoint in place, id preserved.
      await setDelegatedClientsPointer({
        idStore: fixture.idStore,
        updateKeys,
        companionDid: companionB,
        expectedDid: did
      })
      published = await readPublishedLog({ idStore: fixture.idStore })
      expect(published!.doc.service ?? []).toHaveLength(1)
      expect(delegatedClientsPointer({ doc: published!.doc })).toBe(companionB)
      expect((published!.doc.service ?? [])[0]!.id).toBe(
        `${did}#delegated-clients`
      )
    }
  )

  it('refuses a malformed companion DID before touching the log', async () => {
    const { fixture, updateKeys, did } = await accountFixture()
    const entriesBefore = fixture.log()!.trim().split('\n').length
    await expect(
      setDelegatedClientsPointer({
        idStore: fixture.idStore,
        updateKeys,
        companionDid: 'did:web:example.com',
        expectedDid: did
      })
    ).rejects.toThrow(/Not a companion did:webvh/)
    expect(fixture.log()!.trim().split('\n')).toHaveLength(entriesBefore)
  })
})

describe('enrollTransientClient (the GC-race closure)', () => {
  it(
    're-reads the pointer after its append and re-enrolls into a fresh ' +
      'generation on a mismatch',
    async () => {
      const generationA = await companionFixture()
      // The racing GC swap's fresh generation, written by the same credential.
      const generationB = await companionFixture()
      const stores = new Map<string, CompanionWriteStore>([
        [generationA.generationId, generationA.fixture.idStore],
        [generationB.generationId, generationB.fixture.idStore]
      ])
      const pointerDoc = (companionDid: string) =>
        ({
          id: 'did:webvh:acct:host:space:s:id',
          service: [
            {
              id: '#delegated-clients',
              type: DELEGATED_CLIENTS_SERVICE_TYPE,
              serviceEndpoint: companionDid
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
      expect(result.companionDid).toBe(generationB.did)
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
