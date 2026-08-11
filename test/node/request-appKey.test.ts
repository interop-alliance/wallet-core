/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The App Connect app-key credential module: the minted wire shape (fixed
 * two-entry type array, hosted context URL, `appUrl` / `origin` claims),
 * the seed-to-subject binding, the match predicates and instant-based
 * ranking, the store-time refusals, and the legacy re-issue migration.
 * Ported from Freewallet `appKey.test.ts`, migrated to the `appUrl` model.
 */
import { describe, it, expect } from 'vitest'
import { base64urlnopad } from '@scure/base'
import { CapabilityAgent } from '@interop/webkms-client'
import {
  APP_CONNECT_CONTEXT_URL,
  APP_KEY_CREDENTIAL_TYPE,
  APP_KEY_KEY_NAME,
  APP_KEY_TYPE_ARRAY,
  AppKeyMintInvariantError,
  AppKeyRefusedError,
  appKeyAppUrl,
  appKeyCandidates,
  appKeyOrigin,
  appKeySeedBindsSubject,
  appKeySubjectDid,
  assertMintedAppKey,
  assertStorableAppKey,
  findAppKeyCredential,
  findLegacyAppKeyCredential,
  mintAppKeyCredential,
  presentsAsAppKey,
  reissueAppKeyCredential
} from '../../src/request/index.js'
import type { IVerifiableCredential } from '../../src/request/index.js'

const ORIGIN = 'https://app.example'
const APP_URL = 'https://app.example/notes/'
const APP = { name: 'Notes', appUrl: APP_URL }

/**
 * Derives the did:key an app-key seed binds to, with the same derivation the
 * module uses (the handle is cosmetic and does not enter the HMAC).
 */
async function didForSeed(seed: Uint8Array): Promise<string> {
  const agent = await CapabilityAgent.fromSeed({
    seed,
    handle: 'test',
    keyName: APP_KEY_KEY_NAME
  })
  return agent.id
}

/**
 * Builds an unsigned credential that satisfies the match predicates and the
 * seed-to-subject binding (the match path never verifies proofs, so none is
 * needed here).
 */
async function boundCredential(
  options: {
    seed?: Uint8Array
    appUrl?: string | undefined
    origin?: string
    issuanceDate?: string | undefined
    type?: string[]
  } = {}
): Promise<IVerifiableCredential> {
  const seed = options.seed ?? crypto.getRandomValues(new Uint8Array(32))
  // Passing `appUrl: undefined` / `issuanceDate: undefined` explicitly omits
  // the member (a destructuring default would resurrect it).
  const appUrl = 'appUrl' in options ? options.appUrl : APP_URL
  const issuanceDate =
    'issuanceDate' in options ? options.issuanceDate : '2026-01-01T00:00:00Z'
  const origin = options.origin ?? ORIGIN
  const type = options.type ?? [...APP_KEY_TYPE_ARRAY]
  const did = await didForSeed(seed)
  return {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      APP_CONNECT_CONTEXT_URL
    ],
    type,
    issuer: did,
    ...(issuanceDate !== undefined && { issuanceDate }),
    credentialSubject: {
      id: did,
      seed: base64urlnopad.encode(seed),
      ...(appUrl !== undefined && { appUrl }),
      origin
    }
  } as IVerifiableCredential
}

describe('mintAppKeyCredential', () => {
  it('mints the normative wire shape', async () => {
    const { credential, subjectDid } = await mintAppKeyCredential({
      app: APP,
      origin: ORIGIN
    })
    // Fixed two-entry type array, in order.
    expect(credential.type).toEqual([
      'VerifiableCredential',
      'AppKeyCredential'
    ])
    // VC 1.1 context first, the hosted App Connect context URL second (the
    // signature suite appends its own entry when signing).
    const contexts = credential['@context'] as unknown[]
    expect(contexts[0]).toBe('https://www.w3.org/2018/credentials/v1')
    expect(contexts[1]).toBe(APP_CONNECT_CONTEXT_URL)
    // Self-issued by the seed-derived DID.
    expect(credential.issuer).toBe(subjectDid)
    const subject = credential.credentialSubject as Record<string, unknown>
    expect(subject.id).toBe(subjectDid)
    expect(subject.appUrl).toBe(APP_URL)
    expect(subject.origin).toBe(ORIGIN)
    // A 32-byte base64url-no-pad seed.
    expect(base64urlnopad.decode(subject.seed as string)).toHaveLength(32)
    // A canonical-UTC issuanceDate (seconds precision, Z designator).
    expect((credential as { issuanceDate?: string }).issuanceDate).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/
    )
    // Genuinely self-issued: signed, and binds to its own seed.
    expect(credential.proof).toBeDefined()
    await expect(appKeySeedBindsSubject(credential)).resolves.toBe(true)
    await expect(assertMintedAppKey(credential)).resolves.toBeUndefined()
  })

  it('mints a distinct identity per call', async () => {
    const first = await mintAppKeyCredential({ app: APP, origin: ORIGIN })
    const second = await mintAppKeyCredential({ app: APP, origin: ORIGIN })
    expect(first.subjectDid).not.toBe(second.subjectDid)
  })
})

describe('appKeySeedBindsSubject', () => {
  it('accepts a credential whose subject derives from its own seed', async () => {
    await expect(appKeySeedBindsSubject(await boundCredential())).resolves.toBe(
      true
    )
  })

  it('fails closed on a substituted subject or seed', async () => {
    const credential = await boundCredential()
    const otherSeed = crypto.getRandomValues(new Uint8Array(32))
    const subjectSwapped = {
      ...credential,
      credentialSubject: {
        ...(credential.credentialSubject as object),
        id: await didForSeed(otherSeed)
      }
    } as IVerifiableCredential
    await expect(appKeySeedBindsSubject(subjectSwapped)).resolves.toBe(false)
    const seedSwapped = {
      ...credential,
      credentialSubject: {
        ...(credential.credentialSubject as object),
        seed: base64urlnopad.encode(otherSeed)
      }
    } as IVerifiableCredential
    await expect(appKeySeedBindsSubject(seedSwapped)).resolves.toBe(false)
  })

  it('fails closed on an absent, malformed, or wrong-length seed', async () => {
    const credential = await boundCredential()
    for (const seed of [
      undefined,
      42,
      'not!base64url',
      base64urlnopad.encode(new Uint8Array(16))
    ]) {
      const broken = {
        ...credential,
        credentialSubject: {
          ...(credential.credentialSubject as object),
          seed
        }
      } as IVerifiableCredential
      await expect(appKeySeedBindsSubject(broken)).resolves.toBe(false)
    }
  })
})

describe('store-time policy', () => {
  it('assertStorableAppKey refuses every marker credential, binding or not', async () => {
    const binding = await boundCredential()
    expect(() => assertStorableAppKey(binding)).toThrow(AppKeyRefusedError)
    const nonBinding = {
      ...binding,
      credentialSubject: { id: 'did:key:zSomeoneElse' }
    } as IVerifiableCredential
    expect(() => assertStorableAppKey(nonBinding)).toThrow(AppKeyRefusedError)
  })

  it('assertStorableAppKey leaves a non-marker credential alone', () => {
    const ordinary = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: { id: 'did:example:s', seed: 'x', origin: ORIGIN }
    } as IVerifiableCredential
    expect(() => assertStorableAppKey(ordinary)).not.toThrow()
    expect(presentsAsAppKey(ordinary)).toBe(false)
  })

  it('assertMintedAppKey rejects a non-marker or non-binding credential', async () => {
    const binding = await boundCredential()
    const noMarker = {
      ...binding,
      type: ['VerifiableCredential']
    } as IVerifiableCredential
    await expect(assertMintedAppKey(noMarker)).rejects.toThrow(
      AppKeyMintInvariantError
    )
    const nonBinding = {
      ...binding,
      credentialSubject: {
        ...(binding.credentialSubject as object),
        id: 'did:key:zSomeoneElse'
      }
    } as IVerifiableCredential
    await expect(assertMintedAppKey(nonBinding)).rejects.toThrow(
      AppKeyMintInvariantError
    )
  })
})

describe('matching', () => {
  it('selects on marker, appUrl claim, self-issuance, and origin', async () => {
    const match = await boundCredential()
    const noMarker = {
      ...(await boundCredential()),
      type: ['VerifiableCredential', 'NotesAppKey']
    } as IVerifiableCredential
    const otherAppUrl = await boundCredential({
      appUrl: 'https://app.example/other/'
    })
    const otherOrigin = await boundCredential({
      origin: 'https://evil.example'
    })
    const foreignIssuer = {
      ...(await boundCredential()),
      issuer: 'did:key:zSomeoneElse'
    } as IVerifiableCredential
    const candidates = appKeyCandidates({
      credentials: [noMarker, otherAppUrl, otherOrigin, foreignIssuer, match],
      appUrl: APP_URL,
      origin: ORIGIN
    })
    expect(candidates).toEqual([match])
  })

  it('compares the appUrl claim as an exact string', async () => {
    // The request side arrives serialized; a stored claim spelled with the
    // default port is a different string and does not match.
    const oddSpelling = await boundCredential({
      appUrl: 'https://app.example:443/notes/'
    })
    expect(
      appKeyCandidates({
        credentials: [oddSpelling],
        appUrl: APP_URL,
        origin: ORIGIN
      })
    ).toEqual([])
  })

  it('ranks over instants, not date spellings, absent dates last', async () => {
    const seed = crypto.getRandomValues(new Uint8Array(32))
    const older = await boundCredential({
      seed,
      issuanceDate: '2026-01-01T00:00:00Z'
    })
    // A numeric-offset spelling denoting a LATER instant, but sorting
    // earlier as a raw string comparison would have it.
    const newerOffsetSpelling = await boundCredential({
      seed,
      issuanceDate: '2026-01-01T06:00:00+02:00'
    })
    const dateless = await boundCredential({ seed, issuanceDate: undefined })
    const garbageDate = await boundCredential({
      seed,
      issuanceDate: 'not-a-date'
    })
    const ranked = appKeyCandidates({
      credentials: [dateless, older, garbageDate, newerOffsetSpelling],
      appUrl: APP_URL,
      origin: ORIGIN
    })
    expect(ranked[0]).toBe(newerOffsetSpelling)
    expect(ranked[1]).toBe(older)
    expect(ranked.slice(2)).toEqual(
      expect.arrayContaining([dateless, garbageDate])
    )
  })

  it('findAppKeyCredential returns the newest credential that binds', async () => {
    const genuine = await boundCredential({
      issuanceDate: '2026-01-01T00:00:00Z'
    })
    const newerButNotBinding = {
      ...(await boundCredential({ issuanceDate: '2026-02-01T00:00:00Z' })),
      credentialSubject: {
        ...((await boundCredential()).credentialSubject as object),
        id: 'did:key:zSomeoneElse'
      }
    } as IVerifiableCredential
    await expect(
      findAppKeyCredential({
        credentials: [genuine, newerButNotBinding],
        appUrl: APP_URL,
        origin: ORIGIN
      })
    ).resolves.toBe(genuine)
  })

  it('findAppKeyCredential returns undefined on no match (first run)', async () => {
    await expect(
      findAppKeyCredential({ credentials: [], appUrl: APP_URL, origin: ORIGIN })
    ).resolves.toBeUndefined()
  })
})

describe('legacy migration', () => {
  const legacyType = [
    'VerifiableCredential',
    APP_KEY_CREDENTIAL_TYPE,
    'NotesAppKey'
  ]

  it('findLegacyAppKeyCredential finds the origin-bound pre-appUrl credential', async () => {
    const legacy = await boundCredential({
      appUrl: undefined,
      type: legacyType
    })
    const modern = await boundCredential()
    await expect(
      findLegacyAppKeyCredential({
        credentials: [modern, legacy],
        origin: ORIGIN
      })
    ).resolves.toBe(legacy)
  })

  it('returns undefined when two legacy identities share the origin', async () => {
    const first = await boundCredential({ appUrl: undefined, type: legacyType })
    const second = await boundCredential({
      appUrl: undefined,
      type: ['VerifiableCredential', APP_KEY_CREDENTIAL_TYPE, 'OtherAppKey']
    })
    await expect(
      findLegacyAppKeyCredential({
        credentials: [first, second],
        origin: ORIGIN
      })
    ).resolves.toBeUndefined()
  })

  it('tolerates duplicates of one legacy identity, newest first', async () => {
    const seed = crypto.getRandomValues(new Uint8Array(32))
    const older = await boundCredential({
      seed,
      appUrl: undefined,
      type: legacyType,
      issuanceDate: '2026-01-01T00:00:00Z'
    })
    const newer = await boundCredential({
      seed,
      appUrl: undefined,
      type: legacyType,
      issuanceDate: '2026-02-01T00:00:00Z'
    })
    await expect(
      findLegacyAppKeyCredential({
        credentials: [older, newer],
        origin: ORIGIN
      })
    ).resolves.toBe(newer)
  })

  it('reissueAppKeyCredential preserves the identity and adopts the new shape', async () => {
    const seed = crypto.getRandomValues(new Uint8Array(32))
    const legacy = await boundCredential({
      seed,
      appUrl: undefined,
      type: legacyType
    })
    const { credential, subjectDid } = await reissueAppKeyCredential({
      credential: legacy,
      app: APP,
      origin: ORIGIN
    })
    // The same seed, so the same derived DID: identity and encrypted-data
    // access preserved.
    expect(subjectDid).toBe(appKeySubjectDid(legacy))
    expect(appKeySubjectDid(credential)).toBe(subjectDid)
    const subject = credential.credentialSubject as Record<string, unknown>
    expect(subject.seed).toBe(base64urlnopad.encode(seed))
    // The new shape: two-entry type array, appUrl claim, hosted context URL.
    expect(credential.type).toEqual([...APP_KEY_TYPE_ARRAY])
    expect(appKeyAppUrl(credential)).toBe(APP_URL)
    expect(appKeyOrigin(credential)).toBe(ORIGIN)
    expect((credential['@context'] as unknown[])[1]).toBe(
      APP_CONNECT_CONTEXT_URL
    )
    await expect(assertMintedAppKey(credential)).resolves.toBeUndefined()
    // The re-issued credential outranks the legacy one on the next match.
    await expect(
      findAppKeyCredential({
        credentials: [legacy, credential],
        appUrl: APP_URL,
        origin: ORIGIN
      })
    ).resolves.toBe(credential)
  })

  it('reissueAppKeyCredential refuses a non-binding or foreign-origin credential', async () => {
    const nonBinding = {
      ...(await boundCredential({ appUrl: undefined, type: legacyType })),
      credentialSubject: {
        id: 'did:key:zSomeoneElse',
        seed: 'xx',
        origin: ORIGIN
      }
    } as IVerifiableCredential
    await expect(
      reissueAppKeyCredential({
        credential: nonBinding,
        app: APP,
        origin: ORIGIN
      })
    ).rejects.toThrow(AppKeyMintInvariantError)
    const foreignOrigin = await boundCredential({
      appUrl: undefined,
      type: legacyType,
      origin: 'https://other.example'
    })
    await expect(
      reissueAppKeyCredential({
        credential: foreignOrigin,
        app: APP,
        origin: ORIGIN
      })
    ).rejects.toThrow(AppKeyMintInvariantError)
  })
})
