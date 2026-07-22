/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * VP composition (`composeVp`): the unsigned path (bare VP wrapping selected
 * VCs), the signed DID Auth path (holder set, proof present), cryptosuite
 * selection, the challenge-required / domain-optional guard, and the optional
 * embedded App Connect marker (a JSON-literal `@context` term the DIDAuth proof
 * must canonicalize and cover). Real Ed25519 keys are generated so the signing
 * paths run end-to-end. Merged from DCW `composeVp.test.ts` / `vcApi.test.ts`
 * and Freewallet `composeVP.test.ts`.
 */
import { describe, it, expect } from 'vitest'
import {
  composeVp,
  composeVP,
  EDDSA_RDFC_2022
} from '../../src/request/index.js'
import { makePresentationSigner } from './fixtures/request/signer.js'
import { mockCredential } from './fixtures/request/credentials.js'

const CHALLENGE = 'challenge-123'
const DOMAIN = 'verifier.example.com'

describe('composeVp', () => {
  it('throws when there are no credentials, capabilities, or DID Auth', async () => {
    const presentationSigner = await makePresentationSigner()
    await expect(
      composeVp({
        presentationSigner,
        selectedVcs: [],
        didAuthRequested: false
      })
    ).rejects.toThrow(/requires credentials, capabilities, or a DID Auth/)
  })

  it('throws when DID Auth is requested without a challenge', async () => {
    const presentationSigner = await makePresentationSigner()
    await expect(
      composeVp({ presentationSigner, didAuthRequested: true, domain: DOMAIN })
    ).rejects.toThrow(/"challenge" is required/)
  })

  it('builds an unsigned VP wrapping the selected credentials', async () => {
    const presentationSigner = await makePresentationSigner()
    const vp = await composeVp({
      presentationSigner,
      selectedVcs: [mockCredential],
      didAuthRequested: false
    })
    expect(vp.type).toContain('VerifiablePresentation')
    expect(vp.proof).toBeUndefined()
    expect(vp.verifiableCredential).toEqual([mockCredential])
  })

  it('signs a DID-Auth-only VP with the holder set', async () => {
    const presentationSigner = await makePresentationSigner()
    const vp = await composeVp({
      presentationSigner,
      didAuthRequested: true,
      challenge: CHALLENGE,
      domain: DOMAIN
    })
    expect(vp.holder).toBe(presentationSigner.holder)
    expect(vp.proof).toBeDefined()
    expect((vp.proof as { type: string }).type).toBe('Ed25519Signature2020')
    expect((vp.proof as { challenge?: string }).challenge).toBe(CHALLENGE)
  })

  it('signs a DID Auth VP without a domain (domain is optional per VPR)', async () => {
    const presentationSigner = await makePresentationSigner()
    const vp = await composeVp({
      presentationSigner,
      didAuthRequested: true,
      challenge: CHALLENGE
    })
    expect(vp.holder).toBe(presentationSigner.holder)
    expect(vp.proof).toBeDefined()
    expect((vp.proof as { domain?: string }).domain).toBeUndefined()
  })

  it('signs with the default Ed25519Signature2020 suite (VC 1.0) when no cryptosuite is negotiated', async () => {
    const presentationSigner = await makePresentationSigner()
    const vp = await composeVp({
      presentationSigner,
      selectedVcs: [mockCredential],
      didAuthRequested: true,
      challenge: CHALLENGE,
      domain: DOMAIN
    })
    expect((vp.proof as { type: string }).type).toBe('Ed25519Signature2020')
  })

  it('signs with a DataIntegrityProof under the VC 2.0 context for eddsa-rdfc-2022', async () => {
    const presentationSigner = await makePresentationSigner()
    const vp = await composeVp({
      presentationSigner,
      selectedVcs: [],
      didAuthRequested: true,
      challenge: CHALLENGE,
      domain: DOMAIN,
      cryptosuite: EDDSA_RDFC_2022
    })
    expect((vp.proof as { type: string }).type).toBe('DataIntegrityProof')
    expect((vp.proof as { cryptosuite?: string }).cryptosuite).toBe(
      EDDSA_RDFC_2022
    )
    const context = vp['@context']
    const contextList = Array.isArray(context) ? context : [context]
    expect(contextList).toContain('https://www.w3.org/ns/credentials/v2')
  })

  it('exposes the deprecated composeVP spelling as the same function', () => {
    expect(composeVP).toBe(composeVp)
  })
})

describe('composeVp with an appConnect marker', () => {
  it('embeds the marker and its context term on a signed VP', async () => {
    const presentationSigner = await makePresentationSigner()
    const presentation = (await composeVp({
      presentationSigner,
      didAuthRequested: true,
      challenge: CHALLENGE,
      domain: DOMAIN,
      appConnect: { firstRun: true }
    })) as { appConnect?: unknown; '@context': unknown; proof?: unknown }

    expect(presentation.appConnect).toEqual({ firstRun: true })
    const contexts = presentation['@context'] as Array<string | object>
    expect(
      contexts.some(
        entry =>
          typeof entry === 'object' &&
          'appConnect' in (entry as Record<string, unknown>)
      )
    ).toBe(true)
    expect(presentation.proof).toBeDefined()
  })

  it('embeds the marker on an unsigned VP', async () => {
    const presentationSigner = await makePresentationSigner()
    const presentation = (await composeVp({
      presentationSigner,
      didAuthRequested: false,
      selectedVcs: [mockCredential],
      appConnect: { firstRun: false }
    })) as { appConnect?: unknown; proof?: unknown }

    expect(presentation.appConnect).toEqual({ firstRun: false })
    expect(presentation.proof).toBeUndefined()
  })

  it('omits the marker and term when appConnect is absent', async () => {
    const presentationSigner = await makePresentationSigner()
    const presentation = (await composeVp({
      presentationSigner,
      didAuthRequested: true,
      challenge: CHALLENGE,
      domain: DOMAIN
    })) as { appConnect?: unknown; '@context': unknown }

    expect(presentation.appConnect).toBeUndefined()
    const contexts = presentation['@context'] as Array<string | object>
    expect(
      contexts.every(
        entry =>
          typeof entry !== 'object' ||
          !('appConnect' in (entry as Record<string, unknown>))
      )
    ).toBe(true)
  })

  it('uses the default urn:freewallet:vocab# IRI for the embedded zcap term', async () => {
    const presentationSigner = await makePresentationSigner()
    const zcap = {
      '@context': 'https://w3id.org/zcap/v1',
      id: 'urn:zcap:1',
      controller: 'did:key:zController',
      invocationTarget: 'https://example.com/target',
      proof: {}
    }
    const presentation = (await composeVp({
      presentationSigner,
      didAuthRequested: false,
      zcaps: [zcap as never]
    })) as { zcap?: unknown; '@context': unknown }

    expect(presentation.zcap).toEqual([zcap])
    const contexts = presentation['@context'] as Array<string | object>
    const zcapTerm = contexts.find(
      (entry): entry is { zcap: { '@id': string } } =>
        typeof entry === 'object' &&
        'zcap' in (entry as Record<string, unknown>)
    )
    expect(zcapTerm?.zcap?.['@id']).toBe('urn:freewallet:vocab#zcap')
  })
})
