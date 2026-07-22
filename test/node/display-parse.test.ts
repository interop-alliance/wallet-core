/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Credential input parsing. Ported from Freewallet `credentialsFromJSON.test.ts`,
 * the pure `extractCredentialsFrom` cases of DCW `verifiableObject.test.ts`
 * (converted from node:test to vitest; the LRU caching tests stay in DCW), and
 * new `resolveCredentialsInput` cases that exercise the injected `fetchUrl`.
 */
import { describe, it, expect } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import {
  credentialsFromJSON,
  extractCredentialsFrom,
  resolveCredentialsInput,
  ResolveCredentialsInputError
} from '../../src/display/index.js'

const V1 = 'https://www.w3.org/2018/credentials/v1'

const minimalVc: IVerifiableCredential = {
  '@context': [V1],
  type: ['VerifiableCredential'],
  issuer: 'did:example:issuer',
  issuanceDate: '2020-01-01T00:00:00Z',
  credentialSubject: { id: 'did:example:subject' }
}

function secondVc(): IVerifiableCredential {
  return { ...minimalVc, credentialSubject: { id: 'did:example:second' } }
}

function presentationOf(
  verifiableCredential: IVerifiableCredential | IVerifiableCredential[]
): Record<string, unknown> {
  return {
    '@context': [V1],
    type: ['VerifiablePresentation'],
    verifiableCredential
  }
}

describe('credentialsFromJSON', () => {
  it('returns a single VC object wrapped in an array', () => {
    const result = credentialsFromJSON(JSON.stringify(minimalVc))
    expect(result).toEqual([minimalVc])
  })

  it('returns an array of VCs unchanged', () => {
    const credentials = [minimalVc, secondVc()]
    expect(credentialsFromJSON(JSON.stringify(credentials))).toEqual(
      credentials
    )
  })

  it('filters non-credential entries out of an array', () => {
    const input = [minimalVc, { type: ['SomethingElse'] }, { foo: 'bar' }]
    expect(credentialsFromJSON(JSON.stringify(input))).toEqual([minimalVc])
  })

  it('unwraps a single VC from a Verifiable Presentation', () => {
    expect(
      credentialsFromJSON(JSON.stringify(presentationOf(minimalVc)))
    ).toEqual([minimalVc])
  })

  it('unwraps an array of VCs from a Verifiable Presentation', () => {
    expect(
      credentialsFromJSON(
        JSON.stringify(presentationOf([minimalVc, secondVc()]))
      )
    ).toEqual([minimalVc, secondVc()])
  })

  it('throws when an array contains no Verifiable Credentials', () => {
    expect(() =>
      credentialsFromJSON(
        JSON.stringify([{ type: ['SomethingElse'] }, { foo: 'bar' }])
      )
    ).toThrow('Array did not contain any Verifiable Credentials.')
  })

  it('throws when the JSON is a plain object that is not a credential', () => {
    expect(() => credentialsFromJSON(JSON.stringify({ foo: 'bar' }))).toThrow(
      'Could not decode Verifiable Credential(s) from the JSON.'
    )
  })

  it('decodes a credential whose type is a bare string', () => {
    const stringType = { ...minimalVc, type: 'VerifiableCredential' }
    expect(credentialsFromJSON(JSON.stringify(stringType))).toEqual([
      stringType
    ])
  })

  it('throws on malformed JSON input', () => {
    expect(() => credentialsFromJSON('{not valid json')).toThrow()
  })

  it('throws on a JSON null literal', () => {
    expect(() => credentialsFromJSON('null')).toThrow(
      'Could not decode Verifiable Credential(s) from the JSON.'
    )
  })
})

describe('extractCredentialsFrom', () => {
  it('returns null for a plain object with no type', () => {
    expect(extractCredentialsFrom({ '@context': [V1] } as never)).toBeNull()
  })

  it('returns null for an object whose type is neither VC nor VP', () => {
    const foreign = {
      '@context': [V1],
      type: ['SomethingElse'],
      verifiableCredential: [{ type: ['VerifiableCredential'] }]
    }
    expect(extractCredentialsFrom(foreign as never)).toBeNull()
  })

  it('returns a bare VC wrapped in a single-element array', () => {
    const credential = { '@context': [V1], type: ['VerifiableCredential'] }
    const result = extractCredentialsFrom(credential as never)
    expect(result).toHaveLength(1)
    expect(result![0]).toBe(credential)
  })

  it('detects VerifiableCredential before VerifiablePresentation for a dual-typed object', () => {
    const dual = {
      '@context': [V1],
      type: ['VerifiableCredential', 'VerifiablePresentation'],
      verifiableCredential: [{ type: ['VerifiableCredential'] }]
    }
    const result = extractCredentialsFrom(dual as never)
    expect(result).toHaveLength(1)
    expect(result![0]).toBe(dual)
  })

  it('returns null for a VP that carries no verifiableCredential field', () => {
    const emptyVp = { '@context': [V1], type: ['VerifiablePresentation'] }
    expect(extractCredentialsFrom(emptyVp as never)).toBeNull()
  })
})

describe('resolveCredentialsInput', () => {
  const neverFetch = async () => {
    throw new Error('fetchUrl should not be called')
  }

  it('parses raw JSON without fetching', async () => {
    const result = await resolveCredentialsInput({
      raw: JSON.stringify(minimalVc),
      fetchUrl: neverFetch
    })
    expect(result).toEqual([minimalVc])
  })

  it('fetches a URL body via the injected fetchUrl', async () => {
    const result = await resolveCredentialsInput({
      raw: 'https://example.com/vc.json',
      fetchUrl: async url => {
        expect(url).toBe('https://example.com/vc.json')
        return JSON.stringify(minimalVc)
      }
    })
    expect(result).toEqual([minimalVc])
  })

  it('throws an "empty" coded error for blank input', async () => {
    await expect(
      resolveCredentialsInput({ raw: '   ', fetchUrl: neverFetch })
    ).rejects.toMatchObject({ code: 'empty' })
  })

  it('throws a "vpqr_unsupported" coded error for VP1- input', async () => {
    await expect(
      resolveCredentialsInput({ raw: 'VP1-ABC', fetchUrl: neverFetch })
    ).rejects.toMatchObject({ code: 'vpqr_unsupported' })
  })

  it('throws an "invalid_input" coded error for unrecognized input', async () => {
    await expect(
      resolveCredentialsInput({ raw: 'hello there', fetchUrl: neverFetch })
    ).rejects.toBeInstanceOf(ResolveCredentialsInputError)
  })
})
