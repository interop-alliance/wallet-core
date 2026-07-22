/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * QueryByExample matching, both algorithms the shared layer ships:
 * `credentialMatchesVprExampleQuery` / `filterCredentialsByExample` (DCW's
 * jsonpath deep matcher) and `vcMatchesFor` / `requestsCredentialType` /
 * `hasTypedExample` (Freewallet's type-and-issuer matcher). Both operate on
 * plain `IVerifiableCredential`s. Ported from DCW `credentialMatching.test.ts`
 * and Freewallet `vcMatches.test.ts`.
 */
import { describe, it, expect } from 'vitest'
import {
  credentialMatchesVprExampleQuery,
  filterCredentialsByExample,
  hasTypedExample,
  requestsCredentialType,
  vcMatchesFor
} from '../../src/request/index.js'
import type {
  ICredentialQuery,
  IQueryByExample
} from '../../src/request/index.js'
import {
  employmentCredential,
  universityCredential
} from './fixtures/request/credentials.js'

describe('credentialMatchesVprExampleQuery (jsonpath deep matcher)', () => {
  const credential = universityCredential

  it('matches when the example type is a subset of the credential type', () => {
    expect(
      credentialMatchesVprExampleQuery(
        { type: ['VerifiableCredential'] },
        credential
      )
    ).toBe(true)
  })

  it('matches when every requested type is present', () => {
    expect(
      credentialMatchesVprExampleQuery(
        { type: ['VerifiableCredential', 'Assertion'] },
        credential
      )
    ).toBe(true)
  })

  it('does not match when a requested type is absent', () => {
    expect(
      credentialMatchesVprExampleQuery(
        { type: ['VerifiableCredential', 'Missing'] },
        credential
      )
    ).toBe(false)
  })

  it('does not match when the example array is longer than the credential array', () => {
    expect(
      credentialMatchesVprExampleQuery(
        { type: ['VerifiableCredential', 'Assertion', 'Extra'] },
        credential
      )
    ).toBe(false)
  })

  it('does not match an array query against a non-array credential value', () => {
    // issuer here is an object, not an array, so an array query cannot match.
    expect(
      credentialMatchesVprExampleQuery(
        { issuer: ['did:key:university'] },
        credential
      )
    ).toBe(false)
  })

  it('matches a nested object query against the issuer id', () => {
    expect(
      credentialMatchesVprExampleQuery(
        { issuer: { id: 'did:key:university' } },
        credential
      )
    ).toBe(true)
  })

  it('does not match when a nested object query value differs', () => {
    expect(
      credentialMatchesVprExampleQuery(
        { issuer: { id: 'did:key:someone-else' } },
        credential
      )
    ).toBe(false)
  })

  it('matches a literal issuer value when the credential issuer is a string', () => {
    expect(
      credentialMatchesVprExampleQuery(
        { issuer: 'did:key:employer' },
        employmentCredential
      )
    ).toBe(true)
  })

  it('does not match a literal query against an object credential value', () => {
    // credential.issuer is an object, so a literal string comparison fails.
    expect(
      credentialMatchesVprExampleQuery(
        { issuer: 'did:key:university' },
        credential
      )
    ).toBe(false)
  })

  it('matches on a shared @context url', () => {
    expect(
      credentialMatchesVprExampleQuery(
        { '@context': ['https://www.w3.org/2018/credentials/v1'] },
        credential
      )
    ).toBe(true)
  })

  it('treats an empty example as matching any credential', () => {
    expect(credentialMatchesVprExampleQuery({}, credential)).toBe(true)
  })
})

describe('filterCredentialsByExample (jsonpath deep matcher)', () => {
  const credentials = [universityCredential, employmentCredential]

  function query(example: ICredentialQuery['example']): IQueryByExample {
    return { type: 'QueryByExample', credentialQuery: { example } }
  }

  it('returns every credential matching a broad VerifiableCredential type query', () => {
    const result = filterCredentialsByExample(
      credentials,
      query({
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential']
      })
    )
    expect(result).toHaveLength(2)
  })

  it('returns only the credential whose specific type matches', () => {
    const result = filterCredentialsByExample(
      credentials,
      query({ type: ['EmploymentCredential'] })
    )
    expect(result).toEqual([employmentCredential])
  })

  it('filters by a nested issuer query', () => {
    const result = filterCredentialsByExample(
      credentials,
      query({ issuer: { id: 'did:key:university' } })
    )
    expect(result).toEqual([universityCredential])
  })

  it('returns an empty array when nothing matches', () => {
    expect(
      filterCredentialsByExample(
        credentials,
        query({ type: ['NonexistentType'] })
      )
    ).toEqual([])
  })

  it('returns an empty array for a malformed query with no example', () => {
    const malformed = { type: 'QueryByExample', credentialQuery: {} } as never
    expect(filterCredentialsByExample(credentials, malformed)).toEqual([])
  })
})

describe('vcMatchesFor (type + issuer matcher)', () => {
  const credentials = [universityCredential, employmentCredential]

  it('matches by example type', () => {
    const result = vcMatchesFor({
      credentials,
      queries: [
        {
          type: 'QueryByExample',
          credentialQuery: { example: { type: ['EmploymentCredential'] } }
        }
      ]
    })
    expect(result).toEqual([employmentCredential])
  })

  it('additionally constrains on a pinned issuer', () => {
    const result = vcMatchesFor({
      credentials,
      queries: [
        {
          type: 'QueryByExample',
          credentialQuery: {
            example: {
              type: ['VerifiableCredential'],
              issuer: 'did:key:employer'
            }
          }
        }
      ]
    })
    expect(result).toEqual([employmentCredential])
  })

  it('returns nothing when no query pins an example type', () => {
    const result = vcMatchesFor({
      credentials,
      queries: [{ type: 'QueryByExample', credentialQuery: { example: {} } }]
    })
    expect(result).toEqual([])
  })
})

describe('hasTypedExample / requestsCredentialType', () => {
  function queryByExample(
    example: ICredentialQuery['example']
  ): IQueryByExample {
    return { type: 'QueryByExample', credentialQuery: { example } }
  }

  it('hasTypedExample is true only when a query pins a type', () => {
    expect(hasTypedExample([queryByExample({ type: 'LoginCredential' })])).toBe(
      true
    )
    expect(hasTypedExample([queryByExample({})])).toBe(false)
  })

  it('requestsCredentialType is true when an example (string) matches', () => {
    const queries = [queryByExample({ type: 'LoginCredential' })]
    expect(requestsCredentialType({ queries, type: 'LoginCredential' })).toBe(
      true
    )
  })

  it('requestsCredentialType is true when an example (array) includes the type', () => {
    const queries = [
      queryByExample({ type: ['VerifiableCredential', 'LoginCredential'] })
    ]
    expect(requestsCredentialType({ queries, type: 'LoginCredential' })).toBe(
      true
    )
  })

  it('requestsCredentialType is false for an untyped example', () => {
    expect(
      requestsCredentialType({
        queries: [queryByExample({})],
        type: 'LoginCredential'
      })
    ).toBe(false)
  })

  it('requestsCredentialType is false when only other types are requested', () => {
    const queries = [queryByExample({ type: 'AlumniCredential' })]
    expect(requestsCredentialType({ queries, type: 'LoginCredential' })).toBe(
      false
    )
  })

  it('requestsCredentialType is false for an empty query list', () => {
    expect(
      requestsCredentialType({ queries: [], type: 'LoginCredential' })
    ).toBe(false)
  })
})
