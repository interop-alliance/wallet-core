/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Subject readers: `getSubject`, `resolvePersonFullName`, `extractIssuedTo`, and
 * `credentialSubjectRenderInfo`. Ported from DCW `credentialSubject.test.ts`
 * (dates retuned from moment-formatted `startDateFmt`/`endDateFmt` to RAW ISO
 * `startDate`/`endDate`), Freewallet `getSubject.test.ts`, and the person /
 * issued-to cases from Freewallet `displayFieldsHelpers.test.ts`.
 */
import { describe, it, expect } from 'vitest'
import type {
  ICredentialSubject,
  IVerifiableCredential
} from '@interop/data-integrity-core'
import {
  getSubject,
  resolvePersonFullName,
  extractIssuedTo,
  credentialSubjectRenderInfo
} from '../../src/display/index.js'

describe('getSubject', () => {
  it('returns the subject object directly when it is not an array', () => {
    const credential = {
      credentialSubject: { id: 'did:example:123', name: 'Alice' }
    } as unknown as IVerifiableCredential
    expect(getSubject(credential)).toEqual({
      id: 'did:example:123',
      name: 'Alice'
    })
  })

  it('returns the first entry when the subject is an array', () => {
    const credential = {
      credentialSubject: [{ name: 'First' }, { name: 'Second' }]
    } as unknown as IVerifiableCredential
    expect(getSubject(credential)).toEqual({ name: 'First' })
  })
})

describe('resolvePersonFullName', () => {
  it('prefers the nested contact fullName', () => {
    const subject = {
      person: { contact: { fullName: 'Ada Lovelace' }, name: 'ignored' }
    }
    expect(resolvePersonFullName(subject)).toBe('Ada Lovelace')
  })

  it('falls back to a string person name', () => {
    expect(resolvePersonFullName({ person: { name: 'Grace Hopper' } })).toBe(
      'Grace Hopper'
    )
  })

  it('reads formattedName from an object person name', () => {
    const subject = { person: { name: { formattedName: 'Alan Turing' } } }
    expect(resolvePersonFullName(subject)).toBe('Alan Turing')
  })

  it('falls back to the subject name when there is no person', () => {
    expect(resolvePersonFullName({ name: 'Katherine Johnson' })).toBe(
      'Katherine Johnson'
    )
  })

  it('returns an empty string when no name is present', () => {
    expect(resolvePersonFullName({})).toBe('')
  })
})

describe('extractIssuedTo', () => {
  it('resolves the recipient full name from the subject person', () => {
    const vc = {
      credentialSubject: { person: { contact: { fullName: 'Ada Lovelace' } } }
    } as unknown as IVerifiableCredential
    expect(extractIssuedTo(vc)).toBe('Ada Lovelace')
  })

  it('reads a name identity hash entry when no person name exists', () => {
    const vc = {
      credentialSubject: {
        identifier: [
          { identityType: 'email', identityHash: 'a@b.co' },
          { identityType: 'name', identityHash: 'Grace Hopper' }
        ]
      }
    } as unknown as IVerifiableCredential
    expect(extractIssuedTo(vc)).toBe('Grace Hopper')
  })

  it('skips a non-name identity hash (name guard)', () => {
    const vc = {
      credentialSubject: {
        identifier: [{ identityType: 'email', identityHash: 'a@b.co' }]
      },
      name: 'Fallback Name'
    } as unknown as IVerifiableCredential
    expect(extractIssuedTo(vc)).toBe('Fallback Name')
  })

  it('falls back to the top-level credential name when there is no subject', () => {
    const vc = {
      name: 'A Credential',
      credentialSubject: undefined
    } as unknown as IVerifiableCredential
    expect(extractIssuedTo(vc)).toBe('A Credential')
  })
})

describe('credentialSubjectRenderInfo', () => {
  it('extracts basic subject information', () => {
    const subject: ICredentialSubject = {
      id: 'did:example:123',
      name: 'John Doe'
    }
    const result = credentialSubjectRenderInfo(subject)
    expect(result.subjectName).toBe('John Doe')
    expect(result.issuedTo).toBe('John Doe')
    expect(result.degreeName).toBeNull()
    expect(result.description).toBeNull()
    expect(result.criteria).toBeNull()
    expect(result.alignment).toBeUndefined()
  })

  it('extracts achievement information with alignments', () => {
    const subject: ICredentialSubject = {
      id: 'did:example:123',
      achievement: {
        id: 'achievement-1',
        name: 'Test Achievement',
        description: 'Test Description',
        criteria: { type: 'Criteria', narrative: 'Test criteria narrative' },
        alignment: [
          { targetName: 'Test Alignment', targetUrl: 'https://example.com' }
        ]
      }
    }
    const result = credentialSubjectRenderInfo(subject)
    expect(result.description).toBe('Test Description')
    expect(result.criteria).toBe('Test criteria narrative')
    expect(result.alignment).toHaveLength(1)
    expect(result.alignment![0]!.targetName).toBe('Test Alignment')
  })

  it('handles an array of achievements (uses the first)', () => {
    const subject: ICredentialSubject = {
      id: 'did:example:123',
      achievement: [
        {
          id: 'achievement-1',
          name: 'First Achievement',
          description: 'First Description'
        },
        {
          id: 'achievement-2',
          name: 'Second Achievement',
          description: 'Second Description'
        }
      ]
    }
    const result = credentialSubjectRenderInfo(subject)
    expect(result.description).toBe('First Description')
  })

  it('extracts degree information', () => {
    const subject: ICredentialSubject = {
      id: 'did:example:123',
      degree: { type: 'BachelorDegree', name: 'Bachelor of Science' }
    }
    expect(credentialSubjectRenderInfo(subject).degreeName).toBe(
      'Bachelor of Science'
    )
  })

  it('returns RAW ISO start/end dates (formatting stays in the UI)', () => {
    const subject: ICredentialSubject = {
      id: 'did:example:123',
      achievement: {
        id: 'achievement-1',
        awardedOnCompletionOf: {
          startDate: '2023-01-01T00:00:00Z',
          endDate: '2023-12-31T23:59:59Z',
          numberOfCredits: { value: '3' }
        }
      }
    }
    const result = credentialSubjectRenderInfo(subject)
    expect(result.startDate).toBe('2023-01-01T00:00:00Z')
    expect(result.endDate).toBe('2023-12-31T23:59:59Z')
    expect(result.numberOfCredits).toBe('3')
  })

  it('handles missing optional fields gracefully', () => {
    const subject: ICredentialSubject = { id: 'did:example:123' }
    const result = credentialSubjectRenderInfo(subject)
    expect(result.subjectName).toBeNull()
    expect(result.issuedTo).toBeNull()
    expect(result.degreeName).toBeNull()
    expect(result.description).toBeNull()
    expect(result.criteria).toBeNull()
    expect(result.numberOfCredits).toBeNull()
    expect(result.startDate).toBeNull()
    expect(result.endDate).toBeNull()
    expect(result.achievementImage).toBeNull()
    expect(result.achievementType).toBeNull()
    expect(result.alignment).toBeUndefined()
  })
})
