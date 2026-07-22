/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Credential type predicates. Ported from DCW `credentialTypes.test.ts` (the
 * subject-typed `isResumeCredentialSubject`) plus new vc-typed
 * `isResumeCredential` cases that pin the merged entry point.
 */
import { describe, it, expect } from 'vitest'
import type {
  ICredentialSubject,
  IVerifiableCredential
} from '@interop/data-integrity-core'
import {
  isResumeCredentialSubject,
  isResumeCredential,
  isEmploymentCredential,
  isVolunteerCredential
} from '../../src/display/index.js'

describe('isResumeCredentialSubject', () => {
  it('returns false when type is missing', () => {
    expect(isResumeCredentialSubject({} as ICredentialSubject)).toBe(false)
  })

  it('returns true when type is exactly Resume', () => {
    expect(
      isResumeCredentialSubject({
        type: 'Resume'
      } as unknown as ICredentialSubject)
    ).toBe(true)
  })

  it('returns true when a type array contains Resume', () => {
    expect(
      isResumeCredentialSubject({
        type: ['VerifiableCredential', 'Resume']
      } as unknown as ICredentialSubject)
    ).toBe(true)
  })

  it('returns true for a case-insensitive substring match', () => {
    expect(
      isResumeCredentialSubject({
        type: 'ResumeCredential'
      } as unknown as ICredentialSubject)
    ).toBe(true)
    expect(
      isResumeCredentialSubject({
        type: ['Something', 'RESUME']
      } as unknown as ICredentialSubject)
    ).toBe(true)
  })

  it('returns false when no type matches resume', () => {
    expect(
      isResumeCredentialSubject({
        type: ['VerifiableCredential', 'EducationCredential']
      } as unknown as ICredentialSubject)
    ).toBe(false)
  })
})

describe('isResumeCredential (vc-typed)', () => {
  it('reads the subject type off the VC (array containing Resume)', () => {
    const vc = {
      credentialSubject: { type: ['Foo', 'Resume'] }
    } as unknown as IVerifiableCredential
    expect(isResumeCredential(vc)).toBe(true)
  })

  it('matches a substring resume in the subject type', () => {
    const vc = {
      credentialSubject: { type: 'ResumeCredential' }
    } as unknown as IVerifiableCredential
    expect(isResumeCredential(vc)).toBe(true)
  })

  it('is false when the subject type does not mention resume', () => {
    const vc = {
      credentialSubject: { type: 'EducationCredential' }
    } as unknown as IVerifiableCredential
    expect(isResumeCredential(vc)).toBe(false)
  })
})

describe('isEmploymentCredential / isVolunteerCredential', () => {
  it('detects an EmploymentCredential by top-level type', () => {
    expect(
      isEmploymentCredential({
        type: ['VerifiableCredential', 'EmploymentCredential']
      } as IVerifiableCredential)
    ).toBe(true)
  })

  it('detects a VolunteeringCredential by top-level type', () => {
    expect(
      isVolunteerCredential({
        type: ['VerifiableCredential', 'VolunteeringCredential']
      } as IVerifiableCredential)
    ).toBe(true)
  })

  it('is false for unrelated types', () => {
    const vc = { type: ['VerifiableCredential'] } as IVerifiableCredential
    expect(isEmploymentCredential(vc)).toBe(false)
    expect(isVolunteerCredential(vc)).toBe(false)
  })
})
