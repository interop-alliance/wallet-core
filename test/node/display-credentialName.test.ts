/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The merged credential title chain (`credentialName`) and the generic
 * sub-chain (`credentialNameFrom`). Ported from DCW `credentialName.test.ts`
 * and Freewallet `credentialTitle.test.ts`, retuned to the merged behavior:
 * final fallback is `'Verifiable Credential'`; multiple achievements JOIN with
 * `' · '`; an achievement name wins over a sibling `hasCredential` name.
 */
import { describe, it, expect } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { credentialName, credentialNameFrom } from '../../src/display/index.js'
import { welcomeCredential } from './fixtures/display/index.js'

describe('credentialName', () => {
  it('returns the name from a hasCredential property', () => {
    const credential = {
      credentialSubject: {
        hasCredential: { name: 'Bachelor of Science in Computer Science' }
      }
    } as unknown as IVerifiableCredential
    expect(credentialName(credential)).toBe(
      'Bachelor of Science in Computer Science'
    )
  })

  it('returns the name from an achievement property', () => {
    const credential = {
      credentialSubject: {
        achievement: { name: 'Digital Marketing Certificate' }
      }
    } as unknown as IVerifiableCredential
    expect(credentialName(credential)).toBe('Digital Marketing Certificate')
  })

  it('joins all achievement names when the achievement is an array (merged behavior)', () => {
    const credential = {
      credentialSubject: {
        achievement: [
          { name: 'First Achievement' },
          { name: 'Second Achievement' }
        ]
      }
    } as unknown as IVerifiableCredential
    // DCW returned only 'First Achievement'; the merged chain joins with ' · '.
    expect(credentialName(credential)).toBe(
      'First Achievement · Second Achievement'
    )
  })

  it('prefers an achievement name over a sibling hasCredential name (merged order)', () => {
    const credential = {
      credentialSubject: {
        hasCredential: { name: 'Has Credential Name' },
        achievement: { name: 'Achievement Name' }
      }
    } as unknown as IVerifiableCredential
    // DCW preferred hasCredential; the merged chain checks achievements first.
    expect(credentialName(credential)).toBe('Achievement Name')
  })

  it('returns the top-level vc.name (Freewallet read DCW lacked)', () => {
    expect(credentialName(welcomeCredential)).toBe('Your First Credential')
  })

  it('falls back to "Verifiable Credential" when no name is found', () => {
    const credential = {
      credentialSubject: {}
    } as unknown as IVerifiableCredential
    expect(credentialName(credential)).toBe('Verifiable Credential')
  })

  it('falls back to "Verifiable Credential" when the achievement has no name', () => {
    const credential = {
      credentialSubject: { achievement: {} }
    } as unknown as IVerifiableCredential
    expect(credentialName(credential)).toBe('Verifiable Credential')
  })

  it('returns a recommendation title for a RecommendationCredential', () => {
    const credential = {
      type: [
        'VerifiableCredential',
        'https://schema.org/RecommendationCredential'
      ],
      credentialSubject: { name: 'Ross Geller' }
    } as unknown as IVerifiableCredential
    expect(credentialName(credential)).toBe('Recommendation From Ross Geller')
  })

  it('returns a performance-review title for a PerformanceReviewCredential', () => {
    const credential = {
      type: ['VerifiableCredential', 'PerformanceReviewCredential'],
      credentialSubject: { employeeName: 'Omar Salah' }
    } as unknown as IVerifiableCredential
    expect(credentialName(credential)).toBe('Performance Review: Omar Salah')
  })

  it('returns an employment title with company', () => {
    const credential = {
      type: ['VerifiableCredential', 'EmploymentCredential'],
      credentialSubject: { fullName: 'Sam Rivera', company: 'Acme' }
    } as unknown as IVerifiableCredential
    expect(credentialName(credential)).toBe('Employment: Sam Rivera @ Acme')
  })

  it('returns the skill name for a SkillClaimCredential', () => {
    const credential = {
      type: ['VerifiableCredential', 'SkillClaimCredential'],
      credentialSubject: { skill: [{ name: 'Welding' }] }
    } as unknown as IVerifiableCredential
    expect(credentialName(credential)).toBe('Welding')
  })

  it('labels a SkillClaimCredential "Skill Claim" when it has no skill name', () => {
    const credential = {
      type: ['VerifiableCredential', 'SkillClaimCredential'],
      credentialSubject: {}
    } as unknown as IVerifiableCredential
    expect(credentialName(credential)).toBe('Skill Claim')
  })
})

describe('credentialNameFrom', () => {
  it('prefers the top-level credential name', () => {
    const vc = { name: 'Top Name' } as unknown as IVerifiableCredential
    expect(credentialNameFrom(vc, { achievement: { name: 'Badge' } })).toBe(
      'Top Name'
    )
  })

  it('joins multiple achievement names with a separator', () => {
    const vc = {} as IVerifiableCredential
    const subject = { achievement: [{ name: 'One' }, { name: 'Two' }] }
    expect(credentialNameFrom(vc, subject)).toBe('One · Two')
  })

  it('uses a single achievement name', () => {
    const vc = {} as IVerifiableCredential
    expect(
      credentialNameFrom(vc, { achievement: { name: 'Solo Badge' } })
    ).toBe('Solo Badge')
  })

  it('labels a SkillClaimCredential when nothing else names it', () => {
    const vc = {
      type: ['VerifiableCredential', 'SkillClaimCredential']
    } as unknown as IVerifiableCredential
    expect(credentialNameFrom(vc, {})).toBe('Skill Claim')
  })

  it('falls back to a generic name', () => {
    const vc = { type: ['VerifiableCredential'] } as IVerifiableCredential
    expect(credentialNameFrom(vc, {})).toBe('Verifiable Credential')
  })
})
