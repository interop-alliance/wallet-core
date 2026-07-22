/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The cross-app disagreement cases pinned in one place: where DCW and Freewallet
 * historically produced different titles / recipients, this fixes the merged
 * behavior so both the `credentialName` and `extractIssuedTo` seams stay honest.
 */
import { describe, it, expect } from 'vitest'
import {
  credentialName,
  extractIssuedTo,
  isResumeCredential
} from '../../src/display/index.js'
import {
  multiAchievementCredential,
  personContactFullNameCredential,
  obv3NonNameIdentifierCredential,
  resumeCredential,
  skillClaimCredential
} from './fixtures/display/index.js'

describe('cross-app title reconciliation (credentialName)', () => {
  it('joins ALL achievement names (Freewallet), not just the first (DCW)', () => {
    expect(credentialName(multiAchievementCredential)).toBe(
      'First Achievement · Second Achievement'
    )
  })

  it('titles a SkillClaimCredential by its skill name', () => {
    expect(credentialName(skillClaimCredential)).toBe('Welding')
  })

  it('titles a resume via its person full name', () => {
    expect(credentialName(resumeCredential)).toBe('Grace Hopper')
  })
})

describe('cross-app recipient reconciliation (extractIssuedTo)', () => {
  it('resolves a nested person.contact.fullName (Freewallet), which DCW missed', () => {
    expect(extractIssuedTo(personContactFullNameCredential)).toBe(
      'Ada Lovelace'
    )
  })

  it('SKIPS a non-name OBv3 identityHash (Freewallet name guard), which DCW returned', () => {
    // No person name and no name-typed identifier and no top-level name -> ''.
    expect(extractIssuedTo(obv3NonNameIdentifierCredential)).toBe('')
  })
})

describe('cross-app resume detection', () => {
  it('detects a resume from the subject type array', () => {
    expect(isResumeCredential(resumeCredential)).toBe(true)
  })
})
