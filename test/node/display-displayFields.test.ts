/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The aggregate display projection (`getDisplayFields`) and its description /
 * criteria builders. Ported from Freewallet `credentialDisplayFields.test.ts`
 * and the `buildCredentialDescription` / `buildCriteria` cases of
 * `displayFieldsHelpers.test.ts`. `expirationDate` is a RAW ISO string.
 */
import { describe, it, expect } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import {
  getDisplayFields,
  buildCredentialDescription,
  buildCriteria
} from '../../src/display/index.js'
import { welcomeCredential } from './fixtures/display/index.js'

describe('getDisplayFields', () => {
  it('maps a simple credential using its top-level name and subject description', () => {
    const fields = getDisplayFields(welcomeCredential)
    expect(fields.credentialName).toBe('Your First Credential')
    expect(fields.credentialDescription).toBe(
      'You have successfully set up your credentials wallet!'
    )
    expect(fields.criteria).toBe('')
    expect(fields.achievementImage).toBe('')
    expect(fields.alignments).toEqual([])
  })

  it('maps an open-badge achievement into name, description, criteria, and image', () => {
    const vc = {
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      credentialSubject: {
        achievement: {
          name: 'Team Player',
          description: 'Works well with others',
          achievementType: 'Badge',
          image: { id: 'https://img/badge.png' },
          criteria: { narrative: 'Collaborate on a project' },
          alignment: [
            { targetName: 'Collaboration', targetUrl: 'https://skills/collab' }
          ]
        }
      }
    } as unknown as IVerifiableCredential

    const fields = getDisplayFields(vc)
    expect(fields.credentialName).toBe('Team Player')
    expect(fields.credentialDescription).toBe('Works well with others')
    expect(fields.criteria).toBe('Collaborate on a project')
    expect(fields.achievementType).toBe('Badge')
    expect(fields.achievementImage).toBe('https://img/badge.png')
    expect(fields.alignments).toEqual([
      {
        targetName: 'Collaboration',
        targetUrl: 'https://skills/collab',
        targetDescription: ''
      }
    ])
  })

  it('returns safe defaults when the subject is not an object', () => {
    const vc = {
      name: 'Bare Credential',
      type: ['VerifiableCredential'],
      credentialSubject: 'did:example:123'
    } as unknown as IVerifiableCredential

    const fields = getDisplayFields(vc)
    expect(fields.credentialName).toBe('Bare Credential')
    expect(fields.credentialDescription).toBe('')
    expect(fields.criteria).toBe('')
    expect(fields.achievementImage).toBe('')
    expect(fields.achievementType).toBe('')
    expect(fields.alignments).toEqual([])
  })

  it('carries a RAW ISO expiration and the recipient onto the common fields', () => {
    const vc = {
      name: 'Course Certificate',
      validUntil: '2030-01-01T00:00:00Z',
      credentialSubject: { person: { contact: { fullName: 'Ada Lovelace' } } }
    } as unknown as IVerifiableCredential

    const fields = getDisplayFields(vc)
    expect(fields.expirationDate).toBe('2030-01-01T00:00:00Z')
    expect(fields.issuedTo).toBe('Ada Lovelace')
  })
})

describe('buildCredentialDescription', () => {
  it('joins achievement, skill, and subject descriptions into paragraphs', () => {
    const subject = {
      skill: { narrative: 'Skilled worker', durationPerformed: '2 years' },
      description: 'Subject description'
    }
    const achievements = [{ description: 'Achievement description' }]
    expect(buildCredentialDescription(subject, achievements)).toBe(
      'Achievement description\n\nSkilled worker\n\nDuration: 2 years\n\nSubject description'
    )
  })

  it('returns an empty string when there is nothing to describe', () => {
    expect(buildCredentialDescription({}, [])).toBe('')
  })
})

describe('buildCriteria', () => {
  it('returns a single achievement criteria narrative unlabeled', () => {
    expect(
      buildCriteria({}, [{ criteria: { narrative: 'Complete the course' } }])
    ).toBe('Complete the course')
  })

  it('labels criteria blocks when there are multiple achievements', () => {
    const achievements = [
      { name: 'First', criteria: { narrative: 'Do A' } },
      { name: 'Second', criteria: { narrative: 'Do B' } }
    ]
    expect(buildCriteria({}, achievements)).toBe(
      '**First**\n\nDo A\n\n**Second**\n\nDo B'
    )
  })

  it('falls back to hasCredential competencyRequired', () => {
    expect(
      buildCriteria(
        { hasCredential: { competencyRequired: 'Pass the exam' } },
        []
      )
    ).toBe('Pass the exam')
  })
})
