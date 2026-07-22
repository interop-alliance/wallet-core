/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * OBv3 subject helpers. Ported from DCW `extractNameFromOBV3Identifier.test.ts`
 * and the achievement/skill/image helper cases of Freewallet
 * `displayFieldsHelpers.test.ts`.
 */
import { describe, it, expect } from 'vitest'
import type { ICredentialSubject } from '@interop/data-integrity-core'
import {
  extractNameFromOBV3Identifier,
  achievementsList,
  skillsList,
  getSkillImage,
  getEvidenceImage,
  getAchievementImage,
  getAchievementType
} from '../../src/display/index.js'

describe('extractNameFromOBV3Identifier', () => {
  it('returns undefined when there is no identifier object', () => {
    expect(extractNameFromOBV3Identifier({ id: '123' })).toBeUndefined()
  })

  it('returns undefined when the identifier object is empty', () => {
    expect(extractNameFromOBV3Identifier({ identifier: {} })).toBeUndefined()
  })

  it('returns the identityHash of the first non-hashed identifier', () => {
    const subject: ICredentialSubject = {
      identifier: { identityType: 'name', identityHash: 'Jane Doe' }
    }
    expect(extractNameFromOBV3Identifier(subject)).toBe('Jane Doe')
  })

  it('reads from an array of identifiers', () => {
    const subject: ICredentialSubject = {
      identifier: [{ identityType: 'name', identityHash: 'Jane Doe' }]
    }
    expect(extractNameFromOBV3Identifier(subject)).toBe('Jane Doe')
  })
})

describe('achievementsList / skillsList', () => {
  it('wraps a single achievement object in an array', () => {
    expect(achievementsList({ achievement: { name: 'Badge' } })).toEqual([
      { name: 'Badge' }
    ])
  })

  it('returns an achievement array unchanged', () => {
    const list = [{ name: 'One' }, { name: 'Two' }]
    expect(achievementsList({ achievement: list })).toEqual(list)
  })

  it('returns an empty array when there is no achievement', () => {
    expect(achievementsList({})).toEqual([])
  })

  it('wraps a single skill object in an array', () => {
    expect(skillsList({ skill: { name: 'Welding' } })).toEqual([
      { name: 'Welding' }
    ])
  })

  it('returns an empty array when there is no skill', () => {
    expect(skillsList({})).toEqual([])
  })
})

describe('getSkillImage', () => {
  it('reads the id from an object image on the first skill', () => {
    expect(getSkillImage([{ image: { id: 'https://img/skill.png' } }])).toBe(
      'https://img/skill.png'
    )
  })

  it('reads a string image on the first skill', () => {
    expect(getSkillImage([{ image: 'https://img/skill.png' }])).toBe(
      'https://img/skill.png'
    )
  })

  it('returns an empty string for an empty skill list', () => {
    expect(getSkillImage([])).toBe('')
  })
})

describe('getEvidenceImage', () => {
  it('returns the id of the first image-like evidence item', () => {
    const evidence = [
      { id: 'https://example.com/doc', name: 'A document' },
      { id: 'https://example.com/photo.png', name: 'A photo' }
    ]
    expect(getEvidenceImage(evidence)).toBe('https://example.com/photo.png')
  })

  it('matches on an image-like name even when the id has no extension', () => {
    const evidence = [{ id: 'https://example.com/x', name: 'shot.jpg' }]
    expect(getEvidenceImage(evidence)).toBe('https://example.com/x')
  })

  it('returns an empty string when no evidence looks like an image', () => {
    expect(getEvidenceImage([{ id: 'https://example.com/doc' }])).toBe('')
  })
})

describe('getAchievementImage / getAchievementType', () => {
  it('returns a string image directly', () => {
    expect(
      getAchievementImage({ image: 'https://img/badge.png' } as never)
    ).toBe('https://img/badge.png')
  })

  it('reads the id from an object image', () => {
    expect(
      getAchievementImage({ image: { id: 'https://img/badge.png' } } as never)
    ).toBe('https://img/badge.png')
  })

  it('returns an empty string when there is no image', () => {
    expect(getAchievementImage(undefined)).toBe('')
  })

  it('returns a string achievement type', () => {
    expect(getAchievementType({ achievementType: 'Badge' } as never)).toBe(
      'Badge'
    )
  })

  it('returns an empty string when the type is missing', () => {
    expect(getAchievementType(undefined)).toBe('')
  })
})
