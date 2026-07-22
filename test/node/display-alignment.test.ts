/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Alignment helpers. Ported from DCW `alignment.test.ts` (URL-validating
 * `getValidAlignments`) and `openBadgeWithAlignments.test.ts` (retargeted to run
 * `getValidAlignments` over the mock's achievement alignments), plus the
 * `normalizeAlignments` cases of Freewallet `displayFieldsHelpers.test.ts`. Both
 * functions are kept -- they answer different questions.
 */
import { describe, it, expect } from 'vitest'
import type { IAlignment } from '@interop/data-integrity-core'
import {
  getValidAlignments,
  normalizeAlignments
} from '../../src/display/index.js'
import { mockOpenBadgeWithAlignments } from './fixtures/display/index.js'

describe('getValidAlignments', () => {
  it('returns an empty array for undefined / non-array / empty input', () => {
    expect(getValidAlignments(undefined)).toEqual([])
    expect(getValidAlignments(null as never)).toEqual([])
    expect(getValidAlignments([])).toEqual([])
  })

  it('filters out alignments without a targetName', () => {
    expect(
      getValidAlignments([
        {
          targetUrl: 'https://example.com',
          targetDescription: 'Test description'
        }
      ])
    ).toEqual([])
  })

  it('includes alignments with a targetName but no targetUrl', () => {
    expect(getValidAlignments([{ targetName: 'Test Name' }])).toEqual([
      { targetName: 'Test Name', targetDescription: undefined }
    ])
  })

  it('marks an invalid targetUrl as non-clickable', () => {
    expect(
      getValidAlignments([
        { targetName: 'Test Name', targetUrl: 'invalid-url' }
      ])
    ).toEqual([
      {
        targetName: 'Test Name',
        targetUrl: 'invalid-url',
        targetDescription: undefined,
        isValidUrl: false
      }
    ])
  })

  it('returns valid alignments with a valid targetUrl', () => {
    const alignments: IAlignment[] = [
      {
        targetName: 'Requirements Analysis',
        targetUrl:
          'https://credentialfinder.org/credential/20229/Requirements_Analysis',
        targetDescription: 'This is a description'
      }
    ]
    expect(getValidAlignments(alignments)).toEqual([
      {
        targetName: 'Requirements Analysis',
        targetUrl:
          'https://credentialfinder.org/credential/20229/Requirements_Analysis',
        targetDescription: 'This is a description',
        isValidUrl: true
      }
    ])
  })

  it('ignores targetCode / targetFramework / targetType fields', () => {
    const result = getValidAlignments([
      {
        targetName: 'Requirements Analysis',
        targetUrl:
          'https://credentialfinder.org/credential/20229/Requirements_Analysis',
        targetCode: 'ce-cf4dee18-7cea-443a-b920-158a0762c6bf',
        targetFramework: 'Edmonds College Course Catalog',
        targetType: 'some-type'
      }
    ])
    expect(result[0]).not.toHaveProperty('targetCode')
    expect(result[0]).not.toHaveProperty('targetFramework')
    expect(result[0]).not.toHaveProperty('targetType')
  })

  it('handles a mix of valid and invalid alignments', () => {
    const alignments: IAlignment[] = [
      { targetName: 'Valid Alignment', targetUrl: 'https://example.com' },
      { targetName: 'Valid - No URL' },
      { targetUrl: 'https://example2.com' },
      { targetName: 'Invalid URL', targetUrl: 'not-a-url' },
      {
        targetName: 'Another Valid',
        targetUrl: 'https://example3.com',
        targetDescription: 'With description'
      }
    ]
    expect(getValidAlignments(alignments)).toEqual([
      {
        targetName: 'Valid Alignment',
        targetUrl: 'https://example.com',
        targetDescription: undefined,
        isValidUrl: true
      },
      { targetName: 'Valid - No URL', targetDescription: undefined },
      {
        targetName: 'Invalid URL',
        targetUrl: 'not-a-url',
        targetDescription: undefined,
        isValidUrl: false
      },
      {
        targetName: 'Another Valid',
        targetUrl: 'https://example3.com',
        targetDescription: 'With description',
        isValidUrl: true
      }
    ])
  })
})

describe('getValidAlignments over the OBv3 mock', () => {
  it('keeps named alignments and validates their URLs', () => {
    const subject = mockOpenBadgeWithAlignments.credentialSubject as {
      achievement: { alignment?: IAlignment[] }
    }
    const result = getValidAlignments(subject.achievement.alignment)
    // 4 named alignments (all have a targetName); 2 have valid URLs.
    expect(result).toHaveLength(4)
    expect(result.filter(a => a.isValidUrl)).toHaveLength(2)
    expect(result[0]!.targetName).toBe('Requirements Analysis')
    expect(result[3]!.isValidUrl).toBe(false)
  })
})

describe('normalizeAlignments', () => {
  it('normalizes a single alignment object into an array', () => {
    expect(
      normalizeAlignments({
        targetName: '  CCSS  ',
        targetUrl: 'https://a.co',
        targetDescription: 'desc'
      })
    ).toEqual([
      {
        targetName: 'CCSS',
        targetUrl: 'https://a.co',
        targetDescription: 'desc'
      }
    ])
  })

  it('drops alignments without a target name', () => {
    expect(
      normalizeAlignments([{ targetName: '' }, { targetName: 'HTML' }])
    ).toEqual([{ targetName: 'HTML', targetUrl: '', targetDescription: '' }])
  })

  it('returns an empty array for falsy input', () => {
    expect(normalizeAlignments(undefined)).toEqual([])
  })
})
