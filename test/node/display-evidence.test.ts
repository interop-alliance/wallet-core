/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Portfolio evidence extraction (`portfolioEvidenceFrom` /
 * `evidenceFromCredential`). Ported from DCW `evidence.test.ts`.
 */
import { describe, it, expect } from 'vitest'
import {
  portfolioEvidenceFrom,
  evidenceFromCredential
} from '../../src/display/index.js'

describe('portfolioEvidenceFrom', () => {
  it('parses an evidence array of objects', () => {
    const raw = [
      { name: 'Fake Evidence Link1', url: 'https://google.com/' },
      { name: 'Fake Evidence Link2', url: 'https://youtube.com/' }
    ]
    expect(portfolioEvidenceFrom(raw)).toEqual([
      { name: 'Fake Evidence Link1', url: 'https://google.com/' },
      { name: 'Fake Evidence Link2', url: 'https://youtube.com/' }
    ])
  })

  it('parses a string url item inside the array', () => {
    expect(portfolioEvidenceFrom([' https://example.com/foo '])).toEqual([
      { name: 'https://example.com/foo', url: 'https://example.com/foo' }
    ])
  })

  it('drops items without a valid url', () => {
    const raw = [
      { name: 'bad', url: undefined },
      { name: 'also bad', url: null },
      { name: 'good', url: 'https://example.com/' }
    ]
    expect(portfolioEvidenceFrom(raw)).toEqual([
      { name: 'good', url: 'https://example.com/' }
    ])
  })

  it('falls back to url as name when name is missing or empty', () => {
    expect(
      portfolioEvidenceFrom([
        { name: '', url: 'https://example.com/a' },
        { url: 'https://example.com/b' }
      ])
    ).toEqual([
      { name: 'https://example.com/a', url: 'https://example.com/a' },
      { name: 'https://example.com/b', url: 'https://example.com/b' }
    ])
  })

  it('drops null, undefined, and non-object items', () => {
    expect(
      portfolioEvidenceFrom([
        null,
        undefined,
        123,
        true,
        { url: 'https://example.com' }
      ])
    ).toEqual([{ name: 'https://example.com', url: 'https://example.com' }])
  })

  it('handles a single non-array evidence object', () => {
    expect(
      portfolioEvidenceFrom({
        name: 'Single Evidence',
        url: 'https://example.com/single'
      })
    ).toEqual([{ name: 'Single Evidence', url: 'https://example.com/single' }])
  })

  it('handles a single non-array string evidence item', () => {
    expect(portfolioEvidenceFrom(' https://example.com/string ')).toEqual([
      { name: 'https://example.com/string', url: 'https://example.com/string' }
    ])
  })

  it('returns an empty array for empty or invalid input', () => {
    expect(portfolioEvidenceFrom([])).toEqual([])
    expect(portfolioEvidenceFrom(null)).toEqual([])
    expect(portfolioEvidenceFrom(undefined)).toEqual([])
  })
})

describe('evidenceFromCredential', () => {
  it('prefers a top-level evidence array', () => {
    const credential = {
      evidence: [{ name: 'Doc', url: 'https://example.com/doc' }],
      credentialSubject: { portfolio: [{ url: 'https://example.com/ignored' }] }
    }
    expect(evidenceFromCredential(credential)).toEqual([
      { name: 'Doc', url: 'https://example.com/doc' }
    ])
  })

  it('falls back to the subject portfolio when there is no evidence', () => {
    const credential = {
      credentialSubject: { portfolio: [{ url: 'https://example.com/p' }] }
    }
    expect(evidenceFromCredential(credential)).toEqual([
      { name: 'https://example.com/p', url: 'https://example.com/p' }
    ])
  })
})
