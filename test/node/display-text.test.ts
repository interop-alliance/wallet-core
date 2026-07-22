/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * String / record coercion helpers (`asNonEmptyString`, `getTrimmedString`,
 * `asRecord`). Merged from DCW `presentation.ts` and Freewallet
 * `displayFieldsHelpers.ts` behavior.
 */
import { describe, it, expect } from 'vitest'
import {
  asNonEmptyString,
  getTrimmedString,
  asRecord
} from '../../src/display/index.js'

describe('asNonEmptyString', () => {
  it('trims and returns a non-empty string', () => {
    expect(asNonEmptyString('  hi  ')).toBe('hi')
  })

  it('stringifies a non-string value', () => {
    expect(asNonEmptyString(3)).toBe('3')
  })

  it('returns null for null / undefined / empty', () => {
    expect(asNonEmptyString(null)).toBeNull()
    expect(asNonEmptyString(undefined)).toBeNull()
    expect(asNonEmptyString('   ')).toBeNull()
  })
})

describe('getTrimmedString', () => {
  it('trims a string value', () => {
    expect(getTrimmedString('  hi  ')).toBe('hi')
  })

  it('returns an empty string for non-string values', () => {
    expect(getTrimmedString(42)).toBe('')
    expect(getTrimmedString(undefined)).toBe('')
    expect(getTrimmedString({})).toBe('')
  })
})

describe('asRecord', () => {
  it('returns the value for a plain object', () => {
    const value = { a: 1 }
    expect(asRecord(value)).toBe(value)
  })

  it('returns undefined for null, primitives, and missing values', () => {
    expect(asRecord(null)).toBeUndefined()
    expect(asRecord(undefined)).toBeUndefined()
    expect(asRecord('string')).toBeUndefined()
    expect(asRecord(42)).toBeUndefined()
  })
})
