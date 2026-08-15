/**
 * Unit tests for the shared verification-method fragment reader
 * (`src/resourceLog/vmFragment.ts`). The helper is the one place the four
 * former spellings of "multibase = fragment after #" agree, so these pin the
 * decided semantics -- last `#` wins, absent or empty fragment is `undefined`
 * -- and the one deliberate wrapper posture (`multibaseOf`'s whole-string
 * fallback for a fragmentless KMS key alias).
 */
import { describe, expect, it } from 'vitest'
import { vmFragmentOf } from '../../src/resourceLog/vmFragment.js'
import { multibaseOf } from '../../src/webvh/didWeb.js'

const multibase = 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'

describe('vmFragmentOf', () => {
  it('reads the fragment of a `${did}#${multibase}` id', () => {
    expect(vmFragmentOf(`did:key:${multibase}#${multibase}`)).toBe(multibase)
    expect(
      vmFragmentOf(`did:webvh:scid:example.com:space:abc:id#${multibase}`)
    ).toBe(multibase)
  })

  it('reads the fragment of a DID URL carrying query parameters', () => {
    expect(
      vmFragmentOf(`did:webvh:scid:example.com?versionId=3#${multibase}`)
    ).toBe(multibase)
  })

  it('resolves an id with no `#` to undefined', () => {
    expect(vmFragmentOf(multibase)).toBeUndefined()
    expect(vmFragmentOf('did:key:z6Mkabc')).toBeUndefined()
  })

  it('resolves a trailing `#` (empty fragment) to undefined', () => {
    expect(vmFragmentOf('did:key:z6Mkabc#')).toBeUndefined()
  })

  it('resolves an empty id to undefined', () => {
    expect(vmFragmentOf('')).toBeUndefined()
  })

  it('takes the LAST segment of a degenerate double-`#` id', () => {
    expect(vmFragmentOf(`did:example:1#first#${multibase}`)).toBe(multibase)
  })
})

describe('multibaseOf', () => {
  it('reads the fragment of a verification-method id', () => {
    expect(multibaseOf(`did:web:example.com#${multibase}`)).toBe(multibase)
  })

  it('reads a fragmentless key alias back whole', () => {
    expect(multibaseOf(multibase)).toBe(multibase)
  })
})
