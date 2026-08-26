/**
 * Unit tests for the shared ceremony vocabulary (`src/space/ceremony.ts`):
 * every id is kebab-case, the ids are unique, and the array is reachable
 * from the package root barrel as well as the `space` subpath.
 */
import { describe, expect, it } from 'vitest'
import { CEREMONY_IDS as ROOT_CEREMONY_IDS } from '../../src/index.js'
import { CEREMONY_IDS } from '../../src/space/ceremony.js'

describe('CEREMONY_IDS', () => {
  it('is kebab-case, lowercase ASCII only', () => {
    for (const id of CEREMONY_IDS) {
      expect(id).toMatch(/^[a-z]+(-[a-z]+)*$/)
    }
  })

  it('has no duplicate ids', () => {
    expect(new Set(CEREMONY_IDS).size).toBe(CEREMONY_IDS.length)
  })

  it('is importable from the package root barrel', () => {
    expect(ROOT_CEREMONY_IDS).toBe(CEREMONY_IDS)
  })
})
