/**
 * Tests for `isResourceLogRefusal` (`src/resourceLog/errors.ts`): the one
 * implementation of which resource-log refusals a reader must NOT paper over
 * with a cached copy, shared by `descriptors/acquire.ts` and
 * `clients/rosterPolicy.ts`. The truth table is the contract -- the chain-head
 * pin's `rollback` carve-out, the license class staying soft by decision, and
 * the `err.name` matching that must survive a second copy of the package --
 * so it is pinned here directly rather than only through the two call sites'
 * behavior.
 */
import { describe, expect, it } from 'vitest'
import {
  ResourceLogContinuityError,
  ResourceLogIntegrityError
} from '@interop/vh-resource-log'
import {
  isResourceLogRefusal,
  ResourceLogLicenseError
} from '../../src/resourceLog/index.js'

/**
 * An error carrying only a `name` (and optionally a `reason`), standing in for
 * a refusal raised inside an app-injected seam that resolved to a different
 * copy of this package: `instanceof` misses it, `err.name` does not.
 */
function foreignRefusal(name: string, reason?: string): Error {
  const err = new Error(`served by another copy: ${name}`)
  err.name = name
  if (reason !== undefined) {
    ;(err as { reason?: string }).reason = reason
  }
  return err
}

describe('isResourceLogRefusal', () => {
  it('refuses a fabricated log', () => {
    expect(
      isResourceLogRefusal(new ResourceLogIntegrityError('fabricated'))
    ).toBe(true)
  })

  it('refuses every continuity reason but rollback', () => {
    for (const reason of ['fork', 'scid-switch', 'method-switch'] as const) {
      expect(
        isResourceLogRefusal(
          new ResourceLogContinuityError({ reason, pinnedHead: '3-a' })
        )
      ).toBe(true)
    }
  })

  it('carves out a rollback: reconcilable divergence, possibly lag', () => {
    expect(
      isResourceLogRefusal(
        new ResourceLogContinuityError({
          reason: 'rollback',
          pinnedHead: '3-a'
        })
      )
    ).toBe(false)
  })

  it('keeps a license refusal soft on a read', () => {
    // Decided, not omitted: the log is not corrupt and the signer genuinely
    // holds the credential, and the class does its work pre-write.
    expect(
      isResourceLogRefusal(new ResourceLogLicenseError('unlicensed'))
    ).toBe(false)
  })

  it('matches on err.name, so a second package copy still refuses', () => {
    expect(
      isResourceLogRefusal(foreignRefusal('ResourceLogIntegrityError'))
    ).toBe(true)
    expect(
      isResourceLogRefusal(foreignRefusal('ResourceLogContinuityError', 'fork'))
    ).toBe(true)
    expect(
      isResourceLogRefusal(
        foreignRefusal('ResourceLogContinuityError', 'rollback')
      )
    ).toBe(false)
  })

  it('refuses a continuity error carrying no reason at all', () => {
    // Only the literal `rollback` earns the carve-out: a refusal whose reason
    // was stripped in transit must not degrade to the cached copy.
    expect(
      isResourceLogRefusal(foreignRefusal('ResourceLogContinuityError'))
    ).toBe(true)
  })

  it('passes transport failures and non-errors through as soft', () => {
    for (const err of [
      null,
      undefined,
      'not an error',
      {},
      new Error('fetch failed'),
      new TypeError('NetworkError')
    ]) {
      expect(isResourceLogRefusal(err)).toBe(false)
    }
  })
})
