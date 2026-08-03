/**
 * Unit tests for the login-time roster policy
 * (`src/clients/rosterPolicy.ts`): which roster failures refuse a session and
 * which keep the cached key for an offline start, and that an absent roster is
 * not a failure.
 */
import { describe, expect, it, vi } from 'vitest'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'
import { checkPukRosterAtLogin } from '../../src/clients/rosterPolicy.js'
import {
  PukRosterContinuityError,
  PukRosterIntegrityError,
  PukRosterUnwrapError
} from '../../src/keys/pukRoster.js'

/**
 * A descriptor store whose read behaves as instructed.
 *
 * @param read {Function}
 * @returns {EncryptionDescriptorStore}
 */
function storeReading(read: () => unknown): EncryptionDescriptorStore {
  return { read } as unknown as EncryptionDescriptorStore
}

const clientKeyAgreementKey = { id: 'did:key:zSelf#z6LSTwin' } as never

describe('checkPukRosterAtLogin', () => {
  it('resolves null when the account has no roster yet', async () => {
    const onRosterRead = vi.fn()
    const read = await checkPukRosterAtLogin({
      store: storeReading(() => null),
      clientKeyAgreementKey,
      onRosterRead
    })
    expect(read).toBeNull()
    expect(onRosterRead).not.toHaveBeenCalled()
  })

  it('keeps the cached key for an offline start', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const read = await checkPukRosterAtLogin({
      store: storeReading(() => {
        throw new TypeError('Failed to fetch')
      }),
      clientKeyAgreementKey
    })
    expect(read).toBeNull()
    expect(warn).toHaveBeenCalled()
    warn.mockRestore()
  })

  it('refuses the session on each of the three roster errors', async () => {
    const errors = [
      new PukRosterContinuityError({ pinnedEpochId: 'did:key:zOld' }),
      new PukRosterIntegrityError('fabricated'),
      new PukRosterUnwrapError('no wrap')
    ]
    for (const error of errors) {
      await expect(
        checkPukRosterAtLogin({
          store: storeReading(() => {
            throw error
          }),
          clientKeyAgreementKey
        })
      ).rejects.toBe(error)
    }
  })
})
