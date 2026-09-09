/**
 * Unit tests for the composed keyring lookup (`src/keyring/fetch.ts`). The
 * lookup takes the unlock method's KDF parameter set as a required argument:
 * the KDF salt is what keeps two unlock methods from deriving the same unlock
 * identity, so a method that omits it must fail to compile rather than
 * silently derive the passphrase-salted identity and read the wrong unlock
 * Space. The check is type-level; `pnpm typecheck` covers this file, and an
 * `@ts-expect-error` that stops erroring fails that pass.
 */
import { describe, expect, it } from 'vitest'
import { fetchKeyringRecord } from '../../src/keyring/fetch.js'
import { KEYRING_KDF } from '../../src/keyring/kdf.js'

describe('fetchKeyringRecord', () => {
  it('refuses a call that omits the KDF parameter set at compile time', () => {
    // Never invoked: the assertion is that the omission does not type-check.
    function omitsKdf(): Promise<unknown> {
      // @ts-expect-error -- `kdf` is required; no default names a method
      return fetchKeyringRecord({
        secret: 'passphrase',
        storageServerUrl: 'https://was.example'
      })
    }
    function namesKdf(): Promise<unknown> {
      return fetchKeyringRecord({
        secret: 'passphrase',
        kdf: KEYRING_KDF,
        storageServerUrl: 'https://was.example'
      })
    }
    expect(typeof omitsKdf).toBe('function')
    expect(typeof namesKdf).toBe('function')
  })
})
