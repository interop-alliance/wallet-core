/**
 * Client annex host conformance tests: which service descriptions claim the
 * client annex profile, and the refusal a host without the claim gets.
 */
import { describe, expect, it } from 'vitest'
import type { ServiceDescription } from '@interop/was-client'

import {
  assertHostClaimsClientAnnexProfile,
  CLIENT_ANNEX_PROFILE_IDENTIFIER,
  hostClaimsClientAnnexProfile
} from '../../src/clientAnnex/index.js'

const SERVICE_URL = 'https://was.example/service'

function describedWith(annexEntries?: unknown): ServiceDescription {
  return {
    url: SERVICE_URL,
    specs: {
      'https://w3id.org/pws': [{ version: '0.5' }],
      ...(annexEntries !== undefined && {
        [CLIENT_ANNEX_PROFILE_IDENTIFIER]: annexEntries
      })
    }
  } as unknown as ServiceDescription
}

describe('hostClaimsClientAnnexProfile', () => {
  it('accepts an entry of version alone', () => {
    expect(
      hostClaimsClientAnnexProfile({
        serviceDescription: describedWith([{ version: '0.1' }])
      })
    ).toBe(true)
  })

  it('accepts an entry carrying a url beside the version', () => {
    expect(
      hostClaimsClientAnnexProfile({
        serviceDescription: describedWith([
          { version: '0.1', url: 'https://example.org/client-annex/' }
        ])
      })
    ).toBe(true)
  })

  it('accepts a supported entry listed beside an unsupported one', () => {
    expect(
      hostClaimsClientAnnexProfile({
        serviceDescription: describedWith([
          { version: '9.0' },
          { version: '0.1' }
        ])
      })
    ).toBe(true)
  })

  it('refuses a description with no client annex key', () => {
    expect(
      hostClaimsClientAnnexProfile({ serviceDescription: describedWith() })
    ).toBe(false)
  })

  it('refuses an empty entry list', () => {
    expect(
      hostClaimsClientAnnexProfile({ serviceDescription: describedWith([]) })
    ).toBe(false)
  })

  it('ignores members it does not know', () => {
    expect(
      hostClaimsClientAnnexProfile({
        serviceDescription: describedWith([
          { version: '0.1', features: ['ladder-delegation-bounds'] }
        ])
      })
    ).toBe(true)
  })

  it('refuses an entry whose url is not a string', () => {
    for (const url of [42, null, ['https://example.org/client-annex/']]) {
      expect(
        hostClaimsClientAnnexProfile({
          serviceDescription: describedWith([{ version: '0.1', url }])
        })
      ).toBe(false)
    }
  })

  it('refuses an entry whose version this library does not speak', () => {
    expect(
      hostClaimsClientAnnexProfile({
        serviceDescription: describedWith([{ version: '0.2' }])
      })
    ).toBe(false)
  })

  it('refuses malformed entries', () => {
    for (const entries of [
      { version: '0.1' },
      ['0.1'],
      [null],
      [[{ version: '0.1' }]],
      [{ version: 0.1 }],
      [{}]
    ]) {
      expect(
        hostClaimsClientAnnexProfile({
          serviceDescription: describedWith(entries)
        })
      ).toBe(false)
    }
  })
})

describe('assertHostClaimsClientAnnexProfile', () => {
  it('passes a host that claims the profile', () => {
    expect(() =>
      assertHostClaimsClientAnnexProfile({
        serviceDescription: describedWith([{ version: '0.1' }])
      })
    ).not.toThrow()
  })

  it('refuses a host without the claim as an incompatible server', () => {
    let caught: unknown
    try {
      assertHostClaimsClientAnnexProfile({
        serviceDescription: describedWith()
      })
    } catch (err) {
      caught = err
    }
    expect((caught as Error).name).toBe('IncompatibleServerError')
    expect((caught as Error).message).toContain(CLIENT_ANNEX_PROFILE_IDENTIFIER)
    expect((caught as { requestUrl?: string }).requestUrl).toBe(SERVICE_URL)
  })
})
