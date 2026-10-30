/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `pws-link` QR payload parser: round-trip, and rejection of every malformed
 * / wrong-version / non-link input (so the in-app scanner never mis-handles an
 * unrelated QR), plus the structural recognizer the input classifier takes.
 */
import { describe, it, expect } from 'vitest'

import {
  buildPwsLinkPayload,
  encodePwsLinkSecret,
  isPwsLinkPayload,
  parsePwsLinkPayload
} from '../../src/space/pwsLink.js'

describe('isPwsLinkPayload', () => {
  it('recognizes a built payload, whitespace included', () => {
    const raw = buildPwsLinkPayload({
      baseServerUrl: 'https://storage.example',
      passphrase: 'correct horse'
    })
    expect(isPwsLinkPayload(raw)).toBe(true)
    expect(isPwsLinkPayload(`  ${raw}\n`)).toBe(true)
  })

  it('matches on the discriminator alone, without validating', () => {
    expect(isPwsLinkPayload('{"t":"pws-link"}')).toBe(true)
  })

  it('leaves unrelated JSON, non-JSON, and other discriminators alone', () => {
    expect(
      isPwsLinkPayload('{"@context":[],"type":["VerifiableCredential"]}')
    ).toBe(false)
    expect(isPwsLinkPayload('{"t":"other"}')).toBe(false)
    expect(isPwsLinkPayload('freewallet-connect:abc')).toBe(false)
    expect(isPwsLinkPayload('{not json')).toBe(false)
    expect(isPwsLinkPayload('[]')).toBe(false)
  })
})

describe('pws-link payload', () => {
  it('round-trips baseServerUrl + passphrase through build/parse', () => {
    const raw = buildPwsLinkPayload({
      baseServerUrl: 'https://storage.example',
      passphrase: 'correct horse battery staple'
    })
    const parsed = parsePwsLinkPayload(raw)
    expect(parsed.baseServerUrl).toBe('https://storage.example')
    expect(parsed.secret).toBe('correct horse battery staple')
  })

  it('decodes the secret back to the STRING passphrase (not bytes)', () => {
    // The secret must survive as the identical string the web login would type,
    // so the same account is joined (fromSecret is type-sensitive).
    const passphrase = 'p@ss with spaces + Ünicode'
    const raw = JSON.stringify({
      v: 1,
      t: 'pws-link',
      baseServerUrl: 'https://s',
      secret: encodePwsLinkSecret(passphrase)
    })
    expect(parsePwsLinkPayload(raw).secret).toBe(passphrase)
  })

  it('accepts a padded base64url secret too', () => {
    // 'ab' -> 'YWI' (no pad); force a padded variant and confirm it still decodes.
    const raw = JSON.stringify({
      v: 1,
      t: 'pws-link',
      baseServerUrl: 'https://s',
      secret: 'YWI='
    })
    expect(parsePwsLinkPayload(raw).secret).toBe('ab')
  })

  it('rejects non-JSON', () => {
    expect(() => parsePwsLinkPayload('not json')).toThrow()
  })

  it('rejects a different payload type', () => {
    expect(() =>
      parsePwsLinkPayload(
        JSON.stringify({ v: 1, t: 'vcapi', baseServerUrl: 'x', secret: 'x' })
      )
    ).toThrow()
  })

  it('rejects an unsupported future version', () => {
    expect(() =>
      parsePwsLinkPayload(
        JSON.stringify({
          v: 2,
          t: 'pws-link',
          baseServerUrl: 'https://s',
          secret: encodePwsLinkSecret('x')
        })
      )
    ).toThrow()
  })

  it('rejects a missing baseServerUrl or secret', () => {
    expect(() =>
      parsePwsLinkPayload(JSON.stringify({ v: 1, t: 'pws-link', secret: 'x' }))
    ).toThrow()
    expect(() =>
      parsePwsLinkPayload(
        JSON.stringify({ v: 1, t: 'pws-link', baseServerUrl: 'https://s' })
      )
    ).toThrow()
  })

  it('rejects a cleartext http:// server (secret would travel to it)', () => {
    expect(() =>
      parsePwsLinkPayload(
        JSON.stringify({
          v: 1,
          t: 'pws-link',
          baseServerUrl: 'http://attacker.example',
          secret: encodePwsLinkSecret('x')
        })
      )
    ).toThrow()
  })

  it('rejects a non-URL / non-http(s) server', () => {
    for (const baseServerUrl of [
      'not a url',
      'ftp://host/x',
      'javascript:alert(1)'
    ]) {
      expect(() =>
        parsePwsLinkPayload(
          JSON.stringify({
            v: 1,
            t: 'pws-link',
            baseServerUrl,
            secret: encodePwsLinkSecret('x')
          })
        )
      ).toThrow()
    }
  })

  it('allows http:// only for loopback dev hosts', () => {
    const raw = JSON.stringify({
      v: 1,
      t: 'pws-link',
      baseServerUrl: 'http://localhost:3000',
      secret: encodePwsLinkSecret('x')
    })
    expect(parsePwsLinkPayload(raw).baseServerUrl).toBe('http://localhost:3000')
  })

  it('treats an IPv6 localhost server as a loopback dev host', () => {
    const raw = JSON.stringify({
      v: 1,
      t: 'pws-link',
      baseServerUrl: 'http://[::1]:8080',
      secret: encodePwsLinkSecret('x')
    })
    expect(parsePwsLinkPayload(raw).baseServerUrl).toBe('http://[::1]:8080')
  })
})
