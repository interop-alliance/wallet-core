/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `was-link` QR payload parser: round-trip, and rejection of every malformed
 * / wrong-version / non-link input (so the in-app scanner never mis-handles an
 * unrelated QR).
 */
import { describe, it, expect } from 'vitest'

import {
  buildWasLinkPayload,
  encodeWasLinkSecret,
  parseWasLinkPayload
} from '../../src/space/wasLink.js'

describe('was-link payload', () => {
  it('round-trips serverUrl + passphrase through build/parse', () => {
    const raw = buildWasLinkPayload({
      serverUrl: 'https://storage.example',
      passphrase: 'correct horse battery staple'
    })
    const parsed = parseWasLinkPayload(raw)
    expect(parsed.serverUrl).toBe('https://storage.example')
    expect(parsed.secret).toBe('correct horse battery staple')
  })

  it('decodes the secret back to the STRING passphrase (not bytes)', () => {
    // The secret must survive as the identical string the web login would type,
    // so the same account is joined (fromSecret is type-sensitive).
    const passphrase = 'p@ss with spaces + Ünicode'
    const raw = JSON.stringify({
      v: 1,
      t: 'was-link',
      serverUrl: 'https://s',
      secret: encodeWasLinkSecret(passphrase)
    })
    expect(parseWasLinkPayload(raw).secret).toBe(passphrase)
  })

  it('accepts a padded base64url secret too', () => {
    // 'ab' -> 'YWI' (no pad); force a padded variant and confirm it still decodes.
    const raw = JSON.stringify({
      v: 1,
      t: 'was-link',
      serverUrl: 'https://s',
      secret: 'YWI='
    })
    expect(parseWasLinkPayload(raw).secret).toBe('ab')
  })

  it('rejects non-JSON', () => {
    expect(() => parseWasLinkPayload('not json')).toThrow()
  })

  it('rejects a different payload type', () => {
    expect(() =>
      parseWasLinkPayload(
        JSON.stringify({ v: 1, t: 'vcapi', serverUrl: 'x', secret: 'x' })
      )
    ).toThrow()
  })

  it('rejects an unsupported future version', () => {
    expect(() =>
      parseWasLinkPayload(
        JSON.stringify({
          v: 2,
          t: 'was-link',
          serverUrl: 'https://s',
          secret: encodeWasLinkSecret('x')
        })
      )
    ).toThrow()
  })

  it('rejects a missing serverUrl or secret', () => {
    expect(() =>
      parseWasLinkPayload(JSON.stringify({ v: 1, t: 'was-link', secret: 'x' }))
    ).toThrow()
    expect(() =>
      parseWasLinkPayload(
        JSON.stringify({ v: 1, t: 'was-link', serverUrl: 'https://s' })
      )
    ).toThrow()
  })

  it('rejects a cleartext http:// server (secret would travel to it)', () => {
    expect(() =>
      parseWasLinkPayload(
        JSON.stringify({
          v: 1,
          t: 'was-link',
          serverUrl: 'http://attacker.example',
          secret: encodeWasLinkSecret('x')
        })
      )
    ).toThrow()
  })

  it('rejects a non-URL / non-http(s) server', () => {
    for (const serverUrl of [
      'not a url',
      'ftp://host/x',
      'javascript:alert(1)'
    ]) {
      expect(() =>
        parseWasLinkPayload(
          JSON.stringify({
            v: 1,
            t: 'was-link',
            serverUrl,
            secret: encodeWasLinkSecret('x')
          })
        )
      ).toThrow()
    }
  })

  it('allows http:// only for loopback dev hosts', () => {
    const raw = JSON.stringify({
      v: 1,
      t: 'was-link',
      serverUrl: 'http://localhost:3000',
      secret: encodeWasLinkSecret('x')
    })
    expect(parseWasLinkPayload(raw).serverUrl).toBe('http://localhost:3000')
  })
})
