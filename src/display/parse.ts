/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Credential input parsing: turning decoded JSON (or a raw user / QR string)
 * into an array of Verifiable Credentials. File reading and network transport
 * stay app-side -- `resolveCredentialsInput` takes an injected `fetchUrl` so the
 * library never imports an HTTP client (DCW passes its `fetchWithTimeout`,
 * Freewallet its CORS-proxy `fetchFromURL`).
 *
 * Drift resolution: `credentialsFromJSON` (Freewallet) and
 * `extractCredentialsFrom` (DCW) both survive -- the former accepts an array /
 * a bare VC / a VP wrapper from a JSON string, the latter routes an
 * already-decoded object. Both now share the data-integrity-core shape guards
 * instead of open-coding the `type` checks. Freewallet's
 * `ResolveCredentialsInputError` code taxonomy is kept; DCW's
 * `VPQR_UNSUPPORTED_MESSAGE` constant is exported for apps that surface it.
 */
import type {
  IVerifiableCredential,
  IVerifiablePresentation
} from '@interop/data-integrity-core'
import {
  isVerifiableCredential,
  isVerifiablePresentation
} from '@interop/data-integrity-core/guards'

/** Message DCW surfaced for the (now unsupported) VPQR `VP1-` input. */
export const VPQR_UNSUPPORTED_MESSAGE =
  'VPQR encoded credentials are not supported.'

/** Coded failure of {@link resolveCredentialsInput}. */
export class ResolveCredentialsInputError extends Error {
  readonly code: 'empty' | 'invalid_input' | 'none_found' | 'vpqr_unsupported'
  constructor(
    code: 'empty' | 'invalid_input' | 'none_found' | 'vpqr_unsupported'
  ) {
    super(code)
    this.name = 'ResolveCredentialsInputError'
    this.code = code
  }
}

/**
 * Decodes one or more Verifiable Credentials from a JSON string: an array of
 * VCs (non-credential entries filtered out), a Verifiable Presentation wrapping
 * one or many credentials, or a single VC object. Throws when nothing decodes.
 *
 * @param text {string}
 * @returns {IVerifiableCredential[]}
 */
export function credentialsFromJSON(text: string): IVerifiableCredential[] {
  const data = JSON.parse(text)

  if (Array.isArray(data)) {
    const vcs = data.filter(item => isVerifiableCredential(item))
    if (vcs.length > 0) {
      return vcs
    }
    throw new Error('Array did not contain any Verifiable Credentials.')
  }

  if (
    isVerifiablePresentation(data) &&
    data &&
    typeof data === 'object' &&
    'verifiableCredential' in data
  ) {
    const wrapped = (data as IVerifiablePresentation).verifiableCredential!
    return Array.isArray(wrapped) ? wrapped : [wrapped]
  }

  if (isVerifiableCredential(data)) {
    return [data]
  }

  throw new Error('Could not decode Verifiable Credential(s) from the JSON.')
}

/**
 * Extracts the VCs from an already-decoded object: a bare VC becomes a
 * single-element array, a VP yields its `verifiableCredential` (VC-vs-VP
 * detection runs the VC check first), anything else yields `null`.
 *
 * @param obj {IVerifiableCredential | IVerifiablePresentation}
 * @returns {IVerifiableCredential[] | null}
 */
export function extractCredentialsFrom(
  obj: IVerifiableCredential | IVerifiablePresentation
): IVerifiableCredential[] | null {
  if (isVerifiableCredential(obj)) {
    return [obj]
  }
  if (isVerifiablePresentation(obj) && 'verifiableCredential' in obj) {
    const verifiableCredential = obj.verifiableCredential!
    if (Array.isArray(verifiableCredential)) {
      return verifiableCredential
    }
    return [verifiableCredential]
  }
  return null
}

/**
 * Normalizes raw user / QR input into an array of VCs. A URL (http/https) is
 * fetched via the injected `fetchUrl` and its body parsed; raw JSON / JSON-LD
 * (`{` or `[`) is parsed directly; a `VP1-` (VPQR) prefix is detected but not
 * supported. Throws a coded {@link ResolveCredentialsInputError} on each
 * failure path.
 *
 * @param options {object}
 * @param options.raw {string} the raw input text
 * @param options.fetchUrl {(url: string) => Promise<string>} fetches a URL's
 *   body text (app-provided transport)
 * @returns {Promise<IVerifiableCredential[]>}
 */
export async function resolveCredentialsInput({
  raw,
  fetchUrl
}: {
  raw: string
  fetchUrl: (url: string) => Promise<string>
}): Promise<IVerifiableCredential[]> {
  const trimmed = raw.trimStart()
  if (!trimmed) {
    throw new ResolveCredentialsInputError('empty')
  }

  let credentials: IVerifiableCredential[]

  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    const jsonText = await fetchUrl(trimmed.trim())
    credentials = credentialsFromJSON(jsonText)
  } else if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    credentials = credentialsFromJSON(trimmed)
  } else if (trimmed.startsWith('VP1-')) {
    throw new ResolveCredentialsInputError('vpqr_unsupported')
  } else {
    throw new ResolveCredentialsInputError('invalid_input')
  }

  if (credentials.length === 0) {
    throw new ResolveCredentialsInputError('none_found')
  }

  return credentials
}
