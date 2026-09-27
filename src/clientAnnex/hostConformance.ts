/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Host conformance for the client annex profile: whether a storage server's
 * service description claims the server enforces the client-annex delegation
 * clause. The clause bounds what a ladder verification method may delegate.
 * It is a restriction layered on ordinary zcap verification, so a server that
 * does not implement it accepts exactly what the clause exists to refuse. A
 * wallet therefore signs up only on a host whose description carries the
 * claim. The check runs once per account: the later ceremonies that publish a
 * ladder verification method do not repeat it, and nothing re-checks a host
 * that drops the claim after signup. The claim is self-reported, so the check
 * catches a host whose software does not enforce the clause, not one that
 * lies about it.
 *
 * The claim is the profile's entry in the description's `specs` object, under
 * {@link CLIENT_ANNEX_PROFILE_IDENTIFIER}. The entry carries a `version` and
 * an optional `url`. The rule follows was-client's reading of the base WAS
 * entry: a member this library does not know is ignored, and a member it
 * does know is checked before it counts. An entry whose version this library
 * does not speak, or whose `url` is present but not a string, reads as
 * absent.
 */
import { IncompatibleServerError } from '@interop/was-client'
import type { ServiceDescription } from '@interop/was-client'

/**
 * The client annex profile's persistent identifier: the key of its entry in a
 * service description's `specs` object. Provisional until the `pws` namespace
 * is registered.
 */
export const CLIENT_ANNEX_PROFILE_IDENTIFIER =
  'https://w3id.org/pws/client-annex'

/**
 * The versions of the client annex profile this library checks a host
 * against. `0.1` is the clause with its five admission predicates. A change
 * to what the clause admits is a new version, added here once the ladder
 * ceremonies are checked against it.
 */
export const CLIENT_ANNEX_PROFILE_VERSIONS: readonly string[] = ['0.1']

/**
 * Whether a service description claims the client annex profile at a version
 * this library speaks.
 *
 * @param options {object}
 * @param options.serviceDescription {ServiceDescription}   the host's
 *   discovered service description
 * @returns {boolean}
 */
export function hostClaimsClientAnnexProfile({
  serviceDescription
}: {
  serviceDescription: ServiceDescription
}): boolean {
  const specs: unknown = serviceDescription.specs
  if (typeof specs !== 'object' || specs === null) {
    return false
  }
  const entries: unknown = (specs as Record<string, unknown>)[
    CLIENT_ANNEX_PROFILE_IDENTIFIER
  ]
  if (!Array.isArray(entries)) {
    return false
  }
  return entries.some(entry => isUnderstoodEntry(entry))
}

/**
 * Refuses a host whose service description does not claim the client annex
 * profile. Called before a signup's first durable write, so a refused signup
 * leaves nothing behind.
 *
 * @param options {object}
 * @param options.serviceDescription {ServiceDescription}   the host's
 *   discovered service description
 * @returns {void}
 * @throws {IncompatibleServerError}   when the description lists no client
 *   annex entry this library understands
 */
export function assertHostClaimsClientAnnexProfile({
  serviceDescription
}: {
  serviceDescription: ServiceDescription
}): void {
  if (hostClaimsClientAnnexProfile({ serviceDescription })) {
    return
  }
  throw new IncompatibleServerError(
    `The server at "${serviceDescription.url}" lists no version of ` +
      `${CLIENT_ANNEX_PROFILE_IDENTIFIER} this client speaks (supported: ` +
      `${CLIENT_ANNEX_PROFILE_VERSIONS.join(', ')}), so it may not bound what ` +
      'a ladder verification method can delegate. No ladder verification ' +
      'method is published on it.',
    { requestUrl: serviceDescription.url }
  )
}

/**
 * Whether one version entry is a client annex claim this library understands:
 * an object carrying a supported `version`, whose `url`, when present, is a
 * string. Members this library does not know are ignored.
 *
 * @param entry {unknown}
 * @returns {boolean}
 */
function isUnderstoodEntry(entry: unknown): boolean {
  if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
    return false
  }
  const { version, url } = entry as { version?: unknown; url?: unknown }
  if (url !== undefined && typeof url !== 'string') {
    return false
  }
  return (
    typeof version === 'string' &&
    CLIENT_ANNEX_PROFILE_VERSIONS.includes(version)
  )
}
