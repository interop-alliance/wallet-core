/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The one fragment reader for verification-method ids. Every id this stack
 * handles is minted as `${did}#${multibase}`, so the fragment IS the key's
 * public multibase -- which is what lets a did:key kid and a
 * `did:webvh`-spelled verification method be compared as key material rather
 * than as strings. The extraction used to exist in four spellings that
 * disagreed on the degenerate inputs; it lives here instead, dependency-free,
 * because `resourceLog` is the lowest layer the webvh, keys, and descriptors
 * modules all import.
 */

/**
 * The fragment after the LAST `#` of a DID URL or verification-method id, or
 * `undefined` when the id carries no `#` at all or its fragment is empty (a
 * trailing `#`).
 *
 * The last `#` wins on a degenerate double-`#` id: ids are minted as
 * `${did}#${multibase}`, so the final segment is the key material either way,
 * and reading it from the end also survives a DID whose method-specific id
 * ever grows a `#`.
 *
 * `undefined` is the only absent-fragment posture here. A caller that needs a
 * different one -- throwing on a fragmentless id, or falling back to the whole
 * string -- wraps this helper explicitly at its own call site, so the choice
 * stays visible where it is made.
 *
 * @param id {string}
 * @returns {string | undefined}
 */
export function vmFragmentOf(id: string): string | undefined {
  const hashIndex = id.lastIndexOf('#')
  if (hashIndex === -1 || hashIndex === id.length - 1) {
    return undefined
  }
  return id.slice(hashIndex + 1)
}
