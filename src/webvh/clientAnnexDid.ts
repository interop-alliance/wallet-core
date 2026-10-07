/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The client annex DID string's shape, on its own import-free leaf so a base
 * module can recognize and parse an annex DID without the annex module: the
 * generation id convention, the parse of an annex did:webvh into its host,
 * auxiliary Space id, and generation id, and the predicate over that parse.
 * The annex module (`clientAnnex/log.ts`, `clientAnnex/grantRevocation.ts`)
 * re-exports these, so its public surface is unchanged.
 */

/**
 * The literal prefix of every generation collection's name. Wire-level and
 * permanent: orphan discovery is a plain prefix match over the auxiliary
 * Space's collection listing, and the generation id embeds in every annex
 * DID string ever published.
 */
export const GENERATION_ID_PREFIX = 'gen-'

/**
 * The full generation id shape: the literal prefix plus 16 base64url
 * characters.
 */
const GENERATION_ID_PATTERN = /^gen-[A-Za-z0-9_-]{16}$/

/**
 * Refuses anything that is not a well-formed generation id. Run by every
 * annex builder that takes a generation id, so a malformed one is refused
 * before it can reach a DID string, an HKDF label, or a collection id.
 *
 * @param generationId {string}
 */
export function assertGenerationId(generationId: string): void {
  if (!GENERATION_ID_PATTERN.test(generationId)) {
    throw new Error(
      `Not a generation id: "${generationId}" (expected "gen-" plus 16 ` +
        'base64url characters).'
    )
  }
}

/**
 * The three permanent substrings of an annex DID string, as
 * {@link parseClientAnnexDid} reads them.
 */
export interface ClientAnnexDidParts {
  host: string
  spaceId: string
  generationId: string
}

/**
 * The structural parse behind {@link parseClientAnnexDid} and
 * {@link clientAnnexDidParts}: the segments alone, with the generation id
 * not yet checked against its shape, so the throwing parse can name which
 * of the two refused.
 *
 * @param did {string}
 * @returns {ClientAnnexDidParts | undefined}
 */
function splitClientAnnexDid(did: string): ClientAnnexDidParts | undefined {
  const parts = did.split(':')
  const generationId = parts[parts.length - 1]
  const spaceId = parts[parts.length - 2]
  const host = parts[3]
  if (
    parts.length < 7 ||
    parts[0] !== 'did' ||
    parts[1] !== 'webvh' ||
    parts[parts.length - 3] !== 'space' ||
    generationId === undefined ||
    spaceId === undefined ||
    spaceId.length === 0 ||
    host === undefined ||
    host.length === 0
  ) {
    return undefined
  }
  return { host: decodeURIComponent(host), spaceId, generationId }
}

/**
 * Parses the host, the auxiliary Space id and the generation id out of an
 * annex DID string, or returns `undefined` when the string is not an annex
 * did:webvh. All three are permanent substrings of every annex DID by
 * construction: the generation id is the final path segment of the annex
 * DID (`did:webvh:<scid>:<host>:...:space:<spaceId>:<generationId>`), and it
 * is the generation-identifying half of the annex rung HKDF
 * labels, so this parse is what lets an enrollee derive its writing key from
 * the pointer alone -- no log read, no registry.
 *
 * The host is the method-specific id's second segment, percent-decoded (a
 * port rides as `%3A` inside the one segment). A caller enumerating Spaces
 * out of a log compares it against the deployment it is talking to: an
 * account that has migrated hosts carries entries naming the old one, which
 * this deployment cannot address.
 *
 * @param did {string}
 * @returns {ClientAnnexDidParts | undefined}
 */
export function parseClientAnnexDid(
  did: string
): ClientAnnexDidParts | undefined {
  const parts = splitClientAnnexDid(did)
  if (parts === undefined || !GENERATION_ID_PATTERN.test(parts.generationId)) {
    return undefined
  }
  return parts
}

/**
 * {@link parseClientAnnexDid}, refusing with a throw: one naming the DID
 * when its segments are not an annex did:webvh's, and the generation-id
 * refusal when the segments are but the generation id is malformed.
 *
 * @param options {object}
 * @param options.did {string}   an annex did:webvh string
 * @returns {ClientAnnexDidParts}
 */
export function clientAnnexDidParts({
  did
}: {
  did: string
}): ClientAnnexDidParts {
  const parts = splitClientAnnexDid(did)
  if (parts === undefined) {
    throw new Error(`Not a client annex did:webvh: "${did}".`)
  }
  assertGenerationId(parts.generationId)
  return parts
}

/**
 * Whether a DID string is a client annex did:webvh, by the same parse
 * {@link parseClientAnnexDid} applies.
 *
 * @param did {string}
 * @returns {boolean}
 */
export function isClientAnnexDid(did: string): boolean {
  return parseClientAnnexDid(did) !== undefined
}
