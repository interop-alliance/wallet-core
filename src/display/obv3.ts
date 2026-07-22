/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Open Badges v3.0 subject helpers: normalizing the `achievement` / `skill`
 * arrays and pulling out achievement images / types, the recipient name from an
 * OBv3 `identifier`, and an image URL from an evidence list.
 *
 * Drift resolution: DCW open-coded the achievement/skill array handling inline
 * inside its subject render mapper, while Freewallet had these as explicit,
 * separately-tested helpers -- Freewallet's factored helpers win. DCW's
 * standalone `extractNameFromOBV3Identifier` is kept verbatim (it has its own
 * test and is used as a fallback branch by the subject render mapper).
 */
import type {
  IAchievement,
  ICredentialSubject,
  IOpenBadgeSubject
} from '@interop/data-integrity-core'
import { asRecord, getTrimmedString } from './text.js'

/**
 * The recipient display name carried in an OBv3 `identifier` entry: the
 * `identityHash` of the first identifier that has one and is not marked
 * `hashed: true`. Returns `undefined` when no such identifier is present.
 *
 * Note: unlike the name-guarded path in `extractIssuedTo`, this returns the
 * hash of ANY identifier (regardless of `identityType`), matching DCW's
 * historical behavior. Callers wanting only name-typed identifiers use
 * `extractIssuedTo`.
 *
 * @param credentialSubject {IOpenBadgeSubject | ICredentialSubject}
 * @returns {string | undefined}
 */
export function extractNameFromOBV3Identifier(
  credentialSubject: IOpenBadgeSubject | ICredentialSubject
): string | undefined {
  if (!credentialSubject?.identifier) {
    return undefined
  }

  const identifiers = Array.isArray(credentialSubject.identifier)
    ? credentialSubject.identifier
    : [credentialSubject.identifier]

  const identifierWithHash = identifiers.find(
    i => i.identityHash && (i?.hashed === false || i?.hashed === undefined)
  )

  return identifierWithHash?.identityHash || undefined
}

/**
 * Normalizes a subject's `achievement` field to an array of records (a single
 * achievement object is wrapped; a missing one yields `[]`).
 *
 * @param subject {Record<string, unknown>}
 * @returns {Record<string, unknown>[]}
 */
export function achievementsList(
  subject: Record<string, unknown>
): Record<string, unknown>[] {
  const achievementRaw = subject.achievement
  if (achievementRaw == null) {
    return []
  }
  if (Array.isArray(achievementRaw)) {
    return achievementRaw as Record<string, unknown>[]
  }
  return [achievementRaw as Record<string, unknown>]
}

/**
 * Normalizes a subject's `skill` field to an array of records (a single skill
 * object is wrapped; a missing one yields `[]`).
 *
 * @param subject {Record<string, unknown>}
 * @returns {Record<string, unknown>[]}
 */
export function skillsList(
  subject: Record<string, unknown>
): Record<string, unknown>[] {
  const skillRaw = subject.skill
  if (skillRaw == null) {
    return []
  }
  if (Array.isArray(skillRaw)) {
    return skillRaw as Record<string, unknown>[]
  }
  return [skillRaw as Record<string, unknown>]
}

/**
 * The image URL of the first skill in a list: an object image's `id`, or a
 * string image, else `''`.
 *
 * @param skills {Record<string, unknown>[]}
 * @returns {string}
 */
export function getSkillImage(skills: Record<string, unknown>[]): string {
  const first = skills[0]
  if (!first) {
    return ''
  }
  const image = asRecord(first.image)
  if (image) {
    return getTrimmedString(image.id)
  }
  return getTrimmedString(first.image as string)
}

const IMAGE_EXTENSION_RE = /\.(jpe?g|png|gif|webp|svg|avif)(\?|$)/i

/**
 * The `id` (URL) of the first evidence item that looks like an image -- either
 * its `id` or `name` ends in a known image extension -- else `''`.
 *
 * @param evidence {unknown[]}
 * @returns {string}
 */
export function getEvidenceImage(evidence: unknown[]): string {
  for (const ev of evidence) {
    const item = asRecord(ev)
    if (!item) {
      continue
    }
    const id = getTrimmedString(item.id)
    const name = getTrimmedString(item.name)
    if (id && (IMAGE_EXTENSION_RE.test(id) || IMAGE_EXTENSION_RE.test(name))) {
      return id
    }
  }
  return ''
}

/**
 * The achievement's image URL: a string image directly, or an object image's
 * `id`, else `''`.
 *
 * @param primaryAchievement {IAchievement | undefined}
 * @returns {string}
 */
export function getAchievementImage(primaryAchievement?: IAchievement): string {
  if (!primaryAchievement?.image) {
    return ''
  }
  if (typeof primaryAchievement.image === 'string') {
    return primaryAchievement.image
  }
  return primaryAchievement.image.id ?? ''
}

/**
 * The achievement's `achievementType` when it is a string, else `''`.
 *
 * @param primaryAchievement {IAchievement | undefined}
 * @returns {string}
 */
export function getAchievementType(primaryAchievement?: IAchievement): string {
  if (typeof primaryAchievement?.achievementType === 'string') {
    return primaryAchievement.achievementType
  }
  return ''
}
