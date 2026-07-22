/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Freewallet's aggregate display projection: one pass over a VC producing the
 * flat field set the credential card and detail view render. Dates stay RAW
 * (the `expirationDate` field is an ISO string, not a formatted one -- the
 * raw-values seam); the title comes from the merged {@link credentialName}.
 *
 * `credentialNameFrom` lives in `credentialName.ts` (co-located with the merged
 * title fn that calls it); `buildCredentialDescription` / `buildCriteria` are
 * Freewallet's, kept here as they are used only by `getDisplayFields` (and
 * covered by the ported helper tests).
 */
import type {
  IAchievement,
  IAlignment,
  IVerifiableCredential
} from '@interop/data-integrity-core'
import { credentialName } from './credentialName.js'
import { getSubject, extractIssuedTo } from './subject.js'
import { getExpirationDate } from './validity.js'
import {
  achievementsList,
  skillsList,
  getSkillImage,
  getEvidenceImage,
  getAchievementImage,
  getAchievementType
} from './obv3.js'
import { normalizeAlignments } from './alignment.js'
import { asRecord, getTrimmedString } from './text.js'

/** The flat display projection of a VC for the card / detail view. */
export interface CredentialDisplayFields {
  credentialName: string
  issuedTo: string
  /** Raw ISO expiration string (`''` when none). */
  expirationDate: string
  credentialDescription: string
  criteria: string
  achievementImage: string
  achievementType: string
  alignments: IAlignment[]
}

/**
 * Joins achievement descriptions, skill narratives / durations, and various
 * subject description fields into a single paragraph-separated string.
 *
 * @param subject {Record<string, unknown>}
 * @param achievements {Record<string, unknown>[]}
 * @returns {string}
 */
export function buildCredentialDescription(
  subject: Record<string, unknown>,
  achievements: Record<string, unknown>[]
): string {
  const descriptionParts: string[] = []

  for (const achievement of achievements) {
    const achievementDescription = getTrimmedString(achievement.description)
    if (achievementDescription) {
      descriptionParts.push(achievementDescription)
    }
  }

  for (const skill of skillsList(subject)) {
    const narrative = getTrimmedString(skill.narrative)
    if (narrative) {
      descriptionParts.push(narrative)
    }
    const skillDuration = getTrimmedString(skill.durationPerformed)
    if (skillDuration) {
      descriptionParts.push(`Duration: ${skillDuration}`)
    }
  }

  const subjectNarrative = getTrimmedString(subject.narrative)
  if (subjectNarrative) {
    descriptionParts.push(subjectNarrative)
  }

  const evidenceDescription = getTrimmedString(subject.evidenceDescription)
  if (evidenceDescription) {
    descriptionParts.push(evidenceDescription)
  }

  const duration = getTrimmedString(subject.duration)
  if (duration) {
    descriptionParts.push(`Duration: ${duration}`)
  }

  const evidenceLink = getTrimmedString(subject.evidenceLink)
  if (evidenceLink) {
    descriptionParts.push(`Evidence: ${evidenceLink}`)
  }

  const subjectDescription = getTrimmedString(subject.description)
  if (subjectDescription) {
    descriptionParts.push(subjectDescription)
  }

  const hasCredential = asRecord(subject.hasCredential)
  const hasCredentialDescription = getTrimmedString(hasCredential?.description)
  if (hasCredentialDescription) {
    descriptionParts.push(hasCredentialDescription)
  }

  return descriptionParts.join('\n\n')
}

/**
 * Builds the criteria text from the achievements' criteria narratives (labeled
 * with the achievement name when there is more than one), falling back to the
 * subject's `hasCredential.competencyRequired`.
 *
 * @param subject {Record<string, unknown>}
 * @param achievements {Record<string, unknown>[]}
 * @returns {string}
 */
export function buildCriteria(
  subject: Record<string, unknown>,
  achievements: Record<string, unknown>[]
): string {
  const criteriaBlocks = achievements
    .map(achievement => {
      const criteria = asRecord(achievement.criteria)
      const narrative = getTrimmedString(criteria?.narrative)
      if (!narrative) {
        return ''
      }

      const achievementName = getTrimmedString(achievement.name)
      if (achievements.length > 1 && achievementName) {
        return `**${achievementName}**\n\n${narrative}`
      }
      return narrative
    })
    .filter((criteriaBlock): criteriaBlock is string => Boolean(criteriaBlock))
  const criteriaText = criteriaBlocks.join('\n\n')
  if (criteriaText) {
    return criteriaText
  }

  const hasCredential = asRecord(subject.hasCredential)
  return getTrimmedString(hasCredential?.competencyRequired)
}

/**
 * Projects a VC to its flat display field set. The title uses the merged
 * {@link credentialName}; `expirationDate` is a raw ISO string.
 *
 * @param verifiableCredential {IVerifiableCredential}
 * @returns {CredentialDisplayFields}
 */
export function getDisplayFields(
  verifiableCredential: IVerifiableCredential
): CredentialDisplayFields {
  const commonFields = {
    credentialName: credentialName(verifiableCredential),
    issuedTo: extractIssuedTo(verifiableCredential),
    expirationDate: getExpirationDate(verifiableCredential) ?? ''
  }

  const subject = asRecord(getSubject(verifiableCredential))
  if (!subject) {
    return {
      ...commonFields,
      credentialDescription: '',
      criteria: '',
      achievementImage: '',
      achievementType: '',
      alignments: []
    }
  }

  const achievements = achievementsList(subject)
  const primaryAchievement = achievements[0] as IAchievement | undefined
  const skills = skillsList(subject)
  const alignments = achievements.flatMap(achievement =>
    normalizeAlignments((achievement as { alignment?: unknown }).alignment)
  )
  const evidenceRaw = (verifiableCredential as Record<string, unknown>).evidence
  const evidence = Array.isArray(evidenceRaw)
    ? evidenceRaw
    : evidenceRaw
      ? [evidenceRaw]
      : []

  return {
    ...commonFields,
    credentialDescription: buildCredentialDescription(subject, achievements),
    criteria: buildCriteria(subject, achievements),
    achievementImage:
      getAchievementImage(primaryAchievement) ||
      getSkillImage(skills) ||
      getEvidenceImage(evidence),
    achievementType: getAchievementType(primaryAchievement),
    alignments
  }
}
