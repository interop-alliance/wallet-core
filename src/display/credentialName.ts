/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Credential title derivation.
 *
 * Drift resolution (merged chain): DCW and Freewallet produced different titles
 * for the same credential. The merged `credentialName` keeps DCW's
 * type-specific human prefixes first (product copy its screens rely on:
 * `Recommendation From ...`, `Performance Review: ...`, the SkillClaim skill
 * name, `Employment: ... @ ...`, `Volunteer: ... @ ...`), then falls through to
 * Freewallet's more complete generic chain: top-level `vc.name`, achievement
 * name(s) JOINED with `' · '` (DCW returned only the first), skill name(s),
 * resolved person full name, `hasCredential.name`, a `'Skill Claim'` label for
 * a SkillClaimCredential, and finally `'Verifiable Credential'`.
 *
 * Deliberate behavior changes vs DCW: the final fallback is now
 * `'Verifiable Credential'` (was `'Unknown Credential'`); a multi-achievement
 * VC joins all names with `' · '`; and an `achievement` name now wins over a
 * sibling `hasCredential` name (Freewallet's chain order), where DCW preferred
 * `hasCredential`.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { typeArray } from '@interop/data-integrity-core/guards'
import { getSubject, resolvePersonFullName } from './subject.js'
import { achievementsList, skillsList } from './obv3.js'
import { isEmploymentCredential, isVolunteerCredential } from './types.js'
import { asNonEmptyString, asRecord, getTrimmedString } from './text.js'

/**
 * Freewallet's generic title chain over a resolved subject: top-level name,
 * achievement name(s), skill name(s), person full name, `hasCredential.name`,
 * a `'Skill Claim'` label, else `'Verifiable Credential'`.
 *
 * @param verifiableCredential {IVerifiableCredential}
 * @param subject {Record<string, unknown>}
 * @returns {string}
 */
export function credentialNameFrom(
  verifiableCredential: IVerifiableCredential,
  subject: Record<string, unknown>
): string {
  const topLevelName = getTrimmedString(
    (verifiableCredential as { name?: string }).name
  )
  if (topLevelName) {
    return topLevelName
  }

  const achievementNames = achievementsList(subject)
    .map(achievement => getTrimmedString(achievement.name))
    .filter((name): name is string => Boolean(name))
  if (achievementNames.length > 1) {
    return achievementNames.join(' · ')
  }
  const [firstAchievementName] = achievementNames
  if (firstAchievementName) {
    return firstAchievementName
  }

  const skillNames = skillsList(subject)
    .map(skill => getTrimmedString(skill.name))
    .filter((name): name is string => Boolean(name))
  if (skillNames.length > 1) {
    return skillNames.join(' · ')
  }
  const [firstSkillName] = skillNames
  if (firstSkillName) {
    return firstSkillName
  }

  const resumeFullName = resolvePersonFullName(subject)
  if (resumeFullName) {
    return resumeFullName
  }

  const hasCredential = asRecord(subject.hasCredential)
  const hasCredentialName = getTrimmedString(hasCredential?.name)
  if (hasCredentialName) {
    return hasCredentialName
  }

  if (typeArray(verifiableCredential.type).includes('SkillClaimCredential')) {
    return 'Skill Claim'
  }

  return 'Verifiable Credential'
}

/**
 * The display title for a credential: DCW's type-specific prefixes first, then
 * the generic {@link credentialNameFrom} chain.
 *
 * @param credential {IVerifiableCredential}
 * @returns {string}
 */
export function credentialName(credential: IVerifiableCredential): string {
  const types = typeArray(credential.type)
  const subject = asRecord(getSubject(credential)) ?? {}

  if (types.includes('https://schema.org/RecommendationCredential')) {
    const name = asNonEmptyString(subject.name)
    return name ? `Recommendation From ${name}` : 'Recommendation Credential'
  }

  if (types.includes('PerformanceReviewCredential')) {
    const employeeName = asNonEmptyString(subject.employeeName)
    return employeeName
      ? `Performance Review: ${employeeName}`
      : 'Performance Review Credential'
  }

  if (types.includes('SkillClaimCredential')) {
    const [firstSkill] = skillsList(subject)
    const skillName = asNonEmptyString(firstSkill?.name)
    if (skillName) {
      return skillName
    }
    // fall through to the generic chain (lands on 'Skill Claim')
  }

  if (isEmploymentCredential(credential)) {
    const fullName = asNonEmptyString(subject.fullName)
    const company = asNonEmptyString(subject.company)
    if (fullName && company) {
      return `Employment: ${fullName} @ ${company}`
    }
    if (fullName) {
      return `Employment: ${fullName}`
    }
    return 'Employment Credential'
  }

  if (isVolunteerCredential(credential)) {
    const fullName = asNonEmptyString(subject.fullName)
    const volunteerOrg = asNonEmptyString(subject.volunteerOrg)
    if (fullName && volunteerOrg) {
      return `Volunteer: ${fullName} @ ${volunteerOrg}`
    }
    if (fullName) {
      return `Volunteer: ${fullName}`
    }
    return 'Volunteer Credential'
  }

  return credentialNameFrom(credential, subject)
}
