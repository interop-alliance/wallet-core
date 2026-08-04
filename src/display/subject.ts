/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Credential-subject readers: pulling the (first) subject out of a VC, deriving
 * the recipient display name, and projecting the OBv3-flavored subject render
 * fields.
 *
 * Drift resolution:
 * - `getSubject` was identical in both apps -- take either.
 * - Recipient-name resolution DIVERGED. Freewallet's `extractIssuedTo` +
 *   `resolvePersonFullName` win as the vc-level recipient resolver: they walk a
 *   deeper person/contact structure (`person.contact.fullName`, string
 *   `person.name`, `person.name.formattedName` / `.name`, `subject.name`) and
 *   guard the OBv3 identifier on `identityType === 'name'` (more correct than
 *   DCW's "any identityHash").
 * - `credentialSubjectRenderInfo` keeps DCW's subject-level shape and field set
 *   (used by the OBv3 card renderer) but returns RAW `startDate` / `endDate`
 *   ISO strings instead of moment-formatted `startDateFmt` / `endDateFmt` (the
 *   raw-values seam); each app re-applies its own date formatting.
 */
import type {
  IAchievement,
  IAlignment,
  ICredentialSubject,
  IVerifiableCredential
} from '@interop/data-integrity-core'
import { extractNameFromOBV3Identifier } from './obv3.js'
import { imageSourceFrom } from './image.js'
import { asRecord, getTrimmedString, recordList } from './text.js'

/**
 * The subject render fields for the credential detail / card view. All dates
 * are RAW ISO strings; the app formats them.
 */
export interface SubjectRenderInfo {
  subjectName: string | null
  issuedTo: string | null
  degreeName: string | null
  description: string | null
  criteria: string | null
  numberOfCredits: string | null
  startDate: string | null
  endDate: string | null
  achievementImage: string | null
  achievementType: string | null
  alignment: IAlignment[] | undefined
}

/**
 * The (first) credential subject. Partially supports VCs with multiple
 * `credentialSubject` entries by picking the first one.
 *
 * @param vc {IVerifiableCredential}
 * @returns {ICredentialSubject}
 */
export function getSubject(vc: IVerifiableCredential): ICredentialSubject {
  const { credentialSubject } = vc
  if (Array.isArray(credentialSubject)) {
    return credentialSubject[0] as ICredentialSubject
  }
  return credentialSubject
}

/**
 * Resolves a display name from a subject's person / contact structure, in
 * order: `person.contact.fullName`, a string `person.name`, an object
 * `person.name.formattedName`, `person.name.name`, then `subject.name`.
 * Returns `''` when none is present.
 *
 * @param subject {Record<string, unknown>}
 * @returns {string}
 */
export function resolvePersonFullName(
  subject: Record<string, unknown>
): string {
  const person = asRecord(subject.person)
  const contact = asRecord(person?.contact)

  const contactFullName = getTrimmedString(contact?.fullName)
  if (contactFullName) {
    return contactFullName
  }

  const personName = getTrimmedString(person?.name)
  if (personName) {
    return personName
  }

  const personNameRecord = asRecord(person?.name)
  if (personNameRecord) {
    const formattedName = getTrimmedString(personNameRecord.formattedName)
    if (formattedName) {
      return formattedName
    }

    const fallbackPersonName = getTrimmedString(personNameRecord.name)
    if (fallbackPersonName) {
      return fallbackPersonName
    }
  }

  return getTrimmedString(subject.name)
}

/**
 * The recipient name a credential was issued to: the resolved person full name,
 * else a name-typed OBv3 `identifier` hash, else the top-level credential
 * `name`. Returns `''` when nothing resolves.
 *
 * @param verifiableCredential {IVerifiableCredential}
 * @returns {string}
 */
export function extractIssuedTo(
  verifiableCredential: IVerifiableCredential
): string {
  const subject = asRecord(getSubject(verifiableCredential))
  if (!subject) {
    return getTrimmedString((verifiableCredential as { name?: string }).name)
  }

  const resolvedName = resolvePersonFullName(subject)
  if (resolvedName) {
    return resolvedName
  }

  if (Array.isArray(subject.identifier)) {
    const nameEntry = subject.identifier.find(
      (identifier: {
        identityType?: string
        type?: string
        identityHash?: string
      }) => identifier?.identityType === 'name' || identifier?.type === 'name'
    ) as { identityHash?: string } | undefined
    if (nameEntry?.identityHash) {
      return nameEntry.identityHash
    }
  }

  return getTrimmedString((verifiableCredential as { name?: string }).name)
}

/**
 * Projects a credential subject to the render fields used by the OBv3 card /
 * detail view. Dates are RAW ISO strings (see {@link SubjectRenderInfo}).
 *
 * Every field is read through a shape guard: a missing, primitive, or
 * array-shaped subject (and a `degree` / `achievement` of any shape) renders
 * the all-null fallback instead of throwing.
 *
 * @param credentialSubject {ICredentialSubject}
 * @returns {SubjectRenderInfo}
 */
export function credentialSubjectRenderInfo(
  credentialSubject: ICredentialSubject
): SubjectRenderInfo {
  const subject = (asRecord(credentialSubject) ?? {}) as ICredentialSubject
  // SkillClaimCredential: person.name is the subject name.
  const personName = (subject as { person?: { name?: unknown } })?.person?.name
  const personNameStr =
    typeof personName === 'string' && personName.trim()
      ? personName.trim()
      : null

  const identityHashName = extractNameFromOBV3Identifier(subject) ?? null

  // Used in non-OBv3 components.
  const subjectName = personNameStr ?? subject?.name ?? identityHashName ?? null
  // Used in OBv3 components -- prioritize the identityHash over subject.name.
  const issuedTo = personNameStr ?? identityHashName ?? subject?.name ?? null
  const degreeName =
    (asRecord(subject.degree)?.name as string | undefined) ?? null

  const [achievement] = recordList(subject.achievement) as Array<
    IAchievement | undefined
  >

  const description = achievement?.description ?? null
  const criteria = achievement?.criteria?.narrative ?? null
  const numberOfCredits =
    achievement?.awardedOnCompletionOf?.numberOfCredits?.value ?? null
  const achievementImage = imageSourceFrom(achievement?.image)
  const achievementType = achievement?.achievementType
    ? achievement.achievementType
    : null
  const alignment = achievement?.alignment
  const { startDate = null, endDate = null } =
    achievement?.awardedOnCompletionOf || {}

  return {
    subjectName,
    issuedTo,
    degreeName,
    description,
    criteria,
    numberOfCredits,
    startDate,
    endDate,
    achievementImage,
    achievementType,
    alignment
  }
}
