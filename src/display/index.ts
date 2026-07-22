/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/display` subpath: the pure VC derivation / display
 * helpers and credential input parsing two wallet apps (DCW, Freewallet) share,
 * reconciled from their two drifted implementations.
 *
 * Guiding seam: RETURN RAW VALUES, FORMAT IN THE UI. Nothing here imports
 * `moment`, `Intl`, `i18next`, `react-native`, or any app config. Dates come
 * out as ISO strings / `Date`; verification messages are injected as a `labels`
 * map; URL fetching is injected as a `fetchUrl` callback. Each app keeps a thin
 * wrapper that re-applies its own formatting / localization / transport.
 *
 * The loose-shape guards / normalizers (`isVerifiableCredential`, `typeArray`,
 * `issuerId`, `subjectId`, ...) live in `@interop/data-integrity-core` (shared
 * with the `./request` subpath); import them from there.
 */
export { credentialName, credentialNameFrom } from './credentialName.js'

export {
  issuerName,
  getIssuerDetails,
  personNameFromCredential,
  issuerRenderInfoFrom,
  issuerRenderInfoWithVerification
} from './issuer.js'
export type { IssuerDetails, IssuerRenderInfo } from './issuer.js'

export {
  getSubject,
  resolvePersonFullName,
  extractIssuedTo,
  credentialSubjectRenderInfo
} from './subject.js'
export type { SubjectRenderInfo } from './subject.js'

export {
  getIssuanceDate,
  getExpirationDate,
  getExpirationInstant,
  isExpired
} from './validity.js'

export {
  extractNameFromOBV3Identifier,
  achievementsList,
  skillsList,
  getSkillImage,
  getEvidenceImage,
  getAchievementImage,
  getAchievementType
} from './obv3.js'

export { normalizeAlignments, getValidAlignments } from './alignment.js'
export type { IAlignmentView, ValidAlignment } from './alignment.js'

export { portfolioEvidenceFrom, evidenceFromCredential } from './evidence.js'
export type {
  PortfolioEvidenceItem,
  VCEvidenceItem,
  VCWithEvidence
} from './evidence.js'

export {
  isResumeCredentialSubject,
  isResumeCredential,
  isEmploymentCredential,
  isVolunteerCredential
} from './types.js'

export { imageSourceFrom } from './image.js'

export { asNonEmptyString, getTrimmedString, asRecord } from './text.js'

export {
  getDisplayFields,
  buildCredentialDescription,
  buildCriteria
} from './displayFields.js'
export type { CredentialDisplayFields } from './displayFields.js'

export {
  buildVerificationChecklist,
  getVerificationAggregateStatus,
  isFullyVerified,
  isExpiredOnly,
  hasVerificationWarning,
  issuerRecognizedByVerification
} from './verificationView.js'
export type {
  VerificationStep,
  VerificationChecklist,
  VerificationStepStatus,
  VerificationAggregateStatus,
  ChecklistMsgKey
} from './verificationView.js'

export {
  credentialsFromJSON,
  extractCredentialsFrom,
  resolveCredentialsInput,
  ResolveCredentialsInputError,
  VPQR_UNSUPPORTED_MESSAGE
} from './parse.js'
