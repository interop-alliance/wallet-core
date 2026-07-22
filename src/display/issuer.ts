/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Issuer display derivation.
 *
 * Drift resolution: DCW's `issuerRenderInfoFrom` /
 * `issuerRenderInfoWithVerification` are the superset and win -- they return
 * nullable fields, apply the SkillClaimCredential `person.name` override, and
 * overlay registry `federation_entity` metadata from the `registered_issuer`
 * verification-log entry. Freewallet's simpler string conveniences
 * (`issuerName`, `getIssuerDetails`) are kept and layered on top for callers
 * that just want a single string / an all-string detail record. The
 * verification-log argument is typed structurally (not against any app's
 * verifier module) so both apps can pass their own log shape.
 */
import type {
  IImageObject,
  IIssuerObject,
  IVerifiableCredential
} from '@interop/data-integrity-core'
import { typeArray } from '@interop/data-integrity-core/guards'
import { imageSourceFrom } from './image.js'
import { getSubject } from './subject.js'
import { asNonEmptyString } from './text.js'

/** All-string issuer detail record (Freewallet; `''` defaults). */
export interface IssuerDetails {
  id: string
  name: string
  url: string
  image: string
}

/** Nullable issuer render fields (DCW). */
export interface IssuerRenderInfo {
  issuerName: string | null
  issuerUrl: string | null
  issuerId: string | null
  issuerImage: string | null
}

/** The registry metadata overlay carried in a `registered_issuer` log entry. */
interface FederationEntity {
  organization_name?: string
  homepage_uri?: string
  logo_uri?: string
}

/** Structural shape of the verification result read for the registry overlay. */
interface VerifyResultLike {
  log?: Array<{
    id: string
    matchingIssuers?: Array<{
      issuer?: { federation_entity?: FederationEntity }
    }>
  }>
}

/**
 * Human-readable issuer string: the issuer object's `name`, else its `id`, else
 * (for a string issuer) the DID string itself, else `'Unknown Issuer'`. Never
 * returns `null`.
 *
 * @param credential {IVerifiableCredential}
 * @returns {string}
 */
export function issuerName(credential: IVerifiableCredential): string {
  const { issuer } = credential
  if (typeof issuer === 'string') {
    return issuer
  }
  return issuer.name ?? issuer.id ?? 'Unknown Issuer'
}

/**
 * Maps a VC `issuer` to an all-string detail record (`id` / `name` / `url` /
 * `image`), defaulting missing fields to `''`.
 *
 * @param issuer {IVerifiableCredential['issuer']}
 * @returns {IssuerDetails}
 */
export function getIssuerDetails(
  issuer: IVerifiableCredential['issuer']
): IssuerDetails {
  if (typeof issuer === 'string') {
    return { id: issuer, name: '', url: '', image: '' }
  }

  const imageRaw = issuer.image
  let image = ''
  if (typeof imageRaw === 'string') {
    image = imageRaw
  } else if (imageRaw && typeof imageRaw === 'object' && 'id' in imageRaw) {
    image = String((imageRaw as { id?: string }).id ?? '')
  }

  return {
    id: issuer.id ?? '',
    name: issuer.name ?? '',
    url: issuer.url ?? '',
    image
  }
}

/**
 * The `credentialSubject.person.name` (SkillClaimCredential), used to override
 * the issuer display name. `null` when absent or no credential is given.
 *
 * @param credential {IVerifiableCredential | undefined}
 * @returns {string | null}
 */
export function personNameFromCredential(
  credential?: IVerifiableCredential
): string | null {
  if (!credential) {
    return null
  }
  const subject = getSubject(credential)
  return (
    asNonEmptyString(
      (subject as { person?: { name?: unknown } })?.person?.name
    ) ?? null
  )
}

/**
 * Nullable issuer render fields derived from the VC `issuer` alone, with a
 * SkillClaimCredential `person.name` override when a credential is supplied.
 *
 * @param issuer {IIssuerObject | string}
 * @param credential {IVerifiableCredential | undefined}
 * @returns {IssuerRenderInfo}
 */
export function issuerRenderInfoFrom(
  issuer: IIssuerObject | string,
  credential?: IVerifiableCredential
): IssuerRenderInfo {
  const isSkillClaimCredential = credential
    ? typeArray(credential.type).includes('SkillClaimCredential')
    : false
  const personName = isSkillClaimCredential
    ? personNameFromCredential(credential)
    : null

  const issuerName =
    personName ?? (typeof issuer === 'string' ? issuer : issuer?.name) ?? null
  const issuerUrl = (typeof issuer === 'string' ? null : issuer?.url) ?? null
  const issuerId = typeof issuer === 'string' ? null : issuer?.id
  const issuerImage =
    typeof issuer === 'string'
      ? null
      : imageSourceFrom(issuer.image as IImageObject | string | undefined)

  return { issuerName, issuerUrl, issuerId, issuerImage }
}

/**
 * Like {@link issuerRenderInfoFrom} but overlays registry `federation_entity`
 * metadata (organization name / homepage / logo) from the `registered_issuer`
 * verification-log entry when the issuer matched the registry and there is no
 * SkillClaimCredential person-name override.
 *
 * @param issuer {IIssuerObject | string}
 * @param verifyResult {VerifyResultLike | undefined} verification result whose
 *   `log[]` may carry a `registered_issuer` match
 * @param credential {IVerifiableCredential | undefined}
 * @returns {IssuerRenderInfo}
 */
export function issuerRenderInfoWithVerification(
  issuer: IIssuerObject | string,
  verifyResult?: VerifyResultLike,
  credential?: IVerifiableCredential
): IssuerRenderInfo {
  const isSkillClaimCredential = credential
    ? typeArray(credential.type).includes('SkillClaimCredential')
    : false
  const personName = isSkillClaimCredential
    ? personNameFromCredential(credential)
    : null

  const registeredIssuerLog = verifyResult?.log?.find(
    log => log.id === 'registered_issuer'
  )
  const matchingIssuer = registeredIssuerLog?.matchingIssuers?.[0]

  if (matchingIssuer?.issuer?.federation_entity && !personName) {
    const federationEntity = matchingIssuer.issuer.federation_entity
    return {
      issuerName: federationEntity.organization_name ?? '',
      issuerUrl: federationEntity.homepage_uri ?? '',
      issuerId: typeof issuer === 'string' ? null : (issuer?.id ?? ''),
      issuerImage:
        typeof issuer === 'object'
          ? imageSourceFrom(issuer.image as IImageObject | string | undefined)
          : null
    }
  }

  // Fallback to the plain issuer logic (or person name for SkillClaim).
  const fallback = issuerRenderInfoFrom(issuer)
  return {
    issuerName: personName ?? fallback.issuerName ?? '',
    issuerUrl: fallback.issuerUrl ?? '',
    issuerId: fallback.issuerId ?? '',
    issuerImage:
      matchingIssuer?.issuer?.federation_entity?.logo_uri ??
      fallback.issuerImage ??
      ''
  }
}
