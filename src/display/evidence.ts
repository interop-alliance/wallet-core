/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Portfolio-evidence extraction (from DCW; no Freewallet equivalent beyond the
 * image helper in `obv3.ts`). Turns a credential's `evidence` array (or a
 * subject `portfolio`) into a flat list of `{ name, url }` links, coercing the
 * many shapes evidence appears in (string URL, `{ url }`, `{ id }`) and dropping
 * anything without a usable URL.
 */

/** A resolved evidence link. */
export type PortfolioEvidenceItem = { name: string; url: string }

/** Evidence item from a W3C VC evidence array: `{ id, type, name }`. */
export type VCEvidenceItem = {
  id: string
  type?: string
  name?: string
}

/** A VC carrying a top-level `evidence` array (W3C / IMS OB spec). */
export type VCWithEvidence = {
  evidence?: unknown
  credentialSubject?: unknown
}

/** Parses a single evidence item into `{ name, url }`, or `null` when unusable. */
function parseEvidenceItem(item: unknown): PortfolioEvidenceItem | null {
  if (typeof item === 'string') {
    const url = item.trim()
    if (!url) {
      return null
    }
    return { name: url, url }
  }

  if (!item || typeof item !== 'object') {
    return null
  }

  const rawUrl =
    (item as Record<string, unknown>).url ??
    (item as Record<string, unknown>).id ??
    ''
  const url = (typeof rawUrl === 'string' ? rawUrl : `${rawUrl}`).trim()
  if (!url) {
    return null
  }

  const rawName = (item as Record<string, unknown>).name ?? ''
  const name = (typeof rawName === 'string' ? rawName : `${rawName}`).trim()
  return { name: name || url, url }
}

/**
 * Extracts evidence links from a raw array/object/string, dropping items with
 * no usable URL.
 *
 * @param raw {unknown}
 * @returns {PortfolioEvidenceItem[]}
 */
export function portfolioEvidenceFrom(raw: unknown): PortfolioEvidenceItem[] {
  const items = Array.isArray(raw) ? raw : [raw]
  return items.map(parseEvidenceItem).filter(Boolean) as PortfolioEvidenceItem[]
}

/**
 * Extracts evidence from a credential: prefers the credential's top-level
 * `evidence` array, else falls back to the subject's `portfolio`.
 *
 * @param credential {VCWithEvidence}
 * @param subject {unknown} optional pre-resolved subject
 * @returns {PortfolioEvidenceItem[]}
 */
export function evidenceFromCredential(
  credential: VCWithEvidence,
  subject?: unknown
): PortfolioEvidenceItem[] {
  const fromEvidence = credential?.evidence
  if (fromEvidence && Array.isArray(fromEvidence) && fromEvidence.length > 0) {
    return portfolioEvidenceFrom(fromEvidence)
  }
  const rawSubject = credential?.credentialSubject
  const subj =
    subject ?? (Array.isArray(rawSubject) ? rawSubject[0] : rawSubject)
  const portfolio =
    subj && typeof subj === 'object' && 'portfolio' in subj
      ? (subj as { portfolio?: unknown }).portfolio
      : undefined
  return portfolioEvidenceFrom(portfolio)
}
