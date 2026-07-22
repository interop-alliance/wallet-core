/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Achievement alignment normalization. Two functions are kept on purpose
 * because they answer different questions:
 *
 * - `normalizeAlignments` (from Freewallet) trims each alignment and drops the
 *   ones with no `targetName`, returning a plain `{ targetName, targetUrl,
 *   targetDescription }` view. It does NOT validate URLs.
 * - `getValidAlignments` (from DCW) additionally runs a strict http(s) URL
 *   safety check and reports it via an `isValidUrl` flag, so the UI can decide
 *   whether to render a target as a clickable link. It omits `targetUrl` when
 *   absent (rather than emitting `''`).
 *
 * Both had passing tests in their respective apps and both are exported.
 */
import type { IAlignment } from '@interop/data-integrity-core'
import { asRecord } from './text.js'

/** The trimmed, always-present-string alignment view `normalizeAlignments` emits. */
export interface IAlignmentView {
  targetName: string
  targetUrl: string
  targetDescription: string
}

/** A display-safe alignment with an optional validated URL (`getValidAlignments`). */
export interface ValidAlignment {
  targetName: string
  targetUrl?: string
  targetDescription?: string
  isValidUrl?: boolean
}

/**
 * Normalizes a raw alignment field (a single alignment or an array) to trimmed
 * views, dropping entries with no `targetName`. Does not validate URLs.
 *
 * @param rawAlignments {unknown}
 * @returns {IAlignmentView[]}
 */
export function normalizeAlignments(rawAlignments: unknown): IAlignmentView[] {
  if (!rawAlignments) {
    return []
  }

  const alignmentArray: unknown[] = Array.isArray(rawAlignments)
    ? rawAlignments
    : [rawAlignments]

  return alignmentArray
    .map((alignmentField: unknown) => {
      const normalizedField = asRecord(alignmentField) ?? {}
      return {
        targetName: String(normalizedField.targetName ?? '').trim(),
        targetUrl: String(normalizedField.targetUrl ?? '').trim(),
        targetDescription: String(
          normalizedField.targetDescription ?? ''
        ).trim()
      }
    })
    .filter(alignmentField => Boolean(alignmentField.targetName))
}

function normalizeUrl(raw: string): string {
  const trimmed = String(raw).trim()
  // If it already has a scheme (e.g., http:, https:)
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)) {
    return trimmed
  }
  // Otherwise, assume https
  return `https://${trimmed}`
}

function isStrictHttpUrl(raw: string): string | null {
  const candidate = String(raw).trim()

  if (candidate.length === 0) {
    return null
  }
  if (/\s/.test(candidate)) {
    return null
  }

  const normalized = normalizeUrl(candidate)

  // Reject strings that embed multiple schemes
  const firstSchemeIdx = normalized.indexOf('://')
  if (firstSchemeIdx === -1) {
    return null
  }
  if (normalized.indexOf('://', firstSchemeIdx + 3) !== -1) {
    return null
  }

  try {
    const u = new URL(normalized)
    // Only allow http(s)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      return null
    }
    // Must have a hostname
    if (!u.hostname) {
      return null
    }
    // Forbid credentials/userinfo
    if (u.username || u.password) {
      return null
    }
    // Hostname must be reasonable, or be 'localhost' or an IPv4
    const isHostname = /^[A-Za-z0-9.-]+$/.test(u.hostname)
    const isLocalhost = u.hostname.toLowerCase() === 'localhost'
    const isIPv4 =
      /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(
        u.hostname
      )
    if (!(isHostname || isLocalhost || isIPv4)) {
      return null
    }
    // If it's a standard hostname (not localhost/IP), require at least one dot
    if (isHostname && !isLocalhost && !isIPv4 && !u.hostname.includes('.')) {
      return null
    }

    return normalized
  } catch {
    return null
  }
}

/**
 * Filters alignments to those with a `targetName` and, for each, reports
 * whether its `targetUrl` (when present) is a safe http(s) URL via `isValidUrl`.
 * `targetUrl` is omitted from the result when the input had none.
 *
 * @param alignments {IAlignment[] | undefined}
 * @returns {ValidAlignment[]}
 */
export function getValidAlignments(
  alignments?: IAlignment[]
): ValidAlignment[] {
  if (!alignments || !Array.isArray(alignments)) {
    return []
  }

  return alignments
    .filter(alignment => {
      // targetName is required for display
      return !!alignment.targetName
    })
    .map(alignment => {
      const result: ValidAlignment = {
        targetName: alignment.targetName!,
        targetDescription: alignment.targetDescription
      }

      if (alignment.targetUrl) {
        const normalizedUrl = isStrictHttpUrl(alignment.targetUrl)
        result.targetUrl = alignment.targetUrl
        result.isValidUrl = !!normalizedUrl
      }

      return result
    })
}
