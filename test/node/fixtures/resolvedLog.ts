/**
 * The resolved state of a published did:webvh log text, verified under the
 * default verifier and asserted error-free. Shared by every suite that drives
 * a real ceremony against `memoryIdStore` and then reads the document, the
 * `updateKeys`, or the `nextKeyHashes` the ceremony left standing.
 */
import { expect } from 'vitest'
import {
  defaultWebvhLogVerifier,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'

/**
 * Resolves a log text.
 *
 * @param logText {string}
 * @returns {Promise<object>}
 */
export async function resolvedLog(logText: string) {
  const result = await resolveDIDFromLog(readLogFromString(logText), {
    verifier: defaultWebvhLogVerifier
  })
  expect(result.meta.error).toBeUndefined()
  return result
}

/**
 * Resolves the log an in-memory id store currently serves, through its `log`
 * getter.
 *
 * @param log {function}
 * @returns {Promise<object>}
 */
export async function resolved(log: () => string | undefined) {
  return resolvedLog(log()!)
}
