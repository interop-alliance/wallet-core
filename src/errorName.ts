/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The one reading of a thrown value's class name. An import-free leaf, so
 * the mender runner and the ceremony event helpers take it without importing
 * each other. `@interop/wallet-core/menders` re-exports it.
 */

/**
 * The thrown value's class name alone. Its message may carry a DID or a
 * Space id, so a report keeps the name and the logger keeps the error. A
 * value that is not an `Error` still yields a name, so a report site never
 * carries `undefined` where a name belongs.
 *
 * @param err {unknown}
 * @returns {string}
 */
export function errorNameOf(err: unknown): string {
  if (err instanceof Error) {
    return err.name
  }
  if (typeof err === 'object' && err !== null && 'name' in err) {
    return String((err as { name: unknown }).name)
  }
  return 'Error'
}
