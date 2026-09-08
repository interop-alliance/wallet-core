/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The resource-log CLASS dispatch: which admission rule a controller view
 * carries for the log it is about to verify or extend. One account document
 * governs several logs -- the user key roster log, and one encryption
 * descriptor log per governed collection -- so the rule is a property of the
 * log, not of the document, and the adapter that reads the document
 * (`webvhResourceLogController`) cannot know which log its view is about to
 * serve. The class therefore rides the STORE, which is built for exactly one
 * log and states its class at construction; the store passes its resolved
 * view through {@link controllerForLogClass} before every read and every
 * append, so read-side verification and write-side admission run under the
 * same rule and no call site can exempt itself.
 *
 * The rules, one per member of {@link ResourceLogClass}. A new log class is
 * added to the union with its rule stated here, rather than by exempting a
 * caller (app-connect-spec `decisions/0003`, "Scope").
 */
import type { WebvhResourceLogController } from './controller.js'

/**
 * The classes of resource log this wallet verifies, each naming the rule its
 * views admit ladder-signed appends under.
 *
 * - `'user-key-roster'`: the user key roster log (`key-map/user-key.jsonl`),
 *   the log governing the account's root key. A ladder-signed append to it
 *   carries the ceremony-tail license (clause B of the ladder VM's authority
 *   clauses): one of the license's enumerated shapes, one-shot per licensed
 *   controller version, at most one ladder proof per entry. This is the
 *   adapter's own view, unchanged.
 * - `'collection-descriptor'`: a per-collection encryption descriptor log
 *   (one per governed collection, the encrypted-collections profile's log
 *   form). A ladder-signed append admits on `assertionMethod` membership at
 *   the anchored version alone, with no shape check and no one-shot. The
 *   license exists to refuse the silent rekey of the account's root key to
 *   recipients of a credential thief's choosing; a descriptor append escrows
 *   one recipient into one collection and lands as a hash-chained entry
 *   signed by that credential's ladder VM, auditable by the account's clients
 *   and attributable to the credential, so the bound it leaves is
 *   detect-and-remediate rather than silence.
 */
export type ResourceLogClass = 'user-key-roster' | 'collection-descriptor'

/**
 * Returns the controller view a log of the given class must be verified and
 * appended to under: the adapter's licensed view for the roster class, and a
 * view identical in every other member with a membership-only `admitAppend`
 * for the collection-descriptor class.
 *
 * The hook stays a real function rather than being dropped, because the
 * wallet-core extended view makes it mandatory: an account document can list
 * ladder VMs, so a view over one always answers the question, and the
 * collection-descriptor answer is "membership is enough". The library
 * verifier has already settled `assertionMethod` membership at the entry's
 * anchored controller version before the hook runs, so the hook resolves
 * nothing and returns.
 *
 * @param options {object}
 * @param options.controller {WebvhResourceLogController}   the adapter's
 *   view over the verified account log
 * @param options.logClass {ResourceLogClass}   the class of the log this view
 *   will serve
 * @returns {WebvhResourceLogController}
 */
export function controllerForLogClass({
  controller,
  logClass
}: {
  controller: WebvhResourceLogController
  logClass: ResourceLogClass
}): WebvhResourceLogController {
  switch (logClass) {
    case 'user-key-roster':
      return controller
    case 'collection-descriptor':
      return {
        ...controller,
        async admitAppend(): Promise<void> {
          // Membership at the anchored version is the whole rule for this
          // class, and the verifier has already checked it.
          return
        }
      }
    default: {
      // Fail closed: a class this dispatch does not name (a cast, a caller
      // outside the type system) gets no rule, not the permissive one.
      const unknown: never = logClass
      throw new TypeError(
        `Unknown resource-log class ${JSON.stringify(unknown)}.`
      )
    }
  }
}
