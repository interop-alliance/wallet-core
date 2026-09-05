/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The optional KMS authentication stage's concurrency, shared by both account
 * genesis flavors (the enrolled-client ceremony and the credential-anchored
 * one). Nothing in a keystore ensure or a key mint needs the Space, so the
 * thunk STARTS before Space provisioning is awaited and is handed that
 * provisioning as `spaceReady`, which its own `keys.json` write orders itself
 * behind. Both ceremonies join before the genesis entry, which carries the
 * binding.
 *
 * A throw degrades to the keystore-less genesis rather than aborting: the
 * failure is collected for the ceremony's `failed` list and the document
 * simply publishes no `authentication` relation. The stage is marked at the
 * join rather than inside the thunk, so a thunk that finished first cannot
 * mark out of order.
 */
import type { KmsAuthenticationBinding } from '../webvh/index.js'

/**
 * Starts the optional KMS authentication thunk and hands back its join. The
 * thunk is started inside the same guard the join uses, so one that throws
 * synchronously is collected like one that rejects, and its rejection is
 * claimed immediately -- a ceremony whose Space never came up returns while
 * the thunk is still in flight, and the rejection must not surface as an
 * unhandled one.
 *
 * @param options {object}
 * @param [options.provideKmsAuthentication] {Function}   the caller's stage;
 *   absent means the keystore-less genesis
 * @param options.spaceReady {Promise<unknown>}   the Space provisioning the
 *   thunk orders its own writes behind
 * @returns {object}   `{ join }` -- awaiting the stage and reporting it: the
 *   binding when it settled, or `failed` with the collected error. The flag
 *   rather than the value decides, so a thunk rejecting with `undefined` is
 *   still a collected failure
 */
export function startKmsAuthentication({
  provideKmsAuthentication,
  spaceReady
}: {
  provideKmsAuthentication?: (options: {
    spaceReady: Promise<unknown>
  }) => Promise<KmsAuthenticationBinding | undefined>
  spaceReady: Promise<unknown>
}): {
  join: () => Promise<{
    binding?: KmsAuthenticationBinding
    failed: boolean
    error?: unknown
  }>
} {
  let run: Promise<KmsAuthenticationBinding | undefined> | undefined
  let failed = false
  let failure: unknown
  try {
    run = provideKmsAuthentication?.({ spaceReady })
  } catch (err) {
    failed = true
    failure = err
  }
  run?.catch(() => {})

  return {
    join: async () => {
      let binding: KmsAuthenticationBinding | undefined
      if (run) {
        try {
          binding = await run
        } catch (err) {
          failed = true
          failure = err
        }
      }
      return failed
        ? { failed: true, error: failure }
        : { failed: false, ...(binding ? { binding } : {}) }
    }
  }
}
