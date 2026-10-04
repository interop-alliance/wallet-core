/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * TEST FIXTURES ONLY: the `./testing` subpath. The recorded-grant signer
 * fixture, the fast passphrase KDF, and the account builder that makes real
 * accounts against a caller-booted WAS server. Never import it from
 * production code.
 */
export * from './signerFixture.js'
export * from './fastKdf.js'
export * from './accountBuilder.js'
