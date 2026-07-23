/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * QueryByExample matching: which stored credentials satisfy a verifier's
 * `QueryByExample` request. Two independent algorithms ship here because the two
 * apps genuinely differ, and each wallet matches only its own local store (no
 * cross-replica agreement is required):
 *
 * - `credentialMatchesVprExampleQuery` / `filterCredentialsByExample` -- DCW's
 *   jsonpath-plus deep matcher, which walks the example object and matches any
 *   nested field (arrays, nested objects, literals) against the credential.
 * - `vcMatchesFor` / `hasTypedExample` / `requestsCredentialType` --
 *   Freewallet's type-and-issuer matcher, which constrains only on the
 *   example's `type` (and, when pinned, `issuer`).
 *
 * Both operate on plain `IVerifiableCredential`s; each app maps its own record
 * type down to the credential before calling. Ported from DCW's
 * `app/lib/credentialMatching.ts` and Freewallet's
 * `src/lib/walletRequest/vcMatches.ts`.
 */
import { JSONPath } from 'jsonpath-plus'
import type { IVerifiableCredential } from './types.js'
import type { ICredentialQuery, IQueryByExample } from './types.js'
import { credentialQueriesOf } from './classify.js'
import { issuerId, typeArray } from '@interop/data-integrity-core/guards'

// The loose-field normalizers are owned by data-integrity-core; re-export them
// here so a matching consumer imports one module.
export { issuerId, typeArray } from '@interop/data-integrity-core/guards'

// Re-export the query vocabulary the matchers operate on, so a consumer of the
// light `./request/matching` subpath needs no import from the full `./request`
// barrel (whose compose/exchange modules pull in the signing crypto graph).
export type {
  ICredentialQuery,
  IQueryByExample,
  IVerifiableCredential
} from './types.js'

/**
 * Whether a credential matches a QueryByExample `example` object, by the DCW
 * deep-matching algorithm: every key of the example is resolved as a JSONPath
 * against the credential and compared. Array example values require the
 * credential to contain (at least) every listed value; object example values
 * recurse; literal example values compare by strict equality. An empty example
 * matches any credential.
 *
 * @param vprExample {Record<string, unknown>} - The QueryByExample `example`.
 * @param credential {IVerifiableCredential} - The stored credential to test.
 * @param [credentialPath] {string} - JSONPath root into the credential
 *   (defaults to `$`); used internally when recursing into nested objects.
 * @returns {boolean}
 */
export function credentialMatchesVprExampleQuery(
  vprExample: Record<string, unknown>,
  credential: IVerifiableCredential,
  credentialPath = '$'
): boolean {
  const matches: boolean[] = []
  for (const [vprExampleKey, vprExampleValue] of Object.entries(vprExample)) {
    const nextPath = extendPath(credentialPath, vprExampleKey)
    // The result is always dumped into a single-element array.
    const [credentialScope] = JSONPath({ path: nextPath, json: credential })
    if (Array.isArray(vprExampleValue)) {
      // Array query values require that the matching credential contains at
      // least every value specified. This assumes each element is a literal.
      if (!Array.isArray(credentialScope)) {
        return false
      }
      if (credentialScope.length < vprExampleValue.length) {
        return false
      }
      matches.push(
        vprExampleValue.every(exVal => credentialScope.includes(exVal))
      )
    } else if (
      typeof vprExampleValue === 'object' &&
      vprExampleValue !== null
    ) {
      // Object query values recurse, to handle nested queries.
      matches.push(
        credentialMatchesVprExampleQuery(
          vprExampleValue as Record<string, unknown>,
          credential,
          nextPath
        )
      )
    } else {
      // Literal query values compare directly.
      matches.push(credentialScope === vprExampleValue)
    }
  }
  return matches.every(m => m)
}

/**
 * Extends a JSONPath by a literal key, escaping any JSONPath-reserved
 * characters in the key (jsonpath-plus escapes a reserved char by prefixing it
 * with a backtick).
 */
function extendPath(path: string, extension: string): string {
  const reserved = /[$@*()[\].:?]/g
  if (reserved.test(extension)) {
    extension = extension.replace(reserved, match => '`' + match)
  }
  return `${path}.${extension}`
}

/**
 * Filters credentials to those matching a `QueryByExample`, using the deep
 * matcher. Each of the query's `credentialQuery` details contributes its
 * `example`; a credential is included when it matches any of them. A malformed
 * query with no example matches nothing.
 *
 * @param credentials {IVerifiableCredential[]}
 * @param query {IQueryByExample}
 * @returns {IVerifiableCredential[]}
 */
export function filterCredentialsByExample(
  credentials: IVerifiableCredential[],
  query: IQueryByExample
): IVerifiableCredential[] {
  const examples = credentialQueriesOf(query)
    .map(({ example }) => example)
    .filter((example): example is ICredentialQuery['example'] => !!example)
  if (examples.length === 0) {
    // Malformed request: no example to match against.
    return []
  }
  return credentials.filter(credential =>
    examples.some(example =>
      credentialMatchesVprExampleQuery(
        example as Record<string, unknown>,
        credential
      )
    )
  )
}

/**
 * Whether a credential matches a single QueryByExample `example` by the
 * type-and-issuer algorithm: every type listed in `example.type` must appear in
 * the credential's `type`, and -- when the example pins an `issuer` -- the
 * credential's issuer must equal it.
 *
 * @param options {object}
 * @param options.credential {IVerifiableCredential}
 * @param options.example {ICredentialQuery['example']}
 * @returns {boolean}
 */
function matchesExample({
  credential,
  example
}: {
  credential: IVerifiableCredential
  example: ICredentialQuery['example']
}): boolean {
  const wantedTypes = typeArray(example.type)
  const credentialTypes = typeArray(credential.type)
  const typesMatch = wantedTypes.every(type => credentialTypes.includes(type))
  if (!typesMatch) {
    return false
  }
  const wantedIssuer = issuerId(example.issuer)
  if (wantedIssuer) {
    return issuerId(credential.issuer) === wantedIssuer
  }
  return true
}

/**
 * The credentials matching any of the given QueryByExample queries by the
 * type-and-issuer algorithm. Only queries whose `example` carries a `type`
 * constrain the result; a query with no example type matches nothing here (the
 * caller keeps its list-all behavior when *no* query specifies a type).
 *
 * @param options {object}
 * @param options.credentials {IVerifiableCredential[]}
 * @param options.queries {IQueryByExample[]}
 * @returns {IVerifiableCredential[]}
 */
export function vcMatchesFor({
  credentials,
  queries
}: {
  credentials: IVerifiableCredential[]
  queries: IQueryByExample[]
}): IVerifiableCredential[] {
  const examples = typedExamplesOf(queries)
  if (examples.length === 0) {
    return []
  }
  return credentials.filter(credential =>
    examples.some(example => matchesExample({ credential, example }))
  )
}

/**
 * The example credential shapes pinned by a query set: every `credentialQuery`
 * detail carrying an example `type`. Only these constrain the share list.
 *
 * @param queries {IQueryByExample[]}
 * @returns {Array<ICredentialQuery['example']>}
 */
function typedExamplesOf(
  queries: IQueryByExample[]
): Array<ICredentialQuery['example']> {
  return queries
    .flatMap(query => credentialQueriesOf(query))
    .map(({ example }) => example)
    .filter(
      (example): example is ICredentialQuery['example'] =>
        !!example && typeArray(example.type).length > 0
    )
}

/**
 * Whether any of the QueryByExample queries pins an example `type` (and so
 * should filter the share list). When false, the caller keeps showing all
 * stored credentials.
 *
 * @param queries {IQueryByExample[]}
 * @returns {boolean}
 */
export function hasTypedExample(queries: IQueryByExample[]): boolean {
  return typedExamplesOf(queries).length > 0
}

/**
 * Whether any typed example in the query set explicitly lists the given
 * credential `type`. Lets the caller distinguish a request that actually asks
 * for a particular type (e.g. a LoginCredential) from a generic, untyped "any
 * VC" request.
 *
 * @param options {object}
 * @param options.queries {IQueryByExample[]}
 * @param options.type {string}
 * @returns {boolean}
 */
export function requestsCredentialType({
  queries,
  type
}: {
  queries: IQueryByExample[]
  type: string
}): boolean {
  return typedExamplesOf(queries).some(example =>
    typeArray(example.type).includes(type)
  )
}
