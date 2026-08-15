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
 *   deep matcher, which walks the example object and matches any nested field
 *   (arrays, nested objects, literals) against the credential.
 * - `vcMatchesFor` / `hasTypedExample` / `requestsCredentialType` --
 *   Freewallet's type-and-issuer matcher, which constrains only on the
 *   example's `type` (and, when pinned, `issuer`).
 *
 * Both operate on plain `IVerifiableCredential`s; each app maps its own record
 * type down to the credential before calling. Ported from DCW's
 * `app/lib/credentialMatching.ts` and Freewallet's
 * `src/lib/walletRequest/vcMatches.ts`.
 */
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
 * deep-matching algorithm: every key of the example is resolved as a literal
 * property of the credential and compared. Array example values require the
 * credential to contain (at least) every listed value; object example values
 * recurse; literal example values compare by strict equality. An empty example
 * matches any credential.
 *
 * Both sides are normalized for JSON-LD's single-value / array duality: a
 * literal example value also matches a credential field holding the array form
 * (`"type": "AlumniCredential"` vs `type: ['VerifiableCredential',
 * 'AlumniCredential']`), and an array example value also matches a credential
 * field holding the compacted single value.
 *
 * @param vprExample {Record<string, unknown>} - The QueryByExample `example`.
 * @param credential {IVerifiableCredential} - The stored credential to test.
 * @returns {boolean}
 */
export function credentialMatchesVprExampleQuery(
  vprExample: Record<string, unknown>,
  credential: IVerifiableCredential
): boolean {
  return matchesExampleScope(vprExample, credential)
}

/**
 * The recursive half of the deep matcher: whether an example object matches the
 * given scope of a credential. Each example key is resolved as a literal
 * property of the scope, and an object example value recurses into the value it
 * resolved to.
 *
 * @param vprExample {Record<string, unknown>} - The example (or sub-example).
 * @param scope {unknown} - The credential value the example is matched against
 *   (the credential itself at the top level).
 * @returns {boolean}
 */
function matchesExampleScope(
  vprExample: Record<string, unknown>,
  scope: unknown
): boolean {
  const matches: boolean[] = []
  for (const [vprExampleKey, vprExampleValue] of Object.entries(vprExample)) {
    const credentialScope = propertyOf(scope, vprExampleKey)
    if (Array.isArray(vprExampleValue)) {
      // Array query values require that the matching credential contains at
      // least every value specified. This assumes each element is a literal.
      // The credential side may hold the compacted single-value form.
      const scopeValues = valueList(credentialScope)
      if (scopeValues.length < vprExampleValue.length) {
        return false
      }
      matches.push(
        vprExampleValue.every(exampleValue =>
          scopeValues.includes(exampleValue)
        )
      )
    } else if (
      typeof vprExampleValue === 'object' &&
      vprExampleValue !== null
    ) {
      // Object query values recurse, to handle nested queries.
      matches.push(
        matchesExampleScope(
          vprExampleValue as Record<string, unknown>,
          credentialScope
        )
      )
    } else {
      // Literal query values compare directly, or by membership when the
      // credential holds the array form of the field.
      matches.push(
        Array.isArray(credentialScope)
          ? credentialScope.includes(vprExampleValue)
          : credentialScope === vprExampleValue
      )
    }
  }
  return matches.every(match => match)
}

/**
 * Normalizes a credential field value to the array form, so an example's array
 * value can be compared against a field holding either the array or the
 * compacted single value. An absent field yields `[]`.
 *
 * @param value {unknown}
 * @returns {unknown[]}
 */
function valueList(value: unknown): unknown[] {
  if (Array.isArray(value)) {
    return value
  }
  if (value === undefined) {
    return []
  }
  return [value]
}

/**
 * The value of an own property of a credential scope, or `undefined` when the
 * scope carries no such property. Example keys are arbitrary strings, so only
 * own properties resolve: an inherited name (`toString`, `constructor`,
 * `__proto__`) reads as absent rather than reaching the prototype chain. An
 * array scope is an ordinary object here -- a key is not mapped over its
 * elements.
 *
 * @param scope {unknown} - The credential value to read from.
 * @param key {string} - The literal property name.
 * @returns {unknown}
 */
function propertyOf(scope: unknown, key: string): unknown {
  if (scope === null || scope === undefined) {
    return undefined
  }
  if (!Object.hasOwn(scope as object, key)) {
    return undefined
  }
  return (scope as Record<string, unknown>)[key]
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
