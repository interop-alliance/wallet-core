/**
 * The service discovery a fake WAS server answers: was-client HEADs the
 * server URL for its `rel="service"` link and reads the linked description
 * unsigned before its first signed request, so every suite that drives a
 * `WasClient` over a stubbed `fetch` (or over a fake `ZcapClient` that never
 * touches `fetch`) answers those two unsigned requests here, stated once.
 */
import { vi } from 'vitest'
import type { ServiceDescription } from '@interop/was-client'

/**
 * A v0.5 service description for a fake server at `serverUrl`, with the
 * description itself at `service` and the Spaces Repository at `spaces/`
 * under it.
 *
 * @param serverUrl {string}
 * @returns {ServiceDescription}
 */
export function serviceDescriptionFor(serverUrl: string): ServiceDescription {
  const base = serverUrl.endsWith('/') ? serverUrl : `${serverUrl}/`
  return {
    url: new URL('service', base).toString(),
    specs: {
      'https://w3id.org/pws': [
        {
          version: '0.5',
          spaces: new URL('spaces/', base).toString(),
          features: ['listing', 'collection-management', 'space-management']
        }
      ]
    }
  }
}

/**
 * The URL of a fetch call, whatever form it was made in.
 *
 * @param input {RequestInfo | URL}
 * @returns {string}
 */
export function fetchUrlOf(input: RequestInfo | URL): string {
  if (typeof input === 'string') {
    return input
  }
  return input instanceof URL ? input.href : input.url
}

/**
 * The method of a fetch call, upper-cased, defaulting to `GET`.
 *
 * @param input {RequestInfo | URL}
 * @param [init] {RequestInit}
 * @returns {string}
 */
export function fetchMethodOf(input: RequestInfo | URL, init?: RequestInit) {
  const method =
    init?.method ?? (input instanceof Request ? input.method : undefined)
  return (method ?? 'GET').toUpperCase()
}

/**
 * Answers one fetch call when it is a service-discovery step against
 * `serverUrl` (the `HEAD` probe, or the `GET` of the linked description) and
 * returns `undefined` for every other call, so a suite's own stub handles it.
 *
 * @param options {object}
 * @param options.serverUrl {string}
 * @param options.input {RequestInfo | URL}
 * @param [options.init] {RequestInit}
 * @returns {Response | undefined}
 */
export function serviceDiscoveryResponse({
  serverUrl,
  input,
  init
}: {
  serverUrl: string
  input: RequestInfo | URL
  init?: RequestInit
}): Response | undefined {
  const description = serviceDescriptionFor(serverUrl)
  const url = fetchUrlOf(input)
  const method = fetchMethodOf(input, init)
  if (method === 'HEAD' && url === serverUrl) {
    return new Response(null, {
      status: 200,
      headers: { link: `<${description.url}>; rel="service"` }
    })
  }
  if (method === 'GET' && url === description.url) {
    return new Response(JSON.stringify(description), {
      status: 200,
      headers: { 'content-type': 'application/json' }
    })
  }
  return undefined
}

/**
 * Whether a fetch call is one of the two service-discovery steps against
 * `serverUrl`, for a suite that records fetches and counts only its own.
 *
 * @param options {object}
 * @param options.serverUrl {string}
 * @param options.input {RequestInfo | URL}
 * @param [options.init] {RequestInit}
 * @returns {boolean}
 */
export function isServiceDiscoveryFetch({
  serverUrl,
  input,
  init
}: {
  serverUrl: string
  input: RequestInfo | URL
  init?: RequestInit
}): boolean {
  return serviceDiscoveryResponse({ serverUrl, input, init }) !== undefined
}

/**
 * Wraps a suite's fetch stub so service discovery against `serverUrl` is
 * answered first and every other call reaches the stub unchanged.
 *
 * @param options {object}
 * @param options.serverUrl {string}
 * @param options.fetch {function}   the suite's own `(input, init) => Response`
 * @returns {function}   a `fetch`-shaped function
 */
export function withServiceDiscovery({
  serverUrl,
  fetch
}: {
  serverUrl: string
  fetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<unknown>
}): (input: RequestInfo | URL, init?: RequestInit) => Promise<unknown> {
  return async (input, init) =>
    serviceDiscoveryResponse({ serverUrl, input, init }) ?? fetch(input, init)
}

/**
 * Stubs the global `fetch` so service discovery against `serverUrl` is
 * answered and any other call fails loudly, for a suite whose fake server is
 * a `ZcapClient` that never touches `fetch`. Undone by
 * `vi.unstubAllGlobals()`.
 *
 * @param options {object}
 * @param options.serverUrl {string}
 * @returns {void}
 */
export function stubServiceDiscovery({ serverUrl }: { serverUrl: string }) {
  vi.stubGlobal(
    'fetch',
    withServiceDiscovery({
      serverUrl,
      fetch: async input => {
        throw new Error(`Unstubbed fetch of "${fetchUrlOf(input)}".`)
      }
    })
  )
}
