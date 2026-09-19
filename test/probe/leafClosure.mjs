/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The runtime half of the pure-leaf isolation check. `import-graph.test.ts`
 * walks the specifiers written in `src/`, so it cannot see what a dependency
 * package loads on its own. This script imports each built leaf subpath under
 * a resolve hook, records every module Node actually resolves, and fails when
 * a leaf reaches a package or a wallet-core module it must stay clear of. It
 * runs against `dist/`, as part of `pnpm run test:dist`.
 */
import { registerHooks } from 'node:module'
import { readFile } from 'node:fs/promises'

const FORBIDDEN_PACKAGES = [
  '/node_modules/@interop/vh-resource-log/',
  '/node_modules/@interop/did-method-webvh/',
  '/vh-resource-log/dist/',
  '/did-method-webvh/dist/'
]
const FORBIDDEN_MODULES = ['/dist/resourceLog/', '/dist/clientAnnex/']
const ALLOWED_WEBVH_MODULE = '/dist/webvh/updateKeyMultibase.js'

const resolved = new Set()
registerHooks({
  resolve(specifier, context, nextResolve) {
    const result = nextResolve(specifier, context)
    resolved.add(result.url)
    return result
  }
})

function isForbidden(url) {
  if (FORBIDDEN_PACKAGES.some(fragment => url.includes(fragment))) {
    return true
  }
  if (FORBIDDEN_MODULES.some(fragment => url.includes(fragment))) {
    return true
  }
  return url.includes('/dist/webvh/') && !url.endsWith(ALLOWED_WEBVH_MODULE)
}

const packageJson = JSON.parse(
  await readFile(new URL('../../package.json', import.meta.url), 'utf8')
)
// The one list of leaf subpaths, shared with `import-graph.test.ts`.
const LEAF_SUBPATHS = JSON.parse(
  await readFile(new URL('./leafSubpaths.json', import.meta.url), 'utf8')
)

const failures = []
for (const subpath of LEAF_SUBPATHS) {
  const entry = packageJson.exports[subpath]
  if (!entry) {
    failures.push(`${subpath}: no exports entry`)
    continue
  }
  resolved.clear()
  // Node caches evaluated modules, so a forbidden module is reported against
  // the first leaf that loads it and not against the leaves after it.
  await import(new URL(`../../${entry.import}?leaf=${subpath}`, import.meta.url))
  for (const url of resolved) {
    if (isForbidden(url)) {
      failures.push(`${subpath}: reaches ${url}`)
    }
  }
}

if (failures.length > 0) {
  console.error('Pure leaf subpaths reach forbidden modules at runtime:')
  for (const failure of failures) {
    console.error(`  ${failure}`)
  }
  process.exit(1)
}
console.log(`leaf closure: ${LEAF_SUBPATHS.length} leaf subpaths are clear`)
