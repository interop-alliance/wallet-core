/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The pure derivation entry points stay off the ceremony graph. An offline
 * consumer that derives a client from an unlock secret or a recovery code,
 * opens a record envelope, or unwraps user key generations must evaluate no
 * did:webvh log, resource log, or client-annex module. This test walks each
 * listed entry's transitive runtime import graph over `src/` and refuses any
 * reach into those directories or into the two log packages.
 *
 * Only runtime edges are walked. A type-only import or export is erased at
 * build time, so it loads nothing; a dynamic `import(...)` is a runtime edge
 * even though it can appear anywhere in a file's code, not only at the top
 * level, so the specifiers are extracted with the TypeScript parser rather
 * than a regex.
 *
 * Known allowance: `unlock/standingClient.ts` imports
 * `@interop/was-client/identity`, which brings `@interop/ezcap` and
 * `@interop/capability-agent`.
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'
import { describe, expect, it } from 'vitest'

const SRC = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../src'
)

/**
 * Every leaf subpath `package.json` exports for dependency isolation, as
 * `src/`-relative module paths. Each is an `exports` entry of its own, so an
 * offline consumer imports it without a module barrel. The list is shared with
 * `test/probe/leafClosure.mjs`, the runtime half of this check.
 */
const PURE_ENTRIES = (
  JSON.parse(
    fs.readFileSync(path.join(SRC, '../test/probe/leafSubpaths.json'), 'utf8')
  ) as string[]
).map(subpath => `${subpath.replace(/^\.\//, '')}.ts`)

const FORBIDDEN_DIRECTORIES = ['resourceLog/', 'clientAnnex/']

/**
 * The `webvh/` modules a pure entry may reach: import-light leaves that load
 * no log code.
 */
const ALLOWED_WEBVH_MODULES = new Set(['webvh/updateKeyMultibase.ts'])

/**
 * The two log packages, and the was-client entries that load them on their
 * own: `./edv` and `./edv/core` carry the log-governed descriptor stores, and
 * `./log` is the resource-log store binding. A pure entry takes its EDV names
 * from `@interop/was-client/edv/cipher`. This walk reads `src/` alone, so what
 * a package loads at runtime is checked by `test/probe/leafClosure.mjs`.
 */
const FORBIDDEN_PACKAGES = [
  '@interop/did-method-webvh',
  '@interop/vh-resource-log',
  '@interop/was-client/edv/core',
  '@interop/was-client/log'
]

/**
 * Forbidden by exact name, since `@interop/was-client/edv/cipher` shares the
 * prefix and is the allowed entry.
 */
const FORBIDDEN_EXACT_PACKAGES = ['@interop/was-client/edv']

/**
 * Whether an `import` declaration's clause is fully erased at build time: a
 * default or namespace binding is always a runtime value, and a set of named
 * bindings is erased only when every element is individually `type`. A
 * missing clause is a side-effect import (`import '...'`), which IS a
 * runtime edge -- it has no clause to mark type-only.
 *
 * @param clause {ts.ImportClause | undefined}
 * @returns {boolean}
 */
function importClauseIsErased(clause: ts.ImportClause | undefined): boolean {
  if (!clause) {
    return false
  }
  if (clause.isTypeOnly) {
    return true
  }
  if (clause.name) {
    return false
  }
  const bindings = clause.namedBindings
  if (bindings && ts.isNamedImports(bindings)) {
    return (
      bindings.elements.length > 0 &&
      bindings.elements.every(element => element.isTypeOnly)
    )
  }
  return false
}

/**
 * Whether an `export ... from '...'` declaration is fully erased at build
 * time: the whole declaration is `export type`, or every named element is
 * individually `type`. `export * from '...'` and `export * as ns from '...'`
 * have no element list to check and are always runtime.
 *
 * @param declaration {ts.ExportDeclaration}
 * @returns {boolean}
 */
function exportDeclarationIsErased(declaration: ts.ExportDeclaration): boolean {
  if (declaration.isTypeOnly) {
    return true
  }
  const exportClause = declaration.exportClause
  if (exportClause && ts.isNamedExports(exportClause)) {
    return (
      exportClause.elements.length > 0 &&
      exportClause.elements.every(element => element.isTypeOnly)
    )
  }
  return false
}

/**
 * Extracts every runtime import/export/dynamic-import specifier from a
 * module's source text, parsed with the TypeScript compiler API rather than
 * matched with a regex -- a regex over `[^'"]*?` spans newlines, so a
 * multi-line `export type` ahead of a runtime `export ... from` on the next
 * statement reads as part of the same (dropped) match, and a regex anchored
 * to statement starts never looks inside a function body for a dynamic
 * `import(...)`.
 *
 * @param source {string}   the module's source text
 * @returns {string[]}
 */
function runtimeSpecifiersOf(source: string): string[] {
  const sourceFile = ts.createSourceFile(
    'module.ts',
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS
  )
  const specifiers: string[] = []

  function visitDynamicImports(node: ts.Node): void {
    if (
      ts.isCallExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ImportKeyword
    ) {
      const [specifierArgument] = node.arguments
      if (specifierArgument && ts.isStringLiteralLike(specifierArgument)) {
        specifiers.push(specifierArgument.text)
      }
    }
    ts.forEachChild(node, visitDynamicImports)
  }
  visitDynamicImports(sourceFile)

  for (const statement of sourceFile.statements) {
    if (
      ts.isImportDeclaration(statement) &&
      ts.isStringLiteralLike(statement.moduleSpecifier)
    ) {
      if (!importClauseIsErased(statement.importClause)) {
        specifiers.push(statement.moduleSpecifier.text)
      }
    } else if (
      ts.isExportDeclaration(statement) &&
      statement.moduleSpecifier &&
      ts.isStringLiteralLike(statement.moduleSpecifier)
    ) {
      if (!exportDeclarationIsErased(statement)) {
        specifiers.push(statement.moduleSpecifier.text)
      }
    }
  }
  return specifiers
}

// Entries share modules, so each file is read and parsed once per run.
const edgeCache = new Map<string, string[]>()

/**
 * Reads one module and returns the specifiers of its runtime imports,
 * resolved to `src/`-relative `.ts` paths where they are relative.
 *
 * @param relative {string}   a `src/`-relative module path
 * @returns {string[]}
 */
function runtimeEdgesOf(relative: string): string[] {
  const cached = edgeCache.get(relative)
  if (cached) {
    return cached
  }
  const source = fs.readFileSync(path.join(SRC, relative), 'utf8')
  const edges = runtimeSpecifiersOf(source).map(specifier =>
    specifier.startsWith('.')
      ? path.join(path.dirname(relative), specifier).replace(/\.js$/, '.ts')
      : specifier
  )
  edgeCache.set(relative, edges)
  return edges
}

/**
 * Walks an entry's transitive runtime import graph over `src/`.
 *
 * @param entry {string}   a `src/`-relative module path
 * @returns {{ modules: Set<string>; packages: Set<string> }}
 */
function runtimeClosureOf(entry: string): {
  modules: Set<string>
  packages: Set<string>
} {
  const modules = new Set<string>([entry])
  const packages = new Set<string>()
  const queue = [entry]
  while (queue.length > 0) {
    const current = queue.pop() as string
    for (const edge of runtimeEdgesOf(current)) {
      if (!edge.endsWith('.ts')) {
        packages.add(edge)
      } else if (!modules.has(edge)) {
        modules.add(edge)
        queue.push(edge)
      }
    }
  }
  return { modules, packages }
}

describe('runtime specifier extraction', () => {
  it('catches a runtime export hidden behind a multi-line type export, and a dynamic import', () => {
    const source = [
      'export type Foo = { a: number }',
      "export { bar } from '../webvh/didWebvh.js'",
      'async function load() {',
      "  return await import('../webvh/x.js')",
      '}'
    ].join('\n')
    expect(runtimeSpecifiersOf(source).sort()).toEqual(
      ['../webvh/didWebvh.js', '../webvh/x.js'].sort()
    )
  })

  it('drops a fully type-only import and a fully type-only named export', () => {
    const source = [
      "import type { Foo } from '../webvh/didWebvh.js'",
      "import { type Bar } from '../webvh/other.js'",
      "export type { Baz } from '../webvh/third.js'",
      "export { type Qux } from '../webvh/fourth.js'"
    ].join('\n')
    expect(runtimeSpecifiersOf(source)).toEqual([])
  })

  it('keeps a side-effect import with no clause', () => {
    const source = "import '../webvh/sideEffect.js'"
    expect(runtimeSpecifiersOf(source)).toEqual(['../webvh/sideEffect.js'])
  })
})

describe('pure entry points stay off the ceremony graph', () => {
  for (const entry of PURE_ENTRIES) {
    it(`${entry} reaches no log or annex module`, () => {
      const { modules, packages } = runtimeClosureOf(entry)
      const reached = [...modules].filter(
        module =>
          FORBIDDEN_DIRECTORIES.some(dir => module.startsWith(dir)) ||
          (module.startsWith('webvh/') && !ALLOWED_WEBVH_MODULES.has(module))
      )
      expect(reached).toEqual([])
      expect(
        [...packages].filter(
          name =>
            FORBIDDEN_EXACT_PACKAGES.includes(name) ||
            FORBIDDEN_PACKAGES.some(
              forbidden =>
                name === forbidden || name.startsWith(`${forbidden}/`)
            )
        )
      ).toEqual([])
    })
  }

  it('every pure entry has a four-key exports entry', () => {
    const { exports: exportMap } = JSON.parse(
      fs.readFileSync(path.join(SRC, '../package.json'), 'utf8')
    ) as { exports: Record<string, Record<string, string>> }
    for (const entry of PURE_ENTRIES) {
      const stem = entry.replace(/\.ts$/, '')
      expect(exportMap[`./${stem}`]).toEqual({
        types: `./dist/${stem}.d.ts`,
        'react-native': `./dist/${stem}.js`,
        import: `./dist/${stem}.js`,
        default: `./dist/${stem}.js`
      })
    }
  })

  it('unlock/ladderDerivation.ts imports a hash library and the update-key leaf alone', () => {
    const { modules, packages } = runtimeClosureOf('unlock/ladderDerivation.ts')
    expect([...modules].sort()).toEqual([
      'unlock/ladderDerivation.ts',
      'webvh/updateKeyMultibase.ts'
    ])
    expect([...packages].sort()).toEqual([
      '@interop/ed25519-verification-key',
      '@noble/hashes/hkdf.js',
      '@noble/hashes/sha2.js'
    ])
  })

  it('keyring/kdf.ts imports the noble hash libraries and nothing local', () => {
    const { modules, packages } = runtimeClosureOf('keyring/kdf.ts')
    expect([...modules].sort()).toEqual(['keyring/kdf.ts'])
    expect([...packages].sort()).toEqual([
      '@noble/hashes/argon2.js',
      '@noble/hashes/hkdf.js',
      '@noble/hashes/sha2.js'
    ])
  })

  it('keyring/recordEnvelope.ts does not reach the Space layout module or social-core', () => {
    const { modules, packages } = runtimeClosureOf('keyring/recordEnvelope.ts')
    expect([...modules]).not.toContain('space/collections.ts')
    expect([...packages]).not.toContain('@interop/social-core')
  })
})
