# Contributing

Editor setup, code style, and contribution conventions. Coding agents receive
this file via the include in [AGENTS.md](AGENTS.md).

PRs are welcome: tests plus a short summary of what changed is enough. You do
not need to touch roadmaps, changelogs, or any cross-repo bookkeeping --
maintainers handle those at merge. The ecosystem-wide conventions (for
maintainers) live in the
[byoe-ecosystem](https://github.com/interop-alliance/byoe-ecosystem) repo.

The sections between the `interop-conventions-core` markers below are the
**canonical shared conventions core** for `@interop/*` repos: other repos'
CONTRIBUTING.md files carry a verbatim copy of that block, and this file is the
source of truth. Edit the core here, then propagate; keep repo-specific
additions outside the markers.

## Editor setup

Formatting and linting are split into two tools with non-overlapping
responsibilities:

- **Prettier** (`prettier.config.js`) owns all formatting -- quotes, semicolons,
  trailing commas, arrow parens.
- **ESLint** (`eslint.config.js`) owns semantics and auto-fixes -- `curly`,
  `no-var`, `prefer-const`, `no-unused-vars`. It does not format: the
  `eslint-config-prettier` entry switches off every stylistic rule, so the two
  tools never fight.
- **`.editorconfig`** sets the baseline for every editor -- indent, charset,
  line endings, final newline. Prettier reads it natively, inheriting
  `indent_size` and `end_of_line`.

The goal is identical output from every editor, matching what CI enforces via
`pnpm lint`. You can always reproduce the canonical result from the command
line:

```bash
pnpm fix    # eslint --fix, then prettier --write
pnpm lint   # what CI runs
```

### VS Code

Committed settings live in `.vscode/`. On first open, accept the prompt to
install the recommended extensions (`.vscode/extensions.json`):

- Prettier -- `esbenp.prettier-vscode`
- ESLint -- `dbaeumer.vscode-eslint`
- EditorConfig -- `editorconfig.editorconfig` (VS Code does not read
  `.editorconfig` without it)

`.vscode/settings.json` then formats with Prettier and applies ESLint fixes on
save. No further configuration is needed.

### WebStorm / IntelliJ

WebStorm reads `.editorconfig` natively. Point its save actions at the same two
tools -- not the built-in "Reformat Code":

- **Settings ▸ Languages & Frameworks ▸ Prettier** -- "Automatic Prettier
  configuration", check **Run on save**.
- **Settings ▸ Languages & Frameworks ▸ JavaScript ▸ Code Quality Tools ▸
  ESLint** -- "Automatic ESLint configuration".
- **Settings ▸ Tools ▸ Actions on Save** -- enable **Run eslint --fix**, and
  turn **off** "Reformat code" so the IDE formatter does not override Prettier.

<!-- BEGIN interop-conventions-core (canonical source: isomorphic-lib-template/CONTRIBUTING.md) -->

## Refactoring

- Preserve existing comments and formatting

## Code Style

### Special Characters

- Avoid using the character `→` in the code, use `to` instead.
- Avoid mdashes, use `--` instead.
- Avoid the character `…`, use `...` instead.

### Naming

- Use `camelCase` for variables, functions, and properties; `PascalCase` for
  classes
- Avoid single-letter variable names — use descriptive names (e.g. `err` not
  `e`, `chunk` not `c`)

### Functions

- Prefer named `async function` declarations over arrow functions at module
  level
- Export functions and classes inline (`export async function ...`,
  `export class ...`)

### Imports

- Use `node:` prefix for Node.js built-in imports (e.g.
  `import fs from 'node:fs'`)
- Group imports: Node.js built-ins first, then external packages, then local
  modules
- Use named imports; avoid default imports where possible

### Parameters

- Pass related arguments as a single options object and destructure in the
  signature:
  ```js
  export async function exportKey({ publicKey, secretKey }) { ... }
  ```

### Types

- If an options/arguments type is only used once (i.e. twice, counting its own
  definition), inline it at the function/method signature instead of declaring a
  named interface/type.
- If a type/interface only has a single field, inline it at the usage site
  rather than declaring a named interface/type.

## JSDoc

Use multi-line `@param options` style, documenting each property on its own
line:

```js
/**
 * @param options {object}
 * @param options.methodId {string}
 * @param [options.contentType] {string}   ← square brackets for optional params
 */
```

Do not use the inline `@param {{ prop: type }}` style. Use `@returns {type}`
whenever possible.

## Error Handling

- Use `err` (not `e`) as the catch variable name
- Handle specific error codes explicitly (e.g. `err.code === 'ENOENT'`) before
  re-throwing
- Prefer `new Error(message, { cause })` over mutating an error's `.cause`

## Comments

- Use `/** */` JSDoc-style block comments for file, class, and function headers
  (including the one-paragraph "what this file does" header at the top of a
  module).
- Always use the multi-line form for `/** */` blocks, even for a single sentence
  — never the collapsed `/** text */` form:

  ```ts
  /**
   * Correct: multi-line even when the comment is one line.
   */

  /** Wrong: collapsed single-line form. */
  ```

- Use `//` only for short one- or two-line inline comments.
- Do not put "See AGENTS.md ..." cross-references inside code comments; keep
  pointers to the spec/docs in the README and AGENTS.md.

<!-- END interop-conventions-core -->

## Choosing a test tier

Pick the tier by what decides the outcome. A test goes in `test/integration/`
when it depends on a server authorization rule (the current-key-set rule, the
client-annex clause, the pointer-equality clause, the container rule) or on a
tear between two real writes (the request fault seam's refused, dropped, or held
request). Everything else is a unit test against the fakes in
`test/node/fixtures/`, which stay: they are fast and cover stage order well, but
they do not model the server's authorization rules. Integration suites build
accounts through the package's own ceremonies (`test/integration/fixtures/`)
with no fake store. `src/` never imports the server; a lint rule enforces it.

The integration tier is a contract tier. Its assertions are about the shapes a
real server produces that a fake must mirror (what a second run writes, what a
served description carries, which verb-and-target pair the server admits, that a
re-run of a block reports `noop`), not branch coverage the `test:node` fakes
already own. A case that only needs a store's stage logic goes in `test/node/`,
or the tier becomes a slow duplicate of the fakes and both rot.

A new torn-state test uses the server's request fault seam (the `faults` the
`bootServer` fixture returns) when any of these decides it:

- the tear falls between two specific server writes, possibly in different
  stores or Spaces;
- the write must land while the client sees a failure (`dropResponse`), the
  state a re-run has to detect from durable state alone;
- two actors interleave at a chosen write (`hold`);
- the assertion reads the ordered request record, such as "nothing was written
  after the entry" or "no revoke request was issued".

A unit fake's failure knob (`failFor`, a stale-validator
`PreconditionFailedError`) is enough when the test is one module's stage logic
over a store the fake already models, and the failure is the client seeing an
error before anything is applied.
