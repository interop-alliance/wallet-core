# Agent Guidelines

`@interop/wallet-core` is the shared wallet-domain logic (identity derivation,
Space layout, sync engine core, key management, ceremonies) two WAS-enabled
wallet apps -- DCW (React Native) and freewallet (browser) -- hold in common.

## Architecture

The codebase map -- the module layers and dependency direction, the wallet Space
layout, the key hierarchy, the did:webvh client roster, the ceremonies and
cascades, the permanent wire-level constants, what lives in which `@interop/*`
package, and test-layout notes -- lives in @ARCHITECTURE.md -- read it before
making changes.

## Toolchain & Project Layout

### Package Manager

Use `pnpm` (not `npm` or `yarn`). The lockfile is `pnpm-lock.yaml`. Install deps
with `pnpm install`; run scripts with `pnpm run <script>` or `pnpm <script>`.

### Build

The library is built with `tsc` (not `vite build`). `vite.config.ts` exists only
to configure Vitest and to run `vite dev` as a server for Playwright. Running
`pnpm run build` compiles `src/` to `dist/` via `tsconfig.json`.

### Two tsconfigs

- `tsconfig.json` — library build only; includes `src/**/*`
- `tsconfig.dev.json` — extends the above with `noEmit: true`; adds `test/**/*`,
  `vite.config.ts`, and `playwright.config.ts` so ESLint's type-aware rules
  cover all files

Do not add test files to `tsconfig.json` — they would be emitted into `dist/`.

### Tests

- `test/node/` — Vitest unit tests (`pnpm run test:node`); run in Node
- `test/browser/` — Playwright tests (`pnpm run test:browser`); run in real
  Chromium via a Vite dev server (`pnpm run dev`)

The `dev` script exists solely to give Playwright a server that can serve and
transform TypeScript source files on the fly. There is no browser app.

### ESM & import paths

The package is ESM-only (`"type": "module"`). Local imports must use the `.js`
extension even though source files are `.ts` — e.g.
`import { Example } from '../../src/index.js'`. TypeScript's
`moduleResolution: Bundler` resolves these to the `.ts` source at compile time.

## Roadmap & Task Conventions

All roadmap tracking lives in `_spec/ROADMAP.md` (local-only, gitignored):
narrative context plus structured work items. Never create a parallel task list
elsewhere (no `TODO.md`, no task lists in other docs).

Each work item follows this schema:

- A heading `### WC-N: Title`, then a field block, then free prose context.
- Fields: `status` (`todo` / `in-progress` / `draft` / `done`), `priority`
  (`high` / `medium` / `low`), `labels` (comma-separated), optional `blocked-by`
  (other `WC-N` ids), a `touches:` list where it applies, and an `acceptance:`
  checklist.
- `draft` marks items with no actionable done-state yet (blocked externally or
  parking records); a draft states _why_ instead of acceptance criteria and must
  gain acceptance criteria when promoted to `todo`.
- `touches:` is the field defined in the canonical schema in
  isomorphic-lib-template's AGENTS.md ("Roadmap & Task Conventions"): required
  for any item changing a spec, a wire contract, or a shared `@interop/*` API,
  it lists the affected repos and their ARCHITECTURE/AGENTS files, and each
  entry must be resolved (shipped or explicitly waived) before the item may go
  `done`. See that file for the full definition.

Rules:

- Item ids are permanent and never reused. A new item takes the next unused
  number, regardless of which section it lands in.
- Every non-draft item needs acceptance criteria before it may be moved to
  `in-progress`.
- Statuses are edited in place (change the `status:` field); acceptance
  checkboxes are ticked as they are met.
- Completed items move **verbatim** (number, title, field block, prose, with
  their `done` date) from `_spec/ROADMAP.md` to `_spec/archived-roadmap.md` once
  shipped, append-only -- this keeps WC-N references resolvable. CHANGELOG.md
  remains the permanent record of what landed. Do not rewrite or summarize items
  on the way in, and do not fix old references.
- Work discovered mid-implementation gets its own item immediately, noting
  `discovered-from: WC-N` in its prose, plus a `blocked-by` link if it blocks
  anything.
- Do not reference item ids in commit messages or PR descriptions. `_spec/` is
  gitignored, so a `WC-N` in the git history resolves to nothing for anyone
  reading the repo -- describe the change itself instead. (In-repo prose --
  CHANGELOG.md, ARCHITECTURE.md, `decisions/` -- may still cite an id where it
  names a known gap.)

## Ecosystem conventions

- Cross-repo lessons (invariants, gotchas, and process recipes that span repos)
  live in the ecosystem learnings file,
  [byoe-ecosystem/LEARNINGS.md](https://github.com/interop-alliance/byoe-ecosystem/blob/main/LEARNINGS.md)
  (usually checked out beside this repo as `../byoe-ecosystem`); read it at the
  start of any cross-repo task.
- Cross-repo decisions are recorded as `decisions/NNNN-slug.md` in the repo that
  owns the contract; the convention and template are canonical in
  [isomorphic-lib-template's `decisions/`](https://github.com/interop-alliance/isomorphic-lib-template/tree/main/decisions).
- The domain vocabulary is @ARCHITECTURE.md's Glossary; the refinement rules and
  the mapping for skills that expect `CONTEXT.md` or `docs/adr/` are canonical
  in
  [isomorphic-lib-template's `AGENTS.md`](https://github.com/interop-alliance/isomorphic-lib-template/blob/main/AGENTS.md)
  ("Domain language") and
  [`decisions/README.md`](https://github.com/interop-alliance/isomorphic-lib-template/blob/main/decisions/README.md)
  ("Qualifying test").

## Conventions

Code style, refactoring, JSDoc, comment, and error-handling conventions live in
@CONTRIBUTING.md -- follow them. That file's marked conventions block is the
canonical shared core copied across `@interop/*` repos; edit it there, not in
downstream copies.
