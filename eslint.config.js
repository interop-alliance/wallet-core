import js from '@eslint/js'
import globals from 'globals'
import tseslint from 'typescript-eslint'
import prettierConfig from 'eslint-config-prettier'
import { defineConfig, globalIgnores } from 'eslint/config'

// The vh-resource-log testing fixtures never reach production code: the
// fake controller neuters the authorization root (any configured key
// authorizes) and the memory store neuters durability, both while appearing
// to work. Tests and their fixtures are the only importers. (Flat-config
// rule entries replace rather than merge, so every src no-restricted-imports
// block restates this pattern.)
const noTestingSubpath = {
  group: ['@interop/vh-resource-log/testing'],
  message:
    'The vh-resource-log testing fixtures are test-only: the fake ' +
    'controller and memory store neuter authorization and durability ' +
    'while appearing to work.'
}

export default defineConfig([
  globalIgnores(['dist', '**/*.min.js']),
  {
    files: ['**/*.ts'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      prettierConfig // must be last in extends
    ],
    languageOptions: {
      ecmaVersion: 2022,
      globals: { ...globals.browser, ...globals.node },
      parserOptions: {
        project: ['./tsconfig.dev.json']
      }
    },
    rules: {
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
          destructuredArrayIgnorePattern: '^_'
        }
      ],
      '@typescript-eslint/no-explicit-any': 'off',
      curly: ['error', 'all'],
      'no-var': 'error',
      'prefer-const': 'error'
    }
  },
  // The logging seam is a type-only devDependency (decision 0004 in the
  // @interop/logger repo): a value import would ship a runtime dependency
  // and, under link: dev setups, resolve to a second copy with its own
  // sink registry, silently splitting events away from the app's sinks.
  {
    files: ['src/**/*.ts'],
    rules: {
      '@typescript-eslint/no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['@interop/logger'],
              allowTypeImports: true,
              message:
                'Only `import type` from @interop/logger in src/ -- the ' +
                'runtime port is src/log.ts (setLogger).'
            }
          ]
        }
      ]
    }
  },
  // The client-annex dependency direction: `src/clientAnnex/` may import
  // from the base subpaths; nothing in the base imports from it. A new
  // base-to-annex edge is a build failure, not a review catch -- resolve it
  // by moving the code into the annex, or by injecting it as a closure from
  // the durable orchestrator (the revocation and retirement pattern).
  {
    files: ['src/**/*.ts'],
    ignores: [
      'src/clientAnnex/**',
      'src/unlock/standingWebvh.ts',
      'src/recovery/recoveryWebvh.ts'
    ],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['./clientAnnex/*', '../clientAnnex/*'],
              message:
                'The base never imports from src/clientAnnex/. Move the code ' +
                'into the annex subpath, or take it as an injected closure.'
            },
            noTestingSubpath
          ]
        }
      ]
    }
  },
  // The annex subpath sits outside the base block above, so it restates the
  // testing-fixture restriction on its own.
  {
    files: ['src/clientAnnex/**/*.ts'],
    rules: {
      'no-restricted-imports': ['error', { patterns: [noTestingSubpath] }]
    }
  },
  // The pinned exception, for the two base-side retirements that resolve a
  // retired credential's current ladder inventory: `removeUnlockKey` and the
  // remembered recovery continuation's add-and-retire entry. Both use the
  // shared attribution helpers in `clientAnnex/ladder.ts` -- a deliberate
  // base-side dependency on those helpers, never on the annex log machinery.
  {
    files: ['src/unlock/standingWebvh.ts', 'src/recovery/recoveryWebvh.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['../clientAnnex/*', '!../clientAnnex/ladder.js'],
              message:
                'These modules may import only the ladder attribution ' +
                'helpers (clientAnnex/ladder.js) from the annex.'
            },
            noTestingSubpath
          ]
        }
      ]
    }
  }
])
