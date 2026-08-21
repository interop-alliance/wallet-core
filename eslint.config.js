import js from '@eslint/js'
import globals from 'globals'
import tseslint from 'typescript-eslint'
import prettierConfig from 'eslint-config-prettier'
import { defineConfig, globalIgnores } from 'eslint/config'

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
  // The client-annex dependency direction: `src/clientAnnex/` may import
  // from the base subpaths; nothing in the base imports from it. A new
  // base-to-annex edge is a build failure, not a review catch -- resolve it
  // by moving the code into the annex, or by injecting it as a closure from
  // the durable orchestrator (the revocation and retirement pattern).
  {
    files: ['src/**/*.ts'],
    ignores: ['src/clientAnnex/**', 'src/unlock/standingWebvh.ts'],
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
            }
          ]
        }
      ]
    }
  },
  // The one pinned exception: `removeUnlockKey` resolves a retired
  // credential's current ladder footprint with the shared attribution
  // helpers in `clientAnnex/ladder.ts` -- a deliberate base-side dependency
  // on the attribution helpers, never on the annex log machinery.
  {
    files: ['src/unlock/standingWebvh.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['../clientAnnex/*', '!../clientAnnex/ladder.js'],
              message:
                'unlock/standingWebvh.ts may import only the ladder ' +
                'attribution helpers (clientAnnex/ladder.js) from the annex.'
            }
          ]
        }
      ]
    }
  }
])
