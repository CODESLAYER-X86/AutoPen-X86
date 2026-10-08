// ESLint flat configuration for the whole monorepo.
// Scope: type-safety and security-relevant correctness rules. Runtime types
// are additionally enforced by `tsc --strict` in every package.
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';

export default tseslint.config(
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      'data/**',
      'coverage/**',
      'apps/web/dist/**',
      '**/*.js',
      '**/*.cjs',
      '**/*.mjs',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['apps/web/**/*.{ts,tsx}'],
    plugins: { 'react-hooks': reactHooks },
    rules: {
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
    },
  },
  {
    files: ['**/*.ts', '**/*.tsx'],
    rules: {
      // Security-relevant basics.
      'no-eval': 'error',
      'no-implied-eval': 'error',
      eqeqeq: ['error', 'smart'],
      'no-var': 'error',
      'prefer-const': 'error',
      // Keep console discipline: structured logger is the intended path.
      'no-console': ['warn', { allow: ['warn', 'error'] }],
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
);
