import globals from 'globals';
import pluginJs from '@eslint/js';
import tseslint from 'typescript-eslint';
import convexPlugin from '@convex-dev/eslint-plugin';

export default [
  {
    ignores: [
      'dist/**',
      '*.config.{js,mjs,cjs,ts,tsx}',
      'example/**/*.config.{js,mjs,cjs,ts,tsx}',
      '**/_generated/'
    ]
  },
  {
    files: ['src/**/*.{js,mjs,cjs,ts,tsx}', 'example/**/*.{js,mjs,cjs,ts,tsx}'],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        project: ['./tsconfig.json', './example/convex/tsconfig.json'],
        tsconfigRootDir: import.meta.dirname
      }
    }
  },
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  // Convex code - Worker environment
  {
    files: ['src/**/*.{ts,tsx}', 'example/convex/**/*.{ts,tsx}'],
    languageOptions: {
      globals: globals.worker
    },
    plugins: {
      '@convex-dev': convexPlugin
    },
    rules: {
      ...convexPlugin.configs.recommended[0].rules,
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_'
        }
      ],
      '@typescript-eslint/no-unused-expressions': [
        'error',
        {
          allowShortCircuit: true,
          allowTernary: true,
          allowTaggedTemplates: true
        }
      ]
    }
  }
];
