import tsconfigPaths from 'vite-tsconfig-paths';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [tsconfigPaths()],
  resolve: {
    // alias: {
    //   '@': '/src',
    // },
  },
  test: {
    setupFiles: [
      '@/../../src/crypto/signing/kdf/cipherParameters.ts',
      '@/../../src/common/functional/either.ts',
      '@/../../src/brambl/utils/extensions_exp.ts',
      '@/../../src/brambl/syntax/transaction_syntax.ts',
      '@/../../src/brambl/syntax/token_type_identifier_syntax.ts',
      '@/../../src/brambl/syntax/series_policy_syntax.ts',
      '@/../../src/brambl/syntax/int128_syntax.ts',
      '@/../../src/brambl/syntax/group_policy_syntax.ts',
      '@/../../src/brambl/syntax/box_value_syntax.ts',
      '@/../../src/brambl/common/contains_signable.ts',
      '@/../../src/brambl/common/contains_immutable.ts',
      '@/../../src/brambl/common/contains_evidence.ts'
    ]
    // testTimeout: 100000, // TODO remove after debugging
  }
});
