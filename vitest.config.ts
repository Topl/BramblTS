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
    // reporters: ["default"],
    setupFiles: [
      /// Required for Module augmentation to work (Fixes "TypeError (intermediate value).methodName is not a function")"
      '@/../../../src/common/functional/brambl_fp.ts',
      '@/../../../src/brambl/utils/extensions_exp.ts',
      '@/../../../src/brambl/common/contains_signable.ts',
      '@/../../../src/brambl/common/contains_immutable.ts',
      '@/../../../src/brambl/common/contains_evidence.ts',
      '@/../../../src/brambl/syntax/transaction_syntax.ts',
      '@/../../../src/brambl/syntax/token_type_identifier_syntax.ts',
      '@/../../../src/brambl/syntax/series_policy_syntax.ts',
      '@/../../../src/brambl/syntax/int128_syntax.ts',
      '@/../../../src/brambl/syntax/group_policy_syntax.ts',
      '@/../../../src/brambl/syntax/box_value_syntax.ts',
      /// targeted extensions
      '@/../../../src/brambl/syntax/extensions/io_transaction_extensions.ts',
      '@/../../../src/brambl/syntax/extensions/attestation_extensions.ts',
      '@/../../../src/brambl/syntax/extensions/challenge_extensions.ts',
      '@/../../../src/brambl/syntax/extensions/proof_extensions.ts',
      '@/../../../src/brambl/syntax/extensions/datum_extensions.ts',
    ]
    // testTimeout: 100000, // TODO remove after debugging
  }
});
