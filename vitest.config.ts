import { defineConfig } from 'vitest/config';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
  plugins: [tsconfigPaths()],
  resolve: {
    // alias: {
    //   '@': '/src',
    // },
  },
  test: {
    testTimeout: 100000, // TODO remove after debugging
  },
});
