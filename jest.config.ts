import type { Config } from '@jest/types';
import { pathsToModuleNameMapper } from 'ts-jest';
import { compilerOptions } from './tsconfig.json';

const config: Config.InitialOptions = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testPathIgnorePatterns: [
    'BramblTS/test/crypto/generation/test_vectors/',
    'BramblTS/test/crypto/signing/test_vectors/',
  ],
  testMatch: ['**/test/**/*.[jt]s?(x)', '**/?(*.)+(spec|test).[jt]s?(x)'],
  moduleNameMapper: pathsToModuleNameMapper(compilerOptions.paths, {
    prefix: '<rootDir>/',
  }),
};

export default config;
