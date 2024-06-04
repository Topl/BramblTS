import { isLeft } from '@/common/functional/brambl_fp.js';
import { Ed25519, Ed25519Initializer, ExtendedEd25519, ExtendedEd25519Initializer } from '@/crypto/crypto.js';
import { keyInitializerTestVectors, KeyInitializerVector } from './test_vectors/key_initializer_vectors.js';
import { describe, test, expect } from 'vitest';
import * as spec from '@/crypto/signing/ed25519/ed25519_spec.js';
import * as xspec from '@/crypto/signing/extended_ed25519/extended_ed25519_spec.js';

describe('Key Initializer spec', () => {
  for (const x of keyInitializerTestVectors) {
    const vector: KeyInitializerVector = KeyInitializerVector.fromJson(x);

    test(`Generate 96 byte seed from mnemonic: ${vector.mnemonic} + password: ${vector.password}`, async () => {
      const ed25519SkRes = await new Ed25519Initializer(new Ed25519()).fromMnemonicString(vector.mnemonic, {
        password: vector.password,
      });
      if (isLeft(ed25519SkRes)) throw new Error('Failed to generate Ed25519 key');
      const ed25519Sk = ed25519SkRes.right as spec.SecretKey;

      const extendedEd25519SkRes = await new ExtendedEd25519Initializer(new ExtendedEd25519()).fromMnemonicString(
        vector.mnemonic,
        { password: vector.password },
      );
      if (isLeft(extendedEd25519SkRes)) throw new Error('Failed to generate ExtendedEd25519 key');
      const extendedEd25519Sk = extendedEd25519SkRes.right as xspec.SecretKey;

      expect(ed25519Sk.bytes).toEqual(vector.ed25519.bytes);
      expect(extendedEd25519Sk.leftKey).toEqual(vector.extendedEd25519.leftKey);
      expect(extendedEd25519Sk.chainCode).toEqual(vector.extendedEd25519.chainCode);
      expect(extendedEd25519Sk.rightKey).toEqual(vector.extendedEd25519.rightKey);
    });
  }
});
