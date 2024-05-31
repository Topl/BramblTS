import { isLeft } from '@/common/functional/either.js';
import { Ed25519, Ed25519Initializer, ExtendedEd25519, ExtendedEd25519Initializer } from '@/crypto/crypto.js';
import { keyInitializerTestVectors, KeyInitializerVector } from './test_vectors/key_initializer_vectors.js';

describe('Key Initializer spec', () => {
  for (const x of keyInitializerTestVectors) {
    const vector: KeyInitializerVector = KeyInitializerVector.fromJson(x);

    test(`Generate 96 byte seed from mnemonic: ${vector.mnemonic} + password: ${vector.password}`, async () => {
      const ed25519SkRes = await new Ed25519Initializer(new Ed25519()).fromMnemonicString(vector.mnemonic, {
        password: vector.password
      });
      if (isLeft(ed25519SkRes)) throw new Error('Failed to generate Ed25519 key');
      const ed25519Sk = ed25519SkRes;

      const extendedEd25519SkRes = await new ExtendedEd25519Initializer(new ExtendedEd25519()).fromMnemonicString(
        vector.mnemonic,
        { password: vector.password }
      );
      if (isLeft(extendedEd25519SkRes)) throw new Error('Failed to generate ExtendedEd25519 key');
      const extendedEd25519Sk = extendedEd25519SkRes.right;

      expect(ed25519Sk['bytes']).toEqual(vector.ed25519.bytes);
      expect(extendedEd25519Sk['leftKey']).toEqual(vector.extendedEd25519.leftKey);
      expect(extendedEd25519Sk['chainCode']).toEqual(vector.extendedEd25519.chainCode);
    });
  }
});
