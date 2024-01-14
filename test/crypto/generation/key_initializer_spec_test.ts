import { Ed25519Initializer } from '../../../src/crypto/generation/key_initializer/ed25519_initializer';
import { ExtendedEd25519Initializer } from '../../../src/crypto/generation/key_initializer/extended_ed25519_initializer';
import { Ed25519 } from '../../../src/crypto/signing/eddsa/ed25519';
import { ExtendedEd25519 } from '../../../src/crypto/signing/extended_ed25519/extended_ed25519';
import { KeyInitializerVector, keyInitializerTestVectors } from './test_vectors/key_initializer_vectors';

describe('Key Initializer spec', () => {
  keyInitializerTestVectors.forEach((x) => {
    const vector = KeyInitializerVector.fromJson(x);

    test(`Generate 96 byte seed from mnemonic: ${vector.mnemonic} + password: ${vector.password}`, async () => {
      const ed25519SkRes = await new Ed25519Initializer(new Ed25519()).fromMnemonicString(vector.mnemonic, {
        password: vector.password,
      });
      const ed25519Sk = ed25519SkRes.right!;

      const extendedEd25519SkRes = await new ExtendedEd25519Initializer(new ExtendedEd25519()).fromMnemonicString(
        vector.mnemonic,
        {
          password: vector.password,
        },
      );
      const extendedEd25519Sk = extendedEd25519SkRes.right!;

      expect(Buffer.from(ed25519Sk.bytes).equals(Buffer.from(vector.ed25519.bytes))).toBe(true);

      expect(Buffer.from(extendedEd25519Sk.leftKey).equals(Buffer.from(vector.extendedEd25519.leftKey))).toBe(true);
      expect(Buffer.from(extendedEd25519Sk.chainCode).equals(Buffer.from(vector.extendedEd25519.chainCode))).toBe(true);
      expect(Buffer.from(extendedEd25519Sk.rightKey).equals(Buffer.from(vector.extendedEd25519.rightKey))).toBe(true);
    });
  });
});
