import { Ed25519Initializer } from '../../../src/crypto/generation/key_initializer/ed25519_initializer';
import { ExtendedEd25519Initializer } from '../../../src/crypto/generation/key_initializer/extended_ed25519_initializer';
import { SecretKey } from '../../../src/crypto/signing/ed25519/ed25519_spec';
import { Ed25519 } from '../../../src/crypto/signing/eddsa/ed25519';
import { ExtendedEd25519 } from '../../../src/crypto/signing/extended_ed25519/extended_ed25519';
import * as spec from './../../../src/crypto/signing/extended_ed25519/extended_ed25519_spec';
import { KeyInitializerVector, keyInitializerTestVectors } from './test_vectors/key_initializer_vectors';

describe('Key Initializer spec', () => {
  for (const x of keyInitializerTestVectors) {
    const vector: KeyInitializerVector = KeyInitializerVector.fromJson(x);

    test(`Generate 96 byte seed from mnemonic: ${vector.mnemonic} + password: ${vector.password}`, async () => {
      const ed25519SkRes = await new Ed25519Initializer(new Ed25519()).fromMnemonicString(vector.mnemonic, {
        password: vector.password,
      });
      const ed25519Sk: SecretKey = ed25519SkRes.right;

      const extendedEd25519SkRes = await new ExtendedEd25519Initializer(new ExtendedEd25519()).fromMnemonicString(
        vector.mnemonic,
        { password: vector.password },
      );
      const extendedEd25519Sk: spec.SecretKey = extendedEd25519SkRes.right!;

      expect(ed25519Sk.bytes).toBe(vector.ed25519.bytes);
      expect(extendedEd25519Sk.leftKey).toBe(vector.extendedEd25519.leftKey);
      expect(extendedEd25519Sk.chainCode).toBe(vector.extendedEd25519.chainCode);
      expect(extendedEd25519Sk.rightKey).toBe(vector.extendedEd25519.rightKey);
    });
  }
});
