import { isRight, toRightE } from '@/common/functional/brambl_fp.js';
import { Entropy } from '@/crypto/generation/mnemonic/entropy.js';
import { v4 as uuidv4 } from 'uuid';
import { describe, expect, test } from 'vitest';
import { Generators } from '../../helpers/generators.js';
import { mnemonicToEntropyTestVectors, MnemonicToEntropyVector } from '../test_vectors/mnemonic_to_entropy_vectors.js';

describe('Entropy Spec Test Vectors', () => {
  test('random byte arrays (of the correct length) should be a valid Entropy', () => {
    const lengths = [16, 20, 24, 28, 32];
    for (const length of lengths) {
      const bytes = Generators.genByteArrayOfSize(length);
      const entropy = Entropy.fromBytes(bytes);

      expect(isRight(entropy)).toBeTruthy();
    }
  });

  test('Entropy derived from UUIDs should result in valid mnemonic strings', async () => {
    const uuid = uuidv4();
    for (let i = 0; i < 10; i++) {
      const entropy = Entropy.fromUuid(uuid);

      const res = await Entropy.toMnemonicString(entropy);
      expect(isRight(res)).toBeTruthy();
    }
  });

  test('Entropy can be generated and results in valid mnemonic strings', async () => {
    for (const mnemonicSize of Generators.mnemonicSizes) {
      const entropy1 = Entropy.generate(mnemonicSize);
      const entropy2Res = await Entropy.toMnemonicString(entropy1);

      const entropy2String = toRightE(entropy2Res).join(' ');
      const entropy2 = toRightE(await Entropy.fromMnemonicString(entropy2String));

      expect(entropy1.value).toEqual(entropy2.value);
    }
  });

  test('Entropy can be generated, transformed to a mnemonic phrase string, and converted back to the original entropy value', async () => {
    for (const mnemonicSize of Generators.mnemonicSizes) {
      const entropy1 = Entropy.generate(mnemonicSize);
      const entropy2String = toRightE(await Entropy.toMnemonicString(entropy1));
      const entropy2 = toRightE(await Entropy.fromMnemonicString(entropy2String.join(' ')));

      expect(entropy1.value).toEqual(entropy2.value);
    }
  });

  describe('Test vector mnemonic should produce known entropy.', () => {
    for (const v of mnemonicToEntropyTestVectors) {
      const vector = MnemonicToEntropyVector.fromJson(v);

      test(`Test vector mnemonic should produce known entropy. Mnemonic: ${vector.mnemonic}`, async () => {
        const actualEntropy = await Entropy.fromMnemonicString(vector.mnemonic);
        expect(isRight(actualEntropy)).toBeTruthy();
        expect(toRightE(actualEntropy).value).toEqual(vector.entropy.value);
      });
    }
  });
});
