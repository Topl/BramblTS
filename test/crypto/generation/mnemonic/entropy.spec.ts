import { v4 as uuidv4 } from 'uuid';
import { Entropy } from '@/crypto/generation/mnemonic/entropy.js';
import { Generators } from '../../helpers/generators.js';
import {  getOrThrowEither, isRight, withRightE } from '@/common/functional/either.js';
import { describe, test, expect } from 'vitest';


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
    for (let i = 0; i < 10; i++) {
      const mnemonicSize = Generators.getGeneratedMnemonicSize();
      const entropy1 = Entropy.generate(mnemonicSize);
      const entropy2Res = await Entropy.toMnemonicString(entropy1);

      
      const entropy2String = withRightE(entropy2Res).join(' ');
      const entropy2E = await Entropy.fromMnemonicString(entropy2String);
      const entropy2 = withRightE(entropy2E);

      expect(entropy1.value).toBe(entropy2.value);
    }
  });
});
