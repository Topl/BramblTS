import { v4 as uuidv4 } from 'uuid';
import { Entropy } from '../../../../src/crypto/generation/mnemonic/entropy';
import { Generators } from '../../helpers/generators';

describe('Entropy Spec Test Vectors', () => {
  test('random byte arrays (of the correct length) should be a valid Entropy', () => {
    const lengths = [16, 20, 24, 28, 32];
    for (const length of lengths) {
      const bytes = Generators.genByteArrayOfSize(length);
      const entropy = Entropy.fromBytes(bytes);

      expect(entropy.isRight).toBeTruthy();
    }
  });

  test('Entropy derived from UUIDs should result in valid mnemonic strings', async () => {
    for (let i = 0; i < 10; i++) {
      const uuid = uuidv4();
      const entropy = Entropy.fromUuid(uuid);

      const res = await Entropy.toMnemonicString(entropy);
      expect(res.isRight).toBeTruthy();
    }
  });

  test('Entropy can be generated and results in valid mnemonic strings', async () => {
    for (let i = 0; i < 10; i++) {
      const mnemonicSize = Generators.getGeneratedMnemonicSize();
      const entropy1 = Entropy.generate(mnemonicSize);
      const entropy2Res = await Entropy.toMnemonicString(entropy1);
      const entropy2String = entropy2Res.right!.join(' ');
      const entropy2 = await Entropy.fromMnemonicString(entropy2String);

      expect(entropy1.value).toBe(entropy2.right!.value);
    }
  });
});
