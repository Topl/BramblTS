import { Entropy } from '../../../../src/crypto/generation/mnemonic/entropy';
import {
  ChineseSimplified,
  ChineseTraditional,
  Czech,
  English,
  French,
  Italian,
  Japanese,
  Korean,
  Language,
  LanguageWordList,
  Portuguese,
  Spanish,
} from '../../../../src/crypto/generation/mnemonic/language';
import { Phrase } from '../../../../src/crypto/generation/mnemonic/phrase';
import { Generators } from '../../helpers/generators';

describe('Language Spec Test Vectors', () => {
  const languages: Language[] = [
    new English(),
    new ChineseSimplified(),
    new ChineseTraditional(),
    new Portuguese(),
    new Czech(),
    new Spanish(),
    new Italian(),
    new French(),
    new Japanese(),
    new Korean(),
  ];

  for (const language of languages) {
    test(`Language resolves wordlist ${language}`, async () => {
      const x = await LanguageWordList.validated(language);
      expect(x.isRight).toBe(true);
    });

    test(`phrases should be generated in ${language}`, async () => {
      const size = Generators.getGeneratedMnemonicSize();
      const entropy = Entropy.generate(size);
      const phrase = await Phrase.fromEntropy({ entropy, size, language });
      expect(phrase.isRight).toBe(true);
    });
  }
});
