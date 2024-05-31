import { isRight } from '@/common/functional/either.js';
import { Entropy } from '@/crypto/generation/mnemonic/entropy.js';
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
  Spanish
} from '@/crypto/generation/mnemonic/language.js';
import { Phrase } from '@/crypto/generation/mnemonic/phrase.js';
import { describe, expect, test } from 'vitest';
import { Generators } from '../../helpers/generators.js';

describe('Language Spec Test Vectors', async () => {
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
    new Korean()
  ];

  for (const language of languages) {
    test.concurrent(`Language resolves wordlist ${language}`, async () => {
      const x = await LanguageWordList.validated(language);
      expect(isRight(x)).toBe(true);
    });

    test(`phrases should be generated in ${language}`, async () => {
      const size = Generators.getGeneratedMnemonicSize();
      const entropy = Entropy.generate(size);
      const phrase = await Phrase.fromEntropy({ entropy, size, language });
      expect(isRight(phrase)).toBe(true);
    });
  }
});