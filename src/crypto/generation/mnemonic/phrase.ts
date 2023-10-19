import { Either } from '@/common/functional/either';
import { sha256 } from '@/crypto/hash/hash';
import { Entropy } from './entropy';
import { Language, LanguageWordList } from './language';
import { MnemonicSize } from './mnemonic';

export class Phrase {
  readonly value: string[];
  readonly size: MnemonicSize;
  readonly languageWords: LanguageWordList;

  constructor(value: string[], size: MnemonicSize, languageWords: LanguageWordList) {
    this.value = value;
    this.size = size;
    this.languageWords = languageWords;
  }

  static async validated({
    words,
    language,
  }: {
    words: string;
    language: Language;
  }): Promise<Either<PhraseFailure, Phrase>> {
    try {
      const wordListResult = await LanguageWordList.validated(language);
      if (wordListResult.isLeft) {
        return Either.left(new PhraseFailure(PhraseFailureType.wordListFailure));
      }
      const wordList = wordListResult.right!;

      const wordCount = words.split(' ').filter((w) => w.length > 0).length;
      const sizeResult = MnemonicSize.fromNumberOfWords(wordCount);

      if (sizeResult.isLeft) {
        return Either.left(new PhraseFailure(PhraseFailureType.invalidWordLength, words));
      }
      const size = sizeResult.right!;

      const phrase = new Phrase(
        words
          .toLowerCase()
          .split(/\s+/)
          .map((w) => w.trim()),
        size,
        wordList,
      );

      if (phrase.value.length !== phrase.size.wordLength) {
        return Either.left(new PhraseFailure(PhraseFailureType.invalidWordLength, words));
      }

      if (!phrase.value.every((word) => wordList.value.includes(word))) {
        return Either.left(new PhraseFailure(PhraseFailureType.invalidWords, words));
      }

      const [entropyBinaryString, checksumFromPhrase] = Phrase.toBinaryString(phrase);
      const checksumFromSha256 = Phrase._calculateChecksum(entropyBinaryString, size);

      return Either.conditional(
        checksumFromPhrase === checksumFromSha256,
        new PhraseFailure(PhraseFailureType.invalidChecksum, words),
        phrase,
      );
    } catch (e) {
      return Either.left(new PhraseFailure(PhraseFailureType.wordListFailure, e));
    }
  }

  static async fromEntropy({
    entropy,
    size,
    language,
  }: {
    entropy: Entropy;
    size: MnemonicSize;
    language: Language;
  }): Promise<Either<PhraseFailure, Phrase>> {
    if (entropy.value.length !== size.entropyLength / 8) {
      return Either.left(new PhraseFailure(PhraseFailureType.invalidEntropyLength));
    }

    const wordListResult = await LanguageWordList.validated(language);

    if (wordListResult.isLeft && wordListResult.left) {
      return Either.left(wordListResult.left);
    }

    const wordList = wordListResult.right!;
    const entropyBinaryString = Array.from(entropy.value, (byte) => Phrase._byteTo8BitString(byte)).join('');

    const checksum = Phrase._calculateChecksum(entropyBinaryString, size);
    const phraseBinaryString = entropyBinaryString + checksum;

    const phraseWords = [];
    for (let i = 0; i < phraseBinaryString.length; i += 11) {
      const index = parseInt(phraseBinaryString.substring(i, i + 11), 2);
      phraseWords.push(wordList.value[index]);
    }

    return Either.right(new Phrase(phraseWords, size, wordList));
  }

  static toBinaryString(phrase: Phrase): [string, string] {
    const wordList = phrase.languageWords.value;
    const binaryString = phrase.value
      .map((word) => wordList.indexOf(word))
      .map((value) => Phrase._intTo11BitString(value))
      .join('');

    return [binaryString, binaryString.substring(0, phrase.size.entropyLength)];
  }

  private static _calculateChecksum(entropyBinaryString: string, size: MnemonicSize): string {
    const entropyBits = entropyBinaryString.substring(0, size.entropyLength);
    const entropyBytes: number[] = [];

    for (let i = 0; i < entropyBits.length; i += 8) {
      const byte = entropyBits.substring(i, i + 8);
      entropyBytes.push(parseInt(byte, 2));
    }

    const sha256Digest = sha256.hash(Uint8Array.from(entropyBytes));
    const hashString = Array.from(sha256Digest, (byte) => byte.toString(2).padStart(8, '0')).join('');

    return hashString.substring(0, size.checksumLength);
  }

  private static _byteTo8BitString(byte: number): string {
    return byte.toString(2).padStart(8, '0');
  }

  private static _intTo11BitString(value: number): string {
    return value.toString(2).padStart(11, '0');
  }
}

enum PhraseFailureType {
  invalidWordLength,
  invalidWords,
  invalidChecksum,
  invalidEntropyLength,
  wordListFailure,
}

class PhraseFailure extends Error {
  readonly message?: string;
  readonly type: PhraseFailureType;

  constructor(type: PhraseFailureType, message?: string) {
    super();
    this.message = message;
    this.type = type;
  }

  static invalidWordLength(context?: string): PhraseFailure {
    return new PhraseFailure(PhraseFailureType.invalidWordLength, context);
  }

  static invalidWords(context?: string): PhraseFailure {
    return new PhraseFailure(PhraseFailureType.invalidWords, context);
  }

  static invalidChecksum(context?: string): PhraseFailure {
    return new PhraseFailure(PhraseFailureType.invalidChecksum, context);
  }

  static invalidEntropyLength(context?: string): PhraseFailure {
    return new PhraseFailure(PhraseFailureType.invalidEntropyLength, context);
  }

  static wordListFailure(context?: string): PhraseFailure {
    return new PhraseFailure(PhraseFailureType.wordListFailure, context);
  }
}
