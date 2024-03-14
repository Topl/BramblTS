/* eslint-disable @typescript-eslint/no-explicit-any */
import { Either } from '../../../common/functional/either';
import { SHA256 } from '../../../crypto/hash/sha';
import { Entropy } from './entropy';
import { Language, LanguageWordList } from './language';
import { MnemonicSize } from './mnemonic';

export enum PhraseFailureType {
  InvalidWordLength,
  InvalidWords,
  InvalidChecksum,
  InvalidEntropyLength,
  WordListFailure,
}

function _byteTo8BitString(byte: number): string {
  return byte.toString(2).padStart(8, '0');
}

function _intTo11BitString(value: number): string {
  return value.toString(2).padStart(11, '0');
}

export class Phrase {
  value: string[];
  size: MnemonicSize;
  languageWords: LanguageWordList;

  constructor(props: { value: string[]; size: MnemonicSize; languageWords: LanguageWordList }) {
    this.value = props.value;
    this.size = props.size;
    this.languageWords = props.languageWords;
  }

  static async validated({
    words,
    language,
  }: {
    words: string;
    language: Language;
  }): Promise<Either<PhraseFailure, Phrase>> {
    const wordListResult = await LanguageWordList.validated(language);

    if (wordListResult.isLeft) {
      return Either.left(PhraseFailure.wordListFailure());
    }

    const wordList = wordListResult.right!;

    const wordCount = words.split(' ').filter((w) => w !== '').length;
    const sizeResult = MnemonicSize.fromNumberOfWords(wordCount);

    if (sizeResult.isLeft) {
      return Either.left(PhraseFailure.invalidWordLength(words));
    }

    const size = sizeResult.right!;

    const phrase: Phrase = {
      value: words
        .toLowerCase()
        .split(/\s+/)
        .map((w) => w.trim()),
      size,
      languageWords: wordList,
    };

    if (phrase.value.length !== phrase.size.wordLength) {
      return Either.left(PhraseFailure.invalidWordLength(words));
    }

    if (!phrase.value.every((word) => wordList.value.includes(word))) {
      return Either.left(PhraseFailure.invalidWords(words));
    }

    const [entropyBinaryString, checksumFromPhrase] = this.toBinaryString(phrase);
    const checksumFromSha256 = Phrase._calculateChecksum(entropyBinaryString, size);

    return Either.conditional(checksumFromPhrase === checksumFromSha256, {
      left: PhraseFailure.invalidChecksum(words),
      right: phrase,
    });
  }

  static _calculateChecksum(entropyBinaryString: string, size: MnemonicSize): string {
    const byteLength = 8;

    const entropyBits = entropyBinaryString.substring(0, size.entropyLength);

    const entropyBytes: number[] = [];
    for (let i = 0; i < entropyBits.length; i += byteLength) {
      const byte = entropyBits.substring(i, i + byteLength);
      entropyBytes.push(parseInt(byte, 2));
    }

    const sha256Digest = new SHA256().hash(new Uint8Array(entropyBytes));
    const hashBytes = new Uint8Array(sha256Digest);

    const hashBits: string[] = [];
    for (const byte of hashBytes) {
      hashBits.push(_byteTo8BitString(byte));
    }

    const hashBinaryString = hashBits.join('');
    const checksumBinaryString = hashBinaryString.substring(0, size.checksumLength);
    return checksumBinaryString;
  }

  static async fromEntropy({
    entropy,
    size,
    language,
  }: {
    entropy: Entropy;
    size: MnemonicSize;
    language: Language;
  }): Promise<any> {
    if (entropy.value.length !== size.entropyLength / 8) {
      return Either.left(PhraseFailure.invalidEntropyLength());
    }

    const wordListResult = (await LanguageWordList.validated(language)).flatMapLeft(() =>
      Either.left(PhraseFailure.wordListFailure()),
    );

    if (wordListResult.isLeft && wordListResult.left != null) {
      return Either.left(PhraseFailure.wordListFailure());
    }

    const wordList = wordListResult.right!;

    const entropyBinaryString = entropy.value
      .map((item): number => {
        return Number(_byteTo8BitString(item));
      })
      .join('');

    const checksum = Phrase._calculateChecksum(entropyBinaryString, size);

    const phraseBinaryString = entropyBinaryString + checksum;
    const phraseWords: string[] = [];
    for (let i = 0; i < phraseBinaryString.length; i += 11) {
      const index = parseInt(phraseBinaryString.substring(i, i + 11), 2);
      phraseWords.push(wordList.value[index]);
    }

    return Either.right({
      value: phraseWords,
      size: size,
      languageWords: wordList,
    });
  }

  static toBinaryString(phrase: Phrase): [string, string] {
    const wordList = phrase.languageWords.value;
    const binaryString = phrase.value
      .map((word) => wordList.indexOf(word))
      .map(_intTo11BitString)
      .join('');
    const entropyBinaryString = binaryString.slice(0, phrase.size.entropyLength);
    const checksumBinaryString = binaryString.slice(phrase.size.entropyLength);
    return [entropyBinaryString, checksumBinaryString];
  }
}

export class PhraseFailure implements Error {
  readonly name: string = 'PhraseFailure';
  readonly message: string;
  readonly type: PhraseFailureType;

  constructor(type: PhraseFailureType, message?: string) {
    this.type = type;
    this.message = message;
  }
  static invalidWordLength(context?: string): PhraseFailure {
    return new PhraseFailure(PhraseFailureType.InvalidWordLength, context);
  }

  static invalidWords(context?: string): PhraseFailure {
    return new PhraseFailure(PhraseFailureType.InvalidWords, context);
  }

  static invalidChecksum(context?: string): PhraseFailure {
    return new PhraseFailure(PhraseFailureType.InvalidChecksum, context);
  }

  static invalidEntropyLength(context?: string): PhraseFailure {
    return new PhraseFailure(PhraseFailureType.InvalidEntropyLength, context);
  }

  static wordListFailure(context?: string): PhraseFailure {
    return new PhraseFailure(PhraseFailureType.InvalidEntropyLength, context);
  }

  toString(): string {
    return `PhraseFailure{message: ${this.message}, type: ${this.type}}`;
  }
}
