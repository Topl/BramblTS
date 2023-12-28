/* eslint-disable @typescript-eslint/no-unused-vars */
import { v4 as uuidv4 } from 'uuid';
import { Either } from '../../../common/functional/either';
import { English, Language } from './language';
import { MnemonicSize } from './mnemonic';
import { Phrase } from './phrase';
import { getRandomValues } from 'crypto';

const defaultMnemonicSize = MnemonicSize.words12();

enum EntropyFailureType {
  InvalidByteSize,
  PhraseToEntropyFailure,
  WordListFailure,
  InvalidSizeMismatch,
}

class Uuid {
  v4() {
    return uuidv4();
  }
}

export class Entropy {
  value: Uint8Array;

  constructor(value: Uint8Array) {
    this.value = value;
  }

  public static generate(size = defaultMnemonicSize): Entropy {
    const numBytes = size.entropyLength / 8;
    const r = new Uint8Array(numBytes);
    const secureRandom = getRandomValues(r);
    return new Entropy(secureRandom);
  }

  public static async toMnemonicString(
    entropy: Entropy,
    options: { language?: Language } = {},
  ): Promise<Either<EntropyFailure, string[]>> {
    const language = options.language || new English();

    const sizeResult = this.sizeFromEntropyLength(entropy.value.length);
    if (sizeResult.isLeft) return Either.left(sizeResult.left);
    const size = sizeResult.right!;

    const phraseResult = await Phrase.fromEntropy({
      entropy: entropy,
      size: size,
      language: language,
    });

    if (phraseResult.isLeft) {
      return Either.left(EntropyFailure.phraseToEntropyFailure({ context: phraseResult.left.toString() }));
    }

    const phrase = phraseResult.right!;
    return Either.right(phrase.value);
  }

  public static async fromMnemonicString(
    mnemonic: string,
    options: { language?: Language } = {},
  ): Promise<Either<EntropyFailure, Entropy>> {
    const language = options.language || new English(); // Define default language or replace with appropriate logic

    const phraseResult = await Phrase.validated({ words: mnemonic, language });
    if (phraseResult.isLeft) {
      return Either.left(EntropyFailure.phraseToEntropyFailure({ context: phraseResult.left.toString() }));
    }
    const phrase = phraseResult.right!;

    const entropy = this.unsafeFromPhrase(phrase);
    return Either.right(entropy);
  }

  public static fromUuid(uuid: Uuid): Entropy {
    const uuidString = uuid.v4().replace(/-/g, '');
    const bytes = uuidString.split('').map((c) => parseInt(c, 16));
    return new Entropy(new Uint8Array(bytes));
  }

  public static fromBytes(bytes: Uint8Array): Either<EntropyFailure, Entropy> {
    const sizeResult = Entropy.sizeFromEntropyLength(bytes.length);
    if (sizeResult.isLeft) {
      return Either.left(sizeResult.left);
    }
    const entropy = new Entropy(bytes);
    return Either.right(entropy);
  }

  public static sizeFromEntropyLength(entropyByteLength: number): Either<EntropyFailure, MnemonicSize> {
    switch (entropyByteLength) {
      case 16:
        return Either.right(MnemonicSize.words12());
      case 20:
        return Either.right(MnemonicSize.words15());
      case 24:
        return Either.right(MnemonicSize.words18());
      case 28:
        return Either.right(MnemonicSize.words21());
      case 32:
        return Either.right(MnemonicSize.words24());
      default:
        return Either.left(EntropyFailure.invalidByteSize());
    }
  }

  public static unsafeFromPhrase(phrase: Phrase): Entropy {
    const binaryString = Phrase.toBinaryString(phrase)[0];

    const bytes: number[] = [];
    let currentByte = 0;

    for (let i = 0; i < binaryString.length; i++) {
      const bit = parseInt(binaryString[i], 10);

      if (i % 8 === 0) {
        bytes.push(0);
        currentByte = bytes.length - 1;
      }

      bytes[currentByte] += bit << (7 - (i % 8));
    }

    return new Entropy(new Uint8Array(bytes));
  }
}

class EntropyFailure {
  /// A message describing the error.
  readonly message?: string | undefined;
  readonly type: EntropyFailureType;

  constructor(type: EntropyFailureType, message?: string) {
    this.type = type;
    this.message = message;
  }
  name: string;
  stack?: string;

  static invalidByteSize({ context }: { context?: string } = {}): EntropyFailure {
    return new EntropyFailure(EntropyFailureType.InvalidByteSize, context);
  }

  static phraseToEntropyFailure({ context }: { context?: string } = {}): EntropyFailure {
    return new EntropyFailure(EntropyFailureType.PhraseToEntropyFailure, context);
  }

  static wordListFailure({ context }: { context?: string } = {}): EntropyFailure {
    return new EntropyFailure(EntropyFailureType.WordListFailure, context);
  }

  static invalidSizeMismatch({ context }: { context?: string } = {}): EntropyFailure {
    return new EntropyFailure(EntropyFailureType.InvalidSizeMismatch, context);
  }

  toString(): string {
    return `EntropyFailure{message: ${this.message}, type: ${this.type}}`;
  }
}
