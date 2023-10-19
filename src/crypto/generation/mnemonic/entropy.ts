import { randomBytes } from 'crypto';
import { MnemonicSize } from './mnemonic';

const defaultMnemonicSize = MnemonicSize.words12();

enum EntropyFailureType {
  InvalidByteSize,
  PhraseToEntropyFailure,
  WordListFailure,
  InvalidSizeMismatch
}

export class Entropy {
  value: Uint8Array;

  constructor(value: Uint8Array) {
    this.value = value;
  }

  public static generate(size: MnemonicSize = defaultMnemonicSize): Entropy {
    const numBytes = size.entropyLength / 8;

    const r = randomBytes(numBytes);
    return new Entropy(r);
  }

  public static async toMnemonicString(
    entropy: Entropy,
    options: { language?: Language } = {}
  ): Promise<Either<EntropyFailure, string[]>> {
    const language = options.language || new English();
    
    const sizeResult = sizeFromEntropyLength(entropy.value.length);
    if (sizeResult.isLeft()) return left(sizeResult.value);
    const size = sizeResult.value;

    const phraseResult = await Phrase.fromEntropy({
      entropy: entropy,
      size: size,
      language: language
    });

    if (phraseResult.isLeft()) {
      return left(EntropyFailure.phraseToEntropyFailure({ context: phraseResult.value.toString() }));
    }

    const phrase = phraseResult.value;
    return right(phrase.value);
  }

  public static async fromMnemonicString(
    mnemonic: string,
    options: { language?: Language } = {}
  ): Promise<Either<EntropyFailure, Entropy>> {
    const language = options.language || new English(); // Define default language or replace with appropriate logic

    const phraseResult = await Phrase.validated({ words: mnemonic, language });
    if (phraseResult.isLeft()) {
      return left(EntropyFailure.phraseToEntropyFailure({ context: phraseResult.value.toString() }));
    }
    const phrase = phraseResult.value;

    const entropy = unsafeFromPhrase(phrase);
    return right(new Entropy(entropy));
  }

  public static fromUuid(uuid: Uuid): Entropy {
    const bytes = new Uint8Array(
      uuid.v4().replace(/-/g, '').split('').map((c) => parseInt(c, 16))
    );
    return new Entropy(bytes);
  }

  public static fromBytes(bytes: Uint8Array): Either<EntropyFailure, Entropy> {
    const sizeResult = Entropy.sizeFromEntropyLength(bytes.length);
    if (sizeResult.isLeft()) {
      return left(sizeResult.value);
    }
    const entropy = new Entropy(bytes);
    return right(entropy);
  }

  public static sizeFromEntropyLength(entropyByteLength: number): Either<EntropyFailure, MnemonicSize> {
    switch (entropyByteLength) {
      case 16:
        return right(MnemonicSize.words12());
      case 20:
        return right(MnemonicSize.words15());
      case 24:
        return right(MnemonicSize.words18());
      case 28:
        return right(MnemonicSize.words21());
      case 32:
        return right(MnemonicSize.words24());
      default:
        return left(EntropyFailure.invalidByteSize());
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

class EntropyFailure implements Error {
  /// A message describing the error.
  readonly message?: string | undefined;
  readonly type: EntropyFailureType;

  constructor(type: EntropyFailureType, message?: string) {
    this.type = type;
    this.message = message;
  }

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

